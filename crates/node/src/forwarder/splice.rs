//! v1.0.8: Linux splice(2) zero-copy bidirectional TCP forwarding.
//!
//! For an UNLIMITED (non-rate-limited) rule, the node forwards bytes with the
//! `splice(2)` syscall instead of a userspace read/write copy. splice moves
//! data *inside the kernel* through a pipe — the bytes are never copied into
//! this process's address space — which removes the two userspace copies (and
//! the CPU + memory-bandwidth cost) that a plain relay pays per byte. This is
//! the same technique realm and other high-performance relays use.
//!
//! Structure (per direction): a non-blocking pipe is the kernel intermediary.
//! Step 1 splices `socket → pipe` (pull up to a pipe-full from the source);
//! step 2 splices `pipe → socket` (push them to the destination, draining
//! fully). Readiness is driven by tokio (`readable()`/`writable()` + `try_io`),
//! so the task parks instead of busy-looping on EAGAIN. Because the pipe is
//! fully drained between reads, an EAGAIN in step 1 always means "source socket
//! not readable" and in step 2 "destination socket not writable" — never the
//! pipe — so the readiness we wait on is always the right one.
//!
//! Rate limiting is NOT possible here (the bytes never reach userspace to be
//! throttled) — the caller only takes this path for unlimited rules. Byte
//! counts ARE available (splice returns the count moved), so the two totals are
//! returned for traffic accounting / billing, exactly like the userspace path.
//!
//! This whole module is Linux-only; the caller falls back to the userspace copy
//! on other targets.

use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;
use tokio::io::Interest;
use tokio::net::TcpStream;

/// Pipe capacity we try to set (64 KiB = 16 × 4 KiB pages), matching realm's
/// default. Best-effort: if `F_SETPIPE_SZ` fails we keep the kernel default.
const PIPE_SIZE: libc::c_int = 16 * 4096;

/// A non-blocking pipe pair that closes both ends on drop.
struct Pipe {
    r: RawFd,
    w: RawFd,
}

impl Pipe {
    fn new() -> io::Result<Pipe> {
        let mut fds = [0 as libc::c_int; 2];
        // O_CLOEXEC prevents relay pipes leaking into a future child process.
        let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        // Best-effort enlarge — a bigger pipe means fewer splice syscalls under
        // load. Ignore failure (capped by /proc/sys/fs/pipe-max-size, or the
        // caller may lack permission); the kernel default still works.
        unsafe { libc::fcntl(fds[1], libc::F_SETPIPE_SZ, PIPE_SIZE) };
        Ok(Pipe {
            r: fds[0],
            w: fds[1],
        })
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.r);
            libc::close(self.w);
        }
    }
}

/// One raw `splice` call. Returns Ok(0) on EOF, Ok(n) on success, or an
/// `io::Error` (WouldBlock is surfaced so the caller can wait for readiness).
fn splice_raw(from: RawFd, to: RawFd, len: usize) -> io::Result<usize> {
    let n = unsafe {
        libc::splice(
            from,
            std::ptr::null_mut(),
            to,
            std::ptr::null_mut(),
            len,
            (libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK) as libc::c_uint,
        )
    };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

/// Shut down the write half of a socket (SHUT_WR), signalling EOF to the peer.
/// Best-effort; errors (e.g. the peer already closed) are ignored.
fn shutdown_write(fd: RawFd) {
    unsafe {
        libc::shutdown(fd, libc::SHUT_WR);
    }
}

/// Pump one direction, `src → dst`, with splice via a private pipe. Returns the
/// total bytes moved. On return (EOF or error) the destination's write half is
/// shut down so the peer sees EOF and the opposite pump can finish too.
async fn pump(src: &TcpStream, dst: &TcpStream) -> io::Result<u64> {
    let pipe = Pipe::new()?;
    let src_fd = src.as_raw_fd();
    let dst_fd = dst.as_raw_fd();
    let mut total: u64 = 0;

    let result = async {
        loop {
            // Step 1: socket → pipe. The pipe is empty here (fully drained
            // below), so EAGAIN can only mean the source is not readable.
            let n = loop {
                src.readable().await?;
                match src.try_io(Interest::READABLE, || {
                    splice_raw(src_fd, pipe.w, PIPE_SIZE as usize)
                }) {
                    Ok(n) => break n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(e) => return Err(e),
                }
            };
            if n == 0 {
                break; // source EOF — clean end of stream
            }

            // Step 2: pipe → socket, drained fully. The pipe is non-empty, so
            // EAGAIN can only mean the destination is not writable.
            let mut left = n;
            while left > 0 {
                dst.writable().await?;
                match dst.try_io(Interest::WRITABLE, || splice_raw(pipe.r, dst_fd, left)) {
                    Ok(0) => return Ok(()), // destination closed for writing
                    Ok(m) => {
                        left -= m;
                        total += m as u64;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(())
    }
    .await;

    // Whether we ended on EOF or an error, signal EOF to the destination's peer
    // so the other direction's pump unblocks and the connection tears down.
    shutdown_write(dst_fd);
    result.map(|()| total)
}

/// Forward bytes both ways between `a` and `b` with splice zero-copy until both
/// directions reach EOF. Returns `(a→b bytes, b→a bytes)`.
///
/// The streams are wrapped in `Arc` so both pump tasks can drive readiness on
/// them concurrently (`readable`/`writable`/`try_io` take `&self`); the raw fds
/// stay valid for the whole operation because the `Arc`s outlive both pumps.
pub async fn zero_copy_bidirectional(a: TcpStream, b: TcpStream) -> io::Result<(u64, u64)> {
    let a = Arc::new(a);
    let b = Arc::new(b);
    let (a_up, b_up) = (a.clone(), b.clone());
    let ab = pump(&a_up, &b_up); // a → b
    let ba = pump(&b, &a); // b → a
    let (r_ab, r_ba) = tokio::join!(ab, ba);
    Ok((r_ab?, r_ba?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    async fn spawn_fixed_relay(
        target: std::net::SocketAddr,
        connections: usize,
        zero_copy: bool,
    ) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut tasks = Vec::with_capacity(connections);
            for _ in 0..connections {
                let (mut inbound, _) = listener.accept().await.unwrap();
                let mut outbound = TcpStream::connect(target).await.unwrap();
                tasks.push(tokio::spawn(async move {
                    if zero_copy {
                        zero_copy_bidirectional(inbound, outbound).await.unwrap();
                    } else {
                        tokio::io::copy_bidirectional(&mut inbound, &mut outbound)
                            .await
                            .unwrap();
                    }
                }));
            }
            for task in tasks {
                task.await.unwrap();
            }
        });
        addr
    }

    /// End-to-end: client → [splice relay] → echo target. The payload must
    /// round-trip and the returned byte counts must be exact.
    #[tokio::test]
    async fn splice_roundtrips_and_counts_bytes() {
        // Echo target: read once, echo back, then close.
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = target.accept().await.unwrap();
            let mut b = vec![0u8; 1024];
            let n = s.read(&mut b).await.unwrap();
            s.write_all(&b[..n]).await.unwrap();
            s.shutdown().await.unwrap();
        });

        // Relay: accept a client, connect to target, splice both ways.
        let relay = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let relay_task = tokio::spawn(async move {
            let (client, _) = relay.accept().await.unwrap();
            let upstream = TcpStream::connect(target_addr).await.unwrap();
            zero_copy_bidirectional(client, upstream).await.unwrap()
        });

        // Client: send, receive the echo, close.
        let mut client = TcpStream::connect(relay_addr).await.unwrap();
        let msg = b"hello-splice-zero-copy";
        client.write_all(msg).await.unwrap();
        client.shutdown().await.unwrap(); // half-close: signals EOF upstream
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, msg, "payload must round-trip through the splice relay");

        let (up, down) = relay_task.await.unwrap();
        assert_eq!(up, msg.len() as u64, "client→target byte count");
        assert_eq!(down, msg.len() as u64, "target→client byte count");
    }

    /// A larger transfer (bigger than one pipe-full) must move all bytes.
    #[tokio::test]
    async fn splice_moves_large_payload() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        // Sink target: drain everything the relay sends.
        let recv = tokio::spawn(async move {
            let (mut s, _) = target.accept().await.unwrap();
            let mut total = 0u64;
            let mut b = vec![0u8; 64 * 1024];
            loop {
                match s.read(&mut b).await.unwrap() {
                    0 => break,
                    n => total += n as u64,
                }
            }
            total
        });

        let relay = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let relay_task = tokio::spawn(async move {
            let (client, _) = relay.accept().await.unwrap();
            let upstream = TcpStream::connect(target_addr).await.unwrap();
            zero_copy_bidirectional(client, upstream).await.unwrap()
        });

        let mut client = TcpStream::connect(relay_addr).await.unwrap();
        let payload = vec![0x5au8; 1_000_000]; // ~1 MiB, several pipe-fulls
        client.write_all(&payload).await.unwrap();
        client.shutdown().await.unwrap();
        // Drain any (empty) reverse traffic so the relay's b→a pump ends.
        let mut sink = Vec::new();
        client.read_to_end(&mut sink).await.unwrap();

        let (up, _down) = relay_task.await.unwrap();
        let received = recv.await.unwrap();
        assert_eq!(
            received,
            payload.len() as u64,
            "target must receive all bytes"
        );
        assert_eq!(up, payload.len() as u64, "up count must equal payload size");
    }

    /// Regression for encrypted request/response protocols such as SS2022:
    /// two splice relays in series must preserve many deliberately fragmented
    /// frames while the connection remains open and traffic flows both ways.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_hop_splice_preserves_fragmented_full_duplex_frames() {
        const CONNECTIONS: usize = 32;
        const FRAMES: usize = 128;

        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        tokio::spawn(async move {
            let mut tasks = Vec::with_capacity(CONNECTIONS);
            for _ in 0..CONNECTIONS {
                let (mut stream, _) = target.accept().await.unwrap();
                tasks.push(tokio::spawn(async move {
                    for _ in 0..FRAMES {
                        let len = stream.read_u16().await.unwrap() as usize;
                        let mut payload = vec![0u8; len];
                        stream.read_exact(&mut payload).await.unwrap();
                        for byte in &mut payload {
                            *byte ^= 0xa5;
                        }
                        stream.write_u16(len as u16).await.unwrap();
                        stream.write_all(&payload).await.unwrap();
                        stream.flush().await.unwrap();
                    }
                }));
            }
            for task in tasks {
                task.await.unwrap();
            }
        });

        let hop2 = spawn_fixed_relay(target_addr, CONNECTIONS, true).await;
        let hop1 = spawn_fixed_relay(hop2, CONNECTIONS, true).await;

        let mut clients = Vec::with_capacity(CONNECTIONS);
        for client_id in 0..CONNECTIONS {
            clients.push(tokio::spawn(async move {
                let mut stream = TcpStream::connect(hop1).await.unwrap();
                stream.set_nodelay(true).unwrap();
                for frame_id in 0..FRAMES {
                    let len = 1 + ((client_id * 131 + frame_id * 977) % 8191);
                    let payload: Vec<u8> = (0..len)
                        .map(|i| (client_id as u8).wrapping_mul(17) ^ (frame_id as u8) ^ i as u8)
                        .collect();

                    // Split the header and body into small writes to model a
                    // cipher handshake arriving in arbitrary TCP segments.
                    stream.write_all(&(len as u16).to_be_bytes()).await.unwrap();
                    for chunk in payload.chunks(37) {
                        stream.write_all(chunk).await.unwrap();
                        tokio::task::yield_now().await;
                    }

                    let response_len = stream.read_u16().await.unwrap() as usize;
                    assert_eq!(response_len, len);
                    let mut response = vec![0u8; response_len];
                    stream.read_exact(&mut response).await.unwrap();
                    let expected: Vec<u8> = payload.into_iter().map(|byte| byte ^ 0xa5).collect();
                    assert_eq!(response, expected);
                }
                stream.shutdown().await.unwrap();
            }));
        }
        for client in clients {
            tokio::time::timeout(std::time::Duration::from_secs(30), client)
                .await
                .expect("two-hop client timed out")
                .unwrap();
        }
    }

    async fn benchmark_upload(zero_copy: bool, payload_len: usize) -> f64 {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let sink = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut total = 0usize;
            let mut buf = vec![0u8; 256 * 1024];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                total += n;
            }
            total
        });
        let hop2 = spawn_fixed_relay(target_addr, 1, zero_copy).await;
        let hop1 = spawn_fixed_relay(hop2, 1, zero_copy).await;
        let mut client = TcpStream::connect(hop1).await.unwrap();
        let payload = vec![0x5a; payload_len];
        let started = Instant::now();
        client.write_all(&payload).await.unwrap();
        client.shutdown().await.unwrap();
        assert_eq!(sink.await.unwrap(), payload_len);
        payload_len as f64 / started.elapsed().as_secs_f64()
    }

    /// Manual Linux loopback benchmark. It is ignored in normal CI because
    /// throughput depends on the host; run with `--ignored --nocapture`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore]
    async fn benchmark_two_hop_splice_vs_userspace() {
        const PAYLOAD_LEN: usize = 256 * 1024 * 1024;
        let userspace = benchmark_upload(false, PAYLOAD_LEN).await;
        let splice = benchmark_upload(true, PAYLOAD_LEN).await;
        println!(
            "two-hop upload: userspace={:.1} MiB/s splice={:.1} MiB/s ratio={:.2}x",
            userspace / 1024.0 / 1024.0,
            splice / 1024.0 / 1024.0,
            splice / userspace
        );
    }
}
