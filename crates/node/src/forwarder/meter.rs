//! Account each successful write, including partial writes before an error or
//! cancellation. No connection-close flush and no per-chunk map lock.
use crate::reporter::RuleCounterHandle;
use std::io;
use tokio::io::{AsyncWrite, AsyncWriteExt};

pub(super) async fn write_counted<W: AsyncWrite + Unpin>(
    writer: &mut W,
    mut bytes: &[u8],
    counter: Option<&RuleCounterHandle>,
    upload: bool,
) -> io::Result<()> {
    while !bytes.is_empty() {
        let n = writer.write(bytes).await?;
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        if let Some(counter) = counter {
            if upload {
                counter.add_upload(n as u64);
            } else {
                counter.add_download(n as u64);
            }
        }
        bytes = &bytes[n..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reporter::TrafficCounter;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn partial_write_is_counted_before_cancellation() {
        let counter = TrafficCounter::new();
        let handle = counter.handle(7).await;
        let (mut writer, mut reader) = tokio::io::duplex(3);
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(20),
            write_counted(&mut writer, b"abcdef", Some(&handle), true)
        )
        .await
        .is_err());
        let mut bytes = [0; 3];
        reader.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"abc");
        assert_eq!(counter.snapshot().await.entries[0].upload, 3);
    }
}
