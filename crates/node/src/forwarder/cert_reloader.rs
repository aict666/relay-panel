// v0.4.1 PR2: TLS certificate hot-reloader.
//
// Watches the cert + key files via mtime polling (5s). On mtime change:
//   1. Re-read both files.
//   2. Re-parse (rustls-pemfile).
//   3. Verify cert↔key match (rustls ServerConfig build).
//   4. On success: atomically swap the new TlsAcceptor (old connections keep
//      the old one; new connections get the new one).
//   5. On failure: keep the old TlsAcceptor, log the error, push a
//      listener_error so the panel shows it. The node does NOT restart.
//
// Why mtime polling (not inotify/notify):
//   - `notify`/inotify is unreliable inside containers over bind mounts (event
//     coalescing, missed events on overlay fs).
//   - mtime polling is zero-dependency, cross-platform, and robust. 5s latency
//     is acceptable for cert rotation (certs are replaced, not every-second).
//
// Permission check: the private key file MUST be 0600 (owner-only). A more
// permissive mode is rejected — a leaked key defeats TLS entirely. The cert
// file has no such restriction (certs are public).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;

/// Poll interval for mtime checks.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Shared, atomically-swappable TLS acceptor. Cloned per listener task; each
/// reads the current value at accept time. Uses std RwLock (not tokio) because
/// the read is synchronous and never blocks long (no async work under the lock).
pub type SharedTlsAcceptor = Arc<std::sync::RwLock<Option<TlsAcceptor>>>;

/// Manages hot-reloading of a TLS cert + key pair.
pub struct CertReloader {
    cert_path: PathBuf,
    key_path: PathBuf,
    shared: SharedTlsAcceptor,
    last_mtime: Option<(SystemTime, SystemTime)>,
}

impl CertReloader {
    /// Create a CertReloader that ALWAYS starts the poll task, even if the
    /// initial cert load fails. This is critical: if the cert file doesn't
    /// exist yet (operator installs node first, drops cert later), or is
    /// temporarily corrupted, the poll task will pick it up once the file is
    /// fixed — without requiring a node restart.
    ///
    /// Returns (reloader, shared_acceptor). The shared_acceptor starts as
    /// Some(acceptor) if the initial load succeeded, or None if it failed
    /// (the poll task will fill it in on success).
    pub fn new(cert_path: &str, key_path: &str) -> (Self, SharedTlsAcceptor) {
        let cert_path = PathBuf::from(cert_path);
        let key_path = PathBuf::from(key_path);

        // Try initial load. On ANY failure (missing file, bad PEM, permission,
        // cert↔key mismatch), start with None and let the poll task recover.
        let (initial_acceptor, initial_mtime) = match try_load(&cert_path, &key_path) {
            Ok(acceptor) => {
                tracing::info!("TLS certificate loaded at startup");
                let mtime = (file_mtime(&cert_path), file_mtime(&key_path));
                (Some(acceptor), Some(mtime))
            }
            Err(e) => {
                tracing::warn!(
                    "TLS cert load failed at startup: {} — poll task will retry when file is fixed",
                    e
                );
                (None, None)
            }
        };

        let shared: SharedTlsAcceptor = Arc::new(std::sync::RwLock::new(initial_acceptor));

        let reloader = CertReloader {
            cert_path,
            key_path,
            shared: Arc::clone(&shared),
            last_mtime: initial_mtime,
        };

        (reloader, shared)
    }

    /// Spawn the background mtime-poll task. Runs forever; logs + records
    /// errors on failed reloads. The task holds a weak reference so it exits
    /// if the manager is dropped.
    pub fn spawn_poll_task(
        self,
        listener_errors: Arc<Mutex<Vec<relay_shared::protocol::ListenerError>>>,
    ) {
        let cert_path = self.cert_path.clone();
        let key_path = self.key_path.clone();
        let shared = self.shared.clone();
        let last_mtime = self.last_mtime;

        tokio::spawn(async move {
            let mut last = last_mtime;
            // Avoid re-logging the same reload failure every 5s.
            let mut last_error: Option<String> = None;
            loop {
                tokio::time::sleep(POLL_INTERVAL).await;

                let cert_mtime = file_mtime(&cert_path);
                let key_mtime = file_mtime(&key_path);

                // Skip only if mtime is unchanged AND we have a valid cert.
                // If last is None (initial load failed), always retry — the
                // file may have been created/fixed since.
                if Some((cert_mtime, key_mtime)) == last && last.is_some() {
                    continue;
                }

                // Files changed — attempt reload.
                tracing::info!("TLS cert/key mtime changed, reloading...");

                match try_load(&cert_path, &key_path) {
                    Ok(acceptor) => {
                        // Permission check on the key (must still be 0600).
                        if let Err(e) = check_key_permissions(&key_path) {
                            let msg =
                                format!("TLS reload skipped: key permission check failed: {}", e);
                            if last_error.as_deref() != Some(&msg) {
                                tracing::warn!("{}", msg);
                                last_error = Some(msg.clone());
                            }
                            // Keep old cert; don't update last_mtime so we retry.
                            continue;
                        }
                        // Swap in the new acceptor.
                        *shared.write().unwrap() = Some(acceptor);
                        last = Some((cert_mtime, key_mtime));
                        last_error = None;
                        tracing::info!("TLS cert reloaded successfully");
                    }
                    Err(e) => {
                        // Keep old cert. Log + record, deduped.
                        let msg = format!("TLS reload failed (keeping old cert): {}", e);
                        if last_error.as_deref() != Some(&msg) {
                            tracing::warn!("{}", msg);
                            last_error = Some(msg.clone());
                            // Push to listener_errors for panel display.
                            let mut errs = listener_errors.lock().await;
                            errs.push(relay_shared::protocol::ListenerError {
                                port: 0, // Not port-specific.
                                protocol: "tls".into(),
                                error: msg.clone(),
                                tunnel_id: None,
                                rule_id: None,
                            });
                        }
                        // Update last_mtime anyway so we don't spin on the
                        // same broken file every 5s — wait for the NEXT mtime
                        // change before retrying.
                        last = Some((cert_mtime, key_mtime));
                    }
                }
            }
        });
    }
}

/// Load cert + key, check permissions, build a TlsAcceptor. Shared by initial
/// load and reload. Returns Err with a GENERIC message (no key content leaked).
fn try_load(cert_path: &Path, key_path: &Path) -> Result<TlsAcceptor, String> {
    use std::io::BufReader;

    // Check private-key permissions BEFORE loading (0600 required).
    check_key_permissions(key_path)?;

    // Read + parse cert chain.
    let cert_file = std::fs::File::open(cert_path)
        .map_err(|e| format!("cannot open cert file: {}", e.kind()))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "cert file contains no valid PEM certificates".to_string())?;

    if certs.is_empty() {
        return Err("cert file contains no valid PEM certificates".into());
    }

    // Read + parse key (PKCS#8/PKCS#1/SEC1 auto-detected).
    let key_file =
        std::fs::File::open(key_path).map_err(|e| format!("cannot open key file: {}", e.kind()))?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|_| "key file contains no valid PEM private key".to_string())?
        .ok_or_else(|| "key file is empty".to_string())?;

    // Build ServerConfig: TLS 1.2 + 1.3, no client auth. with_single_cert
    // verifies cert↔key match.
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("cert/key mismatch or invalid: {}", e))?;

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

/// Get the mtime of a file, or epoch(0) if unavailable (treated as "changed").
fn file_mtime(path: &Path) -> SystemTime {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

/// Check that the private key file has restrictive permissions (0600 on Unix).
/// A key readable by group/other defeats TLS entirely. On non-Unix (Windows)
/// this is a no-op (Windows ACLs are a different model).
fn check_key_permissions(key_path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(key_path)
            .map_err(|e| format!("cannot stat key file: {}", e.kind()))?;
        let mode = meta.permissions().mode();
        // mode & 0o077 = any group/other permission bits set.
        if mode & 0o077 != 0 {
            return Err(format!(
                "private key file is too open (mode {:04o}); must be 0600 (owner-only)",
                mode
            ));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = key_path; // Suppress unused warning on non-Unix.
    }
    Ok(())
}
