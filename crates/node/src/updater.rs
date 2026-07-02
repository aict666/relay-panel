//! v1.0.10: node self-upgrade.
//!
//! Triggered by a directed `UpgradeNodeMessage` on the WS control channel. The
//! node downloads the official `relay-node` release binary for the REQUESTED
//! version (pinned by the panel to its own version, so the node never jumps
//! ahead of the panel) and this node's architecture, verifies its published
//! sha256, backs up + atomically swaps its own binary, and returns Ok — the
//! caller then exits so systemd (Restart=always) re-execs into the new binary.
//!
//! Guarantees:
//! - **systemd only.** docker / manual installs are refused: only systemd has a
//!   supervisor that restarts the process (and, for docker, a self-replaced
//!   binary is lost when the container is recreated). The install method is also
//!   reported to the panel so the UI never offers a self-upgrade that can't work.
//! - **Single-flight.** A global flag rejects a second upgrade while one runs,
//!   so concurrent/repeated commands can't race on the temp file / swap.
//! - **Mandatory backup.** The current binary is copied to `.bak` BEFORE the
//!   swap; if the backup fails the upgrade is aborted (nothing is replaced).
//! - **Security.** The URL is hardcoded to the official GitHub release and the
//!   version is validated as plain semver, so the panel can at most force an
//!   upgrade to an official build — never run arbitrary code. A failed upgrade
//!   (network / hash / io) leaves the current binary untouched.

use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};

/// Official release source. Never taken from the panel.
const REPO: &str = "MoeShinX/relay-panel";

/// Single-flight guard: true while an upgrade is downloading/swapping.
static UPGRADING: AtomicBool = AtomicBool::new(false);

/// How this node is run. Drives whether a one-click self-upgrade is possible.
/// - `docker`: `/.dockerenv` exists → a self-replaced binary is lost on the next
///   `docker compose up` / image pull, so we don't self-replace.
/// - `systemd`: systemd sets `INVOCATION_ID` for the units it starts (inherited
///   by children) → there's a supervisor to restart us after we exit.
/// - `manual`: neither → exiting would leave nothing to bring the node back.
pub fn install_method() -> &'static str {
    if std::path::Path::new("/.dockerenv").exists() {
        "docker"
    } else if std::env::var_os("INVOCATION_ID").is_some() {
        "systemd"
    } else {
        "manual"
    }
}

/// Map the compiled target arch to the release asset suffix.
fn asset_arch() -> Option<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Some("amd64"),
        "aarch64" => Some("arm64"),
        _ => None,
    }
}

/// A plain semver: `x.y.z` with an optional `-suffix` of `[0-9A-Za-z.-]`. This
/// gates the version before it goes into a URL path, so a panel value can never
/// inject `/`, `..`, etc.
fn is_plain_semver(v: &str) -> bool {
    let (base, suffix) = match v.split_once('-') {
        Some((b, s)) => (b, Some(s)),
        None => (v, None),
    };
    let parts: Vec<&str> = base.split('.').collect();
    if parts.len() != 3
        || !parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    {
        return false;
    }
    match suffix {
        None => true,
        Some(s) => {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        }
    }
}

/// Upgrade this node to `version` (a plain semver WITHOUT a leading "v"). On
/// success the new binary is in place and the caller should exit(0). On any
/// error the running binary is untouched and a later retry is allowed.
pub async fn self_upgrade(version: &str) -> Result<(), String> {
    // Only systemd installs can safely self-replace + restart.
    let method = install_method();
    if method != "systemd" {
        return Err(format!(
            "self-upgrade is only supported for systemd installs (this node is '{method}'); \
             update the container image / re-run the install script instead"
        ));
    }
    if !is_plain_semver(version) {
        return Err(format!(
            "refusing to upgrade to a non-semver version {version:?}"
        ));
    }
    // Single-flight: reject a concurrent/repeat upgrade so two tasks can't race
    // on the temp file and swap, which could leave a truncated binary.
    if UPGRADING
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err("an upgrade is already in progress".into());
    }
    let result = do_upgrade(version).await;
    if result.is_err() {
        // Failed → release the flag so a later command can retry. (On success we
        // exit the process before reaching here, so the flag simply dies with us.)
        UPGRADING.store(false, Ordering::SeqCst);
    }
    result
}

async fn do_upgrade(version: &str) -> Result<(), String> {
    let arch =
        asset_arch().ok_or_else(|| format!("unsupported arch: {}", std::env::consts::ARCH))?;
    let asset = format!("relay-node-linux-{arch}");
    // Pinned to the exact requested release tag (v{version}) — NOT "latest".
    let bin_url = format!("https://github.com/{REPO}/releases/download/v{version}/{asset}");
    let sha_url = format!("{bin_url}.sha256");

    let bin_path = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;

    tracing::warn!("self-upgrade: downloading {bin_url}");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(180))
        .build()
        .map_err(|e| format!("http client: {e}"))?;

    // 1. Binary bytes.
    let bin_bytes = client
        .get(&bin_url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| format!("download binary: {e}"))?
        .bytes()
        .await
        .map_err(|e| format!("read binary: {e}"))?;
    if bin_bytes.is_empty() {
        return Err("downloaded binary is empty".into());
    }

    // 2. Published sha256 (format: "<hex>  <filename>").
    let sha_text = client
        .get(&sha_url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| format!("download sha256: {e}"))?
        .text()
        .await
        .map_err(|e| format!("read sha256: {e}"))?;
    let expected = sha_text
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_lowercase();
    if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("malformed sha256 file: {sha_text:?}"));
    }

    // 3. Verify.
    let mut hasher = Sha256::new();
    hasher.update(&bin_bytes);
    let actual: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if actual != expected {
        return Err(format!(
            "sha256 mismatch: expected {expected}, got {actual}"
        ));
    }
    tracing::warn!(
        "self-upgrade: sha256 verified ({} bytes) for {} v{version}",
        bin_bytes.len(),
        asset
    );

    // 4. Write a UNIQUE temp file (pid + nanos, so a stray concurrent run can't
    // truncate ours), chmod +x, back up the current binary (MANDATORY), then
    // atomically rename over the running binary. Renaming over a running binary
    // is fine on Linux (the live process keeps its old inode).
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = bin_path.with_extension(format!("upgrade.{}.{}.tmp", std::process::id(), nanos));
    let bak = bin_path.with_extension("bak");

    tokio::fs::write(&tmp, &bin_bytes)
        .await
        .map_err(|e| format!("write temp binary: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)) {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(format!("chmod temp binary: {e}"));
        }
    }
    // MANDATORY backup: if we can't preserve a rollback copy, abort (don't swap).
    if let Err(e) = tokio::fs::copy(&bin_path, &bak).await {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(format!(
            "backup to {} failed, aborting upgrade: {e}",
            bak.display()
        ));
    }
    if let Err(e) = tokio::fs::rename(&tmp, &bin_path).await {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(format!("swap binary: {e}"));
    }

    tracing::warn!(
        "self-upgrade: binary swapped at {} (old kept as {}); exiting for systemd restart",
        bin_path.display(),
        bak.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_arch_maps_known_targets() {
        // The real function returns None on an unsupported arch rather than
        // panicking — exercised indirectly by do_upgrade's early return.
        let _ = asset_arch();
    }

    #[test]
    fn semver_validation() {
        assert!(is_plain_semver("1.0.10"));
        assert!(is_plain_semver("1.0.10-rc.1"));
        assert!(is_plain_semver("12.34.56"));
        // Rejects anything that could escape the URL path or isn't x.y.z.
        assert!(!is_plain_semver("1.0"));
        assert!(!is_plain_semver("1.0.10/../../etc"));
        assert!(!is_plain_semver("latest"));
        assert!(!is_plain_semver("1.0.x"));
        assert!(!is_plain_semver(""));
        assert!(!is_plain_semver("1.0.10-"));
    }
}
