use once_cell::sync::Lazy;
use std::fmt;
use std::sync::Arc;
use tokio::sync::Semaphore;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordValidationError {
    TooShort,
    TooLong,
}

pub fn validate_password(password: &str) -> Result<(), PasswordValidationError> {
    if password.len() < 8 {
        return Err(PasswordValidationError::TooShort);
    }
    if password.len() > 72 {
        return Err(PasswordValidationError::TooLong);
    }
    Ok(())
}

/// All bcrypt work shares one small blocking-pool admission budget. Public
/// callers are rate-limited before reaching this queue; awaiting a slot
/// avoids making legitimate concurrent requests fail nondeterministically while
/// still ensuring only four CPU-heavy jobs can execute at once.
static BCRYPT_SLOTS: Lazy<Arc<Semaphore>> = Lazy::new(|| Arc::new(Semaphore::new(4)));

#[derive(Debug)]
pub enum PasswordWorkError {
    Busy,
    Bcrypt(bcrypt::BcryptError),
    Worker(tokio::task::JoinError),
}

impl fmt::Display for PasswordWorkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy => write!(f, "password worker capacity exhausted"),
            Self::Bcrypt(error) => write!(f, "bcrypt error: {error}"),
            Self::Worker(error) => write!(f, "password worker failed: {error}"),
        }
    }
}

pub async fn hash_password_async(password: &str) -> Result<String, PasswordWorkError> {
    let permit = BCRYPT_SLOTS
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| PasswordWorkError::Busy)?;
    let password = password.to_owned();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        bcrypt::hash(password, 12).map_err(PasswordWorkError::Bcrypt)
    })
    .await
    .map_err(PasswordWorkError::Worker)?
}

pub async fn verify_password_async(password: &str, hash: &str) -> Result<bool, PasswordWorkError> {
    let permit = BCRYPT_SLOTS
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| PasswordWorkError::Busy)?;
    let password = password.to_owned();
    let hash = hash.to_owned();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        bcrypt::verify(password, &hash).map_err(PasswordWorkError::Bcrypt)
    })
    .await
    .map_err(PasswordWorkError::Worker)?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_boundaries_are_enforced() {
        assert_eq!(
            validate_password("1234567"),
            Err(PasswordValidationError::TooShort)
        );
        assert!(validate_password("12345678").is_ok());
        assert!(validate_password(&"a".repeat(72)).is_ok());
        assert_eq!(
            validate_password(&"a".repeat(73)),
            Err(PasswordValidationError::TooLong)
        );
    }
}
