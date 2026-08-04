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

const GENERATED_LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
const GENERATED_UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
const GENERATED_DIGITS: &[u8] = b"23456789";
const GENERATED_SYMBOLS: &[u8] = b"!@#%^&*-_=+?";
pub const GENERATED_PASSWORD_LEN: usize = 16;

fn random_bytes(size: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; size];
    getrandom::getrandom(&mut bytes).expect("OS randomness unavailable");
    bytes
}

/// Uniform selection without modulo bias.
fn pick(set: &[u8]) -> u8 {
    let limit = 256 - (256 % set.len());
    loop {
        let byte = random_bytes(1)[0] as usize;
        if byte < limit {
            return set[byte % set.len()];
        }
    }
}

/// Generate a shell-friendly recovery password from the OS CSPRNG.
///
/// Every output contains all four character classes. Ambiguous glyphs and
/// shell-quoting hazards are deliberately excluded because operators commonly
/// copy this value from `docker exec` into a browser.
pub fn generate_password() -> String {
    let mut chars = vec![
        pick(GENERATED_LOWER),
        pick(GENERATED_UPPER),
        pick(GENERATED_DIGITS),
        pick(GENERATED_SYMBOLS),
    ];
    let all: Vec<u8> = [
        GENERATED_LOWER,
        GENERATED_UPPER,
        GENERATED_DIGITS,
        GENERATED_SYMBOLS,
    ]
    .concat();
    while chars.len() < GENERATED_PASSWORD_LEN {
        chars.push(pick(&all));
    }

    // Fisher-Yates shuffle using rejection sampling for each shrinking range.
    for index in (1..chars.len()).rev() {
        let limit = 256 - (256 % (index + 1));
        let target = loop {
            let byte = random_bytes(1)[0] as usize;
            if byte < limit {
                break byte % (index + 1);
            }
        };
        chars.swap(index, target);
    }

    String::from_utf8(chars).expect("generated password charset is ASCII")
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

    #[test]
    fn generated_passwords_satisfy_every_contract() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let password = generate_password();
            assert_eq!(password.len(), GENERATED_PASSWORD_LEN);
            assert!(validate_password(&password).is_ok());
            assert!(password.bytes().any(|b| GENERATED_LOWER.contains(&b)));
            assert!(password.bytes().any(|b| GENERATED_UPPER.contains(&b)));
            assert!(password.bytes().any(|b| GENERATED_DIGITS.contains(&b)));
            assert!(password.bytes().any(|b| GENERATED_SYMBOLS.contains(&b)));
            assert!(!password.chars().any(|c| "0O1lI'\"\\`$ ".contains(c)));
            assert!(seen.insert(password), "generated a duplicate password");
        }
    }
}
