use crate::db::error::DbError;
use crate::db::repo::{Repository, UserProvisionOutcome};
use crate::service::password::{
    hash_password_async, validate_password, PasswordValidationError, PasswordWorkError,
};

#[derive(Debug)]
pub enum CreateUserError {
    InvalidUsername,
    Password(PasswordValidationError),
    Hash(String),
    DuplicateUsername,
    DefaultPlanMissing(i64),
    Database(DbError),
}

impl PartialEq for CreateUserError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::InvalidUsername, Self::InvalidUsername)
                | (
                    Self::Password(PasswordValidationError::TooShort),
                    Self::Password(PasswordValidationError::TooShort)
                )
                | (
                    Self::Password(PasswordValidationError::TooLong),
                    Self::Password(PasswordValidationError::TooLong)
                )
                | (Self::DuplicateUsername, Self::DuplicateUsername)
                | (Self::DefaultPlanMissing(_), Self::DefaultPlanMissing(_))
        )
    }
}

impl Eq for CreateUserError {}

pub fn validate_username(username: &str) -> bool {
    !username.is_empty()
        && username.len() <= 64
        && username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub async fn create_user(
    db: &dyn Repository,
    username: &str,
    password: &str,
) -> Result<(), CreateUserError> {
    if !validate_username(username) {
        return Err(CreateUserError::InvalidUsername);
    }
    validate_password(password).map_err(CreateUserError::Password)?;

    let hashed = hash_password_async(password).await.map_err(|e| match e {
        PasswordWorkError::Busy => CreateUserError::Hash("password service is busy".into()),
        error => CreateUserError::Hash(error.to_string()),
    })?;

    // Resolve and lock the current default only after bcrypt completes, in the
    // same transaction that copies its quota and inserts the user. Registration
    // enabled/disabled does not apply to administrator provisioning.
    match db.insert_admin_user_from_default(username, &hashed).await {
        Ok(UserProvisionOutcome::Created) => Ok(()),
        Ok(UserProvisionOutcome::PlanMissing(plan_id)) => {
            Err(CreateUserError::DefaultPlanMissing(plan_id))
        }
        Ok(UserProvisionOutcome::RegistrationDisabled | UserProvisionOutcome::PlanNotAllowed) => {
            Err(CreateUserError::Database(DbError::NotFound))
        }
        Err(DbError::UniqueViolation) => Err(CreateUserError::DuplicateUsername),
        Err(e) => Err(CreateUserError::Database(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_validation_matches_admin_create_policy() {
        assert!(validate_username("alice_123"));
        assert!(validate_username(&"a".repeat(64)));
        assert!(!validate_username(""));
        assert!(!validate_username(&"a".repeat(65)));
        assert!(!validate_username("bad name"));
        assert!(!validate_username("bad-name"));
        assert!(!validate_username("中文"));
    }
}
