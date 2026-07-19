use crate::db::error::DbError;
use crate::db::repo::Repository;
use crate::service::password::{
    hash_password_async, validate_password, PasswordValidationError, PasswordWorkError,
};
use crate::service::settings::get_registration_settings;

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

    // Admin-created users inherit the configured registration default plan.
    // The registration-enabled switch only controls the public signup route;
    // it must not prevent an administrator from provisioning an account.
    let plan_id = get_registration_settings(db)
        .await
        .map_err(CreateUserError::Database)?
        .default_registration_plan_id;

    let hashed = hash_password_async(password).await.map_err(|e| match e {
        PasswordWorkError::Busy => CreateUserError::Hash("password service is busy".into()),
        error => CreateUserError::Hash(error.to_string()),
    })?;

    match db.insert_user_from_plan(username, &hashed, plan_id).await {
        Ok(1) => Ok(()),
        Ok(_) => Err(CreateUserError::DefaultPlanMissing(plan_id)),
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
