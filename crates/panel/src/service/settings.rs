use crate::db::error::DbError;
use crate::db::repo::{RegistrationSettings, Repository};

pub const DEFAULT_REGISTRATION_PLAN_ID: i64 = 1;
pub const DEFAULT_SITE_NAME: &str = "RelayPanel";
pub const MAX_SITE_NAME_CHARS: usize = 64;

#[derive(Debug)]
pub enum RegistrationSettingsError {
    DefaultPlanMissing,
    AllowedPlansEmpty,
    DefaultPlanNotInAllowed,
    AllowedPlanNotFound(i64),
    InvalidSiteName,
    Database(DbError),
}

pub fn default_registration_settings() -> RegistrationSettings {
    RegistrationSettings {
        registration_enabled: false,
        default_registration_plan_id: DEFAULT_REGISTRATION_PLAN_ID,
        allowed_plan_ids: vec![DEFAULT_REGISTRATION_PLAN_ID],
        site_name: DEFAULT_SITE_NAME.to_string(),
    }
}

pub async fn get_registration_settings(
    db: &dyn Repository,
) -> Result<RegistrationSettings, DbError> {
    Ok(db
        .get_registration_settings()
        .await?
        .unwrap_or_else(default_registration_settings))
}

/// v0.4.21 PR2: update registration settings with multi-plan validation.
///
/// Validation rules:
/// 1. allowed_plan_ids is deduplicated.
/// 2. allowed_plan_ids must not be empty.
/// 3. Every plan_id in allowed_plan_ids must exist in the plans table.
/// 4. default_plan_id must exist in the plans table.
/// 5. default_plan_id must be in allowed_plan_ids.
pub async fn update_registration_settings(
    db: &dyn Repository,
    enabled: bool,
    default_plan_id: i64,
    raw_allowed_plan_ids: &[i64],
    raw_site_name: Option<&str>,
) -> Result<RegistrationSettings, RegistrationSettingsError> {
    let site_name = match raw_site_name {
        Some(value) => {
            normalize_site_name(value).ok_or(RegistrationSettingsError::InvalidSiteName)?
        }
        None => {
            get_registration_settings(db)
                .await
                .map_err(RegistrationSettingsError::Database)?
                .site_name
        }
    };

    // Deduplicate.
    let mut allowed: Vec<i64> = raw_allowed_plan_ids.to_vec();
    allowed.sort_unstable();
    allowed.dedup();

    // Must not be empty.
    if allowed.is_empty() {
        return Err(RegistrationSettingsError::AllowedPlansEmpty);
    }

    // Validate the default plan exists.
    match db.find_plan_name_by_id(default_plan_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return Err(RegistrationSettingsError::DefaultPlanMissing),
        Err(e) => return Err(RegistrationSettingsError::Database(e)),
    }

    // default_plan_id must be in allowed_plan_ids.
    if !allowed.contains(&default_plan_id) {
        return Err(RegistrationSettingsError::DefaultPlanNotInAllowed);
    }

    // Validate every allowed plan exists.
    for &id in &allowed {
        match db.find_plan_name_by_id(id).await {
            Ok(Some(_)) => {}
            Ok(None) => return Err(RegistrationSettingsError::AllowedPlanNotFound(id)),
            Err(e) => return Err(RegistrationSettingsError::Database(e)),
        }
    }

    db.set_system_settings(enabled, default_plan_id, &allowed, &site_name)
        .await
        .map_err(RegistrationSettingsError::Database)?;

    Ok(RegistrationSettings {
        registration_enabled: enabled,
        default_registration_plan_id: default_plan_id,
        allowed_plan_ids: allowed,
        site_name,
    })
}

pub fn normalize_site_name(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.chars().count() > MAX_SITE_NAME_CHARS
        || trimmed.chars().any(char::is_control)
    {
        return None;
    }
    Some(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_settings_are_safe() {
        let settings = default_registration_settings();
        assert!(!settings.registration_enabled);
        assert_eq!(settings.default_registration_plan_id, 1);
        assert_eq!(settings.allowed_plan_ids, vec![1]);
        assert_eq!(settings.site_name, DEFAULT_SITE_NAME);
    }

    #[test]
    fn site_name_validation_trims_and_rejects_invalid_values() {
        assert_eq!(normalize_site_name("  My Relay  "), Some("My Relay".into()));
        assert_eq!(normalize_site_name("中转站"), Some("中转站".into()));
        assert_eq!(normalize_site_name("   "), None);
        assert_eq!(normalize_site_name("bad\nname"), None);
        assert_eq!(
            normalize_site_name(&"x".repeat(MAX_SITE_NAME_CHARS + 1)),
            None
        );
    }
}
