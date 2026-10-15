//! Shared purchase/cycle policy. SQL backends only perform locked I/O; they
//! use these same UTC boundaries and immutable entitlement snapshots.
use crate::db::error::DbError;
use chrono::{Duration, NaiveDateTime};
use serde::{Deserialize, Serialize};

pub const UTC_FORMAT: &str = "%Y-%m-%d %H:%M:%S";

pub fn now() -> String {
    chrono::Utc::now().format(UTC_FORMAT).to_string()
}

pub fn add_days(start: &str, days: i32) -> Result<String, DbError> {
    let start = NaiveDateTime::parse_from_str(start, UTC_FORMAT)
        .map_err(|_| DbError::InvalidData("invalid subscription timestamp"))?;
    start
        .checked_add_signed(Duration::days(i64::from(days)))
        .map(|value| value.format(UTC_FORMAT).to_string())
        .ok_or(DbError::InvalidData("subscription expiry overflow"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitlementSnapshot {
    pub plan_id: i64,
    pub plan_name: String,
    pub plan_type: String,
    pub traffic_limit: i64,
    pub max_rules: i32,
    pub grant_all_groups: bool,
    pub device_group_ids: Vec<i64>,
    pub billing_revision: i64,
}

impl EntitlementSnapshot {
    pub fn encode(&self) -> String {
        serde_json::to_string(self).expect("entitlement snapshot serializes")
    }
    pub fn decode(raw: &str) -> Result<Self, DbError> {
        serde_json::from_str(raw).map_err(|_| DbError::InvalidData("invalid entitlement snapshot"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SubscriptionCycle {
    pub id: String,
    pub subscription_id: String,
    pub user_id: i64,
    pub plan_id: i64,
    pub starts_at: String,
    pub ends_at: Option<String>,
    pub traffic_limit: i64,
    pub traffic_used: i64,
    pub entitlement_snapshot: String,
    pub source: String,
    pub cancelled: bool,
}

#[derive(sqlx::FromRow)]
pub struct CurrentEntitlement {
    pub current_cycle_id: Option<String>,
    pub plan_id: Option<i64>,
    pub plan_expire_at: Option<String>,
    pub traffic_limit: i64,
    pub traffic_used: i64,
    pub max_rules: i32,
    pub all_device_groups: bool,
    pub created_at: String,
    pub plan_source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct BalanceEntry {
    pub sequence: i64,
    pub id: String,
    pub user_id: i64,
    pub kind: String,
    pub amount_cents: i64,
    pub balance_before: String,
    pub balance_after: String,
    pub reference_id: String,
    pub actor_id: Option<i64>,
    pub reason: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Copy)]
pub struct BalanceChange<'a> {
    pub user_id: i64,
    pub kind: &'a str,
    pub before: &'a str,
    pub after: &'a str,
    pub reference_id: &'a str,
    pub actor_id: Option<i64>,
    pub reason: &'a str,
}

pub fn balance_delta(before: &str, after: &str) -> Result<i64, DbError> {
    let cents = |raw| {
        relay_shared::money::balance_to_cents(raw)
            .ok_or(DbError::InvalidData("non-canonical ledger balance"))
    };
    Ok(cents(after)? - cents(before)?)
}
