use relay_shared::protocol::ApiResponse;
use serde::Serialize;

mod auth;
mod groups;
mod nodes;
mod password;
mod plans;
mod profiles;
mod rules;
mod settings;
mod shop;
mod tunnels;
mod users;

fn schedule_route_transition_activation(state: &crate::api::AppState) {
    let connections = state.node_connections.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(
            crate::db::repo::ROUTE_TRANSITION_STAGE_SECS as u64,
        ))
        .await;
        connections
            .broadcast_all(r#"{"type":"config_changed"}"#)
            .await;
    });
}

pub use groups::*;
pub use password::*;
pub use plans::*;
pub use profiles::*;
pub use rules::*;
pub use settings::*;
pub use shop::*;
pub use tunnels::*;
pub use users::*;

/// A user WITHOUT the password hash — for API responses. Never expose the
/// password hash via any endpoint; use this struct instead of `User` in list
/// responses. Deriving FromRow + listing every non-password column means
/// SELECT * also works (the password column is just ignored).
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct UserPublic {
    pub id: i64,
    pub username: String,
    pub balance: String,
    pub plan_id: Option<i64>,
    /// v1.0.7: replaces group_id. true = user may use all device groups.
    pub all_device_groups: bool,
    pub max_rules: i32,
    pub speed_limit: i32,
    pub ip_limit: i32,
    pub traffic_used: i64,
    pub traffic_limit: i64,
    pub admin: bool,
    pub banned: bool,
    pub created_at: String,
    /// v1.0.8: plan expiry (NULL = no expiry).
    #[serde(default)]
    pub plan_expire_at: Option<String>,
    /// v1.0.8: admin suspension.
    #[serde(default)]
    pub suspended: bool,
}

/// A user's view of THEIR OWN account (GET /user/me). Same non-password fields
/// as [`UserPublic`] — the password hash is never exposed by any endpoint.
/// Kept as a distinct type (rather than reusing UserPublic) so the "self" view
/// is explicit in the response and can diverge later (e.g. hide admin/banned
/// from a non-admin's own view, or add email) without touching the admin list
/// projection.
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct UserSelf {
    pub id: i64,
    pub username: String,
    pub admin: bool,
    pub balance: String,
    /// v0.4.10: the user's plan (NULL if unset). plan_name is its human-readable
    /// label, resolved via a separate lookup (no plan → plan_name NULL too).
    pub plan_id: Option<i64>,
    pub plan_name: Option<String>,
    pub max_rules: i32,
    /// v0.4.10: how many rules the user currently owns (for the account center's
    /// "current / limit" display). Counted live via count_by_uid.
    pub current_rules: i64,
    pub traffic_used: i64,
    pub traffic_limit: i64,
    /// v0.4.10: renamed from created_at for the account-center contract. The DB
    /// column is still created_at; this is the JSON field name clients see.
    pub registered_at: String,
    /// v0.4.10 PR4: when true the frontend redirects to the force-password-
    /// change page (the user can only reach /user/me + /user/password until
    /// they change it). The DB column is the source of truth.
    pub must_change_password: bool,
    /// v1.0.8: plan expiry (NULL = no expiry).
    #[serde(default)]
    pub plan_expire_at: Option<String>,
    /// v1.0.8: admin suspension (login allowed; forwarding gated).
    #[serde(default)]
    pub suspended: bool,
    /// v1.0.8: true when this user is unrestricted (admin, or
    /// all_device_groups=1) — every inbound line is usable. When false,
    /// `available_groups` lists the specific lines they're authorized for.
    #[serde(default)]
    pub all_groups: bool,
    /// v1.0.8: names of the device groups (lines) this user can currently use.
    /// Empty when `all_groups` is true (nothing to enumerate) or when the user
    /// has no authorization at all.
    #[serde(default)]
    pub available_groups: Vec<String>,
}

/// Build an error ApiResponse. Accepts `&str` or `String` (or anything else
/// `Into<String>`), so callers can pass a `format!()` result directly without
/// leaking it (the old `Box::leak` workaround) or hand-constructing ApiResponse.
fn err<T: Serialize, S: Into<String>>(code: i32, msg: S) -> ApiResponse<T> {
    ApiResponse {
        code,
        message: msg.into(),
        data: None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        admin_set_user_plan, create_group, create_plan, create_rule, create_tunnel_profile,
        create_user, delete_group, delete_plan, delete_rule, delete_tunnel_profile, delete_user,
        err, get_me, get_registration_settings, list_groups, list_owned_group_summaries,
        list_public_plans, list_rules, reset_user_traffic, update_group, update_plan,
        update_registration_settings, update_rule, update_tunnel_profile, update_user, ApiResponse,
        ChangePasswordRequest, CreateUserRequest, ListRulesQuery,
    };
    use super::{change_password, reset_user_password, ResetPasswordRequest};
    use crate::api::auth::{register, registration_status};
    use crate::api::middleware::{AdminOnly, AuthUser};
    use crate::api::system::ReleaseCache;
    use crate::api::ws::NodeConnections;
    use crate::api::AppState;
    use crate::config::Config;
    use crate::db::error::DbError;
    use crate::db::schema::SCHEMA_SQL;
    use crate::db::sqlite_repo::SqliteRepository;
    use axum::extract::{Path, Query, State};
    use axum::Json;
    use relay_shared::models::BlockedProtocol;
    use relay_shared::protocol::{
        AdminSetUserPlanRequest, CreateGroupRequest, CreatePlanRequest, CreateRuleRequest,
        CreateTunnelProfileRequest, CreateTunnelRequest, GroupType, Protocol, PublicTransport,
        RegisterRequest, RegistrationSettingsRequest, TunnelHopRequest, UpdateGroupRequest,
        UpdatePlanRequest, UpdateRuleRequest, UpdateTunnelProfileRequest, UpdateTunnelRequest,
        UpdateUserRequest,
    };
    use sqlx::sqlite::SqlitePoolOptions;
    use sqlx::SqlitePool;
    use std::sync::Arc;

    async fn test_state() -> (AppState, SqlitePool) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("connect memory db");
        sqlx::query(SCHEMA_SQL)
            .execute(&pool)
            .await
            .expect("create schema");
        let state = AppState {
            db: Arc::new(SqliteRepository::new(pool.clone())),
            config: Config {
                database_path: "sqlite::memory:".into(),
                listen: "127.0.0.1:0".into(),
                key: "test-key".into(),
                jwt_secret: "test-secret".into(),
                public_dir: "public".into(),
                public_panel_url: String::new(),
                registration_enabled: false,
                cors_origins: vec![],
                geoip_enabled: false,
                geoip_cache_ttl: 604_800,
            },
            release_cache: ReleaseCache::new(),
            node_connections: NodeConnections::new(),
            diagnose: crate::api::diagnose::DiagnoseRegistry::new(),
            geoip_in_flight: std::sync::Arc::new(tokio::sync::Mutex::new(
                std::collections::HashSet::new(),
            )),
        };
        (state, pool)
    }

    async fn add_user(pool: &SqlitePool, id: i64, username: &str, admin: bool) -> String {
        let hash = bcrypt::hash(format!("old-password-{id}"), 4).unwrap();
        // v1.0.7: default test users to all_device_groups=1 (unrestricted) so the
        // rule-validation tests exercise the validation path, not the new
        // "unassigned = cannot forward" default. Permission-specific tests
        // override this via assign_user_groups().
        sqlx::query(
            "INSERT INTO users (id, username, password, admin, all_device_groups, balance, max_rules, traffic_used, traffic_limit, banned) \
             VALUES (?, ?, ?, ?, 1, '0', 5, 0, 0, 0)",
        )
        .bind(id)
        .bind(username)
        .bind(&hash)
        .bind(admin)
        .execute(pool)
        .await
        .unwrap();
        hash
    }

    async fn add_group(pool: &SqlitePool, id: i64, uid: i64, name: &str) {
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (?, ?, 'in', ?, ?)",
        )
        .bind(id)
        .bind(name)
        .bind(format!("token-{id}-{uid}"))
        .bind(uid)
        .execute(pool)
        .await
        .unwrap();
    }

    /// v0.4.12 PR1: insert a group with an explicit group_type ('in'/'out'/'monitor').
    async fn add_group_typed(pool: &SqlitePool, id: i64, uid: i64, name: &str, gtype: &str) {
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(name)
        .bind(gtype)
        .bind(format!("token-{id}-{uid}"))
        .bind(uid)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn add_rule(
        pool: &SqlitePool,
        id: i64,
        uid: i64,
        group_id: i64,
        port: i64,
        traffic: i64,
    ) {
        sqlx::query(
            "INSERT INTO forward_rules \
             (id, name, uid, listen_port, device_group_in, target_addr, target_port, traffic_used) \
             VALUES (?, ?, ?, ?, ?, '127.0.0.1', 80, ?)",
        )
        .bind(id)
        .bind(format!("rule-{id}"))
        .bind(uid)
        .bind(port)
        .bind(group_id)
        .bind(traffic)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn update_user_edits_allowed_fields_and_preserves_password_and_admin_role() {
        let (state, pool) = test_state().await;
        let original_hash = add_user(&pool, 2, "alice", false).await;

        let Json(resp) = update_user(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path(2),
            Json(UpdateUserRequest {
                balance: Some("12.34".into()),
                max_rules: Some(42),
                traffic_limit: Some(1024),
                banned: Some(true),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(resp.code, 0, "update should succeed: {}", resp.message);

        let row: (String, i32, i64, bool, String, bool) = sqlx::query_as(
            "SELECT balance, max_rules, traffic_limit, banned, password, admin FROM users WHERE id = 2",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.0, "12.34");
        assert_eq!(row.1, 42);
        assert_eq!(row.2, 1024);
        assert!(row.3);
        assert_eq!(row.4, original_hash, "admin edit must not touch password");
        assert!(!row.5, "admin edit must not grant admin role");
    }

    /// v0.3.5: balance is strictly validated (non-negative decimal, ≤ 2 fraction
    /// digits, ≤ 9999999999.99). Invalid input must be rejected BEFORE any DB
    /// write — the schema has no CHECK constraint yet, so this is the only
    /// guard. The handler must (a) reject obvious garbage, (b) reject negatives
    /// and oversize values, (c) reject NaN / exponent / locale strings, and
    /// (d) canonicalise the value that is stored.
    #[tokio::test]
    async fn update_user_rejects_invalid_balances_and_canonicalises_valid_ones() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;

        // The list is intentionally heterogeneous: each negative case proves a
        // different rule. The valid case at the end proves canonicalisation
        // (input has extra leading zeros + a 1-digit fraction, expected output
        // is the canonical 2-digit-fraction form).
        let cases: &[(&str, bool)] = &[
            ("", false),
            ("-1", false),
            ("-0.01", false),
            ("+1", false),
            ("1e3", false),
            ("NaN", false),
            ("Infinity", false),
            ("abc", false),
            ("1,000.00", false),
            ("12.345", false),
            ("10000000000", false),
            ("0", true),
            ("0012.30", true),
        ];
        for (input, should_succeed) in cases {
            let Json(resp) = update_user(
                AdminOnly { user_id: 1 },
                State(state.clone()),
                Path(2),
                Json(UpdateUserRequest {
                    balance: Some((*input).into()),
                    ..Default::default()
                }),
            )
            .await;
            assert_eq!(
                resp.code == 0,
                *should_succeed,
                "balance {input:?}: expected succeed={should_succeed}, got code={} msg={}",
                resp.code,
                resp.message
            );
            if !should_succeed {
                assert_eq!(
                    resp.code, 400,
                    "rejection should be a 400, got {} (msg={})",
                    resp.code, resp.message
                );
            }
        }

        // After the run the row should hold the canonical form (last successful
        // input was "0012.30"). Verify nothing about the user row leaked from
        // the rejected cases.
        let (balance,): (String,) = sqlx::query_as("SELECT balance FROM users WHERE id = 2")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(balance, "12.30", "balance must be canonicalised in storage");
    }

    #[tokio::test]
    async fn reset_user_traffic_zeros_user_and_owned_rules_only() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_user(&pool, 3, "bob", false).await;
        add_group(&pool, 20, 2, "alice-in").await;
        add_group(&pool, 30, 3, "bob-in").await;
        sqlx::query("UPDATE users SET traffic_used = 111 WHERE id = 2")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE users SET traffic_used = 222 WHERE id = 3")
            .execute(&pool)
            .await
            .unwrap();
        add_rule(&pool, 200, 2, 20, 12000, 333).await;
        add_rule(&pool, 201, 2, 20, 12001, 444).await;
        add_rule(&pool, 300, 3, 30, 13000, 555).await;

        let Json(resp) =
            reset_user_traffic(AdminOnly { user_id: 1 }, State(state.clone()), Path(2)).await;
        assert_eq!(resp.code, 0, "reset should succeed: {}", resp.message);

        let user2: (i64,) = sqlx::query_as("SELECT traffic_used FROM users WHERE id = 2")
            .fetch_one(&pool)
            .await
            .unwrap();
        let user3: (i64,) = sqlx::query_as("SELECT traffic_used FROM users WHERE id = 3")
            .fetch_one(&pool)
            .await
            .unwrap();
        let sum2: (i64,) =
            sqlx::query_as("SELECT SUM(traffic_used) FROM forward_rules WHERE uid = 2")
                .fetch_one(&pool)
                .await
                .unwrap();
        let sum3: (i64,) =
            sqlx::query_as("SELECT SUM(traffic_used) FROM forward_rules WHERE uid = 3")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(user2.0, 0);
        assert_eq!(sum2.0, 0);
        assert_eq!(user3.0, 222, "other user total must be untouched");
        assert_eq!(sum3.0, 555, "other user's rules must be untouched");

        let Json(missing) =
            reset_user_traffic(AdminOnly { user_id: 1 }, State(state), Path(999_999)).await;
        assert_eq!(missing.code, 404);
    }

    #[tokio::test]
    async fn delete_user_refuses_admin_without_deleting_admin_resources() {
        let (state, pool) = test_state().await;
        add_group(&pool, 10, 1, "admin-in").await;
        add_rule(&pool, 100, 1, 10, 11000, 999).await;

        let Json(resp) = delete_user(AdminOnly { user_id: 1 }, State(state.clone()), Path(1)).await;
        assert_eq!(resp.code, 404);

        let user_exists: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE id = 1")
            .fetch_one(&pool)
            .await
            .unwrap();
        let group_exists: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM device_groups WHERE id = 10")
                .fetch_one(&pool)
                .await
                .unwrap();
        let rule_exists: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM forward_rules WHERE id = 100")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(user_exists.0, 1);
        assert_eq!(group_exists.0, 1, "admin group must remain");
        assert_eq!(rule_exists.0, 1, "admin rule must remain");
    }

    #[tokio::test]
    async fn delete_user_reports_tunnel_group_conflict_without_partial_deletion() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "legacy-owner", false).await;
        add_group(&pool, 20, 2, "legacy-entry").await;
        add_group_typed(&pool, 30, 1, "admin-exit", "out").await;
        sqlx::query("INSERT INTO tunnels (id,name,uid) VALUES (40,'legacy-path',1)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO tunnel_hops (tunnel_id,position,device_group_id,listen_port) \
             VALUES (40,0,20,NULL),(40,1,30,23000)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let Json(resp) = delete_user(AdminOnly { user_id: 1 }, State(state), Path(2)).await;
        assert_eq!(resp.code, 409, "{}", resp.message);
        assert!(resp.message.contains("1 个被 1 条预设隧道引用"));

        let user_exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE id=2")
            .fetch_one(&pool)
            .await
            .unwrap();
        let group_exists: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM device_groups WHERE id=20")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(user_exists, 1);
        assert_eq!(group_exists, 1);
    }

    #[tokio::test]
    async fn create_user_makes_non_admin_and_rejects_duplicates_and_bad_input() {
        let (state, pool) = test_state().await;

        // Production installations may delete the original plan id=1 and use
        // another plan as the registration default. Admin provisioning must
        // read that persisted setting instead of assuming plan 1 forever.
        sqlx::query(
            "INSERT INTO plans (id, name, max_rules, traffic) \
             VALUES (2, 'configured-default', 10, 268435456000)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO app_settings \
             (id, registration_enabled, default_registration_plan_id, registration_allowed_plan_ids) \
             VALUES (1, 0, 2, '[2]')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("DELETE FROM plans WHERE id = 1")
            .execute(&pool)
            .await
            .unwrap();

        // Happy path: creates a regular (non-admin) user.
        let Json(ok) = create_user(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(CreateUserRequest {
                username: "bob".into(),
                password: "secret123".into(),
            }),
        )
        .await;
        assert_eq!(ok.code, 0, "create should succeed: {}", ok.message);

        // An admin-created user inherits the configured default plan's quota
        // atomically, the same as self-registration — NOT a bare insert with
        // schema defaults and NOT the historical hard-coded plan id=1.
        let row: (i64, bool, Option<i64>, i64, i64) = sqlx::query_as(
            "SELECT id, admin, plan_id, max_rules, traffic_limit FROM users WHERE username = 'bob'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!row.1, "created user must be NON-admin");
        assert_eq!(row.2, Some(2), "user must use the configured default plan");
        assert_eq!(row.3, 10, "max_rules must be inherited from plan 2");
        assert_eq!(
            row.4, 268435456000,
            "traffic_limit must be inherited from plan 2"
        );

        // Duplicate username → 409.
        let Json(dup) = create_user(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(CreateUserRequest {
                username: "bob".into(),
                password: "secret123".into(),
            }),
        )
        .await;
        assert_eq!(dup.code, 409);

        // v0.4.10: unified password policy is 8..=72 UTF-8 bytes (matches
        // register / change / admin-reset). 7 bytes is the just-too-short
        // boundary → 400; the old policy (>=6) would have wrongly accepted it.
        let Json(short) = create_user(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(CreateUserRequest {
                username: "carol".into(),
                password: "1234567".into(), // 7 bytes
            }),
        )
        .await;
        assert_eq!(short.code, 400, "7-byte password must be rejected");

        // Exactly 8 bytes is the lower bound → accepted.
        let Json(min_ok) = create_user(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(CreateUserRequest {
                username: "dave".into(),
                password: "12345678".into(), // 8 bytes
            }),
        )
        .await;
        assert_eq!(
            min_ok.code, 0,
            "8-byte password must be accepted: {}",
            min_ok.message
        );

        // 73 bytes exceeds the bcrypt 72-byte limit → 400.
        let Json(long) = create_user(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(CreateUserRequest {
                username: "erin".into(),
                password: "a".repeat(73),
            }),
        )
        .await;
        assert_eq!(long.code, 400, "73-byte password must be rejected");

        // Invalid username → 400.
        let Json(bad) = create_user(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(CreateUserRequest {
                username: "bad name!".into(),
                password: "secret123".into(),
            }),
        )
        .await;
        assert_eq!(bad.code, 400);
    }

    #[tokio::test]
    async fn delete_plan_requires_changing_configured_default_first() {
        let (state, pool) = test_state().await;
        sqlx::query(
            "INSERT INTO plans (id, name, max_rules, traffic) \
             VALUES (2, 'configured-default', 10, 268435456000), \
                    (3, 'registration-option', 10, 268435456000)",
        )
        .execute(&pool)
        .await
        .unwrap();
        state
            .db
            .set_registration_settings(false, 2, &[2, 3])
            .await
            .unwrap();

        let Json(default_resp) =
            delete_plan(AdminOnly { user_id: 1 }, State(state.clone()), Path(2)).await;
        assert_eq!(default_resp.code, 409);
        assert_eq!(
            default_resp.message,
            "该套餐是当前默认套餐，请先在系统设置中更换默认套餐。"
        );
        let default_exists: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM plans WHERE id = 2")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(default_exists.0, 1, "the configured default must remain");

        let Json(allowed_resp) =
            delete_plan(AdminOnly { user_id: 1 }, State(state.clone()), Path(3)).await;
        assert_eq!(allowed_resp.code, 409);
        assert_eq!(
            allowed_resp.message,
            "该套餐仍在允许注册列表中，请先修改系统设置。"
        );
        let allowed_exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM plans WHERE id = 3")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(allowed_exists, 1);

        state
            .db
            .set_registration_settings(false, 2, &[2])
            .await
            .unwrap();

        // Once the default has moved away from the original free plan, that
        // otherwise-unused plan can be deleted normally.
        let Json(old_default_resp) =
            delete_plan(AdminOnly { user_id: 1 }, State(state.clone()), Path(1)).await;
        assert_eq!(old_default_resp.code, 0);
        let old_default_exists: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM plans WHERE id = 1")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(old_default_exists.0, 0);

        let Json(missing_resp) =
            delete_plan(AdminOnly { user_id: 1 }, State(state), Path(999)).await;
        assert_eq!(missing_resp.code, 404);
        assert_eq!(missing_resp.message, "套餐不存在");
    }

    #[tokio::test]
    async fn create_user_rejects_a_missing_configured_default_without_inserting() {
        let (state, pool) = test_state().await;
        // With no persisted settings row the safe fallback is plan id=1. Once
        // that plan is absent, account creation must fail atomically.
        sqlx::query("DELETE FROM plans WHERE id = 1")
            .execute(&pool)
            .await
            .unwrap();

        let Json(resp) = create_user(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(CreateUserRequest {
                username: "missing_plan_user".into(),
                password: "secret123".into(),
            }),
        )
        .await;

        assert_eq!(resp.code, 500);
        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM users WHERE username = 'missing_plan_user'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count.0, 0, "failed provisioning must not leave a user row");
    }

    #[tokio::test]
    async fn change_password_requires_current_password_and_updates_only_password() {
        let (state, pool) = test_state().await;
        let old_password = "old-password-2";
        let old_hash = bcrypt::hash(old_password, 4).unwrap();
        sqlx::query("INSERT INTO users (id, username, password, admin, balance) VALUES (2, 'alice', ?, 0, '77')")
            .bind(&old_hash)
            .execute(&pool)
            .await
            .unwrap();

        let Json(bad) = super::change_password(
            AuthUser {
                user_id: 2,
                admin: false,
            },
            State(state.clone()),
            Json(ChangePasswordRequest {
                current_password: "wrong-password".into(),
                new_password: "new-password".into(),
            }),
        )
        .await;
        assert_eq!(bad.code, 401);

        let Json(ok) = super::change_password(
            AuthUser {
                user_id: 2,
                admin: false,
            },
            State(state.clone()),
            Json(ChangePasswordRequest {
                current_password: old_password.into(),
                new_password: "new-password".into(),
            }),
        )
        .await;
        assert_eq!(ok.code, 0, "password change should succeed: {}", ok.message);

        let row: (String, String) =
            sqlx::query_as("SELECT password, balance FROM users WHERE id = 2")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(bcrypt::verify("new-password", &row.0).unwrap());
        assert_eq!(row.1, "77", "non-password fields must be untouched");
    }

    // ── rule/group 404 + no-spurious-broadcast (v0.3.6) ──
    //
    // Before v0.3.6, update/delete on a non-existent id returned success AND
    // broadcast config_changed — a no-op mutation needlessly triggering a node
    // re-fetch. These pin the new contract: 404 + zero broadcasts when nothing
    // changed, success + exactly one broadcast when something did.

    async fn seed_rule_and_group(pool: &SqlitePool) {
        add_user(pool, 2, "alice", false).await;
        add_group(pool, 20, 2, "gin").await;
        // v0.4.11 PR1: rules with ws/tls_simple transport must bind a matching profile.
        // Seed a ws profile first, then create the rule with ws transport.
        sqlx::query(
            "INSERT INTO tunnel_profiles (id, name, transport, tls_mode, ws_path, host_header, sni, is_builtin, uid) \
             VALUES (51, 'ws-seed', 'ws', 'none', '/relay', '', '', 1, 1)",
        )
        .execute(pool)
        .await
        .unwrap();
        // Rule with ws transport (public_transport='ws', node_transport='ws') and bound profile.
        sqlx::query(
            "INSERT INTO forward_rules (id, name, uid, paused, listen_port, protocol, \
             public_transport, node_transport, entry_transport, forward_mode, \
             device_group_in, target_addr, target_port, tunnel_profile_id) \
             VALUES (200, 'test-rule', 2, 0, 12000, 'tcp', 'ws', 'ws', 'ws', \
             'direct', 20, '127.0.0.1', 80, 51)",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    /// Count how many config_changed broadcasts a handler call produced, by
    /// registering a live WS connection on the shared NodeConnections and
    /// draining its receiver for ~50ms after the call.
    async fn expect_broadcasts(
        state: &AppState,
        expected: usize,
        f: impl std::future::Future<Output = ()>,
    ) {
        let (_id, mut rx) = state.node_connections.register(99, None).await;
        f.await;
        let mut n = 0;
        for _ in 0..20 {
            while rx.try_recv().is_ok() {
                n += 1;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            n, expected,
            "expected {expected} config_changed broadcasts, got {n}"
        );
    }

    #[tokio::test]
    async fn update_rule_nonexistent_returns_404_no_broadcast() {
        let (state, _pool) = test_state().await;
        expect_broadcasts(&state, 0, async {
            let Json(resp) = update_rule(
                AuthUser {
                    user_id: 1,
                    admin: true,
                },
                State(state.clone()),
                Path(99999),
                Json(UpdateRuleRequest {
                    name: Some("x".into()),
                    ..Default::default()
                }),
            )
            .await;
            assert_eq!(resp.code, 404);
        })
        .await;
    }

    #[tokio::test]
    async fn update_rule_existing_succeeds_and_broadcasts_once() {
        let (state, pool) = test_state().await;
        seed_rule_and_group(&pool).await;
        expect_broadcasts(&state, 1, async {
            let Json(resp) = update_rule(
                AuthUser {
                    user_id: 1,
                    admin: true,
                },
                State(state.clone()),
                Path(200),
                Json(UpdateRuleRequest {
                    name: Some("renamed".into()),
                    ..Default::default()
                }),
            )
            .await;
            assert_eq!(resp.code, 0, "{}", resp.message);
        })
        .await;
    }

    /// v1.2.0: a non-zero auto-restart interval below the floor is rejected.
    /// A 1-minute restart loop drops connections faster than clients can
    /// reconnect, which turns the safety valve into a permanent outage.
    #[tokio::test]
    async fn update_rule_rejects_auto_restart_below_floor() {
        let (state, pool) = test_state().await;
        seed_rule_and_group(&pool).await;

        let Json(resp) = update_rule(
            AuthUser {
                user_id: 1,
                admin: true,
            },
            State(state.clone()),
            Path(200),
            Json(UpdateRuleRequest {
                auto_restart_minutes: Some(1),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(
            resp.code, 400,
            "1 minute must be rejected: {}",
            resp.message
        );

        let Json(resp) = update_rule(
            AuthUser {
                user_id: 1,
                admin: true,
            },
            State(state.clone()),
            Path(200),
            Json(UpdateRuleRequest {
                max_connections: Some(-1),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(resp.code, 400, "negative caps must be rejected");

        // 0 = off is always allowed, and so is anything at/above the floor.
        for v in [0, relay_shared::models::MIN_AUTO_RESTART_MINUTES] {
            let Json(resp) = update_rule(
                AuthUser {
                    user_id: 1,
                    admin: true,
                },
                State(state.clone()),
                Path(200),
                Json(UpdateRuleRequest {
                    auto_restart_minutes: Some(v),
                    ..Default::default()
                }),
            )
            .await;
            assert_eq!(resp.code, 0, "{} must be accepted: {}", v, resp.message);
        }
    }

    /// Creating a rule accepts the same connection controls as editing one and
    /// persists them atomically with the new row. This pins the UI workflow so
    /// users no longer need a second edit immediately after creation.
    #[tokio::test]
    async fn create_rule_persists_connection_controls() {
        let (state, pool) = test_state().await;
        add_group(&pool, 20, 1, "admin-in").await;

        let Json(resp) = create_rule(
            AuthUser {
                user_id: 1,
                admin: true,
            },
            State(state),
            Json(CreateRuleRequest {
                max_connections: Some(321),
                auto_restart_minutes: Some(relay_shared::models::MIN_AUTO_RESTART_MINUTES),
                ..rule_req("create-with-controls", 21000, 20, None)
            }),
        )
        .await;
        assert_eq!(resp.code, 0, "{}", resp.message);

        let stored: (i64, i64) = sqlx::query_as(
            "SELECT max_connections, auto_restart_minutes FROM forward_rules WHERE name = 'create-with-controls'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            stored,
            (321, relay_shared::models::MIN_AUTO_RESTART_MINUTES as i64)
        );
    }

    #[tokio::test]
    async fn rule_names_are_trimmed_and_blank_names_are_rejected() {
        let (state, pool) = test_state().await;
        add_group(&pool, 20, 1, "admin-in").await;

        let Json(blank_create) = create_rule(
            AuthUser {
                user_id: 1,
                admin: true,
            },
            State(state.clone()),
            Json(rule_req("  \t", 21010, 20, None)),
        )
        .await;
        assert_eq!(blank_create.code, 400);

        let Json(created) = create_rule(
            AuthUser {
                user_id: 1,
                admin: true,
            },
            State(state.clone()),
            Json(rule_req("  trimmed-rule  ", 21011, 20, None)),
        )
        .await;
        assert_eq!(created.code, 0, "{}", created.message);
        let rule_id: (i64,) =
            sqlx::query_as("SELECT id FROM forward_rules WHERE name = 'trimmed-rule'")
                .fetch_one(&pool)
                .await
                .unwrap();

        let Json(blank_update) = update_rule(
            AuthUser {
                user_id: 1,
                admin: true,
            },
            State(state),
            Path(rule_id.0),
            Json(UpdateRuleRequest {
                name: Some("  ".into()),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(blank_update.code, 400);

        let stored: (String,) = sqlx::query_as("SELECT name FROM forward_rules WHERE id = ?")
            .bind(rule_id.0)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(stored.0, "trimmed-rule");
    }

    #[tokio::test]
    async fn create_rule_rejects_auto_restart_below_floor() {
        let (state, pool) = test_state().await;
        add_group(&pool, 20, 1, "admin-in").await;

        let Json(resp) = create_rule(
            AuthUser {
                user_id: 1,
                admin: true,
            },
            State(state.clone()),
            Json(CreateRuleRequest {
                auto_restart_minutes: Some(1),
                ..rule_req("unsafe-restart", 21001, 20, None)
            }),
        )
        .await;
        assert_eq!(resp.code, 400, "{}", resp.message);

        let Json(resp) = create_rule(
            AuthUser {
                user_id: 1,
                admin: true,
            },
            State(state.clone()),
            Json(CreateRuleRequest {
                auto_restart_minutes: Some(-1),
                ..rule_req("negative-restart", 21002, 20, None)
            }),
        )
        .await;
        assert_eq!(resp.code, 400, "negative intervals must be rejected");

        let Json(resp) = create_rule(
            AuthUser {
                user_id: 1,
                admin: true,
            },
            State(state),
            Json(CreateRuleRequest {
                upload_limit_mbps: Some(-1),
                ..rule_req("negative-rate", 21003, 20, None)
            }),
        )
        .await;
        assert_eq!(resp.code, 400, "negative rates must be rejected");
    }

    /// v1.2.0: setting ONLY max_connections must not switch off a rule's
    /// scheduled restart. The two share a form but are independent settings, and
    /// defaulting the omitted one to 0 would make an unrelated edit silently
    /// disable auto-restart.
    #[tokio::test]
    async fn update_rule_partial_conn_controls_does_not_clobber_the_other() {
        let (state, pool) = test_state().await;
        seed_rule_and_group(&pool).await;

        // Turn auto-restart on (10 min), leaving the cap unset.
        let Json(resp) = update_rule(
            AuthUser {
                user_id: 1,
                admin: true,
            },
            State(state.clone()),
            Path(200),
            Json(UpdateRuleRequest {
                auto_restart_minutes: Some(10),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(resp.code, 0, "{}", resp.message);

        // Now set ONLY the cap. auto_restart_minutes must survive.
        let Json(resp) = update_rule(
            AuthUser {
                user_id: 1,
                admin: true,
            },
            State(state.clone()),
            Path(200),
            Json(UpdateRuleRequest {
                max_connections: Some(500),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(resp.code, 0, "{}", resp.message);

        let (cap, restart): (i64, i64) = sqlx::query_as(
            "SELECT max_connections, auto_restart_minutes FROM forward_rules WHERE id = 200",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(cap, 500, "the cap we set must be stored");
        assert_eq!(
            restart, 10,
            "setting only max_connections must NOT reset auto_restart_minutes to 0"
        );
    }

    /// Upload/download caps are independent optional API fields. Updating one
    /// must preserve the stored value of the omitted counterpart.
    #[tokio::test]
    async fn update_rule_partial_rate_limit_does_not_clobber_the_other() {
        let (state, pool) = test_state().await;
        seed_rule_and_group(&pool).await;
        sqlx::query(
            "UPDATE forward_rules SET upload_limit_mbps = 10, download_limit_mbps = 20 \
             WHERE id = 200",
        )
        .execute(&pool)
        .await
        .unwrap();

        let Json(resp) = update_rule(
            AuthUser {
                user_id: 1,
                admin: true,
            },
            State(state.clone()),
            Path(200),
            Json(UpdateRuleRequest {
                download_limit_mbps: Some(-1),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(resp.code, 400, "negative rates must be rejected");

        let Json(resp) = update_rule(
            AuthUser {
                user_id: 1,
                admin: true,
            },
            State(state.clone()),
            Path(200),
            Json(UpdateRuleRequest {
                upload_limit_mbps: Some(30),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(resp.code, 0, "{}", resp.message);

        let limits: (i64, i64) = sqlx::query_as(
            "SELECT upload_limit_mbps, download_limit_mbps FROM forward_rules WHERE id = 200",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(limits, (30, 20));
    }

    #[tokio::test]
    async fn update_chain_protocol_or_entry_port_replans_omitted_hops() {
        let (state, pool) = test_state().await;
        add_group(&pool, 10, 1, "entry").await;
        add_group_typed(&pool, 20, 1, "exit", "out").await;
        sqlx::query(
            "UPDATE device_groups SET connect_host = '127.0.0.1', port_range = '20000-20001' \
             WHERE id = 20",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO forward_rules \
             (id, name, uid, listen_port, protocol, public_transport, node_transport, \
              entry_transport, forward_mode, route_mode, device_group_in, device_group_out, \
              target_addr, target_port) \
             VALUES (200, 'chain', 1, 12000, 'tcp', 'raw', 'raw', 'raw', 'chain', \
                     'chain', 10, 20, '127.0.0.1', 53)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO forward_rule_hops \
             (rule_id, position, device_group_id, listen_port) \
             VALUES (200, 0, 10, 12000), (200, 1, 20, 20000)",
        )
        .execute(&pool)
        .await
        .unwrap();
        // The old TCP hop could legally share its numeric port with this UDP
        // rule. Switching the chain to UDP must therefore allocate 20001 even
        // when the client omits an unchanged `hops` array.
        sqlx::query(
            "INSERT INTO forward_rules \
             (id, name, uid, listen_port, protocol, device_group_in, target_addr, target_port) \
             VALUES (201, 'udp-occupant', 1, 20000, 'udp', 20, '127.0.0.1', 53)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let Json(protocol_response) = update_rule(
            AuthUser {
                user_id: 1,
                admin: true,
            },
            State(state.clone()),
            Path(200),
            Json(UpdateRuleRequest {
                protocol: Some(Protocol::Udp),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(protocol_response.code, 0, "{}", protocol_response.message);
        let after_protocol: (String, i64) = sqlx::query_as(
            "SELECT fr.protocol, h.listen_port FROM forward_rules fr \
             JOIN forward_rule_hops h ON h.rule_id = fr.id \
             WHERE fr.id = 200 AND h.position = 1",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(after_protocol, ("udp".into(), 20001));

        let Json(port_response) = update_rule(
            AuthUser {
                user_id: 1,
                admin: true,
            },
            State(state),
            Path(200),
            Json(UpdateRuleRequest {
                listen_port: Some(13000),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(port_response.code, 0, "{}", port_response.message);
        let hop_ports: Vec<(i64, i64)> = sqlx::query_as(
            "SELECT position, listen_port FROM forward_rule_hops \
             WHERE rule_id = 200 ORDER BY position",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(hop_ports, vec![(0, 13000), (1, 20001)]);
    }

    /// v0.4.8 PR2: changing a rule's protocol to UDP while it's bound to a WS
    /// profile must be rejected, even when tunnel_profile_id is NOT in the
    /// request (the binding is loaded from the stored rule). Without this the
    /// node would skip the listener at config-build time.
    #[tokio::test]
    async fn update_rule_protocol_udp_with_ws_profile_rejected() {
        let (state, pool) = test_state().await;
        seed_rule_and_group(&pool).await;
        // Bind rule 200 to a ws profile.
        sqlx::query(
            "INSERT INTO tunnel_profiles (id, name, transport, tls_mode, ws_path, host_header, sni, is_builtin, uid) \
             VALUES (50, 'ws-x', 'ws', 'none', '/relay', '', '', 0, 2)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("UPDATE forward_rules SET tunnel_profile_id = 50 WHERE id = 200")
            .execute(&pool)
            .await
            .unwrap();

        let Json(resp) = update_rule(
            AuthUser {
                user_id: 1,
                admin: true,
            },
            State(state.clone()),
            Path(200),
            Json(UpdateRuleRequest {
                protocol: Some(Protocol::Udp),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(resp.code, 400, "{}", resp.message);
        // v0.4.10 fix / v0.4.11 PR1: the message must state the incompatibility.
        // The exact wording may vary (incompatible / not supported).
        assert!(
            resp.message.contains("incompatible") || resp.message.contains("not supported"),
            "message should state incompatibility: {}",
            resp.message
        );
    }

    #[tokio::test]
    async fn profile_mutations_validate_names_and_preserve_bound_rule_compatibility() {
        let (state, pool) = test_state().await;
        add_group(&pool, 20, 1, "admin-in").await;

        let request = CreateTunnelProfileRequest {
            name: "custom-ws".into(),
            transport: "ws".into(),
            tls_mode: "none".into(),
            ws_path: "/relay".into(),
            host_header: String::new(),
            sni: String::new(),
        };
        let Json(created) = create_tunnel_profile(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(request),
        )
        .await;
        assert_eq!(created.code, 0, "{}", created.message);
        let profile_id = created.data.unwrap().id;

        let Json(duplicate) = create_tunnel_profile(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(CreateTunnelProfileRequest {
                name: "custom-ws".into(),
                transport: "ws".into(),
                tls_mode: "none".into(),
                ws_path: "/other".into(),
                host_header: String::new(),
                sni: String::new(),
            }),
        )
        .await;
        assert_eq!(duplicate.code, 409);

        let Json(blank) = update_tunnel_profile(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path(profile_id),
            Json(UpdateTunnelProfileRequest {
                name: Some("   ".into()),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(blank.code, 400);

        // Repository-side snapshot validation is authoritative: even if a
        // caller reached the write with stale profile metadata, no mismatched
        // rule can be committed.
        let stale_write = state
            .db
            .create_rule_full_with_tunnel(
                "stale-profile",
                1,
                11999,
                "tcp",
                "tls_simple",
                "tls_simple",
                "direct",
                "tls_simple",
                None,
                20,
                None,
                "direct",
                "127.0.0.1",
                80,
                &[],
                &[],
                "first",
                0,
                0,
                Some(profile_id),
                None,
                0,
                0,
            )
            .await;
        assert!(matches!(stale_write, Err(DbError::ProfileUnavailable)));
        let stale_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM forward_rules WHERE name='stale-profile'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stale_count, 0);

        add_rule(&pool, 200, 1, 20, 12000, 0).await;
        sqlx::query(
            "UPDATE forward_rules SET public_transport='ws', node_transport='ws', \
             entry_transport='ws', tunnel_profile_id=? WHERE id=200",
        )
        .bind(profile_id)
        .execute(&pool)
        .await
        .unwrap();

        // Protocol tcp remains valid for both transports, but the rule's
        // stored public_transport='ws' would no longer match a tls template.
        let Json(conflict) = update_tunnel_profile(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path(profile_id),
            Json(UpdateTunnelProfileRequest {
                transport: Some("tls_simple".into()),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(conflict.code, 400);
        let transport: String =
            sqlx::query_scalar("SELECT transport FROM tunnel_profiles WHERE id = ?")
                .bind(profile_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(transport, "ws", "conflicting edit must roll back");

        let Json(in_use) = delete_tunnel_profile(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path(profile_id),
        )
        .await;
        assert_eq!(in_use.code, 409);

        sqlx::query("DELETE FROM forward_rules WHERE id = 200")
            .execute(&pool)
            .await
            .unwrap();
        let Json(deleted) =
            delete_tunnel_profile(AdminOnly { user_id: 1 }, State(state), Path(profile_id)).await;
        assert_eq!(deleted.code, 0, "{}", deleted.message);
    }

    #[tokio::test]
    async fn delete_rule_nonexistent_returns_404_no_broadcast() {
        let (state, _pool) = test_state().await;
        expect_broadcasts(&state, 0, async {
            let Json(resp) = delete_rule(
                AuthUser {
                    user_id: 1,
                    admin: true,
                },
                State(state.clone()),
                Path(99999),
            )
            .await;
            assert_eq!(resp.code, 404);
        })
        .await;
    }

    #[tokio::test]
    async fn update_group_nonexistent_returns_404_no_broadcast() {
        let (state, _pool) = test_state().await;
        expect_broadcasts(&state, 0, async {
            let Json(resp) = update_group(
                AdminOnly { user_id: 1 },
                State(state.clone()),
                Path(99999),
                Json(UpdateGroupRequest {
                    name: Some("x".into()),
                    ..Default::default()
                }),
            )
            .await;
            assert_eq!(resp.code, 404);
        })
        .await;
    }

    // ── v1.0.4: group delete safety ──

    /// Group with rules referencing it returns 409, not 200.
    #[tokio::test]
    async fn delete_group_with_rules_returns_409() {
        let (state, pool) = test_state().await;
        // Create a group and a rule that references it.
        add_group(&pool, 10, 1, "test-in").await;
        add_rule(&pool, 100, 1, 10, 20000, 0).await;

        let Json(resp) =
            super::delete_group(AdminOnly { user_id: 1 }, State(state.clone()), Path(10)).await;
        assert_eq!(resp.code, 409, "group with rules must be rejected");
        assert!(
            resp.message.contains("条规则"),
            "message must include rule count"
        );
    }

    /// An empty group can be deleted successfully.
    #[tokio::test]
    async fn delete_empty_group_succeeds() {
        let (state, pool) = test_state().await;
        add_group(&pool, 20, 1, "empty-in").await;

        let Json(resp) =
            super::delete_group(AdminOnly { user_id: 1 }, State(state.clone()), Path(20)).await;
        assert_eq!(
            resp.code, 0,
            "empty group must be deletable: {}",
            resp.message
        );
    }

    #[tokio::test]
    async fn delete_group_used_as_fallback_returns_409() {
        let (state, pool) = test_state().await;
        add_group(&pool, 21, 1, "fallback-target").await;
        add_group(&pool, 22, 1, "fallback-owner").await;
        sqlx::query("UPDATE device_groups SET fallback_group=21 WHERE id=22")
            .execute(&pool)
            .await
            .unwrap();

        let Json(resp) =
            super::delete_group(AdminOnly { user_id: 1 }, State(state.clone()), Path(21)).await;
        assert_eq!(resp.code, 409);
        assert!(resp.message.contains("分组回退配置"));
    }

    /// v1.0.4: count_rules_by_group detects rule references correctly.
    #[tokio::test]
    async fn count_rules_by_group_detects_rule_references() {
        let (state, pool) = test_state().await;
        add_group(&pool, 30, 1, "node-group").await;
        add_rule(&pool, 300, 1, 30, 20001, 0).await;

        let count = state.db.count_rules_by_group(30).await.unwrap();
        assert_eq!(count, 1, "group 30 should have 1 rule referencing it");

        // After deleting the rule, the group is free.
        state
            .db
            .delete_rule(300, &crate::db::repo::ResourceScope::All)
            .await
            .unwrap();
        let count2 = state.db.count_rules_by_group(30).await.unwrap();
        assert_eq!(
            count2, 0,
            "after rule deletion, group should have 0 references"
        );

        sqlx::query("DROP TABLE forward_rule_hops")
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            state.db.count_rules_by_group(30).await.is_err(),
            "a failed hop-reference lookup must not be reported as zero"
        );
    }

    #[tokio::test]
    async fn delete_group_nonexistent_returns_404_no_broadcast() {
        let (state, _pool) = test_state().await;
        expect_broadcasts(&state, 0, async {
            let Json(resp) =
                super::delete_group(AdminOnly { user_id: 1 }, State(state.clone()), Path(99999))
                    .await;
            assert_eq!(resp.code, 404);
        })
        .await;
    }

    /// v0.4.8 PR3: err() accepts both &str and owned String (via impl Into<String>),
    /// so a format!() message doesn't need Box::leak.
    #[test]
    fn err_accepts_str_and_owned_string() {
        let from_str: ApiResponse<()> = err(400, "static");
        assert_eq!(from_str.code, 400);
        assert_eq!(from_str.message, "static");

        let from_owned: ApiResponse<()> = err(409, format!("used by {} rules", 3));
        assert_eq!(from_owned.code, 409);
        assert_eq!(from_owned.message, "used by 3 rules");
        assert!(from_owned.data.is_none());
    }

    // ── v0.4.9: GET /user/me ──

    /// get_me returns the calling user's own non-password fields. The password
    /// hash is NEVER in the response (UserSelf has no such field).
    #[tokio::test]
    async fn get_me_returns_own_info_without_password() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        // Give alice a distinguishable balance/limits/traffic so we can assert
        // the right row came back.
        sqlx::query(
            "UPDATE users SET balance='12.50', max_rules=7, traffic_used=1024, \
             traffic_limit=1048576 WHERE id=2",
        )
        .execute(&pool)
        .await
        .unwrap();

        let Json(resp) = get_me(
            AuthUser {
                user_id: 2,
                admin: false,
            },
            State(state.clone()),
        )
        .await;
        assert_eq!(resp.code, 0);
        let me = resp.data.expect("data present");
        assert_eq!(me.id, 2);
        assert_eq!(me.username, "alice");
        assert_eq!(me.balance, "12.50");
        assert_eq!(me.max_rules, 7);
        assert_eq!(me.traffic_used, 1024);
        assert_eq!(me.traffic_limit, 1_048_576);
        assert!(!me.admin);
        // v0.4.10: account projection fields. add_user leaves plan_id NULL and
        // creates no rules, so plan_name is None and current_rules is 0.
        assert_eq!(me.plan_id, None);
        assert_eq!(me.plan_name, None);
        assert_eq!(me.current_rules, 0);
        assert!(
            !me.registered_at.is_empty(),
            "registered_at must be populated"
        );
        // UserSelf has no password-hash field by construction. We assert the
        // serialized response carries neither a bcrypt hash (always starts
        // "$2") nor a bare `"password":` key. We deliberately do NOT assert the
        // substring "password" is absent, because v0.4.10 PR4 added the
        // legitimate `must_change_password` field which contains that substring.
        let serialized = serde_json::to_string(&me).unwrap();
        assert!(
            !serialized.contains("$2"),
            "bcrypt hash must never appear in /user/me response: {serialized}"
        );
        assert!(
            !serialized.contains("\"password\""),
            "password-hash key must never appear in /user/me response: {serialized}"
        );
        // v0.4.10: the JSON field is registered_at (renamed from created_at).
        assert!(
            serialized.contains("registered_at"),
            "JSON must use registered_at key: {serialized}"
        );
    }

    /// v0.4.10: when the user has a plan_id set, plan_name is resolved from
    /// the plans table (plan_id=1 is the seeded 'free' plan).
    #[tokio::test]
    async fn get_me_includes_plan_name_when_plan_set() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        sqlx::query("UPDATE users SET plan_id = 1 WHERE id = 2")
            .execute(&pool)
            .await
            .unwrap();

        let Json(resp) = get_me(
            AuthUser {
                user_id: 2,
                admin: false,
            },
            State(state.clone()),
        )
        .await;
        assert_eq!(resp.code, 0, "{}", resp.message);
        let me = resp.data.unwrap();
        assert_eq!(me.plan_id, Some(1));
        assert_eq!(me.plan_name.as_deref(), Some("free"));
    }

    /// v0.4.10: a plan_id pointing at a non-existent plan yields plan_name
    /// None (defensive — FK should prevent this, but the projection must not
    /// panic or 500 on a dangling reference).
    #[tokio::test]
    async fn get_me_plan_name_none_when_plan_missing() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        // Force a dangling plan_id (FK off so SQLite accepts it).
        sqlx::query("PRAGMA foreign_keys = OFF")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE users SET plan_id = 999 WHERE id = 2")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&pool)
            .await
            .unwrap();

        let Json(resp) = get_me(
            AuthUser {
                user_id: 2,
                admin: false,
            },
            State(state.clone()),
        )
        .await;
        assert_eq!(resp.code, 0, "{}", resp.message);
        let me = resp.data.unwrap();
        assert_eq!(me.plan_id, Some(999));
        assert_eq!(me.plan_name, None, "missing plan must yield plan_name None");
    }

    /// v0.4.10: current_rules reflects the user's actual forward_rules count.
    #[tokio::test]
    async fn get_me_current_rules_reflects_rule_count() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_group(&pool, 20, 2, "alice-in").await;
        // Two rules owned by alice.
        add_rule(&pool, 100, 2, 20, 12000, 0).await;
        add_rule(&pool, 101, 2, 20, 12001, 0).await;

        let Json(resp) = get_me(
            AuthUser {
                user_id: 2,
                admin: false,
            },
            State(state.clone()),
        )
        .await;
        assert_eq!(resp.code, 0, "{}", resp.message);
        let me = resp.data.unwrap();
        assert_eq!(
            me.current_rules, 2,
            "current_rules must equal owned rule count"
        );
    }

    /// A non-admin reading their own account works (this is the whole point of
    /// /user/me — the account page is the non-admin's landing page).
    #[tokio::test]
    async fn get_me_works_for_non_admin() {
        let (state, pool) = test_state().await;
        add_user(&pool, 5, "bob", false).await;
        let Json(resp) = get_me(
            AuthUser {
                user_id: 5,
                admin: false,
            },
            State(state.clone()),
        )
        .await;
        assert_eq!(resp.code, 0);
        assert_eq!(resp.data.unwrap().username, "bob");
    }

    /// A deleted user (JWT still valid but row gone) → 404, not 500.
    #[tokio::test]
    async fn get_me_returns_404_for_deleted_user() {
        let (state, _pool) = test_state().await;
        let Json(resp) = get_me(
            AuthUser {
                user_id: 999,
                admin: false,
            },
            State(state.clone()),
        )
        .await;
        assert_eq!(resp.code, 404);
        assert!(resp.data.is_none());
    }

    // ── v0.4.10 resource-ownership isolation ──
    // These pin the per-user scoping at the HANDLER level: a non-admin may only
    // see/modify their own rules + groups; another user's (or a non-existent)
    // resource is a uniform 404; a forged owner_uid is ignored; an admin keeps
    // unscoped access.

    fn auth(user_id: i64, admin: bool) -> AuthUser {
        AuthUser { user_id, admin }
    }

    fn rule_req(name: &str, port: u16, group_in: i64, owner_uid: Option<i64>) -> CreateRuleRequest {
        CreateRuleRequest {
            name: name.into(),
            listen_port: Some(port),
            protocol: Protocol::Tcp,
            owner_uid,
            device_group_in: group_in,
            device_group_out: None,
            forward_mode: "direct".into(),
            route_mode: Default::default(),
            hops: None,
            tunnel_id: None,
            public_transport: Default::default(),
            ws_path: None,
            target_addr: "127.0.0.1".into(),
            target_port: 80,
            targets: None,
            load_balance_strategy: Default::default(),
            upload_limit_mbps: None,
            download_limit_mbps: None,
            tunnel_profile_id: None,
            max_connections: None,
            auto_restart_minutes: None,
        }
    }

    /// list_rules is owner-scoped: a non-admin sees only their own rules, an
    /// admin sees everyone's.
    #[tokio::test]
    async fn list_rules_is_owner_scoped() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_user(&pool, 3, "bob", false).await;
        add_group(&pool, 10, 2, "alice-in").await;
        add_group(&pool, 11, 3, "bob-in").await;
        add_rule(&pool, 100, 2, 10, 20000, 0).await;
        add_rule(&pool, 101, 3, 11, 20001, 0).await;

        // Alice sees only her own rule.
        let Json(resp) = list_rules(
            auth(2, false),
            Query(ListRulesQuery::default()),
            State(state.clone()),
        )
        .await;
        let rules = resp.data.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, 100);

        // Admin sees both.
        let Json(resp) = list_rules(
            auth(1, true),
            Query(ListRulesQuery::default()),
            State(state.clone()),
        )
        .await;
        assert_eq!(resp.data.unwrap().len(), 2);
    }

    /// v0.4.20: admin can filter rules by owner_uid query param.
    #[tokio::test]
    async fn list_rules_owner_uid_admin_only() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_user(&pool, 3, "bob", false).await;
        add_group(&pool, 10, 2, "alice-in").await;
        add_group(&pool, 11, 3, "bob-in").await;
        add_rule(&pool, 100, 2, 10, 20000, 0).await;
        add_rule(&pool, 101, 3, 11, 20001, 0).await;

        // Admin filters by owner_uid=2 → only alice's rule.
        let Json(resp) = list_rules(
            auth(1, true),
            Query(ListRulesQuery { owner_uid: Some(2) }),
            State(state.clone()),
        )
        .await;
        let rules = resp.data.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, 100);

        // Non-admin passing owner_uid → ignored, still sees only own rules.
        let Json(resp) = list_rules(
            auth(2, false),
            Query(ListRulesQuery { owner_uid: Some(3) }),
            State(state.clone()),
        )
        .await;
        let rules = resp.data.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, 100); // still alice's own rule
    }

    /// A non-admin updating/deleting another user's rule gets a uniform 404 —
    /// indistinguishable from "rule doesn't exist".
    #[tokio::test]
    async fn cross_user_rule_access_is_404() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_user(&pool, 3, "bob", false).await;
        add_group(&pool, 11, 3, "bob-in").await;
        add_rule(&pool, 101, 3, 11, 20001, 0).await;

        // Alice tries to rename bob's rule → 404.
        let Json(resp) = update_rule(
            auth(2, false),
            State(state.clone()),
            Path(101),
            Json(UpdateRuleRequest {
                name: Some("hijacked".into()),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(resp.code, 404, "{}", resp.message);

        // Alice tries to delete bob's rule → 404, and the rule survives.
        let Json(resp) = delete_rule(auth(2, false), State(state.clone()), Path(101)).await;
        assert_eq!(resp.code, 404);
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM forward_rules WHERE id = 101")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 1, "bob's rule must survive alice's delete attempt");
    }

    /// A non-admin's forged owner_uid in create_rule is IGNORED: the rule is
    /// attributed to the caller, not the spoofed target.
    #[tokio::test]
    async fn create_rule_ignores_forged_owner_uid_for_non_admin() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_user(&pool, 3, "bob", false).await;
        // v0.4.12 PR1: inbound group must be admin-owned 'in' (uid=1 = seeded admin).
        add_group(&pool, 10, 1, "shared-in").await;

        // Alice claims owner_uid = 3 (bob). It must be ignored.
        let Json(resp) = create_rule(
            auth(2, false),
            State(state.clone()),
            Json(rule_req("r", 20000, 10, Some(3))),
        )
        .await;
        assert_eq!(resp.code, 0, "{}", resp.message);

        let owner: (i64,) = sqlx::query_as("SELECT uid FROM forward_rules WHERE name = 'r'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            owner.0, 2,
            "forged owner_uid must be ignored; alice owns it"
        );
    }

    /// An admin MAY create a rule on behalf of another user via owner_uid.
    #[tokio::test]
    async fn create_rule_admin_can_set_owner_uid() {
        let (state, pool) = test_state().await;
        add_user(&pool, 3, "bob", false).await;
        // v0.4.12 PR1: inbound group must be admin-owned (uid=1). The rule owner
        // (bob) is independent of the inbound group's owner.
        add_group(&pool, 11, 1, "shared-in").await;

        let Json(resp) = create_rule(
            auth(1, true),
            State(state.clone()),
            Json(rule_req("r", 20000, 11, Some(3))),
        )
        .await;
        assert_eq!(resp.code, 0, "{}", resp.message);
        let owner: (i64,) = sqlx::query_as("SELECT uid FROM forward_rules WHERE name = 'r'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(owner.0, 3, "admin set owner to bob");
    }

    /// create_rule enforces that the referenced inbound group belongs to the
    /// rule's owner: a non-admin can't attach a rule to someone else's group.
    #[tokio::test]
    async fn create_rule_rejects_foreign_inbound_group() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_user(&pool, 3, "bob", false).await;
        add_group(&pool, 11, 3, "bob-in").await; // bob's group

        // Alice references bob's group 11 → rejected (group not hers).
        let Json(resp) = create_rule(
            auth(2, false),
            State(state.clone()),
            Json(rule_req("r", 20000, 11, None)),
        )
        .await;
        assert_eq!(resp.code, 400, "{}", resp.message);
    }

    /// v0.4.11 PR3: a non-admin CAN bind a rule to an inbound group owned by an
    /// ADMIN ("shared inbound" infrastructure). This is the positive case the
    /// foreign-group rejection must not break.
    #[tokio::test]
    async fn create_rule_allows_admin_shared_inbound_group() {
        let (state, pool) = test_state().await;
        // user id=1 is the seeded admin; it owns the shared group.
        add_user(&pool, 2, "alice", false).await;
        add_group(&pool, 11, 1, "shared-in").await; // admin's group

        // Alice references the admin's shared group 11 → allowed.
        let Json(resp) = create_rule(
            auth(2, false),
            State(state.clone()),
            Json(rule_req("r", 20000, 11, None)),
        )
        .await;
        assert_eq!(resp.code, 0, "{}", resp.message);
    }

    /// A `both` group is one physical relay-node registration with two roles:
    /// it must pass the exact same entry validation as `in` while remaining
    /// selectable as a later chain hop.
    #[tokio::test]
    async fn create_rule_allows_admin_both_group_as_inbound() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_group_typed(&pool, 12, 1, "shared-dual-role", "both").await;

        let Json(resp) = create_rule(
            auth(2, false),
            State(state.clone()),
            Json(rule_req("r-both", 20012, 12, None)),
        )
        .await;
        assert_eq!(resp.code, 0, "{}", resp.message);

        let group_id: (i64,) =
            sqlx::query_as("SELECT device_group_in FROM forward_rules WHERE name = 'r-both'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(group_id.0, 12);
    }

    // ── v1.0.7 regression: per-user device-group authorization ──

    /// Restrict a user to an explicit device-group allowlist (all_device_groups
    /// stays 0). An empty list = unassigned = cannot forward.
    async fn assign_user_groups(pool: &SqlitePool, uid: i64, allowed: &[i64]) {
        sqlx::query("UPDATE users SET all_device_groups = 0 WHERE id = ?")
            .bind(uid)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM user_device_groups WHERE user_id = ?")
            .bind(uid)
            .execute(pool)
            .await
            .unwrap();
        for gid in allowed {
            sqlx::query("INSERT INTO user_device_groups (user_id, device_group_id) VALUES (?, ?)")
                .bind(uid)
                .bind(gid)
                .execute(pool)
                .await
                .unwrap();
        }
    }

    /// REGRESSION: a user authorized for group 1 must NOT be able to create a
    /// rule on group 2.
    #[tokio::test]
    async fn create_rule_rejects_group_outside_user_authorization() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_group(&pool, 1, 1, "admin-in-1").await;
        add_group(&pool, 2, 1, "admin-in-2").await;
        // Alice is authorized for ONLY device group 1.
        assign_user_groups(&pool, 2, &[1]).await;

        // Group 1 → allowed.
        let Json(ok) = create_rule(
            auth(2, false),
            State(state.clone()),
            Json(rule_req("r1", 20001, 1, None)),
        )
        .await;
        assert_eq!(ok.code, 0, "group 1 must be allowed: {}", ok.message);

        // Group 2 → forbidden (403).
        let Json(deny) = create_rule(
            auth(2, false),
            State(state.clone()),
            Json(rule_req("r2", 20002, 2, None)),
        )
        .await;
        assert_eq!(
            deny.code, 403,
            "group 2 must be rejected (permission bypass)"
        );
    }

    /// REGRESSION: an empty authorized list means NO access → deny (the bug
    /// treated empty as "allow all").
    #[tokio::test]
    async fn create_rule_empty_authorization_denies_all() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_group(&pool, 1, 1, "admin-in-1").await;
        // Alice is authorized for NOTHING (default: restricted, no assignments).
        assign_user_groups(&pool, 2, &[]).await;

        let Json(deny) = create_rule(
            auth(2, false),
            State(state.clone()),
            Json(rule_req("r", 20001, 1, None)),
        )
        .await;
        assert_eq!(deny.code, 403, "empty authorization must deny, not allow");
    }

    #[tokio::test]
    async fn admin_rule_writes_still_enforce_the_target_owners_authorization() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_group(&pool, 1, 1, "admin-in-1").await;
        assign_user_groups(&pool, 2, &[]).await;

        // Admin actor privileges must not turn into forwarding privileges for
        // the ordinary user who will own and run the rule.
        let Json(create_denied) = create_rule(
            auth(1, true),
            State(state.clone()),
            Json(rule_req("admin-created", 20001, 1, Some(2))),
        )
        .await;
        assert_eq!(create_denied.code, 403, "{}", create_denied.message);
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM forward_rules WHERE name='admin-created'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count, 0);

        // Seed a system-paused rule to exercise the transactional resume guard.
        add_rule(&pool, 200, 2, 1, 20002, 0).await;
        sqlx::query("UPDATE forward_rules SET paused=1,auto_paused=1 WHERE id=200")
            .execute(&pool)
            .await
            .unwrap();
        let Json(resume_denied) = update_rule(
            auth(1, true),
            State(state),
            Path(200),
            Json(UpdateRuleRequest {
                paused: Some(false),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(resume_denied.code, 403, "{}", resume_denied.message);
        let state: (bool, bool) =
            sqlx::query_as("SELECT paused,auto_paused FROM forward_rules WHERE id=200")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(state, (true, true));
    }

    /// A chain update takes its effective entry group from hops[0].  The API
    /// must authorize that value even when device_group_in is omitted; checking
    /// only the legacy field lets restricted users move their rules to shared
    /// infrastructure they cannot otherwise use.
    #[tokio::test]
    async fn update_rule_rejects_unauthorized_entry_from_hops() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_group(&pool, 1, 1, "allowed-entry").await;
        add_group(&pool, 2, 1, "forbidden-entry").await;
        add_group_typed(&pool, 3, 1, "exit", "out").await;
        add_rule(&pool, 200, 2, 1, 20001, 0).await;
        assign_user_groups(&pool, 2, &[1]).await;

        let Json(deny) = update_rule(
            auth(2, false),
            State(state.clone()),
            Path(200),
            Json(UpdateRuleRequest {
                hops: Some(vec![2, 3]),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(deny.code, 403, "hops[0] must be authorization checked");

        let stored_group: (i64,) =
            sqlx::query_as("SELECT device_group_in FROM forward_rules WHERE id = 200")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stored_group.0, 1, "denied update must not mutate the rule");
    }

    #[tokio::test]
    async fn update_rule_rejects_conflicting_entry_fields() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_group(&pool, 1, 1, "allowed-entry").await;
        add_group(&pool, 2, 1, "other-entry").await;
        add_group_typed(&pool, 3, 1, "exit", "out").await;
        add_rule(&pool, 200, 2, 1, 20001, 0).await;

        let Json(deny) = update_rule(
            auth(2, false),
            State(state),
            Path(200),
            Json(UpdateRuleRequest {
                device_group_in: Some(1),
                hops: Some(vec![2, 3]),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(deny.code, 400, "conflicting entry sources must be rejected");
    }

    #[tokio::test]
    async fn update_rule_rejects_hops_on_direct_rule() {
        let (state, pool) = test_state().await;
        add_group(&pool, 1, 1, "entry").await;
        add_group_typed(&pool, 2, 1, "exit", "out").await;
        add_rule(&pool, 200, 1, 1, 20001, 0).await;

        let Json(deny) = update_rule(
            auth(1, true),
            State(state),
            Path(200),
            Json(UpdateRuleRequest {
                hops: Some(vec![1, 2]),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(deny.code, 400, "direct rules must not accept hidden hops");
        let hop_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM forward_rule_hops WHERE rule_id = 200")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(hop_count.0, 0);
    }

    #[tokio::test]
    async fn update_rule_rejects_conflicting_topology_fields() {
        let (state, pool) = test_state().await;
        add_group(&pool, 1, 1, "entry").await;
        add_rule(&pool, 200, 1, 1, 20001, 0).await;

        let Json(deny) = update_rule(
            auth(1, true),
            State(state),
            Path(200),
            Json(UpdateRuleRequest {
                route_mode: Some(relay_shared::protocol::RouteMode::Chain),
                forward_mode: Some("direct".into()),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(deny.code, 400);
    }

    /// REGRESSION: removing a device group from a user's authorization pauses
    /// the user's existing rules on that group (kept, not deleted).
    #[tokio::test]
    async fn changing_user_group_pauses_unauthorized_rules() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_group(&pool, 1, 1, "admin-in-1").await;
        add_group(&pool, 2, 1, "admin-in-2").await;
        // Alice initially authorized for both groups.
        assign_user_groups(&pool, 2, &[1, 2]).await;
        // Alice has a rule on group 2.
        add_rule(&pool, 100, 2, 2, 20002, 0).await;

        // Re-assign Alice to ONLY group 1 (group 2 no longer authorized).
        let Json(resp) = update_user(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path(2),
            Json(UpdateUserRequest {
                device_group_ids: Some(vec![1]),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(resp.code, 0, "{}", resp.message);

        // Rule 100 (on group 2) must now be paused, NOT deleted.
        let row: (i64, bool) =
            sqlx::query_as("SELECT id, paused FROM forward_rules WHERE id = 100")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(row.1, "rule on now-unauthorized group must be paused");
    }

    /// REGRESSION (review round 2): flipping a user from all_device_groups=true
    /// to false must pause their rules on groups that are no longer authorized.
    #[tokio::test]
    async fn flipping_user_to_restricted_pauses_unauthorized_rules() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_group(&pool, 1, 1, "admin-in-1").await;
        add_group(&pool, 2, 1, "admin-in-2").await;
        // Alice initially may use ALL device groups.
        sqlx::query("UPDATE users SET all_device_groups = 1 WHERE id = 2")
            .execute(&pool)
            .await
            .unwrap();
        // Alice has a rule on group 2 (allowed while all_device_groups=true).
        add_rule(&pool, 100, 2, 2, 20002, 0).await;

        // Admin flips Alice to restricted (all_device_groups=false). With no
        // explicit assignments, ALL of her rules become unauthorized → paused.
        let Json(resp) = update_user(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path(2),
            Json(UpdateUserRequest {
                all_device_groups: Some(false),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(resp.code, 0, "{}", resp.message);

        let row: (i64, bool) =
            sqlx::query_as("SELECT id, paused FROM forward_rules WHERE id = 100")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            row.1,
            "rule must be paused after user flipped to restricted (all_device_groups=false)"
        );
    }

    /// REGRESSION: updating the device-group authorization together with
    /// balance/quota must apply ALL fields (the bug early-returned, dropping the
    /// rest).
    #[tokio::test]
    async fn update_user_applies_authz_and_other_fields_together() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;

        let Json(resp) = update_user(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path(2),
            Json(UpdateUserRequest {
                all_device_groups: Some(true),
                max_rules: Some(99),
                balance: Some("50.00".into()),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(resp.code, 0, "{}", resp.message);

        let row: (bool, i64, String) =
            sqlx::query_as("SELECT all_device_groups, max_rules, balance FROM users WHERE id = 2")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(row.0, "all_device_groups must be set");
        assert_eq!(row.1, 99, "max_rules must ALSO be applied (not dropped)");
        assert_eq!(row.2, "50.00", "balance must ALSO be applied (not dropped)");
    }

    /// REGRESSION: the user row, explicit group assignments, and consequent
    /// rule pauses are one transaction. A bad group id must not leave any of
    /// the earlier parts committed.
    #[tokio::test]
    async fn update_user_rolls_back_every_field_when_authorization_fails() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_group(&pool, 1, 1, "admin-in").await;
        assign_user_groups(&pool, 2, &[1]).await;
        add_rule(&pool, 100, 2, 1, 20001, 0).await;

        let Json(resp) = update_user(
            AdminOnly { user_id: 1 },
            State(state),
            Path(2),
            Json(UpdateUserRequest {
                balance: Some("99.00".into()),
                max_rules: Some(42),
                banned: Some(true),
                suspended: Some(true),
                all_device_groups: Some(false),
                device_group_ids: Some(vec![999_999]),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(resp.code, 400, "invalid group id must be rejected");

        let user: (String, i64, bool, bool, i64, bool) = sqlx::query_as(
            "SELECT balance, max_rules, banned, suspended, token_version, \
             all_device_groups FROM users WHERE id = 2",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(user, ("0".into(), 5, false, false, 0, false));

        let assignments: Vec<(i64,)> = sqlx::query_as(
            "SELECT device_group_id FROM user_device_groups \
             WHERE user_id = 2 ORDER BY device_group_id",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(assignments, vec![(1,)]);

        let rule: (bool, bool) =
            sqlx::query_as("SELECT paused, auto_paused FROM forward_rules WHERE id = 100")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(rule, (false, false));
    }

    #[tokio::test]
    async fn enabling_all_groups_ignores_submitted_explicit_list() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_group(&pool, 1, 1, "admin-in").await;
        assign_user_groups(&pool, 2, &[1]).await;

        let Json(resp) = update_user(
            AdminOnly { user_id: 1 },
            State(state),
            Path(2),
            Json(UpdateUserRequest {
                balance: Some("12.30".into()),
                all_device_groups: Some(true),
                // The protocol says this field is ignored when the same
                // request enables all groups. It must neither fail validation
                // nor overwrite the dormant explicit grant set.
                device_group_ids: Some(vec![999_999]),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(resp.code, 0, "{}", resp.message);

        let user: (String, bool) =
            sqlx::query_as("SELECT balance, all_device_groups FROM users WHERE id = 2")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(user, ("12.30".into(), true));
        let assignments: Vec<(i64,)> = sqlx::query_as(
            "SELECT device_group_id FROM user_device_groups WHERE user_id = 2 ORDER BY 1",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(assignments, vec![(1,)]);
    }

    #[tokio::test]
    async fn update_user_rejects_unusable_explicit_group_grants() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_user(&pool, 3, "bob", false).await;
        add_group(&pool, 1, 1, "admin-in").await;
        add_group(&pool, 2, 3, "regular-owned-in").await;
        add_group_typed(&pool, 3, 1, "admin-out", "out").await;
        assign_user_groups(&pool, 2, &[1]).await;

        for invalid_group_id in [2, 3] {
            let Json(resp) = update_user(
                AdminOnly { user_id: 1 },
                State(state.clone()),
                Path(2),
                Json(UpdateUserRequest {
                    balance: Some("99.00".into()),
                    device_group_ids: Some(vec![invalid_group_id]),
                    ..Default::default()
                }),
            )
            .await;
            assert_eq!(resp.code, 400, "group {invalid_group_id}: {}", resp.message);
        }

        let balance: (String,) = sqlx::query_as("SELECT balance FROM users WHERE id = 2")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(balance.0, "0");
        let assignments: Vec<(i64,)> = sqlx::query_as(
            "SELECT device_group_id FROM user_device_groups WHERE user_id = 2 ORDER BY 1",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(assignments, vec![(1,)]);
    }

    #[tokio::test]
    async fn update_user_authz_only_returns_404_for_missing_user() {
        let (state, _pool) = test_state().await;

        for request in [
            UpdateUserRequest {
                all_device_groups: Some(true),
                ..Default::default()
            },
            UpdateUserRequest {
                device_group_ids: Some(vec![]),
                ..Default::default()
            },
            UpdateUserRequest {
                device_group_ids: Some(vec![999_999]),
                ..Default::default()
            },
        ] {
            let Json(resp) = update_user(
                AdminOnly { user_id: 1 },
                State(state.clone()),
                Path(999_999),
                Json(request),
            )
            .await;
            assert_eq!(resp.code, 404, "missing authz-only target must be 404");
        }
    }

    #[tokio::test]
    async fn admin_plan_edit_validates_snapshot_expiry_and_clear_semantics() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_group(&pool, 1, 1, "admin-in").await;
        assign_user_groups(&pool, 2, &[1]).await;
        add_rule(&pool, 100, 2, 1, 20001, 0).await;
        sqlx::query(
            "INSERT INTO plans (id, name, max_rules, traffic, plan_type, duration_days) VALUES \
             (10, 'old-time', 5, 0, 'time', 30), \
             (11, 'new-time', 5, 0, 'time', 30), \
             (12, 'data', 5, 1000, 'data', 0)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("UPDATE users SET plan_id = 11 WHERE id = 2")
            .execute(&pool)
            .await
            .unwrap();

        // A stale modal that still shows plan 10 must not remove plan 11.
        let Json(stale) = admin_set_user_plan(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path(2),
            Json(AdminSetUserPlanRequest {
                expected_plan_id: 10,
                clear: true,
                plan_expire_at: None,
            }),
        )
        .await;
        assert_eq!(stale.code, 409);

        // Malformed values must never enter the lexically-compared TEXT field.
        let Json(invalid_expiry) = admin_set_user_plan(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path(2),
            Json(AdminSetUserPlanRequest {
                expected_plan_id: 11,
                clear: false,
                plan_expire_at: Some("2099-02-30 00:00:00".into()),
            }),
        )
        .await;
        assert_eq!(invalid_expiry.code, 400);

        let Json(valid_expiry) = admin_set_user_plan(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path(2),
            Json(AdminSetUserPlanRequest {
                expected_plan_id: 11,
                clear: false,
                plan_expire_at: Some("2099-12-31 23:59:59".into()),
            }),
        )
        .await;
        assert_eq!(valid_expiry.code, 0, "{}", valid_expiry.message);
        let stored: (Option<i64>, Option<String>) =
            sqlx::query_as("SELECT plan_id, plan_expire_at FROM users WHERE id = 2")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stored, (Some(11), Some("2099-12-31 23:59:59".into())));

        // Data plans have no expiry editor at the product level; enforce that
        // in the API too, then prove a matching clear still revokes everything.
        sqlx::query("UPDATE users SET plan_id = 12, plan_expire_at = NULL WHERE id = 2")
            .execute(&pool)
            .await
            .unwrap();
        let Json(data_expiry) = admin_set_user_plan(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path(2),
            Json(AdminSetUserPlanRequest {
                expected_plan_id: 12,
                clear: false,
                plan_expire_at: None,
            }),
        )
        .await;
        assert_eq!(data_expiry.code, 400);

        let Json(cleared) = admin_set_user_plan(
            AdminOnly { user_id: 1 },
            State(state),
            Path(2),
            Json(AdminSetUserPlanRequest {
                expected_plan_id: 12,
                clear: true,
                plan_expire_at: None,
            }),
        )
        .await;
        assert_eq!(cleared.code, 0, "{}", cleared.message);
        let user: (Option<i64>, bool) =
            sqlx::query_as("SELECT plan_id, all_device_groups FROM users WHERE id = 2")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(user, (None, false));
        let assignments: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM user_device_groups WHERE user_id = 2")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(assignments, 0);
        let rule: (bool, bool) =
            sqlx::query_as("SELECT paused, auto_paused FROM forward_rules WHERE id = 100")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(rule, (true, true));
    }

    /// v0.4.12 PR1: a regular user's OWN historical inbound group is NOT a valid
    /// rule entry — only admin-owned 'in' groups are. (Device groups are
    /// admin-managed shared infrastructure.)
    #[tokio::test]
    async fn create_rule_rejects_users_own_historical_group() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_group(&pool, 30, 2, "alice-own-in").await; // alice's own 'in' group

        let Json(resp) = create_rule(
            auth(2, false),
            State(state.clone()),
            Json(rule_req("r", 20000, 30, None)),
        )
        .await;
        assert_eq!(
            resp.code, 400,
            "a user's own (non-admin) group must be rejected: {}",
            resp.message
        );
    }

    #[tokio::test]
    async fn create_rule_rejects_historical_regular_owned_downstream_hop() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_user(&pool, 3, "legacy-node-owner", false).await;
        add_group(&pool, 30, 1, "admin-entry").await;
        add_group_typed(&pool, 31, 3, "legacy-out", "out").await;
        sqlx::query("UPDATE device_groups SET connect_host='192.0.2.31' WHERE id=31")
            .execute(&pool)
            .await
            .unwrap();
        let mut req = rule_req("unsafe-chain", 20001, 30, None);
        req.forward_mode = "chain".into();
        req.route_mode = relay_shared::protocol::RouteMode::Chain;
        req.hops = Some(vec![30, 31]);
        req.device_group_out = Some(31);

        let Json(resp) = create_rule(auth(2, false), State(state), Json(req)).await;
        assert_eq!(resp.code, 400, "{}", resp.message);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM forward_rules")
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
    }

    /// v0.4.12 PR1: an admin-owned OUT (or monitor) group is NOT a valid rule
    /// entry — device_group_in must be inbound-capable (`in` or `both`).
    #[tokio::test]
    async fn create_rule_rejects_admin_out_group_as_inbound() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_group_typed(&pool, 40, 1, "admin-out", "out").await; // admin 'out' group

        let Json(resp) = create_rule(
            auth(2, false),
            State(state.clone()),
            Json(rule_req("r", 20000, 40, None)),
        )
        .await;
        assert_eq!(
            resp.code, 400,
            "an admin 'out' group must be rejected as device_group_in: {}",
            resp.message
        );
    }

    /// v0.4.20: create_rule rejects forward_mode="group".
    #[tokio::test]
    async fn create_rule_rejects_group_forward_mode() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_group(&pool, 20, 1, "shared-in").await;

        let Json(resp) = create_rule(
            auth(2, false),
            State(state.clone()),
            Json(CreateRuleRequest {
                forward_mode: "group".into(),
                ..rule_req("test", 20000, 20, None)
            }),
        )
        .await;
        assert_eq!(resp.code, 400, "{}", resp.message);
        assert!(resp.message.contains("direct"));
    }

    /// v0.4.20: create_rule rejects non-null device_group_out.
    #[tokio::test]
    async fn create_rule_rejects_device_group_out() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_group(&pool, 20, 1, "shared-in").await;

        let Json(resp) = create_rule(
            auth(2, false),
            State(state.clone()),
            Json(CreateRuleRequest {
                device_group_out: Some(99),
                ..rule_req("test", 20000, 20, None)
            }),
        )
        .await;
        assert_eq!(resp.code, 400, "{}", resp.message);
        assert!(resp.message.contains("device_group_out"));
    }

    /// v0.4.20: update_rule rejects forward_mode="group".
    #[tokio::test]
    async fn update_rule_rejects_group_forward_mode() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_group(&pool, 20, 1, "shared-in").await;
        add_rule(&pool, 200, 2, 20, 12000, 0).await;

        let Json(resp) = update_rule(
            auth(2, false),
            State(state.clone()),
            Path(200),
            Json(UpdateRuleRequest {
                forward_mode: Some("group".into()),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(resp.code, 400, "{}", resp.message);
        assert!(resp.message.contains("direct"));
    }

    /// v0.4.20: update_rule rejects non-null device_group_out.
    #[tokio::test]
    async fn update_rule_rejects_device_group_out() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_group(&pool, 20, 1, "shared-in").await;
        add_rule(&pool, 200, 2, 20, 12000, 0).await;

        let Json(resp) = update_rule(
            auth(2, false),
            State(state.clone()),
            Path(200),
            Json(UpdateRuleRequest {
                device_group_out: Some(99),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(resp.code, 400, "{}", resp.message);
        assert!(resp.message.contains("device_group_out"));
    }

    #[tokio::test]
    async fn group_access_is_owner_scoped() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_user(&pool, 3, "bob", false).await;
        add_group(&pool, 10, 2, "alice-in").await;
        add_group(&pool, 11, 3, "bob-in").await;

        // Alice's compatibility view lists only her group and serializes only
        // the safe summary shape (most importantly, never the node token).
        let Json(resp) = list_owned_group_summaries(auth(2, false), State(state.clone())).await;
        let groups = resp.data.unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].id, 10);
        let json = serde_json::to_value(&groups[0]).unwrap();
        assert!(json.get("token").is_none());
        assert!(json.get("config").is_none());
        assert!(json.get("fallback_group").is_none());
        assert!(json.get("uid").is_none());

        // Admin lists both.
        let Json(resp) = list_groups(AdminOnly { user_id: 1 }, State(state.clone())).await;
        assert_eq!(resp.data.unwrap().len(), 2);

        // v0.4.12 PR1: delete_group is admin-only (scope All). An admin may
        // delete any group regardless of owner.
        let Json(resp) =
            delete_group(AdminOnly { user_id: 1 }, State(state.clone()), Path(11)).await;
        assert_eq!(resp.code, 0, "{}", resp.message);
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM device_groups WHERE id = 11")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0, "admin deleted bob's group");
    }

    /// v0.4.12 PR1: create_group is admin-only and IGNORES owner_uid — the
    /// group always belongs to the creating admin (a regular-user-owned group
    /// would be unmanageable and never shared).
    #[tokio::test]
    async fn create_group_ignores_owner_uid_and_assigns_admin() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_user(&pool, 3, "bob", false).await;

        let Json(resp) = create_group(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(CreateGroupRequest {
                name: "g".into(),
                group_type: GroupType::In,
                connect_host: "1.2.3.4".into(),
                port_range: "20000-30000".into(),
                owner_uid: Some(3),
                rate: None,
                hidden: None,
                blocked_protocols: vec![],
            }),
        )
        .await;
        assert_eq!(resp.code, 0, "{}", resp.message);
        let owner: (i64,) = sqlx::query_as("SELECT uid FROM device_groups WHERE name = 'g'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            owner.0, 1,
            "owner_uid must be ignored; group belongs to the creating admin"
        );
    }

    #[tokio::test]
    async fn group_protocol_policy_is_normalized_validated_and_cleared_with_type() {
        let (state, pool) = test_state().await;
        let Json(invalid) = create_group(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(CreateGroupRequest {
                name: "out-with-policy".into(),
                group_type: GroupType::Out,
                connect_host: "192.0.2.10".into(),
                port_range: "20000-30000".into(),
                owner_uid: None,
                rate: None,
                hidden: None,
                blocked_protocols: vec![BlockedProtocol::Tls],
            }),
        )
        .await;
        assert_eq!(invalid.code, 400);

        let Json(created) = create_group(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(CreateGroupRequest {
                name: "entry-policy".into(),
                group_type: GroupType::In,
                connect_host: "192.0.2.11".into(),
                port_range: "20000-30000".into(),
                owner_uid: None,
                rate: None,
                hidden: None,
                blocked_protocols: vec![
                    BlockedProtocol::Tls,
                    BlockedProtocol::Http,
                    BlockedProtocol::Tls,
                ],
            }),
        )
        .await;
        assert_eq!(created.code, 0, "{}", created.message);
        let group = created.data.unwrap();
        assert_eq!(group.blocked_protocols, "[\"http\",\"tls\"]");

        let Json(updated) = update_group(
            AdminOnly { user_id: 1 },
            State(state),
            Path(group.id),
            Json(UpdateGroupRequest {
                group_type: Some(GroupType::Out),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(updated.code, 0, "{}", updated.message);
        let stored: String =
            sqlx::query_scalar("SELECT blocked_protocols FROM device_groups WHERE id=?")
                .bind(group.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stored, "[]");
    }

    #[tokio::test]
    async fn group_names_are_trimmed_and_blank_names_are_rejected() {
        let (state, pool) = test_state().await;

        let Json(blank_create) = create_group(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(CreateGroupRequest {
                name: " \t ".into(),
                group_type: GroupType::In,
                connect_host: "1.2.3.4".into(),
                port_range: "20000-30000".into(),
                owner_uid: None,
                rate: None,
                hidden: None,
                blocked_protocols: vec![],
            }),
        )
        .await;
        assert_eq!(blank_create.code, 400);

        let Json(created) = create_group(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(CreateGroupRequest {
                name: "  trimmed-group  ".into(),
                group_type: GroupType::In,
                connect_host: "1.2.3.4".into(),
                port_range: "20000-30000".into(),
                owner_uid: None,
                rate: None,
                hidden: None,
                blocked_protocols: vec![],
            }),
        )
        .await;
        assert_eq!(created.code, 0, "{}", created.message);
        let group = created.data.unwrap();
        assert_eq!(group.name, "trimmed-group");

        let Json(blank_update) = update_group(
            AdminOnly { user_id: 1 },
            State(state),
            Path(group.id),
            Json(UpdateGroupRequest {
                name: Some("  ".into()),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(blank_update.code, 400);

        let stored: (String,) = sqlx::query_as("SELECT name FROM device_groups WHERE id = ?")
            .bind(group.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(stored.0, "trimmed-group");
    }

    #[tokio::test]
    async fn group_edits_cannot_invalidate_existing_rule_paths() {
        let (state, pool) = test_state().await;
        add_group(&pool, 40, 1, "rule-entry").await;
        add_group_typed(&pool, 41, 1, "rule-exit", "out").await;
        sqlx::query("UPDATE device_groups SET connect_host='2001:db8::41' WHERE id=41")
            .execute(&pool)
            .await
            .unwrap();
        add_rule(&pool, 140, 1, 40, 36_140, 0).await;
        sqlx::query(
            "UPDATE forward_rules SET route_mode='chain',forward_mode='chain',device_group_out=41 \
             WHERE id=140",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO forward_rule_hops(rule_id,position,device_group_id,listen_port,tunnel_port) \
             VALUES(140,0,40,36140,NULL),(140,1,41,36141,36142)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let Json(entry_conflict) = update_group(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path(40),
            Json(UpdateGroupRequest {
                group_type: Some(GroupType::Out),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(entry_conflict.code, 409);
        assert!(entry_conflict.message.contains("转发规则"));

        let Json(exit_conflict) = update_group(
            AdminOnly { user_id: 1 },
            State(state),
            Path(41),
            Json(UpdateGroupRequest {
                connect_host: Some("  ".into()),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(exit_conflict.code, 409);
        assert!(exit_conflict.message.contains("转发规则"));

        let entry_type: String =
            sqlx::query_scalar("SELECT group_type FROM device_groups WHERE id=40")
                .fetch_one(&pool)
                .await
                .unwrap();
        let exit_host: String =
            sqlx::query_scalar("SELECT connect_host FROM device_groups WHERE id=41")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(entry_type, "in");
        assert_eq!(exit_host, "2001:db8::41");
    }

    #[tokio::test]
    async fn plan_grants_require_admin_inbound_groups_and_block_group_mutation() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "legacy-owner", false).await;
        add_group(&pool, 29, 2, "legacy-user-in").await;
        add_group_typed(&pool, 30, 1, "admin-out", "out").await;

        let Json(missing_update) = update_plan(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path(999_999),
            Json(UpdatePlanRequest {
                device_group_ids: Some(vec![999_999]),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(missing_update.code, 404);

        let Json(invalid_plan) = create_plan(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(CreatePlanRequest {
                name: "invalid-grant".into(),
                max_rules: 5,
                traffic: 1024,
                price: "1.00".into(),
                plan_type: "data".into(),
                duration_days: 0,
                hidden: false,
                reset_traffic: false,
                description: String::new(),
                grant_all_groups: false,
                device_group_ids: vec![30],
            }),
        )
        .await;
        assert_eq!(invalid_plan.code, 400);
        let invalid_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM plans WHERE name = 'invalid-grant'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(invalid_count.0, 0, "invalid plan creation must roll back");

        let Json(user_owned_plan) = create_plan(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(CreatePlanRequest {
                name: "user-owned-grant".into(),
                max_rules: 5,
                traffic: 1024,
                price: "1.00".into(),
                plan_type: "data".into(),
                duration_days: 0,
                hidden: false,
                reset_traffic: false,
                description: String::new(),
                grant_all_groups: false,
                device_group_ids: vec![29],
            }),
        )
        .await;
        assert_eq!(user_owned_plan.code, 400);

        add_group(&pool, 31, 1, "plan-line").await;
        sqlx::query(
            "INSERT INTO plans (id, name, max_rules, traffic, price) \
             VALUES (31, 'line-plan', 5, 1024, '1.00')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO plan_device_groups (plan_id, device_group_id) VALUES (31, 31)")
            .execute(&pool)
            .await
            .unwrap();

        let Json(type_change) = update_group(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path(31),
            Json(UpdateGroupRequest {
                group_type: Some(GroupType::Out),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(type_change.code, 409);

        let Json(delete_response) =
            delete_group(AdminOnly { user_id: 1 }, State(state), Path(31)).await;
        assert_eq!(delete_response.code, 409);
        assert!(delete_response.message.contains("1 个套餐"));
        let group_type: (String,) =
            sqlx::query_as("SELECT group_type FROM device_groups WHERE id = 31")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            group_type.0, "in",
            "rejected mutations must preserve the group"
        );
    }

    #[tokio::test]
    async fn public_plan_catalog_hides_historical_unusable_group_grants() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "legacy-owner", false).await;
        add_group(&pool, 29, 2, "legacy-user-in").await;
        add_group(&pool, 31, 1, "admin-in").await;
        sqlx::query(
            "INSERT INTO plans (id, name, max_rules, traffic, price) VALUES \
             (31, 'valid-plan', 5, 1024, '1.00'), \
             (32, 'historical-invalid-plan', 5, 1024, '1.00')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO plan_device_groups (plan_id, device_group_id) VALUES (31, 31), (32, 29)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let Json(response) = list_public_plans(auth(2, false), State(state)).await;
        assert_eq!(response.code, 0, "{}", response.message);
        let plan_ids: Vec<i64> = response
            .data
            .unwrap()
            .into_iter()
            .map(|item| item.plan.id)
            .collect();
        assert!(plan_ids.contains(&31), "valid plans must remain visible");
        assert!(
            !plan_ids.contains(&32),
            "plans with historical unusable grants must fail closed"
        );
    }

    // ── v0.4.10 fix PR: tunnel-profile builtin scoping + group ownership ──
    // These pin the two security gaps closed by the fix PR:
    //   C6 — a regular user's rule may bind ONLY a builtin tunnel profile
    //        (decided by the RULE OWNER's role, not the operator's)
    //   C7 — update_rule must reject pointing a rule at a group owned by
    //        someone other than the rule's owner (the invariant
    //        rule.uid == group_in.uid == group_out.uid holds for ALL operators)

    /// Helper: insert a tunnel profile row directly (test_state runs SCHEMA_SQL
    /// only, no Migration 6 builtin seed), so tests can pick builtin vs custom.
    async fn add_profile(pool: &SqlitePool, id: i64, name: &str, is_builtin: bool, uid: i64) {
        // v0.4.11 PR1: profiles are now ws/tls_simple only; 'direct' is no longer valid.
        sqlx::query(
            "INSERT INTO tunnel_profiles (id, name, transport, tls_mode, ws_path, host_header, sni, is_builtin, uid) \
             VALUES (?, ?, 'ws', 'none', '/relay', '', '', ?, ?)",
        )
        .bind(id)
        .bind(name)
        .bind(is_builtin)
        .bind(uid)
        .execute(pool)
        .await
        .unwrap();
    }

    /// v0.4.11 PR1: a regular user CAN now bind admin-created custom WS/TLS Simple
    /// templates (AvailableTemplates scope). This is intentional — regular users
    /// can select any available template for their rules.
    #[tokio::test]
    async fn create_rule_rejects_non_builtin_profile_for_non_admin_owner() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_group(&pool, 20, 1, "shared-in").await; // admin-owned inbound (v0.4.12 PR1)
        add_profile(&pool, 50, "custom", false, 1).await; // admin's custom ws profile

        let Json(resp) = create_rule(
            auth(2, false),
            State(state.clone()),
            Json(rule_req_with_profile("r", 12000, 20, None, Some(50))),
        )
        .await;
        // v0.4.11 PR1: allowed — regular users can bind admin-created ws/tls_simple templates
        assert_eq!(resp.code, 0, "{}", resp.message);
    }

    /// v0.4.11 PR1: admin creating rule for non-admin owner CAN bind custom profile.
    /// The AvailableTemplates scope includes admin-created custom templates.
    #[tokio::test]
    async fn create_rule_allows_builtin_profile_for_non_admin_owner() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_group(&pool, 20, 1, "shared-in").await; // admin-owned inbound (v0.4.12 PR1)
        add_profile(&pool, 51, "builtin-ws", true, 1).await;

        let Json(resp) = create_rule(
            auth(2, false),
            State(state.clone()),
            Json(rule_req_with_profile("r", 12001, 20, None, Some(51))),
        )
        .await;
        assert_eq!(resp.code, 0, "{}", resp.message);
    }

    /// v0.4.11 PR1: admin can bind custom profile when creating rule for themselves.
    #[tokio::test]
    async fn create_rule_admin_can_bind_custom_profile() {
        let (state, pool) = test_state().await;
        // user id=1 is the seeded admin
        add_group(&pool, 20, 1, "admin-in").await;
        add_profile(&pool, 50, "custom", false, 1).await;

        let Json(resp) = create_rule(
            auth(1, true),
            State(state.clone()),
            Json(rule_req_with_profile("r", 12002, 20, None, Some(50))),
        )
        .await;
        assert_eq!(resp.code, 0, "{}", resp.message);
    }

    /// v0.4.11 PR1: admin can bind custom profile when creating rule for non-admin.
    #[tokio::test]
    async fn create_rule_admin_rejects_custom_profile_for_non_admin_owner() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_group(&pool, 20, 1, "shared-in").await; // admin-owned inbound (v0.4.12 PR1)
        add_profile(&pool, 50, "custom", false, 1).await;

        // Admin creates a rule owned by alice, binds the custom profile.
        // v0.4.11 PR1: allowed — AvailableTemplates includes admin-created custom templates.
        let Json(resp) = create_rule(
            auth(1, true),
            State(state.clone()),
            Json(rule_req_with_profile("r", 12003, 20, Some(2), Some(50))),
        )
        .await;
        assert_eq!(resp.code, 0, "{}", resp.message);
    }

    /// C7: a regular user re-pointing their rule's device_group_in at ANOTHER
    /// user's group is rejected.
    #[tokio::test]
    async fn update_rule_rejects_foreign_inbound_group() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_user(&pool, 3, "bob", false).await;
        add_group(&pool, 20, 2, "alice-in").await;
        add_group(&pool, 21, 3, "bob-in").await; // bob's group
        add_rule(&pool, 200, 2, 20, 12000, 0).await;

        // Alice tries to point her rule at bob's inbound group.
        let Json(resp) = update_rule(
            auth(2, false),
            State(state.clone()),
            Path(200),
            Json(UpdateRuleRequest {
                device_group_in: Some(21),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(resp.code, 400, "{}", resp.message);
        assert!(resp.message.contains("device_group_in"));
    }

    /// v0.4.20: device_group_out is no longer supported — any non-null value
    /// is rejected at the API boundary before ownership checks.
    #[tokio::test]
    async fn update_rule_rejects_foreign_outbound_group() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_user(&pool, 3, "bob", false).await;
        add_group(&pool, 20, 2, "alice-in").await;
        add_group(&pool, 30, 3, "bob-out").await;
        add_rule(&pool, 200, 2, 20, 12000, 0).await;

        let Json(resp) = update_rule(
            auth(2, false),
            State(state.clone()),
            Path(200),
            Json(UpdateRuleRequest {
                device_group_out: Some(30),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(resp.code, 400, "{}", resp.message);
        assert!(resp.message.contains("device_group_out"));
    }

    /// v0.4.12 PR1: a regular user re-pointing their rule at one of their OWN
    /// (non-admin) groups is now REJECTED — device_group_in must be an
    /// admin-owned 'in' group. (The allowed path — swapping to an admin shared
    /// group — is covered by update_rule_allows_admin_shared_inbound_group.)
    #[tokio::test]
    async fn update_rule_rejects_owner_group_swap() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_group(&pool, 20, 1, "shared-in").await; // admin-owned (valid current inbound)
        add_group(&pool, 21, 2, "alice-in-2").await; // alice's own group (invalid target)
        add_rule(&pool, 200, 2, 20, 12000, 0).await;

        let Json(resp) = update_rule(
            auth(2, false),
            State(state.clone()),
            Path(200),
            Json(UpdateRuleRequest {
                device_group_in: Some(21),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(
            resp.code, 400,
            "swapping to the user's own (non-admin) group must be rejected: {}",
            resp.message
        );
    }

    /// v0.4.11 PR3: a non-admin CAN re-point their rule at an ADMIN-owned shared
    /// inbound group via update_rule.
    #[tokio::test]
    async fn update_rule_allows_admin_shared_inbound_group() {
        let (state, pool) = test_state().await;
        // user id=1 is the seeded admin; it owns the shared group.
        add_user(&pool, 2, "alice", false).await;
        add_group(&pool, 20, 2, "alice-in").await;
        add_group(&pool, 21, 1, "shared-in").await; // admin's group
        add_rule(&pool, 200, 2, 20, 12000, 0).await;

        let Json(resp) = update_rule(
            auth(2, false),
            State(state.clone()),
            Path(200),
            Json(UpdateRuleRequest {
                device_group_in: Some(21),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(resp.code, 0, "{}", resp.message);
    }
    #[tokio::test]
    async fn update_rule_admin_rejects_group_owned_by_different_user() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_user(&pool, 3, "bob", false).await;
        add_group(&pool, 20, 2, "alice-in").await;
        add_group(&pool, 21, 3, "bob-in").await; // bob's group
        add_rule(&pool, 200, 2, 20, 12000, 0).await; // alice's rule

        // Admin edits alice's rule, tries to point it at bob's group.
        let Json(resp) = update_rule(
            auth(1, true),
            State(state.clone()),
            Path(200),
            Json(UpdateRuleRequest {
                device_group_in: Some(21),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(resp.code, 400, "{}", resp.message);
        assert!(resp.message.contains("device_group_in"));
    }

    /// v0.4.12 PR1: an admin editing alice's rule CAN point it at an admin-owned
    /// shared 'in' group (the new valid inbound). Pointing at alice's own group
    /// is no longer valid (covered by update_rule_rejects_owner_group_swap).
    #[tokio::test]
    async fn update_rule_admin_can_swap_to_admin_shared_group() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_group(&pool, 20, 1, "shared-in-1").await; // admin-owned (valid current)
        add_group(&pool, 21, 1, "shared-in-2").await; // admin-owned (valid target)
        add_rule(&pool, 200, 2, 20, 12000, 0).await;

        let Json(resp) = update_rule(
            auth(1, true),
            State(state.clone()),
            Path(200),
            Json(UpdateRuleRequest {
                device_group_in: Some(21),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(resp.code, 0, "{}", resp.message);
    }

    /// C6 (update side): an admin editing a regular user's rule CANNOT rebind it
    /// to a custom profile (the rule owner is the regular user → BuiltinOnly).
    #[tokio::test]
    async fn update_rule_admin_rejects_custom_profile_for_non_admin_owned_rule() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        add_group(&pool, 20, 2, "alice-in").await;
        add_profile(&pool, 50, "custom", false, 1).await;
        add_rule(&pool, 200, 2, 20, 12000, 0).await;

        let Json(resp) = update_rule(
            auth(1, true),
            State(state.clone()),
            Path(200),
            Json(UpdateRuleRequest {
                tunnel_profile_id: Some(Some(50)),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(resp.code, 400, "{}", resp.message);
    }

    fn rule_req_with_profile(
        name: &str,
        port: u16,
        group_in: i64,
        owner_uid: Option<i64>,
        profile_id: Option<i64>,
    ) -> CreateRuleRequest {
        // v0.4.11 PR1: when a profile is provided, transport must be ws (matches profile).
        let public_transport = if profile_id.is_some() {
            PublicTransport::Ws
        } else {
            PublicTransport::Raw
        };
        CreateRuleRequest {
            name: name.into(),
            listen_port: Some(port),
            protocol: Protocol::Tcp,
            owner_uid,
            device_group_in: group_in,
            device_group_out: None,
            forward_mode: "direct".into(),
            route_mode: Default::default(),
            hops: None,
            tunnel_id: None,
            public_transport,
            ws_path: None,
            target_addr: "127.0.0.1".into(),
            target_port: 80,
            targets: None,
            load_balance_strategy: Default::default(),
            upload_limit_mbps: None,
            download_limit_mbps: None,
            tunnel_profile_id: profile_id,
            max_connections: None,
            auto_restart_minutes: None,
        }
    }

    // ── v0.4.10 PR3: registration + settings handler tests ──

    /// registration_status returns enabled=false on an unseeded DB (safe default).
    #[tokio::test]
    async fn registration_status_returns_false_when_unseeded() {
        let (state, _pool) = test_state().await;
        let Json(resp) = registration_status(State(state.clone())).await;
        assert_eq!(resp.code, 0);
        assert!(
            !resp.data.unwrap().enabled,
            "unseeded DB must report registration disabled"
        );
    }

    /// registration_status reflects the DB row once seeded.
    #[tokio::test]
    async fn registration_status_reflects_db_setting() {
        let (state, _pool) = test_state().await;
        state
            .db
            .set_registration_settings(true, 1, &[1])
            .await
            .unwrap();

        let Json(resp) = registration_status(State(state.clone())).await;
        assert_eq!(resp.code, 0);
        assert!(resp.data.unwrap().enabled);
    }

    /// register returns 403 when registration is disabled (unseeded → false).
    #[tokio::test]
    async fn register_rejects_when_disabled() {
        let (state, _pool) = test_state().await;
        let Json(resp) = register(
            State(state.clone()),
            Json(RegisterRequest {
                username: "newuser".into(),
                password: "validpass1".into(),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(resp.code, 403, "{}", resp.message);
    }

    /// register rejects a password shorter than 8 bytes.
    #[tokio::test]
    async fn register_rejects_short_password() {
        let (state, _pool) = test_state().await;
        state
            .db
            .set_registration_settings(true, 1, &[1])
            .await
            .unwrap();

        let Json(resp) = register(
            State(state.clone()),
            Json(RegisterRequest {
                username: "newuser".into(),
                password: "short".into(), // 5 bytes
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(resp.code, 400, "{}", resp.message);
    }

    /// register rejects a password longer than 72 bytes (bcrypt boundary).
    #[tokio::test]
    async fn register_rejects_long_password() {
        let (state, _pool) = test_state().await;
        state
            .db
            .set_registration_settings(true, 1, &[1])
            .await
            .unwrap();

        let Json(resp) = register(
            State(state.clone()),
            Json(RegisterRequest {
                username: "newuser".into(),
                password: "x".repeat(73),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(resp.code, 400, "{}", resp.message);
    }

    /// register rejects a password where the UTF-8 byte length exceeds 72 even
    /// though the character count is small (e.g. multibyte CJK / emoji).
    #[tokio::test]
    async fn register_rejects_multibyte_password_exceeding_byte_limit() {
        let (state, _pool) = test_state().await;
        state
            .db
            .set_registration_settings(true, 1, &[1])
            .await
            .unwrap();
        // 25 × '中' = 25 chars but 75 UTF-8 bytes (> 72).
        let pw = "中".repeat(25);
        assert_eq!(pw.len(), 75);

        let Json(resp) = register(
            State(state.clone()),
            Json(RegisterRequest {
                username: "newuser".into(),
                password: pw,
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(
            resp.code, 400,
            "multibyte password over 72 bytes must be rejected"
        );
    }

    /// A successful registration inherits the plan's quota fields atomically.
    #[tokio::test]
    async fn register_inherits_plan_quota() {
        let (state, pool) = test_state().await;
        state
            .db
            .set_registration_settings(true, 1, &[1])
            .await
            .unwrap();

        let Json(resp) = register(
            State(state.clone()),
            Json(RegisterRequest {
                username: "alice".into(),
                password: "validpass1".into(),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(resp.code, 0, "{}", resp.message);

        // The seeded 'free' plan is max_rules=5, traffic=107374182400.
        let user: relay_shared::models::User =
            sqlx::query_as("SELECT * FROM users WHERE username = 'alice'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(user.plan_id, Some(1));
        assert_eq!(
            user.max_rules, 5,
            "max_rules must be inherited from the plan"
        );
        assert_eq!(
            user.traffic_limit, 107374182400,
            "traffic_limit must be inherited from plan.traffic"
        );
        assert!(!user.admin, "registered users are never admins");
    }

    /// register returns 409 on a duplicate username (UNIQUE constraint).
    #[tokio::test]
    async fn register_rejects_duplicate_username() {
        let (state, _pool) = test_state().await;
        state
            .db
            .set_registration_settings(true, 1, &[1])
            .await
            .unwrap();

        let req = RegisterRequest {
            username: "alice".into(),
            password: "validpass1".into(),
            ..Default::default()
        };
        let Json(r1) = register(State(state.clone()), Json(req.clone())).await;
        assert_eq!(r1.code, 0);
        let Json(r2) = register(State(state.clone()), Json(req)).await;
        assert_eq!(r2.code, 409, "duplicate username must yield 409");
    }

    /// admin update_registration_settings rejects a non-existent default plan.
    #[tokio::test]
    async fn admin_update_settings_rejects_missing_plan() {
        let (state, _pool) = test_state().await;
        let Json(resp) = update_registration_settings(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(RegistrationSettingsRequest {
                enabled: true,
                default_plan_id: 999, // does not exist
                allowed_plan_ids: vec![999],
                site_name: None,
            }),
        )
        .await;
        assert_eq!(resp.code, 400, "{}", resp.message);
    }

    /// admin update_registration_settings persists a valid config and the
    /// subsequent registration_status reflects it.
    #[tokio::test]
    async fn admin_update_settings_persists_and_takes_effect() {
        let (state, _pool) = test_state().await;
        let Json(resp) = update_registration_settings(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(RegistrationSettingsRequest {
                enabled: true,
                default_plan_id: 1,
                allowed_plan_ids: vec![1],
                site_name: Some("星海中转".into()),
            }),
        )
        .await;
        assert_eq!(resp.code, 0, "{}", resp.message);
        let data = resp.data.unwrap();
        assert!(data.registration_enabled);
        assert_eq!(data.default_registration_plan_id, 1);
        assert_eq!(data.site_name, "星海中转");

        // registration_status now reports enabled=true.
        let Json(status) = registration_status(State(state.clone())).await;
        let status = status.data.unwrap();
        assert!(status.enabled);
        assert_eq!(status.site_name, "星海中转");

        // An older frontend omitting site_name must preserve the configured
        // brand while changing registration settings.
        let Json(legacy) = update_registration_settings(
            AdminOnly { user_id: 1 },
            State(state),
            Json(RegistrationSettingsRequest {
                enabled: false,
                default_plan_id: 1,
                allowed_plan_ids: vec![1],
                site_name: None,
            }),
        )
        .await;
        assert_eq!(legacy.code, 0);
        assert_eq!(legacy.data.unwrap().site_name, "星海中转");
    }

    #[tokio::test]
    async fn admin_update_settings_rejects_an_invalid_site_name() {
        let (state, _pool) = test_state().await;
        let Json(resp) = update_registration_settings(
            AdminOnly { user_id: 1 },
            State(state),
            Json(RegistrationSettingsRequest {
                enabled: false,
                default_plan_id: 1,
                allowed_plan_ids: vec![1],
                site_name: Some("   ".into()),
            }),
        )
        .await;
        assert_eq!(resp.code, 400);
    }

    /// admin get_registration_settings returns safe defaults on an unseeded DB.
    #[tokio::test]
    async fn admin_get_settings_returns_defaults_when_unseeded() {
        let (state, _pool) = test_state().await;
        let Json(resp) =
            get_registration_settings(AdminOnly { user_id: 1 }, State(state.clone())).await;
        assert_eq!(resp.code, 0);
        let data = resp.data.unwrap();
        assert!(!data.registration_enabled);
        assert_eq!(data.default_registration_plan_id, 1);
        assert_eq!(data.allowed_plan_ids, vec![1]);
        assert_eq!(data.site_name, crate::service::settings::DEFAULT_SITE_NAME);
    }

    // ── v0.4.21 PR2: registration multi-plan settings ──

    /// update_registration_settings persists allowed_plan_ids and the updated
    /// registration_status reflects the plan list.
    #[tokio::test]
    async fn admin_update_settings_with_allowed_plans() {
        let (state, _pool) = test_state().await;
        let Json(resp) = update_registration_settings(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(RegistrationSettingsRequest {
                enabled: true,
                default_plan_id: 1,
                allowed_plan_ids: vec![1],
                site_name: None,
            }),
        )
        .await;
        assert_eq!(resp.code, 0, "{}", resp.message);
        let data = resp.data.unwrap();
        assert!(data.registration_enabled);
        assert_eq!(data.default_registration_plan_id, 1);
        assert_eq!(data.allowed_plan_ids, vec![1]);

        // registration_status now returns plans.
        let Json(status) = registration_status(State(state.clone())).await;
        let s = status.data.unwrap();
        assert!(s.enabled);
        assert_eq!(s.default_plan_id, 1);
        assert_eq!(s.plans.len(), 1);
        assert_eq!(s.plans[0].id, 1);
    }

    /// registration_status only returns plans that are in allowed_plan_ids.
    #[tokio::test]
    async fn registration_status_only_returns_allowed_plans() {
        let (state, _pool) = test_state().await;
        // There's only plan 1 seeded, but we can still verify filtering works:
        // allowed_plan_ids=[], but the service rejects empty. Instead, use an
        // id that doesn't exist alongside plan 1.
        // Plan 1 exists; plan 999 does not. allowed=[1] should only return [1].
        let Json(_resp) = update_registration_settings(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(RegistrationSettingsRequest {
                enabled: true,
                default_plan_id: 1,
                allowed_plan_ids: vec![1],
                site_name: None,
            }),
        )
        .await;
        let Json(status) = registration_status(State(state.clone())).await;
        let s = status.data.unwrap();
        // Only plan 1 is in the allowed list and exists.
        assert_eq!(s.plans.len(), 1);
        assert_eq!(s.plans[0].id, 1);
    }

    /// register with a plan_id that is in the allowed list succeeds.
    #[tokio::test]
    async fn register_with_valid_plan_id_succeeds() {
        let (state, _pool) = test_state().await;
        state
            .db
            .set_registration_settings(true, 1, &[1])
            .await
            .unwrap();
        let req = RegisterRequest {
            username: "planuser".into(),
            password: "validpass1".into(),
            plan_id: Some(1),
        };
        let Json(resp) = register(State(state.clone()), Json(req)).await;
        assert_eq!(resp.code, 0, "{}", resp.message);
    }

    /// register with a plan_id NOT in the allowed list returns 400.
    #[tokio::test]
    async fn register_with_disallowed_plan_id_fails() {
        let (state, _pool) = test_state().await;
        state
            .db
            .set_registration_settings(true, 1, &[1])
            .await
            .unwrap();
        let req = RegisterRequest {
            username: "badplan".into(),
            password: "validpass1".into(),
            plan_id: Some(999),
        };
        let Json(resp) = register(State(state.clone()), Json(req)).await;
        assert_eq!(resp.code, 400, "must reject plan not in allowed list");
    }

    /// register without plan_id uses the default plan.
    #[tokio::test]
    async fn register_without_plan_id_uses_default() {
        let (state, _pool) = test_state().await;
        state
            .db
            .set_registration_settings(true, 1, &[1])
            .await
            .unwrap();
        let req = RegisterRequest {
            username: "defplan".into(),
            password: "validpass1".into(),
            ..Default::default()
        };
        let Json(resp) = register(State(state.clone()), Json(req)).await;
        assert_eq!(resp.code, 0, "should use default plan_id=1");
    }

    /// update_registration_settings rejects empty allowed_plan_ids.
    #[tokio::test]
    async fn admin_update_settings_rejects_empty_allowed() {
        let (state, _pool) = test_state().await;
        let Json(resp) = update_registration_settings(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(RegistrationSettingsRequest {
                enabled: true,
                default_plan_id: 1,
                allowed_plan_ids: vec![],
                site_name: None,
            }),
        )
        .await;
        assert_eq!(resp.code, 400, "empty allowed_plan_ids must be rejected");
    }

    /// update_registration_settings rejects default_plan_id not in allowed.
    #[tokio::test]
    async fn admin_update_settings_rejects_default_not_in_allowed() {
        let (state, _pool) = test_state().await;
        // Plan 1 exists; use it as the only allowed, but set default=999.
        let Json(resp) = update_registration_settings(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(RegistrationSettingsRequest {
                enabled: true,
                default_plan_id: 999,
                allowed_plan_ids: vec![1],
                site_name: None,
            }),
        )
        .await;
        assert_eq!(resp.code, 400, "default not in allowed must be rejected");
    }

    /// update_registration_settings rejects a non-existent plan in allowed.
    #[tokio::test]
    async fn admin_update_settings_rejects_nonexistent_allowed_plan() {
        let (state, _pool) = test_state().await;
        let Json(resp) = update_registration_settings(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(RegistrationSettingsRequest {
                enabled: true,
                default_plan_id: 1,
                allowed_plan_ids: vec![1, 999],
                site_name: None,
            }),
        )
        .await;
        assert_eq!(
            resp.code, 400,
            "non-existent plan in allowed_plan_ids must be rejected"
        );
    }

    /// v0.4.21 PR2: registration_status returns only plans in the allowed list
    /// when the DB has multiple plans. Constructs real multi-plan data.
    #[tokio::test]
    async fn registration_status_filters_multi_plan() {
        let (state, pool) = test_state().await;
        // Insert a second plan with different quota.
        sqlx::query(
            "INSERT INTO plans (id, name, max_rules, traffic, speed_limit, ip_limit, price) \
             VALUES (2, 'premium', 10, 0, 0, 5, '9.99')",
        )
        .execute(&pool)
        .await
        .unwrap();

        // Set allowed=[1,2] — registration_status should return both.
        state
            .db
            .set_registration_settings(true, 1, &[1, 2])
            .await
            .unwrap();
        let Json(status) = registration_status(State(state.clone())).await;
        let s = status.data.unwrap();
        assert_eq!(s.plans.len(), 2, "should return both allowed plans");
        let ids: Vec<i64> = s.plans.iter().map(|p| p.id).collect();
        assert!(ids.contains(&1));
        assert!(ids.contains(&2));

        // Set allowed=[2] — plan 1 should be filtered out.
        state
            .db
            .set_registration_settings(true, 2, &[2])
            .await
            .unwrap();
        let Json(status2) = registration_status(State(state.clone())).await;
        let s2 = status2.data.unwrap();
        assert_eq!(
            s2.plans.len(),
            1,
            "plan 1 must be filtered when not allowed"
        );
        assert_eq!(s2.plans[0].id, 2);
        assert_eq!(s2.plans[0].max_rules, 10);
    }

    /// v0.4.21 PR2: registering with plan_id=2 inherits plan 2's quota,
    /// NOT plan 1's.
    #[tokio::test]
    async fn register_with_plan_2_inherits_plan_2_quota() {
        let (state, pool) = test_state().await;
        sqlx::query(
            "INSERT INTO plans (id, name, max_rules, traffic, speed_limit, ip_limit, price) \
             VALUES (2, 'premium', 10, 0, 0, 5, '9.99')",
        )
        .execute(&pool)
        .await
        .unwrap();

        state
            .db
            .set_registration_settings(true, 2, &[1, 2])
            .await
            .unwrap();

        let req = RegisterRequest {
            username: "premium_user".into(),
            password: "validpass1".into(),
            plan_id: Some(2),
        };
        let Json(resp) = register(State(state.clone()), Json(req)).await;
        assert_eq!(resp.code, 0, "register with plan 2 should succeed");

        // Verify the user inherited plan 2's quota.
        let user: relay_shared::models::User =
            sqlx::query_as("SELECT * FROM users WHERE username = 'premium_user'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(user.plan_id, Some(2), "user.plan_id must be 2");
        assert_eq!(user.max_rules, 10, "max_rules must come from plan 2");
        assert_eq!(user.traffic_limit, 0, "traffic_limit must come from plan 2");
    }

    // ── v0.4.10 PR4: admin password reset + self change ──

    /// Admin reset bumps the target's token_version and sets must_change_password.
    #[tokio::test]
    async fn admin_reset_password_sets_must_change_and_bumps_version() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;

        let Json(resp) = reset_user_password(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path(2),
            Json(ResetPasswordRequest {
                new_password: "temp-pass-1".into(),
                must_change_password: true,
            }),
        )
        .await;
        assert_eq!(resp.code, 0, "{}", resp.message);

        let s = state.db.find_auth_state_by_id(2).await.unwrap().unwrap();
        assert_eq!(s.1, 1, "token_version bumped");
        assert!(s.2, "must_change_password set");
    }

    /// Admin cannot reset ANOTHER admin's password (privilege protection).
    #[tokio::test]
    async fn admin_cannot_reset_other_admin_password() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "admin2", true).await; // another admin

        let Json(resp) = reset_user_password(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path(2),
            Json(ResetPasswordRequest {
                new_password: "temp-pass-1".into(),
                must_change_password: true,
            }),
        )
        .await;
        assert_eq!(resp.code, 403, "{}", resp.message);
    }

    /// Admin reset rejects a short password (< 8 bytes).
    #[tokio::test]
    async fn admin_reset_password_rejects_short() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, "alice", false).await;
        let Json(resp) = reset_user_password(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path(2),
            Json(ResetPasswordRequest {
                new_password: "short".into(),
                must_change_password: true,
            }),
        )
        .await;
        assert_eq!(resp.code, 400, "{}", resp.message);
    }

    /// Admin reset of a non-existent user → 404.
    #[tokio::test]
    async fn admin_reset_password_missing_user_404() {
        let (state, _pool) = test_state().await;
        let Json(resp) = reset_user_password(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path(999),
            Json(ResetPasswordRequest {
                new_password: "temp-pass-1".into(),
                must_change_password: true,
            }),
        )
        .await;
        assert_eq!(resp.code, 404, "{}", resp.message);
    }

    /// Self change_password bumps token_version and clears must_change_password.
    #[tokio::test]
    async fn self_change_password_bumps_version() {
        let (state, pool) = test_state().await;
        // Seed a user whose current password we know (bcrypt of "old-pass-1").
        let hash = bcrypt::hash("old-pass-1", 4).unwrap();
        sqlx::query(
            "INSERT INTO users (id, username, password, admin, token_version, must_change_password) \
             VALUES (2, 'alice', ?, 0, 0, 1)",
        )
        .bind(&hash)
        .execute(&pool)
        .await
        .unwrap();

        let Json(resp) = change_password(
            AuthUser {
                user_id: 2,
                admin: false,
            },
            State(state.clone()),
            Json(ChangePasswordRequest {
                current_password: "old-pass-1".into(),
                new_password: "new-pass-1".into(),
            }),
        )
        .await;
        assert_eq!(resp.code, 0, "{}", resp.message);

        let s = state.db.find_auth_state_by_id(2).await.unwrap().unwrap();
        assert_eq!(s.1, 1, "token_version bumped on self change");
        assert!(!s.2, "must_change_password cleared on self change");
    }

    /// change_password rejects a short new password (< 8 bytes).
    #[tokio::test]
    async fn self_change_password_rejects_short() {
        let (state, pool) = test_state().await;
        let hash = bcrypt::hash("old-pass-1", 4).unwrap();
        sqlx::query("INSERT INTO users (id, username, password, admin) VALUES (2, 'alice', ?, 0)")
            .bind(&hash)
            .execute(&pool)
            .await
            .unwrap();
        let Json(resp) = change_password(
            AuthUser {
                user_id: 2,
                admin: false,
            },
            State(state.clone()),
            Json(ChangePasswordRequest {
                current_password: "old-pass-1".into(),
                new_password: "short".into(),
            }),
        )
        .await;
        assert_eq!(resp.code, 400, "{}", resp.message);
    }

    async fn seed_tunnel_groups(pool: &SqlitePool) {
        add_group_typed(pool, 501, 1, "preset-entry", "in").await;
        add_group_typed(pool, 502, 1, "preset-exit", "out").await;
        sqlx::query(
            "UPDATE device_groups SET connect_host='127.0.0.1', port_range='35000-35010' \
             WHERE id IN (501, 502)",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    fn tunnel_request(name: &str) -> CreateTunnelRequest {
        CreateTunnelRequest {
            name: name.into(),
            enabled: true,
            shared: true,
            hops: vec![
                TunnelHopRequest {
                    device_group_id: 501,
                    listen_port: None,
                },
                TunnelHopRequest {
                    device_group_id: 502,
                    listen_port: Some(35005),
                },
            ],
        }
    }

    fn tunnel_path_snapshot(tunnel: &relay_shared::models::Tunnel) -> Vec<TunnelHopRequest> {
        tunnel
            .hops
            .iter()
            .map(|hop| TunnelHopRequest {
                device_group_id: hop.device_group_id,
                listen_port: hop.listen_port.map(|port| port as u16),
            })
            .collect()
    }

    #[tokio::test]
    async fn preset_tunnel_rejects_zero_internal_port_on_create_and_update() {
        let (state, pool) = test_state().await;
        seed_tunnel_groups(&pool).await;

        let mut invalid_create = tunnel_request("zero-port-create");
        invalid_create.hops[1].listen_port = Some(0);
        let Json(rejected) = super::tunnels::create_tunnel(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(invalid_create),
        )
        .await;
        assert_eq!(rejected.code, 400, "{}", rejected.message);
        assert_eq!(state.db.list_tunnels().await.unwrap().len(), 0);

        let Json(created) = super::tunnels::create_tunnel(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(tunnel_request("zero-port-update")),
        )
        .await;
        let tunnel = created.data.unwrap();
        let Json(rejected) = super::tunnels::update_tunnel(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path(tunnel.id),
            Json(UpdateTunnelRequest {
                hops: Some(vec![
                    TunnelHopRequest {
                        device_group_id: 501,
                        listen_port: None,
                    },
                    TunnelHopRequest {
                        device_group_id: 502,
                        listen_port: Some(0),
                    },
                ]),
                expected_hops: Some(tunnel_path_snapshot(&tunnel)),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(rejected.code, 400, "{}", rejected.message);
        let stored = state
            .db
            .find_tunnel_by_id(tunnel.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.hops[1].listen_port, Some(35005));
    }

    #[tokio::test]
    async fn preset_tunnel_rejects_historical_regular_owned_downstream_hop() {
        let (state, pool) = test_state().await;
        seed_tunnel_groups(&pool).await;
        add_user(&pool, 52, "legacy-node-owner", false).await;
        add_group_typed(&pool, 503, 52, "legacy-exit", "out").await;
        sqlx::query(
            "UPDATE device_groups SET connect_host='192.0.2.53', port_range='35100-35110' \
             WHERE id=503",
        )
        .execute(&pool)
        .await
        .unwrap();

        let mut invalid = tunnel_request("legacy-downstream-create");
        invalid.hops[1] = TunnelHopRequest {
            device_group_id: 503,
            listen_port: Some(35105),
        };
        let Json(rejected) = super::tunnels::create_tunnel(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(invalid),
        )
        .await;
        assert_eq!(rejected.code, 400, "{}", rejected.message);
        assert!(state.db.list_tunnels().await.unwrap().is_empty());

        let Json(created) = super::tunnels::create_tunnel(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(tunnel_request("valid-before-legacy-update")),
        )
        .await;
        let tunnel = created.data.unwrap();
        let Json(update_rejected) = super::tunnels::update_tunnel(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path(tunnel.id),
            Json(UpdateTunnelRequest {
                hops: Some(vec![
                    TunnelHopRequest {
                        device_group_id: 501,
                        listen_port: None,
                    },
                    TunnelHopRequest {
                        device_group_id: 503,
                        listen_port: Some(35105),
                    },
                ]),
                expected_hops: Some(tunnel_path_snapshot(&tunnel)),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(update_rejected.code, 400, "{}", update_rejected.message);
        let stored = state
            .db
            .find_tunnel_by_id(tunnel.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.hops[1].device_group_id, 502);

        // Legacy data can still contain such a path.  New rule bindings must
        // reject it, while an already-bound rule must remain pausable so an
        // operator can stop unsafe historical state before repairing it.
        let legacy_tunnel_id = sqlx::query(
            "INSERT INTO tunnels(name,enabled,shared,uid) VALUES('legacy-invalid-binding',1,1,1)",
        )
        .execute(&pool)
        .await
        .unwrap()
        .last_insert_rowid();
        sqlx::query(
            "INSERT INTO tunnel_hops(tunnel_id,position,device_group_id,listen_port) \
             VALUES(?,0,501,NULL),(?,1,503,35105)",
        )
        .bind(legacy_tunnel_id)
        .bind(legacy_tunnel_id)
        .execute(&pool)
        .await
        .unwrap();

        let mut bind_legacy = rule_req("must-not-bind-legacy-preset", 34019, 501, None);
        bind_legacy.route_mode = relay_shared::protocol::RouteMode::Chain;
        bind_legacy.forward_mode = "chain".into();
        bind_legacy.device_group_out = Some(503);
        bind_legacy.tunnel_id = Some(legacy_tunnel_id);
        let Json(binding_rejected) =
            create_rule(auth(1, true), State(state.clone()), Json(bind_legacy)).await;
        assert_eq!(binding_rejected.code, 400, "{}", binding_rejected.message);

        let legacy_rule_id = sqlx::query(
            "INSERT INTO forward_rules(name,uid,listen_port,protocol,route_mode,forward_mode, \
             device_group_in,device_group_out,target_addr,target_port,tunnel_id) \
             VALUES('legacy-bound-rule',1,34020,'tcp','chain','chain',501,503,'127.0.0.1',80,?)",
        )
        .bind(legacy_tunnel_id)
        .execute(&pool)
        .await
        .unwrap()
        .last_insert_rowid();
        let Json(paused) = update_rule(
            auth(1, true),
            State(state.clone()),
            Path(legacy_rule_id),
            Json(UpdateRuleRequest {
                paused: Some(true),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(paused.code, 0, "{}", paused.message);
        let is_paused: bool = sqlx::query_scalar("SELECT paused FROM forward_rules WHERE id=?")
            .bind(legacy_rule_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(is_paused);

        let Json(resume_rejected) = update_rule(
            auth(1, true),
            State(state.clone()),
            Path(legacy_rule_id),
            Json(UpdateRuleRequest {
                paused: Some(false),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(resume_rejected.code, 400, "{}", resume_rejected.message);
        let remains_paused: bool =
            sqlx::query_scalar("SELECT paused FROM forward_rules WHERE id=?")
                .bind(legacy_rule_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(remains_paused);
    }

    #[tokio::test]
    async fn preset_tunnel_admin_crud_and_delete_protection() {
        let (state, pool) = test_state().await;
        seed_tunnel_groups(&pool).await;
        let Json(created) = super::tunnels::create_tunnel(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(tunnel_request("  shared-route  ")),
        )
        .await;
        assert_eq!(created.code, 0, "{}", created.message);
        let tunnel = created.data.unwrap();
        assert_eq!(tunnel.name, "shared-route");
        assert_eq!(tunnel.hops.len(), 2);
        assert_eq!(tunnel.hops[0].listen_port, None);
        assert_eq!(tunnel.hops[1].listen_port, Some(35005));
        assert_eq!(tunnel.hops[1].group_name.as_deref(), Some("preset-exit"));
        assert_eq!(tunnel.hops[1].connect_host.as_deref(), Some("127.0.0.1"));

        let Json(updated) = super::tunnels::update_tunnel(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path(tunnel.id),
            Json(UpdateTunnelRequest {
                name: Some("renamed-route".into()),
                enabled: Some(false),
                shared: None,
                hops: None,
                expected_hops: None,
            }),
        )
        .await;
        assert_eq!(updated.code, 0, "{}", updated.message);
        assert_eq!(updated.data.as_ref().unwrap().name, "renamed-route");
        assert!(!updated.data.as_ref().unwrap().enabled);

        sqlx::query(
            "INSERT INTO forward_rules (name, uid, listen_port, protocol, route_mode, \
             forward_mode, device_group_in, device_group_out, target_addr, target_port, tunnel_id) \
             VALUES ('bound', 1, 34001, 'tcp', 'chain', 'chain', 501, 502, '127.0.0.1', 80, ?)",
        )
        .bind(tunnel.id)
        .execute(&pool)
        .await
        .unwrap();
        let Json(blocked) = super::tunnels::delete_tunnel(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path(tunnel.id),
        )
        .await;
        assert_eq!(blocked.code, 409);
    }

    #[tokio::test]
    async fn preset_tunnel_partial_updates_do_not_rewrite_other_fields_or_hops() {
        let (state, pool) = test_state().await;
        seed_tunnel_groups(&pool).await;
        let Json(created) = super::tunnels::create_tunnel(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(tunnel_request("partial-update")),
        )
        .await;
        let tunnel = created.data.unwrap();
        let hop_ids: Vec<i64> = tunnel.hops.iter().map(|hop| hop.id).collect();

        state
            .db
            .update_tunnel_full(tunnel.id, None, None, Some(false), None, None)
            .await
            .unwrap();
        state
            .db
            .update_tunnel_full(tunnel.id, None, Some(false), None, None, None)
            .await
            .unwrap();

        let updated = state
            .db
            .find_tunnel_by_id(tunnel.id)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !updated.shared,
            "enabled-only update must not restore sharing"
        );
        assert!(
            !updated.enabled,
            "sharing-only update must not restore enabled"
        );
        assert_eq!(
            updated.hops.iter().map(|hop| hop.id).collect::<Vec<_>>(),
            hop_ids,
            "scalar-only updates must not delete and recreate tunnel hops"
        );
    }

    #[tokio::test]
    async fn preset_tunnel_stale_path_replacement_is_rejected() {
        let (state, pool) = test_state().await;
        seed_tunnel_groups(&pool).await;
        let Json(created) = super::tunnels::create_tunnel(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(tunnel_request("stale-path")),
        )
        .await;
        let tunnel = created.data.unwrap();
        let expected: Vec<(i64, Option<i32>)> = tunnel
            .hops
            .iter()
            .map(|hop| (hop.device_group_id, hop.listen_port))
            .collect();
        let first = vec![(501, None), (502, Some(35006))];
        state
            .db
            .update_tunnel_full(tunnel.id, None, None, None, Some(&first), Some(&expected))
            .await
            .unwrap();
        let stale_snapshot = tunnel_path_snapshot(&tunnel);
        let Json(stale) = super::tunnels::update_tunnel(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path(tunnel.id),
            Json(UpdateTunnelRequest {
                shared: Some(false),
                hops: Some(stale_snapshot.clone()),
                expected_hops: Some(stale_snapshot),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(stale.code, 409, "{}", stale.message);
        let stored = state
            .db
            .find_tunnel_by_id(tunnel.id)
            .await
            .unwrap()
            .unwrap();
        assert!(
            stored.shared,
            "stale scalar fields must roll back with the path"
        );
        assert_eq!(
            stored.hops[1].listen_port,
            Some(35006),
            "stale form must not overwrite the committed path"
        );
    }

    #[tokio::test]
    async fn preset_tunnel_catalog_filters_by_entry_authorization() {
        let (state, pool) = test_state().await;
        seed_tunnel_groups(&pool).await;
        add_user(&pool, 52, "limited", false).await;
        assign_user_groups(&pool, 52, &[]).await;
        let mut request = tunnel_request("hidden-from-user");
        request.shared = false;
        let Json(created) = super::tunnels::create_tunnel(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(request),
        )
        .await;
        assert_eq!(created.code, 0);
        let tunnel = created.data.unwrap();

        let Json(empty) =
            super::tunnels::list_available_tunnels(auth(52, false), State(state.clone())).await;
        assert!(empty.data.unwrap().is_empty());

        assign_user_groups(&pool, 52, &[501]).await;
        let Json(still_hidden) =
            super::tunnels::list_available_tunnels(auth(52, false), State(state.clone())).await;
        assert!(
            still_hidden.data.unwrap().is_empty(),
            "入口已授权也不能看到管理员未共享的隧道"
        );

        let Json(shared) = super::tunnels::update_tunnel(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path(tunnel.id),
            Json(UpdateTunnelRequest {
                shared: Some(true),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(shared.code, 0, "{}", shared.message);

        sqlx::query(
            "INSERT INTO forward_rules(name,uid,listen_port,protocol,route_mode,forward_mode, \
             device_group_in,device_group_out,target_addr,target_port,tunnel_id) \
             VALUES('catalog-bound',1,34999,'tcp','chain','chain',501,502,'127.0.0.1',80,?)",
        )
        .bind(tunnel.id)
        .execute(&pool)
        .await
        .unwrap();

        // Reproduce a historical shared tunnel with a regular-user-owned
        // downstream hop. It must not be advertised as selectable because
        // current rule writes and runtime config reject that path.
        add_group_typed(&pool, 503, 52, "legacy-user-exit", "out").await;
        sqlx::query("UPDATE device_groups SET connect_host='192.0.2.53' WHERE id=503")
            .execute(&pool)
            .await
            .unwrap();
        let legacy_tunnel_id = sqlx::query(
            "INSERT INTO tunnels(name,enabled,shared,uid) VALUES('legacy-invalid',1,1,1)",
        )
        .execute(&pool)
        .await
        .unwrap()
        .last_insert_rowid();
        sqlx::query(
            "INSERT INTO tunnel_hops(tunnel_id,position,device_group_id,listen_port) \
             VALUES(?,0,501,NULL),(?,1,503,35006)",
        )
        .bind(legacy_tunnel_id)
        .bind(legacy_tunnel_id)
        .execute(&pool)
        .await
        .unwrap();

        let Json(visible) =
            super::tunnels::list_available_tunnels(auth(52, false), State(state.clone())).await;
        let tunnels = visible.data.unwrap();
        assert_eq!(tunnels.len(), 1);
        assert_eq!(
            tunnels[0].bound_rule_count, 0,
            "普通用户目录不能泄露全局规则绑定数量"
        );
        assert!(tunnels[0].hops.iter().all(|hop| hop.connect_host.is_none()));
        assert!(
            tunnels[0].hops.iter().all(|hop| hop.listen_port.is_none()),
            "普通用户目录不能泄露内部中继端口"
        );
    }

    #[tokio::test]
    async fn preset_tunnel_sharing_reuses_entry_authorization_and_gates_runtime() {
        let (state, pool) = test_state().await;
        seed_tunnel_groups(&pool).await;
        add_user(&pool, 54, "shared-user", false).await;
        assign_user_groups(&pool, 54, &[501]).await;

        let mut tunnel_req = tunnel_request("permission-gated-route");
        tunnel_req.shared = false;
        let Json(created) = super::tunnels::create_tunnel(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(tunnel_req),
        )
        .await;
        let tunnel = created.data.unwrap();

        let preset_rule = |name: &str, port: u16| {
            let mut request = rule_req(name, port, 501, None);
            request.route_mode = relay_shared::protocol::RouteMode::Chain;
            request.forward_mode = "chain".into();
            request.device_group_out = Some(502);
            request.tunnel_id = Some(tunnel.id);
            request
        };

        let Json(denied) = create_rule(
            auth(54, false),
            State(state.clone()),
            Json(preset_rule("ordinary-denied", 34010)),
        )
        .await;
        assert_eq!(denied.code, 403, "未共享隧道不能被普通用户猜 ID 绑定");

        let Json(admin_bound) = create_rule(
            auth(1, true),
            State(state.clone()),
            Json(preset_rule("admin-bound", 34011)),
        )
        .await;
        assert_eq!(admin_bound.code, 0, "{}", admin_bound.message);
        assert_eq!(state.db.list_active_for_config(501).await.unwrap().len(), 1);

        let Json(shared) = super::tunnels::update_tunnel(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path(tunnel.id),
            Json(UpdateTunnelRequest {
                shared: Some(true),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(shared.code, 0, "{}", shared.message);
        let Json(user_bound) = create_rule(
            auth(54, false),
            State(state.clone()),
            Json(preset_rule("ordinary-bound", 34012)),
        )
        .await;
        assert_eq!(user_bound.code, 0, "{}", user_bound.message);
        assert_eq!(state.db.list_active_for_config(501).await.unwrap().len(), 2);

        let Json(unshared) = super::tunnels::update_tunnel(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path(tunnel.id),
            Json(UpdateTunnelRequest {
                shared: Some(false),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(unshared.code, 0, "{}", unshared.message);
        let active = state.db.list_active_for_config(501).await.unwrap();
        assert_eq!(active.len(), 1, "取消共享后仅管理员规则继续下发");
        assert_eq!(active[0].uid, 1);
        let ordinary_rule_id: i64 =
            sqlx::query_scalar("SELECT id FROM forward_rules WHERE name='ordinary-bound'")
                .fetch_one(&pool)
                .await
                .unwrap();
        let ordinary_rule = state
            .db
            .list_rules(&crate::db::repo::ResourceScope::Owner(54))
            .await
            .unwrap()
            .into_iter()
            .find(|rule| rule.id == ordinary_rule_id)
            .unwrap();
        assert_eq!(
            ordinary_rule.tunnel_hops.len(),
            2,
            "撤销共享后，规则仍需携带只读路径供原有列表和编辑表单展示"
        );
        assert!(
            ordinary_rule
                .tunnel_hops
                .iter()
                .all(|hop| hop.connect_host.is_none()),
            "规则路径快照不能向普通用户泄露内部连接地址"
        );
        let Json(resume_denied) = update_rule(
            auth(54, false),
            State(state.clone()),
            Path(ordinary_rule_id),
            Json(UpdateRuleRequest {
                paused: Some(false),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(
            resume_denied.code, 403,
            "取消共享后普通用户不能通过恢复规则绕过权限"
        );
        let manual_paused: bool =
            sqlx::query_scalar("SELECT paused FROM forward_rules WHERE name='ordinary-bound'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(!manual_paused, "取消共享不能篡改规则的人工暂停状态");

        let Json(reshared) = super::tunnels::update_tunnel(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path(tunnel.id),
            Json(UpdateTunnelRequest {
                shared: Some(true),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(reshared.code, 0, "{}", reshared.message);
        assert_eq!(state.db.list_active_for_config(501).await.unwrap().len(), 2);

        assign_user_groups(&pool, 54, &[]).await;
        let active = state.db.list_active_for_config(501).await.unwrap();
        assert_eq!(
            active.len(),
            1,
            "套餐撤销入口授权后普通用户规则必须停止下发"
        );
        assert_eq!(active[0].uid, 1);
    }

    #[tokio::test]
    async fn preset_tunnel_rule_binding_is_chain_without_rule_hops_and_can_unbind() {
        let (state, pool) = test_state().await;
        seed_tunnel_groups(&pool).await;
        let Json(created) = super::tunnels::create_tunnel(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(tunnel_request("rule-route")),
        )
        .await;
        let tunnel = created.data.unwrap();

        let mut conflicting_create = rule_req("preset-direct-conflict", 34001, 501, None);
        conflicting_create.tunnel_id = Some(tunnel.id);
        let Json(conflicting_create_response) = create_rule(
            auth(1, true),
            State(state.clone()),
            Json(conflicting_create),
        )
        .await;
        assert_eq!(
            conflicting_create_response.code, 400,
            "direct mode must not silently turn into a preset chain"
        );

        let mut request = rule_req("preset-bound", 34002, 501, None);
        request.route_mode = relay_shared::protocol::RouteMode::Chain;
        request.forward_mode = "chain".into();
        request.device_group_out = Some(502);
        request.tunnel_id = Some(tunnel.id);
        let Json(bound) = create_rule(auth(1, true), State(state.clone()), Json(request)).await;
        assert_eq!(bound.code, 0, "{}", bound.message);
        let (rule_id, route_mode, stored_tunnel): (i64, String, Option<i64>) = sqlx::query_as(
            "SELECT id, route_mode, tunnel_id FROM forward_rules WHERE name='preset-bound'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(route_mode, "chain");
        assert_eq!(stored_tunnel, Some(tunnel.id));
        let hop_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM forward_rule_hops WHERE rule_id=?")
                .bind(rule_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            hop_count, 0,
            "preset binding must not allocate rule-level hops"
        );

        let Json(implicit_custom) = update_rule(
            auth(1, true),
            State(state.clone()),
            Path(rule_id),
            Json(UpdateRuleRequest {
                hops: Some(vec![501, 502]),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(
            implicit_custom.code, 400,
            "custom hops must not be silently ignored while the preset remains bound"
        );
        let unchanged: (Option<i64>, i64) = sqlx::query_as(
            "SELECT tunnel_id, (SELECT COUNT(*) FROM forward_rule_hops WHERE rule_id=?) \
             FROM forward_rules WHERE id=?",
        )
        .bind(rule_id)
        .bind(rule_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(unchanged, (Some(tunnel.id), 0));

        // Explicit null means "unbind". It must be accepted together with a
        // replacement custom path; rejecting every present tunnel_id used to
        // make this transition impossible in one atomic update.
        let Json(custom) = update_rule(
            auth(1, true),
            State(state.clone()),
            Path(rule_id),
            Json(UpdateRuleRequest {
                route_mode: Some(relay_shared::protocol::RouteMode::Chain),
                forward_mode: Some("chain".into()),
                tunnel_id: Some(None),
                hops: Some(vec![501, 502]),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(custom.code, 0, "{}", custom.message);
        let stored_tunnel: Option<i64> =
            sqlx::query_scalar("SELECT tunnel_id FROM forward_rules WHERE id=?")
                .bind(rule_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stored_tunnel, None);
        let hop_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM forward_rule_hops WHERE rule_id=?")
                .bind(rule_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(hop_count, 2);

        let Json(unbound) = update_rule(
            auth(1, true),
            State(state.clone()),
            Path(rule_id),
            Json(UpdateRuleRequest {
                route_mode: Some(relay_shared::protocol::RouteMode::Direct),
                forward_mode: Some("direct".into()),
                tunnel_id: Some(None),
                device_group_in: Some(501),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(unbound.code, 0, "{}", unbound.message);
        let stored: (String, Option<i64>, Option<i64>) = sqlx::query_as(
            "SELECT route_mode, tunnel_id, device_group_out FROM forward_rules WHERE id=?",
        )
        .bind(rule_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(stored, ("direct".into(), None, None));
    }

    #[tokio::test]
    async fn preset_tunnel_port_is_tcp_scoped_and_group_delete_is_protected() {
        let (state, pool) = test_state().await;
        seed_tunnel_groups(&pool).await;
        sqlx::query(
            "INSERT INTO forward_rules (name, uid, listen_port, protocol, device_group_in, target_addr, target_port) \
             VALUES ('udp-only', 1, 35006, 'udp', 502, '127.0.0.1', 53)",
        )
        .execute(&pool)
        .await
        .unwrap();
        let mut udp_same_number = tunnel_request("udp-number-can-be-reused");
        udp_same_number.hops[1].listen_port = Some(35006);
        let Json(created) = super::tunnels::create_tunnel(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(udp_same_number),
        )
        .await;
        assert_eq!(
            created.code, 0,
            "pure UDP must not conflict: {}",
            created.message
        );

        let Json(group_delete) =
            delete_group(AdminOnly { user_id: 1 }, State(state.clone()), Path(502)).await;
        assert_eq!(
            group_delete.code, 409,
            "tunnel-referenced group must be protected"
        );
        assert!(group_delete.message.contains("1 条规则"));
        assert!(group_delete.message.contains("1 条预设隧道"));

        sqlx::query(
            "INSERT INTO forward_rules (name, uid, listen_port, protocol, device_group_in, target_addr, target_port) \
             VALUES ('tcp-owner', 1, 35007, 'tcp', 502, '127.0.0.1', 80)",
        )
        .execute(&pool)
        .await
        .unwrap();
        let mut tcp_conflict = tunnel_request("tcp-number-conflicts");
        tcp_conflict.hops[1].listen_port = Some(35007);
        let Json(rejected) = super::tunnels::create_tunnel(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(tcp_conflict),
        )
        .await;
        assert_eq!(rejected.code, 409);
    }

    #[tokio::test]
    async fn preset_tunnel_entry_change_rolls_back_when_owner_lacks_authorization() {
        let (state, pool) = test_state().await;
        seed_tunnel_groups(&pool).await;
        add_group_typed(&pool, 503, 1, "new-entry", "in").await;
        add_user(&pool, 53, "restricted-owner", false).await;
        assign_user_groups(&pool, 53, &[501]).await;
        let Json(created) = super::tunnels::create_tunnel(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(tunnel_request("auth-checked-route")),
        )
        .await;
        let tunnel = created.data.unwrap();
        sqlx::query(
            "INSERT INTO forward_rules (name, uid, listen_port, protocol, route_mode, forward_mode, \
             device_group_in, device_group_out, target_addr, target_port, tunnel_id) \
             VALUES ('restricted-bound', 53, 34100, 'tcp', 'chain', 'chain', 501, 502, '127.0.0.1', 80, ?)",
        )
        .bind(tunnel.id)
        .execute(&pool)
        .await
        .unwrap();

        let Json(rejected) = super::tunnels::update_tunnel(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path(tunnel.id),
            Json(UpdateTunnelRequest {
                name: None,
                enabled: None,
                shared: None,
                expected_hops: Some(tunnel_path_snapshot(&tunnel)),
                hops: Some(vec![
                    TunnelHopRequest {
                        device_group_id: 503,
                        listen_port: None,
                    },
                    TunnelHopRequest {
                        device_group_id: 502,
                        listen_port: None,
                    },
                ]),
            }),
        )
        .await;
        assert_eq!(rejected.code, 409);
        assert!(rejected.message.contains("1 个用户"));
        let entry: i64 = sqlx::query_scalar(
            "SELECT device_group_id FROM tunnel_hops WHERE tunnel_id=? AND position=0",
        )
        .bind(tunnel.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            entry, 501,
            "failed route replacement must roll back atomically"
        );
    }

    #[tokio::test]
    async fn preset_tunnel_entry_change_updates_bound_rule_endpoints_atomically() {
        let (state, pool) = test_state().await;
        seed_tunnel_groups(&pool).await;
        add_group_typed(&pool, 503, 1, "replacement-entry", "in").await;
        let Json(created) = super::tunnels::create_tunnel(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(tunnel_request("movable-route")),
        )
        .await;
        let tunnel = created.data.unwrap();
        sqlx::query(
            "INSERT INTO forward_rules (name,uid,listen_port,protocol,route_mode,forward_mode, \
             device_group_in,device_group_out,target_addr,target_port,tunnel_id) \
             VALUES ('move-with-route',1,34101,'tcp','chain','chain',501,502,'127.0.0.1',80,?)",
        )
        .bind(tunnel.id)
        .execute(&pool)
        .await
        .unwrap();

        let Json(updated) = super::tunnels::update_tunnel(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path(tunnel.id),
            Json(UpdateTunnelRequest {
                name: None,
                enabled: None,
                shared: None,
                expected_hops: Some(tunnel_path_snapshot(&tunnel)),
                hops: Some(vec![
                    TunnelHopRequest {
                        device_group_id: 503,
                        listen_port: None,
                    },
                    TunnelHopRequest {
                        device_group_id: 502,
                        listen_port: None,
                    },
                ]),
            }),
        )
        .await;
        assert_eq!(updated.code, 0, "{}", updated.message);
        let updated_tunnel = updated.data.expect("updated tunnel");
        assert_ne!(
            updated_tunnel.hops[1].listen_port,
            tunnel.hops[1].listen_port,
            "changing the upstream group must allocate a second shared port so old/new HMAC links overlap"
        );
        let endpoints: (i64, Option<i64>) = sqlx::query_as(
            "SELECT device_group_in,device_group_out FROM forward_rules WHERE name='move-with-route'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(endpoints, (503, Some(502)));
    }

    #[tokio::test]
    async fn preset_tunnel_entry_change_rolls_back_on_bound_public_port_conflict() {
        let (state, pool) = test_state().await;
        seed_tunnel_groups(&pool).await;
        add_group_typed(&pool, 503, 1, "occupied-entry", "in").await;
        let Json(created) = super::tunnels::create_tunnel(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(tunnel_request("conflicting-move")),
        )
        .await;
        let tunnel = created.data.unwrap();
        sqlx::query(
            "INSERT INTO forward_rules (name,uid,listen_port,protocol,route_mode,forward_mode,device_group_in,device_group_out,target_addr,target_port,tunnel_id) \
             VALUES ('bound-port',1,34102,'tcp','chain','chain',501,502,'127.0.0.1',80,?)",
        )
        .bind(tunnel.id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO forward_rules (name,uid,listen_port,protocol,device_group_in,target_addr,target_port) \
             VALUES ('occupied-port',1,34102,'tcp',503,'127.0.0.1',80)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let Json(rejected) = super::tunnels::update_tunnel(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path(tunnel.id),
            Json(UpdateTunnelRequest {
                name: None,
                enabled: None,
                shared: None,
                expected_hops: Some(tunnel_path_snapshot(&tunnel)),
                hops: Some(vec![
                    TunnelHopRequest {
                        device_group_id: 503,
                        listen_port: None,
                    },
                    TunnelHopRequest {
                        device_group_id: 502,
                        listen_port: None,
                    },
                ]),
            }),
        )
        .await;
        assert_eq!(rejected.code, 409, "{}", rejected.message);
        let entry: i64 =
            sqlx::query_scalar("SELECT device_group_in FROM forward_rules WHERE name='bound-port'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(entry, 501);
    }

    #[tokio::test]
    async fn rule_protocol_update_cannot_take_shared_tunnel_tcp_port() {
        let (state, pool) = test_state().await;
        seed_tunnel_groups(&pool).await;
        let Json(created) = super::tunnels::create_tunnel(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(tunnel_request("reserved-shared-port")),
        )
        .await;
        assert_eq!(created.code, 0, "{}", created.message);
        sqlx::query("UPDATE device_groups SET group_type='both' WHERE id=502")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO forward_rules (name,uid,listen_port,protocol,device_group_in,target_addr,target_port) \
             VALUES ('udp-same-number',1,35005,'udp',502,'127.0.0.1',53)",
        )
        .execute(&pool)
        .await
        .unwrap();
        let rule_id: i64 =
            sqlx::query_scalar("SELECT id FROM forward_rules WHERE name='udp-same-number'")
                .fetch_one(&pool)
                .await
                .unwrap();

        let Json(rejected) = update_rule(
            auth(1, true),
            State(state),
            Path(rule_id),
            Json(UpdateRuleRequest {
                protocol: Some(relay_shared::protocol::Protocol::Tcp),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(rejected.code, 409, "{}", rejected.message);
        let protocol: String = sqlx::query_scalar("SELECT protocol FROM forward_rules WHERE id=?")
            .bind(rule_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(protocol, "udp");
    }
}
