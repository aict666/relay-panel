use crate::api::AppState;
use crate::service::password::{
    hash_password_async, validate_password, verify_password_async, PasswordValidationError,
    PasswordWorkError,
};
use crate::service::users::validate_username;
use axum::{extract::State, Json};
use jsonwebtoken::{encode, EncodingKey, Header};
use once_cell::sync::Lazy;
use relay_shared::models::User;
use relay_shared::protocol::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// In-memory login rate-limit state. Per-username counters protect accounts;
/// the separate global counter bounds work from fabricated usernames. State
/// resets on process restart, which is acceptable for this single-process
/// deployment model.
struct LoginAttempt {
    count: u32,
    window_start: Instant,
}

static LOGIN_LIMITER: Lazy<Mutex<HashMap<String, LoginAttempt>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static GLOBAL_LOGIN_LIMITER: Lazy<Mutex<LoginAttempt>> = Lazy::new(|| {
    Mutex::new(LoginAttempt {
        count: 0,
        window_start: Instant::now(),
    })
});

const MAX_LOGIN_ATTEMPTS: u32 = 5;
const MAX_GLOBAL_LOGIN_ATTEMPTS: u32 = 120;
const MAX_GLOBAL_REGISTRATION_ATTEMPTS: u32 = 120;
const LOGIN_WINDOW: Duration = Duration::from_secs(60);
const LOGIN_LIMITER_CAP: usize = 10_000;

/// Returns true if the login attempt should be blocked (too many attempts).
/// Resets the window if it has elapsed. Before reaching capacity, expired
/// entries are pruned; if the map is still full, new keys are rejected.
fn check_username_rate_limit(username: &str) -> bool {
    let now = Instant::now();
    let mut map = LOGIN_LIMITER.lock().unwrap();
    match map.get_mut(username) {
        Some(entry) if now.duration_since(entry.window_start) < LOGIN_WINDOW => {
            entry.count += 1;
            entry.count > MAX_LOGIN_ATTEMPTS
        }
        _ => {
            // Prune before inserting and enforce a real hard cap. Merely
            // retaining unexpired entries after insertion does not cap a burst
            // of distinct usernames inside the active window.
            if map.len() >= LOGIN_LIMITER_CAP {
                map.retain(|_, v| now.duration_since(v.window_start) < LOGIN_WINDOW);
                if map.len() >= LOGIN_LIMITER_CAP {
                    return true;
                }
            }
            // New window (first attempt, or window expired)
            map.insert(
                username.to_string(),
                LoginAttempt {
                    count: 1,
                    window_start: now,
                },
            );
            false
        }
    }
}

/// A process-wide budget prevents an attacker from bypassing the per-account
/// limiter with an unlimited stream of fabricated usernames.
fn check_global_rate_limit() -> bool {
    let now = Instant::now();
    let mut entry = GLOBAL_LOGIN_LIMITER.lock().unwrap();
    if now.duration_since(entry.window_start) >= LOGIN_WINDOW {
        entry.count = 1;
        entry.window_start = now;
        return false;
    }
    entry.count += 1;
    entry.count > MAX_GLOBAL_LOGIN_ATTEMPTS
}

/// Clear the rate-limit counter for a username on successful login.
fn clear_rate_limit(username: &str) {
    LOGIN_LIMITER.lock().unwrap().remove(username);
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: i64, // user id
    admin: bool,
    // v0.4.10 PR4: session-version counter copied from users.token_version at
    // sign time. The auth middleware rejects a token whose token_version != the
    // current DB value, so bumping the DB column instantly revokes this token.
    token_version: i64,
    exp: usize,
}

/// Pre-computed dummy bcrypt hash used when the username does not exist.
/// Verifying against this eliminates the timing side-channel that would
/// otherwise reveal whether a username is registered (~300 ms bcrypt vs ~1 ms
/// early return).
static DUMMY_HASH: &str = "$2b$12$AAAAAAAAAAAAAAAAAAAAAOYEUtP4bEYKnMmFJEPW9HTZLX9R5gO4iSq";

static GLOBAL_REGISTRATION_LIMITER: Lazy<Mutex<LoginAttempt>> = Lazy::new(|| {
    Mutex::new(LoginAttempt {
        count: 0,
        window_start: Instant::now(),
    })
});

fn check_registration_rate_limit() -> bool {
    let now = Instant::now();
    let mut entry = GLOBAL_REGISTRATION_LIMITER.lock().unwrap();
    if now.duration_since(entry.window_start) >= LOGIN_WINDOW {
        entry.count = 1;
        entry.window_start = now;
        return false;
    }
    entry.count += 1;
    entry.count > MAX_GLOBAL_REGISTRATION_ATTEMPTS
}

pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Json<ApiResponse<LoginResponse>> {
    // Reject malformed/unbounded identifiers before they can become limiter
    // keys or reach the database.
    if !validate_username(&req.username) {
        return Json(ApiResponse {
            code: 400,
            message: "Username must be 1-64 chars, ASCII letters/digits/underscore only".into(),
            data: None,
        });
    }

    // Per-account protection plus a process-wide bcrypt budget. A blocked
    // account does not consume the global budget, so repeatedly attacking one
    // known username cannot lock every other user out by itself.
    if check_username_rate_limit(&req.username) || check_global_rate_limit() {
        return Json(ApiResponse {
            code: 429,
            message: "Too many login attempts. Please wait a minute and try again.".into(),
            data: None,
        });
    }

    let (user, lookup_failed): (Option<User>, bool) =
        match state.db.find_by_username_not_banned(&req.username).await {
            Ok(u) => (u, false),
            Err(e) => {
                tracing::error!("login: db lookup failed for {:?}: {}", req.username, e);
                // Still run the dummy bcrypt check below so a transient database
                // failure does not create a cheap username-enumeration oracle.
                (None, true)
            }
        };

    // Always perform a bcrypt verification to prevent timing attacks that
    // reveal whether a username exists. Run it on the blocking pool and cap
    // concurrency so public requests cannot occupy every async runtime worker
    // or enqueue an unbounded number of expensive jobs.
    let verified = match verify_password_async(
        &req.password,
        user.as_ref()
            .map(|u| u.password.as_str())
            .unwrap_or(DUMMY_HASH),
    )
    .await
    {
        Ok(value) => value && user.is_some(),
        Err(PasswordWorkError::Busy) => {
            return Json(ApiResponse {
                code: 429,
                message: "Too many login attempts. Please try again shortly.".into(),
                data: None,
            });
        }
        Err(e) => {
            tracing::error!("login: bcrypt worker failed: {}", e);
            return Json(ApiResponse {
                code: 500,
                message: "Password service failed. Please try again later.".into(),
                data: None,
            });
        }
    };

    if lookup_failed {
        return Json(ApiResponse {
            code: 500,
            message: "database error".into(),
            data: None,
        });
    }

    if verified {
        if let Some(user) = user {
            clear_rate_limit(&req.username);
            let claims = Claims {
                sub: user.id,
                admin: user.admin,
                token_version: user.token_version,
                exp: chrono::Utc::now().timestamp_millis() as usize / 1000 + 86400,
            };
            let token = match encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(state.config.jwt_secret.as_bytes()),
            ) {
                Ok(token) => token,
                Err(e) => {
                    tracing::error!("login: JWT encoding failed: {}", e);
                    return Json(ApiResponse {
                        code: 500,
                        message: "token service failed".into(),
                        data: None,
                    });
                }
            };

            return Json(ApiResponse::success(LoginResponse {
                token,
                admin: user.admin,
            }));
        }
    }

    Json(ApiResponse {
        code: 401,
        message: "Invalid credentials".into(),
        data: None,
    })
}

pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Json<ApiResponse<()>> {
    // v0.4.10 PR3: registration toggle now lives in app_settings (admin-managed),
    // NOT the REGISTRATION_ENABLED env var. The env var only seeds the row on
    // first boot; afterwards only the admin PUT can change it. A missing row
    // (unseeded) is treated as "disabled" (safe default).
    let settings =
        match crate::service::settings::get_registration_settings(state.db.as_ref()).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("register: registration settings lookup failed: {}", e);
                return Json(ApiResponse {
                    code: 500,
                    message: "database error".into(),
                    data: None,
                });
            }
        };
    let enabled = settings.registration_enabled;
    if !enabled {
        return Json(ApiResponse {
            code: 403,
            message: "Registration is disabled. Ask an admin to create your account.".into(),
            data: None,
        });
    }

    // v0.4.21 PR2: resolve plan_id from request, falling back to the default.
    // Validate it is in the allowed list.
    let selected_plan_id = req.plan_id.unwrap_or(settings.default_registration_plan_id);
    if !settings.allowed_plan_ids.contains(&selected_plan_id) {
        return Json(ApiResponse {
            code: 400,
            message: "Selected plan is not available for registration.".into(),
            data: None,
        });
    }

    // Validate username: non-empty, ≤64 chars, ASCII alphanumeric + underscore.
    // Prevents table rendering breakage and DB bloat from absurd inputs.
    if !validate_username(&req.username) {
        return Json(ApiResponse {
            code: 400,
            message: "Username must be 1-64 chars, ASCII letters/digits/underscore only".into(),
            data: None,
        });
    }

    // v0.4.10 PR3: password length validation. bcrypt truncates at 72 bytes,
    // so anything longer is silently weakened; anything shorter than 8 is
    // trivially brute-forced. len() is UTF-8 bytes (matches bcrypt's boundary).
    if let Err(e) = validate_password(&req.password) {
        return Json(ApiResponse {
            code: 400,
            message: match e {
                PasswordValidationError::TooShort => "Password must be at least 8 characters",
                PasswordValidationError::TooLong => {
                    "Password must be at most 72 bytes (bcrypt limit)"
                }
            }
            .into(),
            data: None,
        });
    }

    // Count only requests that passed all cheap validation.  Invalid input must
    // not be able to consume the legitimate registration budget, while every
    // request that is about to schedule bcrypt is globally bounded.
    if check_registration_rate_limit() {
        return Json(ApiResponse {
            code: 429,
            message: "Too many registration attempts. Please wait a minute and try again.".into(),
            data: None,
        });
    }

    let hashed = match hash_password_async(&req.password).await {
        Ok(h) => h,
        Err(PasswordWorkError::Busy) => {
            return Json(ApiResponse {
                code: 429,
                message: "Password service is busy. Please try again shortly.".into(),
                data: None,
            });
        }
        Err(e) => {
            tracing::error!("register: password hashing failed: {}", e);
            return Json(ApiResponse {
                code: 500,
                message: "Password service failed. Please try again later.".into(),
                data: None,
            });
        }
    };

    // Re-check the registration switch, current default/allowed list and plan
    // existence in the same transaction that copies quotas and inserts the
    // user. `req.plan_id=None` intentionally resolves the default again here,
    // so a default changed during bcrypt cannot provision the stale plan.
    match state
        .db
        .insert_public_registered_user(&req.username, &hashed, req.plan_id)
        .await
    {
        Ok(crate::db::repo::UserProvisionOutcome::Created) => Json(ApiResponse::success(())),
        Ok(crate::db::repo::UserProvisionOutcome::RegistrationDisabled) => Json(ApiResponse {
            code: 403,
            message: "Registration is disabled. Ask an admin to create your account.".into(),
            data: None,
        }),
        Ok(crate::db::repo::UserProvisionOutcome::PlanNotAllowed) => Json(ApiResponse {
            code: 400,
            message: "Selected plan is not available for registration.".into(),
            data: None,
        }),
        Ok(crate::db::repo::UserProvisionOutcome::PlanMissing(plan_id)) => {
            tracing::error!(
                "register: selected/default plan {} is missing; no user created",
                plan_id
            );
            Json(ApiResponse {
                code: 500,
                message: "Registration is misconfigured (default plan missing). \
                          Contact an administrator."
                    .into(),
                data: None,
            })
        }
        Err(crate::db::error::DbError::UniqueViolation) => Json(ApiResponse {
            code: 409,
            message: "Username already exists".into(),
            data: None,
        }),
        Err(e) => {
            tracing::error!("register: insert failed for {:?}: {}", req.username, e);
            Json(ApiResponse {
                code: 500,
                message: "database error".into(),
                data: None,
            })
        }
    }
}

/// v0.4.10 PR3 / v0.4.21 PR2: public registration-status probe.
/// Unauthenticated (used by the login page to decide whether to show
/// the "create account" link and the registration page to render a plan
/// selector). Returns enabled flag, default_plan_id, and the list of
/// allowed plans (filtered from the full plans table).
///
/// A DB error is surfaced as 500 (NOT masqueraded as "disabled"), so a panel
/// outage doesn't make users think registration is closed.
pub async fn registration_status(
    State(state): State<AppState>,
) -> Json<ApiResponse<RegistrationStatus>> {
    let settings =
        match crate::service::settings::get_registration_settings(state.db.as_ref()).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("registration_status: settings lookup failed: {}", e);
                return Json(ApiResponse {
                    code: 500,
                    message: "database error".into(),
                    data: None,
                });
            }
        };

    let allowed_set: std::collections::HashSet<i64> =
        settings.allowed_plan_ids.iter().copied().collect();

    let all_plans: Vec<relay_shared::models::Plan> = match state.db.list_plans().await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("registration_status: list_plans failed: {}", e);
            return Json(ApiResponse {
                code: 500,
                message: "database error".into(),
                data: None,
            });
        }
    };

    let plans: Vec<relay_shared::models::Plan> = all_plans
        .into_iter()
        .filter(|p| allowed_set.contains(&p.id))
        .collect();

    Json(ApiResponse::success(RegistrationStatus {
        enabled: settings.registration_enabled,
        default_plan_id: settings.default_registration_plan_id,
        plans,
        site_name: settings.site_name,
        default_password_change_required: default_password_change_required(state.db.as_ref()).await,
    }))
}

/// v0.4.22: check whether the default admin (id=1) still has
/// must_change_password set. Used by the login page to decide whether
/// to show the security reminder banner.
async fn default_password_change_required(db: &dyn crate::db::repo::Repository) -> bool {
    match db.find_auth_state_by_id(1).await {
        Ok(Some((_banned, _version, must_change))) => must_change,
        // User doesn't exist (fresh DB before seed) or DB error → no banner.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_limiter_has_a_real_hard_capacity() {
        LOGIN_LIMITER.lock().unwrap().clear();
        for index in 0..LOGIN_LIMITER_CAP {
            assert!(!check_username_rate_limit(&format!("user_{index}")));
        }
        assert!(check_username_rate_limit("one_user_too_many"));
        assert_eq!(LOGIN_LIMITER.lock().unwrap().len(), LOGIN_LIMITER_CAP);
        LOGIN_LIMITER.lock().unwrap().clear();
    }

    #[test]
    fn global_limiter_stops_distinct_username_bypass() {
        {
            let mut entry = GLOBAL_LOGIN_LIMITER.lock().unwrap();
            entry.count = 0;
            entry.window_start = Instant::now();
        }
        for _ in 0..MAX_GLOBAL_LOGIN_ATTEMPTS {
            assert!(!check_global_rate_limit());
        }
        assert!(check_global_rate_limit());
    }
}
