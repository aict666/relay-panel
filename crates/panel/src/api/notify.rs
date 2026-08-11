//! v1.2.0: notification settings API.
//!
//! Credentials follow a write-only convention: they go IN through PUT, and the
//! GET never returns them (only a boolean saying one is stored). An omitted /
//! empty credential on PUT means "keep what's there", so the UI can render a
//! masked field and submit the form without wiping the secret it never saw.

use axum::extract::State;
use axum::Json;
use relay_shared::protocol::ApiResponse;
use serde::{Deserialize, Serialize};

use crate::api::middleware::AdminOnly;
use crate::api::AppState;
use crate::service::notify::{
    self, DeliveryLogEntry, NotifyConfig, NotifyConfigPublic, MIN_OFFLINE_ALERT_SECS,
};

fn err<T: Serialize>(code: i32, msg: &str) -> ApiResponse<T> {
    ApiResponse {
        code,
        message: msg.into(),
        data: None,
    }
}

async fn load(state: &AppState) -> NotifyConfig {
    let raw = state.db.get(notify::NOTIFY_CONFIG_KEY).await.ok().flatten();
    NotifyConfig::from_json(raw.as_deref())
}

/// GET /api/v1/admin/settings/notify
pub async fn get_notify_settings(
    _admin: AdminOnly,
    State(state): State<AppState>,
) -> Json<ApiResponse<NotifyConfigPublic>> {
    let cfg = load(&state).await;
    Json(ApiResponse::success(NotifyConfigPublic::from(&cfg)))
}

/// GET /api/v1/admin/settings/notify/history
///
/// This is intentionally separate from the admin audit log: audit records
/// configuration changes, while this reports the outcome of real deliveries.
pub async fn get_notify_history(
    _admin: AdminOnly,
    State(state): State<AppState>,
) -> Json<ApiResponse<Vec<DeliveryLogEntry>>> {
    Json(ApiResponse::success(
        notify::list_history(state.db.as_ref()).await,
    ))
}

#[derive(Debug, Deserialize)]
pub struct UpdateNotifyRequest {
    pub enabled: bool,
    #[serde(default = "default_notify_offline")]
    pub notify_offline: bool,
    pub offline_alert_secs: i64,
    pub notify_recovery: bool,
    #[serde(default)]
    pub notify_version_outdated: bool,
    #[serde(default)]
    pub repeat_alert_minutes: i64,
    pub telegram_enabled: bool,
    pub telegram_chat_id: String,
    /// Empty / omitted = keep the stored token. The UI shows a masked field and
    /// never receives the real value, so it cannot echo it back.
    #[serde(default)]
    pub telegram_bot_token: Option<String>,
    pub email_enabled: bool,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    /// Empty / omitted = keep the stored password.
    #[serde(default)]
    pub smtp_password: Option<String>,
    pub smtp_from: String,
    pub smtp_to: String,
    pub smtp_tls: bool,
}

fn default_notify_offline() -> bool {
    true
}

fn normalized_config(
    req: UpdateNotifyRequest,
    existing: &NotifyConfig,
) -> Result<NotifyConfig, String> {
    if req.offline_alert_secs < MIN_OFFLINE_ALERT_SECS {
        return Err(format!("离线告警阈值最小 {MIN_OFFLINE_ALERT_SECS} 秒"));
    }
    if req.repeat_alert_minutes < 0 {
        return Err("持续离线提醒间隔不能小于 0".into());
    }

    // Normalize before validation. Otherwise a whitespace-only value passes an
    // `is_empty` check and is then stored as the empty string.
    let telegram_bot_token = match req.telegram_bot_token {
        Some(token) if !token.trim().is_empty() => token.trim().to_string(),
        _ => existing.telegram_bot_token.clone(),
    };
    let smtp_password = match req.smtp_password {
        Some(password) if !password.is_empty() => password,
        _ => existing.smtp_password.clone(),
    };
    let telegram_chat_id = req.telegram_chat_id.trim().to_string();
    let smtp_host = req.smtp_host.trim().to_string();
    let smtp_username = req.smtp_username.trim().to_string();
    let smtp_from = req.smtp_from.trim().to_string();
    let recipients: Vec<&str> = req
        .smtp_to
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect();
    let smtp_to = recipients.join(",");

    if req.telegram_enabled && (telegram_bot_token.is_empty() || telegram_chat_id.is_empty()) {
        return Err("启用 Telegram 需要填写 Bot Token 和 Chat ID".into());
    }
    if req.email_enabled {
        if smtp_host.is_empty() || recipients.is_empty() {
            return Err("启用邮件需要填写 SMTP 主机和收件人".into());
        }
        let sender = if smtp_from.is_empty() {
            &smtp_username
        } else {
            &smtp_from
        };
        if sender.is_empty() {
            return Err("启用邮件需要填写 SMTP 用户名或发件人地址".into());
        }
        if sender.parse::<lettre::message::Mailbox>().is_err() {
            return Err("SMTP 发件人地址无效".into());
        }
        if recipients
            .iter()
            .any(|address| address.parse::<lettre::message::Mailbox>().is_err())
        {
            return Err("SMTP 收件人地址无效".into());
        }
    }

    Ok(NotifyConfig {
        enabled: req.enabled,
        notify_offline: req.notify_offline,
        offline_alert_secs: req.offline_alert_secs,
        notify_recovery: req.notify_recovery,
        notify_version_outdated: req.notify_version_outdated,
        repeat_alert_minutes: req.repeat_alert_minutes,
        telegram_enabled: req.telegram_enabled,
        telegram_bot_token,
        telegram_chat_id,
        email_enabled: req.email_enabled,
        smtp_host,
        smtp_port: req.smtp_port,
        smtp_username,
        smtp_password,
        smtp_from,
        smtp_to,
        smtp_tls: req.smtp_tls,
    })
}

/// PUT /api/v1/admin/settings/notify
pub async fn update_notify_settings(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Json(req): Json<UpdateNotifyRequest>,
) -> Json<ApiResponse<NotifyConfigPublic>> {
    let existing = load(&state).await;
    let cfg = match normalized_config(req, &existing) {
        Ok(config) => config,
        Err(message) => return Json(err(400, &message)),
    };

    let json = match serde_json::to_string(&cfg) {
        Ok(j) => j,
        Err(e) => {
            tracing::error!("update_notify_settings: serialize failed: {}", e);
            return Json(err(500, "配置序列化失败"));
        }
    };
    if let Err(e) = state.db.set(notify::NOTIFY_CONFIG_KEY, &json).await {
        tracing::error!("update_notify_settings: save failed: {}", e);
        return Json(err(500, "数据库错误"));
    }
    tracing::info!(
        action = "update_notify_settings",
        enabled = cfg.enabled,
        telegram = cfg.telegram_enabled,
        email = cfg.email_enabled,
        "notification settings updated"
    );
    // Which channels are on, never the bot token or SMTP password that this
    // very handler just took care not to leak back to the browser.
    crate::service::audit::record(
        &state,
        Some(_admin.user_id),
        "update_notify_settings",
        "settings",
        "notify",
        &format!(
            "总开关 {} / Telegram {} / 邮件 {}",
            if cfg.enabled { "开" } else { "关" },
            if cfg.telegram_enabled { "开" } else { "关" },
            if cfg.email_enabled { "开" } else { "关" },
        ),
    )
    .await;
    Json(ApiResponse::success(NotifyConfigPublic::from(&cfg)))
}

#[derive(Debug, Deserialize)]
pub struct TestNotifyRequest {
    /// "telegram" | "email" — which channel to exercise.
    pub channel: String,
}

#[derive(Debug, Serialize)]
pub struct TestNotifyResponse {
    pub ok: bool,
    /// The failure reason verbatim from the provider when ok = false.
    pub detail: String,
}

/// POST /api/v1/admin/settings/notify/test
///
/// Sends a real message on one channel using the STORED config. This exists
/// because notification config is the classic write-and-forget setting: a typo
/// in a chat id or an SMTP password is invisible until the night something
/// breaks, which is the worst possible moment to discover it.
///
/// It deliberately ignores the `enabled` master switch — you test before
/// turning it on, not after.
pub async fn test_notify(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Json(req): Json<TestNotifyRequest>,
) -> Json<ApiResponse<TestNotifyResponse>> {
    let cfg = load(&state).await;
    let text = "✅ RelayPanel 测试消息\n\n如果你收到这条消息，说明通知配置正确。";

    let (result, report) = match req.channel.as_str() {
        "telegram" => {
            let result = notify::send_telegram(&cfg, text).await;
            let report = notify::SendReport {
                telegram: Some(result.clone()),
                email: None,
            };
            (result, report)
        }
        "email" => {
            let result = notify::send_email(&cfg, "RelayPanel 测试消息", text).await;
            let report = notify::SendReport {
                telegram: None,
                email: Some(result.clone()),
            };
            (result, report)
        }
        other => {
            return Json(err(400, &format!("未知的通知渠道: {other}")));
        }
    };
    notify::record_report(state.db.as_ref(), "test", None, &report).await;

    match result {
        Ok(()) => {
            tracing::info!(action = "test_notify", channel = %req.channel, "test message sent");
            Json(ApiResponse::success(TestNotifyResponse {
                ok: true,
                detail: String::new(),
            }))
        }
        Err(detail) => {
            // 200 with ok=false, not an HTTP error: the REQUEST succeeded, the
            // delivery didn't, and the UI needs the provider's own words to be
            // able to fix it.
            tracing::warn!(action = "test_notify", channel = %req.channel, %detail, "test failed");
            Json(ApiResponse::success(TestNotifyResponse {
                ok: false,
                detail,
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> UpdateNotifyRequest {
        UpdateNotifyRequest {
            enabled: true,
            notify_offline: true,
            offline_alert_secs: 180,
            notify_recovery: true,
            notify_version_outdated: false,
            repeat_alert_minutes: 0,
            telegram_enabled: false,
            telegram_chat_id: String::new(),
            telegram_bot_token: None,
            email_enabled: false,
            smtp_host: String::new(),
            smtp_port: 587,
            smtp_username: String::new(),
            smtp_password: None,
            smtp_from: String::new(),
            smtp_to: String::new(),
            smtp_tls: false,
        }
    }

    #[test]
    fn whitespace_only_telegram_fields_are_rejected() {
        let mut req = request();
        req.telegram_enabled = true;
        req.telegram_chat_id = "   ".into();
        req.telegram_bot_token = Some(" \t ".into());
        assert!(normalized_config(req, &NotifyConfig::default())
            .unwrap_err()
            .contains("Telegram"));
    }

    #[test]
    fn enabled_email_requires_a_sender() {
        let mut req = request();
        req.email_enabled = true;
        req.smtp_host = " smtp.example.com ".into();
        req.smtp_to = " ops@example.com ".into();
        assert!(normalized_config(req, &NotifyConfig::default())
            .unwrap_err()
            .contains("发件人"));
    }

    #[test]
    fn email_addresses_are_validated_after_normalization() {
        let mut req = request();
        req.email_enabled = true;
        req.smtp_host = " smtp.example.com ".into();
        req.smtp_username = "sender@example.com".into();
        req.smtp_to = "ops@example.com, not-an-address".into();
        assert!(normalized_config(req, &NotifyConfig::default())
            .unwrap_err()
            .contains("收件人"));
    }

    #[test]
    fn username_is_a_valid_sender_fallback() {
        let mut req = request();
        req.email_enabled = true;
        req.smtp_host = " smtp.example.com ".into();
        req.smtp_username = " sender@example.com ".into();
        req.smtp_to = " one@example.com, two@example.com ".into();
        let cfg = normalized_config(req, &NotifyConfig::default()).unwrap();
        assert_eq!(cfg.smtp_host, "smtp.example.com");
        assert_eq!(cfg.smtp_username, "sender@example.com");
        assert_eq!(cfg.smtp_to, "one@example.com,two@example.com");
    }

    #[test]
    fn old_update_payload_keeps_offline_alerts_and_defaults_new_rules_off() {
        let req: UpdateNotifyRequest = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "offline_alert_secs": 180,
            "notify_recovery": true,
            "telegram_enabled": false,
            "telegram_chat_id": "",
            "email_enabled": false,
            "smtp_host": "",
            "smtp_port": 587,
            "smtp_username": "",
            "smtp_from": "",
            "smtp_to": "",
            "smtp_tls": false
        }))
        .unwrap();

        assert!(req.notify_offline);
        assert!(!req.notify_version_outdated);
        assert_eq!(req.repeat_alert_minutes, 0);
    }

    #[test]
    fn negative_repeat_interval_is_rejected() {
        let mut req = request();
        req.repeat_alert_minutes = -1;
        assert!(normalized_config(req, &NotifyConfig::default())
            .unwrap_err()
            .contains("不能小于 0"));
    }
}
