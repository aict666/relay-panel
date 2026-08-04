//! Local command-line recovery operations.
//!
//! These commands are intentionally not exposed over HTTP. An operator who can
//! execute the panel binary already has access to its database; the CLI makes
//! account recovery safe without asking them to edit password hashes by hand.

use crate::db::repo::{NewAuditEntry, Repository};
use crate::service::password::{generate_password, hash_password_async};
use std::sync::Arc;

pub const USAGE: &str = "\
RelayPanel — self-hosted TCP/UDP forwarding panel

USAGE:
    relay-panel                                 start the server (default)
    relay-panel reset-admin-password [USER]     reset a password and print it once
    relay-panel --help                          show this help

reset-admin-password:
    USER defaults to `admin`. The generated password is never accepted as a
    command-line argument, so it does not leak through shell history or `ps`.
    All existing login sessions for the account are revoked.
";

/// Reset an account and return the process exit code.
pub async fn reset_admin_password(db: Arc<dyn Repository>, username: &str) -> i32 {
    let username = username.trim();
    if username.is_empty() {
        eprintln!("错误：用户名不能为空。");
        return 1;
    }

    let user = match db.find_by_username(username).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            eprintln!("错误：用户 `{username}` 不存在。");
            return 1;
        }
        Err(error) => {
            eprintln!("错误：查询用户失败：{error}");
            return 1;
        }
    };

    let password = generate_password();
    let password_hash = match hash_password_async(&password).await {
        Ok(hash) => hash,
        Err(error) => {
            eprintln!("错误：密码哈希失败：{error}");
            return 1;
        }
    };

    // Use the account itself as the actor for the repository's protected
    // reset primitive. Target and actor are identical, so administrators may
    // recover themselves while the HTTP rule that forbids one admin resetting
    // another remains intact. The write also bumps token_version.
    match db
        .admin_reset_password(user.id, user.id, &password_hash, false)
        .await
    {
        Ok(0) => {
            eprintln!("错误：用户 `{username}` 在更新时已不存在。");
            return 1;
        }
        Ok(_) => {}
        Err(error) => {
            eprintln!("错误：更新密码失败：{error}");
            return 1;
        }
    }

    let audit = NewAuditEntry {
        ts: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        actor_id: None,
        actor_name: "命令行".to_string(),
        action: "reset_password".to_string(),
        target_type: "user".to_string(),
        target_id: user.id.to_string(),
        detail: format!("{username} — 通过命令行重置"),
    };
    if let Err(error) = db.record_audit(&audit).await {
        eprintln!("警告：审计记录写入失败（密码已重置）：{error}");
    }

    println!("\n  用户名： {username}");
    println!("  新密码： {password}\n");
    println!("  该账号的所有旧登录会话已失效，请使用上面的密码重新登录。\n");
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::repo::{TrafficRepository, UserRepository};
    use crate::db::schema::SCHEMA_SQL;
    use crate::db::sqlite_repo::SqliteRepository;
    use sqlx::sqlite::SqlitePoolOptions;

    #[tokio::test]
    async fn recovery_reset_changes_hash_revokes_sessions_and_records_audit() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        sqlx::query(
            "UPDATE users SET password = 'old-hash', admin = 1, \
             token_version = 7, must_change_password = 1 WHERE username = 'admin'",
        )
        .execute(&pool)
        .await
        .unwrap();
        let repository = SqliteRepository::new(pool.clone());
        let db: Arc<dyn Repository> = Arc::new(SqliteRepository::new(pool));

        assert_eq!(reset_admin_password(db, "admin").await, 0);

        let admin = repository.find_by_username("admin").await.unwrap().unwrap();
        assert_ne!(admin.password, "old-hash");
        assert!(admin.password.starts_with("$2"));
        assert_eq!(admin.token_version, 8);
        assert!(!admin.must_change_password);
        let audit = repository
            .query_audit_log(Some("reset_password"), 10, 0)
            .await
            .unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].actor_name, "命令行");
        assert_eq!(audit[0].target_id, admin.id.to_string());
    }

    #[tokio::test]
    async fn recovery_reset_rejects_an_empty_username_without_touching_db() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let db: Arc<dyn Repository> = Arc::new(SqliteRepository::new(pool));
        assert_eq!(reset_admin_password(db, "  ").await, 1);
    }
}
