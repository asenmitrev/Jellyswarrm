//! Seerr login sessions held on behalf of virtual users for the Moonfin API.
//!
//! The Seerr session cookie grants the same access as the user's Seerr login,
//! so it is stored encrypted with a purpose-separated key.

use sqlx::{Row, SqlitePool};

use crate::encryption::{EncryptedPassword, MappingEncryptionKey, Password};

#[derive(Debug, Clone)]
pub struct SeerrSession {
    pub user_id: String,
    pub cookie_name: String,
    pub cookie_value: String,
    pub seerr_user_id: i64,
    pub display_name: Option<String>,
    pub avatar: Option<String>,
    pub permissions: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_validated: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone)]
pub struct SeerrSessionStore {
    pool: SqlitePool,
    key: Option<MappingEncryptionKey>,
}

fn key_error(error: impl std::fmt::Display) -> sqlx::Error {
    sqlx::Error::Protocol(error.to_string())
}

impl SeerrSessionStore {
    pub fn new(pool: SqlitePool, key: Option<MappingEncryptionKey>) -> Self {
        Self { pool, key }
    }

    fn key(&self) -> Result<&MappingEncryptionKey, sqlx::Error> {
        self.key
            .as_ref()
            .ok_or_else(|| key_error("seerr session encryption key is unavailable"))
    }

    pub async fn get(&self, user_id: &str) -> Result<Option<SeerrSession>, sqlx::Error> {
        let Some(row) = sqlx::query(
            "SELECT user_id, cookie_name, encrypted_cookie, seerr_user_id, display_name, avatar, \
             permissions, created_at, last_validated FROM seerr_sessions WHERE user_id = ?",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?
        else {
            return Ok(None);
        };

        let cookie_value = self
            .key()?
            .decrypt(&EncryptedPassword::from_raw(
                row.try_get("encrypted_cookie")?,
            ))
            .map_err(key_error)?
            .into_inner();

        Ok(Some(SeerrSession {
            user_id: row.try_get("user_id")?,
            cookie_name: row.try_get("cookie_name")?,
            cookie_value,
            seerr_user_id: row.try_get("seerr_user_id")?,
            display_name: row.try_get("display_name")?,
            avatar: row.try_get("avatar")?,
            permissions: row.try_get("permissions")?,
            created_at: row.try_get("created_at")?,
            last_validated: row.try_get("last_validated")?,
        }))
    }

    pub async fn save(&self, session: &SeerrSession) -> Result<(), sqlx::Error> {
        let encrypted = self
            .key()?
            .encrypt(&Password::from(session.cookie_value.as_str()))
            .map_err(key_error)?;
        sqlx::query(
            r#"
            INSERT INTO seerr_sessions (
                user_id, cookie_name, encrypted_cookie, seerr_user_id, display_name, avatar,
                permissions, created_at, last_validated
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                cookie_name = excluded.cookie_name,
                encrypted_cookie = excluded.encrypted_cookie,
                seerr_user_id = excluded.seerr_user_id,
                display_name = excluded.display_name,
                avatar = excluded.avatar,
                permissions = excluded.permissions,
                created_at = excluded.created_at,
                last_validated = excluded.last_validated
            "#,
        )
        .bind(&session.user_id)
        .bind(&session.cookie_name)
        .bind(encrypted.as_str())
        .bind(session.seerr_user_id)
        .bind(&session.display_name)
        .bind(&session.avatar)
        .bind(session.permissions)
        .bind(session.created_at)
        .bind(session.last_validated)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete(&self, user_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM seerr_sessions WHERE user_id = ?")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MIGRATOR;
    use crate::user_authorization_service::UserAuthorizationService;

    #[tokio::test]
    async fn session_round_trips_encrypted_and_cascades_on_user_delete() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&pool)
            .await
            .unwrap();
        MIGRATOR.run(&pool).await.unwrap();
        let users = UserAuthorizationService::new(pool.clone());
        let user = users
            .get_or_create_user("alice", &"password123".into())
            .await
            .unwrap();
        let store = users.seerr_sessions();
        let now = chrono::Utc::now();

        store
            .save(&SeerrSession {
                user_id: user.id.clone(),
                cookie_name: "connect.sid".into(),
                cookie_value: "s:secret".into(),
                seerr_user_id: 7,
                display_name: Some("Alice".into()),
                avatar: None,
                permissions: 2,
                created_at: now,
                last_validated: now,
            })
            .await
            .unwrap();

        let raw: String =
            sqlx::query_scalar("SELECT encrypted_cookie FROM seerr_sessions WHERE user_id = ?")
                .bind(&user.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(!raw.contains("secret"));

        let loaded = store.get(&user.id).await.unwrap().unwrap();
        assert_eq!(loaded.cookie_value, "s:secret");
        assert_eq!(loaded.seerr_user_id, 7);

        users.delete_user(&user.id).await.unwrap();
        assert!(store.get(&user.id).await.unwrap().is_none());
    }
}
