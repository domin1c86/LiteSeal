use sqlx::{postgres::PgPoolOptions, PgPool, Row};

#[derive(Debug, Clone)]
pub struct Db {
    pool: PgPool,
}

#[derive(Debug, Clone)]
pub struct UserRecord {
    pub id: String,
    pub username: String,
    pub password_hash: String,
}

#[derive(Debug, Clone)]
pub struct DeviceRecord {
    pub id: String,
    pub name: String,
    pub public_key: Vec<u8>,
    pub ed25519_pk: Vec<u8>,
    pub revoked: bool,
}

#[derive(Debug, Clone)]
pub struct OfflineMessageRecord {
    pub message_id: String,
    pub conversation_id: String,
    pub from_user_id: String,
    pub sender_device_id: String,
    pub sender_seq: i64,
    pub prev_hash: Vec<u8>,
    pub recipient_device_id: String,
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp: i64,
}

impl Db {
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await?;
        let db = Self { pool };
        db.migrate().await?;
        Ok(db)
    }

    #[cfg(test)]
    pub fn connect_lazy(database_url: &str) -> Result<Self, sqlx::Error> {
        Ok(Self {
            pool: PgPoolOptions::new().connect_lazy(database_url)?,
        })
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        for stmt in MIGRATIONS
            .split(";")
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            sqlx::query(stmt).execute(&self.pool).await?;
        }
        Ok(())
    }

    pub async fn create_user(
        &self,
        username: &str,
        password_hash: &str,
    ) -> Result<UserRecord, sqlx::Error> {
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, created_at)
             VALUES ($1, $2, $3, now())",
        )
        .bind(&id)
        .bind(username)
        .bind(password_hash)
        .execute(&self.pool)
        .await?;
        Ok(UserRecord {
            id,
            username: username.to_string(),
            password_hash: password_hash.to_string(),
        })
    }

    pub async fn get_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<UserRecord>, sqlx::Error> {
        let row = sqlx::query("SELECT id, username, password_hash FROM users WHERE username = $1")
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| UserRecord {
            id: r.get("id"),
            username: r.get("username"),
            password_hash: r.get("password_hash"),
        }))
    }

    pub async fn create_session(
        &self,
        user_id: &str,
        device_id: &str,
        access_token_hash: &str,
        refresh_token_hash: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO sessions
             (id, user_id, device_id, access_token_hash, refresh_token_hash, expires_at, refresh_expires_at, revoked, created_at)
             VALUES ($1, $2, $3, $4, $5, now() + interval '30 minutes', now() + interval '30 days', false, now())",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(user_id)
        .bind(device_id)
        .bind(access_token_hash)
        .bind(refresh_token_hash)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn validate_access_token(
        &self,
        access_token_hash: &str,
        device_id: &str,
    ) -> Result<Option<String>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT user_id FROM sessions
             WHERE access_token_hash = $1 AND device_id = $2 AND revoked = false AND expires_at > now()",
        )
        .bind(access_token_hash)
        .bind(device_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.get("user_id")))
    }

    pub async fn user_for_access_token(
        &self,
        access_token_hash: &str,
    ) -> Result<Option<String>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT user_id FROM sessions
             WHERE access_token_hash = $1 AND revoked = false AND expires_at > now()",
        )
        .bind(access_token_hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.get("user_id")))
    }

    pub async fn validate_refresh_token(
        &self,
        refresh_token_hash: &str,
    ) -> Result<Option<(String, String)>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT user_id, device_id FROM sessions
             WHERE refresh_token_hash = $1 AND revoked = false AND refresh_expires_at > now()",
        )
        .bind(refresh_token_hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| (r.get("user_id"), r.get("device_id"))))
    }

    pub async fn revoke_session(&self, access_token_hash: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE sessions SET revoked = true WHERE access_token_hash = $1")
            .bind(access_token_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn revoke_refresh_token(&self, refresh_token_hash: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE sessions SET revoked = true WHERE refresh_token_hash = $1")
            .bind(refresh_token_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn revoke_all_sessions(&self, user_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE sessions SET revoked = true WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn register_device(
        &self,
        user_id: &str,
        name: &str,
        public_key: &[u8],
        ed25519_pk: &[u8],
    ) -> Result<DeviceRecord, sqlx::Error> {
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO devices (id, user_id, name, public_key, ed25519_pk, revoked, created_at, last_seen)
             VALUES ($1, $2, $3, $4, $5, false, now(), now())",
        )
        .bind(&id)
        .bind(user_id)
        .bind(name)
        .bind(public_key)
        .bind(ed25519_pk)
        .execute(&self.pool)
        .await?;
        Ok(DeviceRecord {
            id,
            name: name.to_string(),
            public_key: public_key.to_vec(),
            ed25519_pk: ed25519_pk.to_vec(),
            revoked: false,
        })
    }

    pub async fn update_device_keys(
        &self,
        user_id: &str,
        device_id: &str,
        public_key: &[u8],
        ed25519_pk: &[u8],
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE devices SET public_key = $1, ed25519_pk = $2, last_seen = now()
             WHERE user_id = $3 AND id = $4 AND revoked = false",
        )
        .bind(public_key)
        .bind(ed25519_pk)
        .bind(user_id)
        .bind(device_id)
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "INSERT INTO device_keys (id, device_id, public_key, ed25519_pk, active, created_at)
             VALUES ($1, $2, $3, $4, true, now())",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(device_id)
        .bind(public_key)
        .bind(ed25519_pk)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_user_devices(&self, user_id: &str) -> Result<Vec<DeviceRecord>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, name, public_key, ed25519_pk, revoked FROM devices
             WHERE user_id = $1 ORDER BY created_at ASC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| DeviceRecord {
                id: r.get("id"),
                name: r.get("name"),
                public_key: r.get("public_key"),
                ed25519_pk: r.get("ed25519_pk"),
                revoked: r.get("revoked"),
            })
            .collect())
    }

    pub async fn revoke_device(&self, user_id: &str, device_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE devices SET revoked = true
             WHERE user_id = $1 AND id = $2",
        )
        .bind(user_id)
        .bind(device_id)
        .execute(&self.pool)
        .await?;
        sqlx::query("UPDATE sessions SET revoked = true WHERE user_id = $1 AND device_id = $2")
            .bind(user_id)
            .bind(device_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn store_offline_message(
        &self,
        msg: &OfflineMessageRecord,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO offline_messages
             (id, message_id, conversation_id, from_user_id, sender_device_id, sender_seq, prev_hash,
              recipient_device_id, ciphertext, signature, timestamp, delivered, acked, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, false, false, now())
             ON CONFLICT (message_id, recipient_device_id) DO NOTHING",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&msg.message_id)
        .bind(&msg.conversation_id)
        .bind(&msg.from_user_id)
        .bind(&msg.sender_device_id)
        .bind(msg.sender_seq)
        .bind(&msg.prev_hash)
        .bind(&msg.recipient_device_id)
        .bind(&msg.ciphertext)
        .bind(&msg.signature)
        .bind(msg.timestamp)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn drain_offline_messages(
        &self,
        device_id: &str,
    ) -> Result<Vec<OfflineMessageRecord>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT message_id, conversation_id, from_user_id, sender_device_id, sender_seq,
                    prev_hash, recipient_device_id, ciphertext, signature, timestamp
             FROM offline_messages
             WHERE recipient_device_id = $1 AND acked = false
             ORDER BY created_at ASC",
        )
        .bind(device_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| OfflineMessageRecord {
                message_id: r.get("message_id"),
                conversation_id: r.get("conversation_id"),
                from_user_id: r.get("from_user_id"),
                sender_device_id: r.get("sender_device_id"),
                sender_seq: r.get("sender_seq"),
                prev_hash: r.get("prev_hash"),
                recipient_device_id: r.get("recipient_device_id"),
                ciphertext: r.get("ciphertext"),
                signature: r.get("signature"),
                timestamp: r.get("timestamp"),
            })
            .collect())
    }

    pub async fn ack_message(
        &self,
        message_id: &str,
        recipient_device_id: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE offline_messages SET delivered = true, acked = true
             WHERE message_id = $1 AND recipient_device_id = $2",
        )
        .bind(message_id)
        .bind(recipient_device_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn upsert_trusted_contact(
        &self,
        owner_user_id: &str,
        contact_user_id: &str,
        fingerprint: &str,
        state: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO trusted_contacts (id, owner_user_id, contact_user_id, fingerprint, state, updated_at)
             VALUES ($1, $2, $3, $4, $5, now())
             ON CONFLICT(owner_user_id, contact_user_id) DO UPDATE SET
                fingerprint = excluded.fingerprint,
                state = excluded.state,
                updated_at = now()",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(owner_user_id)
        .bind(contact_user_id)
        .bind(fingerprint)
        .bind(state)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn hit_rate_limit(
        &self,
        key: &str,
        max_count: i64,
        window_seconds: i32,
    ) -> Result<bool, sqlx::Error> {
        let row = sqlx::query(
            "INSERT INTO rate_limits (key, window_start, count)
             VALUES ($1, now(), 1)
             ON CONFLICT(key) DO UPDATE SET
                count = CASE
                    WHEN rate_limits.window_start < now() - make_interval(secs => $2)
                    THEN 1 ELSE rate_limits.count + 1 END,
                window_start = CASE
                    WHEN rate_limits.window_start < now() - make_interval(secs => $2)
                    THEN now() ELSE rate_limits.window_start END
             RETURNING count",
        )
        .bind(key)
        .bind(window_seconds)
        .fetch_one(&self.pool)
        .await?;
        let count: i64 = row.get("count");
        Ok(count <= max_count)
    }

    pub async fn insert_audit_event(
        &self,
        user_id: Option<&str>,
        event_type: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO audit_events (id, user_id, event_type, created_at)
             VALUES ($1, $2, $3, now())",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(user_id)
        .bind(event_type)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

const MIGRATIONS: &str = r#"
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    public_key BYTEA NOT NULL,
    ed25519_pk BYTEA NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    access_token_hash TEXT NOT NULL UNIQUE,
    refresh_token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    refresh_expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS device_keys (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    public_key BYTEA NOT NULL,
    ed25519_pk BYTEA NOT NULL,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS offline_messages (
    id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    from_user_id TEXT NOT NULL,
    sender_device_id TEXT NOT NULL,
    sender_seq BIGINT NOT NULL,
    prev_hash BYTEA NOT NULL,
    recipient_device_id TEXT NOT NULL,
    ciphertext BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    timestamp BIGINT NOT NULL,
    delivered BOOLEAN NOT NULL DEFAULT false,
    acked BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE(message_id, recipient_device_id)
);
CREATE TABLE IF NOT EXISTS message_deliveries (
    id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL,
    recipient_device_id TEXT NOT NULL,
    status TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS trusted_contacts (
    id TEXT PRIMARY KEY,
    owner_user_id TEXT NOT NULL,
    contact_user_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    state TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE(owner_user_id, contact_user_id)
);
CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    event_type TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS rate_limits (
    key TEXT PRIMARY KEY,
    window_start TIMESTAMPTZ NOT NULL,
    count BIGINT NOT NULL
);
"#;
