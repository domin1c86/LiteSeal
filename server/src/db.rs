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
    pub protocol_version: i16,
    pub message_id: String,
    pub conversation_id: String,
    pub from_user_id: String,
    pub sender_device_id: String,
    pub sender_seq: i64,
    pub prev_hash: Vec<u8>,
    pub recipient_user_id: String,
    pub recipient_device_id: String,
    pub message_type: String,
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreOfflineOutcome {
    Stored,
    Duplicate,
    QuotaExceeded,
    Conflict,
}

pub struct AckedMessage {
    pub message_id: String,
    pub status: String,
    pub sender_device_id: String,
    pub recipient_user_id: String,
    pub recipient_device_id: String,
}

const MAX_OFFLINE_MESSAGES_PER_DEVICE: i64 = 1_000;
const MAX_OFFLINE_BYTES_PER_DEVICE: i64 = 10 * 1024 * 1024;

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
        let mut transaction = self.pool.begin().await?;
        // CREATE TABLE IF NOT EXISTS alone does not serialize concurrent
        // first boots. Protect the version table and all DDL in one transaction.
        sqlx::query("SELECT pg_advisory_xact_lock(1818850405, 1)")
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                version BIGINT PRIMARY KEY,
                applied_at TIMESTAMPTZ NOT NULL
            )",
        )
        .execute(&mut *transaction)
        .await?;
        for (version, sql) in [
            (1_i64, MIGRATIONS),
            (2, BETA_MIGRATIONS),
            (3, OPERATION_MIGRATIONS),
        ] {
            let applied = sqlx::query("SELECT 1 FROM schema_migrations WHERE version = $1")
                .bind(version)
                .fetch_optional(&mut *transaction)
                .await?;
            if applied.is_some() {
                continue;
            }
            for statement in sql.split(';').map(str::trim).filter(|s| !s.is_empty()) {
                sqlx::query(statement).execute(&mut *transaction).await?;
            }
            sqlx::query("INSERT INTO schema_migrations (version, applied_at) VALUES ($1, now())")
                .bind(version)
                .execute(&mut *transaction)
                .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Creates the user, its only device and the first session atomically.
    #[allow(clippy::too_many_arguments)]
    pub async fn register_user(
        &self,
        username: &str,
        password_hash: &str,
        device_name: &str,
        public_key: &[u8],
        ed25519_pk: &[u8],
        access_token_hash: &str,
        refresh_token_hash: &str,
    ) -> Result<(UserRecord, DeviceRecord), sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        let user_id = uuid::Uuid::new_v4().to_string();
        let device_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, created_at)
             VALUES ($1, $2, $3, now())",
        )
        .bind(&user_id)
        .bind(username)
        .bind(password_hash)
        .execute(&mut *transaction)
        .await?;
        insert_device(
            &mut transaction,
            &device_id,
            &user_id,
            device_name,
            public_key,
            ed25519_pk,
        )
        .await?;
        insert_session(
            &mut transaction,
            &user_id,
            &device_id,
            access_token_hash,
            refresh_token_hash,
        )
        .await?;
        transaction.commit().await?;

        Ok((
            UserRecord {
                id: user_id,
                username: username.to_string(),
                password_hash: password_hash.to_string(),
            },
            DeviceRecord {
                id: device_id,
                name: device_name.to_string(),
                public_key: public_key.to_vec(),
                ed25519_pk: ed25519_pk.to_vec(),
                revoked: false,
            },
        ))
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

    pub async fn get_username(&self, user_id: &str) -> Result<Option<String>, sqlx::Error> {
        let row = sqlx::query("SELECT username FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.get("username")))
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

    pub async fn rotate_refresh_session(
        &self,
        old_refresh_token_hash: &str,
        access_token_hash: &str,
        refresh_token_hash: &str,
    ) -> Result<Option<(String, String)>, sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        let consumed = sqlx::query(
            "UPDATE sessions SET revoked = true
             WHERE refresh_token_hash = $1 AND revoked = false AND refresh_expires_at > now()
             RETURNING user_id, device_id",
        )
        .bind(old_refresh_token_hash)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(consumed) = consumed else {
            transaction.rollback().await?;
            return Ok(None);
        };
        let user_id: String = consumed.get("user_id");
        let device_id: String = consumed.get("device_id");
        insert_session(
            &mut transaction,
            &user_id,
            &device_id,
            access_token_hash,
            refresh_token_hash,
        )
        .await?;
        transaction.commit().await?;
        Ok(Some((user_id, device_id)))
    }

    pub async fn validate_access_token(
        &self,
        access_token_hash: &str,
        device_id: &str,
    ) -> Result<Option<String>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT s.user_id FROM sessions s JOIN devices d ON d.id = s.device_id
             WHERE s.access_token_hash = $1 AND s.device_id = $2 AND s.revoked = false AND s.expires_at > now() AND d.revoked = false",
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
            "SELECT s.user_id FROM sessions s JOIN devices d ON d.id = s.device_id
             WHERE s.access_token_hash = $1 AND s.revoked = false AND s.expires_at > now() AND d.revoked = false",
        )
        .bind(access_token_hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.get("user_id")))
    }

    pub async fn revoke_session(&self, access_token_hash: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE sessions SET revoked = true WHERE access_token_hash = $1")
            .bind(access_token_hash)
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

    pub async fn get_user_device(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Result<Option<DeviceRecord>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT id, name, public_key, ed25519_pk, revoked FROM devices
             WHERE user_id = $1 AND id = $2",
        )
        .bind(user_id)
        .bind(device_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| DeviceRecord {
            id: r.get("id"),
            name: r.get("name"),
            public_key: r.get("public_key"),
            ed25519_pk: r.get("ed25519_pk"),
            revoked: r.get("revoked"),
        }))
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
    ) -> Result<StoreOfflineOutcome, sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        // Serialise quota checks for a recipient without locking unrelated
        // queues. This prevents concurrent sends from racing past the cap.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(&msg.recipient_device_id)
            .execute(&mut *transaction)
            .await?;

        let envelope = msg.envelope();
        let digest = envelope
            .digest()
            .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
        let existing = sqlx::query(
            "SELECT digest FROM beta_receipts WHERE message_id = $1 AND recipient_device_id = $2",
        )
        .bind(&msg.message_id)
        .bind(&msg.recipient_device_id)
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(existing) = existing {
            let same = existing.get::<Vec<u8>, _>("digest") == digest;
            transaction.commit().await?;
            return Ok(if same {
                StoreOfflineOutcome::Duplicate
            } else {
                StoreOfflineOutcome::Conflict
            });
        }
        let occupied = sqlx::query("SELECT 1 FROM beta_receipts WHERE sender_device_id = $1 AND conversation_id = $2 AND sender_seq = $3")
            .bind(&msg.sender_device_id).bind(&msg.conversation_id).bind(msg.sender_seq)
            .fetch_optional(&mut *transaction).await?;
        if occupied.is_some() {
            return Ok(StoreOfflineOutcome::Conflict);
        }
        let usage = sqlx::query(
            "SELECT COUNT(*) AS message_count,
                    COALESCE(SUM(octet_length(ciphertext) + octet_length(signature)), 0) AS byte_count
             FROM offline_messages
             WHERE recipient_device_id = $1 AND acked = false",
        )
        .bind(&msg.recipient_device_id)
        .fetch_one(&mut *transaction)
        .await?;
        let message_count: i64 = usage.get("message_count");
        let byte_count: i64 = usage.get("byte_count");
        let new_bytes =
            i64::try_from(msg.ciphertext.len() + msg.signature.len()).unwrap_or(i64::MAX);
        if message_count >= MAX_OFFLINE_MESSAGES_PER_DEVICE
            || byte_count.saturating_add(new_bytes) > MAX_OFFLINE_BYTES_PER_DEVICE
        {
            transaction.commit().await?;
            return Ok(StoreOfflineOutcome::QuotaExceeded);
        }

        sqlx::query("INSERT INTO beta_receipts (message_id, recipient_device_id, sender_user_id, sender_device_id, recipient_user_id, conversation_id, sender_seq, digest, status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'stored')")
            .bind(&msg.message_id).bind(&msg.recipient_device_id).bind(&msg.from_user_id).bind(&msg.sender_device_id)
            .bind(&msg.recipient_user_id).bind(&msg.conversation_id).bind(msg.sender_seq).bind(digest)
            .execute(&mut *transaction).await?;
        sqlx::query(
            "INSERT INTO offline_messages
             (id, protocol_version, message_id, conversation_id, from_user_id, sender_device_id,
              sender_seq, prev_hash, recipient_user_id, recipient_device_id, message_type,
              ciphertext, signature, timestamp, delivered, acked, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
                     false, false, now())",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(msg.protocol_version)
        .bind(&msg.message_id)
        .bind(&msg.conversation_id)
        .bind(&msg.from_user_id)
        .bind(&msg.sender_device_id)
        .bind(msg.sender_seq)
        .bind(&msg.prev_hash)
        .bind(&msg.recipient_user_id)
        .bind(&msg.recipient_device_id)
        .bind(&msg.message_type)
        .bind(&msg.ciphertext)
        .bind(&msg.signature)
        .bind(msg.timestamp)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(StoreOfflineOutcome::Stored)
    }

    #[cfg(test)]
    pub async fn drain_offline_messages(
        &self,
        device_id: &str,
    ) -> Result<Vec<OfflineMessageRecord>, sqlx::Error> {
        self.pending_messages(device_id, 1000).await
    }

    pub async fn pending_window(
        &self,
        device_id: &str,
    ) -> Result<Vec<OfflineMessageRecord>, sqlx::Error> {
        self.pending_messages(device_id, 128).await
    }

    async fn pending_messages(
        &self,
        device_id: &str,
        limit: i64,
    ) -> Result<Vec<OfflineMessageRecord>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT protocol_version, message_id, conversation_id, from_user_id, sender_device_id,
                    sender_seq, prev_hash, recipient_user_id, recipient_device_id, message_type,
                    ciphertext, signature, timestamp
             FROM offline_messages
             WHERE recipient_device_id = $1 AND acked = false
             ORDER BY delivery_order ASC LIMIT $2",
        )
        .bind(device_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| OfflineMessageRecord {
                protocol_version: r.get("protocol_version"),
                message_id: r.get("message_id"),
                conversation_id: r.get("conversation_id"),
                from_user_id: r.get("from_user_id"),
                sender_device_id: r.get("sender_device_id"),
                sender_seq: r.get("sender_seq"),
                prev_hash: r.get("prev_hash"),
                recipient_user_id: r.get("recipient_user_id"),
                recipient_device_id: r.get("recipient_device_id"),
                message_type: r.get("message_type"),
                ciphertext: r.get("ciphertext"),
                signature: r.get("signature"),
                timestamp: r.get("timestamp"),
            })
            .collect())
    }

    pub async fn ack_message(
        &self,
        message_id: &str,
        device_id: &str,
        outcome: liteseal_shared::protocol::AckOutcome,
    ) -> Result<Option<AckedMessage>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query("UPDATE beta_receipts SET status = CASE WHEN status = 'stored' THEN $3 ELSE status END WHERE message_id = $1 AND recipient_device_id = $2 RETURNING message_id, sender_device_id, recipient_user_id, recipient_device_id, status")
            .bind(message_id).bind(device_id).bind(outcome.status()).fetch_optional(&mut *tx).await?;
        if row.is_some() {
            sqlx::query(
                "DELETE FROM offline_messages WHERE message_id = $1 AND recipient_device_id = $2",
            )
            .bind(message_id)
            .bind(device_id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(row.map(|row| AckedMessage {
            message_id: row.get("message_id"),
            status: row.get("status"),
            sender_device_id: row.get("sender_device_id"),
            recipient_user_id: row.get("recipient_user_id"),
            recipient_device_id: row.get("recipient_device_id"),
        }))
    }

    pub async fn delivery_statuses(
        &self,
        sender_device: &str,
        ids: &[String],
    ) -> Result<Vec<liteseal_shared::protocol::DeliveryStatus>, sqlx::Error> {
        let rows = sqlx::query("SELECT message_id, recipient_user_id, recipient_device_id, status FROM beta_receipts WHERE sender_device_id = $1 AND message_id = ANY($2)")
            .bind(sender_device).bind(ids).fetch_all(&self.pool).await?;
        Ok(ids
            .iter()
            .map(|id| {
                let row = rows
                    .iter()
                    .find(|row| row.get::<String, _>("message_id") == *id);
                liteseal_shared::protocol::DeliveryStatus {
                    message_id: id.clone(),
                    recipient_user_id: row.map(|r| r.get("recipient_user_id")).unwrap_or_default(),
                    recipient_device_id: row
                        .map(|r| r.get("recipient_device_id"))
                        .unwrap_or_default(),
                    status: row
                        .map(|r| r.get("status"))
                        .unwrap_or_else(|| "unknown".to_string()),
                }
            })
            .collect())
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

async fn insert_device(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    device_id: &str,
    user_id: &str,
    name: &str,
    public_key: &[u8],
    ed25519_pk: &[u8],
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO devices (id, user_id, name, public_key, ed25519_pk, revoked, created_at, last_seen)
         VALUES ($1, $2, $3, $4, $5, false, now(), now())",
    )
    .bind(device_id)
    .bind(user_id)
    .bind(name)
    .bind(public_key)
    .bind(ed25519_pk)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn insert_session(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: &str,
    device_id: &str,
    access_token_hash: &str,
    refresh_token_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO sessions
         (id, user_id, device_id, access_token_hash, refresh_token_hash, expires_at,
          refresh_expires_at, revoked, created_at)
         VALUES ($1, $2, $3, $4, $5, now() + interval '30 minutes',
                 now() + interval '30 days', false, now())",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(user_id)
    .bind(device_id)
    .bind(access_token_hash)
    .bind(refresh_token_hash)
    .execute(&mut **transaction)
    .await?;
    Ok(())
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
    protocol_version SMALLINT NOT NULL DEFAULT 1,
    message_id TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    from_user_id TEXT NOT NULL,
    sender_device_id TEXT NOT NULL,
    sender_seq BIGINT NOT NULL,
    prev_hash BYTEA NOT NULL,
    recipient_user_id TEXT NOT NULL DEFAULT '',
    recipient_device_id TEXT NOT NULL,
    message_type TEXT NOT NULL DEFAULT 'text',
    ciphertext BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    timestamp BIGINT NOT NULL,
    delivered BOOLEAN NOT NULL DEFAULT false,
    acked BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE(message_id, recipient_device_id)
);
ALTER TABLE offline_messages ADD COLUMN IF NOT EXISTS protocol_version SMALLINT NOT NULL DEFAULT 1;
ALTER TABLE offline_messages ADD COLUMN IF NOT EXISTS recipient_user_id TEXT NOT NULL DEFAULT '';
ALTER TABLE offline_messages ADD COLUMN IF NOT EXISTS message_type TEXT NOT NULL DEFAULT 'text';
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
CREATE TABLE IF NOT EXISTS invitation_codes (
    id TEXT PRIMARY KEY,
    code_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    consumed_by TEXT,
    created_at TIMESTAMPTZ NOT NULL
);
"#;

const BETA_MIGRATIONS: &str = "
ALTER TABLE offline_messages ADD COLUMN delivery_order BIGSERIAL;
CREATE INDEX offline_pending_device_idx ON offline_messages (recipient_device_id, delivery_order) WHERE acked = false;
CREATE TABLE beta_receipts (
 message_id TEXT NOT NULL, recipient_device_id TEXT NOT NULL,
 sender_user_id TEXT NOT NULL, sender_device_id TEXT NOT NULL, recipient_user_id TEXT NOT NULL,
 conversation_id TEXT NOT NULL, sender_seq BIGINT NOT NULL, digest BYTEA NOT NULL,
 status TEXT NOT NULL CHECK (status IN ('stored','delivered','rejected')),
 PRIMARY KEY (message_id, recipient_device_id), UNIQUE (sender_device_id, conversation_id, sender_seq)
);
CREATE INDEX beta_receipts_sender_idx ON beta_receipts (sender_device_id, message_id);
";

// Receipts outlive acknowledged ciphertext, so message operations locate the
// original message and its server receive time through them.
const OPERATION_MIGRATIONS: &str = "
ALTER TABLE beta_receipts ADD COLUMN received_at BIGINT NOT NULL DEFAULT ((EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT);
CREATE INDEX beta_receipts_message_idx ON beta_receipts (message_id);
CREATE TABLE IF NOT EXISTS message_operations (
 id TEXT PRIMARY KEY, target_id TEXT NOT NULL, kind TEXT NOT NULL,
 revision BIGINT NOT NULL, accepted_at BIGINT NOT NULL, request TEXT NOT NULL,
 UNIQUE(target_id, revision)
);
CREATE TABLE IF NOT EXISTS operation_deliveries (
 operation_id TEXT NOT NULL REFERENCES message_operations(id), device_id TEXT NOT NULL,
 body TEXT NOT NULL, acked BOOLEAN NOT NULL DEFAULT false, PRIMARY KEY(operation_id, device_id)
);
CREATE INDEX IF NOT EXISTS operation_pending_device ON operation_deliveries(device_id) WHERE acked = false;
";

impl OfflineMessageRecord {
    pub fn envelope(&self) -> liteseal_shared::protocol::SignedEnvelopeV2 {
        liteseal_shared::protocol::SignedEnvelopeV2 {
            protocol_version: self.protocol_version as u8,
            message_id: self.message_id.clone(),
            conversation_id: self.conversation_id.clone(),
            sender_user_id: self.from_user_id.clone(),
            sender_device_id: self.sender_device_id.clone(),
            recipient_user_id: self.recipient_user_id.clone(),
            recipient_device_id: self.recipient_device_id.clone(),
            sender_seq: self.sender_seq,
            prev_hash: self.prev_hash.clone(),
            sent_at: self.timestamp,
            message_type: self.message_type.clone(),
            ciphertext: self.ciphertext.clone(),
            signature: self.signature.clone(),
        }
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
    async fn concurrent_first_boot_migrations_are_atomic() {
        let url =
            std::env::var("LITESEAL_TEST_DATABASE_URL").expect("dedicated test database required");
        let admin = PgPoolOptions::new().connect(&url).await.unwrap();
        let schema = format!("migration_test_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        let options = url
            .parse::<sqlx::postgres::PgConnectOptions>()
            .unwrap()
            .options([("search_path", schema.as_str())]);
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .unwrap();
        let db = Db { pool };
        tokio::try_join!(db.migrate(), db.migrate(), db.migrate(), db.migrate()).unwrap();
        let versions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM schema_migrations")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(versions, 3);
        sqlx::query("SELECT 1 FROM offline_messages LIMIT 1")
            .execute(db.pool())
            .await
            .unwrap();
        db.pool.close().await;
        // The UUID-named schema was created exclusively by this test.
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
    }

    async fn test_db() -> Db {
        let url = std::env::var("LITESEAL_TEST_DATABASE_URL")
            .expect("set LITESEAL_TEST_DATABASE_URL to a dedicated test database");
        Db::connect(&url).await.expect("connect test Postgres")
    }

    async fn register(db: &Db, username: &str) -> Result<(String, String), sqlx::Error> {
        let access = format!("access-{username}");
        let refresh = format!("refresh-{username}");
        db.register_user(
            username,
            "password-hash",
            "test device",
            &[1; 32],
            &[2; 32],
            &access,
            &refresh,
        )
        .await
        .map(|(user, device)| (user.id, device.id))
    }

    #[tokio::test]
    #[ignore = "requires dedicated Postgres: LITESEAL_TEST_DATABASE_URL"]
    async fn registration_rolls_back_and_refresh_rotates_once_under_concurrency() {
        let db = test_db().await;
        let suffix = uuid::Uuid::new_v4();
        let user = format!("user-{suffix}");
        let (user_id, _) = register(&db, &user).await.expect("first registration");
        // A duplicate username fails without leaving a second device behind.
        assert!(db
            .register_user(
                &user,
                "password-hash",
                "test device",
                &[1; 32],
                &[2; 32],
                "duplicate-user-access",
                "duplicate-user-refresh",
            )
            .await
            .is_err());
        assert_eq!(db.list_user_devices(&user_id).await.unwrap().len(), 1);

        let refresh_user = format!("refresh-user-{suffix}");
        register(&db, &refresh_user)
            .await
            .expect("refresh test registration");
        let old_refresh = format!("refresh-{refresh_user}");
        let rotate_one = {
            let db = db.clone();
            let old_refresh = old_refresh.clone();
            let new_access = format!("new-access-1-{suffix}");
            let new_refresh = format!("new-refresh-1-{suffix}");
            tokio::spawn(async move {
                db.rotate_refresh_session(&old_refresh, &new_access, &new_refresh)
                    .await
                    .unwrap()
            })
        };
        let rotate_two = {
            let db = db.clone();
            let new_access = format!("new-access-2-{suffix}");
            let new_refresh = format!("new-refresh-2-{suffix}");
            tokio::spawn(async move {
                db.rotate_refresh_session(&old_refresh, &new_access, &new_refresh)
                    .await
                    .unwrap()
            })
        };
        let rotations = [rotate_one.await.unwrap(), rotate_two.await.unwrap()];
        assert_eq!(
            rotations.iter().filter(|result| result.is_some()).count(),
            1,
            "a refresh token must only rotate once"
        );
    }
}
