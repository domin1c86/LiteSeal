use rusqlite::{params, Connection};
use thiserror::Error;

use super::models::{AttachmentModel, ContactModel, ConversationModel, DeviceModel, MessageModel};

#[derive(Error, Debug)]
pub enum DbError {
    #[error("Database error: {0}")]
    SqliteError(#[from] rusqlite::Error),
    #[error("Not found")]
    NotFound,
}

#[derive(serde::Serialize)]
pub struct ConversationSummary {
    pub conversation_id: String,
    pub latest: MessageModel,
    pub unread_count: i64,
}

#[derive(serde::Serialize)]
pub struct ConversationPreference {
    pub peer_id: String,
    pub pinned: bool,
    pub archived: bool,
    pub draft: Vec<u8>,
}

pub struct MessageRepository {
    conn: Connection,
}

impl MessageRepository {
    pub fn new(db_path: &str) -> Result<Self, DbError> {
        let conn = Connection::open(db_path)?;

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS conversations (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                storage_policy TEXT,
                privacy_mode TEXT
            );

            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                sender_device_id TEXT NOT NULL,
                sender_seq INTEGER NOT NULL,
                timestamp INTEGER NOT NULL,
                message_type TEXT NOT NULL,
                local_state TEXT NOT NULL,
                expire_at INTEGER,
                ciphertext BLOB NOT NULL,
                signature BLOB NOT NULL,
                prev_hash BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS conversation_preferences (
                user_id TEXT NOT NULL, peer_id TEXT NOT NULL,
                pinned INTEGER NOT NULL DEFAULT 0, archived INTEGER NOT NULL DEFAULT 0,
                draft BLOB NOT NULL DEFAULT X'', PRIMARY KEY(user_id, peer_id)
            );
            CREATE TABLE IF NOT EXISTS local_message_reads (
                user_id TEXT NOT NULL, message_id TEXT NOT NULL,
                PRIMARY KEY(user_id, message_id)
            );
            CREATE TABLE IF NOT EXISTS outgoing_chains (
                message_id TEXT NOT NULL, device_id TEXT NOT NULL,
                sender_seq INTEGER NOT NULL, prev_hash BLOB NOT NULL,
                PRIMARY KEY(message_id, device_id)
            );
            CREATE TABLE IF NOT EXISTS incoming_chain_versions (
                message_id TEXT PRIMARY KEY, version INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS outgoing_delivery (
                message_id TEXT NOT NULL, device_id TEXT NOT NULL, status TEXT NOT NULL,
                PRIMARY KEY(message_id, device_id)
            );
            CREATE TABLE IF NOT EXISTS outgoing_payloads (
                message_id TEXT PRIMARY KEY,
                payloads TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS attachments (
                id TEXT PRIMARY KEY,
                message_id TEXT NOT NULL,
                blob_id TEXT NOT NULL,
                encrypted_name BLOB NOT NULL,
                encrypted_mime BLOB NOT NULL,
                size INTEGER NOT NULL,
                downloaded INTEGER NOT NULL DEFAULT 0,
                pinned INTEGER NOT NULL DEFAULT 0,
                expire_at INTEGER,
                last_accessed_at INTEGER
            );

            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                public_key BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                last_seen INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS contacts (
                user_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                public_key BLOB NOT NULL,
                ed25519_pk BLOB,
                trust_state TEXT NOT NULL DEFAULT 'unverified',
                fingerprint TEXT NOT NULL DEFAULT '',
                key_changed INTEGER NOT NULL DEFAULT 0,
                added_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_messages_conversation
            ON messages(conversation_id, timestamp);

            CREATE INDEX IF NOT EXISTS idx_attachments_message
            ON attachments(message_id);
        ",
        )?;

        let _ = conn.execute("ALTER TABLE contacts ADD COLUMN ed25519_pk BLOB", []);
        let _ = conn.execute(
            "ALTER TABLE contacts ADD COLUMN trust_state TEXT NOT NULL DEFAULT 'unverified'",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE contacts ADD COLUMN fingerprint TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE contacts ADD COLUMN key_changed INTEGER NOT NULL DEFAULT 0",
            [],
        );

        Ok(Self { conn })
    }

    pub fn record_delivery(
        &self,
        message_id: &str,
        device_id: &str,
        status: &str,
    ) -> Result<String, DbError> {
        self.conn.execute(
            "INSERT INTO outgoing_delivery(message_id, device_id, status) VALUES (?1, ?2, ?3)
            ON CONFLICT(message_id, device_id) DO UPDATE SET status = CASE
            WHEN outgoing_delivery.status = 'received' THEN 'received' ELSE excluded.status END",
            params![message_id, device_id, status],
        )?;
        let mut stmt = self
            .conn
            .prepare("SELECT status FROM outgoing_delivery WHERE message_id = ?1")?;
        let statuses = stmt
            .query_map([message_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        let expected = self
            .outgoing_payloads(message_id)
            .ok()
            .and_then(|text| {
                serde_json::from_str::<Vec<liteseal_shared::protocol::EncryptedPayload>>(&text).ok()
            })
            .map_or(statuses.len(), |items| items.len());
        let received = statuses.iter().filter(|s| s.as_str() == "received").count();
        let state = if statuses.iter().any(|s| s == "failed") {
            "failed"
        } else if received == expected && expected > 0 {
            "received"
        } else if received > 0 {
            "partially_received"
        } else if statuses.len() < expected || statuses.iter().any(|s| s == "queued") {
            "queued"
        } else {
            "stored_offline"
        };
        self.update_message_state(message_id, state)?;
        Ok(state.into())
    }

    pub fn prepare_outgoing(&self, msg: &MessageModel, payloads: &str) -> Result<(), DbError> {
        use liteseal_shared::protocol::EncryptedPayload;
        let tx = self.conn.unchecked_transaction()?;
        let items: Vec<EncryptedPayload> =
            serde_json::from_str(payloads).map_err(|_| DbError::NotFound)?;
        for item in &items {
            let previous_id = {
                let mut stmt = tx.prepare("SELECT c.message_id FROM outgoing_chains c JOIN messages m ON m.id = c.message_id
                    WHERE m.conversation_id = ?1 AND m.sender_device_id = ?2 AND c.device_id = ?3
                    ORDER BY c.sender_seq DESC LIMIT 1")?;
                let mut rows = stmt.query(params![
                    msg.conversation_id,
                    msg.sender_device_id,
                    item.recipient_device_id
                ])?;
                rows.next()?
                    .map(|row| row.get::<_, String>(0))
                    .transpose()?
            };
            let (seq, hash) = if let Some(id) = previous_id {
                let mut previous = self.get_message(&id)?.ok_or(DbError::NotFound)?;
                let old_items: Vec<EncryptedPayload> =
                    serde_json::from_str(&self.outgoing_payloads(&id)?)
                        .map_err(|_| DbError::NotFound)?;
                let old_payload = old_items
                    .iter()
                    .find(|p| p.recipient_device_id == item.recipient_device_id)
                    .ok_or(DbError::NotFound)?;
                let chain = tx.query_row("SELECT sender_seq, prev_hash FROM outgoing_chains WHERE message_id = ?1 AND device_id = ?2",
                    params![id, item.recipient_device_id], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)))?;
                previous.sender_seq = chain.0;
                previous.prev_hash = chain.1;
                previous.ciphertext = old_payload.ciphertext.clone();
                previous.signature = old_payload.signature.clone();
                (
                    previous.sender_seq + 1,
                    crate::integrity::MessageIntegrityStore::hash_message(&previous),
                )
            } else {
                (1, Vec::new())
            };
            tx.execute("INSERT INTO outgoing_chains(message_id, device_id, sender_seq, prev_hash) VALUES (?1, ?2, ?3, ?4)",
                params![msg.id, item.recipient_device_id, seq, hash])?;
        }
        self.insert_message(msg)?;
        tx.execute(
            "INSERT INTO outgoing_payloads(message_id, payloads) VALUES (?1, ?2)",
            params![msg.id, payloads],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn outgoing_chains(
        &self,
        message_id: &str,
    ) -> Result<
        std::collections::BTreeMap<String, liteseal_shared::protocol::RecipientChain>,
        DbError,
    > {
        let mut stmt = self.conn.prepare(
            "SELECT device_id, sender_seq, prev_hash FROM outgoing_chains WHERE message_id = ?1",
        )?;
        let result = stmt
            .query_map([message_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    liteseal_shared::protocol::RecipientChain {
                        sender_seq: row.get(1)?,
                        prev_hash: row.get(2)?,
                    },
                ))
            })?
            .collect::<Result<_, _>>()?;
        Ok(result)
    }

    pub fn insert_received(
        &self,
        message: &MessageModel,
        version: i64,
    ) -> Result<Vec<MessageModel>, DbError> {
        let mut repaired = Vec::new();
        let tx = self.conn.unchecked_transaction()?;
        self.insert_message(message)?;
        tx.execute(
            "INSERT INTO incoming_chain_versions(message_id, version) VALUES (?1, ?2)",
            params![message.id, version],
        )?;
        // Revisit quarantined successors when a missing predecessor arrives.
        if version == 2 {
            loop {
                let previous = self.get_latest_received_for_version(
                    &message.conversation_id,
                    &message.sender_device_id,
                    version,
                )?;
                let next_seq = previous
                    .as_ref()
                    .map_or(1, |m| m.sender_seq.saturating_add(1));
                let ids = {
                    let mut stmt = tx.prepare("SELECT m.id FROM messages m JOIN incoming_chain_versions v ON v.message_id = m.id
                        WHERE m.conversation_id = ?1 AND m.sender_device_id = ?2 AND v.version = ?3
                        AND m.sender_seq = ?4 AND m.local_state = 'integrity_failed'")?;
                    let rows = stmt.query_map(
                        params![
                            message.conversation_id,
                            message.sender_device_id,
                            version,
                            next_seq
                        ],
                        |r| r.get::<_, String>(0),
                    )?;
                    rows.collect::<Result<Vec<_>, _>>()?
                };
                if ids.len() != 1 {
                    break;
                }
                let mut candidate = self.get_message(&ids[0])?.ok_or(DbError::NotFound)?;
                let valid_start = previous.is_some()
                    || (candidate.sender_seq == 1 && candidate.prev_hash.is_empty());
                if !valid_start
                    || crate::integrity::MessageIntegrityStore::validate_next(
                        previous.as_ref(),
                        &candidate,
                    ) != crate::integrity::IntegrityResult::Valid
                {
                    break;
                }
                self.update_message_state(&candidate.id, "received")?;
                candidate.local_state = "received".into();
                repaired.push(candidate);
            }
        }
        tx.commit()?;
        Ok(repaired)
    }

    pub fn incoming_chain_version(&self, message_id: &str) -> Result<i64, DbError> {
        Ok(self.conn.query_row("SELECT COALESCE((SELECT version FROM incoming_chain_versions WHERE message_id = ?1), 0)",
            [message_id], |row| row.get(0))?)
    }

    pub fn conversation_preferences(
        &self,
        user_id: &str,
    ) -> Result<Vec<ConversationPreference>, DbError> {
        let mut stmt = self.conn.prepare("SELECT peer_id, pinned, archived, draft FROM conversation_preferences WHERE user_id = ?1")?;
        let rows = stmt.query_map([user_id], |row| {
            Ok(ConversationPreference {
                peer_id: row.get(0)?,
                pinned: row.get(1)?,
                archived: row.get(2)?,
                draft: row.get(3)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn save_conversation_preference(
        &self,
        user_id: &str,
        peer_id: &str,
        pinned: Option<bool>,
        archived: Option<bool>,
        draft: Option<&[u8]>,
    ) -> Result<(), DbError> {
        self.conn.execute("INSERT INTO conversation_preferences(user_id, peer_id, pinned, archived, draft)
            VALUES (?1, ?2, COALESCE(?3, 0), COALESCE(?4, 0), COALESCE(?5, X''))
            ON CONFLICT(user_id, peer_id) DO UPDATE SET
            pinned = COALESCE(?3, pinned), archived = COALESCE(?4, archived), draft = COALESCE(?5, draft)",
            params![user_id, peer_id, pinned, archived, draft])?;
        Ok(())
    }

    pub fn conversation_summaries(
        &self,
        user_id: &str,
    ) -> Result<Vec<ConversationSummary>, DbError> {
        let mut stmt = self.conn.prepare("SELECT conversation_id,
            (SELECT id FROM messages latest WHERE latest.conversation_id = m.conversation_id ORDER BY timestamp DESC, id DESC LIMIT 1),
            SUM(CASE WHEN sender_id != ?1 AND NOT EXISTS
                (SELECT 1 FROM local_message_reads r WHERE r.user_id = ?1 AND r.message_id = m.id)
                THEN 1 ELSE 0 END)
            FROM messages m GROUP BY conversation_id ORDER BY MAX(timestamp) DESC, conversation_id")?;
        let rows = stmt.query_map([user_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        let mut result = Vec::new();
        for row in rows {
            let (conversation_id, id, unread_count) = row?;
            result.push(ConversationSummary {
                conversation_id,
                latest: self.get_message(&id)?.ok_or(DbError::NotFound)?,
                unread_count,
            });
        }
        Ok(result)
    }

    pub fn mark_messages_read(&self, user_id: &str, ids: &[String]) -> Result<(), DbError> {
        let tx = self.conn.unchecked_transaction()?;
        for id in ids {
            tx.execute(
                "INSERT OR IGNORE INTO local_message_reads(user_id, message_id)
                SELECT ?1, id FROM messages WHERE id = ?2 AND sender_id != ?1",
                params![user_id, id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn outgoing_payloads(&self, message_id: &str) -> Result<String, DbError> {
        Ok(self.conn.query_row(
            "SELECT payloads FROM outgoing_payloads WHERE message_id = ?1",
            [message_id],
            |row| row.get(0),
        )?)
    }

    // Conversation operations

    pub fn insert_conversation(&self, conv: &ConversationModel) -> Result<(), DbError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO conversations (id, type, created_at, updated_at, storage_policy, privacy_mode)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                conv.id,
                conv.conversation_type,
                conv.created_at,
                conv.updated_at,
                conv.storage_policy,
                conv.privacy_mode,
            ],
        )?;
        Ok(())
    }

    pub fn get_conversation(&self, id: &str) -> Result<Option<ConversationModel>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, type, created_at, updated_at, storage_policy, privacy_mode
             FROM conversations WHERE id = ?1",
        )?;

        let mut rows = stmt.query_map(params![id], |row| {
            Ok(ConversationModel {
                id: row.get(0)?,
                conversation_type: row.get(1)?,
                created_at: row.get(2)?,
                updated_at: row.get(3)?,
                storage_policy: row.get(4)?,
                privacy_mode: row.get(5)?,
            })
        })?;

        match rows.next() {
            Some(Ok(conv)) => Ok(Some(conv)),
            Some(Err(e)) => Err(DbError::SqliteError(e)),
            None => Ok(None),
        }
    }

    pub fn update_conversation_timestamp(&self, id: &str, updated_at: i64) -> Result<(), DbError> {
        let rows_changed = self.conn.execute(
            "UPDATE conversations SET updated_at = ?1 WHERE id = ?2",
            params![updated_at, id],
        )?;
        if rows_changed == 0 {
            return Err(DbError::NotFound);
        }
        Ok(())
    }

    // Message operations

    pub fn insert_message(&self, msg: &MessageModel) -> Result<(), DbError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO messages (id, conversation_id, sender_id, sender_device_id,
             sender_seq, timestamp, message_type, local_state, expire_at,
             ciphertext, signature, prev_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                msg.id,
                msg.conversation_id,
                msg.sender_id,
                msg.sender_device_id,
                msg.sender_seq,
                msg.timestamp,
                msg.message_type,
                msg.local_state,
                msg.expire_at,
                msg.ciphertext,
                msg.signature,
                msg.prev_hash,
            ],
        )?;
        Ok(())
    }

    pub fn update_message_state(&self, id: &str, local_state: &str) -> Result<(), DbError> {
        let rows_changed = self.conn.execute(
            "UPDATE messages SET local_state = ?1 WHERE id = ?2",
            params![local_state, id],
        )?;
        if rows_changed == 0 {
            return Err(DbError::NotFound);
        }
        Ok(())
    }

    pub fn get_message(&self, id: &str) -> Result<Option<MessageModel>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, conversation_id, sender_id, sender_device_id,
             sender_seq, timestamp, message_type, local_state, expire_at,
             ciphertext, signature, prev_hash
             FROM messages WHERE id = ?1",
        )?;

        let mut rows = stmt.query_map(params![id], |row| {
            Ok(MessageModel {
                id: row.get(0)?,
                conversation_id: row.get(1)?,
                sender_id: row.get(2)?,
                sender_device_id: row.get(3)?,
                sender_seq: row.get(4)?,
                timestamp: row.get(5)?,
                message_type: row.get(6)?,
                local_state: row.get(7)?,
                expire_at: row.get(8)?,
                ciphertext: row.get(9)?,
                signature: row.get(10)?,
                prev_hash: row.get(11)?,
            })
        })?;

        match rows.next() {
            Some(Ok(msg)) => Ok(Some(msg)),
            Some(Err(e)) => Err(DbError::SqliteError(e)),
            None => Ok(None),
        }
    }

    pub fn get_messages_by_conversation(
        &self,
        conversation_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<MessageModel>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, conversation_id, sender_id, sender_device_id,
             sender_seq, timestamp, message_type, local_state, expire_at,
             ciphertext, signature, prev_hash
             FROM messages WHERE conversation_id = ?1
             ORDER BY timestamp ASC LIMIT ?2 OFFSET ?3",
        )?;

        let rows = stmt.query_map(params![conversation_id, limit, offset], |row| {
            Ok(MessageModel {
                id: row.get(0)?,
                conversation_id: row.get(1)?,
                sender_id: row.get(2)?,
                sender_device_id: row.get(3)?,
                sender_seq: row.get(4)?,
                timestamp: row.get(5)?,
                message_type: row.get(6)?,
                local_state: row.get(7)?,
                expire_at: row.get(8)?,
                ciphertext: row.get(9)?,
                signature: row.get(10)?,
                prev_hash: row.get(11)?,
            })
        })?;

        let mut messages = Vec::new();
        for row in rows {
            messages.push(row?);
        }
        Ok(messages)
    }

    pub fn get_message_page(
        &self,
        conversation_id: &str,
        limit: i64,
        before_timestamp: Option<i64>,
        before_id: Option<&str>,
    ) -> Result<Vec<MessageModel>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, conversation_id, sender_id, sender_device_id,
             sender_seq, timestamp, message_type, local_state, expire_at,
             ciphertext, signature, prev_hash
             FROM messages WHERE conversation_id = ?1
             AND (?3 IS NULL OR timestamp < ?3 OR (timestamp = ?3 AND id < ?4))
             ORDER BY timestamp DESC, id DESC LIMIT ?2",
        )?;

        let rows = stmt.query_map(
            params![conversation_id, limit, before_timestamp, before_id],
            |row| {
                Ok(MessageModel {
                    id: row.get(0)?,
                    conversation_id: row.get(1)?,
                    sender_id: row.get(2)?,
                    sender_device_id: row.get(3)?,
                    sender_seq: row.get(4)?,
                    timestamp: row.get(5)?,
                    message_type: row.get(6)?,
                    local_state: row.get(7)?,
                    expire_at: row.get(8)?,
                    ciphertext: row.get(9)?,
                    signature: row.get(10)?,
                    prev_hash: row.get(11)?,
                })
            },
        )?;

        let mut messages = Vec::new();
        for row in rows {
            messages.push(row?);
        }
        Ok(messages)
    }

    pub fn get_latest_message_for_sender(
        &self,
        conversation_id: &str,
        sender_device_id: &str,
    ) -> Result<Option<MessageModel>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, conversation_id, sender_id, sender_device_id,
             sender_seq, timestamp, message_type, local_state, expire_at,
             ciphertext, signature, prev_hash
             FROM messages
             WHERE conversation_id = ?1 AND sender_device_id = ?2 AND local_state != 'integrity_failed'
             ORDER BY sender_seq DESC LIMIT 1",
        )?;

        let mut rows = stmt.query_map(params![conversation_id, sender_device_id], |row| {
            Ok(MessageModel {
                id: row.get(0)?,
                conversation_id: row.get(1)?,
                sender_id: row.get(2)?,
                sender_device_id: row.get(3)?,
                sender_seq: row.get(4)?,
                timestamp: row.get(5)?,
                message_type: row.get(6)?,
                local_state: row.get(7)?,
                expire_at: row.get(8)?,
                ciphertext: row.get(9)?,
                signature: row.get(10)?,
                prev_hash: row.get(11)?,
            })
        })?;

        match rows.next() {
            Some(Ok(msg)) => Ok(Some(msg)),
            Some(Err(e)) => Err(DbError::SqliteError(e)),
            None => Ok(None),
        }
    }
    pub fn get_latest_received_for_version(
        &self,
        conversation_id: &str,
        sender_device_id: &str,
        version: i64,
    ) -> Result<Option<MessageModel>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, conversation_id, sender_id, sender_device_id,
             sender_seq, timestamp, message_type, local_state, expire_at,
             ciphertext, signature, prev_hash
             FROM messages
             WHERE conversation_id = ?1 AND sender_device_id = ?2 AND local_state != 'integrity_failed'
             AND COALESCE((SELECT version FROM incoming_chain_versions WHERE message_id = messages.id), 0) = ?3
             ORDER BY sender_seq DESC LIMIT 1",
        )?;

        let mut rows =
            stmt.query_map(params![conversation_id, sender_device_id, version], |row| {
                Ok(MessageModel {
                    id: row.get(0)?,
                    conversation_id: row.get(1)?,
                    sender_id: row.get(2)?,
                    sender_device_id: row.get(3)?,
                    sender_seq: row.get(4)?,
                    timestamp: row.get(5)?,
                    message_type: row.get(6)?,
                    local_state: row.get(7)?,
                    expire_at: row.get(8)?,
                    ciphertext: row.get(9)?,
                    signature: row.get(10)?,
                    prev_hash: row.get(11)?,
                })
            })?;

        match rows.next() {
            Some(Ok(msg)) => Ok(Some(msg)),
            Some(Err(e)) => Err(DbError::SqliteError(e)),
            None => Ok(None),
        }
    }

    pub fn delete_message(&self, id: &str) -> Result<(), DbError> {
        let rows_changed = self
            .conn
            .execute("DELETE FROM messages WHERE id = ?1", params![id])?;
        if rows_changed == 0 {
            return Err(DbError::NotFound);
        }
        Ok(())
    }

    // Attachment operations

    pub fn insert_attachment(&self, att: &AttachmentModel) -> Result<(), DbError> {
        self.conn.execute(
            "INSERT INTO attachments (id, message_id, blob_id, encrypted_name, encrypted_mime,
             size, downloaded, pinned, expire_at, last_accessed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                att.id,
                att.message_id,
                att.blob_id,
                att.encrypted_name,
                att.encrypted_mime,
                att.size,
                att.downloaded as i32,
                att.pinned as i32,
                att.expire_at,
                att.last_accessed_at,
            ],
        )?;
        Ok(())
    }

    pub fn get_attachment(&self, id: &str) -> Result<Option<AttachmentModel>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, message_id, blob_id, encrypted_name, encrypted_mime,
             size, downloaded, pinned, expire_at, last_accessed_at
             FROM attachments WHERE id = ?1",
        )?;

        let mut rows = stmt.query_map(params![id], |row| {
            Ok(AttachmentModel {
                id: row.get(0)?,
                message_id: row.get(1)?,
                blob_id: row.get(2)?,
                encrypted_name: row.get(3)?,
                encrypted_mime: row.get(4)?,
                size: row.get(5)?,
                downloaded: row.get::<_, i32>(6)? != 0,
                pinned: row.get::<_, i32>(7)? != 0,
                expire_at: row.get(8)?,
                last_accessed_at: row.get(9)?,
            })
        })?;

        match rows.next() {
            Some(Ok(att)) => Ok(Some(att)),
            Some(Err(e)) => Err(DbError::SqliteError(e)),
            None => Ok(None),
        }
    }

    pub fn get_attachments_by_message(
        &self,
        message_id: &str,
    ) -> Result<Vec<AttachmentModel>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, message_id, blob_id, encrypted_name, encrypted_mime,
             size, downloaded, pinned, expire_at, last_accessed_at
             FROM attachments WHERE message_id = ?1",
        )?;

        let rows = stmt.query_map(params![message_id], |row| {
            Ok(AttachmentModel {
                id: row.get(0)?,
                message_id: row.get(1)?,
                blob_id: row.get(2)?,
                encrypted_name: row.get(3)?,
                encrypted_mime: row.get(4)?,
                size: row.get(5)?,
                downloaded: row.get::<_, i32>(6)? != 0,
                pinned: row.get::<_, i32>(7)? != 0,
                expire_at: row.get(8)?,
                last_accessed_at: row.get(9)?,
            })
        })?;

        let mut attachments = Vec::new();
        for row in rows {
            attachments.push(row?);
        }
        Ok(attachments)
    }

    pub fn update_attachment_downloaded(&self, id: &str, downloaded: bool) -> Result<(), DbError> {
        let rows_changed = self.conn.execute(
            "UPDATE attachments SET downloaded = ?1, last_accessed_at = strftime('%s', 'now') WHERE id = ?2",
            params![downloaded as i32, id],
        )?;
        if rows_changed == 0 {
            return Err(DbError::NotFound);
        }
        Ok(())
    }

    pub fn delete_attachment(&self, id: &str) -> Result<(), DbError> {
        let rows_changed = self
            .conn
            .execute("DELETE FROM attachments WHERE id = ?1", params![id])?;
        if rows_changed == 0 {
            return Err(DbError::NotFound);
        }
        Ok(())
    }

    // Device operations

    pub fn insert_device(&self, device: &DeviceModel) -> Result<(), DbError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO devices (id, user_id, public_key, created_at, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                device.id,
                device.user_id,
                device.public_key,
                device.created_at,
                device.last_seen,
            ],
        )?;
        Ok(())
    }

    pub fn get_device(&self, id: &str) -> Result<Option<DeviceModel>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, user_id, public_key, created_at, last_seen
             FROM devices WHERE id = ?1",
        )?;

        let mut rows = stmt.query_map(params![id], |row| {
            Ok(DeviceModel {
                id: row.get(0)?,
                user_id: row.get(1)?,
                public_key: row.get(2)?,
                created_at: row.get(3)?,
                last_seen: row.get(4)?,
            })
        })?;

        match rows.next() {
            Some(Ok(device)) => Ok(Some(device)),
            Some(Err(e)) => Err(DbError::SqliteError(e)),
            None => Ok(None),
        }
    }

    // Contact operations

    pub fn insert_contact(&self, contact: &ContactModel) -> Result<(), DbError> {
        self.conn.execute(
            "INSERT INTO contacts
             (user_id, username, public_key, ed25519_pk, trust_state, fingerprint, key_changed, added_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(user_id) DO UPDATE SET
                username = excluded.username,
                public_key = excluded.public_key,
                ed25519_pk = excluded.ed25519_pk,
                fingerprint = excluded.fingerprint,
                key_changed = CASE
                    WHEN contacts.public_key != excluded.public_key
                         OR COALESCE(contacts.ed25519_pk, x'') != COALESCE(excluded.ed25519_pk, x'')
                    THEN 1 ELSE contacts.key_changed END,
                trust_state = CASE
                    WHEN contacts.public_key != excluded.public_key
                         OR COALESCE(contacts.ed25519_pk, x'') != COALESCE(excluded.ed25519_pk, x'')
                    THEN 'key_changed' ELSE contacts.trust_state END",
            params![
                contact.user_id,
                contact.username,
                contact.public_key,
                contact.ed25519_pk,
                contact.trust_state,
                contact.fingerprint,
                contact.key_changed as i32,
                contact.added_at
            ],
        )?;
        Ok(())
    }

    pub fn get_contacts(&self) -> Result<Vec<ContactModel>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT user_id, username, public_key, ed25519_pk, trust_state, fingerprint, key_changed, added_at
             FROM contacts ORDER BY added_at DESC"
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(ContactModel {
                user_id: row.get(0)?,
                username: row.get(1)?,
                public_key: row.get(2)?,
                ed25519_pk: row.get(3)?,
                trust_state: row.get(4)?,
                fingerprint: row.get(5)?,
                key_changed: row.get::<_, i32>(6)? != 0,
                added_at: row.get(7)?,
            })
        })?;

        let mut contacts = Vec::new();
        for row in rows {
            contacts.push(row?);
        }
        Ok(contacts)
    }

    pub fn get_contact(&self, user_id: &str) -> Result<Option<ContactModel>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT user_id, username, public_key, ed25519_pk, trust_state, fingerprint, key_changed, added_at
             FROM contacts WHERE user_id = ?1"
        )?;

        let mut rows = stmt.query_map(params![user_id], |row| {
            Ok(ContactModel {
                user_id: row.get(0)?,
                username: row.get(1)?,
                public_key: row.get(2)?,
                ed25519_pk: row.get(3)?,
                trust_state: row.get(4)?,
                fingerprint: row.get(5)?,
                key_changed: row.get::<_, i32>(6)? != 0,
                added_at: row.get(7)?,
            })
        })?;

        match rows.next() {
            Some(Ok(contact)) => Ok(Some(contact)),
            Some(Err(e)) => Err(DbError::SqliteError(e)),
            None => Ok(None),
        }
    }

    pub fn delete_contact(&self, user_id: &str) -> Result<(), DbError> {
        let rows_changed = self
            .conn
            .execute("DELETE FROM contacts WHERE user_id = ?1", params![user_id])?;
        if rows_changed == 0 {
            return Err(DbError::NotFound);
        }
        Ok(())
    }

    pub fn update_contact_trust(&self, user_id: &str, trust_state: &str) -> Result<(), DbError> {
        let rows_changed = self.conn.execute(
            "UPDATE contacts SET trust_state = ?1, key_changed = CASE WHEN ?1 = 'verified' THEN 0 ELSE key_changed END
             WHERE user_id = ?2",
            params![trust_state, user_id],
        )?;
        if rows_changed == 0 {
            return Err(DbError::NotFound);
        }
        Ok(())
    }

    // Storage stats

    pub fn get_storage_stats(&self) -> Result<StorageStats, DbError> {
        let conversation_count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM conversations", [], |r| r.get(0))?;
        let message_count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))?;
        let ciphertext_bytes: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(LENGTH(ciphertext)), 0) FROM messages",
            [],
            |r| r.get(0),
        )?;
        let contact_count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM contacts", [], |r| r.get(0))?;
        let device_count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM devices", [], |r| r.get(0))?;
        let attachment_count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM attachments", [], |r| r.get(0))?;
        let attachment_bytes: i64 =
            self.conn
                .query_row("SELECT COALESCE(SUM(size), 0) FROM attachments", [], |r| {
                    r.get(0)
                })?;

        Ok(StorageStats {
            conversation_count,
            message_count,
            ciphertext_bytes,
            contact_count,
            device_count,
            attachment_count,
            attachment_bytes,
        })
    }

    pub fn clear_expired_messages(&self, now: i64) -> Result<usize, DbError> {
        let deleted = self.conn.execute(
            "DELETE FROM messages WHERE expire_at IS NOT NULL AND expire_at < ?1",
            params![now],
        )?;
        Ok(deleted)
    }

    pub fn clear_unpinned_attachments(&self) -> Result<usize, DbError> {
        let deleted = self
            .conn
            .execute("DELETE FROM attachments WHERE pinned = 0", [])?;
        Ok(deleted)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StorageStats {
    pub conversation_count: i64,
    pub message_count: i64,
    pub ciphertext_bytes: i64,
    pub contact_count: i64,
    pub device_count: i64,
    pub attachment_count: i64,
    pub attachment_bytes: i64,
}
