use rusqlite::{Connection, params};
use thiserror::Error;

use super::models::{MessageModel, ConversationModel, AttachmentModel, DeviceModel, ContactModel};

#[derive(Error, Debug)]
pub enum DbError {
    #[error("Database error: {0}")]
    SqliteError(#[from] rusqlite::Error),
    #[error("Not found")]
    NotFound,
}

pub struct MessageRepository {
    conn: Connection,
}

impl MessageRepository {
    pub fn new(db_path: &str) -> Result<Self, DbError> {
        let conn = Connection::open(db_path)?;

        conn.execute_batch("
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
                added_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_messages_conversation
            ON messages(conversation_id, timestamp);

            CREATE INDEX IF NOT EXISTS idx_attachments_message
            ON attachments(message_id);
        ")?;

        let _ = conn.execute("ALTER TABLE contacts ADD COLUMN ed25519_pk BLOB", []);

        Ok(Self { conn })
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
             FROM conversations WHERE id = ?1"
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
            "INSERT INTO messages (id, conversation_id, sender_id, sender_device_id,
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

    pub fn get_message(&self, id: &str) -> Result<Option<MessageModel>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, conversation_id, sender_id, sender_device_id,
             sender_seq, timestamp, message_type, local_state, expire_at,
             ciphertext, signature, prev_hash
             FROM messages WHERE id = ?1"
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
             ORDER BY timestamp DESC LIMIT ?2 OFFSET ?3"
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

    pub fn delete_message(&self, id: &str) -> Result<(), DbError> {
        let rows_changed = self.conn.execute(
            "DELETE FROM messages WHERE id = ?1",
            params![id],
        )?;
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
             FROM attachments WHERE id = ?1"
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

    pub fn get_attachments_by_message(&self, message_id: &str) -> Result<Vec<AttachmentModel>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, message_id, blob_id, encrypted_name, encrypted_mime,
             size, downloaded, pinned, expire_at, last_accessed_at
             FROM attachments WHERE message_id = ?1"
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
        let rows_changed = self.conn.execute(
            "DELETE FROM attachments WHERE id = ?1",
            params![id],
        )?;
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
             FROM devices WHERE id = ?1"
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
            "INSERT INTO contacts (user_id, username, public_key, ed25519_pk, added_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(user_id) DO UPDATE SET username = excluded.username, public_key = excluded.public_key, ed25519_pk = excluded.ed25519_pk",
            params![contact.user_id, contact.username, contact.public_key, contact.ed25519_pk, contact.added_at],
        )?;
        Ok(())
    }

    pub fn get_contacts(&self) -> Result<Vec<ContactModel>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT user_id, username, public_key, ed25519_pk, added_at FROM contacts ORDER BY added_at DESC"
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(ContactModel {
                user_id: row.get(0)?,
                username: row.get(1)?,
                public_key: row.get(2)?,
                ed25519_pk: row.get(3)?,
                added_at: row.get(4)?,
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
            "SELECT user_id, username, public_key, ed25519_pk, added_at FROM contacts WHERE user_id = ?1"
        )?;

        let mut rows = stmt.query_map(params![user_id], |row| {
            Ok(ContactModel {
                user_id: row.get(0)?,
                username: row.get(1)?,
                public_key: row.get(2)?,
                ed25519_pk: row.get(3)?,
                added_at: row.get(4)?,
            })
        })?;

        match rows.next() {
            Some(Ok(contact)) => Ok(Some(contact)),
            Some(Err(e)) => Err(DbError::SqliteError(e)),
            None => Ok(None),
        }
    }

    pub fn delete_contact(&self, user_id: &str) -> Result<(), DbError> {
        let rows_changed = self.conn.execute(
            "DELETE FROM contacts WHERE user_id = ?1",
            params![user_id],
        )?;
        if rows_changed == 0 {
            return Err(DbError::NotFound);
        }
        Ok(())
    }

    // Storage stats

    pub fn get_storage_stats(&self) -> Result<StorageStats, DbError> {
        let conversation_count: i64 = self.conn
            .query_row("SELECT COUNT(*) FROM conversations", [], |r| r.get(0))?;
        let message_count: i64 = self.conn
            .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))?;
        let ciphertext_bytes: i64 = self.conn
            .query_row("SELECT COALESCE(SUM(LENGTH(ciphertext)), 0) FROM messages", [], |r| r.get(0))?;
        let contact_count: i64 = self.conn
            .query_row("SELECT COUNT(*) FROM contacts", [], |r| r.get(0))?;
        let device_count: i64 = self.conn
            .query_row("SELECT COUNT(*) FROM devices", [], |r| r.get(0))?;
        let attachment_count: i64 = self.conn
            .query_row("SELECT COUNT(*) FROM attachments", [], |r| r.get(0))?;
        let attachment_bytes: i64 = self.conn
            .query_row("SELECT COALESCE(SUM(size), 0) FROM attachments", [], |r| r.get(0))?;

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
        let deleted = self.conn.execute(
            "DELETE FROM attachments WHERE pinned = 0",
            [],
        )?;
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
