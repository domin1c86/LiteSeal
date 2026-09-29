use super::*;
#[path = "collab_store.rs"]
mod collaboration;
pub use collaboration::{CollaborationView, PollView};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};

pub struct GroupStore {
    conn: Connection,
    scope: String,
    identity: GroupIdentity,
    notifications: Vec<GroupNotification>,
}
#[derive(Clone, Debug, Serialize)]
pub struct GroupNotification {
    pub group_id: String,
    pub message_id: String,
}
#[derive(Debug, Serialize)]
pub struct GroupStorageStats {
    pub visible_messages: i64,
    pub hidden_messages: i64,
    pub unread_messages: i64,
    pub pending_tasks: i64,
    pub logical_bytes: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupLocalMessage {
    pub id: String,
    pub sender_user_id: String,
    pub sender_device_id: String,
    pub sent_at: i64,
    pub text: String,
    pub status: String,
}
#[derive(Debug, Serialize)]
pub struct GroupHistoryPage {
    pub messages: Vec<GroupLocalMessage>,
    pub next_before: Option<i64>,
}
fn db(_: rusqlite::Error) -> String {
    "群本机存储失败，未确认收件".into()
}
fn invalid() -> String {
    "群签名、身份、版本或消息链无法验证".into()
}
fn json<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string(value).map_err(|_| invalid())
}
fn parse<T: serde::de::DeserializeOwned>(body: &str) -> Result<T, String> {
    serde_json::from_str(body).map_err(|_| invalid())
}
fn sealed(keys: &crypto::KeyPair, bytes: &[u8]) -> Result<Vec<u8>, String> {
    crypto::encrypt(bytes, &keys.public_key, &keys.secret_key).map_err(|_| invalid())
}
fn opened(keys: &crypto::KeyPair, bytes: &[u8]) -> Result<Vec<u8>, String> {
    crypto::decrypt(bytes, &keys.public_key, &keys.secret_key).map_err(|_| invalid())
}
fn seal_local(
    scope: &str,
    group: &str,
    message: &GroupLocalMessage,
    keys: &crypto::KeyPair,
) -> Result<Vec<u8>, String> {
    sealed(
        keys,
        json(&("LiteSeal/group-local/v1", scope, group, message))?.as_bytes(),
    )
}
fn queued(
    conn: &Connection,
    scope: &str,
    id: &str,
    identity: &GroupIdentity,
) -> Result<Option<Vec<GroupEnvelope>>, String> {
    let body:Option<String>=conn.query_row("SELECT batch FROM local_group_outbox WHERE scope=?1 AND group_id=?2 AND status='queued'",params![scope,id],|row|row.get(0)).optional().map_err(db)?;
    let Some(body) = body else { return Ok(None) };
    let batch: Vec<GroupEnvelope> = parse(&body)?;
    let first = batch.first().ok_or_else(invalid)?;
    if first.group_id != id
        || first.sender_user_id != identity.user_id
        || first.sender_device_id != identity.device_id
    {
        return Err(invalid());
    }
    let historical = state(conn, scope, id, Some(first.epoch))?;
    if historical
        .member(&identity.user_id)
        .is_none_or(|member| member.identity != *identity)
    {
        return Err(invalid());
    }
    validate_batch(&historical, &batch).map_err(|_| invalid())?;
    Ok(Some(batch))
}
fn state(
    conn: &Connection,
    scope: &str,
    id: &str,
    through: Option<u64>,
) -> Result<GroupState, String> {
    let root: String = conn
        .query_row(
            "SELECT owner FROM local_group_roots WHERE scope=?1 AND group_id=?2",
            params![scope, id],
            |row| row.get(0),
        )
        .map_err(db)?;
    let owner: GroupIdentity = parse(&root)?;
    let mut query=conn.prepare("SELECT body FROM local_group_events WHERE scope=?1 AND group_id=?2 AND epoch<=?3 ORDER BY epoch LIMIT 1001").map_err(db)?;
    let rows = query
        .query_map(params![scope, id, through.unwrap_or(1001)], |row| {
            row.get::<_, String>(0)
        })
        .map_err(db)?;
    let mut current = None;
    for body in rows {
        let event: GroupChange = parse(&body.map_err(db)?)?;
        current = Some(
            match current.as_ref() {
                None => pin_creation(&event, &owner),
                Some(previous) => apply_change(Some(previous), &event),
            }
            .map_err(|_| invalid())?,
        );
    }
    let current = current.ok_or_else(invalid)?;
    if current.group_id() != id || through.is_some_and(|epoch| current.epoch() != epoch) {
        return Err(invalid());
    }
    Ok(current)
}
fn head(
    conn: &Connection,
    scope: &str,
    group: &str,
    direction: &str,
    sender: (&str, u64),
    recipient: (&str, u64),
) -> Result<Option<GroupChainHead>, String> {
    let body:Option<String>=conn.query_row("SELECT body FROM local_group_heads WHERE scope=?1 AND group_id=?2 AND direction=?3 AND sender_device=?4 AND sender_join=?5 AND recipient_device=?6 AND recipient_join=?7",params![scope,group,direction,sender.0,sender.1,recipient.0,recipient.1],|row|row.get(0)).optional().map_err(db)?;
    body.map(|body| parse(&body)).transpose()
}
fn save_head(
    tx: &Transaction<'_>,
    scope: &str,
    direction: &str,
    envelope: &GroupEnvelope,
) -> Result<(), String> {
    tx.execute("INSERT INTO local_group_heads(scope,group_id,direction,sender_device,sender_join,recipient_device,recipient_join,body) VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(scope,group_id,direction,sender_device,sender_join,recipient_device,recipient_join) DO UPDATE SET body=excluded.body",params![scope,envelope.group_id,direction,envelope.sender_device_id,envelope.sender_join_epoch,envelope.recipient_device_id,envelope.recipient_join_epoch,json(&GroupChainHead::from_verified(envelope))?]).map_err(db)?;
    Ok(())
}
impl GroupStore {
    pub fn open(path: &str, origin: &str, identity: GroupIdentity) -> Result<Self, String> {
        identity.validate().map_err(|_| invalid())?;
        let origin = api::canonical_origin(origin)?;
        let scope = hex::encode(sha2::Sha256::digest(
            json(&("LiteSeal/group-scope/v1", origin, &identity))?.as_bytes(),
        ));
        let conn = Connection::open(path).map_err(db)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(db)?;
        conn.execute_batch(SCHEMA).map_err(db)?;
        conn.execute_batch(collaboration::SCHEMA).map_err(db)?;
        Ok(Self {
            conn,
            scope,
            identity,
            notifications: Vec::new(),
        })
    }
    pub fn pin(&mut self, event: &GroupChange, owner: &GroupIdentity) -> Result<(), String> {
        pin_creation(event, owner).map_err(|_| invalid())?;
        let tx = self.conn.transaction().map_err(db)?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT owner FROM local_group_roots WHERE scope=?1 AND group_id=?2",
                params![self.scope, event.group_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)?;
        if let Some(existing) = existing {
            if existing != json(owner)? {
                return Err(invalid());
            }
        }
        tx.execute(
            "INSERT OR IGNORE INTO local_group_roots(scope,group_id,owner) VALUES(?1,?2,?3)",
            params![self.scope, event.group_id, json(owner)?],
        )
        .map_err(db)?;
        let body = json(event)?;
        let previous: Option<String> = tx
            .query_row(
                "SELECT body FROM local_group_events WHERE scope=?1 AND group_id=?2 AND epoch=1",
                params![self.scope, event.group_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)?;
        if previous.is_some_and(|previous| previous != body) {
            return Err(invalid());
        }
        tx.execute("INSERT OR IGNORE INTO local_group_events(scope,group_id,epoch,body) VALUES(?1,?2,1,?3)",params![self.scope,event.group_id,body]).map_err(db)?;
        tx.commit().map_err(db)
    }
    pub fn state(&self, id: &str) -> Result<GroupState, String> {
        state(&self.conn, &self.scope, id, None)
    }
    pub fn apply(&mut self, id: &str, events: &[GroupChange]) -> Result<GroupState, String> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db)?;
        let mut current = state(&tx, &self.scope, id, None)?;
        for event in events {
            if event.group_id != id || event.epoch > 1001 {
                return Err(invalid());
            }
            if event.epoch <= current.epoch() {
                let stored:String=tx.query_row("SELECT body FROM local_group_events WHERE scope=?1 AND group_id=?2 AND epoch=?3",params![self.scope,id,event.epoch],|row|row.get(0)).map_err(db)?;
                if stored != json(event)? {
                    return Err(invalid());
                }
                continue;
            }
            current = apply_change(Some(&current), event).map_err(|_| invalid())?;
            tx.execute(
                "INSERT INTO local_group_events(scope,group_id,epoch,body) VALUES(?1,?2,?3,?4)",
                params![self.scope, id, event.epoch, json(event)?],
            )
            .map_err(db)?;
        }
        if let Some(member) = current
            .member(&self.identity.user_id)
            .filter(|m| m.identity == self.identity && !current.closed())
        {
            tx.execute(
                "DELETE FROM local_group_ack WHERE scope=?1 AND group_id=?2 AND joined!=?3",
                params![self.scope, id, member.joined_epoch],
            )
            .map_err(db)?;
        } else {
            tx.execute(
                "DELETE FROM local_group_ack WHERE scope=?1 AND group_id=?2",
                params![self.scope, id],
            )
            .map_err(db)?;
        }
        tx.commit().map_err(db)?;
        Ok(current)
    }
    pub fn group_ids(&self) -> Result<Vec<String>, String> {
        let mut q = self
            .conn
            .prepare("SELECT group_id FROM local_group_roots WHERE scope=?1 ORDER BY group_id")
            .map_err(db)?;
        let rows = q
            .query_map([&self.scope], |row| row.get(0))
            .map_err(db)?
            .collect::<Result<_, _>>()
            .map_err(db);
        rows
    }
    pub fn queued(&self, id: &str) -> Result<Option<Vec<GroupEnvelope>>, String> {
        queued(&self.conn, &self.scope, id, &self.identity)
    }
    pub fn seal_text(
        &mut self,
        id: &str,
        text: &str,
        keys: &crypto::KeyPair,
    ) -> Result<String, String> {
        check_keys(&self.identity, keys)?;
        if text.trim().is_empty() || text.len() > MAX_GROUP_TEXT_BYTES {
            return Err("群文字不能为空或超过 4096 UTF-8 字节".into());
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db)?;
        if queued(&tx, &self.scope, id, &self.identity)?.is_some() {
            return Err("请先处理本群原发件任务，重试将复用原密文".into());
        }
        let current = state(&tx, &self.scope, id, None)?;
        let sender = current
            .member(&self.identity.user_id)
            .filter(|member| member.identity == self.identity)
            .ok_or_else(invalid)?;
        if current.closed() || current.members().len() < 2 {
            return Err("群已关闭或没有其他成员".into());
        }
        let message = uuid::Uuid::new_v4().to_string();
        let sent_at = chrono::Utc::now().timestamp_millis();
        let mut batch = Vec::new();
        for recipient in current
            .members()
            .iter()
            .filter(|member| member.identity.user_id != self.identity.user_id)
        {
            let previous = head(
                &tx,
                &self.scope,
                id,
                "send",
                (&self.identity.device_id, sender.joined_epoch),
                (&recipient.identity.device_id, recipient.joined_epoch),
            )?;
            let mut envelope = GroupEnvelope {
                version: 1,
                message_id: message.clone(),
                group_id: id.into(),
                epoch: current.epoch(),
                membership_hash: current.revision_hash().to_vec(),
                sender_user_id: self.identity.user_id.clone(),
                sender_device_id: self.identity.device_id.clone(),
                sender_join_epoch: sender.joined_epoch,
                recipient_user_id: recipient.identity.user_id.clone(),
                recipient_device_id: recipient.identity.device_id.clone(),
                recipient_join_epoch: recipient.joined_epoch,
                sender_seq: previous
                    .as_ref()
                    .map(|head| head.sender_seq.checked_add(1).ok_or_else(invalid))
                    .transpose()?
                    .unwrap_or(1),
                prev_hash: previous
                    .as_ref()
                    .map(|head| head.chain_hash.clone())
                    .unwrap_or_default(),
                sent_at,
                ciphertext: crypto::encrypt(
                    text.as_bytes(),
                    &recipient
                        .identity
                        .public_key
                        .as_slice()
                        .try_into()
                        .map_err(|_| invalid())?,
                    &keys.secret_key,
                )
                .map_err(|_| invalid())?,
                signature: Vec::new(),
            };
            envelope.signature =
                crypto::sign(&envelope.signing_bytes(), &keys.ed25519_sk).map_err(|_| invalid())?;
            validate_chain_head(&envelope, previous.as_ref()).map_err(|_| invalid())?;
            batch.push(envelope);
        }
        validate_batch(&current, &batch).map_err(|_| invalid())?;
        let local = GroupLocalMessage {
            id: message.clone(),
            sender_user_id: self.identity.user_id.clone(),
            sender_device_id: self.identity.device_id.clone(),
            sent_at,
            text: text.into(),
            status: "queued".into(),
        };
        tx.execute("INSERT INTO local_group_outbox(scope,group_id,message_id,batch,status) VALUES(?1,?2,?3,?4,'queued')",params![self.scope,id,message,json(&batch)?]).map_err(db)?;
        tx.execute("INSERT INTO local_group_messages(scope,group_id,message_id,body,status,sent_at,envelope) VALUES(?1,?2,?3,?4,'queued',?5,NULL)",params![self.scope,id,message,seal_local(&self.scope,id,&local,keys)?,sent_at]).map_err(db)?;
        tx.execute(
            "DELETE FROM local_group_drafts WHERE scope=?1 AND group_id=?2",
            params![self.scope, id],
        )
        .map_err(db)?;
        tx.commit().map_err(db)?;
        Ok(message)
    }
    pub fn accepted(&mut self, id: &str, receipt: &GroupMessageReceipt) -> Result<(), String> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db)?;
        let batch = queued(&tx, &self.scope, id, &self.identity)?.ok_or_else(invalid)?;
        if receipt.group_id != id
            || receipt.message_id != batch[0].message_id
            || receipt.recipients.len() != batch.len()
        {
            return Err(invalid());
        }
        let mut seen = std::collections::HashSet::new();
        for recipient in &receipt.recipients {
            if !["pending", "delivered", "removed"].contains(&recipient.status.as_str())
                || !seen.insert(&recipient.recipient_device_id)
                || !batch.iter().any(|e| {
                    e.recipient_user_id == recipient.recipient_user_id
                        && e.recipient_device_id == recipient.recipient_device_id
                        && e.recipient_join_epoch == recipient.recipient_join_epoch
                })
            {
                return Err(invalid());
            }
        }
        for envelope in &batch {
            let previous = head(
                &tx,
                &self.scope,
                id,
                "send",
                (&envelope.sender_device_id, envelope.sender_join_epoch),
                (&envelope.recipient_device_id, envelope.recipient_join_epoch),
            )?;
            validate_chain_head(envelope, previous.as_ref()).map_err(|_| invalid())?;
            save_head(&tx, &self.scope, "send", envelope)?;
        }
        tx.execute("UPDATE local_group_outbox SET status='accepted' WHERE scope=?1 AND group_id=?2 AND message_id=?3",params![self.scope,id,receipt.message_id]).map_err(db)?;
        tx.execute("UPDATE local_group_messages SET status='accepted' WHERE scope=?1 AND group_id=?2 AND message_id=?3",params![self.scope,id,receipt.message_id]).map_err(db)?;
        tx.commit().map_err(db)
    }
    /// Call only after an authenticated atomic server cancellation result.
    pub(super) fn cancel_unaccepted(&mut self, id: &str, expected: &str) -> Result<(), String> {
        let tx = self.conn.transaction().map_err(db)?;
        let message:Option<String>=tx.query_row("SELECT message_id FROM local_group_outbox WHERE scope=?1 AND group_id=?2 AND status='queued'",params![self.scope,id],|row|row.get(0)).optional().map_err(db)?;
        if let Some(message) = message {
            if message != expected {
                return Err(invalid());
            }
            tx.execute("UPDATE local_group_outbox SET status='cancelled' WHERE scope=?1 AND group_id=?2 AND message_id=?3",params![self.scope,id,message]).map_err(db)?;
            tx.execute("UPDATE local_group_messages SET status='cancelled' WHERE scope=?1 AND group_id=?2 AND message_id=?3",params![self.scope,id,message]).map_err(db)?;
        }
        tx.commit().map_err(db)
    }
    pub fn receive(
        &mut self,
        envelope: &GroupEnvelope,
        keys: &crypto::KeyPair,
    ) -> Result<bool, String> {
        check_keys(&self.identity, keys)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db)?;
        let current = state(&tx, &self.scope, &envelope.group_id, None)?;
        let local = current
            .member(&self.identity.user_id)
            .filter(|member| member.identity == self.identity)
            .ok_or_else(invalid)?;
        if current.closed()
            || local.joined_epoch != envelope.recipient_join_epoch
            || envelope.recipient_user_id != self.identity.user_id
            || envelope.recipient_device_id != self.identity.device_id
        {
            return Err(invalid());
        }
        let historical = state(&tx, &self.scope, &envelope.group_id, Some(envelope.epoch))?;
        validate_envelope(&historical, envelope).map_err(|_| invalid())?;
        let encoded = json(envelope)?;
        let existing:Option<Option<String>>=tx.query_row("SELECT envelope FROM local_group_messages WHERE scope=?1 AND group_id=?2 AND message_id=?3",params![self.scope,envelope.group_id,envelope.message_id],|row|row.get(0)).optional().map_err(db)?;
        let fresh = existing.is_none();
        if let Some(existing) = existing {
            if existing.as_deref() != Some(&encoded) {
                return Err(invalid());
            }
        } else {
            let previous = head(
                &tx,
                &self.scope,
                &envelope.group_id,
                "receive",
                (&envelope.sender_device_id, envelope.sender_join_epoch),
                (&envelope.recipient_device_id, envelope.recipient_join_epoch),
            )?;
            validate_chain_head(envelope, previous.as_ref()).map_err(|_| invalid())?;
            let sender = historical
                .member(&envelope.sender_user_id)
                .ok_or_else(invalid)?;
            let plain = crypto::decrypt(
                &envelope.ciphertext,
                &sender
                    .identity
                    .public_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| invalid())?,
                &keys.secret_key,
            )
            .map_err(|_| invalid())?;
            let text = String::from_utf8(plain).map_err(|_| invalid())?;
            if text.trim().is_empty() || text.len() > MAX_GROUP_TEXT_BYTES {
                return Err(invalid());
            }
            let local = GroupLocalMessage {
                id: envelope.message_id.clone(),
                sender_user_id: envelope.sender_user_id.clone(),
                sender_device_id: envelope.sender_device_id.clone(),
                sent_at: envelope.sent_at,
                text,
                status: "received".into(),
            };
            tx.execute("INSERT INTO local_group_messages(scope,group_id,message_id,body,status,sent_at,envelope) VALUES(?1,?2,?3,?4,'received',?5,?6)",params![self.scope,envelope.group_id,envelope.message_id,seal_local(&self.scope,&envelope.group_id,&local,keys)?,envelope.sent_at,encoded]).map_err(db)?;
            save_head(&tx, &self.scope, "receive", envelope)?;
        }
        tx.execute("INSERT OR IGNORE INTO local_group_ack(scope,group_id,joined,message_id) VALUES(?1,?2,?3,?4)",params![self.scope,envelope.group_id,envelope.recipient_join_epoch,envelope.message_id]).map_err(db)?;
        tx.commit().map_err(db)?;
        if fresh
            && envelope.sender_user_id != self.identity.user_id
            && !self.muted(&envelope.group_id)?
        {
            if self.notifications.len() >= 20000 {
                self.notifications.remove(0);
            }
            self.notifications.push(GroupNotification {
                group_id: envelope.group_id.clone(),
                message_id: envelope.message_id.clone(),
            });
        }
        Ok(fresh)
    }
    pub fn acknowledgements(&self, id: &str, joined: u64) -> Result<Vec<String>, String> {
        let mut q=self.conn.prepare("SELECT message_id FROM local_group_ack WHERE scope=?1 AND group_id=?2 AND joined=?3 ORDER BY message_id LIMIT 100").map_err(db)?;
        let rows = q
            .query_map(params![self.scope, id, joined], |row| row.get(0))
            .map_err(db)?
            .collect::<Result<_, _>>()
            .map_err(db);
        rows
    }
    pub fn acknowledged(&mut self, id: &str, joined: u64, ids: &[String]) -> Result<(), String> {
        let tx = self.conn.transaction().map_err(db)?;
        for message in ids {
            tx.execute("DELETE FROM local_group_ack WHERE scope=?1 AND group_id=?2 AND joined=?3 AND message_id=?4",params![self.scope,id,joined,message]).map_err(db)?;
        }
        tx.commit().map_err(db)
    }
    pub fn messages(
        &self,
        id: &str,
        keys: &crypto::KeyPair,
    ) -> Result<Vec<GroupLocalMessage>, String> {
        Ok(self.history(id, None, keys)?.messages)
    }
    pub fn clear_history(&mut self, id: &str) -> Result<usize, String> {
        self.state(id)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db)?;
        let count = tx.execute("INSERT OR IGNORE INTO local_group_hidden(scope,group_id,message_id) SELECT scope,group_id,message_id FROM local_group_messages m WHERE scope=?1 AND group_id=?2 AND status NOT IN ('queued','cancelled') AND NOT EXISTS(SELECT 1 FROM local_group_outbox o WHERE o.scope=m.scope AND o.group_id=m.group_id AND o.message_id=m.message_id AND o.status='queued')",params![self.scope,id]).map_err(db)?;
        tx.commit().map_err(db)?;
        self.notifications.retain(|item| item.group_id != id);
        Ok(count)
    }
    pub fn storage_stats(&self, id: &str) -> Result<GroupStorageStats, String> {
        self.state(id)?;
        // One read transaction keeps counts and byte totals consistent with concurrent connections.
        let tx = self.conn.unchecked_transaction().map_err(db)?;
        let (visible,hidden,unread) = tx.query_row("SELECT COALESCE(SUM(CASE WHEN h.message_id IS NULL THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN h.message_id IS NOT NULL THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN h.message_id IS NULL AND m.status='received' THEN 1 ELSE 0 END),0) FROM local_group_messages m LEFT JOIN local_group_hidden h ON h.scope=m.scope AND h.group_id=m.group_id AND h.message_id=m.message_id WHERE m.scope=?1 AND m.group_id=?2 AND m.status!='cancelled'",params![self.scope,id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(db)?;
        let pending = tx.query_row("SELECT (SELECT COUNT(*) FROM local_group_outbox WHERE scope=?1 AND group_id=?2 AND status='queued')+(SELECT COUNT(*) FROM local_collab_outbox WHERE scope=?1 AND group_id=?2 AND status IN ('queued','conflict'))",params![self.scope,id],|r|r.get(0)).map_err(db)?;
        // Logical payload bytes only: not SQLite page allocation or filesystem space.
        let mut logical_bytes = 0_i64;
        for (table, expression) in [
            ("local_group_roots", "length(CAST(owner AS BLOB))"),
            ("local_group_events", "length(CAST(body AS BLOB))"),
            ("local_group_heads", "length(CAST(body AS BLOB))"),
            (
                "local_group_messages",
                "length(body)+COALESCE(length(CAST(envelope AS BLOB)),0)",
            ),
            ("local_group_outbox", "length(CAST(batch AS BLOB))"),
            ("local_group_drafts", "length(body)"),
            ("local_group_ack", "length(CAST(message_id AS BLOB))"),
            ("local_group_hidden", "length(CAST(message_id AS BLOB))"),
            (
                "local_collab_log",
                "length(CAST(header AS BLOB))+COALESCE(length(content),0)",
            ),
            ("local_collab_outbox", "length(CAST(body AS BLOB))"),
            ("local_collab_ack", "length(CAST(id AS BLOB))"),
        ] {
            logical_bytes += tx.query_row(&format!("SELECT COALESCE(SUM({expression}),0) FROM {table} WHERE scope=?1 AND group_id=?2"),params![self.scope,id],|r|r.get::<_,i64>(0)).map_err(db)?;
        }
        tx.commit().map_err(db)?;
        Ok(GroupStorageStats {
            visible_messages: visible,
            hidden_messages: hidden,
            unread_messages: unread,
            pending_tasks: pending,
            logical_bytes,
        })
    }
    pub fn muted(&self, id: &str) -> Result<bool, String> {
        self.state(id)?;
        Ok(self
            .conn
            .query_row(
                "SELECT muted FROM local_group_preferences WHERE scope=?1 AND group_id=?2",
                params![self.scope, id],
                |r| r.get(0),
            )
            .optional()
            .map_err(db)?
            .unwrap_or(false))
    }
    pub fn set_muted(&mut self, id: &str, muted: bool) -> Result<(), String> {
        self.state(id)?;
        self.conn.execute("INSERT INTO local_group_preferences(scope,group_id,muted) VALUES(?1,?2,?3) ON CONFLICT(scope,group_id) DO UPDATE SET muted=excluded.muted", params![self.scope,id,muted]).map_err(db)?;
        if muted {
            self.notifications.retain(|item| item.group_id != id);
        }
        Ok(())
    }
    pub fn take_notifications(&mut self) -> Result<Vec<GroupNotification>, String> {
        let pending = std::mem::take(&mut self.notifications);
        let mut result = Vec::new();
        for item in pending {
            let state = self.state(&item.group_id)?;
            let visible: bool = self.conn.query_row("SELECT EXISTS(SELECT 1 FROM local_group_messages m WHERE scope=?1 AND group_id=?2 AND message_id=?3 AND status='received' AND NOT EXISTS(SELECT 1 FROM local_group_hidden h WHERE h.scope=m.scope AND h.group_id=m.group_id AND h.message_id=m.message_id))",params![self.scope,item.group_id,item.message_id],|r|r.get(0)).map_err(db)?;
            if visible
                && !self.muted(&item.group_id)?
                && !state.closed()
                && state
                    .member(&self.identity.user_id)
                    .is_some_and(|m| m.identity == self.identity)
            {
                result.push(item);
            }
        }
        Ok(result)
    }
    pub fn unread(&self, id: &str) -> Result<i64, String> {
        self.conn.query_row("SELECT COUNT(*) FROM local_group_messages m WHERE scope=?1 AND group_id=?2 AND status='received' AND NOT EXISTS(SELECT 1 FROM local_group_hidden h WHERE h.scope=m.scope AND h.group_id=m.group_id AND h.message_id=m.message_id)",params![self.scope,id],|row|row.get(0)).map_err(db)
    }
    pub fn mark_seen(&mut self, id: &str, ids: &[String]) -> Result<(), String> {
        if ids.len() > 100 {
            return Err(invalid());
        }
        let tx = self.conn.transaction().map_err(db)?;
        for message in ids {
            tx.execute("UPDATE local_group_messages AS m SET status='seen' WHERE scope=?1 AND group_id=?2 AND message_id=?3 AND status='received' AND NOT EXISTS(SELECT 1 FROM local_group_hidden h WHERE h.scope=m.scope AND h.group_id=m.group_id AND h.message_id=m.message_id)",params![self.scope,id,message]).map_err(db)?;
        }
        tx.commit().map_err(db)
    }
    pub fn save_draft(
        &mut self,
        id: &str,
        text: &str,
        keys: &crypto::KeyPair,
    ) -> Result<(), String> {
        check_keys(&self.identity, keys)?;
        self.state(id)?;
        if text.len() > MAX_GROUP_TEXT_BYTES {
            return Err("群草稿过长，请缩短文字".into());
        }
        let body = sealed(
            keys,
            json(&("LiteSeal/group-draft/v1", &self.scope, id, text))?.as_bytes(),
        )?;
        self.conn.execute("INSERT INTO local_group_drafts(scope,group_id,body) VALUES(?1,?2,?3) ON CONFLICT(scope,group_id) DO UPDATE SET body=excluded.body",params![self.scope,id,body]).map_err(db)?;
        Ok(())
    }
    pub fn draft(&self, id: &str, keys: &crypto::KeyPair) -> Result<String, String> {
        check_keys(&self.identity, keys)?;
        let body: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT body FROM local_group_drafts WHERE scope=?1 AND group_id=?2",
                params![self.scope, id],
                |r| r.get(0),
            )
            .optional()
            .map_err(db)?;
        let Some(body) = body else {
            return Ok(String::new());
        };
        let (domain, scope, group, text): (String, String, String, String) =
            serde_json::from_slice(&opened(keys, &body)?).map_err(|_| invalid())?;
        if domain != "LiteSeal/group-draft/v1" || scope != self.scope || group != id {
            return Err(invalid());
        }
        Ok(text)
    }
    pub fn history(
        &self,
        id: &str,
        before: Option<i64>,
        keys: &crypto::KeyPair,
    ) -> Result<GroupHistoryPage, String> {
        check_keys(&self.identity, keys)?;
        if before.is_some_and(|value| value < 1) {
            return Err(invalid());
        }
        let mut q=self.conn.prepare("SELECT body,status,message_id,rowid FROM local_group_messages m WHERE scope=?1 AND group_id=?2 AND status!='cancelled' AND NOT EXISTS(SELECT 1 FROM local_group_hidden h WHERE h.scope=m.scope AND h.group_id=m.group_id AND h.message_id=m.message_id) AND (?3 IS NULL OR rowid<?3) ORDER BY rowid DESC LIMIT 101").map_err(db)?;
        let rows = q
            .query_map(params![self.scope, id, before], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(db)?;
        let mut result = Vec::new();
        let mut oldest = None;
        let mut more = false;
        for row in rows {
            if result.len() == 100 {
                more = true;
                break;
            }
            let (body, status, message_id, row_id) = row.map_err(db)?;
            let (domain, scope, group, mut message): (String, String, String, GroupLocalMessage) =
                serde_json::from_slice(&opened(keys, &body)?).map_err(|_| invalid())?;
            if domain != "LiteSeal/group-local/v1"
                || scope != self.scope
                || group != id
                || message.id != message_id
            {
                return Err(invalid());
            }
            message.status = status;
            result.push(message);
            oldest = Some(row_id);
        }
        result.reverse();
        Ok(GroupHistoryPage {
            messages: result,
            next_before: if more { oldest } else { None },
        })
    }
}
const SCHEMA:&str="
CREATE TABLE IF NOT EXISTS local_group_hidden(scope TEXT NOT NULL,group_id TEXT NOT NULL,message_id TEXT NOT NULL,PRIMARY KEY(scope,group_id,message_id));
CREATE TABLE IF NOT EXISTS local_group_preferences(scope TEXT NOT NULL,group_id TEXT NOT NULL,muted INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(scope,group_id));
CREATE TABLE IF NOT EXISTS local_group_roots(scope TEXT NOT NULL,group_id TEXT NOT NULL,owner TEXT NOT NULL,PRIMARY KEY(scope,group_id));
CREATE TABLE IF NOT EXISTS local_group_events(scope TEXT NOT NULL,group_id TEXT NOT NULL,epoch INTEGER NOT NULL,body TEXT NOT NULL,PRIMARY KEY(scope,group_id,epoch));
CREATE TABLE IF NOT EXISTS local_group_heads(scope TEXT NOT NULL,group_id TEXT NOT NULL,direction TEXT NOT NULL,sender_device TEXT NOT NULL,sender_join INTEGER NOT NULL,recipient_device TEXT NOT NULL,recipient_join INTEGER NOT NULL,body TEXT NOT NULL,PRIMARY KEY(scope,group_id,direction,sender_device,sender_join,recipient_device,recipient_join));
CREATE TABLE IF NOT EXISTS local_group_messages(scope TEXT NOT NULL,group_id TEXT NOT NULL,message_id TEXT NOT NULL,body BLOB NOT NULL,status TEXT NOT NULL,sent_at INTEGER NOT NULL,envelope TEXT,PRIMARY KEY(scope,group_id,message_id));
CREATE INDEX IF NOT EXISTS local_group_history ON local_group_messages(scope,group_id,sent_at);
CREATE TABLE IF NOT EXISTS local_group_outbox(scope TEXT NOT NULL,group_id TEXT NOT NULL,message_id TEXT NOT NULL,batch TEXT NOT NULL,status TEXT NOT NULL,PRIMARY KEY(scope,group_id,message_id));
CREATE UNIQUE INDEX IF NOT EXISTS local_group_pending ON local_group_outbox(scope,group_id) WHERE status='queued';
CREATE TABLE IF NOT EXISTS local_group_ack(scope TEXT NOT NULL,group_id TEXT NOT NULL,joined INTEGER NOT NULL,message_id TEXT NOT NULL,PRIMARY KEY(scope,group_id,joined,message_id));
CREATE TABLE IF NOT EXISTS local_group_drafts(scope TEXT NOT NULL,group_id TEXT NOT NULL,body BLOB NOT NULL,PRIMARY KEY(scope,group_id));
";
