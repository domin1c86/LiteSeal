use super::{MessageRequest, Peer};
use crate::{
    chat::canonical_conversation_id,
    client::DisplayMessage,
    secret_store::{protect_local, unprotect_local},
};
use liteseal_shared::{
    crypto,
    protocol::{AckOutcome, SignedEnvelopeV2, PROTOCOL_V2},
};
use rusqlite::{params, Connection, OptionalExtension};

type Result<T> = std::result::Result<T, String>;
fn error(e: impl std::fmt::Display) -> String {
    e.to_string()
}

pub struct Store {
    conn: Connection,
}

#[derive(Clone)]
pub struct Outgoing {
    pub id: String,
    pub recipient: String,
    pub body: Vec<u8>,
    pub envelope: Option<SignedEnvelopeV2>,
    pub state: String,
}

impl Store {
    pub fn open(path: &str) -> Result<Self> {
        let mut conn = Connection::open(path).map_err(error)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(error)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;",
        )
        .map_err(error)?;
        let tx = conn.transaction().map_err(error)?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS beta_schema(version INTEGER PRIMARY KEY);")
            .map_err(error)?;
        let version: i64 = tx
            .query_row(
                "SELECT COALESCE(MAX(version),0) FROM beta_schema",
                [],
                |r| r.get(0),
            )
            .map_err(error)?;
        if version > 1 {
            return Err("Database was created by a newer beta".into());
        }
        if version == 0 {
            tx.execute_batch(SCHEMA).map_err(error)?;
        }
        tx.commit().map_err(error)?;
        Ok(Self { conn })
    }

    pub fn peer(&self, id: &str) -> Result<Option<Peer>> {
        self.conn.query_row("SELECT user_id, username, device_id, public_key, signing_key, fingerprint, accepted, verified, blocked, key_changed FROM peers WHERE user_id=?1", [id], read_peer).optional().map_err(error)
    }

    /// A discovery can fill an empty pin, never replace an existing identity.
    pub fn discover(&self, peer: &Peer) -> Result<()> {
        if let Some(old) = self.peer(&peer.user_id)? {
            if !old.device_id.is_empty()
                && (old.device_id != peer.device_id
                    || old.public_key != peer.public_key
                    || old.ed25519_pk != peer.ed25519_pk)
            {
                self.conn
                    .execute(
                        "UPDATE peers SET key_changed=1 WHERE user_id=?1",
                        [&peer.user_id],
                    )
                    .map_err(error)?;
                return Err("Contact identity changed; beta replacement is disabled".into());
            }
        }
        if peer.public_key.len() != 32 || peer.ed25519_pk.len() != 32 || peer.device_id.is_empty() {
            return Err("Invalid device identity".into());
        }
        self.conn.execute("INSERT INTO peers(user_id,username,device_id,public_key,signing_key,fingerprint) VALUES (?1,?2,?3,?4,?5,?6) ON CONFLICT(user_id) DO UPDATE SET username=excluded.username,device_id=excluded.device_id,public_key=excluded.public_key,signing_key=excluded.signing_key,fingerprint=excluded.fingerprint",
            params![peer.user_id,peer.username,peer.device_id,peer.public_key,peer.ed25519_pk,peer.fingerprint]).map_err(error)?;
        Ok(())
    }

    pub fn accept(&self, id: &str, fingerprint: &str, verified: bool) -> Result<()> {
        let peer = self.peer(id)?.ok_or("Contact identity is not available")?;
        if peer.key_changed
            || peer.device_id.is_empty()
            || peer.fingerprint != fingerprint
            || peer.blocked
        {
            return Err("Verify the current device fingerprint first".into());
        }
        self.conn
            .execute(
                "UPDATE peers SET accepted=1,verified=?2 WHERE user_id=?1",
                params![id, verified],
            )
            .map_err(error)?;
        Ok(())
    }

    pub fn block(&self, id: &str, blocked: bool) -> Result<()> {
        self.conn
            .execute(
                "UPDATE peers SET blocked=?2,accepted=0,verified=0 WHERE user_id=?1",
                params![id, blocked],
            )
            .map_err(error)?;
        Ok(())
    }

    pub fn contacts(&self) -> Result<Vec<Peer>> {
        let mut query = self.conn.prepare("SELECT user_id,username,device_id,public_key,signing_key,fingerprint,accepted,verified,blocked,key_changed FROM peers WHERE accepted=1 OR blocked=1 ORDER BY username").map_err(error)?;
        let rows = query.query_map([], read_peer).map_err(error)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(error)
    }

    pub fn requests(&self) -> Result<Vec<MessageRequest>> {
        let mut query = self.conn.prepare("SELECT p.user_id,p.username,p.device_id,p.public_key,p.signing_key,p.fingerprint,p.accepted,p.verified,p.blocked,p.key_changed,COUNT(i.id),MIN(i.sent_at),MAX(i.sent_at) FROM peers p JOIN inbox i ON i.sender_id=p.user_id WHERE p.accepted=0 AND p.blocked=0 AND i.state='waiting' GROUP BY p.user_id ORDER BY MAX(i.sent_at) DESC").map_err(error)?;
        let rows = query
            .query_map([], |r| {
                Ok(MessageRequest {
                    peer: read_peer(r)?,
                    count: r.get(10)?,
                    first_at: r.get(11)?,
                    last_at: r.get(12)?,
                })
            })
            .map_err(error)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(error)
    }

    pub fn queue(&self, sender: &str, recipient: &str, plaintext: &str) -> Result<String> {
        if plaintext.trim().is_empty() || plaintext.len() > 8192 {
            return Err("Text must contain 1–8192 bytes".into());
        }
        let peer = self
            .peer(recipient)?
            .ok_or("Add and verify this contact first")?;
        if !peer.accepted || !peer.verified || peer.blocked || peer.key_changed {
            return Err("Verify the contact before sending".into());
        }
        let body = protect_local(plaintext.as_bytes())?;
        let tx = self.conn.unchecked_transaction().map_err(error)?;
        let (count,bytes):(i64,i64)=tx.query_row("SELECT COUNT(*),COALESCE(SUM(length(body)),0) FROM outbox WHERE state NOT IN ('delivered','rejected')",[],|r|Ok((r.get(0)?,r.get(1)?))).map_err(error)?;
        if count >= 1000 || bytes + body.len() as i64 > 10 * 1024 * 1024 {
            return Err("Local send queue is full".into());
        }
        let id = uuid::Uuid::new_v4().to_string();
        tx.execute("INSERT INTO outbox(id,recipient,conversation_id,body,created_at,state) VALUES (?1,?2,?3,?4,?5,'queued')",params![id,recipient,canonical_conversation_id(sender,recipient),body,chrono::Utc::now().timestamp_millis()]).map_err(error)?;
        tx.commit().map_err(error)?;
        Ok(id)
    }

    pub fn ready(&self) -> Result<Vec<Outgoing>> {
        let mut query=self.conn.prepare("SELECT o.id,o.recipient,o.body,o.envelope,o.state FROM outbox o WHERE o.state IN ('queued','sending','retry_wait') AND NOT EXISTS(SELECT 1 FROM outbox prev WHERE prev.conversation_id=o.conversation_id AND prev.rowid<o.rowid AND prev.state NOT IN ('stored','delivered','rejected')) ORDER BY o.rowid LIMIT 16").map_err(error)?;
        let rows = query
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })
            .map_err(error)?;
        rows.map(|row| {
            let (id, recipient, body, json, state) = row.map_err(error)?;
            Ok(Outgoing {
                id,
                recipient,
                body,
                state,
                envelope: json
                    .map(|v| serde_json::from_str(&v).map_err(error))
                    .transpose()?,
            })
        })
        .collect()
    }

    /// The caller holds the store mutex; sealing and sequence allocation commit together.
    pub fn seal(
        &self,
        id: &str,
        conversation: &str,
        device: &str,
        build: impl FnOnce(i64, Vec<u8>) -> Result<SignedEnvelopeV2>,
    ) -> Result<SignedEnvelopeV2> {
        let tx = self.conn.unchecked_transaction().map_err(error)?;
        let existing: Option<String> = tx
            .query_row("SELECT envelope FROM outbox WHERE id=?1", [id], |r| {
                r.get(0)
            })
            .map_err(error)?;
        if let Some(json) = existing {
            return serde_json::from_str(&json).map_err(error);
        }
        let (seq, hash) = head(&tx, "send", conversation, device)?;
        let envelope = build(seq + 1, hash)?;
        tx.execute(
            "UPDATE outbox SET envelope=?2,state='sending' WHERE id=?1",
            params![id, serde_json::to_string(&envelope).map_err(error)?],
        )
        .map_err(error)?;
        write_head(&tx, "send", &envelope)?;
        tx.commit().map_err(error)?;
        Ok(envelope)
    }

    pub fn status(&self, id: &str, state: &str, reason: &str) -> Result<()> {
        if ![
            "queued",
            "sending",
            "stored",
            "delivered",
            "retry_wait",
            "failed",
            "rejected",
        ]
        .contains(&state)
        {
            return Err("Invalid delivery status".into());
        }
        self.conn.execute("UPDATE outbox SET state=?2,error=?3 WHERE id=?1 AND state NOT IN ('delivered','rejected')",params![id,state,reason]).map_err(error)?;
        Ok(())
    }

    pub fn retry(&self, id: &str) -> Result<()> {
        self.conn.execute("UPDATE outbox SET state=CASE WHEN envelope IS NULL THEN 'queued' ELSE 'retry_wait' END,error='' WHERE id=?1 AND state IN ('failed','retry_wait')",[id]).map_err(error)?;
        Ok(())
    }

    pub fn unresolved(&self) -> Result<Vec<String>> {
        let mut q=self.conn.prepare("SELECT id FROM outbox WHERE envelope IS NOT NULL AND state NOT IN ('delivered','rejected') ORDER BY rowid").map_err(error)?;
        let result = q
            .query_map([], |r| r.get(0))
            .map_err(error)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(error);
        result
    }

    pub fn receive(&self, user: &str, device: &str, item: &SignedEnvelopeV2) -> Result<()> {
        if item.protocol_version != PROTOCOL_V2
            || item.recipient_user_id != user
            || item.recipient_device_id != device
            || item.conversation_id != canonical_conversation_id(user, &item.sender_user_id)
        {
            return Err("Incoming identity mismatch".into());
        }
        let digest = item.digest().map_err(error)?;
        let tx = self.conn.unchecked_transaction().map_err(error)?;
        let existing: Option<(Vec<u8>, String)> = tx
            .query_row(
                "SELECT digest,state FROM inbox WHERE id=?1",
                [&item.message_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(error)?;
        if let Some((previous, state)) = existing {
            if previous != digest {
                return Err("Conflicting message identity; original preserved".into());
            }
            if state != "waiting" {
                ack(
                    &tx,
                    &item.message_id,
                    if state == "received" {
                        AckOutcome::Processed
                    } else {
                        AckOutcome::Rejected
                    },
                )?;
            }
            tx.commit().map_err(error)?;
            return Ok(());
        }
        let json = serde_json::to_string(item).map_err(error)?;
        let (count, bytes): (i64, i64) = tx
            .query_row(
                "SELECT COUNT(*),COALESCE(SUM(size),0) FROM inbox WHERE state='waiting'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(error)?;
        let size = (item.ciphertext.len() + item.signature.len()) as i64;
        if count >= 1000 || bytes + size > 10 * 1024 * 1024 {
            return Err("Pending inbox is full; message remains on relay".into());
        }
        let is_new: bool = tx
            .query_row(
                "SELECT NOT EXISTS(SELECT 1 FROM peers WHERE user_id=?1)",
                [&item.sender_user_id],
                |r| r.get(0),
            )
            .map_err(error)?;
        if is_new {
            let requests: i64 = tx
                .query_row(
                    "SELECT COUNT(*) FROM peers WHERE accepted=0 AND blocked=0",
                    [],
                    |r| r.get(0),
                )
                .map_err(error)?;
            if requests >= 100 {
                return Err("Message request inbox is full".into());
            }
        }
        tx.execute(
            "INSERT OR IGNORE INTO peers(user_id,username) VALUES (?1,?1)",
            [&item.sender_user_id],
        )
        .map_err(error)?;
        tx.execute("INSERT INTO inbox(id,sender_id,device_id,conversation_id,sender_seq,sent_at,envelope,digest,size,state) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,'waiting')",params![item.message_id,item.sender_user_id,item.sender_device_id,item.conversation_id,item.sender_seq,item.sent_at,json,digest,size]).map_err(error)?;
        tx.commit().map_err(error)?;
        Ok(())
    }

    pub fn pending(&self) -> Result<Vec<SignedEnvelopeV2>> {
        let mut q=self.conn.prepare("SELECT envelope FROM inbox WHERE state='waiting' ORDER BY sender_id,device_id,sender_seq LIMIT 1000").map_err(error)?;
        let result = q
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(error)?
            .map(|row| serde_json::from_str(&row.map_err(error)?).map_err(error))
            .collect();
        result
    }

    pub fn process(&self, secret: &[u8; 32], item: &SignedEnvelopeV2) -> Result<bool> {
        let Some(peer) = self.peer(&item.sender_user_id)? else {
            return Ok(false);
        };
        if peer.device_id.is_empty() || peer.key_changed {
            return Ok(false);
        }
        if peer.device_id != item.sender_device_id {
            return Err("Sender device changed".into());
        }
        let signing: [u8; 32] = peer
            .ed25519_pk
            .clone()
            .try_into()
            .map_err(|_| "Invalid signing key")?;
        let valid = crypto::verify_with_public_key(
            &item.signing_bytes().map_err(error)?,
            &item.signature,
            &signing,
        )
        .map_err(error)?;
        if !valid {
            self.finish(item, None, "quarantined", "invalid_signature", false)?;
            return Ok(true);
        }
        if !peer.blocked && (!peer.accepted || !peer.verified) {
            return Ok(false);
        }
        let (seq, hash) = head(
            &self.conn,
            "receive",
            &item.conversation_id,
            &item.sender_device_id,
        )?;
        if item.sender_seq > seq + 1 {
            return Ok(false);
        }
        if item.sender_seq != seq + 1 || item.prev_hash != hash {
            self.finish(item, None, "quarantined", "chain_conflict", false)?;
            return Ok(true);
        }
        if peer.blocked {
            self.finish(item, None, "rejected", "blocked", true)?;
            return Ok(true);
        }
        let public: [u8; 32] = peer
            .public_key
            .try_into()
            .map_err(|_| "Invalid encryption key")?;
        let plaintext = crypto::decrypt(&item.ciphertext, &public, secret)
            .map_err(error)
            .and_then(|bytes| String::from_utf8(bytes).map_err(error));
        match plaintext {
            Ok(body) => self.finish(
                item,
                Some(protect_local(body.as_bytes())?),
                "received",
                "verified_v2",
                true,
            )?,
            Err(_) => self.finish(item, None, "quarantined", "decryption_failed", false)?,
        }
        Ok(true)
    }

    fn finish(
        &self,
        item: &SignedEnvelopeV2,
        body: Option<Vec<u8>>,
        state: &str,
        reason: &str,
        advance: bool,
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction().map_err(error)?;
        tx.execute("UPDATE inbox SET state=?2,body=?3,reason=?4,envelope=NULL,size=0 WHERE id=?1 AND state='waiting'",params![item.message_id,state,body,reason]).map_err(error)?;
        if advance {
            write_head(&tx, "receive", item)?;
        }
        ack(
            &tx,
            &item.message_id,
            if state == "received" {
                AckOutcome::Processed
            } else {
                AckOutcome::Rejected
            },
        )?;
        tx.commit().map_err(error)?;
        Ok(())
    }

    pub fn acks(&self) -> Result<Vec<(String, AckOutcome)>> {
        let mut q = self
            .conn
            .prepare("SELECT id,outcome FROM pending_acks LIMIT 128")
            .map_err(error)?;
        let result = q
            .query_map([], |r| {
                Ok((
                    r.get(0)?,
                    if r.get::<_, String>(1)? == "processed" {
                        AckOutcome::Processed
                    } else {
                        AckOutcome::Rejected
                    },
                ))
            })
            .map_err(error)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(error);
        result
    }
    pub fn ack_sent(&self, id: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM pending_acks WHERE id=?1", [id])
            .map_err(error)?;
        Ok(())
    }

    pub fn history(
        &self,
        user: &str,
        device: &str,
        recipient: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DisplayMessage>> {
        let conv = canonical_conversation_id(user, recipient);
        let mut result = Vec::new();
        let mut q = self
            .conn
            .prepare(
                "SELECT id,created_at,body,state,envelope FROM outbox WHERE conversation_id=?1",
            )
            .map_err(error)?;
        let rows = q
            .query_map([&conv], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, Option<String>>(4)?,
                ))
            })
            .map_err(error)?;
        for row in rows {
            let (id, timestamp, body, state, json) = row.map_err(error)?;
            let envelope: Option<SignedEnvelopeV2> = json
                .map(|j| serde_json::from_str(&j).map_err(error))
                .transpose()?;
            result.push(DisplayMessage {
                id,
                conversation_id: conv.clone(),
                sender_id: user.into(),
                sender_device_id: device.into(),
                sender_seq: envelope.map(|e| e.sender_seq).unwrap_or(0),
                timestamp,
                plaintext: decode(&body)?,
                local_state: state,
                protocol_version: 2,
                verification_state: "authored_v2".into(),
            });
        }
        let mut q=self.conn.prepare("SELECT id,sender_id,device_id,sender_seq,sent_at,body,state,reason FROM inbox WHERE conversation_id=?1 AND state IN ('received','quarantined')").map_err(error)?;
        let rows = q
            .query_map([&conv], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, Option<Vec<u8>>>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, String>(7)?,
                ))
            })
            .map_err(error)?;
        for row in rows {
            let (id, sender_id, sender_device_id, sender_seq, timestamp, body, state, reason) =
                row.map_err(error)?;
            result.push(DisplayMessage {
                id,
                conversation_id: conv.clone(),
                sender_id,
                sender_device_id,
                sender_seq,
                timestamp,
                plaintext: body.map(|b| decode(&b)).transpose()?.unwrap_or_default(),
                local_state: state,
                protocol_version: 2,
                verification_state: reason,
            });
        }
        result.sort_by(|a, b| (a.timestamp, &a.id).cmp(&(b.timestamp, &b.id)));
        let end = result.len().saturating_sub(offset.max(0) as usize);
        let start = end.saturating_sub(limit.clamp(1, 200) as usize);
        Ok(result.drain(start..end).collect())
    }
}

pub fn decode(bytes: &[u8]) -> Result<String> {
    String::from_utf8(unprotect_local(bytes)?).map_err(error)
}
fn read_peer(r: &rusqlite::Row<'_>) -> rusqlite::Result<Peer> {
    Ok(Peer {
        user_id: r.get(0)?,
        username: r.get(1)?,
        device_id: r.get(2)?,
        public_key: r.get(3)?,
        ed25519_pk: r.get(4)?,
        fingerprint: r.get(5)?,
        accepted: r.get(6)?,
        verified: r.get(7)?,
        blocked: r.get(8)?,
        key_changed: r.get(9)?,
    })
}
fn head(
    conn: &Connection,
    direction: &str,
    conversation: &str,
    device: &str,
) -> Result<(i64, Vec<u8>)> {
    Ok(conn.query_row("SELECT seq,hash FROM chain_heads WHERE direction=?1 AND conversation_id=?2 AND device_id=?3",params![direction,conversation,device],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(error)?.unwrap_or_default())
}
fn write_head(conn: &Connection, direction: &str, e: &SignedEnvelopeV2) -> Result<()> {
    conn.execute("INSERT INTO chain_heads(direction,conversation_id,device_id,seq,hash) VALUES (?1,?2,?3,?4,?5) ON CONFLICT(direction,conversation_id,device_id) DO UPDATE SET seq=excluded.seq,hash=excluded.hash",params![direction,e.conversation_id,e.sender_device_id,e.sender_seq,e.chain_hash()]).map_err(error)?;
    Ok(())
}
fn ack(conn: &Connection, id: &str, outcome: AckOutcome) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO pending_acks(id,outcome) VALUES (?1,?2)",
        params![
            id,
            if outcome == AckOutcome::Processed {
                "processed"
            } else {
                "rejected"
            }
        ],
    )
    .map_err(error)?;
    Ok(())
}

const SCHEMA:&str="
CREATE TABLE peers(user_id TEXT PRIMARY KEY,username TEXT NOT NULL,device_id TEXT NOT NULL DEFAULT '',public_key BLOB NOT NULL DEFAULT X'',signing_key BLOB NOT NULL DEFAULT X'',fingerprint TEXT NOT NULL DEFAULT '',accepted INTEGER NOT NULL DEFAULT 0,verified INTEGER NOT NULL DEFAULT 0,blocked INTEGER NOT NULL DEFAULT 0,key_changed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE outbox(id TEXT PRIMARY KEY,recipient TEXT NOT NULL,conversation_id TEXT NOT NULL,body BLOB NOT NULL,envelope TEXT,created_at INTEGER NOT NULL,state TEXT NOT NULL,error TEXT NOT NULL DEFAULT '');
CREATE INDEX outbox_chain ON outbox(conversation_id,state);
CREATE TABLE chain_heads(direction TEXT NOT NULL,conversation_id TEXT NOT NULL,device_id TEXT NOT NULL,seq INTEGER NOT NULL,hash BLOB NOT NULL,PRIMARY KEY(direction,conversation_id,device_id));
CREATE TABLE inbox(id TEXT PRIMARY KEY,sender_id TEXT NOT NULL,device_id TEXT NOT NULL,conversation_id TEXT NOT NULL,sender_seq INTEGER NOT NULL,sent_at INTEGER NOT NULL,envelope TEXT,digest BLOB NOT NULL,size INTEGER NOT NULL,state TEXT NOT NULL,body BLOB,reason TEXT NOT NULL DEFAULT '');
CREATE INDEX inbox_waiting ON inbox(sender_id,device_id,sender_seq) WHERE state='waiting';
CREATE TABLE pending_acks(id TEXT PRIMARY KEY,outcome TEXT NOT NULL);
INSERT INTO beta_schema(version) VALUES (1);
";
