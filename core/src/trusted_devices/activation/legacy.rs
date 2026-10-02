//! Current-root legacy cutover admission. Public configuration is authenticated
//! and protected with the existing task witness; private keys stay in Rust.
use super::{jobs, Enable, VerifiedMode};
use crate::trusted_devices::{self as t, witness::Witness, Checkpoint, DeviceTrustStore};
use liteseal_shared::{
    crypto::{self, KeyPair},
    trusted_device::Anchor,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use zeroize::Zeroizing;
fn bad() -> String {
    "旧协议切换范围或保护状态无法验证；已保留本机数据".into()
}
fn db(_: rusqlite::Error) -> String {
    "旧协议切换存储不可用".into()
}
#[derive(Default, Debug, Serialize, PartialEq, Eq)]
pub struct Pending {
    pub messages: u64,
    pub uploads: u64,
    pub scheduled: u64,
    pub operations: u64,
    pub reactions: u64,
    pub receipts: u64,
}
impl Pending {
    pub fn empty(&self) -> bool {
        self == &Self::default()
    }
}
pub(super) fn pending(conn: &Connection, user: &str, device: &str) -> Result<Pending, String> {
    let count = |query: &str| -> Result<u64, String> {
        conn.query_row(query, params![user, device], |r| r.get(0))
            .map_err(db)
    };
    Ok(Pending {
        messages:count("SELECT COUNT(*) FROM messages WHERE sender_id=?1 AND sender_device_id=?2 AND local_state NOT IN ('delivered','received')")?,
        uploads:count("SELECT COUNT(*) FROM attachment_transfers WHERE user_id=?1 AND direction='upload' AND ?2 IS NOT NULL")?,
        scheduled:count("SELECT COUNT(*) FROM scheduled_messages WHERE user_id=?1 AND device_id=?2 AND state!='submitted'")?,
        operations:count("SELECT COUNT(*) FROM local_message_operations WHERE user_id=?1 AND device_id=?2 AND status='pending'")?,
        reactions:count("SELECT COUNT(*) FROM local_reactions WHERE user_id=?1 AND seq=0 AND (json_extract(body,'$.device')=?2 OR COALESCE(json_type(body,'$.device'),'null')!='text')")?,
        receipts:count("SELECT COUNT(*) FROM local_read_receipts WHERE user_id=?1 AND seq=0 AND (json_extract(body,'$.device')=?2 OR COALESCE(json_type(body,'$.device'),'null')!='text')")?,
    })
}
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Admission {
    Legacy,
    Switching,
    V3,
}
pub(super) fn admission_in(
    conn: &Connection,
    anchor: &Anchor,
    keys: &KeyPair,
) -> Result<Admission, String> {
    if fact(conn, anchor, keys)?.is_some() {
        return Ok(Admission::V3);
    }
    jobs::legacy_state(conn, anchor, keys)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fact {
    domain: String,
    version: u8,
    scope: String,
    revision: u64,
    event: Enable,
}
fn scope(anchor: &Anchor) -> Result<String, String> {
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(&("LiteSeal/root-direct-mode/v1", anchor)).map_err(|_| bad())?,
    )))
}
fn fact(conn: &Connection, anchor: &Anchor, keys: &KeyPair) -> Result<Option<Fact>, String> {
    let scope = scope(anchor)?;
    let row: Option<(u64, String, bool, Vec<u8>)> = conn
        .query_row(
            "SELECT revision,kind,terminal,body FROM device_control_tasks WHERE scope=?1 AND id=?2",
            params![scope, anchor.root.device_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()
        .map_err(db)?;
    let Some((revision, kind, terminal, body)) = row else {
        return Ok(None);
    };
    if kind != "root_direct_mode" || !terminal || body.len() > 8192 || revision == 0 {
        return Err(bad());
    }
    let plain = Zeroizing::new(
        crypto::decrypt(&body, &keys.public_key, &keys.secret_key).map_err(|_| bad())?,
    );
    let fact: Fact = serde_json::from_slice(&plain).map_err(|_| bad())?;
    if fact.domain != "LiteSeal/observed-root-direct-mode/v1"
        || fact.version != 1
        || fact.scope != scope
        || fact.revision != revision
    {
        return Err(bad());
    }
    fact.event.verify_root(anchor).map_err(|_| bad())?;
    t::read_at(
        conn,
        anchor,
        &Checkpoint {
            revision: fact.event.revision,
            hash: fact.event.head.to_vec(),
        },
    )?;
    if anchor.root.encryption_key != keys.public_key || anchor.root.signing_key != keys.ed25519_pk {
        return Err(bad());
    }
    liteseal_shared::backup_crypto::validate_identity(
        &keys.public_key,
        &keys.secret_key,
        &keys.ed25519_pk,
        &keys.ed25519_sk,
    )
    .map_err(|_| bad())?;
    Ok(Some(fact))
}
pub struct Store {
    trust: DeviceTrustStore,
    anchor: Anchor,
}
impl Store {
    pub fn open(path: &Path, anchor: Anchor, witness: Witness) -> Result<Self, String> {
        let mut trust = DeviceTrustStore::open(path)?;
        trust.protect(witness)?;
        Ok(Self { trust, anchor })
    }
    pub fn admission(&mut self, keys: &KeyPair) -> Result<Admission, String> {
        self.trust
            .read_checked(|conn| admission_in(conn, &self.anchor, keys))
    }
    pub fn pending(&mut self) -> Result<Pending, String> {
        self.trust
            .read_checked(|conn| pending(conn, &self.anchor.account, &self.anchor.root.device_id))
    }
    /// Requires the SDK's private provenance marker, not a raw mode event.
    pub fn remember_enabled(
        &mut self,
        observed: VerifiedMode,
        keys: &KeyPair,
    ) -> Result<(), String> {
        if observed.query.origin != self.anchor.origin
            || observed.query.account != self.anchor.account
            || observed.query.device != self.anchor.root
            || observed.query.authorization.as_slice() != self.anchor.hash()
        {
            return Err(bad());
        }
        let event = observed.event.ok_or_else(bad)?;
        event.verify_root(&self.anchor).map_err(|_| bad())?;
        let scope = scope(&self.anchor)?;
        self.trust.write_checked(|conn|{
            t::read_at(conn,&self.anchor,&Checkpoint{revision:event.revision,hash:event.head.to_vec()})?;
            if let Some(existing)=fact(conn,&self.anchor,keys)?{
                if existing.event!=event{return Err(bad());}return Ok(());
            }
            let record=Fact{domain:"LiteSeal/observed-root-direct-mode/v1".into(),version:1,scope:scope.clone(),revision:1,event};
            if self.anchor.root.encryption_key!=keys.public_key||self.anchor.root.signing_key!=keys.ed25519_pk{return Err(bad());}
            liteseal_shared::backup_crypto::validate_identity(&keys.public_key,&keys.secret_key,&keys.ed25519_pk,&keys.ed25519_sk).map_err(|_|bad())?;
            let plain=Zeroizing::new(serde_json::to_vec(&record).map_err(|_|bad())?);
            let body=crypto::encrypt(&plain,&keys.public_key,&keys.secret_key).map_err(|_|bad())?;
            if body.len()>8192{return Err(bad());}
            conn.execute("INSERT INTO device_control_tasks(scope,id,revision,kind,terminal,body) VALUES(?1,?2,1,'root_direct_mode',1,?3)",params![scope,self.anchor.root.device_id,body]).map_err(db)?;
            Ok(())
        })
    }
}
/// Fresh legacy databases have no T23 schema or native record. If either is
/// present, authenticate the whole protected store before admitting a write.
pub fn admission(
    path: &Path,
    anchor: Anchor,
    keys: &KeyPair,
    witness: Witness,
) -> Result<Admission, String> {
    let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(db)?;
    let initialized:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name IN ('device_control_tasks','device_state_witness','trusted_device_anchors'))",[],|r|r.get(0)).map_err(db)?;
    drop(conn);
    if !initialized && !witness.has_record()? {
        return Ok(Admission::Legacy);
    }
    Store::open(path, anchor, witness)?.admission(keys)
}
