//! Durable direct v3 state. All private bodies remain encrypted at rest.
use super::{witness::Witness, Checkpoint, DeviceTrustStore};
use liteseal_shared::{
    backup_crypto,
    crypto::{self, KeyPair},
    direct_message::{self as d, Ack, Batch, ChainHead, Header, Kind, MessageSpec},
    protocol::AckOutcome,
    trusted_device::{Anchor, DeviceIdentity, DeviceState},
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
pub mod api;
pub mod conversations;
pub mod coordinator;
pub mod drafts;
mod ordering;
const MAX_LOCAL: usize = 73768;
const MAX_TASKS: usize = 128;
pub(crate) fn require_backup_support(
    conn: &Connection,
    identity: &crate::keystore::KeystoreData,
) -> Result<(), String> {
    let exists=conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='direct_v3_records')",[],|r|r.get::<_,bool>(0)).map_err(db)?;
    if !exists {
        return Ok(());
    }
    let keys = crate::backup::identity_keys(identity)?;
    let origin = liteseal_shared::trusted_device::canonical_origin(&identity.server_url)
        .map_err(|_| invalid())?;
    let scope = Owner::new(&origin, &identity.user_id, &identity.device_id, &keys)?.scope();
    let task_table:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='device_control_tasks')",[],|r|r.get(0)).map_err(db)?;
    if task_table && conn.query_row("SELECT EXISTS(SELECT 1 FROM device_control_tasks WHERE scope=?1 AND kind='direct_v3_conversation')", [format!("conversation:{scope}")], |r| r.get::<_,bool>(0)).map_err(db)? {
        return Err("当前身份含单聊 v3 会话设置，本版备份尚不支持；未生成会遗漏设置的备份".into());
    }
    if task_table&&conn.query_row("SELECT EXISTS(SELECT 1 FROM device_control_tasks WHERE scope=?1 AND kind='direct_v3_draft')",[format!("draft:{scope}")],|r|r.get::<_,bool>(0)).map_err(db)?{
        return Err("当前身份含单聊 v3 草稿，本版备份尚不支持；未生成会遗漏草稿的备份".into());
    }
    if conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM direct_v3_records WHERE scope=?1)",
            [scope],
            |r| r.get::<_, bool>(0),
        )
        .map_err(db)?
    {
        return Err("当前身份含单聊 v3 历史，本版备份尚不支持；未生成会遗漏历史的备份".into());
    }
    Ok(())
}
fn invalid() -> String {
    "单聊 v3 身份、原批次或持久状态不匹配".into()
}
fn db(_: rusqlite::Error) -> String {
    "单聊 v3 本机存储不可用".into()
}
fn conflict() -> String {
    "单聊 v3 原任务或目录已变化；请查询原结果，不要重签".into()
}
#[derive(Clone)]
pub struct Owner {
    origin: String,
    account: String,
    device: DeviceIdentity,
}
impl Owner {
    pub fn new(origin: &str, account: &str, device: &str, keys: &KeyPair) -> Result<Self, String> {
        backup_crypto::validate_identity(
            &keys.public_key,
            &keys.secret_key,
            &keys.ed25519_pk,
            &keys.ed25519_sk,
        )?;
        let owner = Self {
            origin: origin.into(),
            account: account.into(),
            device: DeviceIdentity::from_keys(device.into(), keys),
        };
        Anchor {
            origin: owner.origin.clone(),
            account: owner.account.clone(),
            root: owner.device.clone(),
        }
        .validate()
        .map_err(|_| invalid())?;
        if account.contains(':') {
            return Err(invalid());
        }
        Ok(owner)
    }
    fn scope(&self) -> String {
        hex::encode(Sha256::digest(
            serde_json::to_vec(&(
                "LiteSeal/direct-local-scope/v3",
                &self.origin,
                &self.account,
                &self.device,
            ))
            .expect("public owner"),
        ))
    }
    fn keys(&self, keys: &KeyPair) -> Result<(), String> {
        if self.device != DeviceIdentity::from_keys(self.device.device_id.clone(), keys) {
            return Err(invalid());
        }
        backup_crypto::validate_identity(
            &keys.public_key,
            &keys.secret_key,
            &keys.ed25519_pk,
            &keys.ed25519_sk,
        )
    }
    fn member(&self, state: &DeviceState) -> Result<[u8; 32], String> {
        if state.anchor().origin != self.origin || state.anchor().account != self.account {
            return Err(invalid());
        }
        d::Directory::from_state(state)
            .members
            .into_iter()
            .find(|member| member.device == self.device)
            .map(|m| m.authorization_hash)
            .ok_or_else(invalid)
    }
    fn role(&self, batch: &Batch) -> Result<&'static str, String> {
        if batch.header.origin != self.origin {
            return Err(invalid());
        }
        if batch.header.sender == self.account {
            if batch.header.sender_device == self.device.device_id {
                Ok("authored")
            } else {
                Ok("own_replica")
            }
        } else if batch.header.peer == self.account {
            Ok("incoming")
        } else {
            Err(invalid())
        }
    }
}
pub struct Store {
    trust: DeviceTrustStore,
    owner: Owner,
}
pub struct Prepare<'a> {
    pub id: &'a str,
    pub peer: &'a str,
    pub sent_at: i64,
    pub kind: Kind,
    pub body: &'a [u8],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    Prepared,
    Publishing,
    Conflict,
    Accepted,
    Cancelled,
}
impl TaskState {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "publishing" => Ok(Self::Publishing),
            "conflict" => Ok(Self::Conflict),
            "accepted" => Ok(Self::Accepted),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(invalid()),
        }
    }
}
#[derive(Debug, Serialize)]
pub struct TaskView {
    pub id: String,
    pub revision: u64,
    pub state: TaskState,
    pub peer: String,
    pub epoch: String,
    pub digest: [u8; 32],
    pub cancel_requested: bool,
}
struct Task {
    id: String,
    revision: u64,
    state: TaskState,
    peer: String,
    epoch: String,
    wire: Vec<u8>,
    local: Vec<u8>,
    cancel_requested: bool,
}
struct Record {
    id: String,
    stream: String,
    sequence: i64,
    wire: Vec<u8>,
    digest: Vec<u8>,
    local: Vec<u8>,
    role: String,
    outcome: String,
    accepted_at: i64,
}
#[derive(Debug, Serialize)]
pub struct RecordView {
    pub cursor: i64,
    pub id: String,
    pub sender: String,
    pub sender_device: String,
    pub peer: String,
    pub role: String,
    pub kind: Kind,
    pub outcome: String,
    pub sent_at: i64,
    pub accepted_at: i64,
}
/// Metadata only, constructed by a bound authenticated transport, never by page
/// IPC. This is not cryptographic evidence of remote acceptance on its own.
pub struct Acceptance {
    id: String,
    digest: [u8; 32],
    accepted_at: i64,
}
impl Acceptance {
    pub fn from_authenticated_response(
        batch: &Batch,
        id: &str,
        digest: [u8; 32],
        accepted_at: i64,
    ) -> Result<Self, String> {
        if id != batch.header.id
            || digest != batch.digest().map_err(|_| invalid())?
            || !(1..=8_640_000_000_000_000).contains(&accepted_at)
        {
            return Err(invalid());
        }
        Ok(Self {
            id: id.into(),
            digest,
            accepted_at,
        })
    }
    fn matches(&self, batch: &Batch) -> Result<(), String> {
        if self.id != batch.header.id || self.digest != batch.digest().map_err(|_| invalid())? {
            return Err(invalid());
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Local {
    domain: String,
    scope: String,
    id: String,
    digest: [u8; 32],
    role: String,
    outcome: String,
    body: Vec<u8>,
    #[serde(default)]
    cancel_requested: bool,
}
fn seal(
    owner: &Owner,
    batch: &Batch,
    role: &str,
    outcome: &str,
    body: &[u8],
    keys: &KeyPair,
) -> Result<Vec<u8>, String> {
    seal_with_cancel(owner, batch, role, outcome, body, keys, false)
}
fn seal_with_cancel(
    owner: &Owner,
    batch: &Batch,
    role: &str,
    outcome: &str,
    body: &[u8],
    keys: &KeyPair,
    cancel_requested: bool,
) -> Result<Vec<u8>, String> {
    let local = Local {
        domain: "LiteSeal/direct-local-body/v3".into(),
        scope: owner.scope(),
        id: batch.header.id.clone(),
        digest: batch.digest().map_err(|_| invalid())?,
        role: role.into(),
        outcome: outcome.into(),
        body: body.to_vec(),
        cancel_requested,
    };
    let mut plain = Zeroizing::new(Vec::with_capacity(MAX_LOCAL));
    serde_json::to_writer(&mut *plain, &local).map_err(|_| invalid())?;
    if plain.len() > MAX_LOCAL - 40 {
        return Err(invalid());
    }
    crypto::encrypt(&plain, &keys.public_key, &keys.secret_key).map_err(|_| invalid())
}
fn unseal(
    owner: &Owner,
    batch: &Batch,
    role: &str,
    outcome: &str,
    bytes: &[u8],
    keys: &KeyPair,
) -> Result<Local, String> {
    if bytes.len() > MAX_LOCAL {
        return Err(invalid());
    }
    let plain = Zeroizing::new(
        crypto::decrypt(bytes, &keys.public_key, &keys.secret_key).map_err(|_| invalid())?,
    );
    let local: Local = serde_json::from_slice(&plain).map_err(|_| invalid())?;
    if local.domain != "LiteSeal/direct-local-body/v3"
        || local.scope != owner.scope()
        || local.id != batch.header.id
        || local.digest != batch.digest().map_err(|_| invalid())?
        || local.role != role
        || local.outcome != outcome
        || local.body.len() > d::MAX_BODY
    {
        return Err(invalid());
    }
    Ok(local)
}
fn evidence(conn: &Connection, batch: &Batch) -> Result<(DeviceState, DeviceState), String> {
    let sender = super::resolve(conn, &batch.header.origin, &batch.header.sender)?;
    let peer = super::resolve(conn, &batch.header.origin, &batch.header.peer)?;
    let sender = super::read_at(
        conn,
        &sender,
        &Checkpoint {
            revision: batch.header.sender_directory.revision,
            hash: batch.header.sender_directory.head.to_vec(),
        },
    )?;
    let peer = super::read_at(
        conn,
        &peer,
        &Checkpoint {
            revision: batch.header.peer_directory.revision,
            hash: batch.header.peer_directory.head.to_vec(),
        },
    )?;
    batch.verify(&sender, &peer).map_err(|_| invalid())?;
    Ok((sender, peer))
}
fn current(conn: &Connection, origin: &str, account: &str) -> Result<DeviceState, String> {
    let anchor = super::resolve(conn, origin, account)?;
    super::read(conn, &anchor, None)
}
fn head(
    conn: &Connection,
    scope: &str,
    stream: &str,
    epoch: [u8; 32],
) -> Result<Option<ChainHead>, String> {
    conn.query_row(
        "SELECT sequence,digest FROM direct_v3_heads WHERE scope=?1 AND stream=?2",
        params![scope, stream],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
    )
    .optional()
    .map_err(db)?
    .map(|(sequence, digest)| {
        Ok(ChainHead {
            epoch,
            sequence,
            digest: digest.try_into().map_err(|_| invalid())?,
        })
    })
    .transpose()
}
fn advance(conn: &Connection, scope: &str, stream: &str, batch: &Batch) -> Result<(), String> {
    conn.execute("INSERT INTO direct_v3_heads(scope,stream,sequence,digest) VALUES(?1,?2,?3,?4) ON CONFLICT(scope,stream) DO UPDATE SET sequence=excluded.sequence,digest=excluded.digest",params![scope,stream,batch.header.sequence,batch.digest().map_err(|_|invalid())?.as_slice()]).map_err(db)?;
    Ok(())
}
fn task(conn: &Connection, scope: &str, id: &str) -> Result<Option<Task>, String> {
    let row=conn.query_row("SELECT revision,state,peer,epoch,wire,local FROM direct_v3_tasks WHERE scope=?1 AND id=?2",params![scope,id],|r|Ok((r.get::<_,u64>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,Vec<u8>>(4)?,r.get::<_,Vec<u8>>(5)?))).optional().map_err(db)?;
    row.map(|(revision, state, peer, epoch, wire, local)| {
        Ok(Task {
            id: id.into(),
            revision,
            state: TaskState::parse(&state)?,
            peer,
            epoch,
            wire,
            local,
            cancel_requested: false,
        })
    })
    .transpose()
}
fn checked_task(
    conn: &Connection,
    owner: &Owner,
    mut row: Task,
    keys: &KeyPair,
) -> Result<(Task, Batch, Local), String> {
    let batch = Batch::from_wire(&row.wire).map_err(|_| invalid())?;
    evidence(conn, &batch)?;
    if row.revision > 1_000_000
        || row.id != batch.header.id
        || row.peer != batch.header.peer
        || row.epoch != hex::encode(batch.header.epoch().map_err(|_| invalid())?)
        || owner.role(&batch)? != "authored"
    {
        return Err(invalid());
    }
    let local = unseal(owner, &batch, "authored", "processed", &row.local, keys)?;
    row.cancel_requested = local.cancel_requested;
    Ok((row, batch, local))
}
fn record(conn: &Connection, scope: &str, id: &str) -> Result<Option<Record>, String> {
    conn.query_row("SELECT stream,sequence,wire,digest,local,role,outcome,accepted_at FROM direct_v3_records WHERE scope=?1 AND id=?2",params![scope,id],|r|Ok(Record{id:id.into(),stream:r.get(0)?,sequence:r.get(1)?,wire:r.get(2)?,digest:r.get(3)?,local:r.get(4)?,role:r.get(5)?,outcome:r.get(6)?,accepted_at:r.get(7)?})).optional().map_err(db)
}
fn checked_record(
    conn: &Connection,
    owner: &Owner,
    row: &Record,
    keys: &KeyPair,
) -> Result<(Batch, Local), String> {
    let batch = Batch::from_wire(&row.wire).map_err(|_| invalid())?;
    evidence(conn, &batch)?;
    let prefix = if row.role == "authored" { "out" } else { "in" };
    if owner.role(&batch)? != row.role
        || row.id != batch.header.id
        || row.digest != batch.digest().map_err(|_| invalid())?
        || row.sequence != batch.header.sequence
        || row.stream
            != format!(
                "{prefix}:{}",
                hex::encode(batch.header.epoch().map_err(|_| invalid())?)
            )
        || row.accepted_at <= 0
        || !matches!(row.outcome.as_str(), "processed" | "rejected")
    {
        return Err(invalid());
    }
    let local = unseal(owner, &batch, &row.role, &row.outcome, &row.local, keys)?;
    Ok((batch, local))
}
fn insert_record(
    conn: &Connection,
    scope: &str,
    batch: &Batch,
    stream: &str,
    local: &[u8],
    state: (&str, &str),
    accepted_at: i64,
) -> Result<(), String> {
    let (role, outcome) = state;
    conn.execute("INSERT INTO direct_v3_records(scope,id,stream,sequence,wire,digest,local,role,outcome,accepted_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",params![scope,batch.header.id,stream,batch.header.sequence,batch.to_wire().map_err(|_|invalid())?,batch.digest().map_err(|_|invalid())?.as_slice(),local,role,outcome,accepted_at]).map_err(db)?;
    ordering::insert(conn, scope, &batch.header.id, conn.last_insert_rowid())?;
    Ok(())
}
impl Store {
    pub fn open(path: &Path, owner: Owner, witness: Witness) -> Result<Self, String> {
        let mut trust = DeviceTrustStore::open(path)?;
        trust.protect(witness)?;
        trust.enable_direct_messages()?;
        trust.write_checked(|conn| ordering::initialize(conn, &owner.scope()))?;
        Ok(Self { trust, owner })
    }
    pub fn trust(&mut self) -> &mut DeviceTrustStore {
        &mut self.trust
    }
    pub(super) fn roots(&mut self, keys: &KeyPair) -> Result<Vec<Anchor>, String> {
        self.owner.keys(keys)?;
        self.trust.read_checked(|conn|{
            let mut query=conn.prepare("SELECT anchor FROM trusted_device_anchors WHERE origin=?1 ORDER BY account LIMIT 130").map_err(db)?;
            let rows=query.query_map([&self.owner.origin],|r|r.get::<_,Vec<u8>>(0)).map_err(db)?.collect::<rusqlite::Result<Vec<_>>>().map_err(db)?;
            if rows.len()>129{return Err("已核对根身份达到本机上限".into());}
            rows.into_iter().map(|bytes|{let anchor:Anchor=serde_json::from_slice(&bytes).map_err(|_|invalid())?;super::read(conn,&anchor,None)?;Ok(anchor)}).collect()
        })
    }
    pub fn prepare(&mut self, request: Prepare<'_>, keys: &KeyPair) -> Result<TaskView, String> {
        self.prepare_with_draft(request, None, keys)
    }
    pub fn draft(&mut self, peer: &str, keys: &KeyPair) -> Result<drafts::View, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.read_checked(|conn| {
            current(conn, &owner.origin, peer)?;
            drafts::load(conn, &owner, peer, keys)
        })
    }
    pub fn save_draft(
        &mut self,
        peer: &str,
        revision: u64,
        text: &str,
        keys: &KeyPair,
    ) -> Result<drafts::View, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.write_checked(|conn| {
            current(conn, &owner.origin, peer)?;
            drafts::put(conn, &owner, peer, revision, text, None, keys)
        })
    }
    pub fn prepare_with_draft(
        &mut self,
        request: Prepare<'_>,
        draft_revision: Option<u64>,
        keys: &KeyPair,
    ) -> Result<TaskView, String> {
        self.owner.keys(keys)?;
        if uuid::Uuid::parse_str(request.id)
            .ok()
            .is_none_or(|id| id.to_string() != request.id)
        {
            return Err(invalid());
        }
        let owner = self.owner.clone();
        let scope = owner.scope();
        self.trust.write_checked(|conn| {
            if let Some(expected)=draft_revision {
                if request.kind!=Kind::Text{return Err(invalid());}
                let draft=drafts::load(conn,&owner,request.peer,keys)?;
                if draft.revision!=expected {
                    if draft.revision==expected.checked_add(1).ok_or_else(invalid)? {
                        if let Some(id)=draft.prepared.as_ref(){
                            let row=task(conn,&scope,id)?.ok_or("原准备已整理，请保留原结果，不会重新创建")?;
                            let (row,batch,local)=checked_task(conn,&owner,row,keys)?;
                            if batch.header.peer==request.peer&&batch.header.kind==Kind::Text&&local.body==request.body{return view(&row,&batch);}
                        }
                    }
                    return Err("草稿修订已变化，原准备没有覆盖新正文".into());
                }
                if draft.text.as_bytes()!=request.body{return Err("请先保存当前正文，原草稿未改变".into());}
            }
            let sender=current(conn,&owner.origin,&owner.account)?;owner.member(&sender)?;let peer=current(conn,&owner.origin,request.peer)?;
            if let Some(row)=task(conn,&scope,request.id)? {
                let (row,batch,body)=checked_task(conn,&owner,row,keys)?;
                if row.cancel_requested||matches!(row.state,TaskState::Cancelled|TaskState::Conflict)||body.body!=request.body||batch.header.kind!=request.kind||batch.header.sent_at!=request.sent_at||batch.header.peer!=request.peer||batch.header.sender_directory!=d::Directory::from_state(&sender)||batch.header.peer_directory!=d::Directory::from_state(&peer) {return Err(conflict());}
                return view(&row,&batch);
            }
            if record(conn,&scope,request.id)?.is_some() {return Err("原消息已接受，不能重新准备同一编号".into());}
            if conn.query_row("SELECT COUNT(*) FROM direct_v3_tasks WHERE scope=?1",[&scope],|r|r.get::<_,usize>(0)).map_err(db)? >=MAX_TASKS {return Err("单聊 v3 待发记录数量达到上限".into());}
            let probe=Header::new(&sender,&peer,&owner.device.device_id,MessageSpec{id:request.id.into(),sequence:1,previous:vec![],sent_at:request.sent_at,kind:request.kind}).map_err(|_|invalid())?;
            let epoch=probe.epoch().map_err(|_|invalid())?;let stream=format!("out:{}",hex::encode(epoch));let previous=head(conn,&scope,&stream,epoch)?;
            let mut header=probe;
            if let Some(head)=&previous {header.sequence=head.sequence.checked_add(1).ok_or_else(invalid)?;header.previous=head.digest.to_vec();}
            let batch=Batch::make(header,&sender,&peer,keys,request.body).map_err(|_|invalid())?;batch.verify_next(previous.as_ref()).map_err(|_|invalid())?;
            let local=seal(&owner,&batch,"authored","processed",request.body,keys)?;let wire=batch.to_wire().map_err(|_|invalid())?;let epoch=hex::encode(epoch);
            conn.execute("INSERT INTO direct_v3_tasks(scope,id,revision,state,peer,epoch,wire,local) VALUES(?1,?2,0,'prepared',?3,?4,?5,?6)",params![scope,request.id,request.peer,epoch,wire,local]).map_err(|_|conflict())?;
            if let Some(expected)=draft_revision{drafts::put(conn,&owner,request.peer,expected,"",Some(request.id.into()),keys)?;}
            Ok(TaskView{id:request.id.into(),revision:0,state:TaskState::Prepared,peer:request.peer.into(),epoch,digest:batch.digest().map_err(|_|invalid())?,cancel_requested:false})
        })
    }
    pub fn original(&mut self, id: &str, keys: &KeyPair) -> Result<Batch, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        let scope = owner.scope();
        self.trust.read_checked(|conn| {
            let row = task(conn, &scope, id)?.ok_or_else(invalid)?;
            let (_, batch, _) = checked_task(conn, &owner, row, keys)?;
            Ok(batch)
        })
    }
    pub(super) fn task_view(&mut self, id: &str, keys: &KeyPair) -> Result<TaskView, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        let scope = owner.scope();
        self.trust.read_checked(|conn| {
            let (row, batch, _) = checked_task(
                conn,
                &owner,
                task(conn, &scope, id)?.ok_or_else(invalid)?,
                keys,
            )?;
            view(&row, &batch)
        })
    }
    /// A publishing task keeps the immutable wire. Persist cancellation before
    /// any remote fence request so reopening cannot accidentally resume send.
    pub fn request_cancel(&mut self, id: &str, keys: &KeyPair) -> Result<TaskView, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        let scope = owner.scope();
        self.trust.write_checked(|conn| {
            let (mut row, batch, local) = checked_task(
                conn,
                &owner,
                task(conn, &scope, id)?.ok_or_else(invalid)?,
                keys,
            )?;
            if matches!(row.state, TaskState::Accepted | TaskState::Cancelled)
                || row.cancel_requested
            {
                return view(&row, &batch);
            }
            if row.state != TaskState::Publishing {
                return transition(conn, &scope, row, &batch, "cancelled");
            }
            let encrypted = seal_with_cancel(
                &owner,
                &batch,
                "authored",
                "processed",
                &local.body,
                keys,
                true,
            )?;
            conn.execute(
                "UPDATE direct_v3_tasks SET local=?3 WHERE scope=?1 AND id=?2",
                params![scope, id, encrypted],
            )
            .map_err(db)?;
            row.cancel_requested = true;
            transition(conn, &scope, row, &batch, "publishing")
        })
    }
    pub(super) fn root(&mut self, account: &str, keys: &KeyPair) -> Result<Anchor, String> {
        self.owner.keys(keys)?;
        let realm = self.owner.origin.clone();
        self.trust
            .read_checked(|conn| super::resolve(conn, &realm, account))
    }
    pub(super) fn maybe_root(
        &mut self,
        account: &str,
        keys: &KeyPair,
    ) -> Result<Option<Anchor>, String> {
        self.owner.keys(keys)?;
        let realm = self.owner.origin.clone();
        self.trust.read_checked(|conn| {
            let exists:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM trusted_device_anchors WHERE origin=?1 AND account=?2)",params![realm,account],|r|r.get(0)).map_err(db)?;
            if exists {super::resolve(conn,&realm,account).map(Some)}else{Ok(None)}
        })
    }
    pub(super) fn is_current(&mut self, batch: &Batch, keys: &KeyPair) -> Result<bool, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.read_checked(|conn| {
            evidence(conn, batch)?;
            let sender = current(conn, &owner.origin, &batch.header.sender)?;
            let peer = current(conn, &owner.origin, &batch.header.peer)?;
            Ok(batch.verify(&sender, &peer).is_ok() && owner.member(&sender).is_ok())
        })
    }
    pub(super) fn validate_acks(
        &mut self,
        batch: &Batch,
        acks: &[Ack],
        keys: &KeyPair,
    ) -> Result<(), String> {
        self.owner.keys(keys)?;
        self.trust.read_checked(|conn| {
            let (s, p) = evidence(conn, batch)?;
            let mut unique = std::collections::HashSet::new();
            if acks.len() > d::MAX_TARGETS {
                return Err(invalid());
            }
            for ack in acks {
                if !unique.insert((&ack.account, &ack.device)) {
                    return Err(invalid());
                }
                ack.verify(batch, &s, &p).map_err(|_| invalid())?;
            }
            Ok(())
        })
    }
    pub(super) fn text(&mut self, id: &str, keys: &KeyPair) -> Result<String, String> {
        self.owner.keys(keys)?;
        let scope = self.owner.scope();
        let owner = self.owner.clone();
        self.trust.read_checked(|conn| {
            let row = record(conn, &scope, id)?.ok_or_else(invalid)?;
            let (batch, _) = checked_record(conn, &owner, &row, keys)?;
            if batch.header.kind != Kind::Text {
                return Err("此单聊类型尚未接入".into());
            }
            Ok(())
        })?;
        let body = Zeroizing::new(self.body(id, keys)?);
        String::from_utf8(body.to_vec()).map_err(|_| invalid())
    }
    pub fn tasks(&mut self, keys: &KeyPair) -> Result<Vec<TaskView>, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        let scope = owner.scope();
        self.trust.read_checked(|conn| {
            let mut query = conn
                .prepare("SELECT id FROM direct_v3_tasks WHERE scope=?1 ORDER BY rowid LIMIT 129")
                .map_err(db)?;
            let ids = query
                .query_map([&scope], |r| r.get::<_, String>(0))
                .map_err(db)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(db)?;
            if ids.len() > MAX_TASKS {
                return Err(invalid());
            }
            ids.into_iter()
                .map(|id| {
                    let (row, batch, _) = checked_task(
                        conn,
                        &owner,
                        task(conn, &scope, &id)?.ok_or_else(invalid)?,
                        keys,
                    )?;
                    view(&row, &batch)
                })
                .collect()
        })
    }
    /// Persist this transition before starting network I/O. Publishing cannot
    /// be abandoned on timeout; callers query or resend the immutable batch.
    pub fn begin_publish(
        &mut self,
        id: &str,
        revision: u64,
        keys: &KeyPair,
    ) -> Result<TaskView, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        let scope = owner.scope();
        self.trust.write_checked(|conn| {
            let (row, batch, _) = checked_task(
                conn,
                &owner,
                task(conn, &scope, id)?.ok_or_else(invalid)?,
                keys,
            )?;
            if row.revision != revision
                || !matches!(row.state, TaskState::Prepared | TaskState::Publishing)
            {
                return Err(conflict());
            }
            let sender = current(conn, &owner.origin, &owner.account)?;
            owner.member(&sender)?;
            let peer = current(conn, &owner.origin, &batch.header.peer)?;
            batch.verify(&sender, &peer).map_err(|_| conflict())?;
            if row.state == TaskState::Publishing {
                return view(&row, &batch);
            }
            transition(conn, &scope, row, &batch, "publishing")
        })
    }
    pub fn cancel_unpublished(
        &mut self,
        id: &str,
        revision: u64,
        keys: &KeyPair,
    ) -> Result<TaskView, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        let scope = owner.scope();
        self.trust.write_checked(|conn| {
            let (row, batch, _) = checked_task(
                conn,
                &owner,
                task(conn, &scope, id)?.ok_or_else(invalid)?,
                keys,
            )?;
            if row.revision != revision
                || !matches!(
                    row.state,
                    TaskState::Prepared | TaskState::Conflict | TaskState::Cancelled
                )
            {
                return Err("原批次发送结果尚未确认，不能只在本机取消".into());
            }
            if row.state == TaskState::Cancelled {
                return view(&row, &batch);
            }
            transition(conn, &scope, row, &batch, "cancelled")
        })
    }
    /// Call only after a bound authenticated server reply explicitly confirms
    /// no acceptance. A timeout or stale-directory observation is insufficient.
    pub fn confirm_unaccepted(
        &mut self,
        id: &str,
        digest: [u8; 32],
        keys: &KeyPair,
    ) -> Result<TaskView, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        let scope = owner.scope();
        self.trust.write_checked(|conn| {
            let (row, batch, _) = checked_task(
                conn,
                &owner,
                task(conn, &scope, id)?.ok_or_else(invalid)?,
                keys,
            )?;
            if batch.digest().map_err(|_| invalid())? != digest
                || !matches!(row.state, TaskState::Publishing | TaskState::Conflict)
            {
                return Err(conflict());
            }
            if row.state == TaskState::Conflict {
                return view(&row, &batch);
            }
            transition(conn, &scope, row, &batch, "conflict")
        })
    }
    pub fn confirm_accepted(
        &mut self,
        receipt: &Acceptance,
        keys: &KeyPair,
    ) -> Result<TaskView, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        let scope = owner.scope();
        self.trust.write_checked(|conn| {
            let (row, batch, _) = checked_task(
                conn,
                &owner,
                task(conn, &scope, &receipt.id)?.ok_or_else(invalid)?,
                keys,
            )?;
            receipt.matches(&batch)?;
            if row.state == TaskState::Accepted {
                let existing = record(conn, &scope, &receipt.id)?.ok_or_else(invalid)?;
                if existing.digest != receipt.digest || existing.accepted_at != receipt.accepted_at
                {
                    return Err(invalid());
                }
                return view(&row, &batch);
            }
            if row.state != TaskState::Publishing {
                return Err(conflict());
            }
            let stream = format!("out:{}", row.epoch);
            let prior = head(
                conn,
                &scope,
                &stream,
                batch.header.epoch().map_err(|_| invalid())?,
            )?;
            batch.verify_next(prior.as_ref()).map_err(|_| conflict())?;
            insert_record(
                conn,
                &scope,
                &batch,
                &stream,
                &row.local,
                ("authored", "processed"),
                receipt.accepted_at,
            )?;
            advance(conn, &scope, &stream, &batch)?;
            transition(conn, &scope, row, &batch, "accepted")
        })
    }
    /// Envelope authentication, original audience/current local eligibility and
    /// chain checks precede one atomic body/quarantine + head + ACK commit.
    pub fn receive(
        &mut self,
        batch: &Batch,
        receipt: &Acceptance,
        keys: &KeyPair,
    ) -> Result<AckOutcome, String> {
        self.owner.keys(keys)?;
        receipt.matches(batch)?;
        let owner = self.owner.clone();
        let scope = owner.scope();
        self.trust.write_checked(|conn| {
            let (sender, peer) = evidence(conn, batch)?;
            let role = owner.role(batch)?;
            if role == "authored" {
                return Err(invalid());
            }
            let current = current(conn, &owner.origin, &owner.account)?;
            let active = owner.member(&current)?;
            let original = if owner.account == batch.header.sender {
                &sender
            } else {
                &peer
            };
            if owner.member(original)? != active {
                return Err(invalid());
            }
            if let Some(row) = record(conn, &scope, &batch.header.id)? {
                checked_record(conn, &owner, &row, keys)?;
                if row.digest != receipt.digest || row.accepted_at != receipt.accepted_at {
                    return Err(invalid());
                }
                let updated = conn
                    .execute(
                        "UPDATE direct_v3_ack SET pending=1 WHERE scope=?1 AND id=?2 AND pending=0",
                        params![scope, batch.header.id],
                    )
                    .map_err(db)?;
                if updated == 0
                    && !conn
                        .query_row(
                            "SELECT EXISTS(SELECT 1 FROM direct_v3_ack WHERE scope=?1 AND id=?2)",
                            params![scope, batch.header.id],
                            |r| r.get::<_, bool>(0),
                        )
                        .map_err(db)?
                {
                    return Err(invalid());
                }
                return outcome(&row.outcome);
            }
            let epoch = batch.header.epoch().map_err(|_| invalid())?;
            let stream = format!("in:{}", hex::encode(epoch));
            batch
                .verify_next(head(conn, &scope, &stream, epoch)?.as_ref())
                .map_err(|_| conflict())?;
            let opened = batch.open(
                &sender,
                &peer,
                &owner.account,
                &owner.device.device_id,
                keys,
            );
            let (body, result) = match opened {
                Ok(body) => (Zeroizing::new(body), AckOutcome::Processed),
                Err(d::DirectError::Proof) => (Zeroizing::new(vec![]), AckOutcome::Rejected),
                Err(_) => return Err(invalid()),
            };
            let status = result_name(result);
            let local = seal(&owner, batch, role, status, &body, keys)?;
            let ack = Ack::make(
                batch,
                &sender,
                &peer,
                &owner.account,
                &owner.device.device_id,
                keys,
                result,
            )
            .map_err(|_| invalid())?;
            insert_record(
                conn,
                &scope,
                batch,
                &stream,
                &local,
                (role, status),
                receipt.accepted_at,
            )?;
            advance(conn, &scope, &stream, batch)?;
            conn.execute(
                "INSERT INTO direct_v3_ack(scope,id,wire,pending) VALUES(?1,?2,?3,1)",
                params![
                    scope,
                    batch.header.id,
                    ack.to_wire().map_err(|_| invalid())?
                ],
            )
            .map_err(db)?;
            Ok(result)
        })
    }
    pub fn pending_acks(&mut self, keys: &KeyPair) -> Result<Vec<Ack>, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        let scope = owner.scope();
        self.trust.read_checked(|conn| {
            let mut query=conn.prepare("SELECT id,wire FROM direct_v3_ack WHERE scope=?1 AND pending=1 ORDER BY rowid LIMIT 100").map_err(db)?;
            let rows=query.query_map([&scope],|r|Ok((r.get::<_,String>(0)?,r.get::<_,Vec<u8>>(1)?))).map_err(db)?.collect::<rusqlite::Result<Vec<_>>>().map_err(db)?;
            rows.into_iter().map(|(id,wire)|{let ack=Ack::from_wire(&wire).map_err(|_|invalid())?;let row=record(conn,&scope,&id)?.ok_or_else(invalid)?;let (batch,_)=checked_record(conn,&owner,&row,keys)?;let (sender,peer)=evidence(conn,&batch)?;ack.verify(&batch,&sender,&peer).map_err(|_|invalid())?;if ack.account!=owner.account||ack.device!=owner.device.device_id||ack.outcome!=outcome(&row.outcome)? {return Err(invalid());}Ok(ack)}).collect()
        })
    }
    pub fn confirm_ack(&mut self, ack: &Ack, keys: &KeyPair) -> Result<(), String> {
        self.owner.keys(keys)?;
        let scope = self.owner.scope();
        let wire = ack.to_wire().map_err(|_| invalid())?;
        self.trust.write_checked(|conn| {
            let existing: Vec<u8> = conn
                .query_row(
                    "SELECT wire FROM direct_v3_ack WHERE scope=?1 AND id=?2",
                    params![scope, ack.id],
                    |r| r.get(0),
                )
                .map_err(db)?;
            if existing != wire {
                return Err(invalid());
            }
            conn.execute(
                "UPDATE direct_v3_ack SET pending=0 WHERE scope=?1 AND id=?2 AND pending=1",
                params![scope, ack.id],
            )
            .map_err(db)?;
            Ok(())
        })
    }
    /// Accepted history remains the durable id/digest tombstone. Cancelled or
    /// unknown tasks retain their original packet and cannot be cleared here.
    pub fn clear_accepted_task(&mut self, id: &str, keys: &KeyPair) -> Result<(), String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        let scope = owner.scope();
        self.trust.write_checked(|conn| {
            let (row, batch, _) = checked_task(
                conn,
                &owner,
                task(conn, &scope, id)?.ok_or_else(invalid)?,
                keys,
            )?;
            if row.state != TaskState::Accepted {
                return Err(conflict());
            }
            let saved = record(conn, &scope, id)?.ok_or_else(invalid)?;
            checked_record(conn, &owner, &saved, keys)?;
            if saved.digest != batch.digest().map_err(|_| invalid())? {
                return Err(invalid());
            }
            conn.execute(
                "DELETE FROM direct_v3_tasks WHERE scope=?1 AND id=?2 AND state='accepted'",
                params![scope, id],
            )
            .map_err(db)?;
            Ok(())
        })
    }
    pub fn hide(&mut self, id: &str, keys: &KeyPair) -> Result<(), String> {
        self.owner.keys(keys)?;
        let scope = self.owner.scope();
        self.trust.write_checked(|conn| {
            if record(conn, &scope, id)?.is_none() {
                return Err(invalid());
            }
            conn.execute(
                "INSERT OR IGNORE INTO direct_v3_hidden(scope,id) VALUES(?1,?2)",
                params![scope, id],
            )
            .map_err(db)?;
            Ok(())
        })
    }
    pub fn history(
        &mut self,
        before: Option<i64>,
        limit: usize,
        keys: &KeyPair,
    ) -> Result<Vec<RecordView>, String> {
        self.history_peer(None, before, limit, keys)
    }
    pub fn history_peer(
        &mut self,
        peer: Option<&str>,
        before: Option<i64>,
        limit: usize,
        keys: &KeyPair,
    ) -> Result<Vec<RecordView>, String> {
        self.owner.keys(keys)?;
        if !(1..=100).contains(&limit) {
            return Err(invalid());
        }
        let owner = self.owner.clone();
        let scope = owner.scope();
        self.trust.read_checked(|conn| {
            if let Some(peer) = peer { current(conn, &owner.origin, peer)?; }
            ordering::check(conn, &scope)?;
            let mut query=conn.prepare("SELECT rowid,id FROM direct_v3_records r WHERE scope=?1 AND rowid<?2 AND (?4 IS NULL OR CASE WHEN json_extract(CAST(wire AS TEXT),'$.header.sender')=?5 THEN json_extract(CAST(wire AS TEXT),'$.header.peer') ELSE json_extract(CAST(wire AS TEXT),'$.header.sender') END=?4) AND NOT EXISTS(SELECT 1 FROM direct_v3_hidden h WHERE h.scope=r.scope AND h.id=r.id) ORDER BY rowid DESC LIMIT ?3").map_err(db)?;
            let rows=query.query_map(params![scope,before.unwrap_or(i64::MAX),limit,peer,owner.account],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?))).map_err(db)?.collect::<rusqlite::Result<Vec<_>>>().map_err(db)?;
            rows.into_iter().map(|(cursor,id)| {
                let row=record(conn,&scope,&id)?.ok_or_else(invalid)?;
                let (batch,_)=checked_record(conn,&owner,&row,keys)?;
                let other=if batch.header.sender==owner.account {batch.header.peer.clone()}else{batch.header.sender.clone()};
                Ok(RecordView{cursor,id:row.id,sender:batch.header.sender,sender_device:batch.header.sender_device,peer:other,role:row.role,kind:batch.header.kind,outcome:row.outcome,sent_at:batch.header.sent_at,accepted_at:row.accepted_at})
            }).collect()
        })
    }
    /// Rust business decoders only: attachment/voice bodies contain secret keys
    /// and must be filtered into public metadata before any renderer response.
    pub fn body(&mut self, id: &str, keys: &KeyPair) -> Result<Vec<u8>, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        let scope = owner.scope();
        self.trust.read_checked(|conn| {
            if conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM direct_v3_hidden WHERE scope=?1 AND id=?2)",
                    params![scope, id],
                    |r| r.get::<_, bool>(0),
                )
                .map_err(db)?
            {
                return Err("此消息已在本机隐藏".into());
            }
            let row = record(conn, &scope, id)?.ok_or_else(invalid)?;
            let (_, local) = checked_record(conn, &owner, &row, keys)?;
            if row.outcome != "processed" {
                return Err("此消息正文认证失败，已隔离".into());
            }
            Ok(local.body.clone())
        })
    }
}
fn result_name(result: AckOutcome) -> &'static str {
    match result {
        AckOutcome::Processed => "processed",
        AckOutcome::Rejected => "rejected",
    }
}
fn outcome(text: &str) -> Result<AckOutcome, String> {
    match text {
        "processed" => Ok(AckOutcome::Processed),
        "rejected" => Ok(AckOutcome::Rejected),
        _ => Err(invalid()),
    }
}
fn view(row: &Task, batch: &Batch) -> Result<TaskView, String> {
    Ok(TaskView {
        id: row.id.clone(),
        revision: row.revision,
        state: row.state,
        peer: row.peer.clone(),
        epoch: row.epoch.clone(),
        digest: batch.digest().map_err(|_| invalid())?,
        cancel_requested: row.cancel_requested,
    })
}
fn transition(
    conn: &Connection,
    scope: &str,
    row: Task,
    batch: &Batch,
    state: &str,
) -> Result<TaskView, String> {
    let revision = row
        .revision
        .checked_add(1)
        .filter(|n| *n <= 1_000_000)
        .ok_or_else(invalid)?;
    let changed=conn.execute("UPDATE direct_v3_tasks SET revision=?3,state=?4 WHERE scope=?1 AND id=?2 AND revision=?5",params![scope,row.id,revision,state,row.revision]).map_err(db)?;
    if changed != 1 {
        return Err(conflict());
    }
    view(
        &Task {
            revision,
            state: TaskState::parse(state)?,
            ..row
        },
        batch,
    )
}
pub(super) const SCHEMA:&str="
CREATE TABLE direct_v3_tasks (
 scope TEXT NOT NULL,id TEXT NOT NULL,revision INTEGER NOT NULL CHECK(revision>=0),state TEXT NOT NULL,
 peer TEXT NOT NULL,epoch TEXT NOT NULL,wire BLOB NOT NULL CHECK(length(wire)<=262144),local BLOB NOT NULL CHECK(length(local)<=73768),
 PRIMARY KEY(scope,id));
CREATE UNIQUE INDEX direct_v3_one_pending ON direct_v3_tasks(scope,peer) WHERE state IN ('prepared','publishing','conflict');
CREATE TABLE direct_v3_heads (
 scope TEXT NOT NULL,stream TEXT NOT NULL,sequence INTEGER NOT NULL CHECK(sequence>0),digest BLOB NOT NULL CHECK(length(digest)=32),PRIMARY KEY(scope,stream));
CREATE TABLE direct_v3_records (
 scope TEXT NOT NULL,id TEXT NOT NULL,stream TEXT NOT NULL,sequence INTEGER NOT NULL CHECK(sequence>0),
 wire BLOB NOT NULL CHECK(length(wire)<=262144),digest BLOB NOT NULL CHECK(length(digest)=32),local BLOB NOT NULL CHECK(length(local)<=73768),
 role TEXT NOT NULL,outcome TEXT NOT NULL,accepted_at INTEGER NOT NULL CHECK(accepted_at>0),PRIMARY KEY(scope,id),UNIQUE(scope,stream,sequence));
CREATE TABLE direct_v3_ack (
 scope TEXT NOT NULL,id TEXT NOT NULL,wire BLOB NOT NULL CHECK(length(wire)<=8192),pending INTEGER NOT NULL CHECK(pending IN (0,1)),PRIMARY KEY(scope,id));
CREATE TABLE direct_v3_hidden (scope TEXT NOT NULL,id TEXT NOT NULL,PRIMARY KEY(scope,id));
";

#[cfg(test)]
mod compatibility {
    use super::*;
    #[test]
    fn authenticated_old_local_body_without_cancel_flag_remains_readable() {
        let keys = crypto::generate_keypair().unwrap();
        let peer = crypto::generate_keypair().unwrap();
        let realm = "https://synthetic.invalid";
        let owner = Owner::new(realm, "old-sender", "old-device", &keys).unwrap();
        let source = DeviceState::pin(Anchor {
            origin: realm.into(),
            account: "old-sender".into(),
            root: owner.device.clone(),
        })
        .unwrap();
        let recipient = DeviceState::pin(Anchor {
            origin: realm.into(),
            account: "old-peer".into(),
            root: DeviceIdentity::from_keys("old-peer-device".into(), &peer),
        })
        .unwrap();
        let header = Header::new(
            &source,
            &recipient,
            "old-device",
            MessageSpec {
                id: "old-message".into(),
                sequence: 1,
                previous: vec![],
                sent_at: 123,
                kind: Kind::Text,
            },
        )
        .unwrap();
        let batch = Batch::make(header, &source, &recipient, &keys, "旧缓存🙂".as_bytes()).unwrap();
        let encrypted = seal(
            &owner,
            &batch,
            "authored",
            "processed",
            "旧缓存🙂".as_bytes(),
            &keys,
        )
        .unwrap();
        let plain = Zeroizing::new(
            crypto::decrypt(&encrypted, &keys.public_key, &keys.secret_key).unwrap(),
        );
        let mut old: serde_json::Value = serde_json::from_slice(&plain).unwrap();
        old.as_object_mut().unwrap().remove("cancel_requested");
        let bytes = Zeroizing::new(serde_json::to_vec(&old).unwrap());
        let encrypted = crypto::encrypt(&bytes, &keys.public_key, &keys.secret_key).unwrap();
        let body = unseal(&owner, &batch, "authored", "processed", &encrypted, &keys).unwrap();
        assert!(!body.cancel_requested);
        assert_eq!(body.body, "旧缓存🙂".as_bytes());
    }
}
