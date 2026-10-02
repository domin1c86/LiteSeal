//! Native-protected current sessions and immutable refresh originals. No page
//! receives the credentials, challenge secret or private task representation.
use super::{ClosedFamily, Observation};
use crate::trusted_devices::{
    self as t,
    activation::{jobs::Owner, ActivationApi, CheckedSession},
    tasks::{TaskGate, TaskLease},
    witness::{platform::Protection, Witness},
    Checkpoint, DeviceTrustStore,
};
use liteseal_shared::{
    crypto::{self, KeyPair},
    device_activation::{refresh as r, Challenge, Enable, Proof, Session},
    trusted_device::DeviceState,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Mutex};
use zeroize::{Zeroize, Zeroizing};
const MAX: usize = 65536;
const KIND: &str = "session_refresh";
const CURRENT: &str = "session_refresh_current";
fn bad() -> String {
    "原续期任务、正式会话或保护状态无法验证，请保留原数据".into()
}
fn db(_: rusqlite::Error) -> String {
    "原续期任务存储不可用".into()
}
fn scope(owner: &Owner) -> String {
    hex::encode(Sha256::digest(
        serde_json::to_vec(&("LiteSeal/refresh-owner/v1", owner)).expect("public owner"),
    ))
}
fn uuid(id: &str) -> Result<(), String> {
    if uuid::Uuid::parse_str(id).is_ok_and(|v| v.to_string() == id) {
        Ok(())
    } else {
        Err(bad())
    }
}
fn copy_session(session: &Session) -> Result<Session, String> {
    let plain = Zeroizing::new(serde_json::to_vec(session).map_err(|_| bad())?);
    serde_json::from_slice(&plain).map_err(|_| bad())
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Prepared,
    Started,
    Proving,
    Conflict,
    Complete,
    Cancelled,
    Ended,
}
impl Stage {
    fn terminal(self) -> bool {
        matches!(self, Self::Complete | Self::Cancelled | Self::Ended)
    }
}
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct View {
    pub id: String,
    pub revision: u64,
    pub stage: Stage,
    pub current: bool,
    pub cancel_requested: bool,
}
#[derive(Debug, Serialize)]
pub struct CurrentView {
    pub generation: u64,
    pub account: String,
    pub device: String,
    pub session: String,
    pub has_credentials: bool,
    pub access_expired: bool,
    pub eligible: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CurrentRecord {
    domain: String,
    version: u8,
    owner: Owner,
    generation: u64,
    family: String,
    mode: Enable,
    session: Session,
    active: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    domain: String,
    version: u8,
    owner: Owner,
    revision: u64,
    generation: u64,
    family: String,
    request: r::Start,
    mode: Enable,
    original: Session,
    stage: Stage,
    started: bool,
    cancel_requested: bool,
    challenge: Option<Challenge>,
    proof: Option<Vec<u8>>,
    result: Option<r::Envelope>,
}
impl Drop for Stored {
    fn drop(&mut self) {
        if let Some(proof) = &mut self.proof {
            proof.zeroize();
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FamilyReceipt {
    domain: String,
    version: u8,
    owner: Owner,
    family: String,
    request: [u8; 32],
}
fn receipt_scope(owner: &Owner) -> String {
    format!("{}:closed", scope(owner))
}
fn family_closed(
    conn: &Connection,
    owner: &Owner,
    family: &str,
    keys: &KeyPair,
) -> Result<bool, String> {
    let bytes:Option<Vec<u8>>=conn.query_row("SELECT body FROM device_control_tasks WHERE scope=?1 AND id=?2 AND kind='refresh_family_closed' AND terminal=1 AND revision=1",params![receipt_scope(owner),family],|r|r.get(0)).optional().map_err(db)?;
    let Some(bytes) = bytes else { return Ok(false) };
    let receipt: FamilyReceipt = open(&bytes, keys)?;
    if receipt.domain != "LiteSeal/refresh-family-closed/v1"
        || receipt.version != 1
        || receipt.owner != *owner
        || receipt.family != family
        || receipt.request == [0; 32]
    {
        return Err(bad());
    }
    Ok(true)
}
fn prune_receipts(conn: &Connection, owner: &Owner, keys: &KeyPair) -> Result<(), String> {
    let mut keep = std::collections::HashSet::new();
    if let Some(c) = current(conn, owner, keys)? {
        keep.insert(c.family);
    }
    let mut stmt = conn
        .prepare("SELECT id FROM device_control_tasks WHERE scope=?1 AND kind=?2 LIMIT 129")
        .map_err(db)?;
    let ids = stmt
        .query_map(params![scope(owner), KIND], |r| r.get::<_, String>(0))
        .map_err(db)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(db)?;
    if ids.len() > 128 {
        return Err(bad());
    }
    for id in ids {
        keep.insert(get(conn, owner, &id, keys)?.family.clone());
    }
    let mut stmt=conn.prepare("SELECT id FROM device_control_tasks WHERE scope=?1 AND kind='refresh_family_closed' LIMIT 130").map_err(db)?;
    let ids = stmt
        .query_map([receipt_scope(owner)], |r| r.get::<_, String>(0))
        .map_err(db)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(db)?;
    if ids.len() > 129 {
        return Err(bad());
    }
    for family in ids {
        if !family_closed(conn, owner, &family, keys)? {
            return Err(bad());
        }
        if !keep.contains(&family) {
            conn.execute("DELETE FROM device_control_tasks WHERE scope=?1 AND id=?2 AND kind='refresh_family_closed'",params![receipt_scope(owner),family]).map_err(db)?;
        }
    }
    Ok(())
}
pub struct Task {
    stored: Stored,
    current: bool,
}
impl Task {
    pub fn view(&self) -> View {
        View {
            id: self.stored.request.id.clone(),
            revision: self.stored.revision,
            stage: self.stored.stage,
            current: self.current,
            cancel_requested: self.stored.cancel_requested,
        }
    }
    pub fn request(&self) -> &r::Start {
        &self.stored.request
    }
    pub fn challenge(&self) -> Option<&Challenge> {
        self.stored.challenge.as_ref()
    }
    pub fn proof(&self) -> Result<Option<Proof>, String> {
        self.stored
            .proof
            .as_ref()
            .map(|p| serde_json::from_slice(p).map_err(|_| bad()))
            .transpose()
    }
}
fn seal<T: Serialize>(value: &T, keys: &KeyPair) -> Result<Vec<u8>, String> {
    let plain = Zeroizing::new(serde_json::to_vec(value).map_err(|_| bad())?);
    if plain.len() > MAX - 1024 {
        return Err(bad());
    }
    crypto::encrypt(&plain, &keys.public_key, &keys.secret_key).map_err(|_| bad())
}
fn open<T: serde::de::DeserializeOwned>(bytes: &[u8], keys: &KeyPair) -> Result<T, String> {
    if bytes.len() > MAX {
        return Err(bad());
    }
    let plain = Zeroizing::new(
        crypto::decrypt(bytes, &keys.public_key, &keys.secret_key).map_err(|_| bad())?,
    );
    serde_json::from_slice(&plain).map_err(|_| bad())
}
fn current(
    conn: &Connection,
    owner: &Owner,
    keys: &KeyPair,
) -> Result<Option<CurrentRecord>, String> {
    owner.keys(keys)?;
    let row=conn.query_row("SELECT revision,body,terminal FROM device_control_tasks WHERE scope=?1 AND id=?2 AND kind=?3",params![scope(owner),CURRENT,CURRENT],|r|Ok((r.get::<_,u64>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,bool>(2)?))).optional().map_err(db)?;
    let Some((revision, body, terminal)) = row else {
        return Ok(None);
    };
    let record: CurrentRecord = open(&body, keys)?;
    if record.domain != "LiteSeal/refresh-current/v1"
        || record.version != 1
        || record.owner != *owner
        || record.generation != revision
        || revision == 0
        || !terminal
    {
        return Err(bad());
    }
    record.mode.verify_root(owner.anchor()).map_err(|_| bad())?;
    t::read_at(
        conn,
        owner.anchor(),
        &Checkpoint {
            revision: record.mode.revision,
            hash: record.mode.head.to_vec(),
        },
    )?;
    if record.session.account != owner.anchor().account
        || record.session.device != owner.device().device_id
        || record.session.mode != record.mode.digest().map_err(|_| bad())?
    {
        return Err(bad());
    }
    uuid(&record.session.id)?;
    uuid(&record.family)?;
    let present =
        !record.session.access_token.is_empty() && !record.session.refresh_token.is_empty();
    if record.active != present
        || !record.active
            && (!record.session.access_token.is_empty() || !record.session.refresh_token.is_empty())
        || record.session.access_token.len() > 256
        || record.session.refresh_token.len() > 256
        || record.session.authorization == [0; 32]
        || !record
            .session
            .access_token
            .bytes()
            .all(|v| v.is_ascii_graphic())
        || !record
            .session
            .refresh_token
            .bytes()
            .all(|v| v.is_ascii_graphic())
        || record.active
            && (record.session.expires_at <= 0
                || record.session.refresh_expires_at <= record.session.expires_at
                || record.session.refresh_expires_at > 8_640_000_000_000_000)
    {
        return Err(bad());
    }
    Ok(Some(record))
}
pub(crate) fn credentials_in(
    conn: &Connection,
    owner: &Owner,
    keys: &KeyPair,
) -> Result<Option<Session>, String> {
    let Some(record) = current(conn, owner, keys)? else {
        return Ok(None);
    };
    let mut session = copy_session(&record.session)?;
    if !record.active
        || owner.member(&t::read(conn, owner.anchor(), None)?).ok() != Some(session.authorization)
    {
        session.access_token.zeroize();
        session.refresh_token.zeroize();
        session.expires_at = 0;
        session.refresh_expires_at = 0;
    }
    Ok(Some(session))
}
fn put_current(
    conn: &Connection,
    record: &mut CurrentRecord,
    previous: Option<u64>,
    keys: &KeyPair,
) -> Result<(), String> {
    record.generation = previous.unwrap_or(0).checked_add(1).ok_or_else(bad)?;
    let sealed = seal(record, keys)?;
    let count = if let Some(previous) = previous {
        conn.execute("UPDATE device_control_tasks SET revision=?3,body=?4 WHERE scope=?1 AND id=?2 AND kind=?5 AND revision=?6",params![scope(&record.owner),CURRENT,record.generation,sealed,CURRENT,previous]).map_err(db)?
    } else {
        conn.execute("INSERT INTO device_control_tasks(scope,id,revision,kind,terminal,body) VALUES(?1,?2,?3,?4,1,?5)",params![scope(&record.owner),CURRENT,record.generation,CURRENT,sealed]).map_err(db)?
    };
    if count != 1 {
        return Err(bad());
    }
    Ok(())
}
pub(crate) fn generation_in(
    conn: &Connection,
    owner: &Owner,
    keys: &KeyPair,
) -> Result<Option<u64>, String> {
    Ok(current(conn, owner, keys)?.map(|c| c.generation))
}
pub(crate) struct Adoption {
    record: CurrentRecord,
}
impl Adoption {
    pub(crate) fn new(
        owner: Owner,
        activation: &crate::trusted_devices::activation::jobs::Task,
        checked: CheckedSession,
        keys: &KeyPair,
    ) -> Result<Self, String> {
        owner.keys(keys)?;
        let mode = activation.enable().clone();
        let session = checked.bind(activation.initial_session(&owner, keys)?)?;
        mode.verify_root(owner.anchor()).map_err(|_| bad())?;
        Ok(Self {
            record: CurrentRecord {
                domain: "LiteSeal/refresh-current/v1".into(),
                version: 1,
                owner,
                generation: 0,
                family: session.id.clone(),
                mode,
                session,
                active: true,
            },
        })
    }
    pub(crate) fn commit(
        mut self,
        conn: &Connection,
        keys: &KeyPair,
        expected: Option<u64>,
    ) -> Result<(), String> {
        let owner = &self.record.owner;
        let state = t::read(conn, owner.anchor(), None)?;
        t::read_at(
            conn,
            owner.anchor(),
            &Checkpoint {
                revision: self.record.mode.revision,
                hash: self.record.mode.head.to_vec(),
            },
        )?;
        if self.record.session.account != owner.anchor().account
            || self.record.session.device != owner.device().device_id
            || self.record.session.authorization != owner.member(&state)?
            || self.record.session.mode != self.record.mode.digest().map_err(|_| bad())?
        {
            return Err(bad());
        }
        if generation_in(conn, owner, keys)? != expected {
            return Err("正式会话代次已变化，原保存未覆盖当前记录".into());
        }
        let owner = owner.clone();
        put_current(conn, &mut self.record, expected, keys)?;
        prune_receipts(conn, &owner, keys)
    }
}
pub(crate) fn clear_in(conn: &Connection, owner: &Owner, keys: &KeyPair) -> Result<(), String> {
    if let Some(mut record) = current(conn, owner, keys)? {
        let previous = record.generation;
        record.active = false;
        record.session.access_token.zeroize();
        record.session.refresh_token.zeroize();
        put_current(conn, &mut record, Some(previous), keys)?;
    }
    Ok(())
}
fn original(conn: &Connection, task: &Stored) -> Result<DeviceState, String> {
    t::read_at(
        conn,
        task.owner.anchor(),
        &Checkpoint {
            revision: task.request.revision,
            hash: task.request.head.to_vec(),
        },
    )
}
fn validate(conn: &Connection, owner: &Owner, task: &Stored, keys: &KeyPair) -> Result<(), String> {
    uuid(&task.family)?;
    owner.keys(keys)?;
    if task.domain != "LiteSeal/refresh-task/v1"
        || task.version != 1
        || task.owner != *owner
        || task.revision == 0
        || task.generation == 0
        || task.request.device != *owner.device()
    {
        return Err(bad());
    }
    task.request
        .bind_original(&task.original)
        .map_err(|_| bad())?;
    let state = original(conn, task)?;
    t::read_at(
        conn,
        owner.anchor(),
        &Checkpoint {
            revision: task.mode.revision,
            hash: task.mode.head.to_vec(),
        },
    )?;
    task.request
        .verify_state(&state, &task.mode, task.request.issued_at)
        .map_err(|_| bad())?;
    if let Some(challenge) = &task.challenge {
        task.request
            .verify_challenge(challenge, &state, &task.mode, keys)
            .map_err(|_| bad())?;
    }
    if let Some(proof) = &task.proof {
        if proof.len() > 2048 {
            return Err(bad());
        }
        serde_json::from_slice::<Proof>(proof)
            .map_err(|_| bad())?
            .verify(task.challenge.as_ref().ok_or_else(bad)?)
            .map_err(|_| bad())?;
    }
    if let Some(result) = &task.result {
        result
            .open(
                &task.request,
                task.challenge.as_ref().ok_or_else(bad)?,
                keys,
            )
            .map_err(|_| bad())?;
    }
    if task.stage == Stage::Complete && task.result.is_none()
        || task.result.is_some() && !matches!(task.stage, Stage::Complete | Stage::Ended)
        || task.stage == Stage::Proving && task.proof.is_none()
        || task.proof.is_some() && task.challenge.is_none()
        || !task.started
            && (task.challenge.is_some() || task.proof.is_some() || task.result.is_some())
        || !task.started && !matches!(task.stage, Stage::Prepared | Stage::Cancelled)
        || task.stage == Stage::Prepared && task.started
        || task.stage == Stage::Cancelled && (task.started || !task.cancel_requested)
    {
        return Err(bad());
    }
    Ok(())
}
fn get(conn: &Connection, owner: &Owner, id: &str, keys: &KeyPair) -> Result<Stored, String> {
    uuid(id)?;
    let (revision,terminal,bytes)=conn.query_row("SELECT revision,terminal,body FROM device_control_tasks WHERE scope=?1 AND id=?2 AND kind=?3",params![scope(owner),id,KIND],|r|Ok((r.get::<_,u64>(0)?,r.get::<_,bool>(1)?,r.get::<_,Vec<u8>>(2)?))).map_err(db)?;
    let task: Stored = open(&bytes, keys)?;
    validate(conn, owner, &task, keys)?;
    if task.request.id != id || task.revision != revision || task.stage.terminal() != terminal {
        return Err(bad());
    }
    Ok(task)
}
fn put(
    conn: &Connection,
    task: &mut Stored,
    keys: &KeyPair,
    previous: Option<u64>,
) -> Result<(), String> {
    task.revision = previous.unwrap_or(0).checked_add(1).ok_or_else(bad)?;
    validate(conn, &task.owner, task, keys)?;
    let bytes = seal(task, keys)?;
    let count = if let Some(previous) = previous {
        conn.execute("UPDATE device_control_tasks SET revision=?3,terminal=?4,body=?5 WHERE scope=?1 AND id=?2 AND kind=?6 AND revision=?7",params![scope(&task.owner),task.request.id,task.revision,task.stage.terminal(),bytes,KIND,previous]).map_err(db)?
    } else {
        let count: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM device_control_tasks WHERE scope=?1 AND kind=?2",
                params![scope(&task.owner), KIND],
                |r| r.get(0),
            )
            .map_err(db)?;
        if count >= 128 {
            return Err("原续期任务达到上限，请先整理已确认结果".into());
        }
        conn.execute("INSERT INTO device_control_tasks(scope,id,revision,kind,terminal,body) VALUES(?1,?2,?3,?4,?5,?6)",params![scope(&task.owner),task.request.id,task.revision,KIND,task.stage.terminal(),bytes]).map_err(db)?
    };
    if count != 1 {
        return Err(bad());
    }
    Ok(())
}
pub struct Store {
    trust: DeviceTrustStore,
    owner: Owner,
}
impl Store {
    pub fn credentials(&mut self, keys: &KeyPair) -> Result<Option<Session>, String> {
        self.trust
            .read_checked(|conn| credentials_in(conn, &self.owner, keys))
    }
    pub fn open(
        path: &Path,
        owner: Owner,
        keys: &KeyPair,
        witness: Witness,
    ) -> Result<Self, String> {
        owner.keys(keys)?;
        let mut trust = DeviceTrustStore::open(path)?;
        trust.protect(witness)?;
        trust.load(owner.anchor(), None)?;
        Ok(Self { trust, owner })
    }
    pub fn current_view(&mut self, keys: &KeyPair) -> Result<Option<CurrentView>, String> {
        self.trust.read_checked(|conn| {
            let Some(record) = current(conn, &self.owner, keys)? else {
                return Ok(None);
            };
            let state = t::read(conn, self.owner.anchor(), None)?;
            Ok(Some(CurrentView {
                generation: record.generation,
                account: record.session.account.clone(),
                device: record.session.device.clone(),
                session: record.session.id.clone(),
                has_credentials: record.active,
                access_expired: record.session.expires_at <= chrono::Utc::now().timestamp_millis(),
                eligible: self.owner.member(&state).ok() == Some(record.session.authorization),
            }))
        })
    }
    pub fn session(&mut self, keys: &KeyPair) -> Result<Session, String> {
        self.trust.read_checked(|conn| {
            let record = current(conn, &self.owner, keys)?.ok_or_else(bad)?;
            if !record.active
                || self
                    .owner
                    .member(&t::read(conn, self.owner.anchor(), None)?)?
                    != record.session.authorization
            {
                return Err(bad());
            }
            copy_session(&record.session)
        })
    }
    pub fn adopt(
        &mut self,
        activation: &crate::trusted_devices::activation::jobs::Task,
        checked: CheckedSession,
        keys: &KeyPair,
    ) -> Result<CurrentView, String> {
        let expected = self.current_view(keys)?.map(|v| v.generation);
        self.adopt_expected(activation, checked, keys, expected)
    }
    pub fn adopt_expected(
        &mut self,
        activation: &crate::trusted_devices::activation::jobs::Task,
        checked: CheckedSession,
        keys: &KeyPair,
        expected: Option<u64>,
    ) -> Result<CurrentView, String> {
        let adoption = Adoption::new(self.owner.clone(), activation, checked, keys)?;
        self.trust
            .write_checked(|conn| adoption.commit(conn, keys, expected))?;
        self.current_view(keys)?.ok_or_else(bad)
    }
    pub fn task(&mut self, id: &str, keys: &KeyPair) -> Result<Task, String> {
        self.trust.read_checked(|conn| {
            let task = get(conn, &self.owner, id, keys)?;
            let current = current(conn, &self.owner, keys)?
                .is_some_and(|c| c.active && c.generation == task.generation);
            Ok(Task {
                stored: task,
                current,
            })
        })
    }
    pub fn views(&mut self, keys: &KeyPair) -> Result<Vec<View>, String> {
        self.trust.read_checked(|conn|{self.owner.keys(keys)?;let generation=current(conn,&self.owner,keys)?.filter(|c|c.active).map(|c|c.generation);let mut stmt=conn.prepare("SELECT id FROM device_control_tasks WHERE scope=?1 AND kind=?2 ORDER BY id LIMIT 129").map_err(db)?;let ids=stmt.query_map(params![scope(&self.owner),KIND],|r|r.get::<_,String>(0)).map_err(db)?.collect::<Result<Vec<_>,_>>().map_err(db)?;if ids.len()>128{return Err(bad());}ids.iter().map(|id|{let task=get(conn,&self.owner,id,keys)?;let current=generation==Some(task.generation);Ok(Task{stored:task,current}.view())}).collect()})
    }
    pub fn prepare(&mut self, keys: &KeyPair) -> Result<View, String> {
        self.trust.write_checked(|conn|{let record=current(conn,&self.owner,keys)?.filter(|r|r.active).ok_or_else(bad)?;let state=t::read(conn,self.owner.anchor(),None)?;if self.owner.member(&state)?!=record.session.authorization{return Err(bad());}
        let pending:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM device_control_tasks WHERE scope=?1 AND kind=?2 AND terminal=0)",params![scope(&self.owner),KIND],|r|r.get(0)).map_err(db)?;
        // Old unresolved tasks remain queryable; an explicit new checked login
        // does not silently delete them or claim their remote family ended.
        if pending{let mut stmt=conn.prepare("SELECT id FROM device_control_tasks WHERE scope=?1 AND kind=?2 AND terminal=0").map_err(db)?;let ids=stmt.query_map(params![scope(&self.owner),KIND],|r|r.get::<_,String>(0)).map_err(db)?.collect::<Result<Vec<_>,_>>().map_err(db)?;for id in ids{if get(conn,&self.owner,&id,keys)?.generation==record.generation{return Err("原续期任务仍未结束，请继续原编号".into());}}}
        let request=r::Start::make(&state,&record.mode,&record.session,&uuid::Uuid::new_v4().to_string(),chrono::Utc::now().timestamp_millis(),keys).map_err(|_|bad())?;
        let mut task=Stored{domain:"LiteSeal/refresh-task/v1".into(),version:1,owner:self.owner.clone(),revision:0,generation:record.generation,family:record.family.clone(),request,mode:record.mode,original:record.session,stage:Stage::Prepared,started:false,cancel_requested:false,challenge:None,proof:None,result:None};put(conn,&mut task,keys,None)?;Ok(Task{stored:task,current:true}.view())
    })
    }
    fn edit(
        &mut self,
        expected: &View,
        keys: &KeyPair,
        callback: impl FnOnce(&Connection, &mut Stored) -> Result<(), String>,
    ) -> Result<Task, String> {
        self.trust.write_checked(|conn| {
            let mut task = get(conn, &self.owner, &expected.id, keys)?;
            if task.revision != expected.revision {
                return Err(bad());
            }
            callback(conn, &mut task)?;
            put(conn, &mut task, keys, Some(expected.revision))?;
            let current = current(conn, &self.owner, keys)?
                .is_some_and(|c| c.active && c.generation == task.generation);
            Ok(Task {
                stored: task,
                current,
            })
        })
    }
    fn start(&mut self, expected: &View, keys: &KeyPair) -> Result<Task, String> {
        self.edit(expected, keys, |conn, task| {
            let c = current(conn, &task.owner, keys)?.ok_or_else(bad)?;
            if c.generation != task.generation
                || !c.active
                || task.stage.terminal()
                || task.cancel_requested
            {
                return Err(bad());
            }
            task.started = true;
            task.stage = Stage::Started;
            Ok(())
        })
    }
    pub fn request_cancel(&mut self, id: &str, keys: &KeyPair) -> Result<View, String> {
        let expected = self.task(id, keys)?.view();
        if matches!(expected.stage, Stage::Cancelled | Stage::Ended) {
            return Ok(expected);
        }
        self.edit(&expected, keys, |_, task| {
            task.cancel_requested = true;
            if !task.started {
                task.stage = Stage::Cancelled;
            }
            Ok(())
        })
        .map(|t| t.view())
    }
    fn seal_proof(&mut self, expected: &View, keys: &KeyPair) -> Result<Task, String> {
        self.edit(expected, keys, |conn, task| {
            if task.cancel_requested || task.proof.is_some() || task.stage.terminal() {
                return Err(bad());
            }
            let state = original(conn, task)?;
            let proof = task
                .challenge
                .as_ref()
                .ok_or_else(bad)?
                .answer(
                    &state,
                    &task.mode,
                    chrono::Utc::now().timestamp_millis(),
                    keys,
                )
                .map_err(|_| bad())?;
            task.proof = Some(serde_json::to_vec(&proof).map_err(|_| bad())?);
            task.stage = Stage::Proving;
            Ok(())
        })
    }
    fn accept(
        &mut self,
        expected: &View,
        observed: Observation,
        keys: &KeyPair,
    ) -> Result<Task, String> {
        self.edit(expected, keys, |conn, task| {
            if observed.request != task.request || task.cancel_requested {
                return Err(bad());
            }
            let c = current(conn, &task.owner, keys)?
                .filter(|c| c.active && c.generation == task.generation)
                .ok_or_else(bad)?;
            let state = t::read(conn, task.owner.anchor(), None)?;
            if task.owner.member(&state)? != task.request.authorization {
                return Err(bad());
            }
            let (challenge, envelope) = match observed.reply {
                r::Reply::Pending { challenge, .. } => (*challenge, None),
                r::Reply::Accepted {
                    challenge,
                    envelope,
                    ..
                } => (*challenge, Some(envelope)),
            };
            if task.challenge.as_ref().is_some_and(|old| *old != challenge) {
                return Err(bad());
            }
            task.challenge = Some(challenge);
            if let Some(envelope) = envelope {
                let session = envelope
                    .open(
                        &task.request,
                        task.challenge.as_ref().ok_or_else(bad)?,
                        keys,
                    )
                    .map_err(|_| bad())?;
                let mut next = CurrentRecord {
                    domain: c.domain,
                    version: 1,
                    owner: c.owner,
                    generation: 0,
                    family: c.family,
                    mode: task.mode.clone(),
                    session,
                    active: true,
                };
                put_current(conn, &mut next, Some(c.generation), keys)?;
                task.result = Some(envelope);
                task.stage = Stage::Complete;
            }
            Ok(())
        })
    }
    fn closed(
        &mut self,
        expected: &View,
        closed: ClosedFamily,
        keys: &KeyPair,
    ) -> Result<Task, String> {
        self.edit(expected, keys, |conn, task| {
            if !task.cancel_requested
                || closed.request != task.request.digest().map_err(|_| bad())?
            {
                return Err(bad());
            }
            if !family_closed(conn,&task.owner,&task.family,keys)? {
                let receipt=FamilyReceipt{domain:"LiteSeal/refresh-family-closed/v1".into(),version:1,owner:task.owner.clone(),family:task.family.clone(),request:closed.request};
                conn.execute("INSERT INTO device_control_tasks(scope,id,revision,kind,terminal,body) VALUES(?1,?2,1,'refresh_family_closed',1,?3)",params![receipt_scope(&task.owner),task.family,seal(&receipt,keys)?]).map_err(db)?;
            }
            if let Some(mut c) = current(conn, &task.owner, keys)? {
                if c.active && c.family == task.family {
                    let previous = c.generation;
                    c.active = false;
                    c.session.access_token.zeroize();
                    c.session.refresh_token.zeroize();
                    put_current(conn, &mut c, Some(previous), keys)?;
                }
            }
            task.stage = Stage::Ended;
            Ok(())
        })
    }
    pub fn clear_local(&mut self, keys: &KeyPair) -> Result<(), String> {
        self.trust
            .write_checked(|conn| clear_in(conn, &self.owner, keys))
    }
    pub fn forget_ended(&mut self, id: &str, keys: &KeyPair) -> Result<(), String> {
        self.trust.write_checked(|conn| {
            let task=get(conn,&self.owner,id,keys)?;
            if !task.stage.terminal() || task.cancel_requested && task.stage==Stage::Complete {
                return Err("原续期结果或家族退出仍未处理，请保留任务".into());
            }
            let current=current(conn,&self.owner,keys)?.ok_or_else(bad)?;
            if task.stage==Stage::Complete && !(current.active && current.family==task.family && current.generation>task.generation || family_closed(conn,&self.owner,&task.family,keys)?) {return Err(bad());}
            conn.execute("DELETE FROM device_control_tasks WHERE scope=?1 AND id=?2 AND kind=?3 AND revision=?4",params![scope(&self.owner),id,KIND,task.revision]).map_err(db)?;
            prune_receipts(conn,&self.owner,keys)?;
            Ok(())
        })
    }
}
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Condition {
    Complete,
    Cancelled,
    Ended,
    Superseded,
    Ineligible,
    Retry,
    Conflict,
    Pending,
}
#[derive(Debug, Serialize)]
pub struct Progress {
    pub task: View,
    pub condition: Condition,
    pub http_status: Option<u16>,
}
pub struct Coordinator {
    store: Mutex<Store>,
    gate: TaskGate,
    network: tokio::sync::Mutex<()>,
    api: ActivationApi,
    _protection: Protection,
}
impl Coordinator {
    pub fn open(path: &Path, owner: Owner, keys: &KeyPair) -> Result<Self, String> {
        Self::open_with_protection(path, owner, keys, Protection::default())
    }
    pub fn open_with_protection(
        path: &Path,
        owner: Owner,
        keys: &KeyPair,
        protection: Protection,
    ) -> Result<Self, String> {
        let api = ActivationApi::new(&owner.anchor().origin).map_err(|_| bad())?;
        Ok(Self {
            store: Mutex::new(Store::open(path, owner, keys, protection.witness(path)?)?),
            gate: TaskGate::new()?,
            network: tokio::sync::Mutex::new(()),
            api,
            _protection: protection,
        })
    }
    fn with<T>(
        &self,
        lease: &TaskLease,
        work: impl FnOnce(&mut Store) -> Result<T, String>,
    ) -> Result<T, String> {
        self.gate
            .with_current(lease, || work(&mut *self.store.lock().map_err(|_| bad())?))
    }
    pub fn invalidate(&self) -> Result<(), String> {
        self.gate.invalidate()
    }
    pub fn resume(&self) -> Result<(), String> {
        self.gate.unlock()
    }
    pub fn adopt(
        &self,
        activation: &crate::trusted_devices::activation::jobs::Task,
        checked: CheckedSession,
        keys: &KeyPair,
    ) -> Result<CurrentView, String> {
        let lease = self.gate.lease()?;
        self.gate.rotate_current_with(&lease, || {
            self.store
                .lock()
                .map_err(|_| bad())?
                .adopt(activation, checked, keys)
        })
    }
    pub fn clear_local(&self, keys: &KeyPair) -> Result<(), String> {
        self.gate
            .rotate_with(|| self.store.lock().map_err(|_| bad())?.clear_local(keys))
    }
    pub fn prepare(&self, keys: &KeyPair) -> Result<View, String> {
        let lease = self.gate.lease()?;
        self.with(&lease, |s| s.prepare(keys))
    }
    pub fn views(&self, keys: &KeyPair) -> Result<Vec<View>, String> {
        let lease = self.gate.lease()?;
        self.with(&lease, |s| s.views(keys))
    }
    pub fn current_view(&self, keys: &KeyPair) -> Result<Option<CurrentView>, String> {
        let lease = self.gate.lease()?;
        self.with(&lease, |s| s.current_view(keys))
    }
    pub fn session(&self, keys: &KeyPair) -> Result<Session, String> {
        let lease = self.gate.lease()?;
        self.with(&lease, |s| s.session(keys))
    }
    pub fn request_cancel(&self, id: &str, keys: &KeyPair) -> Result<View, String> {
        let lease = self.gate.lease()?;
        self.with(&lease, |s| s.request_cancel(id, keys))
    }
    pub fn forget_ended(&self, id: &str, keys: &KeyPair) -> Result<(), String> {
        let lease = self.gate.lease()?;
        self.with(&lease, |s| s.forget_ended(id, keys))
    }
    pub async fn step(&self, id: &str, keys: &KeyPair) -> Result<Progress, String> {
        let lease = self.gate.lease()?;
        let _network = self.network.lock().await;
        let mut task = self.with(&lease, |s| s.task(id, keys))?;
        let terminal = match task.stored.stage {
            Stage::Cancelled => Some(Condition::Cancelled),
            Stage::Ended => Some(Condition::Ended),
            Stage::Complete if !task.stored.cancel_requested => Some(Condition::Complete),
            _ => None,
        };
        if let Some(condition) = terminal {
            return Ok(Progress {
                task: task.view(),
                condition,
                http_status: None,
            });
        }
        if !task.current && !task.stored.cancel_requested {
            return Ok(Progress {
                task: task.view(),
                condition: Condition::Superseded,
                http_status: None,
            });
        }
        let original = self.with(&lease, |s| {
            s.trust.read_checked(|conn| original(conn, &task.stored))
        })?;
        if task.stored.cancel_requested {
            let response = self
                .api
                .close_refresh_family(
                    &task.stored.request,
                    &task.stored.original,
                    &original,
                    &task.stored.mode,
                    keys,
                )
                .await;
            return match response {
                Ok(closed) => {
                    let task = self.with(&lease, |s| s.closed(&task.view(), closed, keys))?;
                    Ok(Progress {
                        task: task.view(),
                        condition: Condition::Ended,
                        http_status: None,
                    })
                }
                Err(error) => self.error(&lease, &task, error.status, keys),
            };
        }
        let eligible = self.with(&lease, |s| {
            s.trust.read_checked(|conn| {
                Ok(s.owner.member(&t::read(conn, s.owner.anchor(), None)?).ok()
                    == Some(task.stored.request.authorization))
            })
        })?;
        if !eligible {
            return Ok(Progress {
                task: task.view(),
                condition: Condition::Ineligible,
                http_status: None,
            });
        }
        if !task.stored.started {
            task = self.with(&lease, |s| s.start(&task.view(), keys))?;
        }
        if task.stored.challenge.is_none() {
            let observed = self
                .api
                .begin_refresh(
                    &task.stored.request,
                    &task.stored.original,
                    &original,
                    &task.stored.mode,
                    keys,
                )
                .await;
            match observed {
                Ok(observed) => {
                    task = self.with(&lease, |s| s.accept(&task.view(), observed, keys))?
                }
                Err(error) => return self.error(&lease, &task, error.status, keys),
            };
            if task.stored.stage == Stage::Complete {
                return Ok(Progress {
                    task: task.view(),
                    condition: Condition::Complete,
                    http_status: None,
                });
            }
        }
        if task.stored.proof.is_none() {
            task = self.with(&lease, |s| s.seal_proof(&task.view(), keys))?;
        }
        let proof = task.proof()?.ok_or_else(bad)?;
        let challenge = task.stored.challenge.as_ref().ok_or_else(bad)?;
        let observed = self
            .api
            .prove_refresh(
                &task.stored.request,
                &proof,
                challenge,
                &task.stored.original,
                &original,
                &task.stored.mode,
                keys,
            )
            .await;
        match observed {
            Ok(observed) => {
                let task = self.with(&lease, |s| s.accept(&task.view(), observed, keys))?;
                Ok(Progress {
                    task: task.view(),
                    condition: Condition::Complete,
                    http_status: None,
                })
            }
            Err(error) => self.error(&lease, &task, error.status, keys),
        }
    }
    fn error(
        &self,
        lease: &TaskLease,
        task: &Task,
        status: Option<u16>,
        keys: &KeyPair,
    ) -> Result<Progress, String> {
        self.with(lease, |s| {
            let current = s.task(&task.stored.request.id, keys)?;
            if current.view().revision != task.view().revision {
                return Err(bad());
            }
            Ok(Progress {
                task: current.view(),
                condition: if status == Some(409) {
                    Condition::Conflict
                } else {
                    Condition::Retry
                },
                http_status: status,
            })
        })
    }
}
