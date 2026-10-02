//! Immutable activation originals inside the existing externally protected task
//! table. Passwords and plaintext session tokens are never persisted.
use super::ActivationApi;
use crate::trusted_devices::{
    self as t, tasks::TaskGate, witness::platform::Protection, Checkpoint, DeviceTrustStore,
};
use liteseal_shared::{
    backup_crypto,
    crypto::{self, KeyPair},
    device_activation::{
        ActivationCancel, ActivationCancelResult, Challenge, ClosedReason, Closure, Enable,
        EnableCancel, EnableCancelResult, Envelope, Inspection, InspectionResult, Proof, Session,
        Start,
    },
    direct_message::Directory,
    trusted_device::{Anchor, DeviceIdentity, DeviceState},
};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    sync::{Mutex, RwLock},
};
use zeroize::{Zeroize, Zeroizing};
const MAX: usize = 65536;
fn bad() -> String {
    "激活任务、原身份或保护状态不匹配；请保留原任务".into()
}
fn db(_: rusqlite::Error) -> String {
    "激活任务存储不可用".into()
}
fn uuid(id: &str) -> Result<(), String> {
    if uuid::Uuid::parse_str(id)
        .ok()
        .is_none_or(|v| v.to_string() != id)
    {
        Err(bad())
    } else {
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Owner {
    anchor: Anchor,
    device: DeviceIdentity,
}
impl Owner {
    pub fn new(anchor: Anchor, device: &str, keys: &KeyPair) -> Result<Self, String> {
        anchor.validate().map_err(|_| bad())?;
        uuid(device)?;
        let owner = Self {
            anchor,
            device: DeviceIdentity::from_keys(device.into(), keys),
        };
        owner.keys(keys)?;
        Ok(owner)
    }
    pub(crate) fn keys(&self, keys: &KeyPair) -> Result<(), String> {
        if self.device != DeviceIdentity::from_keys(self.device.device_id.clone(), keys) {
            return Err(bad());
        }
        backup_crypto::validate_identity(
            &keys.public_key,
            &keys.secret_key,
            &keys.ed25519_pk,
            &keys.ed25519_sk,
        )
        .map_err(|_| bad())
    }
    fn scope(&self, kind: Kind) -> String {
        hex::encode(Sha256::digest(
            serde_json::to_vec(&("LiteSeal/activation-owner/v1", self, kind))
                .expect("public owner"),
        ))
    }
    pub(crate) fn member(&self, state: &DeviceState) -> Result<[u8; 32], String> {
        if state.anchor() != &self.anchor {
            return Err(bad());
        }
        Directory::from_state(state)
            .members
            .into_iter()
            .find(|m| m.device == self.device)
            .map(|m| m.authorization_hash)
            .ok_or_else(bad)
    }
    pub(crate) fn anchor(&self) -> &Anchor {
        &self.anchor
    }
    pub(crate) fn device(&self) -> &DeviceIdentity {
        &self.device
    }
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
    Ineligible,
    Ended,
}
impl Stage {
    fn terminal(self) -> bool {
        matches!(
            self,
            Self::Complete | Self::Cancelled | Self::Ineligible | Self::Ended
        )
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Enable,
    Login,
}
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct View {
    pub id: String,
    pub revision: u64,
    pub kind: Kind,
    pub stage: Stage,
    pub cancel_requested: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closed: Option<ClosedSummary>,
}
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ClosedSummary {
    pub reason: ClosedReason,
    pub accepted: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    username: String,
    credential: String,
    authority: [u8; 32],
    base: Checkpoint,
    challenge: Option<Challenge>,
    proof: Option<Vec<u8>>,
    result: Option<Envelope>,
    cancel: Option<ActivationCancel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    closed: Option<Closure>,
}
impl Drop for Login {
    fn drop(&mut self) {
        self.credential.zeroize();
        if let Some(proof) = &mut self.proof {
            proof.zeroize();
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Data {
    Enable { cancel: Option<EnableCancel> },
    Login(Box<Login>),
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    version: u8,
    id: String,
    revision: u64,
    owner: Owner,
    mode: Enable,
    stage: Stage,
    started: bool,
    cancel_requested: bool,
    data: Data,
}
impl Stored {
    fn view(&self) -> View {
        View {
            id: self.id.clone(),
            revision: self.revision,
            kind: match self.data {
                Data::Enable { .. } => Kind::Enable,
                Data::Login(_) => Kind::Login,
            },
            stage: self.stage,
            cancel_requested: self.cancel_requested,
            closed: match &self.data {
                Data::Login(login) => login.closed.as_ref().map(|c| ClosedSummary {
                    reason: c.reason,
                    accepted: c.accepted,
                }),
                _ => None,
            },
        }
    }
}
/// Private Rust snapshot, deliberately without Serialize, Debug or Clone.
pub struct Task {
    stored: Stored,
}
impl Task {
    pub(crate) fn initial_session(&self, owner: &Owner, keys: &KeyPair) -> Result<Session, String> {
        owner.keys(keys)?;
        if self.stored.owner != *owner || self.stored.stage != Stage::Complete {
            return Err(bad());
        }
        let Data::Login(login) = &self.stored.data else {
            return Err(bad());
        };
        login
            .result
            .as_ref()
            .ok_or_else(bad)?
            .open(login.challenge.as_ref().ok_or_else(bad)?, keys)
            .map_err(|_| bad())
    }
    pub fn view(&self) -> View {
        self.stored.view()
    }
    pub fn enable(&self) -> &Enable {
        &self.stored.mode
    }
    pub fn challenge(&self) -> Option<&Challenge> {
        if let Data::Login(login) = &self.stored.data {
            login.challenge.as_ref()
        } else {
            None
        }
    }
    pub fn proof(&self) -> Result<Option<Proof>, String> {
        if let Data::Login(login) = &self.stored.data {
            login
                .proof
                .as_ref()
                .map(|bytes| serde_json::from_slice(bytes).map_err(|_| bad()))
                .transpose()
        } else {
            Ok(None)
        }
    }
    pub fn start(&self, password: &str) -> Result<Start, String> {
        let Data::Login(login) = &self.stored.data else {
            return Err(bad());
        };
        if !self.stored.started || password.len() > 1024 || password.is_empty() {
            return Err(bad());
        }
        Ok(Start {
            id: self.stored.id.clone(),
            request_token: login.credential.clone(),
            username: login.username.clone(),
            password: password.into(),
            device: self.stored.owner.device.device_id.clone(),
            authorization: login.authority,
        })
    }
    fn credential(&self) -> Result<Zeroizing<String>, String> {
        if let Data::Login(login) = &self.stored.data {
            Ok(Zeroizing::new(login.credential.clone()))
        } else {
            Err(bad())
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sealed {
    domain: String,
    scope: String,
    task: Stored,
}
fn validate(conn: &Connection, owner: &Owner, task: &Stored, keys: &KeyPair) -> Result<(), String> {
    owner.keys(keys)?;
    uuid(&task.id)?;
    if task.version != 1
        || task.owner != *owner
        || task.revision == 0
        || task.revision > i64::MAX as u64
    {
        return Err(bad());
    }
    task.mode.verify_root(&owner.anchor).map_err(|_| bad())?;
    match &task.data {
        Data::Enable { cancel } => {
            if owner.device != owner.anchor.root
                || task.id != task.mode.id
                || matches!(task.stage, Stage::Proving | Stage::Ended)
            {
                return Err(bad());
            }
            let original = t::read_at(
                conn,
                &owner.anchor,
                &Checkpoint {
                    revision: task.mode.revision,
                    hash: task.mode.head.to_vec(),
                },
            )?;
            task.mode.verify_current(&original).map_err(|_| bad())?;
            if let Some(cancel) = cancel {
                cancel.verify(&owner.anchor).map_err(|_| bad())?;
                if cancel.event != task.mode {
                    return Err(bad());
                }
            }
            if task.cancel_requested != cancel.is_some() {
                return Err(bad());
            }
        }
        Data::Login(login) => {
            let original = t::read_at(conn, &owner.anchor, &login.base)?;
            if owner.member(&original)? != login.authority
                || login.username.is_empty()
                || login.username.len() > 128
                || login.username.trim() != login.username
                || login.username.chars().any(char::is_control)
                || login.credential.len() != 64
                || hex::decode(&login.credential).is_err()
            {
                return Err(bad());
            }
            if let Some(challenge) = &login.challenge {
                let checkpoint = Checkpoint {
                    revision: challenge.revision,
                    hash: challenge.head.to_vec(),
                };
                let challenge_state = t::read_at(conn, &owner.anchor, &checkpoint)?;
                challenge
                    .authenticate(&challenge_state, &task.mode, keys)
                    .map_err(|_| bad())?;
                if challenge.id != task.id
                    || challenge.device != owner.device
                    || challenge.authorization != login.authority
                {
                    return Err(bad());
                }
            }
            if let Some(bytes) = &login.proof {
                if bytes.len() > 2048 {
                    return Err(bad());
                }
                let proof: Proof = serde_json::from_slice(bytes).map_err(|_| bad())?;
                proof
                    .verify(login.challenge.as_ref().ok_or_else(bad)?)
                    .map_err(|_| bad())?;
            }
            if let Some(result) = &login.result {
                result
                    .open(login.challenge.as_ref().ok_or_else(bad)?, keys)
                    .map_err(|_| bad())?;
            }
            if task.stage == Stage::Complete && login.result.is_none()
                || !matches!(
                    task.stage,
                    Stage::Complete | Stage::Ended | Stage::Ineligible
                ) && login.result.is_some()
                || task.stage == Stage::Proving && login.proof.is_none()
            {
                return Err(bad());
            }
            if !task.started
                && (login.challenge.is_some() || login.proof.is_some() || login.result.is_some())
            {
                return Err(bad());
            }
            if let Some(cancel) = &login.cancel {
                cancel
                    .verify(&original, &task.mode, &login.credential)
                    .map_err(|_| bad())?;
                if cancel.id != task.id || cancel.device != owner.device {
                    return Err(bad());
                }
            }
            if task.cancel_requested != login.cancel.is_some() {
                return Err(bad());
            }
            if (task.stage == Stage::Ended) != login.closed.is_some() {
                return Err(bad());
            }
            if let Some(closed) = &login.closed {
                let request = Inspection::make(
                    &original,
                    &task.mode,
                    &task.id,
                    &login.credential,
                    &owner.device.device_id,
                    keys,
                )
                .map_err(|_| bad())?;
                closed.verify(&request).map_err(|_| bad())?;
                if login
                    .challenge
                    .as_ref()
                    .is_some_and(|c| c.digest().ok() != closed.challenge)
                    || login.proof.is_some()
                        && closed.reason == ClosedReason::Cancelled
                        && closed.accepted
                    || login.result.is_some() && !closed.accepted
                {
                    return Err(bad());
                }
            }
        }
    }
    if !task.started && !matches!(task.stage, Stage::Prepared | Stage::Cancelled)
        || task.stage == Stage::Prepared && task.started
        || task.stage == Stage::Cancelled && !task.cancel_requested
    {
        return Err(bad());
    }
    Ok(())
}
fn get(conn: &Connection, owner: &Owner, id: &str, keys: &KeyPair) -> Result<Stored, String> {
    uuid(id)?;
    owner.keys(keys)?;
    let mut stmt = conn.prepare("SELECT scope,revision,kind,terminal,body FROM device_control_tasks WHERE scope IN (?1,?2) AND id=?3").map_err(db)?;
    let mut rows = stmt
        .query(params![
            owner.scope(Kind::Enable),
            owner.scope(Kind::Login),
            id
        ])
        .map_err(db)?;
    let row = rows.next().map_err(db)?.ok_or_else(bad)?;
    let scope: String = row.get(0).map_err(db)?;
    let revision: u64 = row.get(1).map_err(db)?;
    let kind: String = row.get(2).map_err(db)?;
    let terminal: bool = row.get(3).map_err(db)?;
    let bytes: Vec<u8> = row.get(4).map_err(db)?;
    if rows.next().map_err(db)?.is_some() {
        return Err(bad());
    }
    if bytes.len() > MAX + 40 {
        return Err(bad());
    }
    let plain = Zeroizing::new(
        crypto::decrypt(&bytes, &keys.public_key, &keys.secret_key).map_err(|_| bad())?,
    );
    if plain.len() > MAX {
        return Err(bad());
    }
    let sealed: Sealed = serde_json::from_slice(&plain).map_err(|_| bad())?;
    let task = sealed.task;
    if sealed.domain != "LiteSeal/activation-task/v1"
        || sealed.scope != scope
        || task.id != id
        || task.revision != revision
        || terminal != task.stage.terminal()
        || kind != kind_name(task.view().kind)
        || scope != owner.scope(task.view().kind)
    {
        return Err(bad());
    }
    validate(conn, owner, &task, keys)?;
    Ok(task)
}
fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Enable => "activation_enable",
        Kind::Login => "activation_login",
    }
}
pub(super) fn legacy_state(
    conn: &Connection,
    anchor: &Anchor,
    keys: &KeyPair,
) -> Result<super::legacy::Admission, String> {
    // Route by the public identity first, so unrelated old test/account IDs do
    // not need to satisfy the newer activation UUID rules when no task exists.
    let owner = Owner {
        anchor: anchor.clone(),
        device: anchor.root.clone(),
    };
    let mut statement = conn
        .prepare("SELECT id FROM device_control_tasks WHERE scope=?1 ORDER BY id LIMIT 129")
        .map_err(db)?;
    let ids = statement
        .query_map([owner.scope(Kind::Enable)], |r| r.get::<_, String>(0))
        .map_err(db)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(db)?;
    if ids.len() > 128 {
        return Err(bad());
    }
    let mut state = super::legacy::Admission::Legacy;
    for id in ids {
        match get(conn, &owner, &id, keys)?.stage {
            Stage::Complete => return Ok(super::legacy::Admission::V3),
            Stage::Cancelled => {}
            _ => state = super::legacy::Admission::Switching,
        }
    }
    Ok(state)
}
fn put(
    conn: &Connection,
    task: Stored,
    keys: &KeyPair,
    previous: Option<u64>,
) -> Result<Stored, String> {
    validate(conn, &task.owner, &task, keys)?;
    let sealed = Sealed {
        domain: "LiteSeal/activation-task/v1".into(),
        scope: task.owner.scope(task.view().kind),
        task,
    };
    let plain = Zeroizing::new(serde_json::to_vec(&sealed).map_err(|_| bad())?);
    if plain.len() > MAX {
        return Err(bad());
    }
    let bytes = crypto::encrypt(&plain, &keys.public_key, &keys.secret_key).map_err(|_| bad())?;
    let task = &sealed.task;
    let count = if let Some(previous) = previous {
        conn.execute("UPDATE device_control_tasks SET revision=?3,kind=?4,terminal=?5,body=?6 WHERE scope=?1 AND id=?2 AND revision=?7",
            params![sealed.scope, task.id, task.revision, kind_name(task.view().kind), task.stage.terminal(), bytes, previous]).map_err(db)?
    } else {
        let count: usize = conn
            .query_row(
                "SELECT COUNT(*) FROM device_control_tasks WHERE scope=?1",
                [&sealed.scope],
                |r| r.get(0),
            )
            .map_err(db)?;
        if count >= 128 {
            return Err("激活任务记录达到上限，请保留原数据".into());
        }
        conn.execute("INSERT INTO device_control_tasks(scope,id,revision,kind,terminal,body) VALUES(?1,?2,?3,?4,?5,?6)",
            params![sealed.scope, task.id, task.revision, kind_name(task.view().kind), task.stage.terminal(), bytes]).map_err(db)?
    };
    if count != 1 {
        return Err(bad());
    }
    Ok(sealed.task)
}
pub struct Store {
    trust: DeviceTrustStore,
    owner: Owner,
}
impl Store {
    pub fn open(
        path: &Path,
        owner: Owner,
        keys: &KeyPair,
        witness: t::witness::Witness,
    ) -> Result<Self, String> {
        owner.keys(keys)?;
        let mut trust = DeviceTrustStore::open(path)?;
        trust.protect(witness)?;
        // Opening a job store is not independent confirmation of a wire root.
        trust.load(&owner.anchor, None)?;
        Ok(Self { trust, owner })
    }
    pub fn task(&mut self, id: &str, keys: &KeyPair) -> Result<Task, String> {
        self.trust
            .read_checked(|conn| get(conn, &self.owner, id, keys).map(|stored| Task { stored }))
    }
    pub fn views(&mut self, keys: &KeyPair) -> Result<Vec<View>, String> {
        self.trust.read_checked(|conn| {
            self.owner.keys(keys)?;
            let mut stmt = conn
                .prepare("SELECT id FROM device_control_tasks WHERE scope IN (?1,?2) ORDER BY id LIMIT 257")
                .map_err(db)?;
            let ids = stmt
                .query_map(params![self.owner.scope(Kind::Enable), self.owner.scope(Kind::Login)], |r| r.get::<_, String>(0))
                .map_err(db)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db)?;
            if ids.len() > 256 {
                return Err(bad());
            }
            ids.into_iter()
                .map(|id| get(conn, &self.owner, &id, keys).map(|task| task.view()))
                .collect()
        })
    }
    pub fn state(&mut self, keys: &KeyPair) -> Result<DeviceState, String> {
        self.owner.keys(keys)?;
        self.trust.load(&self.owner.anchor, None)
    }
    fn original(&mut self, task: &Task, keys: &KeyPair) -> Result<DeviceState, String> {
        self.owner.keys(keys)?;
        let base = match &task.stored.data {
            Data::Enable { .. } => Checkpoint {
                revision: task.stored.mode.revision,
                hash: task.stored.mode.head.to_vec(),
            },
            Data::Login(login) => login.base.clone(),
        };
        let base = task
            .challenge()
            .map(|c| Checkpoint {
                revision: c.revision,
                hash: c.head.to_vec(),
            })
            .unwrap_or(base);
        self.trust.at_checkpoint(&self.owner.anchor, &base)
    }
    pub fn prepare_enable(&mut self, keys: &KeyPair) -> Result<Task, String> {
        self.prepare_enable_inner(keys, false)
    }
    /// Desktop cutover: legacy backlog and the original enable task commit in
    /// one protected SQLite transaction. A failed check creates no new task.
    pub fn prepare_enable_checked(&mut self, keys: &KeyPair) -> Result<Task, String> {
        self.prepare_enable_inner(keys, true)
    }
    fn prepare_enable_inner(&mut self, keys: &KeyPair, checked: bool) -> Result<Task, String> {
        let state = self.state(keys)?;
        if self.owner.device != self.owner.anchor.root {
            return Err(bad());
        }
        let id = uuid::Uuid::new_v4().to_string();
        let mode = Enable::make(&state, &id, keys).map_err(|_| bad())?;
        let task = Stored {
            version: 1,
            id,
            revision: 1,
            owner: self.owner.clone(),
            mode,
            stage: Stage::Prepared,
            started: false,
            cancel_requested: false,
            data: Data::Enable { cancel: None },
        };
        self.trust.write_checked(|conn| {
            if checked
                && super::legacy::admission_in(conn, &self.owner.anchor, keys)?
                    != super::legacy::Admission::Legacy
            {
                return Err("原切换已准备或启用，请查询原任务；不会重建启用事件".into());
            }
            if checked
                && !super::legacy::pending(
                    conn,
                    &self.owner.anchor.account,
                    &self.owner.device.device_id,
                )?
                .empty()
            {
                return Err("本机旧单聊、附件或操作仍待处理；已保留原任务，不能切换".into());
            }
            put(conn, task, keys, None).map(|stored| Task { stored })
        })
    }
    pub fn prepare_login(
        &mut self,
        username: &str,
        mode: Enable,
        keys: &KeyPair,
    ) -> Result<Task, String> {
        let state = self.state(keys)?;
        let login = Login {
            username: username.into(),
            credential: hex::encode(crypto::random_challenge().map_err(|_| bad())?),
            authority: self.owner.member(&state)?,
            base: Checkpoint::from_state(&state),
            challenge: None,
            proof: None,
            result: None,
            cancel: None,
            closed: None,
        };
        let task = Stored {
            version: 1,
            id: uuid::Uuid::new_v4().to_string(),
            revision: 1,
            owner: self.owner.clone(),
            mode,
            stage: Stage::Prepared,
            started: false,
            cancel_requested: false,
            data: Data::Login(Box::new(login)),
        };
        self.trust
            .write_checked(|conn| put(conn, task, keys, None).map(|stored| Task { stored }))
    }
    fn edit(
        &mut self,
        expected: &View,
        keys: &KeyPair,
        change: impl FnOnce(&mut Stored, &Connection) -> Result<(), String>,
    ) -> Result<Task, String> {
        self.trust.write_checked(|conn| {
            let mut task = get(conn, &self.owner, &expected.id, keys)?;
            if task.view() != *expected {
                return Err("激活任务已变化，拒绝迟到结果".into());
            }
            change(&mut task, conn)?;
            task.revision = task.revision.checked_add(1).ok_or_else(bad)?;
            put(conn, task, keys, Some(expected.revision)).map(|stored| Task { stored })
        })
    }
    pub fn begin(&mut self, expected: &View, keys: &KeyPair) -> Result<Task, String> {
        self.edit(expected, keys, |task, _| {
            if task.stage.terminal() || task.cancel_requested {
                return Err(bad());
            }
            task.started = true;
            if task.stage == Stage::Prepared {
                task.stage = Stage::Started;
            }
            Ok(())
        })
    }
    pub fn save_challenge(
        &mut self,
        expected: &View,
        challenge: Challenge,
        keys: &KeyPair,
    ) -> Result<Task, String> {
        self.edit(expected, keys, |task, _| {
            let Data::Login(login) = &mut task.data else {
                return Err(bad());
            };
            if !task.started
                || task.stage.terminal()
                || task.cancel_requested
                || login
                    .challenge
                    .as_ref()
                    .is_some_and(|old| *old != challenge)
            {
                return Err(bad());
            }
            login.challenge = Some(challenge);
            Ok(())
        })
    }
    pub fn seal_proof(&mut self, expected: &View, at: i64, keys: &KeyPair) -> Result<Task, String> {
        self.edit(expected, keys, |task, conn| {
            let Data::Login(login) = &mut task.data else {
                return Err(bad());
            };
            if !task.started || task.stage.terminal() || task.cancel_requested {
                return Err(bad());
            }
            if login.proof.is_none() {
                let challenge = login.challenge.as_ref().ok_or_else(bad)?;
                let checkpoint = Checkpoint {
                    revision: challenge.revision,
                    hash: challenge.head.to_vec(),
                };
                let state = t::read_at(conn, &task.owner.anchor, &checkpoint)?;
                let proof = login
                    .challenge
                    .as_ref()
                    .ok_or_else(bad)?
                    .answer(&state, &task.mode, at, keys)
                    .map_err(|_| bad())?;
                login.proof = Some(serde_json::to_vec(&proof).map_err(|_| bad())?);
            }
            task.stage = Stage::Proving;
            Ok(())
        })
    }
    pub fn request_cancel(&mut self, id: &str, keys: &KeyPair) -> Result<Task, String> {
        let task = self.task(id, keys)?;
        if task.stored.stage.terminal() || task.stored.cancel_requested {
            return Ok(task);
        }
        self.edit(&task.view(), keys, |task, conn| {
            match &mut task.data {
                Data::Enable { cancel } => {
                    *cancel = Some(
                        EnableCancel::make(task.mode.clone(), &task.owner.anchor, keys)
                            .map_err(|_| bad())?,
                    )
                }
                Data::Login(login) => {
                    let state = t::read_at(conn, &task.owner.anchor, &login.base)?;
                    login.cancel = Some(
                        ActivationCancel::make(
                            &state,
                            &task.mode,
                            &task.id,
                            &login.credential,
                            &task.owner.device.device_id,
                            keys,
                        )
                        .map_err(|_| bad())?,
                    );
                }
            }
            task.cancel_requested = true;
            if !task.started {
                task.stage = Stage::Cancelled;
            }
            Ok(())
        })
    }
    pub fn accept_enable(
        &mut self,
        expected: &View,
        event: &Enable,
        keys: &KeyPair,
    ) -> Result<Task, String> {
        self.edit(expected, keys, |task, _| {
            if !matches!(task.data, Data::Enable { .. })
                || !task.started
                || task.stage.terminal()
                || task.mode != *event
            {
                return Err(bad());
            }
            task.stage = Stage::Complete;
            Ok(())
        })
    }
    pub fn accept_session(
        &mut self,
        expected: &View,
        challenge: Challenge,
        envelope: Envelope,
        keys: &KeyPair,
    ) -> Result<Task, String> {
        self.edit(expected, keys, |task, _| {
            let Data::Login(login) = &mut task.data else {
                return Err(bad());
            };
            if !task.started
                || task.stage.terminal()
                || login
                    .challenge
                    .as_ref()
                    .is_some_and(|old| *old != challenge)
            {
                return Err(bad());
            }
            login.challenge = Some(challenge);
            login.result = Some(envelope);
            task.stage = Stage::Complete;
            Ok(())
        })
    }
    fn cancelled(&mut self, expected: &View, keys: &KeyPair) -> Result<Task, String> {
        self.edit(expected, keys, |task, _| {
            if !task.cancel_requested || task.stage.terminal() {
                return Err(bad());
            }
            task.stage = Stage::Cancelled;
            Ok(())
        })
    }
    fn conflict(&mut self, expected: &View, keys: &KeyPair) -> Result<Task, String> {
        self.edit(expected, keys, |task, _| {
            if task.stage.terminal() {
                return Err(bad());
            }
            task.stage = Stage::Conflict;
            Ok(())
        })
    }
    fn ineligible(&mut self, expected: &View, keys: &KeyPair) -> Result<Task, String> {
        self.edit(expected, keys, |task, conn| {
            let Data::Login(login) = &task.data else {
                return Err(bad());
            };
            let current = t::read(conn, &task.owner.anchor, None)?;
            if task.owner.member(&current).ok() == Some(login.authority) {
                return Err(bad());
            }
            task.started = true;
            task.stage = Stage::Ineligible;
            Ok(())
        })
    }
    pub fn session(&mut self, id: &str, keys: &KeyPair) -> Result<Session, String> {
        let task = self.task(id, keys)?;
        let Data::Login(login) = &task.stored.data else {
            return Err(bad());
        };
        let current = self.state(keys)?;
        if task.stored.stage != Stage::Complete || self.owner.member(&current)? != login.authority {
            return Err(bad());
        }
        login
            .result
            .as_ref()
            .ok_or_else(bad)?
            .open(login.challenge.as_ref().ok_or_else(bad)?, keys)
            .map_err(|_| bad())
    }
    /// Only a scoped, authenticated transport result can end an unknown task.
    fn apply_inspected(
        &mut self,
        expected: &View,
        response: super::Inspected,
        keys: &KeyPair,
    ) -> Result<(Task, Condition), String> {
        let condition = match &response.result {
            InspectionResult::Unknown { .. } => Condition::Retry,
            InspectionResult::Pending { .. } => Condition::Pending,
            InspectionResult::Accepted { .. } => Condition::Complete,
            InspectionResult::Closed { .. } => Condition::Ended,
        };
        let task = self.edit(expected, keys, |task, conn| {
            let Data::Login(login) = &mut task.data else {
                return Err(bad());
            };
            let original = t::read_at(conn, &task.owner.anchor, &login.base)?;
            let request = Inspection::make(
                &original,
                &task.mode,
                &task.id,
                &login.credential,
                &task.owner.device.device_id,
                keys,
            )
            .map_err(|_| bad())?;
            if response.request != request
                || task.stage == Stage::Ended
                || task.stage == Stage::Cancelled
                || task.stage == Stage::Ineligible
            {
                return Err(bad());
            }
            match response.result {
                InspectionResult::Unknown { .. } => {
                    if login.result.is_some() {
                        return Err(bad());
                    }
                }
                InspectionResult::Pending { challenge, .. } => {
                    if login.result.is_some()
                        || login.challenge.as_ref().is_some_and(|c| *c != *challenge)
                    {
                        return Err(bad());
                    }
                    login.challenge = Some(*challenge);
                }
                InspectionResult::Accepted {
                    challenge,
                    envelope,
                    ..
                } => {
                    if login.challenge.as_ref().is_some_and(|c| *c != *challenge)
                        || login.result.as_ref().is_some_and(|old| *old != envelope)
                    {
                        return Err(bad());
                    }
                    login.challenge = Some(*challenge);
                    login.result = Some(envelope);
                    task.stage = Stage::Complete;
                }
                InspectionResult::Closed { closure } => {
                    login.closed = Some(*closure);
                    task.stage = Stage::Ended;
                }
            }
            task.started = true;
            if task.stage == Stage::Prepared {
                task.stage = Stage::Started;
            }
            Ok(())
        })?;
        Ok((task, condition))
    }
    pub fn forget_ended(&mut self, id: &str, keys: &KeyPair) -> Result<(), String> {
        self.trust.write_checked(|conn| {
            let task = get(conn, &self.owner, id, keys)?;
            if !matches!(
                task.stage,
                Stage::Ended | Stage::Cancelled | Stage::Ineligible
            ) {
                return Err("只能整理明确结束的任务；请保留原申请".into());
            }
            let changed = conn
                .execute(
                    "DELETE FROM device_control_tasks WHERE scope=?1 AND id=?2 AND revision=?3",
                    params![self.owner.scope(task.view().kind), id, task.revision],
                )
                .map_err(db)?;
            if changed != 1 {
                return Err(bad());
            }
            Ok(())
        })
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Condition {
    Complete,
    Cancelled,
    Ineligible,
    NeedsPassword,
    SessionRequired,
    Retry,
    Conflict,
    Pending,
    Ended,
}
#[derive(Debug, Serialize)]
pub struct Progress {
    pub task: View,
    pub condition: Condition,
    pub http_status: Option<u16>,
}
pub struct Coordinator {
    owner: Owner,
    api: ActivationApi,
    store: Mutex<Store>,
    gate: TaskGate,
    network: tokio::sync::Mutex<()>,
    token: RwLock<Zeroizing<String>>,
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
        drop(DeviceTrustStore::open(path)?);
        let store = Store::open(path, owner.clone(), keys, protection.witness(path)?)?;
        let api = ActivationApi::new(&owner.anchor.origin).map_err(|_| bad())?;
        Ok(Self {
            owner,
            api,
            store: Mutex::new(store),
            gate: TaskGate::new()?,
            network: tokio::sync::Mutex::new(()),
            token: RwLock::new(Zeroizing::new(String::new())),
            _protection: protection,
        })
    }
    fn with<T>(
        &self,
        lease: &t::tasks::TaskLease,
        callback: impl FnOnce(&mut Store) -> Result<T, String>,
    ) -> Result<T, String> {
        self.gate.with_current(lease, || {
            callback(&mut *self.store.lock().map_err(|_| bad())?)
        })
    }
    pub fn renew_session(&self, token: String) -> Result<(), String> {
        let token = Zeroizing::new(token);
        if token.len() > 256 || token.bytes().any(|b| !b.is_ascii_graphic()) {
            return Err(bad());
        }
        self.gate.rotate_with(|| {
            *self.token.write().map_err(|_| bad())? = token;
            Ok(())
        })
    }
    pub fn invalidate(&self) -> Result<(), String> {
        self.gate.invalidate()?;
        self.renew_session(String::new())
    }
    pub fn resume(&self) -> Result<(), String> {
        self.gate.unlock()
    }
    pub async fn discover_mode(&self, keys: &KeyPair) -> Result<Option<Enable>, String> {
        self.owner.keys(keys)?;
        let lease = self.gate.lease()?;
        let _network = self.network.lock().await;
        let state = self.with(&lease, |s| s.state(keys))?;
        let authority = self.owner.member(&state)?;
        let mode = self
            .api
            .discover_mode(&state, &self.owner.device.device_id, keys)
            .await
            .map_err(|e| e.to_string())?;
        self.with(&lease, |s| {
            if self.owner.member(&s.state(keys)?)? != authority {
                return Err(bad());
            }
            Ok(mode)
        })
    }
    pub fn prepare_enable(&self, keys: &KeyPair) -> Result<View, String> {
        let lease = self.gate.lease()?;
        self.with(&lease, |s| s.prepare_enable(keys).map(|t| t.view()))
    }
    pub fn prepare_enable_checked(&self, keys: &KeyPair) -> Result<View, String> {
        let lease = self.gate.lease()?;
        self.with(&lease, |s| s.prepare_enable_checked(keys).map(|t| t.view()))
    }
    pub fn prepare_login(
        &self,
        username: &str,
        mode: Enable,
        keys: &KeyPair,
    ) -> Result<View, String> {
        let lease = self.gate.lease()?;
        self.with(&lease, |s| {
            s.prepare_login(username, mode, keys).map(|t| t.view())
        })
    }
    pub fn views(&self, keys: &KeyPair) -> Result<Vec<View>, String> {
        let lease = self.gate.lease()?;
        self.with(&lease, |s| s.views(keys))
    }
    pub fn request_cancel(&self, id: &str, keys: &KeyPair) -> Result<View, String> {
        let lease = self.gate.lease()?;
        self.with(&lease, |s| s.request_cancel(id, keys).map(|t| t.view()))
    }
    pub fn session(&self, id: &str, keys: &KeyPair) -> Result<Session, String> {
        let lease = self.gate.lease()?;
        self.with(&lease, |s| s.session(id, keys))
    }
    pub fn forget_ended(&self, id: &str, keys: &KeyPair) -> Result<(), String> {
        let lease = self.gate.lease()?;
        self.with(&lease, |s| s.forget_ended(id, keys))
    }
    pub async fn inspect(&self, id: &str, keys: &KeyPair) -> Result<Progress, String> {
        self.owner.keys(keys)?;
        let lease = self.gate.lease()?;
        let _network = self.network.lock().await;
        let mut task = self.with(&lease, |s| s.task(id, keys))?;
        let Data::Login(login) = &task.stored.data else {
            return Err(bad());
        };
        if matches!(
            task.stored.stage,
            Stage::Ended | Stage::Cancelled | Stage::Ineligible
        ) {
            return Ok(Progress {
                condition: match task.stored.stage {
                    Stage::Ended => Condition::Ended,
                    Stage::Cancelled => Condition::Cancelled,
                    _ => Condition::Ineligible,
                },
                task: task.view(),
                http_status: None,
            });
        }
        let current = self.with(&lease, |s| s.state(keys))?;
        if self.owner.member(&current).ok() != Some(login.authority) {
            task = self.with(&lease, |s| s.ineligible(&task.view(), keys))?;
            return Ok(Progress {
                task: task.view(),
                condition: Condition::Ineligible,
                http_status: None,
            });
        }
        if !task.stored.started {
            task = self.with(&lease, |s| s.begin(&task.view(), keys))?;
        }
        let credential = task.credential()?;
        let request = Inspection::make(
            &current,
            &task.stored.mode,
            id,
            &credential,
            &self.owner.device.device_id,
            keys,
        )
        .map_err(|_| bad())?;
        match self
            .api
            .inspect(&credential, &request, &current, &task.stored.mode, keys)
            .await
        {
            Ok(response) => {
                let (task, condition) =
                    self.with(&lease, |s| s.apply_inspected(&task.view(), response, keys))?;
                Ok(Progress {
                    task: task.view(),
                    condition,
                    http_status: None,
                })
            }
            Err(error) => {
                // Failed inspection never becomes a terminal result, even 410.
                self.with(&lease, |s| {
                    if s.task(id, keys)?.view() != task.view() {
                        return Err(bad());
                    }
                    Ok(())
                })?;
                Ok(Progress {
                    task: task.view(),
                    condition: Condition::Retry,
                    http_status: error.status,
                })
            }
        }
    }
    pub async fn step(
        &self,
        id: &str,
        password: Option<&str>,
        keys: &KeyPair,
    ) -> Result<Progress, String> {
        self.owner.keys(keys)?;
        let lease = self.gate.lease()?;
        let _network = self.network.lock().await;
        let mut task = self.with(&lease, |s| s.task(id, keys))?;
        let terminal = match task.stored.stage {
            Stage::Complete => Some(Condition::Complete),
            Stage::Cancelled => Some(Condition::Cancelled),
            Stage::Ineligible => Some(Condition::Ineligible),
            Stage::Ended => Some(Condition::Ended),
            _ => None,
        };
        if let Some(condition) = terminal {
            return Ok(Progress {
                task: task.view(),
                condition,
                http_status: None,
            });
        }
        let current = self.with(&lease, |s| s.state(keys))?;
        if let Data::Login(login) = &task.stored.data {
            if self.owner.member(&current).ok() != Some(login.authority) {
                task = self.with(&lease, |s| s.ineligible(&task.view(), keys))?;
                return Ok(Progress {
                    task: task.view(),
                    condition: Condition::Ineligible,
                    http_status: None,
                });
            }
        }
        if !task.stored.started {
            task = self.with(&lease, |s| s.begin(&task.view(), keys))?;
        }
        let result: Result<Task, super::ActivationError> = match &task.stored.data {
            Data::Enable { cancel } => {
                let token = self
                    .gate
                    .with_current(&lease, || Ok(self.token.read().map_err(|_| bad())?.clone()))?;
                if token.is_empty() {
                    return Ok(Progress {
                        task: task.view(),
                        condition: Condition::SessionRequired,
                        http_status: None,
                    });
                }
                if let Some(cancel) = cancel {
                    match self
                        .api
                        .cancel_enable(&token, cancel, &self.owner.anchor)
                        .await
                    {
                        Ok(EnableCancelResult::Cancelled { .. }) => {
                            Ok(self.with(&lease, |s| s.cancelled(&task.view(), keys))?)
                        }
                        Ok(EnableCancelResult::Accepted { event }) => {
                            Ok(self.with(&lease, |s| s.accept_enable(&task.view(), &event, keys))?)
                        }
                        Err(error) => Err(error),
                    }
                } else {
                    match self.api.status(&token, &self.owner.anchor).await {
                        Ok(Some(event)) if event == task.stored.mode => {
                            Ok(self.with(&lease, |s| s.accept_enable(&task.view(), &event, keys))?)
                        }
                        Ok(Some(_)) => Ok(self.with(&lease, |s| s.conflict(&task.view(), keys))?),
                        Ok(None) => {
                            // Check revision before a follow-up request after a lookup.
                            let current = self.with(&lease, |s| {
                                if s.task(id, keys)?.view() != task.view() {
                                    return Err(bad());
                                }
                                Ok(task.stored.mode.verify_current(&s.state(keys)?).is_ok())
                            })?;
                            if !current {
                                Ok(self.with(&lease, |s| s.conflict(&task.view(), keys))?)
                            } else {
                                match self
                                    .api
                                    .enable(&token, &task.stored.mode, &self.owner.anchor)
                                    .await
                                {
                                    Ok(event) => Ok(self.with(&lease, |s| {
                                        s.accept_enable(&task.view(), &event, keys)
                                    })?),
                                    Err(error) => Err(error),
                                }
                            }
                        }
                        Err(error) => Err(error),
                    }
                }
            }
            Data::Login(login) => {
                let original = self.with(&lease, |s| s.original(&task, keys))?;
                let credential = task.credential()?;
                if let Some(cancel) = &login.cancel {
                    match self
                        .api
                        .cancel(&credential, cancel, &original, &task.stored.mode, keys)
                        .await
                    {
                        Ok(ActivationCancelResult::Cancelled { .. }) => {
                            Ok(self.with(&lease, |s| s.cancelled(&task.view(), keys))?)
                        }
                        Ok(ActivationCancelResult::Accepted {
                            challenge,
                            envelope,
                        }) => Ok(self.with(&lease, |s| {
                            s.accept_session(&task.view(), *challenge, envelope, keys)
                        })?),
                        Err(error) => Err(error),
                    }
                } else {
                    if login.challenge.is_none() {
                        let response = self
                            .api
                            .challenge(&credential, id, &original, &task.stored.mode)
                            .await;
                        let challenge = match response {
                            Ok(challenge) => Ok(challenge),
                            Err(error) if error.status == Some(401) => {
                                if let Data::Login(login) = &task.stored.data {
                                    if Checkpoint::from_state(&current) != login.base {
                                        task =
                                            self.with(&lease, |s| s.conflict(&task.view(), keys))?;
                                        return Ok(Progress {
                                            task: task.view(),
                                            condition: Condition::Conflict,
                                            http_status: None,
                                        });
                                    }
                                }
                                let Some(password) = password else {
                                    self.with(&lease, |s| {
                                        if s.task(id, keys)?.view() != task.view() {
                                            return Err(bad());
                                        }
                                        Ok(())
                                    })?;
                                    return Ok(Progress {
                                        task: task.view(),
                                        condition: Condition::NeedsPassword,
                                        http_status: None,
                                    });
                                };
                                self.with(&lease, |s| {
                                    if s.task(id, keys)?.view() != task.view() {
                                        return Err(bad());
                                    }
                                    Ok(())
                                })?;
                                self.api
                                    .begin(&task.start(password)?, &original, &task.stored.mode)
                                    .await
                            }
                            Err(error) => Err(error),
                        };
                        match challenge {
                            Ok(challenge) => {
                                task = self.with(&lease, |s| {
                                    s.save_challenge(&task.view(), challenge, keys)
                                })?
                            }
                            Err(error) => return self.failed(&lease, task, keys, error),
                        }
                    }
                    if task.proof()?.is_none() {
                        task = self.with(&lease, |s| {
                            s.seal_proof(&task.view(), chrono::Utc::now().timestamp_millis(), keys)
                        })?;
                    }
                    let challenge = task.challenge().ok_or_else(bad)?;
                    let proof = task.proof()?.ok_or_else(bad)?;
                    match self
                        .api
                        .prove_envelope(&credential, challenge, &proof, keys)
                        .await
                    {
                        Ok(envelope) => Ok(self.with(&lease, |s| {
                            s.accept_session(&task.view(), challenge.clone(), envelope, keys)
                        })?),
                        Err(error) => Err(error),
                    }
                }
            }
        };
        match result {
            Ok(task) => Ok(Progress {
                condition: match task.stored.stage {
                    Stage::Complete => Condition::Complete,
                    Stage::Cancelled => Condition::Cancelled,
                    _ => Condition::Conflict,
                },
                task: task.view(),
                http_status: None,
            }),
            Err(error) => self.failed(&lease, task, keys, error),
        }
    }
    fn failed(
        &self,
        lease: &t::tasks::TaskLease,
        task: Task,
        keys: &KeyPair,
        error: super::ActivationError,
    ) -> Result<Progress, String> {
        let task = self.with(lease, |s| {
            if s.task(&task.stored.id, keys)?.view() != task.view() {
                return Err(bad());
            }
            if matches!(error.status, Some(409 | 410)) {
                s.conflict(&task.view(), keys)
            } else {
                Ok(task)
            }
        })?;
        Ok(Progress {
            condition: if matches!(error.status, Some(409 | 410)) {
                Condition::Conflict
            } else {
                Condition::Retry
            },
            task: task.view(),
            http_status: error.status,
        })
    }
}
