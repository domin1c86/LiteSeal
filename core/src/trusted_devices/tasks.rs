//! Durable business tasks. Only encrypted task envelopes reach SQLite; private
//! keys and normal session tokens are never stored here or exposed by TaskView.
use super::{Checkpoint, DeviceTrustStore};
use liteseal_shared::{
    crypto::{self, KeyPair},
    trusted_device::*,
};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Mutex};
use zeroize::Zeroize;
const MAX_TASK_BYTES: usize = 64 * 1024;
pub(super) const SCHEMA:&str="
CREATE TABLE IF NOT EXISTS device_control_tasks (
 scope TEXT NOT NULL,id TEXT NOT NULL,revision INTEGER NOT NULL,kind TEXT NOT NULL,
 terminal INTEGER NOT NULL CHECK(terminal IN (0,1)),body BLOB NOT NULL CHECK(length(body)<=65576),
 PRIMARY KEY(scope,id)
);
CREATE UNIQUE INDEX IF NOT EXISTS device_control_one_pending ON device_control_tasks(scope) WHERE terminal=0;";
fn invalid() -> String {
    "设备任务记录、身份或阶段不符合要求".into()
}
fn stale() -> String {
    "设备任务已变化，请重新查询；不要重建原签名".into()
}
fn db(_: rusqlite::Error) -> String {
    "设备任务存储不可用".into()
}
fn key_check(keys: &KeyPair) -> Result<(), String> {
    let message = b"LiteSeal/device-task-keys/v1";
    let signed = crypto::sign(message, &keys.ed25519_sk).map_err(|_| invalid())?;
    if !crypto::verify_with_public_key(message, &signed, &keys.ed25519_pk).unwrap_or(false) {
        return Err(invalid());
    }
    let peer = crypto::generate_keypair().map_err(|_| invalid())?;
    let boxed =
        crypto::encrypt(message, &peer.public_key, &keys.secret_key).map_err(|_| invalid())?;
    if crypto::decrypt(&boxed, &keys.public_key, &peer.secret_key).map_err(|_| invalid())?
        != message
    {
        return Err(invalid());
    }
    Ok(())
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaskOwner {
    origin: String,
    profile: String,
    device: String,
    encryption: [u8; 32],
    signing: [u8; 32],
    joining: bool,
}
impl TaskOwner {
    pub(super) fn origin(&self) -> &str {
        &self.origin
    }
    pub(super) fn root_anchor(&self) -> Option<Anchor> {
        (!self.joining).then(|| Anchor {
            origin: self.origin.clone(),
            account: self.profile.clone(),
            root: DeviceIdentity {
                device_id: self.device.clone(),
                encryption_key: self.encryption,
                signing_key: self.signing,
            },
        })
    }
    pub fn for_join(
        server: &str,
        username: &str,
        local_device: &str,
        keys: &KeyPair,
    ) -> Result<Self, String> {
        key_check(keys)?;
        if username.trim().is_empty()
            || username.len() > 128
            || username.chars().any(char::is_control)
            || uuid::Uuid::parse_str(local_device).is_err()
        {
            return Err(invalid());
        }
        Ok(Self {
            origin: canonical_origin(server).map_err(|_| invalid())?,
            profile: format!("join:{}", username.trim()),
            device: local_device.into(),
            encryption: keys.public_key,
            signing: keys.ed25519_pk,
            joining: true,
        })
    }
    pub fn for_root(anchor: &Anchor, keys: &KeyPair) -> Result<Self, String> {
        key_check(keys)?;
        anchor.validate().map_err(|_| invalid())?;
        if anchor.root.encryption_key != keys.public_key
            || anchor.root.signing_key != keys.ed25519_pk
        {
            return Err(invalid());
        }
        Ok(Self {
            origin: anchor.origin.clone(),
            profile: anchor.account.clone(),
            device: anchor.root.device_id.clone(),
            encryption: keys.public_key,
            signing: keys.ed25519_pk,
            joining: false,
        })
    }
    fn scope(&self) -> String {
        hex::encode(Sha256::digest(
            serde_json::to_vec(&("LiteSeal/device-task-owner/v1", self))
                .expect("task owner serialization"),
        ))
    }
    pub(super) fn keys(&self, keys: &KeyPair) -> Result<(), String> {
        key_check(keys)?;
        if self.encryption != keys.public_key || self.signing != keys.ed25519_pk {
            Err(invalid())
        } else {
            Ok(())
        }
    }
    fn root(&self, anchor: &Anchor) -> Result<(), String> {
        if self.joining
            || self.origin != anchor.origin
            || self.profile != anchor.account
            || self.device != anchor.root.device_id
            || self.encryption != anchor.root.encryption_key
            || self.signing != anchor.root.signing_key
        {
            return Err(invalid());
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaskPhase {
    Draft,
    AwaitingRootConfirmation,
    AwaitingChallenge,
    AwaitingAuthorization,
    Prepared,
    Cancelling,
    Conflict,
    Complete,
    Cancelled,
    Expired,
    Revoked,
}
impl TaskPhase {
    fn terminal(self) -> bool {
        matches!(
            self,
            Self::Complete | Self::Cancelled | Self::Expired | Self::Revoked
        )
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaskKind {
    Join,
    Challenge,
    Grant,
    Revoke,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JoinData {
    #[serde(default)]
    local_abandonment: bool,
    username: String,
    name: String,
    credential: Option<String>,
    ticket: Option<JoinTicket>,
    confirmed: bool,
    intent: Option<JoinIntent>,
    challenge: Option<Challenge>,
    proof: Option<DeviceProof>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeData {
    anchor: Anchor,
    base: Checkpoint,
    intent: JoinIntent,
    challenge: Challenge,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventData {
    anchor: Anchor,
    base: Checkpoint,
    event: DeviceEvent,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Data {
    Join(Box<JoinData>),
    Challenge(Box<ChallengeData>),
    Event(Box<EventData>),
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredTask {
    version: u8,
    id: String,
    owner: TaskOwner,
    revision: u64,
    phase: TaskPhase,
    data: Data,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    domain: String,
    scope: String,
    task: StoredTask,
}
/// This type deliberately has no Serialize or Debug implementation.
#[derive(Clone)]
pub struct ControlTask {
    inner: StoredTask,
}
#[derive(Debug, Serialize)]
pub struct TaskView {
    pub id: String,
    pub kind: TaskKind,
    pub phase: TaskPhase,
    pub revision: u64,
    pub request_id: Option<String>,
    pub event_id: Option<String>,
    pub root_fingerprint: Option<String>,
}
pub fn anchor_fingerprint(anchor: &Anchor) -> String {
    hex::encode(anchor.hash())
}
impl ControlTask {
    pub fn local_abandonment(&self) -> bool {
        matches!(&self.inner.data, Data::Join(data) if data.local_abandonment)
    }
    pub(super) fn same_ticket(&self, status: &JoinStatus) -> bool {
        self.ticket().is_some_and(|ticket| ticket == &status.ticket)
            && self
                .intent()
                .is_none_or(|intent| status.intent.as_ref().is_none_or(|other| intent == other))
            && self.challenge().is_none_or(|challenge| {
                status
                    .challenge
                    .as_ref()
                    .is_none_or(|other| challenge == other)
            })
            && self
                .proof()
                .is_none_or(|proof| status.proof.as_ref().is_none_or(|other| proof == other))
    }
    pub fn view(&self) -> TaskView {
        let (kind, request_id, event_id, anchor) = match &self.inner.data {
            Data::Join(data) => (
                TaskKind::Join,
                Some(self.inner.id.clone()),
                None,
                data.ticket.as_ref().map(|x| &x.anchor),
            ),
            Data::Challenge(data) => (
                TaskKind::Challenge,
                Some(data.intent.id.clone()),
                None,
                Some(&data.anchor),
            ),
            Data::Event(data) => (
                if matches!(data.event.action, DeviceAction::Grant { .. }) {
                    TaskKind::Grant
                } else {
                    TaskKind::Revoke
                },
                None,
                Some(data.event.id.clone()),
                Some(&data.anchor),
            ),
        };
        TaskView {
            id: self.inner.id.clone(),
            kind,
            phase: self.inner.phase,
            revision: self.inner.revision,
            request_id,
            event_id,
            root_fingerprint: anchor.map(anchor_fingerprint),
        }
    }
    /// Rust-only request construction. Password is supplied afresh and never saved.
    pub fn start_request(&self, password: &str) -> Result<JoinStartRequest, String> {
        let Data::Join(data) = &self.inner.data else {
            return Err(invalid());
        };
        if self.inner.phase != TaskPhase::Draft {
            return Err(invalid());
        }
        Ok(JoinStartRequest {
            request_id: self.inner.id.clone(),
            request_token: data.credential.clone().ok_or_else(invalid)?,
            username: data.username.clone(),
            password: password.into(),
            device_name: data.name.clone(),
            encryption_key: self.inner.owner.encryption,
            signing_key: self.inner.owner.signing,
        })
    }
    pub fn join_credential(&self) -> Result<&str, String> {
        match &self.inner.data {
            Data::Join(data) => data.credential.as_deref().ok_or_else(invalid),
            _ => Err(invalid()),
        }
    }
    pub fn ticket(&self) -> Option<&JoinTicket> {
        if let Data::Join(data) = &self.inner.data {
            data.ticket.as_ref()
        } else {
            None
        }
    }
    pub fn intent(&self) -> Option<&JoinIntent> {
        match &self.inner.data {
            Data::Join(data) => data.intent.as_ref(),
            Data::Challenge(data) => Some(&data.intent),
            _ => None,
        }
    }
    pub fn challenge(&self) -> Option<&Challenge> {
        match &self.inner.data {
            Data::Join(data) => data.challenge.as_ref(),
            Data::Challenge(data) => Some(&data.challenge),
            _ => None,
        }
    }
    pub fn proof(&self) -> Option<&DeviceProof> {
        if let Data::Join(data) = &self.inner.data {
            data.proof.as_ref()
        } else {
            None
        }
    }
    pub fn event(&self) -> Option<&DeviceEvent> {
        if let Data::Event(data) = &self.inner.data {
            Some(&data.event)
        } else {
            None
        }
    }
}
pub struct DeviceTaskStore {
    trust: DeviceTrustStore,
    owner: TaskOwner,
}
impl DeviceTaskStore {
    pub(super) fn abandon_unsigned_join(
        &mut self,
        task: &ControlTask,
        keys: &KeyPair,
    ) -> Result<ControlTask, String> {
        let Data::Join(data) = &task.inner.data else {
            return Err(invalid());
        };
        // No intent was ever signed: even a delayed begin cannot admit this device.
        // This is local abandonment, not evidence that the remote row was removed.
        if task.inner.phase != TaskPhase::Cancelling
            || data.intent.is_some()
            || data.confirmed
            || data.challenge.is_some()
            || data.proof.is_some()
        {
            return Err(invalid());
        }
        let mut next = task.inner.clone();
        if let Data::Join(data) = &mut next.data {
            data.local_abandonment = true;
        }
        next.phase = TaskPhase::Cancelled;
        self.replace(task, next, keys)
    }
    pub(super) fn confirm_authorized_challenge(
        &mut self,
        task: &ControlTask,
        status: &JoinStatus,
        keys: &KeyPair,
    ) -> Result<ControlTask, String> {
        let Data::Challenge(data) = &task.inner.data else {
            return Err(invalid());
        };
        if task.inner.phase != TaskPhase::Cancelling || status.phase != JoinPhase::Authorized {
            return Err(invalid());
        }
        let (_, bytes) = self.verified_event(
            &data.anchor,
            status.authorization_id.as_deref().ok_or_else(invalid)?,
        )?;
        let bytes = bytes.ok_or_else(invalid)?;
        let event: DeviceEvent = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        let DeviceAction::Grant {
            intent, challenge, ..
        } = event.action
        else {
            return Err(invalid());
        };
        if *intent != data.intent
            || *challenge != data.challenge
            || !status.ticket.matches(&data.intent)
            || status.intent.as_ref() != Some(&data.intent)
            || status.challenge.as_ref() != Some(&data.challenge)
        {
            return Err(invalid());
        }
        let mut next = task.inner.clone();
        next.phase = TaskPhase::Complete;
        self.replace(task, next, keys)
    }
    pub(super) fn challenge_terminal(
        &mut self,
        task: &ControlTask,
        status: &JoinStatus,
        keys: &KeyPair,
    ) -> Result<ControlTask, String> {
        let Data::Challenge(data) = &task.inner.data else {
            return Err(invalid());
        };
        if !status.ticket.matches(&data.intent)
            || !matches!(status.phase, JoinPhase::Cancelled | JoinPhase::Expired)
        {
            return Err(invalid());
        }
        let mut next = task.inner.clone();
        next.phase = if status.phase == JoinPhase::Cancelled {
            TaskPhase::Cancelled
        } else {
            TaskPhase::Expired
        };
        self.replace(task, next, keys)
    }
    pub(super) fn join_terminal(
        &mut self,
        task: &ControlTask,
        status: &JoinStatus,
        keys: &KeyPair,
    ) -> Result<ControlTask, String> {
        if !matches!(status.phase, JoinPhase::Cancelled | JoinPhase::Expired)
            || !task.same_ticket(status)
        {
            return Err(invalid());
        }
        let mut next = task.inner.clone();
        next.phase = if status.phase == JoinPhase::Cancelled {
            TaskPhase::Cancelled
        } else {
            TaskPhase::Expired
        };
        self.replace(task, next, keys)
    }
    pub(super) fn event_accepted(&mut self, task: &ControlTask) -> Result<bool, String> {
        let Data::Event(data) = &task.inner.data else {
            return Err(invalid());
        };
        let (current, digest) = self.verified_event(&data.anchor, &data.event.id)?;
        if current.revision() < data.event.revision {
            return Ok(false);
        }
        let digest = digest.unwrap_or_default();
        if digest.is_empty() {
            return Ok(false);
        }
        let event: DeviceEvent = serde_json::from_slice(&digest).map_err(|_| invalid())?;
        if event.hash() != data.event.hash() {
            return Err(invalid());
        }
        Ok(true)
    }
    pub(super) fn base_matches(&mut self, task: &ControlTask, current: &DeviceState) -> bool {
        match &task.inner.data {
            Data::Event(data) => {
                data.anchor == *current.anchor() && data.base == Checkpoint::from_state(current)
            }
            Data::Challenge(data) => {
                data.anchor == *current.anchor() && data.base == Checkpoint::from_state(current)
            }
            _ => false,
        }
    }
    pub fn open(path: &Path, owner: TaskOwner, keys: &KeyPair) -> Result<Self, String> {
        owner.keys(keys)?;
        let trust = DeviceTrustStore::open(path)?;
        trust.conn.execute_batch(SCHEMA).map_err(db)?;
        Ok(Self { trust, owner })
    }
    pub fn protect(&mut self, witness: super::witness::Witness) -> Result<(), String> {
        self.trust.protect(witness)
    }
    /// Caller verifies pages through this store, without holding a SQLite lock across await.
    pub fn trust(&mut self) -> &mut DeviceTrustStore {
        &mut self.trust
    }
    fn verified_event(
        &mut self,
        anchor: &Anchor,
        id: &str,
    ) -> Result<(DeviceState, Option<Vec<u8>>), String> {
        self.trust.read_checked(|conn| {
            let state = super::read(conn, anchor, None)?;
            let bytes = conn.query_row("SELECT payload FROM trusted_device_events WHERE origin=?1 AND account=?2 AND event_id=?3",
                params![anchor.origin,anchor.account,id],|r|r.get(0)).optional().map_err(db)?;
            Ok((state, bytes))
        })
    }
    fn historical(&mut self, anchor: &Anchor, base: &Checkpoint) -> Result<DeviceState, String> {
        self.trust.read_checked(|conn| {
        super::read(conn, anchor, Some(base))?;
        let mut state = DeviceState::pin(anchor.clone()).map_err(|_| invalid())?;
        let mut query=conn.prepare("SELECT payload FROM trusted_device_events WHERE origin=?1 AND account=?2 AND revision<=?3 ORDER BY revision").map_err(db)?;
        let rows = query
            .query_map(params![anchor.origin, anchor.account, base.revision], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .map_err(db)?;
        for row in rows {
            let payload = row.map_err(db)?;
            if payload.len() > MAX_DEVICE_EVENT_BYTES {
                return Err(invalid());
            }
            let event: DeviceEvent = serde_json::from_slice(&payload).map_err(|_| invalid())?;
            state = state.apply(&event).map_err(|_| invalid())?;
        }
        if Checkpoint::from_state(&state) != *base {
            return Err(invalid());
        }
        Ok(state)
        })
    }
    fn validate(&mut self, task: &StoredTask, keys: &KeyPair) -> Result<(), String> {
        self.owner.keys(keys)?;
        if task.version != 1
            || task.owner != self.owner
            || uuid::Uuid::parse_str(&task.id).is_err()
            || task.revision > 1_000_000
        {
            return Err(invalid());
        }
        match &task.data {
            Data::Join(data) => {
                if !self.owner.joining
                    || data.local_abandonment
                        && (task.phase != TaskPhase::Cancelled
                            || data.confirmed
                            || data.intent.is_some()
                            || data.challenge.is_some()
                            || data.proof.is_some())
                    || self.owner.profile != format!("join:{}", data.username)
                    || data.name.trim().is_empty()
                    || data.name.chars().count() > 80
                    || data.name.chars().any(char::is_control)
                    || !task.phase.terminal()
                        && data.credential.as_ref().is_none_or(|v| {
                            v.len() != 64 || !v.bytes().all(|b| b.is_ascii_hexdigit())
                        })
                {
                    return Err(invalid());
                }
                if let Some(ticket) = &data.ticket {
                    if ticket.id != task.id
                        || ticket.device.encryption_key != keys.public_key
                        || ticket.device.signing_key != keys.ed25519_pk
                        || ticket.anchor.origin != self.owner.origin
                        || ticket.device_name != data.name
                    {
                        return Err(invalid());
                    }
                    ticket.anchor.validate().map_err(|_| invalid())?;
                    if data.confirmed {
                        self.trust.load(&ticket.anchor, None)?;
                    }
                    if let Some(intent) = &data.intent {
                        if !data.confirmed || !ticket.matches(intent) {
                            return Err(invalid());
                        }
                        intent
                            .verify(&ticket.anchor, intent.issued_at)
                            .map_err(|_| invalid())?;
                    }
                    if let Some(challenge) = &data.challenge {
                        let intent = data.intent.as_ref().ok_or_else(invalid)?;
                        let base = Checkpoint {
                            revision: challenge.revision.checked_sub(1).ok_or_else(invalid)?,
                            hash: challenge.previous.clone(),
                        };
                        challenge
                            .verify(
                                &self.historical(&ticket.anchor, &base)?,
                                intent,
                                challenge.issued_at,
                            )
                            .map_err(|_| invalid())?;
                    }
                    if let Some(proof) = &data.proof {
                        proof
                            .verify(data.challenge.as_ref().ok_or_else(invalid)?, &ticket.device)
                            .map_err(|_| invalid())?;
                    }
                } else if data.confirmed
                    || data.intent.is_some()
                    || data.challenge.is_some()
                    || data.proof.is_some()
                {
                    return Err(invalid());
                }
            }
            Data::Challenge(data) => {
                self.owner.root(&data.anchor)?;
                data.challenge
                    .verify(
                        &self.historical(&data.anchor, &data.base)?,
                        &data.intent,
                        data.challenge.issued_at,
                    )
                    .map_err(|_| invalid())?;
            }
            Data::Event(data) => {
                self.owner.root(&data.anchor)?;
                self.historical(&data.anchor, &data.base)?
                    .apply(&data.event)
                    .map_err(|_| invalid())?;
            }
        }
        Ok(())
    }
    fn encrypted(&self, task: &StoredTask, keys: &KeyPair) -> Result<Vec<u8>, String> {
        let mut plain = serde_json::to_vec(&Envelope {
            domain: "LiteSeal/device-task-local/v1".into(),
            scope: self.owner.scope(),
            task: task.clone(),
        })
        .map_err(|_| invalid())?;
        if plain.len() > MAX_TASK_BYTES {
            plain.zeroize();
            return Err(invalid());
        }
        let result =
            crypto::encrypt(&plain, &keys.public_key, &keys.secret_key).map_err(|_| invalid());
        plain.zeroize();
        result
    }
    fn kind(task: &StoredTask) -> &'static str {
        match &task.data {
            Data::Join(_) => "join",
            Data::Challenge(_) => "challenge",
            Data::Event(data) => {
                if matches!(data.event.action, DeviceAction::Grant { .. }) {
                    "grant"
                } else {
                    "revoke"
                }
            }
        }
    }
    fn insert(&mut self, task: StoredTask, keys: &KeyPair) -> Result<ControlTask, String> {
        self.validate(&task, keys)?;
        let body = self.encrypted(&task, keys)?;
        let scope = self.owner.scope();
        self.trust.write_checked(|tx|{
        let count: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM device_control_tasks WHERE scope=?1",
                params![scope],
                |r| r.get(0),
            )
            .map_err(db)?;
        if count >= 128 {
            return Err("设备任务数量达到上限，请整理已完成任务".into());
        }
        tx.execute("INSERT INTO device_control_tasks(scope,id,revision,kind,terminal,body) VALUES(?1,?2,?3,?4,?5,?6)",
            params![scope,task.id,task.revision,Self::kind(&task),task.phase.terminal(),body]).map_err(|_|"已有待处理设备任务，请查询或取消原任务".to_string())?;
        Ok(())})?;
        Ok(ControlTask { inner: task })
    }
    fn replace(
        &mut self,
        original: &ControlTask,
        mut task: StoredTask,
        keys: &KeyPair,
    ) -> Result<ControlTask, String> {
        if original.inner.owner != self.owner || original.inner.id != task.id {
            return Err(invalid());
        }
        task.revision = original.inner.revision.checked_add(1).ok_or_else(invalid)?;
        if task.phase.terminal() {
            if let Data::Join(data) = &mut task.data {
                if let Some(mut token) = data.credential.take() {
                    token.zeroize();
                }
            }
        }
        self.validate(&task, keys)?;
        let body = self.encrypted(&task, keys)?;
        let scope = self.owner.scope();
        self.trust.write_checked(|tx|{
        let changed=tx.execute("UPDATE device_control_tasks SET revision=?4,kind=?5,terminal=?6,body=?7 WHERE scope=?1 AND id=?2 AND revision=?3",
            params![scope,task.id,original.inner.revision,task.revision,Self::kind(&task),task.phase.terminal(),body]).map_err(db)?;
        if changed != 1 {
            return Err(stale());
        }
        Ok(())})?;
        Ok(ControlTask { inner: task })
    }
    pub fn get(&mut self, id: &str, keys: &KeyPair) -> Result<ControlTask, String> {
        self.owner.keys(keys)?;
        let scope = self.owner.scope();
        let (revision,kind,terminal,body):(u64,String,bool,Vec<u8>)=self.trust.read_checked(|conn|conn.query_row("SELECT revision,kind,terminal,body FROM device_control_tasks WHERE scope=?1 AND id=?2",
            params![scope,id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).map_err(|_|invalid()))?;
        if body.len() > MAX_TASK_BYTES + 40 {
            return Err(invalid());
        }
        let mut plain =
            crypto::decrypt(&body, &keys.public_key, &keys.secret_key).map_err(|_| invalid())?;
        let envelope = serde_json::from_slice::<Envelope>(&plain).map_err(|_| invalid());
        plain.zeroize();
        let envelope = envelope?;
        if envelope.domain != "LiteSeal/device-task-local/v1"
            || envelope.scope != self.owner.scope()
            || envelope.task.id != id
            || envelope.task.revision != revision
            || Self::kind(&envelope.task) != kind
            || envelope.task.phase.terminal() != terminal
        {
            return Err(invalid());
        }
        self.validate(&envelope.task, keys)?;
        Ok(ControlTask {
            inner: envelope.task,
        })
    }
    pub fn views(&mut self, keys: &KeyPair) -> Result<Vec<TaskView>, String> {
        let scope = self.owner.scope();
        let ids: Vec<String> = self.trust.read_checked(|conn| {
            let mut q = conn
                .prepare(
                    "SELECT id FROM device_control_tasks WHERE scope=?1 ORDER BY rowid LIMIT 129",
                )
                .map_err(db)?;
            let rows = q.query_map(params![scope], |r| r.get(0)).map_err(db)?;
            rows.collect::<Result<_, _>>().map_err(db)
        })?;
        if ids.len() > 128 {
            return Err(invalid());
        }
        ids.iter()
            .map(|id| self.get(id, keys).map(|t| t.view()))
            .collect()
    }
    fn new_task(&self, data: Data, phase: TaskPhase) -> StoredTask {
        StoredTask {
            version: 1,
            id: uuid::Uuid::new_v4().to_string(),
            owner: self.owner.clone(),
            revision: 0,
            phase,
            data,
        }
    }
    pub fn prepare_join(&mut self, name: &str, keys: &KeyPair) -> Result<ControlTask, String> {
        self.prepare_join_with_id(&uuid::Uuid::new_v4().to_string(), name, keys)
    }
    pub(super) fn prepare_join_with_id(
        &mut self,
        id: &str,
        name: &str,
        keys: &KeyPair,
    ) -> Result<ControlTask, String> {
        uuid::Uuid::parse_str(id).map_err(|_| invalid())?;
        let username = self
            .owner
            .profile
            .strip_prefix("join:")
            .ok_or_else(invalid)?
            .to_string();
        let mut task = self.new_task(
            Data::Join(Box::new(JoinData {
                local_abandonment: false,
                username,
                name: name.into(),
                credential: Some(hex::encode(
                    crypto::random_challenge().map_err(|_| invalid())?,
                )),
                ticket: None,
                confirmed: false,
                intent: None,
                challenge: None,
                proof: None,
            })),
            TaskPhase::Draft,
        );
        task.id = id.into();
        self.insert(task, keys)
    }
    pub fn accept_ticket(
        &mut self,
        task: &ControlTask,
        status: &JoinStatus,
        keys: &KeyPair,
    ) -> Result<ControlTask, String> {
        if task.inner.phase != TaskPhase::Draft {
            return Err(invalid());
        }
        let mut next = task.inner.clone();
        let Data::Join(data) = &mut next.data else {
            return Err(invalid());
        };
        if status.phase != JoinPhase::Begun {
            return Err(invalid());
        }
        data.ticket = Some(status.ticket.clone());
        next.phase = TaskPhase::AwaitingRootConfirmation;
        self.replace(task, next, keys)
    }
    pub fn confirm_root(
        &mut self,
        task: &ControlTask,
        known: &Anchor,
        fingerprint: &str,
        keys: &KeyPair,
    ) -> Result<ControlTask, String> {
        if task.inner.phase != TaskPhase::AwaitingRootConfirmation {
            return Err(invalid());
        }
        let mut next = task.inner.clone();
        let Data::Join(data) = &mut next.data else {
            return Err(invalid());
        };
        let ticket = data.ticket.as_ref().ok_or_else(invalid)?;
        if ticket.anchor != *known || anchor_fingerprint(known) != fingerprint {
            return Err(invalid());
        }
        self.owner.keys(keys)?;
        data.confirmed = true;
        data.intent = Some(ticket.sign_intent(keys).map_err(|_| invalid())?);
        next.phase = TaskPhase::AwaitingChallenge;
        next.revision = task.inner.revision.checked_add(1).ok_or_else(invalid)?;
        if next.revision > 1_000_000 {
            return Err(invalid());
        }
        let body = self.encrypted(&next, keys)?;
        let scope = self.owner.scope();
        let initial = DeviceState::pin(known.clone()).map_err(|_| invalid())?;
        self.trust.write_checked(|tx|{
        tx.execute("INSERT OR IGNORE INTO trusted_device_anchors(origin,account,anchor,revision,head) VALUES(?1,?2,?3,0,?4)",
            params![known.origin,known.account,serde_json::to_vec(known).map_err(|_|invalid())?,initial.head()]).map_err(db)?;
        super::read(tx, known, None)?;
        let changed=tx.execute("UPDATE device_control_tasks SET revision=?4,body=?5 WHERE scope=?1 AND id=?2 AND revision=?3 AND terminal=0",
            params![scope,next.id,task.inner.revision,next.revision,body]).map_err(db)?;
        if changed != 1 {
            return Err(stale());
        }
        Ok(())})?;
        Ok(ControlTask { inner: next })
    }
    pub fn seal_proof(
        &mut self,
        task: &ControlTask,
        state: &DeviceState,
        challenge: &Challenge,
        at: i64,
        keys: &KeyPair,
    ) -> Result<ControlTask, String> {
        if task.inner.phase != TaskPhase::AwaitingChallenge {
            return Err(invalid());
        }
        let mut next = task.inner.clone();
        let Data::Join(data) = &mut next.data else {
            return Err(invalid());
        };
        if data
            .ticket
            .as_ref()
            .is_none_or(|t| t.anchor != *state.anchor())
        {
            return Err(invalid());
        }
        self.historical(state.anchor(), &Checkpoint::from_state(state))?;
        data.proof = Some(
            answer_challenge(
                state,
                data.intent.as_ref().ok_or_else(invalid)?,
                challenge,
                at,
                keys,
            )
            .map_err(|_| invalid())?,
        );
        data.challenge = Some(challenge.clone());
        next.phase = TaskPhase::AwaitingAuthorization;
        self.replace(task, next, keys)
    }
    pub fn prepare_challenge(
        &mut self,
        state: &DeviceState,
        intent: &JoinIntent,
        at: i64,
        keys: &KeyPair,
    ) -> Result<ControlTask, String> {
        self.owner.root(state.anchor())?;
        self.trust.pin(state.anchor())?;
        self.historical(state.anchor(), &Checkpoint::from_state(state))?;
        let challenge = make_challenge(state, intent, at, keys).map_err(|_| invalid())?;
        let data = ChallengeData {
            anchor: state.anchor().clone(),
            base: Checkpoint::from_state(state),
            intent: intent.clone(),
            challenge,
        };
        let task = self.new_task(Data::Challenge(Box::new(data)), TaskPhase::Prepared);
        self.insert(task, keys)
    }
    fn prepare_event(
        &mut self,
        state: &DeviceState,
        action: DeviceAction,
        at: i64,
        keys: &KeyPair,
    ) -> Result<ControlTask, String> {
        self.owner.root(state.anchor())?;
        self.trust.pin(state.anchor())?;
        self.historical(state.anchor(), &Checkpoint::from_state(state))?;
        let event = make_event(state, uuid::Uuid::new_v4().to_string(), action, at, keys)
            .map_err(|_| invalid())?;
        let data = EventData {
            anchor: state.anchor().clone(),
            base: Checkpoint::from_state(state),
            event,
        };
        let task = self.new_task(Data::Event(Box::new(data)), TaskPhase::Prepared);
        self.insert(task, keys)
    }
    pub fn prepare_grant(
        &mut self,
        state: &DeviceState,
        status: &JoinStatus,
        at: i64,
        keys: &KeyPair,
    ) -> Result<ControlTask, String> {
        if status.phase != JoinPhase::Proved || status.ticket.anchor != *state.anchor() {
            return Err(invalid());
        }
        let intent = status.intent.clone().ok_or_else(invalid)?;
        if !status.ticket.matches(&intent) {
            return Err(invalid());
        }
        self.prepare_event(
            state,
            DeviceAction::Grant {
                intent: Box::new(intent),
                challenge: Box::new(status.challenge.clone().ok_or_else(invalid)?),
                proof: status.proof.clone().ok_or_else(invalid)?,
            },
            at,
            keys,
        )
    }
    pub fn prepare_revoke(
        &mut self,
        state: &DeviceState,
        at: i64,
        keys: &KeyPair,
    ) -> Result<ControlTask, String> {
        let device = state.secondary().ok_or_else(invalid)?;
        self.prepare_event(
            state,
            DeviceAction::Revoke {
                device_id: device.device_id.clone(),
                grant_hash: state.grant_hash().ok_or_else(invalid)?.to_vec(),
            },
            at,
            keys,
        )
    }
    pub fn request_cancel(
        &mut self,
        task: &ControlTask,
        keys: &KeyPair,
    ) -> Result<ControlTask, String> {
        if task.inner.phase.terminal() {
            return Err(invalid());
        }
        let mut next = task.inner.clone();
        next.phase = TaskPhase::Cancelling;
        self.replace(task, next, keys)
    }
    pub fn mark_conflict(
        &mut self,
        task: &ControlTask,
        keys: &KeyPair,
    ) -> Result<ControlTask, String> {
        if task.inner.phase.terminal() || task.inner.phase == TaskPhase::Cancelling {
            return Err(invalid());
        }
        let mut next = task.inner.clone();
        next.phase = TaskPhase::Conflict;
        self.replace(task, next, keys)
    }
    pub fn confirm_challenge(
        &mut self,
        task: &ControlTask,
        status: &JoinStatus,
        keys: &KeyPair,
    ) -> Result<ControlTask, String> {
        if task.inner.phase != TaskPhase::Prepared {
            return Err(invalid());
        }
        let Data::Challenge(data) = &task.inner.data else {
            return Err(invalid());
        };
        if !status.ticket.matches(&data.intent)
            || status.intent.as_ref() != Some(&data.intent)
            || status.challenge.as_ref() != Some(&data.challenge)
            || !matches!(
                status.phase,
                JoinPhase::Challenged | JoinPhase::Proved | JoinPhase::Authorized
            )
        {
            return Err(invalid());
        }
        let mut next = task.inner.clone();
        next.phase = TaskPhase::Complete;
        self.replace(task, next, keys)
    }
    pub fn confirm_event_accepted(
        &mut self,
        task: &ControlTask,
        keys: &KeyPair,
    ) -> Result<ControlTask, String> {
        if task.inner.phase.terminal() {
            return Err(invalid());
        }
        let Data::Event(data) = &task.inner.data else {
            return Err(invalid());
        };
        self.historical(
            &data.anchor,
            &Checkpoint {
                revision: data.event.revision,
                hash: data.event.hash(),
            },
        )?;
        let mut next = task.inner.clone();
        next.phase = TaskPhase::Complete;
        self.replace(task, next, keys)
    }
    pub fn confirm_event_cancel(
        &mut self,
        task: &ControlTask,
        result: &DeviceCancelResult,
        keys: &KeyPair,
    ) -> Result<ControlTask, String> {
        if task.inner.phase != TaskPhase::Cancelling {
            return Err(invalid());
        }
        let Data::Event(data) = &task.inner.data else {
            return Err(invalid());
        };
        if result.cancelled && result.receipt.is_none() {
            let mut next = task.inner.clone();
            next.phase = TaskPhase::Cancelled;
            self.replace(task, next, keys)
        } else if let Some(receipt) = &result.receipt {
            if result.cancelled
                || receipt.event_id != data.event.id
                || receipt.event_hash != data.event.hash()
            {
                return Err(invalid());
            }
            self.confirm_event_accepted(task, keys)
        } else {
            Err(invalid())
        }
    }
    pub fn confirm_join_cancel(
        &mut self,
        task: &ControlTask,
        status: &JoinStatus,
        keys: &KeyPair,
    ) -> Result<ControlTask, String> {
        if task.inner.phase != TaskPhase::Cancelling || status.phase != JoinPhase::Cancelled {
            return Err(invalid());
        }
        let mut next = task.inner.clone();
        match &mut next.data {
            Data::Join(data) => {
                if data.ticket.as_ref().is_some_and(|t| t != &status.ticket) {
                    return Err(invalid());
                }
                data.ticket = Some(status.ticket.clone());
            }
            Data::Challenge(data) => {
                if !status.ticket.matches(&data.intent) {
                    return Err(invalid());
                }
            }
            _ => return Err(invalid()),
        }
        next.phase = TaskPhase::Cancelled;
        self.replace(task, next, keys)
    }
    pub fn confirm_join_authorized(
        &mut self,
        task: &ControlTask,
        event_id: &str,
        keys: &KeyPair,
    ) -> Result<ControlTask, String> {
        if !matches!(
            task.inner.phase,
            TaskPhase::AwaitingAuthorization | TaskPhase::Cancelling | TaskPhase::Conflict
        ) {
            return Err(invalid());
        }
        let Data::Join(data) = &task.inner.data else {
            return Err(invalid());
        };
        let ticket = data.ticket.as_ref().ok_or_else(invalid)?;
        let (current, payload) = self.verified_event(&ticket.anchor, event_id)?;
        let payload = payload.ok_or_else(invalid)?;
        let event: DeviceEvent = serde_json::from_slice(&payload).map_err(|_| invalid())?;
        let DeviceAction::Grant {
            intent,
            challenge,
            proof,
        } = &event.action
        else {
            return Err(invalid());
        };
        if data.intent.as_ref() != Some(intent.as_ref())
            || data.challenge.as_ref() != Some(challenge.as_ref())
            || data.proof.as_ref() != Some(proof)
        {
            return Err(invalid());
        }
        let mut next = task.inner.clone();
        next.phase = if current.secondary() == Some(&ticket.device) {
            TaskPhase::Complete
        } else {
            TaskPhase::Revoked
        };
        self.replace(task, next, keys)
    }
    pub fn discard_terminal(&mut self, task: &ControlTask, keys: &KeyPair) -> Result<(), String> {
        self.owner.keys(keys)?;
        if !task.inner.phase.terminal() || task.inner.owner != self.owner {
            return Err(invalid());
        }
        let scope = self.owner.scope();
        self.trust.write_checked(|tx|{
        let deleted=tx.execute("DELETE FROM device_control_tasks WHERE scope=?1 AND id=?2 AND revision=?3 AND terminal=1",params![scope,task.inner.id,task.inner.revision]).map_err(db)?;
        if deleted != 1 {
            return Err(stale());
        }
        Ok(())})
    }
}
/// An invalidation waits for an in-progress synchronous commit, but never for
/// network I/O. Only synchronous callbacks belong inside `with_current`.
pub struct TaskGate {
    state: Mutex<GateState>,
}
struct GateState {
    id: [u8; 32],
    generation: u64,
    open: bool,
}
#[derive(Clone)]
pub struct TaskLease {
    id: [u8; 32],
    generation: u64,
}
impl TaskGate {
    pub(super) fn rotate_with<T>(
        &self,
        callback: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        let mut state = self.state.lock().map_err(|_| invalid())?;
        state.generation = state.generation.checked_add(1).ok_or_else(invalid)?;
        callback()
    }
    pub fn new() -> Result<Self, String> {
        // A fresh instance never revives leases of an earlier process.
        Ok(Self {
            state: Mutex::new(GateState {
                id: crypto::random_challenge().map_err(|_| invalid())?,
                generation: 0,
                open: true,
            }),
        })
    }
    pub(super) fn rotate_current_with<T>(
        &self,
        lease: &TaskLease,
        callback: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        let mut state = self.state.lock().map_err(|_| invalid())?;
        if !state.open || state.id != lease.id || state.generation != lease.generation {
            return Err("设备任务结果已失效".into());
        }
        state.generation = state.generation.checked_add(1).ok_or_else(invalid)?;
        callback()
    }
    pub fn lease(&self) -> Result<TaskLease, String> {
        let state = self.state.lock().map_err(|_| invalid())?;
        if !state.open {
            return Err("设备任务已锁定".into());
        }
        Ok(TaskLease {
            id: state.id,
            generation: state.generation,
        })
    }
    pub fn invalidate(&self) -> Result<(), String> {
        let mut state = self.state.lock().map_err(|_| invalid())?;
        state.generation = state.generation.checked_add(1).ok_or_else(invalid)?;
        state.open = false;
        Ok(())
    }
    pub fn unlock(&self) -> Result<(), String> {
        let mut state = self.state.lock().map_err(|_| invalid())?;
        state.generation = state.generation.checked_add(1).ok_or_else(invalid)?;
        state.open = true;
        Ok(())
    }
    pub fn with_current<T>(
        &self,
        lease: &TaskLease,
        callback: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        let state = self.state.lock().map_err(|_| invalid())?;
        if !state.open || state.id != lease.id || state.generation != lease.generation {
            return Err("设备任务结果已失效".into());
        }
        callback()
    }
}
