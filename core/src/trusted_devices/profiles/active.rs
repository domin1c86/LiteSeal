//! Independent normal-session records for an authorized joining identity. The
//! original DPAPI identity is immutable; no new keys or device IDs are minted.
use super::{JoinProfile, JoinProfileStore};
use crate::{
    keystore::KeystoreData,
    secret_store,
    trusted_devices::{
        self as t,
        activation::{
            jobs::{Condition, Coordinator as Jobs, Owner as JobOwner},
            ActivationApi, CheckedSession,
        },
        tasks::{DeviceTaskStore, TaskGate, TaskPhase},
        witness::platform::Protection,
        DeviceTrustStore,
    },
};
use liteseal_shared::{
    crypto::KeyPair,
    device_activation::{Enable, Session},
    direct_message::Directory,
    trusted_device::{Anchor, DeviceAction, DeviceEvent, DeviceIdentity, DeviceState},
};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::Mutex,
};
use zeroize::{Zeroize, Zeroizing};
const MAX: usize = 32768;
fn bad() -> String {
    "正常设备档案、会话或原授权范围无法验证".into()
}
fn db(_: rusqlite::Error) -> String {
    "正常设备档案存储不可用".into()
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    domain: String,
    version: u8,
    profile: String,
    binding: [u8; 32],
    revision: u64,
    activation: String,
    mode: Enable,
    session: Session,
}
#[derive(Debug, Serialize)]
pub struct View {
    pub id: String,
    pub origin: String,
    pub username: String,
    pub device_name: String,
    pub account: String,
    pub device: String,
    pub root_fingerprint: String,
    pub encryption_fingerprint: String,
    pub signing_fingerprint: String,
    pub revision: u64,
    pub has_saved_session: bool,
    pub access_expired: bool,
    pub eligible: bool,
}
pub struct ActiveProfile {
    profile: JoinProfile,
    record: Record,
    eligible: bool,
    root_fingerprint: String,
}
impl ActiveProfile {
    pub fn view(&self) -> View {
        let p = self.profile.view();
        let s = &self.record.session;
        View {
            id: p.id,
            origin: p.origin,
            username: p.username,
            device_name: p.device_name,
            account: s.account.clone(),
            device: s.device.clone(),
            root_fingerprint: self.root_fingerprint.clone(),
            encryption_fingerprint: p.encryption_fingerprint,
            signing_fingerprint: p.signing_fingerprint,
            revision: self.record.revision,
            has_saved_session: !s.access_token.is_empty() && !s.refresh_token.is_empty(),
            access_expired: s.expires_at <= chrono::Utc::now().timestamp_millis(),
            eligible: self.eligible,
        }
    }
    /// Rust only. Callers validate the current session before starting network
    /// work; a local saved record does not assert remote liveness.
    pub fn identity(&self) -> KeystoreData {
        let mut identity = self.profile.record.identity.clone();
        let s = &self.record.session;
        identity.user_id = s.account.clone();
        identity.device_id = s.device.clone();
        if self.eligible {
            identity.token = s.access_token.clone();
            identity.refresh_token = s.refresh_token.clone();
        }
        identity
    }
}
pub struct Store {
    profiles: JoinProfileStore,
    profile_id: String,
    anchor: Anchor,
    device: DeviceIdentity,
    authority: [u8; 32],
    binding: [u8; 32],
    scope: String,
    trust: DeviceTrustStore,
    protection: Protection,
}
impl Store {
    pub fn open(root: PathBuf, id: &str) -> Result<Self, String> {
        Self::open_with_protection(root, id, Protection::default())
    }
    pub fn open_with_protection(
        root: PathBuf,
        id: &str,
        protection: Protection,
    ) -> Result<Self, String> {
        let profiles = JoinProfileStore::with_protection(root, protection.clone());
        let profile = profiles.load(id)?;
        let keys = profile.keys()?;
        let path = profiles.database(id)?;
        let mut joining = DeviceTaskStore::open(&path, profile.owner()?, &keys)?;
        joining.protect(protection.witness(&path)?)?;
        let task = joining.get(profile.task_id(), &keys)?;
        if !matches!(task.view().phase, TaskPhase::Complete | TaskPhase::Revoked)
            || task.local_abandonment()
        {
            return Err(bad());
        }
        let ticket = task.ticket().ok_or_else(bad)?;
        if ticket.device.encryption_key != keys.public_key
            || ticket.device.signing_key != keys.ed25519_pk
            || ticket.anchor.origin != profile.view().origin
        {
            return Err(bad());
        }
        let anchor = ticket.anchor.clone();
        let device = ticket.device.clone();
        joining.trust().load(&anchor, None)?;
        let authority = joining.trust().read_checked(|conn| {
            let mut stmt = conn.prepare("SELECT payload FROM trusted_device_events WHERE origin=?1 AND account=?2 ORDER BY revision LIMIT 4097").map_err(db)?;
            let mut found = None;
            for row in stmt.query_map(params![anchor.origin, anchor.account], |r|r.get::<_,Vec<u8>>(0)).map_err(db)? {
                let event: DeviceEvent = serde_json::from_slice(&row.map_err(db)?).map_err(|_|bad())?;
                if let DeviceAction::Grant { intent, challenge, proof } = &event.action {
                    if task.intent() == Some(intent.as_ref()) && task.challenge() == Some(challenge.as_ref()) && task.proof() == Some(proof) {
                        if found.is_some() { return Err(bad()); } found = Some(event.hash().try_into().map_err(|_|bad())?);
                    }
                }
            }
            found.ok_or_else(bad)
        })?;
        let binding: [u8; 32] = Sha256::digest(
            serde_json::to_vec(&(
                "LiteSeal/active-join-binding/v1",
                profile.view(),
                profile.task_id(),
                &anchor,
                &device,
                authority,
            ))
            .map_err(|_| bad())?,
        )
        .into();
        let scope = hex::encode(Sha256::digest(
            serde_json::to_vec(&("LiteSeal/active-join-scope/v1", id, binding))
                .map_err(|_| bad())?,
        ));
        drop(joining);
        let mut trust = DeviceTrustStore::open(&path)?;
        trust.protect(protection.witness(&path)?)?;
        Ok(Self {
            profiles,
            profile_id: id.into(),
            anchor,
            device,
            authority,
            binding,
            scope,
            trust,
            protection,
        })
    }
    pub fn database(&self) -> Result<PathBuf, String> {
        self.profiles.database(&self.profile_id)
    }
    pub fn job_owner(&self) -> Result<JobOwner, String> {
        JobOwner::new(
            self.anchor.clone(),
            &self.device.device_id,
            &self.profiles.load(&self.profile_id)?.keys()?,
        )
    }
    fn state(&mut self) -> Result<DeviceState, String> {
        self.trust.load(&self.anchor, None)
    }
    fn eligible(&self, state: &DeviceState) -> bool {
        Directory::from_state(state)
            .members
            .iter()
            .any(|m| m.device == self.device && m.authorization_hash == self.authority)
    }
    fn record(&mut self) -> Result<Option<Record>, String> {
        let record = self.trust.read_checked(|conn| {
            let row: Option<(u64,String,bool,Vec<u8>)> = conn.query_row("SELECT revision,kind,terminal,body FROM device_control_tasks WHERE scope=?1 AND id=?2",params![self.scope,self.profile_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().map_err(db)?;
            let Some((revision,kind,terminal,body)) = row else { return Ok(None); };
            if body.len() > MAX || kind != "active_profile" || !terminal { return Err(bad()); }
            let plain = Zeroizing::new(secret_store::unprotect_local(&body).map_err(|_|bad())?);
            let record: Record = serde_json::from_slice(&plain).map_err(|_|bad())?;
            if record.revision != revision { return Err(bad()); } Ok(Some(record))
        })?;
        if let Some(record) = &record {
            self.validate(record)?;
        }
        Ok(record)
    }
    fn validate(&self, r: &Record) -> Result<(), String> {
        let s = &r.session;
        r.mode.verify_root(&self.anchor).map_err(|_| bad())?;
        if r.domain != "LiteSeal/active-join-session/v1"
            || r.version != 1
            || r.profile != self.profile_id
            || r.binding != self.binding
            || r.revision == 0
            || r.revision > i64::MAX as u64
            || uuid::Uuid::parse_str(&r.activation)
                .ok()
                .is_none_or(|v| v.to_string() != r.activation)
            || uuid::Uuid::parse_str(&s.id)
                .ok()
                .is_none_or(|v| v.to_string() != s.id)
            || s.account != self.anchor.account
            || s.device != self.device.device_id
            || s.authorization != self.authority
            || s.mode != r.mode.digest().map_err(|_| bad())?
            || s.access_token.is_empty() != s.refresh_token.is_empty()
            || s.access_token.len() > 256
            || s.refresh_token.len() > 256
            || !s.access_token.bytes().all(|v| v.is_ascii_graphic())
            || !s.refresh_token.bytes().all(|v| v.is_ascii_graphic())
            || s.refresh_expires_at > 8_640_000_000_000_000
            || s.access_token.is_empty() && (s.expires_at != 0 || s.refresh_expires_at != 0)
            || !s.access_token.is_empty()
                && (s.expires_at <= 0 || s.refresh_expires_at <= s.expires_at)
        {
            return Err(bad());
        }
        Ok(())
    }
    pub fn load(&mut self) -> Result<Option<ActiveProfile>, String> {
        let Some(record) = self.record()? else {
            return Ok(None);
        };
        let state = self.state()?;
        let eligible = self.eligible(&state);
        let profile = self.profiles.load(&self.profile_id)?;
        if self.parent_binding(&profile)? != self.binding {
            return Err(bad());
        }
        Ok(Some(ActiveProfile {
            profile,
            record,
            eligible,
            root_fingerprint: hex::encode(self.anchor.hash()),
        }))
    }
    fn save(&mut self, mut record: Record, previous: Option<u64>) -> Result<(), String> {
        record.revision = previous.unwrap_or(0).checked_add(1).ok_or_else(bad)?;
        self.validate(&record)?;
        let plain = Zeroizing::new(serde_json::to_vec(&record).map_err(|_| bad())?);
        if plain.len() > MAX - 1024 {
            return Err(bad());
        }
        let protected = secret_store::protect_local(&plain).map_err(|_| bad())?;
        if protected.len() > MAX {
            return Err(bad());
        }
        let anchor = &self.anchor;
        let device = &self.device;
        let authority = self.authority;
        let parent = self.profiles.load(&self.profile_id)?;
        if self.parent_binding(&parent)? != self.binding {
            return Err(bad());
        }
        self.trust.write_checked(|conn| {
            // Check the immutable parent and signed eligibility in this commit.
            let current_parent = self.profiles.load(&self.profile_id)?;
            let binding: [u8;32] = Sha256::digest(serde_json::to_vec(&("LiteSeal/active-join-binding/v1", current_parent.view(), current_parent.task_id(), anchor, device, authority)).map_err(|_|bad())?).into();
            if binding != record.binding { return Err(bad()); }
            let state = t::read(conn, anchor, None)?;
            if !record.session.access_token.is_empty() && !Directory::from_state(&state).members.iter().any(|m| m.device == *device && m.authorization_hash == authority) { return Err(bad()); }
            let count = if let Some(previous) = previous {
                conn.execute("UPDATE device_control_tasks SET revision=?3,body=?4 WHERE scope=?1 AND id=?2 AND revision=?5 AND kind='active_profile' AND terminal=1",params![self.scope,self.profile_id,record.revision,protected,previous]).map_err(db)?
            } else { conn.execute("INSERT INTO device_control_tasks(scope,id,revision,kind,terminal,body) VALUES(?1,?2,?3,'active_profile',1,?4)",params![self.scope,self.profile_id,record.revision,protected]).map_err(db)? };
            if count != 1 { return Err(bad()); } Ok(())
        })
    }
    pub fn save_checked(
        &mut self,
        activation: &str,
        mode: Enable,
        mut session: Session,
        checked: CheckedSession,
        previous: Option<u64>,
    ) -> Result<(), String> {
        let keys = self.profiles.load(&self.profile_id)?.keys()?;
        let path = self.database()?;
        let mut jobs = t::activation::jobs::Store::open(
            &path,
            self.job_owner()?,
            &keys,
            self.protection.witness(&path)?,
        )?;
        let original = jobs.task(activation, &keys)?;
        if original.enable() != &mode {
            return Err(bad());
        }
        if original.view().stage == t::activation::jobs::Stage::Complete {
            if jobs.session(activation, &keys)?.id != session.id {
                return Err(bad());
            }
        } else {
            let existing = self.record()?.ok_or_else(bad)?;
            if existing.activation != activation
                || existing.revision != previous.ok_or_else(bad)?
                || !original.view().closed.is_some_and(|closed| closed.accepted)
            {
                return Err(bad());
            }
        }
        drop(jobs);
        if checked.token_hash != Sha256::digest(session.access_token.as_bytes()).as_slice()
            || checked.info.refresh_hash
                != Sha256::digest(session.refresh_token.as_bytes()).as_slice()
            || checked.info.account != session.account
            || checked.info.device != self.device
            || checked.info.authorization != session.authorization
            || checked.info.mode != session.mode
            || checked.info.id != session.id
        {
            return Err(bad());
        }
        session.expires_at = checked.info.expires_at;
        session.refresh_expires_at = checked.info.refresh_expires_at;
        self.save(
            Record {
                domain: "LiteSeal/active-join-session/v1".into(),
                version: 1,
                profile: self.profile_id.clone(),
                binding: self.binding,
                revision: 0,
                activation: activation.into(),
                mode,
                session,
            },
            previous,
        )
    }
    pub fn clear_session(&mut self) -> Result<(), String> {
        let Some(mut record) = self.record()? else {
            return Ok(());
        };
        let previous = record.revision;
        record.session.access_token.zeroize();
        record.session.refresh_token.zeroize();
        record.session.expires_at = 0;
        record.session.refresh_expires_at = 0;
        self.save(record, Some(previous))
    }
    fn parent_binding(&self, profile: &JoinProfile) -> Result<[u8; 32], String> {
        Ok(Sha256::digest(
            serde_json::to_vec(&(
                "LiteSeal/active-join-binding/v1",
                profile.view(),
                profile.task_id(),
                &self.anchor,
                &self.device,
                self.authority,
            ))
            .map_err(|_| bad())?,
        )
        .into())
    }
}
/// Owns all async/session admission. Synchronous/native locks never cross await.
pub struct Coordinator {
    store: Mutex<Store>,
    gate: TaskGate,
    network: tokio::sync::Mutex<()>,
}
impl Coordinator {
    pub fn open(root: PathBuf, id: &str) -> Result<Self, String> {
        Self::open_with_protection(root, id, Protection::default())
    }
    pub fn open_with_protection(
        root: PathBuf,
        id: &str,
        protection: Protection,
    ) -> Result<Self, String> {
        Ok(Self {
            store: Mutex::new(Store::open_with_protection(root, id, protection)?),
            gate: TaskGate::new()?,
            network: tokio::sync::Mutex::new(()),
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
    pub fn invalidate(&self) -> Result<(), String> {
        self.gate.invalidate()
    }
    pub fn resume(&self) -> Result<(), String> {
        self.gate.unlock()
    }
    pub fn view(&self) -> Result<Option<View>, String> {
        let lease = self.gate.lease()?;
        self.with(&lease, |s| s.load().map(|p| p.map(|p| p.view())))
    }
    pub fn clear_session(&self) -> Result<(), String> {
        self.gate
            .rotate_with(|| self.store.lock().map_err(|_| bad())?.clear_session())
    }
    pub async fn checked_identity(&self) -> Result<KeystoreData, String> {
        let lease = self.gate.lease()?;
        let _network = self.network.lock().await;
        let (profile, state, device, mode, previous) = self.with(&lease, |s| {
            let profile = s.load()?.ok_or_else(bad)?;
            if !profile.eligible || profile.record.session.access_token.is_empty() {
                return Err(bad());
            }
            let mode = profile.record.mode.clone();
            let previous = profile.record.revision;
            Ok((profile, s.state()?, s.device.clone(), mode, previous))
        })?;
        let keys = profile.profile.keys()?;
        let api = ActivationApi::new(&state.anchor().origin).map_err(|_| bad())?;
        let checked = api
            .check_session(
                &profile.record.session.access_token,
                &state,
                &mode,
                &device,
                &keys,
            )
            .await
            .map_err(|_| "当前会话未确认，请刷新或重新认证；原档案已保留".to_string())?;
        if checked.info.id != profile.record.session.id
            || checked.info.refresh_hash
                != Sha256::digest(profile.record.session.refresh_token.as_bytes()).as_slice()
        {
            return Err(bad());
        }
        self.with(&lease, |s| {
            let current = s.load()?.ok_or_else(bad)?;
            if current.record.revision != previous || !current.eligible {
                return Err(bad());
            }
            Ok(current.identity())
        })
    }
    pub async fn activate(&self, id: &str) -> Result<View, String> {
        let lease = self.gate.lease()?;
        let _network = self.network.lock().await;
        let (path, owner, keys, protection, previous, state, device) = self.with(&lease, |s| {
            Ok((
                s.database()?,
                s.job_owner()?,
                s.profiles.load(&s.profile_id)?.keys()?,
                s.protection.clone(),
                s.record()?.map(|r| r.revision),
                s.state()?,
                s.device.clone(),
            ))
        })?;
        let jobs = Jobs::open_with_protection(&path, owner, &keys, protection)?;
        if jobs.inspect(id, &keys).await?.condition != Condition::Complete {
            return Err("原激活尚未确认有效会话，请查询原申请".into());
        }
        let session = jobs.session(id, &keys)?;
        let mode = {
            let mut store = t::activation::jobs::Store::open(
                &path,
                jobs_owner(&state, &device, &keys)?,
                &keys,
                self.with(&lease, |s| s.protection.witness(&path))?,
            )?;
            store.task(id, &keys)?.enable().clone()
        };
        let api = ActivationApi::new(&state.anchor().origin).map_err(|_| bad())?;
        let checked = api
            .check_session(&session.access_token, &state, &mode, &device, &keys)
            .await
            .map_err(|_| bad())?;
        self.with(&lease, |s| {
            s.save_checked(id, mode, session, checked, previous)?;
            s.load()?.map(|p| p.view()).ok_or_else(bad)
        })
    }
}
fn jobs_owner(
    state: &DeviceState,
    device: &DeviceIdentity,
    keys: &KeyPair,
) -> Result<JobOwner, String> {
    JobOwner::new(state.anchor().clone(), &device.device_id, keys)
}
pub(super) fn refuse_removal(database: &Path) -> Result<(), String> {
    if !database.exists() {
        return Ok(());
    }
    let conn =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(db)?;
    let exists:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='device_control_tasks')",[],|r|r.get(0)).map_err(db)?;
    if exists
        && conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM device_control_tasks WHERE kind='active_profile')",
                [],
                |r| r.get::<_, bool>(0),
            )
            .map_err(db)?
    {
        return Err("已建立正常会话档案，不能用加入申请整理入口删除身份或历史".into());
    }
    Ok(())
}
