//! Bounded network steps over durable tasks. No SQLite or session lock spans
//! await; invalidation and cancellation can interrupt local results immediately.
use super::{
    api::{ControlError, DeviceControlApi},
    tasks::*,
    Checkpoint,
};
use liteseal_shared::{crypto::KeyPair, trusted_device::*};
use serde::Serialize;
use std::{
    path::Path,
    sync::{Mutex, RwLock},
};
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Condition {
    Advanced,
    Waiting,
    NeedsPassword,
    NeedsConfirmation,
    Syncing,
    Retry,
    SessionRequired,
    Unsupported,
    Conflict,
    Terminal,
}
#[derive(Debug, Serialize)]
pub struct Progress {
    pub task: TaskView,
    pub condition: Condition,
    pub http_status: Option<u16>,
}
#[derive(Debug, Serialize)]
pub struct JoinInspection {
    pub request_id: String,
    pub device_id: String,
    pub device_name: String,
    pub encryption_fingerprint: String,
    pub signing_fingerprint: String,
    pub combined_fingerprint: String,
    pub phase: JoinPhase,
}
#[derive(Debug, Serialize)]
pub struct RootSnapshot {
    pub root_fingerprint: String,
    pub supported: bool,
    pub syncing: bool,
    pub messaging_enabled: bool,
    pub requests: Vec<JoinInspection>,
    pub tasks: Vec<TaskView>,
    pub authorized: Option<AuthorizedView>,
}
#[derive(Debug, Serialize)]
pub struct AuthorizedView {
    pub device_id: String,
    pub combined_fingerprint: String,
    pub encryption_fingerprint: String,
    pub signing_fingerprint: String,
}
pub fn device_fingerprint(device: &DeviceIdentity) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(
        serde_json::to_vec(&("LiteSeal/device-inspection/v1", device))
            .expect("public device serialization"),
    ))
}
#[derive(Debug)]
pub struct CoordinatorError {
    pub message: &'static str,
}
impl std::fmt::Display for CoordinatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message)
    }
}
impl std::error::Error for CoordinatorError {}
type Result<T> = std::result::Result<T, CoordinatorError>;
fn local(_: String) -> CoordinatorError {
    CoordinatorError {
        message: "设备任务、身份或代次已变化，请重新查询",
    }
}
fn invalid() -> CoordinatorError {
    CoordinatorError {
        message: "设备任务远端记录无法绑定或验证",
    }
}
pub struct DeviceCoordinator {
    owner: TaskOwner,
    api: DeviceControlApi,
    store: Mutex<DeviceTaskStore>,
    gate: TaskGate,
    network: tokio::sync::Mutex<()>,
    session: RwLock<String>,
}
impl DeviceCoordinator {
    pub async fn root_snapshot(&self, keys: &KeyPair) -> Result<RootSnapshot> {
        let lease = self.lease(keys)?;
        let _network = self.network.lock().await;
        let anchor = self.owner.root_anchor().ok_or_else(invalid)?;
        let tasks = self.with(&lease, |s| s.views(keys))?;
        let token = self.token(&lease)?;
        let statuses = match self.api.list(&token, &anchor.root.device_id).await {
            Ok(statuses) => statuses,
            Err(error) if error.status == Some(404) => {
                self.with(&lease, |_| Ok(()))?;
                return Ok(RootSnapshot {
                    root_fingerprint: anchor_fingerprint(&anchor),
                    supported: false,
                    syncing: false,
                    messaging_enabled: false,
                    requests: vec![],
                    tasks,
                    authorized: None,
                });
            }
            Err(_) => return Err(invalid()),
        };
        let mut requests = vec![];
        for status in statuses {
            if status.ticket.anchor != anchor {
                return Err(invalid());
            }
            use sha2::Digest;
            requests.push(JoinInspection {
                request_id: status.ticket.id,
                device_id: status.ticket.device.device_id.clone(),
                device_name: status.ticket.device_name,
                encryption_fingerprint: hex::encode(sha2::Sha256::digest(
                    status.ticket.device.encryption_key,
                )),
                signing_fingerprint: hex::encode(sha2::Sha256::digest(
                    status.ticket.device.signing_key,
                )),
                combined_fingerprint: device_fingerprint(&status.ticket.device),
                phase: status.phase,
            });
        }
        let state = self
            .sync(&lease, None, &anchor, &token, None, keys)
            .await
            .map_err(|_| invalid())?;
        use sha2::Digest;
        let authorized = state
            .as_ref()
            .and_then(DeviceState::secondary)
            .map(|device| AuthorizedView {
                device_id: device.device_id.clone(),
                combined_fingerprint: device_fingerprint(device),
                encryption_fingerprint: hex::encode(sha2::Sha256::digest(device.encryption_key)),
                signing_fingerprint: hex::encode(sha2::Sha256::digest(device.signing_key)),
            });
        Ok(RootSnapshot {
            root_fingerprint: anchor_fingerprint(&anchor),
            supported: true,
            syncing: state.is_none(),
            messaging_enabled: false,
            requests,
            tasks,
            authorized,
        })
    }
    pub fn open(path: &Path, owner: TaskOwner, keys: &KeyPair) -> Result<Self> {
        let api = DeviceControlApi::new(owner.origin()).map_err(|_| invalid())?;
        let store = DeviceTaskStore::open(path, owner.clone(), keys).map_err(local)?;
        Ok(Self {
            owner,
            api,
            store: Mutex::new(store),
            gate: TaskGate::new().map_err(local)?,
            network: Default::default(),
            session: RwLock::new(String::new()),
        })
    }
    /// Renewing a token invalidates in-flight results without unlocking a locked context.
    pub fn renew_session(&self, token: String) -> Result<()> {
        self.gate
            .rotate_with(|| {
                *self
                    .session
                    .write()
                    .map_err(|_| "设备会话锁不可用".to_string())? = token;
                Ok(())
            })
            .map_err(local)
    }
    pub fn invalidate(&self) -> Result<()> {
        self.gate.invalidate().map_err(local)?;
        self.renew_session(String::new())
    }
    pub fn resume(&self) -> Result<()> {
        self.gate.unlock().map_err(local)
    }
    fn lease(&self, keys: &KeyPair) -> Result<TaskLease> {
        self.owner.keys(keys).map_err(local)?;
        self.gate.lease().map_err(local)
    }
    fn with<T>(
        &self,
        lease: &TaskLease,
        callback: impl FnOnce(&mut DeviceTaskStore) -> std::result::Result<T, String>,
    ) -> Result<T> {
        self.gate
            .with_current(lease, || {
                let mut store = self
                    .store
                    .lock()
                    .map_err(|_| "设备任务锁不可用".to_string())?;
                callback(&mut store)
            })
            .map_err(local)
    }
    fn current<T>(
        &self,
        lease: &TaskLease,
        task: &ControlTask,
        keys: &KeyPair,
        callback: impl FnOnce(&mut DeviceTaskStore) -> std::result::Result<T, String>,
    ) -> Result<T> {
        self.with(lease, |store| {
            let current = store.get(&task.view().id, keys)?;
            if current.view().revision != task.view().revision {
                return Err("任务已被取消或改变".into());
            }
            callback(store)
        })
    }
    fn token(&self, lease: &TaskLease) -> Result<String> {
        self.gate
            .with_current(lease, || {
                Ok(self
                    .session
                    .read()
                    .map_err(|_| "设备会话锁不可用".to_string())?
                    .clone())
            })
            .map_err(local)
    }
    fn progress(task: &ControlTask, condition: Condition) -> Progress {
        Progress {
            task: task.view(),
            condition,
            http_status: None,
        }
    }
    fn remote(
        &self,
        lease: &TaskLease,
        task: &ControlTask,
        error: ControlError,
        keys: &KeyPair,
    ) -> Result<Progress> {
        self.current(lease, task, keys, |_| Ok(()))?;
        let condition = match error.status {
            Some(401 | 403) => Condition::SessionRequired,
            Some(404) => Condition::Unsupported,
            Some(409 | 410) => Condition::Conflict,
            _ => Condition::Retry,
        };
        let task = if condition == Condition::Conflict && task.view().phase != TaskPhase::Cancelling
        {
            self.current(lease, task, keys, |s| s.mark_conflict(task, keys))?
        } else {
            task.clone()
        };
        Ok(Progress {
            task: task.view(),
            condition,
            http_status: error.status,
        })
    }
    pub fn tasks(&self, keys: &KeyPair) -> Result<Vec<TaskView>> {
        let lease = self.lease(keys)?;
        self.with(&lease, |s| s.views(keys))
    }
    pub fn prepare_join(&self, name: &str, keys: &KeyPair) -> Result<TaskView> {
        let lease = self.lease(keys)?;
        self.with(&lease, |s| s.prepare_join(name, keys).map(|t| t.view()))
    }
    /// Caller supplies a fingerprint checked through the original device; no raw keys leave Rust.
    pub fn confirm_root(&self, id: &str, fingerprint: &str, keys: &KeyPair) -> Result<TaskView> {
        let lease = self.lease(keys)?;
        self.with(&lease, |s| {
            let task = s.get(id, keys)?;
            let anchor = task.ticket().ok_or("申请尚未建立")?.anchor.clone();
            s.confirm_root(&task, &anchor, fingerprint, keys)
                .map(|t| t.view())
        })
    }
    pub fn request_cancel(&self, id: &str, keys: &KeyPair) -> Result<TaskView> {
        let lease = self.lease(keys)?;
        self.with(&lease, |s| {
            let task = s.get(id, keys)?;
            s.request_cancel(&task, keys).map(|t| t.view())
        })
    }
    pub fn discard_terminal(&self, id: &str, keys: &KeyPair) -> Result<()> {
        let lease = self.lease(keys)?;
        self.with(&lease, |s| {
            let task = s.get(id, keys)?;
            s.discard_terminal(&task, keys)
        })
    }
    /// At most one page per invocation. A partial directory cannot authorize a new task.
    async fn sync(
        &self,
        lease: &TaskLease,
        task: Option<&ControlTask>,
        anchor: &Anchor,
        token: &str,
        request_id: Option<&str>,
        keys: &KeyPair,
    ) -> std::result::Result<Option<DeviceState>, ControlError> {
        let failure = || ControlError {
            status: None,
            message: "设备目录同步或代次失效",
        };
        let checkpoint = self
            .with(lease, |s| {
                if let Some(task) = task {
                    if s.get(&task.view().id, keys)?.view().revision != task.view().revision {
                        return Err("任务已改变".into());
                    }
                }
                s.trust()
                    .load(anchor, None)
                    .or_else(|_| s.trust().pin(anchor))
                    .map(|state| Checkpoint::from_state(&state))
            })
            .map_err(|_| failure())?;
        let page = match request_id {
            Some(id) => {
                self.api
                    .join_manifest(token, id, checkpoint.revision)
                    .await?
            }
            None => {
                self.api
                    .manifest(token, &anchor.account, checkpoint.revision)
                    .await?
            }
        };
        let state = self
            .with(lease, |s| {
                if let Some(task) = task {
                    if s.get(&task.view().id, keys)?.view().revision != task.view().revision {
                        return Err("任务已改变".into());
                    }
                }
                s.trust().import_page(anchor, &checkpoint, &page)
            })
            .map_err(|_| failure())?;
        Ok((!page.more).then_some(state))
    }
    pub async fn inspect_join(&self, request_id: &str, keys: &KeyPair) -> Result<JoinInspection> {
        let lease = self.lease(keys)?;
        let _network = self.network.lock().await;
        let anchor = self.owner.root_anchor().ok_or_else(invalid)?;
        let token = self.token(&lease)?;
        let status = self
            .api
            .status(&token, request_id, Some(&anchor.root.device_id))
            .await
            .map_err(|_| invalid())?;
        self.with(&lease, |_| Ok(()))?;
        if status.ticket.anchor != anchor {
            return Err(invalid());
        }
        use sha2::Digest;
        Ok(JoinInspection {
            request_id: status.ticket.id,
            device_id: status.ticket.device.device_id.clone(),
            device_name: status.ticket.device_name,
            encryption_fingerprint: hex::encode(sha2::Sha256::digest(
                status.ticket.device.encryption_key,
            )),
            signing_fingerprint: hex::encode(sha2::Sha256::digest(
                status.ticket.device.signing_key,
            )),
            combined_fingerprint: device_fingerprint(&status.ticket.device),
            phase: status.phase,
        })
    }
    pub async fn prepare_challenge(
        &self,
        request_id: &str,
        confirmed_fingerprint: &str,
        keys: &KeyPair,
    ) -> Result<Option<TaskView>> {
        let lease = self.lease(keys)?;
        let _network = self.network.lock().await;
        let anchor = self.owner.root_anchor().ok_or_else(invalid)?;
        let token = self.token(&lease)?;
        if token.is_empty() {
            return Err(CoordinatorError {
                message: "原设备会话不可用",
            });
        }
        let Some(state) = self
            .sync(&lease, None, &anchor, &token, None, keys)
            .await
            .map_err(|_| invalid())?
        else {
            return Ok(None);
        };
        let status = self
            .api
            .status(&token, request_id, Some(&anchor.root.device_id))
            .await
            .map_err(|_| invalid())?;
        if status.phase != JoinPhase::Ready
            || status.ticket.anchor != anchor
            || device_fingerprint(&status.ticket.device) != confirmed_fingerprint
            || !status
                .ticket
                .matches(status.intent.as_ref().ok_or_else(invalid)?)
        {
            return Err(invalid());
        }
        self.with(&lease, |s| {
            s.prepare_challenge(
                &state,
                status.intent.as_ref().unwrap(),
                chrono::Utc::now().timestamp_millis(),
                keys,
            )
            .map(|t| Some(t.view()))
        })
    }
    pub async fn prepare_grant(
        &self,
        request_id: &str,
        confirmed_fingerprint: &str,
        keys: &KeyPair,
    ) -> Result<Option<TaskView>> {
        let lease = self.lease(keys)?;
        let _network = self.network.lock().await;
        let anchor = self.owner.root_anchor().ok_or_else(invalid)?;
        let token = self.token(&lease)?;
        if token.is_empty() {
            return Err(CoordinatorError {
                message: "原设备会话不可用",
            });
        }
        let Some(state) = self
            .sync(&lease, None, &anchor, &token, None, keys)
            .await
            .map_err(|_| invalid())?
        else {
            return Ok(None);
        };
        let status = self
            .api
            .status(&token, request_id, Some(&anchor.root.device_id))
            .await
            .map_err(|_| invalid())?;
        if device_fingerprint(&status.ticket.device) != confirmed_fingerprint {
            return Err(invalid());
        }
        self.with(&lease, |s| {
            s.prepare_grant(&state, &status, chrono::Utc::now().timestamp_millis(), keys)
                .map(|t| Some(t.view()))
        })
    }
    pub async fn prepare_revoke(&self, keys: &KeyPair) -> Result<Option<TaskView>> {
        self.prepare_revoke_with(None, keys).await
    }
    pub async fn prepare_revoke_confirmed(
        &self,
        confirmed_fingerprint: &str,
        keys: &KeyPair,
    ) -> Result<Option<TaskView>> {
        self.prepare_revoke_with(Some(confirmed_fingerprint), keys)
            .await
    }
    async fn prepare_revoke_with(
        &self,
        confirmed_fingerprint: Option<&str>,
        keys: &KeyPair,
    ) -> Result<Option<TaskView>> {
        let lease = self.lease(keys)?;
        let _network = self.network.lock().await;
        let anchor = self.owner.root_anchor().ok_or_else(invalid)?;
        let token = self.token(&lease)?;
        if token.is_empty() {
            return Err(CoordinatorError {
                message: "原设备会话不可用",
            });
        }
        let Some(state) = self
            .sync(&lease, None, &anchor, &token, None, keys)
            .await
            .map_err(|_| invalid())?
        else {
            return Ok(None);
        };
        if confirmed_fingerprint.is_some_and(|fingerprint| {
            state
                .secondary()
                .is_none_or(|device| device_fingerprint(device) != fingerprint)
        }) {
            return Err(invalid());
        }
        self.with(&lease, |s| {
            s.prepare_revoke(&state, chrono::Utc::now().timestamp_millis(), keys)
                .map(|t| Some(t.view()))
        })
    }
    pub async fn step(&self, id: &str, password: Option<&str>, keys: &KeyPair) -> Result<Progress> {
        let lease = self.lease(keys)?;
        let _network = self.network.lock().await;
        let task = self.with(&lease, |s| s.get(id, keys))?;
        let view = task.view();
        if matches!(
            view.phase,
            TaskPhase::Complete | TaskPhase::Cancelled | TaskPhase::Expired | TaskPhase::Revoked
        ) {
            return Ok(Self::progress(&task, Condition::Terminal));
        }
        if view.phase == TaskPhase::Conflict {
            return Ok(Self::progress(&task, Condition::Conflict));
        }
        if view.kind == TaskKind::Join {
            return self.join_step(&lease, task, password, keys).await;
        }
        self.root_step(&lease, task, keys).await
    }
    async fn join_step(
        &self,
        lease: &TaskLease,
        task: ControlTask,
        password: Option<&str>,
        keys: &KeyPair,
    ) -> Result<Progress> {
        let id = task.view().id;
        let token = task.join_credential().map_err(local)?;
        let remote = match self.api.status(token, &id, None).await {
            Ok(status) => status,
            Err(error) if task.view().phase == TaskPhase::Draft && error.status == Some(401) => {
                let Some(password) = password else {
                    return Ok(Self::progress(&task, Condition::NeedsPassword));
                };
                match self
                    .api
                    .begin(&task.start_request(password).map_err(local)?)
                    .await
                {
                    Ok(status) => status,
                    Err(error) => return self.remote(lease, &task, error, keys),
                }
            }
            Err(error) => return self.remote(lease, &task, error, keys),
        };
        self.current(lease, &task, keys, |_| Ok(()))?;
        if task.view().phase == TaskPhase::Cancelling {
            let status = if remote.phase == JoinPhase::Cancelled {
                remote
            } else {
                match self.api.cancel(token, &id, None).await {
                    Ok(status) => status,
                    Err(error) => return self.remote(lease, &task, error, keys),
                }
            };
            let cancelled = self.current(lease, &task, keys, |s| {
                s.confirm_join_cancel(&task, &status, keys)
            })?;
            return Ok(Self::progress(&cancelled, Condition::Terminal));
        }
        if task.view().phase == TaskPhase::Draft {
            let accepted = self.current(lease, &task, keys, |s| {
                s.accept_ticket(&task, &remote, keys)
            })?;
            return Ok(Self::progress(&accepted, Condition::NeedsConfirmation));
        }
        if !task.same_ticket(&remote) {
            return Err(invalid());
        }
        if matches!(remote.phase, JoinPhase::Expired | JoinPhase::Cancelled) {
            let finished = self.current(lease, &task, keys, |s| {
                s.join_terminal(&task, &remote, keys)
            })?;
            return Ok(Self::progress(&finished, Condition::Terminal));
        }
        if task.view().phase == TaskPhase::AwaitingRootConfirmation {
            return Ok(Self::progress(&task, Condition::NeedsConfirmation));
        }
        let anchor = task.ticket().ok_or_else(invalid)?.anchor.clone();
        if remote.phase == JoinPhase::Authorized {
            match self
                .sync(lease, Some(&task), &anchor, token, Some(&id), keys)
                .await
            {
                Ok(None) => return Ok(Self::progress(&task, Condition::Syncing)),
                Err(error) => return self.remote(lease, &task, error, keys),
                _ => {}
            }
            let event_id = remote.authorization_id.as_deref().ok_or_else(invalid)?;
            let accepted = self.current(lease, &task, keys, |s| {
                s.confirm_join_authorized(&task, event_id, keys)
            })?;
            return Ok(Self::progress(&accepted, Condition::Terminal));
        }
        if remote.intent.is_none() {
            let original = task.intent().ok_or_else(invalid)?;
            match self.api.intent(token, original).await {
                Ok(_) => {}
                Err(error) => return self.remote(lease, &task, error, keys),
            }
            self.current(lease, &task, keys, |_| Ok(()))?;
            return Ok(Self::progress(&task, Condition::Advanced));
        }
        if task.view().phase == TaskPhase::AwaitingChallenge {
            let Some(challenge) = remote.challenge.as_ref() else {
                return Ok(Self::progress(&task, Condition::Waiting));
            };
            let state = match self
                .sync(lease, Some(&task), &anchor, token, Some(&id), keys)
                .await
            {
                Ok(Some(state)) => state,
                Ok(None) => return Ok(Self::progress(&task, Condition::Syncing)),
                Err(error) => return self.remote(lease, &task, error, keys),
            };
            let sealed = self.current(lease, &task, keys, |s| {
                s.seal_proof(
                    &task,
                    &state,
                    challenge,
                    chrono::Utc::now().timestamp_millis(),
                    keys,
                )
            })?;
            return Ok(Self::progress(&sealed, Condition::Advanced));
        }
        if task.view().phase == TaskPhase::AwaitingAuthorization && remote.proof.is_none() {
            match self
                .api
                .proof(token, &id, task.proof().ok_or_else(invalid)?)
                .await
            {
                Ok(_) => {}
                Err(error) => return self.remote(lease, &task, error, keys),
            }
            self.current(lease, &task, keys, |_| Ok(()))?;
            return Ok(Self::progress(&task, Condition::Advanced));
        }
        Ok(Self::progress(&task, Condition::Waiting))
    }
    async fn root_step(
        &self,
        lease: &TaskLease,
        task: ControlTask,
        keys: &KeyPair,
    ) -> Result<Progress> {
        let anchor = self.owner.root_anchor().ok_or_else(invalid)?;
        let token = self.token(lease)?;
        if token.is_empty() {
            return Ok(Self::progress(&task, Condition::SessionRequired));
        }
        if let Some(event) = task.event() {
            let state = match self
                .sync(lease, Some(&task), &anchor, &token, None, keys)
                .await
            {
                Ok(Some(state)) => state,
                Ok(None) => return Ok(Self::progress(&task, Condition::Syncing)),
                Err(error) => return self.remote(lease, &task, error, keys),
            };
            if self.current(lease, &task, keys, |s| s.event_accepted(&task))? {
                let accepted = self.current(lease, &task, keys, |s| {
                    s.confirm_event_accepted(&task, keys)
                })?;
                return Ok(Self::progress(&accepted, Condition::Terminal));
            }
            if task.view().phase == TaskPhase::Cancelling {
                let result = match self
                    .api
                    .cancel_event(&token, &anchor.root.device_id, event)
                    .await
                {
                    Ok(result) => result,
                    Err(error) => return self.remote(lease, &task, error, keys),
                };
                if !result.cancelled {
                    return Ok(Self::progress(&task, Condition::Syncing));
                } // Receipt alone cannot finalize acceptance.
                let cancelled = self.current(lease, &task, keys, |s| {
                    s.confirm_event_cancel(&task, &result, keys)
                })?;
                return Ok(Self::progress(&cancelled, Condition::Terminal));
            }
            if !self.current(lease, &task, keys, |s| Ok(s.base_matches(&task, &state)))? {
                let conflict =
                    self.current(lease, &task, keys, |s| s.mark_conflict(&task, keys))?;
                return Ok(Self::progress(&conflict, Condition::Conflict));
            }
            match self.api.submit(&token, &anchor.root.device_id, event).await {
                Ok(_) => {}
                Err(error) => return self.remote(lease, &task, error, keys),
            }
            self.current(lease, &task, keys, |_| Ok(()))?;
            return Ok(Self::progress(&task, Condition::Syncing)); // The next invocation verifies the accepted directory.
        }
        let request_id = task.intent().ok_or_else(invalid)?.id.clone();
        let remote = match self
            .api
            .status(&token, &request_id, Some(&anchor.root.device_id))
            .await
        {
            Ok(status) => status,
            Err(error) => return self.remote(lease, &task, error, keys),
        };
        if task.view().phase == TaskPhase::Cancelling {
            let cancelled = match self
                .api
                .cancel(&token, &request_id, Some(&anchor.root.device_id))
                .await
            {
                Ok(status) => status,
                Err(error) => return self.remote(lease, &task, error, keys),
            };
            let finished = self.current(lease, &task, keys, |s| {
                s.confirm_join_cancel(&task, &cancelled, keys)
            })?;
            return Ok(Self::progress(&finished, Condition::Terminal));
        }
        if matches!(remote.phase, JoinPhase::Cancelled | JoinPhase::Expired) {
            let finished = self.current(lease, &task, keys, |s| {
                s.challenge_terminal(&task, &remote, keys)
            })?;
            return Ok(Self::progress(&finished, Condition::Terminal));
        }
        if remote.challenge.is_some() {
            let accepted = self.current(lease, &task, keys, |s| {
                s.confirm_challenge(&task, &remote, keys)
            })?;
            return Ok(Self::progress(&accepted, Condition::Terminal));
        }
        let state = match self
            .sync(lease, Some(&task), &anchor, &token, None, keys)
            .await
        {
            Ok(Some(state)) => state,
            Ok(None) => return Ok(Self::progress(&task, Condition::Syncing)),
            Err(error) => return self.remote(lease, &task, error, keys),
        };
        if !self.current(lease, &task, keys, |s| Ok(s.base_matches(&task, &state)))? {
            let conflict = self.current(lease, &task, keys, |s| s.mark_conflict(&task, keys))?;
            return Ok(Self::progress(&conflict, Condition::Conflict));
        }
        match self
            .api
            .challenge(
                &token,
                &request_id,
                &anchor.root.device_id,
                task.challenge().ok_or_else(invalid)?,
            )
            .await
        {
            Ok(status) => {
                let accepted = self.current(lease, &task, keys, |s| {
                    s.confirm_challenge(&task, &status, keys)
                })?;
                Ok(Self::progress(&accepted, Condition::Terminal))
            }
            Err(error) => self.remote(lease, &task, error, keys),
        }
    }
}
