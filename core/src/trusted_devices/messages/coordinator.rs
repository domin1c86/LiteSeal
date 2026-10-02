//! Bounded orchestration over immutable encrypted v3 tasks. Sync/native locks
//! never cross await. Late results require both the current lease and revision.
use super::{
    api::{ApiError, AuthenticatedResult, DirectApi},
    Acceptance, Owner, Prepare, RecordView, Store, TaskState, TaskView,
};
use crate::trusted_devices::{
    api::DeviceControlApi,
    tasks::{anchor_fingerprint, TaskGate, TaskLease},
    witness::platform::Protection,
    Checkpoint, DeviceTrustStore,
};
use liteseal_shared::{
    crypto::KeyPair,
    direct_message::{Batch, Kind},
    direct_transport::Result as Outcome,
    trusted_device::Anchor,
};
use serde::Serialize;
use std::{
    path::Path,
    sync::{Mutex, RwLock},
};
use zeroize::Zeroizing;
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Condition {
    Prepared,
    Accepted,
    Cancelled,
    Syncing,
    NeedsTrust,
    Conflict,
    Retry,
    SessionRequired,
    Unsupported,
    Idle,
    Received,
    Acknowledged,
}
#[derive(Debug, Serialize)]
pub struct Progress {
    pub task: TaskView,
    pub condition: Condition,
    pub http_status: Option<u16>,
}
#[derive(Debug, Serialize)]
pub struct Preparation {
    pub task: Option<TaskView>,
    pub condition: Condition,
    pub http_status: Option<u16>,
}
#[derive(Debug, Serialize)]
pub struct Poll {
    pub condition: Condition,
    pub received: usize,
    pub acknowledged: usize,
    pub has_more: bool,
    pub http_status: Option<u16>,
}
#[derive(Debug)]
pub struct CoordinatorError {
    pub message: &'static str,
    pub http_status: Option<u16>,
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
        message: "单聊 v3 身份、任务或安全状态无法验证；请保留原数据",
        http_status: None,
    }
}
fn remote(error: ApiError) -> CoordinatorError {
    CoordinatorError {
        message: error.message,
        http_status: error.status,
    }
}
fn condition(status: Option<u16>) -> Condition {
    match status {
        Some(401 | 403) => Condition::SessionRequired,
        Some(404 | 426) => Condition::Unsupported,
        Some(409 | 410) => Condition::Conflict,
        _ => Condition::Retry,
    }
}
pub struct MessageCoordinator {
    owner: Owner,
    api: DirectApi,
    control: DeviceControlApi,
    store: Mutex<Store>,
    gate: TaskGate,
    network: tokio::sync::Mutex<()>,
    session: RwLock<Zeroizing<String>>,
    // Keep isolated native targets until after all task handles close.
    _protection: Protection,
}
impl MessageCoordinator {
    pub fn open(path: &Path, owner: Owner, keys: &KeyPair) -> Result<Self> {
        Self::open_with_protection(path, owner, keys, Protection::default())
    }
    pub fn open_with_protection(
        path: &Path,
        owner: Owner,
        keys: &KeyPair,
        protection: Protection,
    ) -> Result<Self> {
        owner.keys(keys).map_err(local)?;
        let api = DirectApi::new(&owner.origin).map_err(remote)?;
        let control = DeviceControlApi::new(&owner.origin).map_err(|_| local("API".into()))?;
        drop(DeviceTrustStore::open(path).map_err(local)?);
        let store = Store::open(
            path,
            owner.clone(),
            protection.witness(path).map_err(local)?,
        )
        .map_err(local)?;
        Ok(Self {
            owner,
            api,
            control,
            store: Mutex::new(store),
            gate: TaskGate::new().map_err(local)?,
            network: tokio::sync::Mutex::new(()),
            session: RwLock::new(Zeroizing::new(String::new())),
            _protection: protection,
        })
    }
    pub fn renew_session(&self, token: String) -> Result<()> {
        let token = Zeroizing::new(token);
        if token.len() > 256 || token.bytes().any(|b| !b.is_ascii_graphic()) {
            return Err(local("session".into()));
        }
        self.gate
            .rotate_with(|| {
                *self
                    .session
                    .write()
                    .map_err(|_| "会话锁不可用".to_string())? = token;
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
        callback: impl FnOnce(&mut Store) -> std::result::Result<T, String>,
    ) -> Result<T> {
        self.gate
            .with_current(lease, || {
                let mut store = self
                    .store
                    .lock()
                    .map_err(|_| "消息存储锁不可用".to_string())?;
                callback(&mut store)
            })
            .map_err(local)
    }
    fn token(&self, lease: &TaskLease) -> Result<Zeroizing<String>> {
        self.gate
            .with_current(lease, || {
                Ok(self
                    .session
                    .read()
                    .map_err(|_| "会话锁不可用".to_string())?
                    .clone())
            })
            .map_err(local)
    }
    fn current<T>(
        &self,
        lease: &TaskLease,
        task: &TaskView,
        keys: &KeyPair,
        callback: impl FnOnce(&mut Store) -> std::result::Result<T, String>,
    ) -> Result<T> {
        self.with(lease, |store| {
            let now = store.task_view(&task.id, keys)?;
            if now.revision != task.revision || now.digest != task.digest {
                return Err("原任务已变化".into());
            }
            callback(store)
        })
    }
    pub fn confirm_root(&self, anchor: &Anchor, fingerprint: &str, keys: &KeyPair) -> Result<()> {
        let lease = self.lease(keys)?;
        if anchor.origin != self.owner.origin || anchor_fingerprint(anchor) != fingerprint {
            return Err(local("root".into()));
        }
        self.with(&lease, |s| s.trust().pin(anchor).map(|_| ()))
    }
    pub fn tasks(&self, keys: &KeyPair) -> Result<Vec<TaskView>> {
        let lease = self.lease(keys)?;
        self.with(&lease, |s| s.tasks(keys))
    }
    pub fn roots(&self, keys: &KeyPair) -> Result<Vec<Anchor>> {
        let lease = self.lease(keys)?;
        self.with(&lease, |s| s.roots(keys))
    }
    pub fn conversations(&self, keys: &KeyPair) -> Result<Vec<super::conversations::View>> {
        let lease = self.lease(keys)?;
        self.with(&lease, |s| s.conversations(keys))
    }
    pub fn claim_notifications(
        &self,
        keys: &KeyPair,
    ) -> Result<Vec<super::conversations::Notification>> {
        let lease = self.lease(keys)?;
        self.with(&lease, |s| s.claim_notifications(keys))
    }
    pub fn mark_read(&self, peer: &str, through_id: &str, keys: &KeyPair) -> Result<()> {
        let lease = self.lease(keys)?;
        self.with(&lease, |s| s.mark_read(peer, through_id, keys))
    }
    pub fn set_muted(&self, peer: &str, revision: u64, muted: bool, keys: &KeyPair) -> Result<()> {
        let lease = self.lease(keys)?;
        self.with(&lease, |s| s.set_muted(peer, revision, muted, keys))
    }
    pub fn history_peer(
        &self,
        peer: Option<&str>,
        before: Option<i64>,
        limit: usize,
        keys: &KeyPair,
    ) -> Result<Vec<RecordView>> {
        let lease = self.lease(keys)?;
        self.with(&lease, |s| s.history_peer(peer, before, limit, keys))
    }
    pub fn request_cancel(&self, id: &str, keys: &KeyPair) -> Result<TaskView> {
        let lease = self.lease(keys)?;
        self.with(&lease, |s| s.request_cancel(id, keys))
    }
    pub fn clear_accepted(&self, id: &str, keys: &KeyPair) -> Result<()> {
        let lease = self.lease(keys)?;
        self.with(&lease, |s| s.clear_accepted_task(id, keys))
    }
    pub fn history(
        &self,
        before: Option<i64>,
        limit: usize,
        keys: &KeyPair,
    ) -> Result<Vec<RecordView>> {
        let lease = self.lease(keys)?;
        self.with(&lease, |s| s.history(before, limit, keys))
    }
    pub fn draft(&self, peer: &str, keys: &KeyPair) -> Result<super::drafts::View> {
        let lease = self.lease(keys)?;
        self.with(&lease, |s| s.draft(peer, keys))
    }
    pub fn save_draft(
        &self,
        peer: &str,
        revision: u64,
        text: &str,
        keys: &KeyPair,
    ) -> Result<super::drafts::View> {
        let lease = self.lease(keys)?;
        self.with(&lease, |s| s.save_draft(peer, revision, text, keys))
    }
    pub fn text(&self, id: &str, keys: &KeyPair) -> Result<String> {
        let lease = self.lease(keys)?;
        self.with(&lease, |s| s.text(id, keys))
    }
    pub fn hide(&self, id: &str, keys: &KeyPair) -> Result<()> {
        let lease = self.lease(keys)?;
        self.with(&lease, |s| s.hide(id, keys))
    }
    fn pinned(&self, lease: &TaskLease, account: &str, keys: &KeyPair) -> Result<bool> {
        self.with(lease, |s| {
            s.maybe_root(account, keys).map(|root| root.is_some())
        })
    }
    /// Exactly one verified manifest page; never adopt a root supplied by wire.
    async fn sync(
        &self,
        lease: &TaskLease,
        task: Option<&TaskView>,
        account: &str,
        keys: &KeyPair,
    ) -> Result<bool> {
        let (anchor, checkpoint) = self.with(lease, |s| {
            if let Some(task) = task {
                if s.task_view(&task.id, keys)?.revision != task.revision {
                    return Err("原任务已变化".into());
                }
            }
            let anchor = s.root(account, keys)?;
            let state = s.trust().load(&anchor, None)?;
            Ok((anchor, Checkpoint::from_state(&state)))
        })?;
        let token = self.token(lease)?;
        let page = self
            .control
            .manifest(&token, account, checkpoint.revision)
            .await
            .map_err(|error| CoordinatorError {
                message: "单聊 v3 目录未确认，保留原批次",
                http_status: error.status,
            })?;
        self.with(lease, |s| {
            if let Some(task) = task {
                if s.task_view(&task.id, keys)?.revision != task.revision {
                    return Err("原任务已变化".into());
                }
            }
            s.trust().import_page(&anchor, &checkpoint, &page)?;
            Ok(!page.more)
        })
    }
    pub async fn prepare_text(
        &self,
        peer: &str,
        text: &str,
        keys: &KeyPair,
    ) -> Result<Preparation> {
        self.prepare_text_draft(peer, text, None, keys).await
    }
    pub async fn prepare_text_draft(
        &self,
        peer: &str,
        text: &str,
        draft_revision: Option<u64>,
        keys: &KeyPair,
    ) -> Result<Preparation> {
        if text.is_empty() || text.len() > liteseal_shared::direct_message::MAX_BODY {
            return Err(local("text".into()));
        }
        let lease = self.lease(keys)?;
        let _network = self.network.lock().await;
        let token = self.token(&lease)?;
        if token.is_empty() {
            return Ok(Preparation {
                task: None,
                condition: Condition::SessionRequired,
                http_status: None,
            });
        }
        for account in [&self.owner.account, peer] {
            if !self.pinned(&lease, account, keys)? {
                return Ok(Preparation {
                    task: None,
                    condition: Condition::NeedsTrust,
                    http_status: None,
                });
            }
            match self.sync(&lease, None, account, keys).await {
                Ok(true) => {}
                Ok(false) => {
                    return Ok(Preparation {
                        task: None,
                        condition: Condition::Syncing,
                        http_status: None,
                    })
                }
                Err(error) => {
                    self.with(&lease, |_| Ok(()))?;
                    return Ok(Preparation {
                        task: None,
                        condition: condition(error.http_status),
                        http_status: error.http_status,
                    });
                }
            }
        }
        let task = self.with(&lease, |s| {
            s.prepare_with_draft(
                Prepare {
                    id: &uuid::Uuid::new_v4().to_string(),
                    peer,
                    sent_at: chrono::Utc::now().timestamp_millis(),
                    kind: Kind::Text,
                    body: text.as_bytes(),
                },
                draft_revision,
                keys,
            )
        })?;
        Ok(Preparation {
            condition: match task.state {
                TaskState::Accepted => Condition::Accepted,
                TaskState::Cancelled => Condition::Cancelled,
                TaskState::Conflict => Condition::Conflict,
                _ => Condition::Prepared,
            },
            task: Some(task),
            http_status: None,
        })
    }
    fn failed(
        &self,
        lease: &TaskLease,
        task: &TaskView,
        keys: &KeyPair,
        status: Option<u16>,
    ) -> Result<Progress> {
        self.current(lease, task, keys, |_| Ok(()))?;
        Ok(Progress {
            task: self.with(lease, |s| s.task_view(&task.id, keys))?,
            condition: condition(status),
            http_status: status,
        })
    }
    fn apply(
        &self,
        lease: &TaskLease,
        task: &TaskView,
        batch: &Batch,
        result: AuthenticatedResult,
        keys: &KeyPair,
    ) -> Result<Option<Progress>> {
        match result.outcome {
            Outcome::Unknown { .. } => {
                self.current(lease, task, keys, |_| Ok(()))?;
                Ok(None)
            }
            Outcome::Accepted {
                receipt,
                acknowledgements,
            } => {
                let accepted = Acceptance::from_authenticated_response(
                    batch,
                    &receipt.id,
                    receipt.digest,
                    receipt.accepted_at,
                )
                .map_err(local)?;
                let task = self.current(lease, task, keys, |s| {
                    s.validate_acks(batch, &acknowledgements, keys)?;
                    s.confirm_accepted(&accepted, keys)
                })?;
                Ok(Some(Progress {
                    task,
                    condition: Condition::Accepted,
                    http_status: None,
                }))
            }
            Outcome::Cancelled { digest, .. } => {
                let task = self.current(lease, task, keys, |s| {
                    let fenced = s.confirm_unaccepted(&task.id, digest, keys)?;
                    s.cancel_unpublished(&task.id, fenced.revision, keys)
                })?;
                Ok(Some(Progress {
                    task,
                    condition: Condition::Cancelled,
                    http_status: None,
                }))
            }
        }
    }
    pub async fn step(&self, id: &str, keys: &KeyPair) -> Result<Progress> {
        let lease = self.lease(keys)?;
        let _network = self.network.lock().await;
        let mut task = self.with(&lease, |s| s.task_view(id, keys))?;
        match task.state {
            TaskState::Accepted => {
                return Ok(Progress {
                    task,
                    condition: Condition::Accepted,
                    http_status: None,
                })
            }
            TaskState::Cancelled => {
                return Ok(Progress {
                    task,
                    condition: Condition::Cancelled,
                    http_status: None,
                })
            }
            TaskState::Conflict => {
                task = self.with(&lease, |s| s.cancel_unpublished(id, task.revision, keys))?;
                return Ok(Progress {
                    task,
                    condition: Condition::Cancelled,
                    http_status: None,
                });
            }
            _ => {}
        }
        if self.token(&lease)?.is_empty() {
            return self.failed(&lease, &task, keys, Some(401));
        }
        if task.state == TaskState::Prepared {
            task = self.current(&lease, &task, keys, |s| {
                s.begin_publish(id, task.revision, keys)
            })?;
        }
        let batch = self.current(&lease, &task, keys, |s| s.original(id, keys))?;
        let token = self.token(&lease)?;
        let result = match self.api.lookup(&token, &batch).await {
            Ok(result) => result,
            Err(error) => return self.failed(&lease, &task, keys, error.status),
        };
        if let Some(progress) = self.apply(&lease, &task, &batch, result, keys)? {
            return Ok(progress);
        }
        if !task.cancel_requested {
            for account in [&self.owner.account, &batch.header.peer] {
                match self.sync(&lease, Some(&task), account, keys).await {
                    Ok(true) => {}
                    Ok(false) => {
                        return Ok(Progress {
                            task,
                            condition: Condition::Syncing,
                            http_status: None,
                        })
                    }
                    Err(error) => return self.failed(&lease, &task, keys, error.http_status),
                }
            }
            if !self.current(&lease, &task, keys, |s| s.is_current(&batch, keys))? {
                return Ok(Progress {
                    task,
                    condition: Condition::Conflict,
                    http_status: None,
                });
            }
        }
        self.current(&lease, &task, keys, |_| Ok(()))?;
        let token = self.token(&lease)?;
        let result = if task.cancel_requested {
            self.api.cancel(&token, &batch).await
        } else {
            self.api.publish(&token, &batch).await
        };
        let result = match result {
            Ok(result) => result,
            Err(error) => return self.failed(&lease, &task, keys, error.status),
        };
        self.apply(&lease, &task, &batch, result, keys)?
            .ok_or_else(|| local("unconfirmed mutation".into()))
    }
    fn poll_result(
        &self,
        lease: &TaskLease,
        cond: Condition,
        acknowledged: usize,
        status: Option<u16>,
    ) -> Result<Poll> {
        self.with(lease, |_| Ok(()))?;
        Ok(Poll {
            condition: cond,
            received: 0,
            acknowledged,
            has_more: false,
            http_status: status,
        })
    }
    /// At most one ACK and one delivery per invocation. Scheduler policy and
    /// notifications belong to the eventual activated desktop lifecycle.
    pub async fn poll(&self, keys: &KeyPair) -> Result<Poll> {
        let lease = self.lease(keys)?;
        let _network = self.network.lock().await;
        let token = self.token(&lease)?;
        if token.is_empty() {
            return self.poll_result(&lease, Condition::SessionRequired, 0, None);
        }
        let mut acknowledged = 0;
        let ack = self.with(&lease, |s| {
            s.pending_acks(keys).map(|acks| acks.into_iter().next())
        })?;
        if let Some(ack) = ack {
            let token = self.token(&lease)?;
            match self.api.ack(&token, &ack).await {
                Ok(()) => {
                    self.with(&lease, |s| s.confirm_ack(&ack, keys))?;
                    acknowledged = 1;
                }
                Err(error) => {
                    return self.poll_result(&lease, condition(error.status), 0, error.status)
                }
            }
        }
        if !self.pinned(&lease, &self.owner.account, keys)? {
            return self.poll_result(&lease, Condition::NeedsTrust, acknowledged, None);
        }
        match self.sync(&lease, None, &self.owner.account, keys).await {
            Ok(true) => {}
            Ok(false) => return self.poll_result(&lease, Condition::Syncing, acknowledged, None),
            Err(error) => {
                return self.poll_result(
                    &lease,
                    condition(error.http_status),
                    acknowledged,
                    error.http_status,
                )
            }
        }
        let token = self.token(&lease)?;
        let page = match self
            .api
            .pending(&token, &self.owner.account, &self.owner.device.device_id, 1)
            .await
        {
            Ok(page) => page.page,
            Err(error) => {
                return self.poll_result(
                    &lease,
                    condition(error.status),
                    acknowledged,
                    error.status,
                )
            }
        };
        self.with(&lease, |_| Ok(()))?;
        let Some(item) = page.items.into_iter().next() else {
            let has_more = self.with(&lease, |s| {
                s.pending_acks(keys).map(|acks| !acks.is_empty())
            })?;
            return Ok(Poll {
                condition: if acknowledged > 0 {
                    Condition::Acknowledged
                } else {
                    Condition::Idle
                },
                received: 0,
                acknowledged,
                has_more,
                http_status: None,
            });
        };
        if item.batch.header.kind != Kind::Text {
            return self.poll_result(&lease, Condition::Unsupported, acknowledged, None);
        }
        for account in [&item.batch.header.sender, &item.batch.header.peer] {
            if !self.pinned(&lease, account, keys)? {
                return self.poll_result(&lease, Condition::NeedsTrust, acknowledged, None);
            }
            let snapshot = if account == &item.batch.header.sender {
                &item.batch.header.sender_directory
            } else {
                &item.batch.header.peer_directory
            };
            let needs = self.with(&lease, |s| {
                let anchor = s.root(account, keys)?;
                let state = s.trust().load(&anchor, None)?;
                Ok(state.revision() < snapshot.revision)
            })?;
            if needs {
                match self.sync(&lease, None, account, keys).await {
                    Ok(true) => {}
                    Ok(false) => {
                        return self.poll_result(&lease, Condition::Syncing, acknowledged, None)
                    }
                    Err(error) => {
                        return self.poll_result(
                            &lease,
                            condition(error.http_status),
                            acknowledged,
                            error.http_status,
                        )
                    }
                }
            }
        }
        let accepted = Acceptance::from_authenticated_response(
            &item.batch,
            &item.receipt.id,
            item.receipt.digest,
            item.receipt.accepted_at,
        )
        .map_err(local)?;
        self.with(&lease, |s| s.receive(&item.batch, &accepted, keys))?;
        Ok(Poll {
            condition: Condition::Received,
            received: 1,
            acknowledged,
            // Even the last remote item has a newly persisted local ACK.
            has_more: true,
            http_status: None,
        })
    }
}
