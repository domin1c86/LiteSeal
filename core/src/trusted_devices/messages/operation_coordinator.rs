//! Immutable original operation retries, bounded log import and lease/revision
//! fences. Operation traffic has its own lane so text and media keep advancing.
use super::*;
use crate::trusted_devices::messages::{
    api::{AuthenticatedOperationResult, RemoteState},
    operations::{OperationTaskView, PrepareOperation},
};
use liteseal_shared::direct_operation::Action;
use std::collections::BTreeSet;

#[derive(Debug, Serialize)]
pub struct OperationProgress {
    pub task: OperationTaskView,
    pub condition: Condition,
    pub http_status: Option<u16>,
}
#[derive(Debug, Serialize)]
pub struct OperationPreparation {
    pub task: Option<OperationTaskView>,
    pub condition: Condition,
    pub http_status: Option<u16>,
}
#[derive(Debug, Serialize)]
pub struct OperationPoll {
    pub condition: Condition,
    pub received: usize,
    pub has_more: bool,
    pub http_status: Option<u16>,
}
impl MessageCoordinator {
    pub fn operation_tasks(&self, keys: &KeyPair) -> Result<Vec<OperationTaskView>> {
        let lease = self.lease(keys)?;
        self.with(&lease, |s| s.operation_tasks(keys))
    }
    fn operation_current<T>(
        &self,
        lease: &TaskLease,
        task: &OperationTaskView,
        keys: &KeyPair,
        callback: impl FnOnce(&mut Store) -> std::result::Result<T, String>,
    ) -> Result<T> {
        self.with(lease, |s| {
            let current = s.operation_task(&task.id, keys)?;
            if current.revision != task.revision || current.digest != task.digest {
                return Err("原操作任务已变化".into());
            }
            callback(s)
        })
    }
    pub fn cancel_operation(
        &self,
        id: &str,
        revision: u64,
        keys: &KeyPair,
    ) -> Result<OperationTaskView> {
        let lease = self.lease(keys)?;
        self.with(&lease, |s| {
            let task = s.operation_task(id, keys)?;
            // Background publishing may have advanced state since the displayed
            // view. This id/digest is immutable: cancel the same original intent
            // with a fresh local CAS, never a replacement operation.
            if revision > task.revision {
                return Err("原操作修订无效".into());
            }
            s.request_operation_cancel(id, task.revision, keys)
        })
    }
    pub fn clear_operation_task(&self, id: &str, revision: u64, keys: &KeyPair) -> Result<()> {
        let lease = self.lease(keys)?;
        self.with(&lease, |s| s.clear_operation_task(id, revision, keys))
    }
    async fn sync_operation(
        &self,
        lease: &TaskLease,
        task: &OperationTaskView,
        account: &str,
        keys: &KeyPair,
    ) -> Result<bool> {
        let (anchor, checkpoint) = self.operation_current(lease, task, keys, |s| {
            let anchor = s.root(account, keys)?;
            let state = s.trust().load(&anchor, None)?;
            Ok((anchor, Checkpoint::from_state(&state)))
        })?;
        let token = self.token(lease)?;
        let page = self
            .control
            .manifest(&token, account, checkpoint.revision)
            .await
            .map_err(|e| CoordinatorError {
                message: "原操作的目录尚未确认",
                http_status: e.status,
            })?;
        self.operation_current(lease, task, keys, |s| {
            s.trust().import_page(&anchor, &checkpoint, &page)?;
            Ok(!page.more)
        })
    }
    pub async fn prepare_operation(
        &self,
        request: PrepareOperation<'_>,
        keys: &KeyPair,
    ) -> Result<OperationPreparation> {
        if request.action == Action::Edit
            && request
                .text
                .is_none_or(|s| s.is_empty() || s.len() > liteseal_shared::direct_message::MAX_BODY)
            || request.action == Action::Retract && request.text.is_some()
        {
            return Err(local("operation body".into()));
        }
        let lease = self.lease(keys)?;
        let _network = self.operation_network.lock().await;
        // A saved id is never re-encrypted, even when its current directory has
        // changed. The store compares the original request and returns it.
        if self
            .with(&lease, |s| s.operation_tasks(keys))?
            .iter()
            .any(|t| t.id == request.id)
        {
            let task = self.with(&lease, |s| s.prepare_operation(request, keys))?;
            let condition = match task.state {
                TaskState::Accepted => Condition::Accepted,
                TaskState::Cancelled => Condition::Cancelled,
                TaskState::Conflict => Condition::Conflict,
                _ => Condition::Prepared,
            };
            return Ok(OperationPreparation {
                task: Some(task),
                condition,
                http_status: None,
            });
        }
        let peer = self.with(&lease, |s| s.operation_peer(request.target, keys))?;
        if self.token(&lease)?.is_empty() {
            return Ok(OperationPreparation {
                task: None,
                condition: Condition::SessionRequired,
                http_status: None,
            });
        }
        for account in [&self.owner.account, &peer] {
            if !self.pinned(&lease, account, keys)? {
                return Ok(OperationPreparation {
                    task: None,
                    condition: Condition::NeedsTrust,
                    http_status: None,
                });
            }
            let synced = self.sync(&lease, None, account, keys).await;
            self.with(&lease, |_| Ok(()))?;
            match synced {
                Ok(true) => {}
                Ok(false) => {
                    return Ok(OperationPreparation {
                        task: None,
                        condition: Condition::Syncing,
                        http_status: None,
                    })
                }
                Err(error) => {
                    return Ok(OperationPreparation {
                        task: None,
                        condition: condition(error.http_status),
                        http_status: error.http_status,
                    })
                }
            }
        }
        let task = self.with(&lease, |s| s.prepare_operation(request, keys))?;
        Ok(OperationPreparation {
            task: Some(task),
            condition: Condition::Prepared,
            http_status: None,
        })
    }
    fn operation_progress(
        &self,
        lease: &TaskLease,
        task: &OperationTaskView,
        keys: &KeyPair,
        cond: Condition,
        status: Option<u16>,
    ) -> Result<OperationProgress> {
        self.operation_current(lease, task, keys, |_| Ok(()))?;
        Ok(OperationProgress {
            task: self.with(lease, |s| s.operation_task(&task.id, keys))?,
            condition: cond,
            http_status: status,
        })
    }
    fn operation_apply(
        &self,
        lease: &TaskLease,
        task: &OperationTaskView,
        response: AuthenticatedOperationResult,
        keys: &KeyPair,
    ) -> Result<Option<OperationProgress>> {
        let state = response.state();
        let saved = self.operation_current(lease, task, keys, |s| {
            s.confirm_operation_result(&task.id, task.revision, &response, keys)
        })?;
        match state {
            RemoteState::Unknown => Ok(None),
            RemoteState::Accepted | RemoteState::Cancelled => Ok(Some(OperationProgress {
                task: saved,
                condition: if state == RemoteState::Accepted {
                    Condition::Accepted
                } else {
                    Condition::Cancelled
                },
                http_status: None,
            })),
        }
    }
    pub async fn operation_step(&self, id: &str, keys: &KeyPair) -> Result<OperationProgress> {
        let lease = self.lease(keys)?;
        let _network = self.operation_network.lock().await;
        let mut task = self.with(&lease, |s| s.operation_task(id, keys))?;
        match task.state {
            TaskState::Accepted => {
                return self.operation_progress(&lease, &task, keys, Condition::Accepted, None)
            }
            TaskState::Cancelled => {
                return self.operation_progress(&lease, &task, keys, Condition::Cancelled, None)
            }
            _ => {}
        }
        let token = self.token(&lease)?;
        if token.is_empty() {
            return self.operation_progress(&lease, &task, keys, Condition::SessionRequired, None);
        }
        // Record attempted state before any mutation. Unknown/timeout preserves
        // this exact wire; a later cancel must establish a remote fence.
        if task.state == TaskState::Prepared {
            task = self.operation_current(&lease, &task, keys, |s| {
                s.begin_operation_publish(id, task.revision, keys)
            })?;
        }
        let original =
            self.operation_current(&lease, &task, keys, |s| s.operation_original(id, keys))?;
        let result = match self.api.operation_lookup(&token, &original).await {
            Ok(result) => result,
            Err(error) => {
                return self.operation_progress(
                    &lease,
                    &task,
                    keys,
                    condition(error.status),
                    error.status,
                )
            }
        };
        if let Some(progress) = self.operation_apply(&lease, &task, result, keys)? {
            return Ok(progress);
        }
        if task.state == TaskState::Conflict && !task.cancel_requested {
            return self.operation_progress(&lease, &task, keys, Condition::Conflict, None);
        }
        if !task.cancel_requested {
            for account in [&self.owner.account, &task.peer] {
                self.operation_current(&lease, &task, keys, |_| Ok(()))?;
                let synced = self.sync_operation(&lease, &task, account, keys).await;
                self.operation_current(&lease, &task, keys, |_| Ok(()))?;
                match synced {
                    Ok(true) => {}
                    Ok(false) => {
                        return self.operation_progress(
                            &lease,
                            &task,
                            keys,
                            Condition::Syncing,
                            None,
                        )
                    }
                    Err(error) => {
                        return self.operation_progress(
                            &lease,
                            &task,
                            keys,
                            condition(error.http_status),
                            error.http_status,
                        )
                    }
                }
            }
            task = self.operation_current(&lease, &task, keys, |s| {
                s.begin_operation_publish(id, task.revision, keys)
            })?;
            if task.state == TaskState::Conflict {
                return self.operation_progress(&lease, &task, keys, Condition::Conflict, None);
            }
        }
        self.operation_current(&lease, &task, keys, |_| Ok(()))?;
        let token = self.token(&lease)?;
        let result = if task.cancel_requested {
            self.api.operation_cancel(&token, &original).await
        } else {
            self.api.operation_publish(&token, &original).await
        };
        match result {
            Ok(result) => self
                .operation_apply(&lease, &task, result, keys)?
                .ok_or_else(|| local("unknown operation mutation".into())),
            Err(error) => {
                self.operation_progress(&lease, &task, keys, condition(error.status), error.status)
            }
        }
    }
    pub async fn poll_operations(&self, keys: &KeyPair) -> Result<OperationPoll> {
        let lease = self.lease(keys)?;
        let _network = self.operation_network.lock().await;
        let empty = |cond, status| -> Result<OperationPoll> {
            self.with(&lease, |_| Ok(()))?;
            Ok(OperationPoll {
                condition: cond,
                received: 0,
                has_more: false,
                http_status: status,
            })
        };
        let token = self.token(&lease)?;
        if token.is_empty() {
            return empty(Condition::SessionRequired, None);
        }
        match self.sync(&lease, None, &self.owner.account, keys).await {
            Ok(true) => {}
            Ok(false) => return empty(Condition::Syncing, None),
            Err(error) => return empty(condition(error.http_status), error.http_status),
        }
        let after = self.with(&lease, |s| s.operation_cursor(keys))?;
        let page = match self
            .api
            .operations(
                &token,
                &self.owner.account,
                &self.owner.device.device_id,
                after,
                8,
            )
            .await
        {
            Ok(page) => page,
            Err(error) => return empty(condition(error.status), error.status),
        };
        self.with(&lease, |_| Ok(()))?;
        let accounts: BTreeSet<_> = page
            .page
            .events
            .iter()
            .flat_map(|e| {
                [
                    &e.operation.original.header.sender,
                    &e.operation.original.header.peer,
                ]
            })
            .cloned()
            .collect();
        for account in accounts {
            if !self.pinned(&lease, &account, keys)? {
                return empty(Condition::NeedsTrust, None);
            }
            match self.sync(&lease, None, &account, keys).await {
                Ok(true) => {}
                Ok(false) => return empty(Condition::Syncing, None),
                Err(error) => return empty(condition(error.http_status), error.http_status),
            }
        }
        self.with(&lease, |s| {
            s.import_authenticated_operations(after, &page, keys)
        })?;
        Ok(OperationPoll {
            condition: if page.is_empty() {
                Condition::Idle
            } else {
                Condition::Received
            },
            received: page.len(),
            has_more: page.has_more(),
            http_status: None,
        })
    }
}
