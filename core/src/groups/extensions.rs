use super::*;
use liteseal_shared::{collaboration::Member, group_extension as e};
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExtensionCommand {
    Activity {
        title: String,
        start_at: i64,
        timezone: String,
        location: String,
        description: String,
    },
    Respond {
        activity: String,
        answer: e::Answer,
        revision: u64,
    },
    Close {
        activity: String,
        revision: u64,
    },
    Cancel {
        activity: String,
        revision: u64,
    },
}
impl GroupClient {
    pub fn extension_has_task(&self, id: &str) -> Result<bool, String> {
        Ok(self.store()?.extension_task(id)?.is_some())
    }
    pub async fn extension_supported(&self, id: &str) -> Result<bool, String> {
        match self.api.extension_capability(id).await {
            Ok(1) => Ok(true),
            Ok(_) => Ok(false),
            Err(e) if e.status == Some(404) => Ok(false),
            Err(e) => Err(e.to_string()),
        }
    }
    pub fn extension_view(
        &self,
        id: &str,
        ids: &[String],
        keys: &crypto::KeyPair,
    ) -> Result<ExtensionView, String> {
        self.store()?.extension_view(id, ids, keys)
    }
    pub fn extension_attachment(
        &self,
        id: &str,
        object: &str,
        keys: &crypto::KeyPair,
    ) -> Result<e::Attachment, String> {
        self.store()?.extension_attachment(id, object, keys)
    }
    pub async fn extension_sync(&self, id: &str, keys: &crypto::KeyPair) -> Result<usize, String> {
        let _guard = self.gate.lock().await;
        self.extension_sync_inner(id, keys).await
    }
    async fn extension_sync_inner(
        &self,
        id: &str,
        keys: &crypto::KeyPair,
    ) -> Result<usize, String> {
        check_keys(&self.identity, keys)?;
        self.sync_inner(id).await?;
        let mut changed = 0;
        for _ in 0..100 {
            let after = self.store()?.extension_cursor(id)?;
            let page = self
                .api
                .extension_page(id, after)
                .await
                .map_err(|e| e.to_string())?;
            changed += self.store()?.extension_apply(id, &page, keys)?;
            if !page.more {
                return Ok(changed);
            }
        }
        Err("群扩展同步超出范围".into())
    }
    async fn extension_retry_inner(
        &self,
        id: &str,
        keys: &crypto::KeyPair,
    ) -> Result<Option<GroupMessageReceipt>, String> {
        if self.store()?.extension_conflicted(id)? {
            return Err("原群扩展发生版本冲突，请取消或重新创建".into());
        }
        let Some(task) = self.store()?.extension_pending(id)? else {
            return Ok(None);
        };
        if task.event.actor.user != self.identity.user_id
            || task.event.actor.device != self.identity.device_id
        {
            return Err("本机群身份已改变".into());
        }
        let receipt = match self.api.extension_submit(id, &task).await {
            Ok(r) => r,
            Err(error) => {
                if error.status == Some(409) {
                    self.store()?.extension_conflict(id, &task.event.id)?;
                }
                return Err(error.to_string());
            }
        };
        self.store()?
            .extension_accepted(id, &task, &receipt, keys)?;
        Ok(receipt.root)
    }
    pub async fn extension_retry(&self, id: &str, keys: &crypto::KeyPair) -> Result<(), String> {
        check_keys(&self.identity, keys)?;
        let _guard = self.gate.lock().await;
        self.extension_retry_inner(id, keys).await?;
        let group = self.state(id)?;
        if !group.closed() && group.member(&self.identity.user_id).is_some() {
            self.extension_sync_inner(id, keys).await?;
        }
        Ok(())
    }
    pub async fn extension_cancel_task(
        &self,
        id: &str,
        keys: &crypto::KeyPair,
    ) -> Result<(), String> {
        check_keys(&self.identity, keys)?;
        let _guard = self.gate.lock().await;
        let Some(task) = self.store()?.extension_task(id)? else {
            return Ok(());
        };
        let result = self
            .api
            .extension_cancel(
                id,
                &task.event.id,
                task.event
                    .action
                    .creates()
                    .then_some(task.event.object.as_str()),
            )
            .await
            .map_err(|e| e.to_string())?;
        match (result.cancelled, result.receipt) {
            (true, None) => self.store()?.extension_cancelled(id, &task),
            (false, Some(receipt)) => {
                self.store()?
                    .extension_accepted(id, &task, &receipt, keys)?;
                Err("原扩展已接受，不能取消发送任务".into())
            }
            _ => Err("群扩展取消结果不确定".into()),
        }
    }
    pub async fn send_extension_content(
        &self,
        id: &str,
        content: &e::Content,
        keys: &crypto::KeyPair,
    ) -> Result<String, String> {
        let _guard = self.gate.lock().await;
        check_keys(&self.identity, keys)?;
        self.sync_inner(id).await?;
        if self
            .api
            .extension_capability(id)
            .await
            .map_err(|e| e.to_string())?
            != 1
        {
            return Err("服务端不支持群扩展".into());
        }
        let message = self.store()?.seal_extension(id, content, keys)?;
        self.extension_retry_inner(id, keys).await?;
        Ok(message)
    }
    pub async fn extension_submit(
        &self,
        id: &str,
        command: ExtensionCommand,
        keys: &crypto::KeyPair,
    ) -> Result<(), String> {
        if let ExtensionCommand::Activity {
            title,
            start_at,
            timezone,
            location,
            description,
        } = command
        {
            self.send_extension_content(
                id,
                &e::Content::Activity(e::Activity {
                    title,
                    start_at,
                    timezone,
                    location,
                    description,
                }),
                keys,
            )
            .await?;
            return Ok(());
        }
        let _guard = self.gate.lock().await;
        self.extension_sync_inner(id, keys).await?;
        let group = self.state(id)?;
        let (object, revision, action) = match command {
            ExtensionCommand::Respond {
                activity,
                answer,
                revision,
            } => (activity, revision, e::Action::Respond { answer }),
            ExtensionCommand::Close { activity, revision } => {
                (activity, revision, e::Action::Close)
            }
            ExtensionCommand::Cancel { activity, revision } => {
                (activity, revision, e::Action::Cancel)
            }
            _ => unreachable!(),
        };
        let previous = self
            .store()?
            .extension_object(id, &object)?
            .ok_or("活动尚未取得")?;
        if previous.revision != revision {
            return Err("活动状态已改变，请刷新后重试".into());
        }
        let me = Member::from(
            group
                .member(&self.identity.user_id)
                .ok_or("本机已不在群中")?,
        );
        let task = e::make(
            &group,
            &me,
            object,
            uuid::Uuid::new_v4().to_string(),
            Some(&previous),
            action,
            None,
            vec![],
            keys,
            now(),
        )
        .map_err(|_| "活动报名或管理权限不符合要求")?;
        self.store()?.extension_queue(&task)?;
        self.extension_retry_inner(id, keys).await?;
        self.extension_sync_inner(id, keys).await?;
        Ok(())
    }
}
