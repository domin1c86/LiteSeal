use super::*;
use liteseal_shared::collaboration as c;
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CollaborationCommand {
    Mention {
        text: String,
        mentions: Vec<c::Member>,
    },
    Poll {
        question: String,
        options: Vec<String>,
    },
    Vote {
        poll: String,
        option: String,
        revision: u64,
    },
    Close {
        poll: String,
        revision: u64,
    },
    Pin {
        message: Option<String>,
        revision: u64,
    },
}
impl GroupClient {
    pub fn collaboration_view(
        &self,
        id: &str,
        keys: &crypto::KeyPair,
    ) -> Result<CollaborationView, String> {
        self.store()?.collaboration_view(id, keys)
    }
    pub fn collaboration_discard_conflict(&self, id: &str) -> Result<(), String> {
        self.store()?.collaboration_discard_conflict(id)
    }
    pub async fn collaboration_sync(
        &self,
        id: &str,
        keys: &crypto::KeyPair,
    ) -> Result<bool, String> {
        let _gate = self.gate.lock().await;
        self.sync_inner(id).await?;
        self.collaboration_sync_inner(id, keys).await
    }
    async fn collaboration_sync_inner(
        &self,
        id: &str,
        keys: &crypto::KeyPair,
    ) -> Result<bool, String> {
        match self.api.collaboration_capability(id).await {
            Ok(1) => {}
            Ok(_) => return Ok(false),
            Err(error) if error.status == Some(404) => return Ok(false),
            Err(error) => return Err(error.to_string()),
        }
        for _ in 0..10 {
            let after = self.store()?.collaboration_cursor(id)?;
            let page = self
                .api
                .collaboration_page(id, after)
                .await
                .map_err(|e| e.to_string())?;
            self.store()?.collaboration_apply(id, &page, keys)?;
            let ack = self.store()?.collaboration_acks(id)?;
            if !ack.is_empty() {
                self.api
                    .collaboration_ack(id, &ack)
                    .await
                    .map_err(|e| e.to_string())?;
                self.store()?.collaboration_acked(id, &ack)?;
            }
            if !page.more {
                return Ok(true);
            }
        }
        Err("群协作记录尚未补收完成，请继续同步".into())
    }
    pub async fn collaboration_retry(
        &self,
        id: &str,
        keys: &crypto::KeyPair,
    ) -> Result<(), String> {
        let _gate = self.gate.lock().await;
        self.collaboration_retry_inner(id).await?;
        self.sync_inner(id).await?;
        self.collaboration_sync_inner(id, keys).await?;
        Ok(())
    }
    async fn collaboration_retry_inner(&self, id: &str) -> Result<(), String> {
        let pending = self.store()?.collaboration_pending(id)?;
        let Some(pending) = pending else {
            return Ok(());
        };
        match self.api.collaboration_submit(id, &pending).await {
            Ok(seq) if seq > 0 => self.store()?.collaboration_accepted(id, &pending.event.id),
            Ok(_) => Err("群协作收据无效，原任务已保留".into()),
            Err(error) => {
                if error.status == Some(409) {
                    self.store()?
                        .collaboration_conflict(id, &pending.event.id)?;
                    return Err(
                        "群协作版本或权限已变化，任务保留为冲突；请同步后放弃冲突任务，再重新操作"
                            .into(),
                    );
                }
                Err(error.to_string())
            }
        }
    }
    pub async fn collaboration_send(
        &self,
        id: &str,
        command: CollaborationCommand,
        keys: &crypto::KeyPair,
    ) -> Result<(), String> {
        check_keys(&self.identity, keys)?;
        let _gate = self.gate.lock().await;
        let group = self.sync_inner(id).await?;
        if !self.collaboration_sync_inner(id, keys).await? {
            return Err("服务端不支持群协作，请升级后重试".into());
        }
        let actor = c::Member::from(group.member(&self.identity.user_id).ok_or("当前不在群内")?);
        let event_id = uuid::Uuid::new_v4().to_string();
        let (object, expected, action, plain, target) = match command {
            CollaborationCommand::Mention { text, mentions } => (
                event_id.clone(),
                0,
                c::Action::Mention,
                Some(c::Content::Mention { text, mentions }),
                None,
            ),
            CollaborationCommand::Poll { question, options } => {
                let options: Vec<_> = options
                    .into_iter()
                    .map(|text| c::OptionText {
                        id: uuid::Uuid::new_v4().to_string(),
                        text: text.trim().into(),
                    })
                    .collect();
                (
                    event_id.clone(),
                    0,
                    c::Action::Poll {
                        options: options.iter().map(|o| o.id.clone()).collect(),
                    },
                    Some(c::Content::Poll {
                        question: question.trim().into(),
                        options,
                    }),
                    None,
                )
            }
            CollaborationCommand::Vote {
                poll,
                option,
                revision,
            } => (poll, revision, c::Action::Vote { option }, None, None),
            CollaborationCommand::Close { poll, revision } => {
                (poll, revision, c::Action::Close, None, None)
            }
            CollaborationCommand::Pin { message, revision } => (
                id.into(),
                revision,
                c::Action::Pin {
                    target_hash: message.as_ref().map(|m| c::digest(m.as_bytes())),
                },
                Some(c::Content::Pin {
                    message_id: message.clone(),
                }),
                message,
            ),
        };
        let prior = self.store()?.collaboration_object(id, &object)?;
        if prior.as_ref().map_or(0, |p| p.revision) != expected {
            return Err("群协作版本已变化，请刷新后重新操作".into());
        }
        let current = c::members(&group);
        let audience = if let Some(target) = &target {
            self.store()?.collaboration_pin_audience(id, target)?
        } else if matches!(action, c::Action::Vote { .. } | c::Action::Close) {
            prior
                .as_ref()
                .ok_or("投票不存在")?
                .audience
                .iter()
                .filter(|m| current.contains(m))
                .cloned()
                .collect()
        } else {
            current
        };
        let mut event = c::Event {
            version: 1,
            id: event_id,
            group: id.into(),
            epoch: group.epoch(),
            membership_hash: group.revision_hash().to_vec(),
            actor,
            object,
            revision: expected + 1,
            previous: prior.as_ref().map_or(vec![], |p| p.head.clone()),
            at: now(),
            action,
            audience,
            slots: vec![],
            signature: vec![],
        };
        let mut boxes = vec![];
        if let Some(plain) = &plain {
            c::validate_content(&event, plain)
                .map_err(|_| "群协作内容无效，请检查长度、选项或提及成员")?;
            let bytes = serde_json::to_vec(&("collab-content-v1", &event.id, plain))
                .map_err(|_| "群协作编码失败")?;
            for member in &event.audience {
                let pk: [u8; 32] = group
                    .member(&member.user)
                    .ok_or("成员已变化")?
                    .identity
                    .public_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| "公钥无效")?;
                let cipher =
                    crypto::encrypt(&bytes, &pk, &keys.secret_key).map_err(|_| "群协作加密失败")?;
                event.slots.push(c::Slot {
                    member: member.clone(),
                    hash: c::digest(&cipher),
                });
                boxes.push(c::Boxed {
                    member: member.clone(),
                    ciphertext: cipher,
                });
            }
        }
        event.signature =
            crypto::sign(&event.signing_bytes(), &keys.ed25519_sk).map_err(|_| "群协作签名失败")?;
        let submission = c::Submission {
            event,
            boxes,
            pin_target: target,
        };
        self.store()?
            .collaboration_queue(&submission, plain.as_ref(), keys)?;
        self.collaboration_retry_inner(id).await?;
        self.collaboration_sync_inner(id, keys).await?;
        Ok(())
    }
}
