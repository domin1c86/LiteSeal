//! Private group business logic. Secrets stay in the calling Rust key owner.
pub mod api;
mod store;
use liteseal_shared::{crypto, group::*};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::sync::{Mutex, MutexGuard};
pub use store::{GroupHistoryPage, GroupLocalMessage, GroupNotification, GroupStore};
use tokio::sync::Mutex as AsyncMutex;

fn check_keys(identity: &GroupIdentity, keys: &crypto::KeyPair) -> Result<(), String> {
    if identity.public_key != keys.public_key || identity.signing_key != keys.ed25519_pk {
        return Err("群身份与本机密钥不一致".into());
    }
    let proof = b"LiteSeal/group-local-key-check/v1";
    let signed = crypto::sign(proof, &keys.ed25519_sk).map_err(|_| "本机签名密钥无效")?;
    if !crypto::verify_with_public_key(proof, &signed, &keys.ed25519_pk)
        .map_err(|_| "本机签名密钥无效")?
    {
        return Err("本机签名密钥无效".into());
    }
    // An independent peer checks the advertised encryption key, rather than
    // encrypting and decrypting with the same possibly mismatched secret.
    let peer = crypto::generate_keypair().map_err(|_| "本机加密密钥无法验证")?;
    let cipher = crypto::encrypt(proof, &peer.public_key, &keys.secret_key)
        .map_err(|_| "本机加密密钥无法验证")?;
    if crypto::decrypt(&cipher, &keys.public_key, &peer.secret_key)
        .map_err(|_| "本机加密密钥无效")?
        != proof
    {
        return Err("本机加密密钥无效".into());
    }
    Ok(())
}
fn now() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Keep one client per account store. The async gate serializes network-driven
/// mutations; the SQLite mutex is never held across await.
pub struct GroupClient {
    api: api::GroupApi,
    identity: GroupIdentity,
    store: Mutex<GroupStore>,
    gate: AsyncMutex<()>,
}
impl GroupClient {
    pub fn new(
        path: &str,
        server: &str,
        token: String,
        identity: GroupIdentity,
    ) -> Result<Self, String> {
        let api = api::GroupApi::new(server, token, identity.device_id.clone())?;
        let store = GroupStore::open(path, &api.origin, identity.clone())?;
        Ok(Self {
            api,
            identity,
            store: Mutex::new(store),
            gate: AsyncMutex::new(()),
        })
    }
    fn store(&self) -> Result<MutexGuard<'_, GroupStore>, String> {
        self.store.lock().map_err(|_| "群本机存储锁不可用".into())
    }
    pub async fn update_token(&self, token: String) -> Result<(), String> {
        if self.api.token_matches(&token) {
            return Ok(());
        }
        let _gate = self.gate.lock().await;
        self.api.update_token(token)
    }
    pub fn invalidate_token_if(&self, expected: &str) {
        self.api.invalidate_token_if(expected);
    }
    pub fn pending(&self, id: &str) -> Result<bool, String> {
        Ok(self.store()?.queued(id)?.is_some())
    }
    pub fn muted(&self, id: &str) -> Result<bool, String> {
        self.store()?.muted(id)
    }
    pub fn set_muted(&self, id: &str, muted: bool) -> Result<(), String> {
        self.store()?.set_muted(id, muted)
    }
    pub fn take_notifications(&self) -> Result<Vec<GroupNotification>, String> {
        self.store()?.take_notifications()
    }
    pub fn unread(&self, id: &str) -> Result<i64, String> {
        self.store()?.unread(id)
    }
    pub fn mark_seen(&self, id: &str, ids: &[String]) -> Result<(), String> {
        self.store()?.mark_seen(id, ids)
    }
    pub fn draft(&self, id: &str, keys: &crypto::KeyPair) -> Result<String, String> {
        self.store()?.draft(id, keys)
    }
    pub fn save_draft(&self, id: &str, text: &str, keys: &crypto::KeyPair) -> Result<(), String> {
        self.store()?.save_draft(id, text, keys)
    }
    pub async fn creator_hint(&self, id: &str) -> Result<(String, GroupIdentity), String> {
        let page = self.api.changes(id, 0).await.map_err(|e| e.to_string())?;
        let first = page
            .changes
            .first()
            .filter(|event| event.group_id == id && event.epoch == 1)
            .ok_or("没有可核实的群创建记录")?;
        match &first.action {
            GroupAction::Create { name, owner } => {
                pin_creation(first, owner).map_err(|_| "群创建签名记录无效")?;
                Ok((name.clone(), owner.clone()))
            }
            _ => Err("群创建记录格式无效".into()),
        }
    }
    /// The hint above remains untrusted until this separately verified owner
    /// is supplied by the business layer and its signed prefix is pinned.
    pub async fn recover_trusted(
        &self,
        id: &str,
        owner: &GroupIdentity,
    ) -> Result<GroupState, String> {
        let _gate = self.gate.lock().await;
        let page = self.api.changes(id, 0).await.map_err(|e| e.to_string())?;
        let first = page
            .changes
            .first()
            .filter(|e| e.group_id == id)
            .ok_or("没有群创建记录")?;
        self.store()?.pin(first, owner)?;
        self.store()?.apply(id, &page.changes)?;
        self.sync_inner(id).await
    }
    pub fn group_ids(&self) -> Result<Vec<String>, String> {
        self.store()?.group_ids()
    }
    pub fn history(
        &self,
        id: &str,
        before: Option<i64>,
        keys: &crypto::KeyPair,
    ) -> Result<GroupHistoryPage, String> {
        self.store()?.history(id, before, keys)
    }
    pub fn state(&self, id: &str) -> Result<GroupState, String> {
        self.store()?.state(id)
    }
    pub fn messages(
        &self,
        id: &str,
        keys: &crypto::KeyPair,
    ) -> Result<Vec<GroupLocalMessage>, String> {
        self.store()?.messages(id, keys)
    }
    pub async fn remote_groups(&self, after: Option<&str>) -> Result<GroupListPage, String> {
        self.api.list(after).await.map_err(|e| e.to_string())
    }
    pub async fn invitations(&self, after: Option<&str>) -> Result<GroupInvitePage, String> {
        self.api.invites(after).await.map_err(|e| e.to_string())
    }
    pub async fn decline(&self, id: &str) -> Result<(), String> {
        self.api.cancel_invite(id).await.map_err(|e| e.to_string())
    }
    fn change(
        &self,
        state: Option<&GroupState>,
        action: GroupAction,
        keys: &crypto::KeyPair,
    ) -> Result<GroupChange, String> {
        check_keys(&self.identity, keys)?;
        let mut change = GroupChange {
            group_id: state
                .map(|state| state.group_id().to_string())
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            epoch: state.map(|state| state.epoch() + 1).unwrap_or(1),
            previous_hash: state
                .map(|state| state.revision_hash().to_vec())
                .unwrap_or_default(),
            actor: self.identity.user_id.clone(),
            created_at: now(),
            action,
            signature: Vec::new(),
        };
        change.signature = crypto::sign(&change.signing_bytes(), &keys.ed25519_sk)
            .map_err(|_| "无法签名群变更")?;
        validate_submission(state, &change, now()).map_err(|_| "无效群变更或没有操作权限")?;
        Ok(change)
    }
    pub async fn create(&self, name: String, keys: &crypto::KeyPair) -> Result<String, String> {
        let _gate = self.gate.lock().await;
        let change = self.change(
            None,
            GroupAction::Create {
                name,
                owner: self.identity.clone(),
            },
            keys,
        )?;
        let accepted = self
            .api
            .change(&change, true)
            .await
            .map_err(|e| e.to_string())?;
        if accepted != change {
            return Err("服务端返回了不同的群创建事件".into());
        }
        self.store()?.pin(&change, &self.identity)?;
        Ok(change.group_id)
    }
    /// Recover only one's own creation from an authoritative signed prefix.
    pub async fn recover_own(&self, id: &str) -> Result<GroupState, String> {
        let _gate = self.gate.lock().await;
        let page = self.api.changes(id, 0).await.map_err(|e| e.to_string())?;
        let creation = page.changes.first().ok_or("没有群创建记录")?;
        if creation.group_id != id {
            return Err("群创建编号不一致".into());
        }
        self.store()?.pin(creation, &self.identity)?;
        self.store()?.apply(id, &page.changes)?;
        self.sync_inner(id).await
    }
    /// `owner` must come from a separately verified contact/identity, not the
    /// self-signed creation embedded in this server response.
    pub async fn adopt_invitation(
        &self,
        invite: &GroupInvite,
        owner: &GroupIdentity,
    ) -> Result<GroupState, String> {
        let _gate = self.gate.lock().await;
        if invite.member != self.identity {
            return Err("邀请不是发给本机身份".into());
        }
        let page = self
            .api
            .changes(&invite.group_id, 0)
            .await
            .map_err(|e| e.to_string())?;
        let creation = page.changes.first().ok_or("邀请缺少群创建记录")?;
        if creation.group_id != invite.group_id {
            return Err("邀请与群创建编号不一致".into());
        }
        self.store()?.pin(creation, owner)?;
        self.store()?.apply(&invite.group_id, &page.changes)?;
        let state = self.sync_inner(&invite.group_id).await?;
        validate_invite(&state, invite, now()).map_err(|_| "邀请已失效或无法验证")?;
        Ok(state)
    }
    pub async fn sync(&self, id: &str) -> Result<GroupState, String> {
        let _gate = self.gate.lock().await;
        self.sync_inner(id).await
    }
    async fn sync_inner(&self, id: &str) -> Result<GroupState, String> {
        for _ in 0..12 {
            let current = self.store()?.state(id)?;
            let page = self
                .api
                .changes(id, current.epoch())
                .await
                .map_err(|e| e.to_string())?;
            if page.changes.len() > 100
                || page.through_epoch > 1001
                || page.through_epoch < current.epoch()
            {
                return Err("服务端群成员记录范围无效或回退".into());
            }
            let last = page
                .changes
                .last()
                .map(|event| event.epoch)
                .unwrap_or(current.epoch());
            if last > page.through_epoch
                || page.has_more != (last < page.through_epoch)
                || (page.has_more && page.changes.is_empty())
            {
                return Err("服务端群成员分页无法验证".into());
            }
            let next = self.store()?.apply(id, &page.changes)?;
            if !page.has_more {
                return Ok(next);
            }
        }
        Err("群成员同步超出试验版本上限".into())
    }
    pub async fn invite(
        &self,
        id: &str,
        member: GroupIdentity,
        keys: &crypto::KeyPair,
    ) -> Result<GroupInvite, String> {
        let _gate = self.gate.lock().await;
        check_keys(&self.identity, keys)?;
        let state = self.sync_inner(id).await?;
        if state.owner() != self.identity.user_id
            || state
                .member(&self.identity.user_id)
                .is_none_or(|m| m.identity != self.identity)
        {
            return Err("只有当前群主可以邀请".into());
        }
        let mut invite = GroupInvite {
            id: uuid::Uuid::new_v4().to_string(),
            group_id: id.into(),
            epoch: state.epoch(),
            previous_hash: state.revision_hash().to_vec(),
            member,
            issued_at: now(),
            expires_at: now() + 24 * 60 * 60 * 1000,
            signature: Vec::new(),
        };
        invite.signature =
            crypto::sign(&invite.signing_bytes(), &keys.ed25519_sk).map_err(|_| "无法签名邀请")?;
        validate_invite(&state, &invite, now()).map_err(|_| "邀请目标或群版本无效")?;
        let accepted = self.api.invite(&invite).await.map_err(|e| e.to_string())?;
        if accepted.invite != invite || accepted.status != "pending" {
            return Err("服务端返回了不同的邀请状态".into());
        }
        Ok(invite)
    }
    pub async fn accept(
        &self,
        invite: GroupInvite,
        keys: &crypto::KeyPair,
    ) -> Result<GroupState, String> {
        let _gate = self.gate.lock().await;
        check_keys(&self.identity, keys)?;
        if invite.member != self.identity {
            return Err("邀请不是发给本机身份".into());
        }
        let state = self.sync_inner(&invite.group_id).await?;
        validate_invite(&state, &invite, now()).map_err(|_| "邀请已失效或无法验证")?;
        let mut acceptance = GroupAcceptance {
            invite_id: invite.id.clone(),
            invite_hash: invite.digest(),
            signature: Vec::new(),
        };
        acceptance.signature = crypto::sign(&acceptance.signing_bytes(), &keys.ed25519_sk)
            .map_err(|_| "无法签名接受邀请")?;
        self.submit_inner(&state, GroupAction::Join { invite, acceptance }, keys)
            .await
    }
    pub async fn change_membership(
        &self,
        id: &str,
        action: GroupAction,
        keys: &crypto::KeyPair,
    ) -> Result<GroupState, String> {
        let _gate = self.gate.lock().await;
        if matches!(
            &action,
            GroupAction::Create { .. } | GroupAction::Join { .. }
        ) {
            return Err("创建和加入须使用专用流程".into());
        }
        let state = self.sync_inner(id).await?;
        self.submit_inner(&state, action, keys).await
    }
    async fn submit_inner(
        &self,
        state: &GroupState,
        action: GroupAction,
        keys: &crypto::KeyPair,
    ) -> Result<GroupState, String> {
        let change = self.change(Some(state), action, keys)?;
        let accepted = self
            .api
            .change(&change, false)
            .await
            .map_err(|e| e.to_string())?;
        if accepted != change {
            return Err("服务端返回了不同的群变更事件".into());
        }
        self.store()?.apply(state.group_id(), &[change])
    }
    pub async fn queue_text(
        &self,
        id: &str,
        text: &str,
        keys: &crypto::KeyPair,
    ) -> Result<String, String> {
        let _gate = self.gate.lock().await;
        self.sync_inner(id).await?;
        self.store()?.seal_text(id, text, keys)
    }
    pub async fn send_queued(&self, id: &str) -> Result<Option<GroupMessageReceipt>, String> {
        let _gate = self.gate.lock().await;
        let batch = self.store()?.queued(id)?;
        let Some(batch) = batch else { return Ok(None) };
        let receipt = self.api.send(id, &batch).await.map_err(|e| e.to_string())?;
        self.store()?.accepted(id, &receipt)?;
        Ok(Some(receipt))
    }
    /// The server serializes cancellation with admission, without submitting
    /// an unsent message merely because the user asked to cancel it.
    pub async fn cancel_unsent(&self, id: &str) -> Result<(), String> {
        let _gate = self.gate.lock().await;
        let Some(batch) = self.store()?.queued(id)? else {
            return Ok(());
        };
        let result = self
            .api
            .cancel_message(id, &batch[0].message_id)
            .await
            .map_err(|e| e.to_string())?;
        if result.group_id != id || result.message_id != batch[0].message_id {
            return Err("取消响应与原任务不一致".into());
        }
        match (result.cancelled, result.receipt) {
            (true, None) => self.store()?.cancel_unaccepted(id, &batch[0].message_id),
            (false, Some(receipt)) => {
                self.store()?.accepted(id, &receipt)?;
                Err("原消息已被服务端接受，不能取消".into())
            }
            _ => Err("原消息接收状态尚不能确认，请保留任务".into()),
        }
    }
    pub async fn poll(&self, id: &str, keys: &crypto::KeyPair) -> Result<usize, String> {
        let _gate = self.gate.lock().await;
        let state = self.sync_inner(id).await?;
        let joined = state
            .member(&self.identity.user_id)
            .filter(|m| m.identity == self.identity && !state.closed())
            .ok_or("本机已不在此群")?
            .joined_epoch;
        let page = self.api.pending(id).await.map_err(|e| e.to_string())?;
        if page.envelopes.len() > 100 {
            return Err("群待收窗口超出限制".into());
        }
        let mut fresh = 0;
        for envelope in page.envelopes {
            if envelope.group_id != id {
                return Err("群待收路由不一致".into());
            }
            if self.store()?.receive(&envelope, keys)? {
                fresh += 1;
            }
        }
        let ack = self.store()?.acknowledgements(id, joined)?;
        if !ack.is_empty() {
            self.api
                .ack(id, joined, &ack)
                .await
                .map_err(|e| e.to_string())?;
            self.store()?.acknowledged(id, joined, &ack)?;
        }
        Ok(fresh)
    }
}
