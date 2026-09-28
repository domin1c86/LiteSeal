use crate::AppState;
use liteseal_core::{
    groups::{GroupClient, GroupHistoryPage, GroupNotification},
    keystore::KeystoreData,
};
use liteseal_shared::{crypto, group::*};
use serde::Serialize;
use std::{collections::BTreeMap, sync::Arc};

struct Cached {
    key: String,
    client: Arc<GroupClient>,
}
#[derive(Default)]
pub(crate) struct Runtime {
    cache: Option<Cached>,
    remote: BTreeMap<String, GroupListEntry>,
    invitations: Vec<GroupInvite>,
    cursor: Option<String>,
    errors: Vec<String>,
    round: usize,
    last_refresh: Option<std::time::Instant>,
    revision: usize,
}
struct Context {
    saved: KeystoreData,
    client: Arc<GroupClient>,
    keys: crypto::KeyPair,
    identity: GroupIdentity,
}
#[derive(Serialize)]
pub struct MemberView {
    user_id: String,
    device_id: String,
    name: String,
    fingerprint: String,
    joined_epoch: u64,
}
#[derive(Serialize)]
pub struct View {
    id: String,
    name: String,
    owner: String,
    epoch: u64,
    closed: bool,
    active: bool,
    trusted: bool,
    members: Vec<MemberView>,
    unread: i64,
    pending: bool,
    muted: bool,
}
#[derive(Serialize)]
pub struct InvitationView {
    id: String,
    group_id: String,
    expires_at: i64,
}
#[derive(Serialize)]
pub struct Snapshot {
    groups: Vec<View>,
    invitations: Vec<InvitationView>,
    errors: Vec<String>,
    next_cursor: Option<String>,
}
#[derive(Serialize)]
pub struct Inspection {
    group_id: String,
    name: String,
    owner_id: String,
    owner_name: String,
    owner_device: String,
    fingerprint: String,
    eligible: bool,
    reason: String,
}
#[derive(Serialize)]
pub struct SendView {
    message_id: String,
    state: String,
    error: Option<String>,
}
#[derive(Default, Serialize)]
pub struct Report {
    pub changed: usize,
    pub errors: Vec<String>,
    pub notifications: Vec<GroupNotification>,
    pub notification_identity: Option<NotificationIdentity>,
}
#[derive(Serialize)]
pub struct NotificationIdentity {
    user_id: String,
    device_id: String,
    server_url: String,
}
pub async fn set_muted(state: &AppState, id: String, muted: bool) -> Result<(), String> {
    let ctx = local_context(state).await?;
    ctx.client.set_muted(&id, muted)?;
    current(state, &ctx.saved)
}
fn fingerprint(identity: &GroupIdentity) -> String {
    format!(
        "{} / {}",
        liteseal_core::contacts::fingerprint(&identity.public_key),
        liteseal_core::contacts::fingerprint(&identity.signing_key)
    )
}
fn current(state: &AppState, saved: &KeystoreData) -> Result<(), String> {
    let now = state.identity()?;
    if now.user_id != saved.user_id
        || now.device_id != saved.device_id
        || now.server_url != saved.server_url
        || now.token != saved.token
        || now.public_key != saved.public_key
        || now.ed25519_pk != saved.ed25519_pk
    {
        return Err("会话已变化，请刷新群聊".into());
    }
    Ok(())
}
async fn context(state: &AppState) -> Result<Context, String> {
    context_mode(state, true).await
}
async fn local_context(state: &AppState) -> Result<Context, String> {
    context_mode(state, false).await
}
async fn context_mode(state: &AppState, network: bool) -> Result<Context, String> {
    let saved = state.identity()?;
    if saved.token.is_empty() || saved.user_id.is_empty() || saved.device_id.is_empty() {
        return Err("请先登录群聊账号".into());
    }
    let identity = GroupIdentity {
        user_id: saved.user_id.clone(),
        device_id: saved.device_id.clone(),
        public_key: saved.public_key.clone(),
        signing_key: saved.ed25519_pk.clone(),
    };
    let key = serde_json::to_string(&(
        liteseal_core::groups::api::canonical_origin(&saved.server_url)?,
        &identity,
    ))
    .map_err(|_| "无效群身份")?;
    let client = {
        let mut runtime = state
            .groups_runtime
            .lock()
            .map_err(|_| "群运行状态不可用")?;
        if runtime.cache.as_ref().is_none_or(|cache| cache.key != key) {
            let client = Arc::new(GroupClient::new(
                state.db_path.to_str().ok_or("群存储路径无效")?,
                &saved.server_url,
                saved.token.clone(),
                identity.clone(),
            )?);
            *runtime = Runtime {
                cache: Some(Cached { key, client }),
                ..Default::default()
            };
        }
        runtime
            .cache
            .as_ref()
            .ok_or("群客户端不可用")?
            .client
            .clone()
    };
    current(state, &saved)?;
    if network {
        client.update_token(saved.token.clone()).await?;
    }
    if let Err(error) = current(state, &saved) {
        client.invalidate_token_if(&saved.token);
        return Err(error);
    }
    let keys = crypto::KeyPair {
        public_key: saved
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| "加密公钥无效")?,
        secret_key: saved
            .secret_key
            .as_slice()
            .try_into()
            .map_err(|_| "加密身份无效")?,
        ed25519_pk: saved
            .ed25519_pk
            .as_slice()
            .try_into()
            .map_err(|_| "签名公钥无效")?,
        ed25519_sk: saved
            .ed25519_sk
            .as_slice()
            .try_into()
            .map_err(|_| "签名身份无效")?,
    };
    Ok(Context {
        saved,
        client,
        keys,
        identity,
    })
}
pub(crate) fn invalidate(state: &AppState, saved: &KeystoreData) -> Result<(), String> {
    let Ok(origin) = liteseal_core::groups::api::canonical_origin(&saved.server_url) else {
        return Ok(());
    };
    let identity = GroupIdentity {
        user_id: saved.user_id.clone(),
        device_id: saved.device_id.clone(),
        public_key: saved.public_key.clone(),
        signing_key: saved.ed25519_pk.clone(),
    };
    let key = serde_json::to_string(&(origin, identity)).map_err(|_| "无效群身份")?;
    let runtime = state
        .groups_runtime
        .lock()
        .map_err(|_| "群运行状态不可用")?;
    if let Some(cache) = runtime.cache.as_ref().filter(|cache| cache.key == key) {
        cache.client.invalidate_token_if(&saved.token);
    }
    Ok(())
}
async fn refresh(state: &AppState, ctx: &Context, after: Option<&str>) -> Result<(), String> {
    let (groups, invites) = tokio::join!(
        ctx.client.remote_groups(after),
        ctx.client.invitations(None)
    );
    current(state, &ctx.saved)?;
    let mut runtime = state
        .groups_runtime
        .lock()
        .map_err(|_| "群运行状态不可用")?;
    runtime.errors.clear();
    let old_invitations: Vec<_> = runtime
        .invitations
        .iter()
        .map(|i| (i.id.clone(), i.digest()))
        .collect();
    match groups {
        Ok(page) if page.groups.len() <= 100 => {
            for group in page.groups {
                runtime.remote.insert(group.group_id.clone(), group);
            }
            runtime.cursor = page.next_cursor;
        }
        Ok(_) => runtime.errors.push("群列表超出分页限制".into()),
        Err(error) => runtime.errors.push(error),
    }
    match invites {
        Ok(page)
            if page.invites.len() <= 100
                && page
                    .invites
                    .iter()
                    .all(|invite| invite.member == ctx.identity) =>
        {
            runtime.invitations = page.invites
        }
        Ok(_) => runtime.errors.push("邀请列表身份或大小无效".into()),
        Err(error) => runtime.errors.push(error),
    }
    runtime.last_refresh = Some(std::time::Instant::now());
    if old_invitations
        != runtime
            .invitations
            .iter()
            .map(|i| (i.id.clone(), i.digest()))
            .collect::<Vec<_>>()
    {
        runtime.revision += 1;
    }
    Ok(())
}
fn view(state: &AppState, ctx: &Context, id: &str) -> Result<View, String> {
    let group = ctx.client.state(id)?;
    let contacts = state.client.get_contacts()?;
    let members = group
        .members()
        .iter()
        .map(|member| MemberView {
            user_id: member.identity.user_id.clone(),
            device_id: member.identity.device_id.clone(),
            name: if member.identity == ctx.identity {
                "我".into()
            } else {
                contacts
                    .iter()
                    .find(|c| c.user_id == member.identity.user_id)
                    .map(|c| c.username.clone())
                    .unwrap_or_else(|| member.identity.user_id.clone())
            },
            fingerprint: fingerprint(&member.identity),
            joined_epoch: member.joined_epoch,
        })
        .collect();
    Ok(View {
        id: id.into(),
        name: group.name().into(),
        owner: group.owner().into(),
        epoch: group.epoch(),
        closed: group.closed(),
        active: !group.closed()
            && group
                .member(&ctx.identity.user_id)
                .is_some_and(|m| m.identity == ctx.identity),
        trusted: true,
        members,
        unread: ctx.client.unread(id)?,
        pending: ctx.client.pending(id)?,
        muted: ctx.client.muted(id)?,
    })
}
pub async fn list(
    state: &AppState,
    network: bool,
    after: Option<String>,
) -> Result<Snapshot, String> {
    let _gate = if network {
        Some(state.groups_gate.lock().await)
    } else {
        None
    };
    let ctx = if network {
        context(state).await?
    } else {
        local_context(state).await?
    };
    if network {
        refresh(state, &ctx, after.as_deref()).await?;
    }
    let mut groups = BTreeMap::new();
    let mut errors = Vec::new();
    for id in ctx.client.group_ids()? {
        match view(state, &ctx, &id) {
            Ok(group) => {
                groups.insert(id, group);
            }
            Err(error) => errors.push(error),
        }
    }
    let runtime = state
        .groups_runtime
        .lock()
        .map_err(|_| "群运行状态不可用")?;
    for remote in runtime.remote.values() {
        groups
            .entry(remote.group_id.clone())
            .or_insert_with(|| View {
                id: remote.group_id.clone(),
                name: "需要核实群身份".into(),
                owner: String::new(),
                epoch: remote.visible_epoch,
                closed: false,
                active: false,
                trusted: false,
                members: vec![],
                unread: 0,
                pending: false,
                muted: false,
            });
    }
    errors.extend(runtime.errors.clone());
    current(state, &ctx.saved)?;
    Ok(Snapshot {
        groups: groups.into_values().collect(),
        invitations: runtime
            .invitations
            .iter()
            .map(|invite| InvitationView {
                id: invite.id.clone(),
                group_id: invite.group_id.clone(),
                expires_at: invite.expires_at,
            })
            .collect(),
        errors,
        next_cursor: runtime.cursor.clone(),
    })
}
async fn registered(
    state: &AppState,
    ctx: &Context,
    peer: &str,
    confirmed: &str,
    allow_revoked: bool,
) -> Result<GroupIdentity, String> {
    if peer == ctx.identity.user_id {
        if confirmed != fingerprint(&ctx.identity) {
            return Err("请重新核对本机指纹".into());
        }
        return Ok(ctx.identity.clone());
    }
    let contact = state
        .client
        .get_contacts()?
        .into_iter()
        .find(|c| c.user_id == peer)
        .ok_or("请先添加并核实群主或目标联系人")?;
    if contact.trust_state != "verified"
        || contact.key_changed
        || contact
            .ed25519_pk
            .as_ref()
            .is_none_or(|key| key.len() != 32)
    {
        return Err("请先通过可信渠道核实联系人，两组公钥均须保留且未变化".into());
    }
    let devices = liteseal_core::api::get_user_devices(
        ctx.saved.server_url.clone(),
        peer.into(),
        ctx.saved.token.clone(),
    )
    .await?;
    let mut matching = devices.into_iter().filter(|device| {
        (allow_revoked || !device.revoked)
            && device.public_key == contact.public_key
            && Some(&device.ed25519_pk) == contact.ed25519_pk.as_ref()
    });
    let device = matching
        .next()
        .ok_or("已核实公钥与当前设备不一致，请重新核实身份")?;
    if matching.next().is_some() {
        return Err("目标身份存在多个设备，请先确认设备归属".into());
    }
    let identity = GroupIdentity {
        user_id: peer.into(),
        device_id: device.id,
        public_key: device.public_key,
        signing_key: device.ed25519_pk,
    };
    if fingerprint(&identity) != confirmed {
        return Err("指纹已变化，请重新查看并确认".into());
    }
    Ok(identity)
}
fn find_invite(state: &AppState, id: &str) -> Result<GroupInvite, String> {
    state
        .groups_runtime
        .lock()
        .map_err(|_| "邀请状态不可用")?
        .invitations
        .iter()
        .find(|invite| invite.id == id)
        .cloned()
        .ok_or_else(|| "邀请已变化，请刷新列表".into())
}
pub async fn inspect(
    state: &AppState,
    group_id: String,
    invite_id: Option<String>,
) -> Result<Inspection, String> {
    let _gate = state.groups_gate.lock().await;
    let ctx = context(state).await?;
    let allow_revoked = invite_id.is_none();
    if let Some(id) = invite_id {
        refresh(state, &ctx, None).await?;
        if find_invite(state, &id)?.group_id != group_id {
            return Err("邀请群编号不一致".into());
        }
    }
    let (name, owner) = ctx.client.creator_hint(&group_id).await?;
    owner.validate().map_err(|_| "群创建身份无效")?;
    let fingerprint = fingerprint(&owner);
    let contact = state
        .client
        .get_contacts()?
        .into_iter()
        .find(|c| c.user_id == owner.user_id);
    let verified = registered(state, &ctx, &owner.user_id, &fingerprint, allow_revoked).await;
    let (eligible, reason) = match verified {
        Ok(expected) if expected == owner => (true, String::new()),
        Ok(_) => (false, "群主设备与已核实身份不一致".into()),
        Err(error) => (false, error),
    };
    current(state, &ctx.saved)?;
    Ok(Inspection {
        group_id,
        name,
        owner_id: owner.user_id.clone(),
        owner_name: if owner.user_id == ctx.identity.user_id {
            "我".into()
        } else {
            contact
                .map(|c| c.username)
                .unwrap_or_else(|| "未核实的群主".into())
        },
        owner_device: owner.device_id,
        fingerprint,
        eligible,
        reason,
    })
}
pub async fn create(state: &AppState, name: String) -> Result<String, String> {
    let _gate = state.groups_gate.lock().await;
    let ctx = context(state).await?;
    let id = ctx.client.create(name, &ctx.keys).await?;
    current(state, &ctx.saved)?;
    Ok(id)
}
pub async fn peer(state: &AppState, peer: String) -> Result<MemberView, String> {
    let _gate = state.groups_gate.lock().await;
    let ctx = context(state).await?;
    let contact = state
        .client
        .get_contacts()?
        .into_iter()
        .find(|c| c.user_id == peer)
        .ok_or("请先添加联系人")?;
    let signing = contact
        .ed25519_pk
        .clone()
        .ok_or("联系人缺少签名公钥，请重新核实")?;
    let candidate = GroupIdentity {
        user_id: peer.clone(),
        device_id: String::new(),
        public_key: contact.public_key,
        signing_key: signing,
    };
    let expected = fingerprint(&candidate);
    let member = registered(state, &ctx, &peer, &expected, false).await?;
    current(state, &ctx.saved)?;
    Ok(MemberView {
        user_id: member.user_id.clone(),
        device_id: member.device_id.clone(),
        name: contact.username,
        fingerprint: expected,
        joined_epoch: 0,
    })
}
pub async fn invite(
    state: &AppState,
    id: String,
    peer: String,
    confirmed: String,
) -> Result<(), String> {
    let _gate = state.groups_gate.lock().await;
    let ctx = context(state).await?;
    let member = registered(state, &ctx, &peer, &confirmed, false).await?;
    ctx.client.invite(&id, member, &ctx.keys).await?;
    current(state, &ctx.saved)
}
pub async fn accept(state: &AppState, id: String, confirmed: String) -> Result<String, String> {
    let _gate = state.groups_gate.lock().await;
    let ctx = context(state).await?;
    refresh(state, &ctx, None).await?;
    let invite = find_invite(state, &id)?;
    let (_, hint) = ctx.client.creator_hint(&invite.group_id).await?;
    let owner = registered(state, &ctx, &hint.user_id, &confirmed, false).await?;
    if owner != hint {
        return Err("群创建身份与已核实群主不一致".into());
    }
    ctx.client.adopt_invitation(&invite, &owner).await?;
    let group = ctx.client.accept(invite, &ctx.keys).await?;
    refresh(state, &ctx, None).await?;
    current(state, &ctx.saved)?;
    Ok(group.group_id().into())
}
pub async fn recover(state: &AppState, id: String, confirmed: String) -> Result<(), String> {
    let _gate = state.groups_gate.lock().await;
    let ctx = context(state).await?;
    let (_, hint) = ctx.client.creator_hint(&id).await?;
    let owner = registered(state, &ctx, &hint.user_id, &confirmed, true).await?;
    ctx.client.recover_trusted(&id, &owner).await?;
    current(state, &ctx.saved)
}
#[derive(Serialize)]
pub struct SentInvitationView {
    id: String,
    group_id: String,
    user_id: String,
    device_id: String,
    expires_at: i64,
    status: String,
}
#[derive(Serialize)]
pub struct SentInvitationPage {
    invites: Vec<SentInvitationView>,
    next_cursor: Option<String>,
}
pub async fn sent_invites(
    state: &AppState,
    id: String,
    after: Option<String>,
) -> Result<SentInvitationPage, String> {
    let _gate = state.groups_gate.lock().await;
    let ctx = context(state).await?;
    let page = ctx.client.sent_invitations(&id, after.as_deref()).await?;
    current(state, &ctx.saved)?;
    Ok(SentInvitationPage {
        next_cursor: page.next_cursor,
        invites: page
            .invites
            .into_iter()
            .map(|entry| SentInvitationView {
                id: entry.invite.id,
                group_id: entry.invite.group_id,
                user_id: entry.invite.member.user_id,
                device_id: entry.invite.member.device_id,
                expires_at: entry.invite.expires_at,
                status: entry.status,
            })
            .collect(),
    })
}
pub async fn revoke_invite(state: &AppState, id: String) -> Result<(), String> {
    let _gate = state.groups_gate.lock().await;
    let ctx = context(state).await?;
    ctx.client.decline(&id).await?;
    current(state, &ctx.saved)
}
pub async fn decline(state: &AppState, id: String) -> Result<(), String> {
    let _gate = state.groups_gate.lock().await;
    let ctx = context(state).await?;
    ctx.client.decline(&id).await?;
    refresh(state, &ctx, None).await?;
    current(state, &ctx.saved)
}
pub async fn membership(
    state: &AppState,
    id: String,
    action: String,
    value: Option<String>,
) -> Result<(), String> {
    let _gate = state.groups_gate.lock().await;
    let ctx = context(state).await?;
    let action = match action.as_str() {
        "rename" => GroupAction::Rename {
            name: value.ok_or("请输入群名")?,
        },
        "remove" => GroupAction::Remove {
            user_id: value.ok_or("请选择成员")?,
        },
        "leave" => GroupAction::Leave,
        "close" => GroupAction::Close,
        _ => return Err("不支持此群操作".into()),
    };
    ctx.client.change_membership(&id, action, &ctx.keys).await?;
    current(state, &ctx.saved)
}
pub async fn history(
    state: &AppState,
    id: String,
    before: Option<i64>,
) -> Result<GroupHistoryPage, String> {
    let ctx = local_context(state).await?;
    let page = ctx.client.history(&id, before, &ctx.keys)?;
    current(state, &ctx.saved)?;
    Ok(page)
}
pub async fn sync(state: &AppState, id: String) -> Result<usize, String> {
    let _gate = state.groups_gate.lock().await;
    let ctx = context(state).await?;
    let group = ctx.client.sync(&id).await?;
    let received = if !group.closed()
        && group
            .member(&ctx.identity.user_id)
            .is_some_and(|m| m.identity == ctx.identity)
    {
        ctx.client.poll(&id, &ctx.keys).await?
    } else {
        0
    };
    current(state, &ctx.saved)?;
    Ok(received)
}
pub async fn draft(state: &AppState, id: String, text: Option<String>) -> Result<String, String> {
    let ctx = local_context(state).await?;
    if let Some(text) = text {
        ctx.client.save_draft(&id, &text, &ctx.keys)?;
    }
    let draft = ctx.client.draft(&id, &ctx.keys)?;
    current(state, &ctx.saved)?;
    Ok(draft)
}
pub async fn seen(state: &AppState, id: String, ids: Vec<String>) -> Result<(), String> {
    let ctx = local_context(state).await?;
    ctx.client.mark_seen(&id, &ids)?;
    current(state, &ctx.saved)
}
pub async fn send(state: &AppState, id: String, text: Option<String>) -> Result<SendView, String> {
    let _gate = state.groups_gate.lock().await;
    let ctx = context(state).await?;
    let message = if let Some(text) = text {
        let message = ctx.client.queue_text(&id, &text, &ctx.keys).await?;
        Some(message)
    } else {
        None
    };
    let result = ctx.client.send_queued(&id).await;
    current(state, &ctx.saved)?;
    match result {
        Ok(Some(receipt)) => Ok(SendView {
            message_id: receipt.message_id,
            state: "accepted".into(),
            error: None,
        }),
        Ok(None) => Ok(SendView {
            message_id: message.unwrap_or_default(),
            state: "accepted".into(),
            error: None,
        }),
        Err(error) => Ok(SendView {
            message_id: message.unwrap_or_default(),
            state: "queued".into(),
            error: Some(error),
        }),
    }
}
pub async fn cancel(state: &AppState, id: String) -> Result<(), String> {
    let _gate = state.groups_gate.lock().await;
    let ctx = context(state).await?;
    ctx.client.cancel_unsent(&id).await?;
    current(state, &ctx.saved)
}
pub async fn process(state: &AppState) -> Result<Report, String> {
    let _gate = state.groups_gate.lock().await;
    let ctx = match context(state).await {
        Ok(ctx) => ctx,
        Err(_) => return Ok(Report::default()),
    };
    let old_errors = state
        .groups_runtime
        .lock()
        .map_err(|_| "群运行状态不可用")?
        .errors
        .clone();
    let old_revision = state
        .groups_runtime
        .lock()
        .map_err(|_| "群运行状态不可用")?
        .revision;
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(25),
        process_inner(state, &ctx),
    )
    .await;
    let mut report = match result {
        Ok(result) => result?,
        Err(_) => Report {
            changed: 1,
            errors: vec!["群后台检查超时，未完成任务已保留".into()],
            ..Report::default()
        },
    };
    current(state, &ctx.saved)?;
    report.notifications = ctx.client.take_notifications()?;
    report.notification_identity = Some(NotificationIdentity {
        user_id: ctx.saved.user_id.clone(),
        device_id: ctx.saved.device_id.clone(),
        server_url: ctx.saved.server_url.clone(),
    });
    let mut runtime = state
        .groups_runtime
        .lock()
        .map_err(|_| "群运行状态不可用")?;
    report.changed += runtime.revision.saturating_sub(old_revision);
    if report.errors != old_errors {
        report.changed += 1;
    }
    runtime.errors = report.errors.clone();
    Ok(report)
}
async fn process_inner(state: &AppState, ctx: &Context) -> Result<Report, String> {
    let needs_refresh = state
        .groups_runtime
        .lock()
        .map_err(|_| "群运行状态不可用")?
        .last_refresh
        .is_none_or(|last| last.elapsed().as_secs() >= 30);
    if needs_refresh {
        refresh(state, ctx, None).await?;
    }
    let mut report = Report {
        notifications: Vec::new(),
        notification_identity: None,
        changed: 0,
        errors: state
            .groups_runtime
            .lock()
            .map_err(|_| "群运行状态不可用")?
            .errors
            .clone(),
    };
    let ids = ctx.client.group_ids()?;
    if ids.is_empty() {
        return Ok(report);
    }
    let start = {
        let mut runtime = state
            .groups_runtime
            .lock()
            .map_err(|_| "群运行状态不可用")?;
        let start = runtime.round % ids.len();
        runtime.round = (start + 3) % ids.len();
        start
    };
    for step in 0..ids.len().min(3) {
        let id = &ids[(start + step) % ids.len()];
        let before = ctx.client.state(id)?;
        if ctx.client.pending(id)? {
            match ctx.client.send_queued(id).await {
                Ok(Some(_)) => report.changed += 1,
                Ok(None) => {}
                Err(error) => report.errors.push(error),
            }
        }
        if !before.closed() && before.member(&ctx.identity.user_id).is_some() {
            match ctx.client.poll(id, &ctx.keys).await {
                Ok(count) => report.changed += count,
                Err(error) => {
                    let latest = ctx.client.state(id)?;
                    if !latest.closed() && latest.member(&ctx.identity.user_id).is_some() {
                        report.errors.push(error);
                    }
                }
            }
            if ctx.client.state(id)?.revision_hash() != before.revision_hash() {
                report.changed += 1;
            }
        }
    }
    Ok(report)
}
