//! Selected v3 text chat. Only public metadata and authenticated text leave Rust.
use super::normal_profile as normal;
use crate::AppState;
use liteseal_core::trusted_devices::{
    api::DeviceControlApi,
    messages::{
        coordinator::{
            Condition, MediaProgress, MessageCoordinator, OperationPoll, OperationPreparation,
            OperationProgress, Poll, Preparation, Progress,
        },
        Owner, RecordView, TaskView,
    },
    profiles::active,
    tasks::anchor_fingerprint,
};
use liteseal_shared::{
    crypto::KeyPair,
    direct_message::Kind,
    trusted_device::{Anchor, DeviceIdentity},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc, time::Duration};
#[path = "direct_history_transfer.rs"]
pub mod history_transfer;
#[path = "direct_media.rs"]
pub mod media;
#[path = "direct_operations.rs"]
pub mod operations;
#[path = "direct_audio.rs"]
pub mod audio;
#[derive(Default)]
pub(crate) struct Runtime {
    cache: Option<Cached>,
    suspended: bool,
}
struct Cached {
    key: String,
    token_hash: [u8; 32],
    actor: Arc<MessageCoordinator>,
    candidates: HashMap<String, Anchor>,
}
struct Context {
    selected: normal::Context,
    key: String,
    keys: KeyPair,
    actor: Arc<MessageCoordinator>,
}
#[derive(Serialize)]
pub struct Peer {
    pub account: String,
    pub origin: String,
    pub root_device: String,
    pub root_fingerprint: String,
    pub encryption_fingerprint: String,
    pub signing_fingerprint: String,
}
fn peer(anchor: &Anchor) -> Peer {
    Peer {
        account: anchor.account.clone(),
        origin: anchor.origin.clone(),
        root_device: anchor.root.device_id.clone(),
        root_fingerprint: anchor_fingerprint(anchor),
        encryption_fingerprint: hex::encode(Sha256::digest(anchor.root.encryption_key)),
        signing_fingerprint: hex::encode(Sha256::digest(anchor.root.signing_key)),
    }
}
#[derive(Serialize)]
pub struct Snapshot {
    pub notification_scope: String,
    pub identity: Peer,
    pub device: String,
    pub peers: Vec<Peer>,
    pub conversations: Vec<liteseal_core::trusted_devices::messages::conversations::View>,
    pub tasks: Vec<TaskView>,
    pub operations: Vec<liteseal_core::trusted_devices::messages::operations::OperationTaskView>,
    pub can_network: bool,
}
#[derive(Serialize)]
pub struct TextRecord {
    #[serde(flatten)]
    pub record: RecordView,
    pub text: Option<String>,
    pub media: Option<liteseal_core::trusted_devices::messages::media::Info>,
}
#[derive(Serialize)]
pub struct History {
    pub messages: Vec<TextRecord>,
    pub next_cursor: Option<i64>,
}
#[derive(Serialize, Default)]
pub struct Report {
    pub operation: Option<OperationProgress>,
    pub operation_poll: Option<OperationPoll>,
    pub media: Option<MediaProgress>,
    pub errors: Vec<String>,
    pub changed: bool,
    pub task: Option<Progress>,
    pub poll: Option<Poll>,
    pub notification_scope: Option<String>,
    pub notifications: Vec<liteseal_core::trusted_devices::messages::conversations::Notification>,
}
fn bad() -> String {
    "选中单聊范围已变化或不可用，请查询原任务，不会自动重建".into()
}
fn uuid(value: &str) -> Result<(), String> {
    if uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value) {
        Ok(())
    } else {
        Err("请输入规范账号编号".into())
    }
}
pub(crate) fn transition(
    state: &AppState,
    suspend: bool,
    resume: bool,
    work: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    let mut r = state.direct_runtime.lock().map_err(|_| bad())?;
    if let Some(c) = r.cache.take() {
        c.actor.invalidate().map_err(|e| e.to_string())?;
    }
    if suspend {
        r.suspended = true;
    }
    work()?;
    if resume {
        r.suspended = false;
    }
    Ok(())
}
fn own_anchor(state: &AppState, ctx: &normal::Context, keys: &KeyPair) -> Result<Anchor, String> {
    match &ctx.target {
        normal::Target::Root {} => Ok(Anchor {
            origin: ctx.identity.server_url.clone(),
            account: ctx.identity.user_id.clone(),
            root: DeviceIdentity::from_keys(ctx.identity.device_id.clone(), keys),
        }),
        normal::Target::Join { profile_id } => Ok(active::Store::open_with_protection(
            state.device_join_directory()?,
            profile_id,
            state.device_protection.clone(),
        )?
        .root_anchor()),
    }
}
fn context(state: &AppState) -> Result<Context, String> {
    let mut selected = normal::capture(state)?.ok_or("请先选择正常档案")?;
    if selected.protocol != "v3" {
        return Err("当前档案尚未启用单聊 v3".into());
    }
    if matches!(selected.target, normal::Target::Root {})
        && super::root_refresh::store(state, &state.saved_identity()?)?.is_none()
    {
        selected.identity.token.clear();
        selected.identity.refresh_token.clear();
    }
    let key = selected.cache_key()?;
    let keys = liteseal_core::backup::identity_keys(&selected.identity)?;
    let token_hash: [u8; 32] = Sha256::digest(selected.identity.token.as_bytes()).into();
    let mut runtime = state.direct_runtime.lock().map_err(|_| bad())?;
    if runtime.suspended {
        return Err(bad());
    }
    normal::current(state, &selected)?;
    if runtime.cache.as_ref().is_none_or(|c| c.key != key) {
        if let Some(c) = runtime.cache.take() {
            c.actor.invalidate().map_err(|e| e.to_string())?;
        }
        let actor = Arc::new(
            MessageCoordinator::open_with_protection(
                &selected.database,
                Owner::new(
                    &selected.identity.server_url,
                    &selected.identity.user_id,
                    &selected.identity.device_id,
                    &keys,
                )?,
                &keys,
                state.device_protection.clone(),
            )
            .map_err(|e| e.to_string())?,
        );
        let anchor = own_anchor(state, &selected, &keys)?;
        actor
            .confirm_root(&anchor, &anchor_fingerprint(&anchor), &keys)
            .map_err(|e| e.to_string())?;
        actor
            .renew_session(selected.identity.token.clone())
            .map_err(|e| e.to_string())?;
        runtime.cache = Some(Cached {
            key: key.clone(),
            token_hash,
            actor,
            candidates: HashMap::new(),
        });
    }
    let cached = runtime.cache.as_mut().ok_or_else(bad)?;
    if cached.token_hash != token_hash {
        cached
            .actor
            .renew_session(selected.identity.token.clone())
            .map_err(|e| e.to_string())?;
        cached.token_hash = token_hash;
        cached.candidates.clear();
    }
    let actor = cached.actor.clone();
    normal::current(state, &selected)?;
    Ok(Context {
        selected,
        key,
        keys,
        actor,
    })
}
fn current(state: &AppState, ctx: &Context) -> Result<(), String> {
    let r = state.direct_runtime.lock().map_err(|_| bad())?;
    if r.suspended || r.cache.as_ref().is_none_or(|c| c.key != ctx.key) {
        return Err(bad());
    }
    normal::current(state, &ctx.selected)
}
async fn bounded<T>(
    work: impl std::future::Future<
        Output = Result<T, liteseal_core::trusted_devices::messages::coordinator::CoordinatorError>,
    >,
) -> Result<T, String> {
    tokio::time::timeout(Duration::from_secs(50), work)
        .await
        .map_err(|_| "原任务结果尚未确认，请继续原编号".to_string())?
        .map_err(|e| e.to_string())
}
pub fn snapshot(state: &AppState) -> Result<Snapshot, String> {
    let ctx = context(state)?;
    let own = own_anchor(state, &ctx.selected, &ctx.keys)?;
    let peers = ctx
        .actor
        .roots(&ctx.keys)
        .map_err(|e| e.to_string())?
        .iter()
        .filter(|a| a.account != own.account)
        .map(peer)
        .collect();
    let result = Snapshot {
        notification_scope: ctx.key.clone(),
        identity: peer(&own),
        device: ctx.selected.identity.device_id.clone(),
        peers,
        conversations: ctx
            .actor
            .conversations(&ctx.keys)
            .map_err(|e| e.to_string())?,
        tasks: ctx.actor.tasks(&ctx.keys).map_err(|e| e.to_string())?,
        operations: ctx
            .actor
            .operation_tasks(&ctx.keys)
            .map_err(|e| e.to_string())?,
        can_network: !ctx.selected.identity.token.is_empty(),
    };
    current(state, &ctx)?;
    Ok(result)
}
pub fn history(state: &AppState, before: Option<i64>) -> Result<History, String> {
    history_peer(state, None, before)
}
pub fn history_peer(
    state: &AppState,
    account: Option<String>,
    before: Option<i64>,
) -> Result<History, String> {
    if let Some(account) = &account {
        uuid(account)?;
    }
    if before.is_some_and(|n| n <= 0) {
        return Err("历史游标无效".into());
    }
    let ctx = context(state)?;
    let rows = ctx
        .actor
        .history_peer(account.as_deref(), before, 6, &ctx.keys)
        .map_err(|e| e.to_string())?;
    let next_cursor = if rows.len() == 6 {
        rows.last().map(|r| r.cursor)
    } else {
        None
    };
    let messages = rows
        .into_iter()
        .map(|record| {
            let text = if record.kind == Kind::Text && record.outcome == "processed" {
                Some(
                    ctx.actor
                        .text(&record.id, &ctx.keys)
                        .map_err(|e| e.to_string())?,
                )
            } else {
                None
            };
            let media = if record.kind != Kind::Text && record.outcome == "processed" {
                Some(
                    ctx.actor
                        .media_info(&record.id, &ctx.keys)
                        .map_err(|e| e.to_string())?,
                )
            } else {
                None
            };
            Ok(TextRecord {
                record,
                text,
                media,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    current(state, &ctx)?;
    Ok(History {
        messages,
        next_cursor,
    })
}
pub fn mark_read(state: &AppState, account: String, through_id: String) -> Result<(), String> {
    uuid(&account)?;
    let ctx = context(state)?;
    ctx.actor
        .mark_read(&account, &through_id, &ctx.keys)
        .map_err(|e| e.to_string())?;
    current(state, &ctx)
}
pub fn set_muted(
    state: &AppState,
    account: String,
    revision: u64,
    muted: bool,
) -> Result<(), String> {
    uuid(&account)?;
    let ctx = context(state)?;
    ctx.actor
        .set_muted(&account, revision, muted, &ctx.keys)
        .map_err(|e| e.to_string())?;
    current(state, &ctx)
}
pub async fn inspect_peer(state: &AppState, account: String) -> Result<Peer, String> {
    uuid(&account)?;
    let ctx = context(state)?;
    if account == ctx.selected.identity.user_id {
        return Err("不能把本机账号作为对方".into());
    }
    let page = DeviceControlApi::new(&ctx.selected.identity.server_url)
        .map_err(|e| e.to_string())?
        .manifest(&ctx.selected.identity.token, &account, 0)
        .await
        .map_err(|e| e.to_string())?;
    let anchor = page.anchor;
    anchor.validate().map_err(|_| bad())?;
    if anchor.origin != ctx.selected.identity.server_url || anchor.account != account {
        return Err(bad());
    }
    current(state, &ctx)?;
    let mut runtime = state.direct_runtime.lock().map_err(|_| bad())?;
    normal::current(state, &ctx.selected)?;
    let cached = runtime
        .cache
        .as_mut()
        .filter(|c| c.key == ctx.key)
        .ok_or_else(bad)?;
    if cached.candidates.len() >= 128 && !cached.candidates.contains_key(&account) {
        return Err("待核对身份达到上限".into());
    }
    let result = peer(&anchor);
    cached.candidates.insert(account, anchor);
    Ok(result)
}
pub fn confirm_peer(state: &AppState, account: String, fingerprint: String) -> Result<(), String> {
    let ctx = context(state)?;
    let runtime = state.direct_runtime.lock().map_err(|_| bad())?;
    normal::current(state, &ctx.selected)?;
    let anchor = runtime
        .cache
        .as_ref()
        .filter(|c| c.key == ctx.key)
        .and_then(|c| c.candidates.get(&account))
        .ok_or("请先查询并核对这次候选身份")?;
    let roots = ctx.actor.roots(&ctx.keys).map_err(|e| e.to_string())?;
    if roots.len() >= 129 && !roots.iter().any(|root| root.account == account) {
        return Err("已核对对方账号达到本机上限".into());
    }
    ctx.actor
        .confirm_root(anchor, &fingerprint, &ctx.keys)
        .map_err(|e| e.to_string())?;
    Ok(())
}
pub async fn prepare(
    state: &AppState,
    account: String,
    text: String,
    draft_revision: Option<u64>,
) -> Result<Preparation, String> {
    uuid(&account)?;
    let ctx = context(state)?;
    if draft_revision.is_none()
        && ctx
            .actor
            .draft(&account, &ctx.keys)
            .ok()
            .is_some_and(|draft| draft.revision > 0)
    {
        return Err("请查询已保存草稿并携带原修订，不会另建替代任务".into());
    }
    let result = bounded(
        ctx.actor
            .prepare_text_draft(&account, &text, draft_revision, &ctx.keys),
    )
    .await?;
    current(state, &ctx)?;
    Ok(result)
}
pub fn draft(
    state: &AppState,
    account: String,
) -> Result<liteseal_core::trusted_devices::messages::drafts::View, String> {
    uuid(&account)?;
    let ctx = context(state)?;
    let result = ctx
        .actor
        .draft(&account, &ctx.keys)
        .map_err(|e| e.to_string())?;
    current(state, &ctx)?;
    Ok(result)
}
pub fn save_draft(
    state: &AppState,
    account: String,
    revision: u64,
    text: String,
) -> Result<liteseal_core::trusted_devices::messages::drafts::View, String> {
    uuid(&account)?;
    let ctx = context(state)?;
    let result = ctx
        .actor
        .save_draft(&account, revision, &text, &ctx.keys)
        .map_err(|e| e.to_string())?;
    current(state, &ctx)?;
    Ok(result)
}
pub async fn step(state: &AppState, id: String) -> Result<Progress, String> {
    let ctx = context(state)?;
    let result = bounded(ctx.actor.step(&id, &ctx.keys)).await?;
    current(state, &ctx)?;
    Ok(result)
}
pub fn cancel(state: &AppState, id: String) -> Result<TaskView, String> {
    let ctx = context(state)?;
    let result = ctx
        .actor
        .request_cancel(&id, &ctx.keys)
        .map_err(|e| e.to_string())?;
    current(state, &ctx)?;
    Ok(result)
}
pub fn forget(state: &AppState, id: String) -> Result<(), String> {
    let ctx = context(state)?;
    ctx.actor
        .clear_accepted(&id, &ctx.keys)
        .map_err(|e| e.to_string())?;
    current(state, &ctx)
}
pub fn hide(state: &AppState, id: String) -> Result<(), String> {
    let ctx = context(state)?;
    ctx.actor.hide(&id, &ctx.keys).map_err(|e| e.to_string())?;
    current(state, &ctx)
}
pub async fn process(state: &AppState) -> Result<Report, String> {
    let Some(selected) = normal::capture(state)? else {
        return Ok(Report::default());
    };
    if selected.protocol != "v3" || selected.identity.token.is_empty() {
        return Ok(Report::default());
    }
    let ctx = context(state)?;
    if ctx.selected.identity.token.is_empty() {
        return Ok(Report::default());
    }
    let work = async {
        let poll = ctx.actor.poll(&ctx.keys).await?;
        let (drive, errors) = match ctx.actor.drive(false, &ctx.keys).await {
            Ok(drive) => (drive, vec![]),
            Err(error) => (Default::default(), vec![error.to_string()]),
        };
        let changed = drive
            .task
            .as_ref()
            .is_some_and(|t| matches!(t.condition, Condition::Accepted | Condition::Cancelled))
            || poll.received > 0;
        Ok::<_, liteseal_core::trusted_devices::messages::coordinator::CoordinatorError>(Report {
            changed,
            task: drive.task,
            media: None,
            errors,
            poll: Some(poll),
            notification_scope: Some(ctx.key.clone()),
            notifications: ctx.actor.claim_notifications(&ctx.keys)?,
            operation: None,
            operation_poll: None,
        })
    };
    let result = bounded(work).await?;
    current(state, &ctx)?;
    Ok(result)
}

pub async fn process_media(state: &AppState) -> Result<Report, String> {
    let Some(selected) = normal::capture(state)? else {
        return Ok(Report::default());
    };
    if selected.protocol != "v3" || selected.identity.token.is_empty() {
        return Ok(Report::default());
    }
    let ctx = context(state)?;
    let result = bounded(ctx.actor.drive(true, &ctx.keys)).await;
    current(state, &ctx)?;
    match result {
        Ok(drive) => Ok(Report {
            changed: drive.task.is_some() || drive.media.is_some(),
            task: drive.task,
            media: drive.media,
            notification_scope: Some(ctx.key),
            ..Default::default()
        }),
        Err(error) => Ok(Report {
            errors: vec![error],
            notification_scope: Some(ctx.key),
            ..Default::default()
        }),
    }
}
