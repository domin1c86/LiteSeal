//! Formal activation of an accepted joining profile. No normal identity switch,
//! relay connection, passwords or session credentials are returned to a page.
use crate::AppState;
use liteseal_core::trusted_devices::{activation::jobs, profiles::active};
use liteseal_shared::crypto::KeyPair;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Weak};
use zeroize::Zeroizing;

#[derive(Default)]
pub(crate) struct Runtime {
    cache: Option<Cached>,
    suspended: bool,
    epoch: u64,
    retired: Vec<(String, Weak<jobs::Coordinator>, Weak<active::Coordinator>)>,
}
struct Cached {
    id: String,
    binding: String,
    jobs: Arc<jobs::Coordinator>,
    normal: Arc<active::Coordinator>,
}
struct Context {
    id: String,
    username: String,
    keys: KeyPair,
    epoch: u64,
    binding: String,
    jobs: Arc<jobs::Coordinator>,
    normal: Arc<active::Coordinator>,
}
#[derive(Serialize)]
pub struct Snapshot {
    pub profile_id: String,
    pub tasks: Vec<jobs::View>,
    pub normal: Option<active::View>,
}
fn bad() -> String {
    "正式激活档案已失效或不可用，请重新查询原申请".into()
}
fn available(runtime: &Runtime) -> Result<(), String> {
    if runtime.suspended {
        Err("正式激活已暂停，请解锁后重试".into())
    } else {
        Ok(())
    }
}
fn retire(runtime: &mut Runtime, cache: Cached) -> Result<(), String> {
    cache.jobs.invalidate()?;
    cache.normal.invalidate()?;
    runtime
        .retired
        .retain(|(_, j, n)| j.strong_count() > 0 || n.strong_count() > 0);
    if Arc::strong_count(&cache.jobs) > 1 || Arc::strong_count(&cache.normal) > 1 {
        runtime.retired.push((
            cache.id,
            Arc::downgrade(&cache.jobs),
            Arc::downgrade(&cache.normal),
        ));
    }
    Ok(())
}
pub(crate) fn invalidate(state: &AppState, suspend: bool) -> Result<(), String> {
    super::session_refresh::invalidate(state, suspend)?;
    let mut runtime = state.device_activation_runtime.lock().map_err(|_| bad())?;
    runtime.epoch = runtime.epoch.checked_add(1).ok_or_else(bad)?;
    if suspend {
        runtime.suspended = true;
    }
    if let Some(cache) = runtime.cache.take() {
        retire(&mut runtime, cache)?;
    }
    Ok(())
}
pub(crate) fn resume(state: &AppState) -> Result<(), String> {
    super::session_refresh::resume(state)?;
    let mut runtime = state.device_activation_runtime.lock().map_err(|_| bad())?;
    runtime.epoch = runtime.epoch.checked_add(1).ok_or_else(bad)?;
    runtime.suspended = false;
    Ok(())
}
pub(crate) fn release_profile(state: &AppState, id: &str) -> Result<(), String> {
    let mut runtime = state.device_activation_runtime.lock().map_err(|_| bad())?;
    let busy = runtime.cache.as_ref().is_some_and(|c| {
        c.id == id && (Arc::strong_count(&c.jobs) > 1 || Arc::strong_count(&c.normal) > 1)
    }) || runtime
        .retired
        .iter()
        .any(|(p, j, n)| p == id && (j.strong_count() > 0 || n.strong_count() > 0));
    if busy {
        return Err("正式激活仍有在途请求，请稍后整理；原身份已保留".into());
    }
    if runtime.cache.as_ref().is_some_and(|c| c.id == id) {
        let cache = runtime.cache.take().unwrap();
        retire(&mut runtime, cache)?;
        runtime.epoch = runtime.epoch.checked_add(1).ok_or_else(bad)?;
    }
    Ok(())
}
fn context(state: &AppState, id: &str) -> Result<Context, String> {
    let mut runtime = state.device_activation_runtime.lock().map_err(|_| bad())?;
    available(&runtime)?;
    let profiles = state.device_join_store()?;
    let profile = profiles.load(id)?;
    let keys = profile.keys()?;
    let local = active::Store::open_with_protection(
        state.device_join_directory()?,
        id,
        state.device_protection.clone(),
    )?;
    let owner = local.job_owner()?;
    let binding = hex::encode(Sha256::digest(
        serde_json::to_vec(&(profile.view(), profile.task_id(), &owner)).map_err(|_| bad())?,
    ));
    if runtime
        .cache
        .as_ref()
        .is_none_or(|c| c.id != id || c.binding != binding)
    {
        if let Some(cache) = runtime.cache.take() {
            retire(&mut runtime, cache)?;
        }
        runtime.epoch = runtime.epoch.checked_add(1).ok_or_else(bad)?;
        runtime.cache = Some(Cached {
            id: id.into(),
            binding: binding.clone(),
            jobs: Arc::new(jobs::Coordinator::open_with_protection(
                &local.database()?,
                owner,
                &keys,
                state.device_protection.clone(),
            )?),
            normal: Arc::new(active::Coordinator::open_with_protection(
                state.device_join_directory()?,
                id,
                state.device_protection.clone(),
            )?),
        });
    }
    let cache = runtime.cache.as_ref().unwrap();
    Ok(Context {
        id: id.into(),
        username: profile.view().username,
        keys,
        epoch: runtime.epoch,
        binding,
        jobs: cache.jobs.clone(),
        normal: cache.normal.clone(),
    })
}
fn current(state: &AppState, ctx: &Context) -> Result<(), String> {
    let runtime = state.device_activation_runtime.lock().map_err(|_| bad())?;
    available(&runtime)?;
    if runtime.epoch != ctx.epoch
        || runtime
            .cache
            .as_ref()
            .is_none_or(|c| c.id != ctx.id || c.binding != ctx.binding)
    {
        return Err(bad());
    }
    Ok(())
}
fn view(ctx: &Context) -> Result<Snapshot, String> {
    Ok(Snapshot {
        profile_id: ctx.id.clone(),
        tasks: ctx.jobs.views(&ctx.keys)?,
        normal: ctx.normal.view()?,
    })
}
pub fn snapshot(state: &AppState, id: String) -> Result<Snapshot, String> {
    let ctx = context(state, &id)?;
    let result = view(&ctx)?;
    current(state, &ctx)?;
    Ok(result)
}
pub async fn prepare(state: &AppState, id: String) -> Result<jobs::View, String> {
    let ctx = context(state, &id)?;
    if ctx
        .normal
        .view()?
        .is_some_and(|v| v.has_saved_session && !v.access_expired)
    {
        return Err("已有保存的有效期限会话；请先查询或明确清除本机会话".into());
    }
    let mode = ctx
        .jobs
        .discover_mode(&ctx.keys)
        .await?
        .ok_or("原设备尚未明确启用单聊 v3，请先在原设备完成切换")?;
    current(state, &ctx)?;
    let result = ctx.jobs.prepare_login(&ctx.username, mode, &ctx.keys)?;
    current(state, &ctx)?;
    Ok(result)
}
pub async fn step(
    state: &AppState,
    profile: String,
    id: String,
    password: Option<String>,
) -> Result<jobs::Progress, String> {
    let password = password.map(Zeroizing::new);
    if password
        .as_ref()
        .is_some_and(|p| p.is_empty() || p.len() > 1024)
    {
        return Err("账号密码长度无效".into());
    }
    let ctx = context(state, &profile)?;
    let result = ctx
        .jobs
        .step(&id, password.as_ref().map(|p| p.as_str()), &ctx.keys)
        .await?;
    current(state, &ctx)?;
    Ok(result)
}
pub async fn inspect(
    state: &AppState,
    profile: String,
    id: String,
) -> Result<jobs::Progress, String> {
    let ctx = context(state, &profile)?;
    let result = ctx.jobs.inspect(&id, &ctx.keys).await?;
    current(state, &ctx)?;
    Ok(result)
}
pub fn cancel(state: &AppState, profile: String, id: String) -> Result<jobs::View, String> {
    let ctx = context(state, &profile)?;
    let result = ctx.jobs.request_cancel(&id, &ctx.keys)?;
    current(state, &ctx)?;
    Ok(result)
}
pub fn forget(state: &AppState, profile: String, id: String) -> Result<(), String> {
    let ctx = context(state, &profile)?;
    if ctx.normal.view()?.is_some_and(|v| v.has_saved_session) {
        return Err("请先明确清除本机保存会话，再整理激活终态；身份和历史仍保留".into());
    }
    ctx.jobs.forget_ended(&id, &ctx.keys)?;
    current(state, &ctx)
}
pub async fn save(state: &AppState, profile: String, id: String) -> Result<active::View, String> {
    let ctx = context(state, &profile)?;
    let result = ctx.normal.activate(&id).await?;
    current(state, &ctx)?;
    Ok(result)
}
pub fn clear_session(state: &AppState, profile: String) -> Result<(), String> {
    let ctx = context(state, &profile)?;
    let mut runtime = state.device_activation_runtime.lock().map_err(|_| bad())?;
    available(&runtime)?;
    if runtime.epoch != ctx.epoch
        || runtime
            .cache
            .as_ref()
            .is_none_or(|c| c.id != ctx.id || c.binding != ctx.binding)
    {
        return Err(bad());
    }
    ctx.normal.clear_session()?;
    // Retire both admission gates while still holding the desktop transition
    // lock. An already captured context cannot obtain a fresh post-clear lease.
    if let Some(cache) = runtime.cache.take() {
        retire(&mut runtime, cache)?;
    }
    runtime.epoch = runtime.epoch.checked_add(1).ok_or_else(bad)?;
    Ok(())
}
