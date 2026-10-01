//! Join-only profiles never bind the ordinary identity or connect a relay.
use crate::AppState;
use liteseal_core::trusted_devices::{
    coordinator::{DeviceCoordinator, JoinInfo, Progress},
    profiles::{JoinProfile, JoinProfileStore, ProfileListing, ProfileView},
    tasks::TaskPhase,
};
use liteseal_shared::crypto::KeyPair;
use serde::Serialize;
use std::sync::{Arc, Weak};

#[derive(Default)]
pub(crate) struct Runtime {
    cache: Option<Cached>,
    suspended: bool,
    epoch: u64,
    retired: Vec<(String, Weak<DeviceCoordinator>)>,
}
struct Cached {
    id: String,
    client: Arc<DeviceCoordinator>,
}
struct Context {
    epoch: u64,
    profile: JoinProfile,
    keys: KeyPair,
    client: Arc<DeviceCoordinator>,
}
fn retire(runtime: &mut Runtime, cache: Cached) -> Result<(), String> {
    cache.client.invalidate().map_err(|e| e.to_string())?;
    runtime
        .retired
        .retain(|(_, client)| client.strong_count() > 0);
    if Arc::strong_count(&cache.client) > 1 {
        runtime
            .retired
            .push((cache.id, Arc::downgrade(&cache.client)));
    }
    Ok(())
}
#[derive(Serialize)]
pub struct JoinSnapshot {
    pub profile: ProfileView,
    pub join: JoinInfo,
    pub messaging_enabled: bool,
}
fn store(state: &AppState) -> Result<JoinProfileStore, String> {
    state.device_join_store()
}
fn available(runtime: &Runtime) -> Result<(), String> {
    if runtime.suspended {
        Err("加入设备已暂停，请解锁后重试".into())
    } else {
        Ok(())
    }
}
pub(crate) fn invalidate(state: &AppState, suspend: bool) -> Result<(), String> {
    let mut runtime = state
        .device_join_runtime
        .lock()
        .map_err(|_| "加入设备锁不可用")?;
    runtime.epoch = runtime.epoch.checked_add(1).ok_or("加入设备代次无效")?;
    if suspend {
        runtime.suspended = true;
    }
    if let Some(cache) = runtime.cache.take() {
        retire(&mut runtime, cache)?;
    }
    Ok(())
}
pub(crate) fn resume(state: &AppState) -> Result<(), String> {
    let mut runtime = state
        .device_join_runtime
        .lock()
        .map_err(|_| "加入设备锁不可用")?;
    runtime.epoch = runtime.epoch.checked_add(1).ok_or("加入设备代次无效")?;
    runtime.suspended = false;
    Ok(())
}
fn open(
    state: &AppState,
    runtime: &mut Runtime,
    store: &JoinProfileStore,
    id: &str,
) -> Result<Context, String> {
    available(runtime)?;
    let profile = store.load(id)?;
    let keys = profile.keys()?;
    let database = store.database(id)?;
    if runtime.cache.as_ref().is_none_or(|cache| cache.id != id) {
        if let Some(cache) = runtime.cache.take() {
            retire(runtime, cache)?;
        }
        runtime.epoch = runtime.epoch.checked_add(1).ok_or("加入设备代次无效")?;
        let client = Arc::new(
            DeviceCoordinator::open_protected(
                &database,
                profile.owner()?,
                &keys,
                state.device_witness(&database)?,
            )
            .map_err(|e| e.to_string())?,
        );
        let tasks = client.tasks(&keys).map_err(|e| e.to_string())?;
        if tasks.len() != 1 || tasks[0].id != profile.task_id() {
            return Err("加入档案申请缺失或不匹配，已保留密钥且未重新生成任务".into());
        }
        runtime.cache = Some(Cached {
            id: id.into(),
            client,
        });
    }
    Ok(Context {
        epoch: runtime.epoch,
        profile,
        keys,
        client: runtime.cache.as_ref().unwrap().client.clone(),
    })
}
fn context(state: &AppState, id: &str) -> Result<Context, String> {
    let mut runtime = state
        .device_join_runtime
        .lock()
        .map_err(|_| "加入设备锁不可用")?;
    open(state, &mut runtime, &store(state)?, id)
}
fn current(state: &AppState, ctx: &Context) -> Result<(), String> {
    let runtime = state
        .device_join_runtime
        .lock()
        .map_err(|_| "加入设备锁不可用")?;
    available(&runtime)?;
    if runtime.epoch != ctx.epoch
        || runtime
            .cache
            .as_ref()
            .is_none_or(|cache| cache.id != ctx.profile.view().id)
    {
        return Err("加入档案已切换，迟到结果未交付".into());
    }
    Ok(())
}
fn info(ctx: &Context) -> Result<JoinInfo, String> {
    let tasks = ctx.client.tasks(&ctx.keys).map_err(|e| e.to_string())?;
    if tasks.len() != 1 {
        return Err("加入档案的申请数量不符合要求".into());
    }
    ctx.client
        .join_info(&tasks[0].id, &ctx.keys)
        .map_err(|e| e.to_string())
}
fn view(ctx: &Context) -> Result<JoinSnapshot, String> {
    Ok(JoinSnapshot {
        profile: ctx.profile.view(),
        join: info(ctx)?,
        messaging_enabled: false,
    })
}
pub fn list(state: &AppState) -> Result<Vec<ProfileListing>, String> {
    let runtime = state
        .device_join_runtime
        .lock()
        .map_err(|_| "加入设备锁不可用")?;
    available(&runtime)?;
    store(state)?.list()
}
pub fn create(
    state: &AppState,
    origin: String,
    username: String,
    name: String,
) -> Result<JoinSnapshot, String> {
    let mut runtime = state
        .device_join_runtime
        .lock()
        .map_err(|_| "加入设备锁不可用")?;
    available(&runtime)?;
    let store = store(state)?;
    let profile = store.create(&origin, &username, &name)?;
    let ctx = open(state, &mut runtime, &store, &profile.view().id)?;
    view(&ctx)
}
pub fn snapshot(state: &AppState, id: String) -> Result<JoinSnapshot, String> {
    let ctx = context(state, &id)?;
    let result = view(&ctx)?;
    current(state, &ctx)?;
    Ok(result)
}
pub fn confirm(state: &AppState, id: String, fingerprint: String) -> Result<JoinSnapshot, String> {
    let ctx = context(state, &id)?;
    let task = info(&ctx)?.task;
    ctx.client
        .confirm_root(&task.id, &fingerprint, &ctx.keys)
        .map_err(|e| e.to_string())?;
    let result = view(&ctx)?;
    current(state, &ctx)?;
    Ok(result)
}
pub async fn step(
    state: &AppState,
    id: String,
    password: Option<String>,
) -> Result<Progress, String> {
    if password
        .as_ref()
        .is_some_and(|password| password.len() > 1024 || password.is_empty())
    {
        return Err("账号密码长度无效".into());
    }
    let ctx = context(state, &id)?;
    let task = info(&ctx)?.task;
    let result = ctx
        .client
        .step(&task.id, password.as_deref(), &ctx.keys)
        .await
        .map_err(|e| e.to_string())?;
    current(state, &ctx)?;
    Ok(result)
}
pub fn cancel(state: &AppState, id: String) -> Result<JoinSnapshot, String> {
    let ctx = context(state, &id)?;
    let task = info(&ctx)?.task;
    ctx.client
        .request_cancel(&task.id, &ctx.keys)
        .map_err(|e| e.to_string())?;
    let result = view(&ctx)?;
    current(state, &ctx)?;
    Ok(result)
}
pub fn forget(state: &AppState, id: String) -> Result<(), String> {
    // Existing accepted identities remain available for the later activation phase.
    let mut runtime = state
        .device_join_runtime
        .lock()
        .map_err(|_| "加入设备锁不可用")?;
    available(&runtime)?;
    let store = store(state)?;
    if !store.exists(&id)?
        && runtime.cache.as_ref().is_none_or(|cache| cache.id != id)
        && !runtime
            .retired
            .iter()
            .any(|(profile, client)| profile == &id && client.strong_count() > 0)
    {
        return Ok(());
    }
    if store.load(&id).is_err() && runtime.cache.as_ref().is_none_or(|cache| cache.id != id) {
        return store.remove_empty(&id);
    }
    let ctx = open(state, &mut runtime, &store, &id)?;
    if !matches!(
        info(&ctx)?.task.phase,
        TaskPhase::Cancelled | TaskPhase::Expired | TaskPhase::Revoked
    ) {
        return Err("请先确认申请取消或过期；已授权档案需保留，撤销请在原设备操作".into());
    }
    if Arc::strong_count(&ctx.client) != 2
        || runtime
            .retired
            .iter()
            .any(|(profile, client)| profile == &id && client.strong_count() > 0)
    {
        return Err("仍有在途请求，请稍后整理".into());
    }
    if let Some(cache) = runtime.cache.take() {
        retire(&mut runtime, cache)?;
    }
    runtime.epoch = runtime.epoch.checked_add(1).ok_or("加入设备代次无效")?;
    drop(ctx);
    store.remove(&id)
}
pub fn abandon(state: &AppState, id: String) -> Result<JoinSnapshot, String> {
    let ctx = context(state, &id)?;
    let task = info(&ctx)?.task;
    ctx.client
        .abandon_unsigned(&task.id, &ctx.keys)
        .map_err(|e| e.to_string())?;
    let result = view(&ctx)?;
    current(state, &ctx)?;
    Ok(result)
}
