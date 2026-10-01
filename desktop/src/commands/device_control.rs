//! Original-device control only. Keys and normal session credentials are loaded
//! from the Rust identity, never accepted as IPC arguments or returned to pages.
use crate::AppState;
use liteseal_core::{
    keystore::KeystoreData,
    trusted_devices::{
        coordinator::{DeviceCoordinator, JoinInspection, Progress, RootSnapshot},
        tasks::{TaskOwner, TaskView},
    },
};
use liteseal_shared::{
    crypto,
    trusted_device::{canonical_origin, Anchor, DeviceIdentity},
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
#[derive(Default)]
pub(crate) struct Runtime {
    cache: Option<Cached>,
    suspended: bool,
    epoch: u64,
}
struct Cached {
    key: String,
    client: Arc<DeviceCoordinator>,
}
struct Context {
    key: String,
    client: Arc<DeviceCoordinator>,
    keys: crypto::KeyPair,
    epoch: u64,
}
fn binding(saved: &KeystoreData) -> Result<String, String> {
    let bytes = serde_json::to_vec(&(
        canonical_origin(&saved.server_url).map_err(|_| "服务器地址无法用于设备授权")?,
        &saved.user_id,
        &saved.device_id,
        &saved.public_key,
        &saved.ed25519_pk,
        &saved.secret_key,
        &saved.ed25519_sk,
        &saved.token,
    ))
    .map_err(|_| "设备身份无法确认")?;
    Ok(hex::encode(Sha256::digest(bytes)))
}
fn context(state: &AppState) -> Result<Context, String> {
    let saved = state.identity()?;
    if saved.user_id.is_empty() || saved.device_id.is_empty() || saved.token.is_empty() {
        return Err("请在原设备登录后进行设备授权".into());
    }
    let key = binding(&saved)?;
    let keys = liteseal_core::backup::identity_keys(&saved)?;
    let anchor = Anchor {
        origin: canonical_origin(&saved.server_url).map_err(|_| "服务器地址无效")?,
        account: saved.user_id.clone(),
        root: DeviceIdentity::from_keys(saved.device_id.clone(), &keys),
    };
    let mut runtime = state
        .device_control_runtime
        .lock()
        .map_err(|_| "设备控制锁不可用")?;
    if runtime.suspended {
        return Err("设备控制已暂停，请解锁后重试".into());
    }
    if binding(&state.identity()?)? != key {
        return Err("设备身份已变化，请重新查询".into());
    }
    if runtime.cache.as_ref().is_none_or(|cache| cache.key != key) {
        if let Some(cache) = runtime.cache.take() {
            cache.client.invalidate().map_err(|e| e.to_string())?;
        }
        runtime.epoch = runtime.epoch.checked_add(1).ok_or("设备控制代次无效")?;
        let owner = TaskOwner::for_root(&anchor, &keys)?;
        let client = Arc::new(
            DeviceCoordinator::open(&state.db_path, owner, &keys).map_err(|e| e.to_string())?,
        );
        client
            .renew_session(saved.token)
            .map_err(|e| e.to_string())?;
        runtime.cache = Some(Cached {
            key: key.clone(),
            client,
        });
    }
    Ok(Context {
        key,
        keys,
        epoch: runtime.epoch,
        client: runtime.cache.as_ref().unwrap().client.clone(),
    })
}
fn current(state: &AppState, ctx: &Context) -> Result<(), String> {
    if binding(&state.identity()?)? != ctx.key {
        return Err("设备身份已变化，结果未交付".into());
    }
    let runtime = state
        .device_control_runtime
        .lock()
        .map_err(|_| "设备控制锁不可用")?;
    if runtime.suspended || runtime.epoch != ctx.epoch {
        return Err("设备控制结果已失效".into());
    }
    Ok(())
}
pub(crate) fn invalidate(state: &AppState) -> Result<(), String> {
    let mut runtime = state
        .device_control_runtime
        .lock()
        .map_err(|_| "设备控制锁不可用")?;
    runtime.epoch = runtime.epoch.checked_add(1).ok_or("设备控制代次无效")?;
    if let Some(cache) = runtime.cache.take() {
        cache.client.invalidate().map_err(|e| e.to_string())?;
    }
    Ok(())
}
pub fn suspend(state: &AppState) -> Result<(), String> {
    let mut runtime = state
        .device_control_runtime
        .lock()
        .map_err(|_| "设备控制锁不可用")?;
    runtime.suspended = true;
    runtime.epoch = runtime.epoch.checked_add(1).ok_or("设备控制代次无效")?;
    if let Some(cache) = runtime.cache.take() {
        cache.client.invalidate().map_err(|e| e.to_string())?;
    }
    Ok(())
}
pub fn resume(state: &AppState) -> Result<(), String> {
    let mut runtime = state
        .device_control_runtime
        .lock()
        .map_err(|_| "设备控制锁不可用")?;
    runtime.epoch = runtime.epoch.checked_add(1).ok_or("设备控制代次无效")?;
    runtime.suspended = false;
    Ok(())
}
pub async fn snapshot(state: &AppState) -> Result<RootSnapshot, String> {
    let ctx = context(state)?;
    let result = ctx
        .client
        .root_snapshot(&ctx.keys)
        .await
        .map_err(|e| e.to_string())?;
    current(state, &ctx)?;
    Ok(result)
}
pub async fn inspect(state: &AppState, id: String) -> Result<JoinInspection, String> {
    let ctx = context(state)?;
    let result = ctx
        .client
        .inspect_join(&id, &ctx.keys)
        .await
        .map_err(|e| e.to_string())?;
    current(state, &ctx)?;
    Ok(result)
}
pub async fn prepare(
    state: &AppState,
    id: String,
    fingerprint: String,
    grant: bool,
) -> Result<Option<TaskView>, String> {
    let ctx = context(state)?;
    let result = if grant {
        ctx.client.prepare_grant(&id, &fingerprint, &ctx.keys).await
    } else {
        ctx.client
            .prepare_challenge(&id, &fingerprint, &ctx.keys)
            .await
    }
    .map_err(|e| e.to_string())?;
    current(state, &ctx)?;
    Ok(result)
}
pub async fn revoke(state: &AppState, fingerprint: String) -> Result<Option<TaskView>, String> {
    let ctx = context(state)?;
    let result = ctx
        .client
        .prepare_revoke_confirmed(&fingerprint, &ctx.keys)
        .await
        .map_err(|e| e.to_string())?;
    current(state, &ctx)?;
    Ok(result)
}
pub async fn step(state: &AppState, id: String) -> Result<Progress, String> {
    let ctx = context(state)?;
    let result = ctx
        .client
        .step(&id, None, &ctx.keys)
        .await
        .map_err(|e| e.to_string())?;
    current(state, &ctx)?;
    Ok(result)
}
pub fn cancel(state: &AppState, id: String) -> Result<TaskView, String> {
    let ctx = context(state)?;
    let result = ctx
        .client
        .request_cancel(&id, &ctx.keys)
        .map_err(|e| e.to_string())?;
    current(state, &ctx)?;
    Ok(result)
}
pub fn discard(state: &AppState, id: String) -> Result<(), String> {
    let ctx = context(state)?;
    ctx.client
        .discard_terminal(&id, &ctx.keys)
        .map_err(|e| e.to_string())?;
    current(state, &ctx)
}
