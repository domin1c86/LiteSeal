//! Root-only cutover. An async desktop gate drains in-flight legacy writes;
//! sync/native locks are held only for bounded local transitions, never awaits.
use crate::AppState;
use liteseal_core::{
    keystore::KeystoreData,
    trusted_devices::{
        activation::{
            jobs,
            legacy::{self, Admission, Pending},
            ActivationApi,
        },
        tasks::anchor_fingerprint,
    },
};
use liteseal_shared::{
    crypto::KeyPair,
    trusted_device::{canonical_origin, Anchor, DeviceIdentity},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::{Arc, MutexGuard};
use zeroize::Zeroizing;
#[derive(Default)]
pub(crate) struct Runtime {
    cache: Option<Cached>,
    suspended: bool,
    epoch: u64,
}
struct Cached {
    binding: String,
    jobs: Arc<jobs::Coordinator>,
}
struct Context {
    binding: String,
    epoch: u64,
    anchor: Anchor,
    keys: KeyPair,
    jobs: Arc<jobs::Coordinator>,
}
#[derive(Serialize)]
pub struct Snapshot {
    pub root_fingerprint: String,
    pub admission: Admission,
    pub pending: Pending,
    pub tasks: Vec<jobs::View>,
}
fn bad() -> String {
    "原设备切换状态已失效，请查询原任务；原身份已保留".into()
}
fn root(saved: &KeystoreData) -> Result<(Anchor, KeyPair), String> {
    let keys = liteseal_core::backup::identity_keys(saved)?;
    let anchor = Anchor {
        origin: canonical_origin(&saved.server_url).map_err(|_| bad())?,
        account: saved.user_id.clone(),
        root: DeviceIdentity::from_keys(saved.device_id.clone(), &keys),
    };
    Ok((anchor, keys))
}
fn binding(saved: &KeystoreData) -> Result<String, String> {
    let plain = Zeroizing::new(serde_json::to_vec(saved).map_err(|_| bad())?);
    Ok(hex::encode(Sha256::digest(&plain)))
}
fn available(runtime: &Runtime) -> Result<(), String> {
    if runtime.suspended {
        Err("原设备切换已暂停，请解锁后重试".into())
    } else {
        Ok(())
    }
}
pub(crate) fn invalidate(state: &AppState, suspend: bool) -> Result<(), String> {
    let mut runtime = state.root_messaging_runtime.lock().map_err(|_| bad())?;
    runtime.epoch = runtime.epoch.checked_add(1).ok_or_else(bad)?;
    if suspend {
        runtime.suspended = true;
    }
    if let Some(cache) = runtime.cache.take() {
        cache.jobs.invalidate()?;
    }
    Ok(())
}
pub(crate) fn resume(state: &AppState) -> Result<(), String> {
    let mut r = state.root_messaging_runtime.lock().map_err(|_| bad())?;
    r.epoch = r.epoch.checked_add(1).ok_or_else(bad)?;
    r.suspended = false;
    Ok(())
}
fn context(state: &AppState) -> Result<Context, String> {
    let saved = state.identity()?;
    let bound = binding(&saved)?;
    let (anchor, keys) = root(&saved)?;
    let mut runtime = state.root_messaging_runtime.lock().map_err(|_| bad())?;
    available(&runtime)?;
    if binding(&state.identity()?)? != bound {
        return Err(bad());
    }
    if runtime.cache.as_ref().is_none_or(|c| c.binding != bound) {
        if let Some(cache) = runtime.cache.take() {
            cache.jobs.invalidate()?;
        }
        runtime.epoch = runtime.epoch.checked_add(1).ok_or_else(bad)?;
        // The original-device control page must first verify/sync its own root.
        let jobs = Arc::new(jobs::Coordinator::open_with_protection(
            &state.db_path,
            jobs::Owner::new(anchor.clone(), &anchor.root.device_id, &keys)?,
            &keys,
            state.device_protection.clone(),
        )?);
        jobs.renew_session(saved.token)?;
        runtime.cache = Some(Cached {
            binding: bound.clone(),
            jobs,
        });
    }
    Ok(Context {
        binding: bound,
        epoch: runtime.epoch,
        anchor,
        keys,
        jobs: runtime.cache.as_ref().unwrap().jobs.clone(),
    })
}
fn current<'a>(state: &'a AppState, ctx: &Context) -> Result<MutexGuard<'a, Runtime>, String> {
    let runtime = state.root_messaging_runtime.lock().map_err(|_| bad())?;
    available(&runtime)?;
    if runtime.epoch != ctx.epoch
        || runtime
            .cache
            .as_ref()
            .is_none_or(|c| c.binding != ctx.binding)
        || binding(&state.identity()?)? != ctx.binding
    {
        return Err(bad());
    }
    Ok(runtime)
}
fn local(state: &AppState, ctx: &Context) -> Result<legacy::Store, String> {
    legacy::Store::open(
        &state.db_path,
        ctx.anchor.clone(),
        state.device_witness(&state.db_path)?,
    )
}
fn view(state: &AppState, ctx: &Context) -> Result<Snapshot, String> {
    let mut local = local(state, ctx)?;
    let admission = local.admission(&ctx.keys)?;
    let pending = local.pending()?;
    let tasks = ctx
        .jobs
        .views(&ctx.keys)?
        .into_iter()
        .filter(|v| v.kind == jobs::Kind::Enable)
        .collect();
    Ok(Snapshot {
        root_fingerprint: anchor_fingerprint(&ctx.anchor),
        admission,
        pending,
        tasks,
    })
}
pub fn snapshot(state: &AppState) -> Result<Snapshot, String> {
    let ctx = context(state)?;
    let _current = current(state, &ctx)?;
    view(state, &ctx)
}
pub async fn prepare(state: &AppState, fingerprint: String) -> Result<jobs::View, String> {
    let ctx = context(state)?;
    if fingerprint != anchor_fingerprint(&ctx.anchor) {
        return Err("请核对当前原设备完整指纹并明确确认切换".into());
    }
    let _writes = state.legacy_direct_gate.write().await;
    let _current = current(state, &ctx)?;
    ctx.jobs.prepare_enable_checked(&ctx.keys)
}
pub async fn check(state: &AppState) -> Result<Snapshot, String> {
    let ctx = context(state)?;
    let _writes = state.legacy_direct_gate.write().await;
    let directory = {
        let _current = current(state, &ctx)?;
        let mut store = liteseal_core::trusted_devices::DeviceTrustStore::open(&state.db_path)?;
        store.protect(state.device_witness(&state.db_path)?)?;
        store.load(&ctx.anchor, None)?
    };
    let api = ActivationApi::new(&ctx.anchor.origin).map_err(|e| e.to_string())?;
    let observed = api
        .observe_mode(&directory, &ctx.anchor.root.device_id, &ctx.keys)
        .await
        .map_err(|e| e.to_string())?;
    let _current = current(state, &ctx)?;
    if observed.enabled() {
        local(state, &ctx)?.remember_enabled(observed, &ctx.keys)?;
    }
    view(state, &ctx)
}
pub async fn step(state: &AppState, id: String) -> Result<jobs::Progress, String> {
    let ctx = context(state)?;
    let _writes = state.legacy_direct_gate.write().await;
    {
        let _current = current(state, &ctx)?;
        ensure_enable(&ctx, &id)?;
    }
    let result = ctx.jobs.step(&id, None, &ctx.keys).await?;
    let _current = current(state, &ctx)?;
    Ok(result)
}
fn ensure_enable(ctx: &Context, id: &str) -> Result<(), String> {
    if ctx
        .jobs
        .views(&ctx.keys)?
        .iter()
        .any(|v| v.id == id && v.kind == jobs::Kind::Enable)
    {
        Ok(())
    } else {
        Err(bad())
    }
}
pub fn cancel(state: &AppState, id: String) -> Result<jobs::View, String> {
    let ctx = context(state)?;
    let _current = current(state, &ctx)?;
    ensure_enable(&ctx, &id)?;
    ctx.jobs.request_cancel(&id, &ctx.keys)
}
pub fn forget(state: &AppState, id: String) -> Result<(), String> {
    let ctx = context(state)?;
    let _current = current(state, &ctx)?;
    ensure_enable(&ctx, &id)?;
    ctx.jobs.forget_ended(&id, &ctx.keys)
}
/// Checked at the typed dispatcher while holding its async legacy read gate.
pub(crate) fn admission(state: &AppState) -> Result<Admission, String> {
    if state.db_path.to_str() == Some(":memory:") {
        return Ok(Admission::Legacy);
    }
    let saved = state.identity()?;
    let (anchor, keys) = root(&saved)?;
    legacy::admission(
        &state.db_path,
        anchor,
        &keys,
        state.device_witness(&state.db_path)?,
    )
}
pub(crate) fn local_seen(state: &AppState, user: &str, ids: &[String]) -> Result<(), String> {
    if state.identity()?.user_id != user {
        return Err("已读账号不匹配".into());
    }
    state
        .client
        .db
        .lock()
        .map_err(|_| bad())?
        .mark_visible_with_receipts(user, ids, &Default::default())
        .map_err(|e| e.to_string())
}
pub(crate) fn download(state: &AppState, id: &str) -> Result<bool, String> {
    let user = state.identity()?.user_id;
    Ok(state
        .client
        .db
        .lock()
        .map_err(|_| bad())?
        .attachment_transfer(&user, id)
        .map_err(|e| e.to_string())?
        .direction
        == "download")
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use liteseal_core::{
        backup::WorkDirectory,
        trusted_devices::{witness::platform::Protection, DeviceTrustStore},
    };
    fn fixture() -> (WorkDirectory, Arc<AppState>, Anchor) {
        let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
        let state = Arc::new(
            AppState::with_device_protection(
                work.0.join("root.db").to_str().unwrap(),
                Some(work.0.join("root.bin")),
                Protection::isolated_test(),
            )
            .unwrap(),
        );
        let keys = liteseal_shared::crypto::generate_keypair().unwrap();
        let anchor = Anchor {
            origin: "https://root-unit.invalid".into(),
            account: uuid::Uuid::new_v4().to_string(),
            root: DeviceIdentity::from_keys(uuid::Uuid::new_v4().to_string(), &keys),
        };
        state
            .save_identity(KeystoreData {
                user_id: anchor.account.clone(),
                device_id: anchor.root.device_id.clone(),
                server_url: anchor.origin.clone(),
                token: "synthetic-access".into(),
                refresh_token: "synthetic-refresh".into(),
                public_key: keys.public_key.to_vec(),
                secret_key: keys.secret_key.to_vec(),
                ed25519_pk: keys.ed25519_pk.to_vec(),
                ed25519_sk: keys.ed25519_sk.to_vec(),
            })
            .unwrap();
        let mut trust = DeviceTrustStore::open(&state.db_path).unwrap();
        trust
            .protect(state.device_witness(&state.db_path).unwrap())
            .unwrap();
        trust.pin(&anchor).unwrap();
        (work, state, anchor)
    }
    #[tokio::test]
    async fn cutover_waits_for_in_flight_legacy_reader_and_revalidates_suspension() {
        for suspend in [false, true] {
            let (_work, state, anchor) = fixture();
            let reader = state.legacy_direct_gate.read().await;
            let active = state.clone();
            let fingerprint = anchor_fingerprint(&anchor);
            let pending = tokio::spawn(async move { prepare(&active, fingerprint).await });
            tokio::time::sleep(std::time::Duration::from_millis(40)).await;
            assert!(!pending.is_finished());
            assert!(snapshot(&state).unwrap().tasks.is_empty());
            if suspend {
                super::super::device_control::suspend(&state).unwrap();
                super::super::device_control::resume(&state).unwrap();
            }
            drop(reader);
            let result = pending.await.unwrap();
            if suspend {
                assert!(result.is_err());
                assert!(snapshot(&state).unwrap().tasks.is_empty());
            } else {
                assert_eq!(result.unwrap().stage, jobs::Stage::Prepared);
            }
        }
    }
    #[tokio::test]
    async fn typed_legacy_dispatch_waits_for_writer_before_admission() {
        let (_work, state, anchor) = fixture();
        let writer = state.legacy_direct_gate.write().await;
        let active = state.clone();
        let pending = tokio::spawn(async move {
            crate::protocol::dispatch(
                crate::protocol::Command::SendTyping {
                    peer_id: "peer".into(),
                    active: true,
                },
                &active,
            )
            .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        assert!(!pending.is_finished());
        let ctx = context(&state).unwrap();
        ctx.jobs.prepare_enable_checked(&ctx.keys).unwrap();
        drop(writer);
        assert!(pending
            .await
            .unwrap()
            .unwrap_err()
            .contains("旧单聊发送已暂停"));
        assert_eq!(
            snapshot(&state).unwrap().root_fingerprint,
            anchor_fingerprint(&anchor)
        );
    }
}
