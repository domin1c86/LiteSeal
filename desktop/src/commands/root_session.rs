//! Recover an enabled original device with the original private keys. Neither
//! login capabilities nor new identities are accepted from or returned to pages.
use super::root_messaging::{self as root, Context};
use crate::AppState;
use liteseal_core::trusted_devices::{
    activation::{
        jobs,
        legacy::{self, Admission},
        ActivationApi,
    },
    DeviceTrustStore,
};
use serde::Serialize;
use zeroize::Zeroizing;
#[derive(Serialize)]
pub struct Snapshot {
    pub root_fingerprint: String,
    pub tasks: Vec<jobs::View>,
    pub has_local_credentials: bool,
}
#[derive(Serialize)]
pub struct Saved {
    pub user_id: String,
    pub device_id: String,
    pub server_url: String,
    pub public_key: Vec<u8>,
    pub ed25519_pk: Vec<u8>,
}
fn bad() -> String {
    "原设备正式会话申请范围已失效，请查询原任务".into()
}
fn ensure(ctx: &Context, id: &str) -> Result<(), String> {
    if ctx
        .jobs
        .views(&ctx.keys)?
        .iter()
        .any(|v| v.id == id && v.kind == jobs::Kind::Login)
    {
        Ok(())
    } else {
        Err(bad())
    }
}
fn directory(
    state: &AppState,
    ctx: &Context,
) -> Result<liteseal_shared::trusted_device::DeviceState, String> {
    let mut trust = DeviceTrustStore::open(&state.db_path)?;
    trust.protect(state.device_witness(&state.db_path)?)?;
    trust.load(&ctx.anchor, None)
}
pub fn snapshot(state: &AppState) -> Result<Snapshot, String> {
    let ctx = root::context(state)?;
    let _current = root::current(state, &ctx)?;
    Ok(Snapshot {
        root_fingerprint: liteseal_core::trusted_devices::tasks::anchor_fingerprint(&ctx.anchor),
        tasks: ctx
            .jobs
            .views(&ctx.keys)?
            .into_iter()
            .filter(|v| v.kind == jobs::Kind::Login)
            .collect(),
        has_local_credentials: !ctx.saved.token.is_empty(),
    })
}
pub async fn prepare(state: &AppState, username: String) -> Result<jobs::View, String> {
    if username.trim().is_empty() || username.trim().len() > 128 {
        return Err("原账号名长度无效".into());
    }
    let ctx = root::context(state)?;
    let state_dir = {
        let _current = root::current(state, &ctx)?;
        let mut local = legacy::Store::open(
            &state.db_path,
            ctx.anchor.clone(),
            state.device_witness(&state.db_path)?,
        )?;
        if local.admission(&ctx.keys)? == Admission::Legacy {
            return Err("请先明确准备原设备单聊协议切换".into());
        }
        directory(state, &ctx)?
    };
    let observed = ActivationApi::new(&ctx.anchor.origin)
        .map_err(|e| e.to_string())?
        .observe_mode(&state_dir, &ctx.anchor.root.device_id, &ctx.keys)
        .await
        .map_err(|e| e.to_string())?;
    let mode = observed.event().cloned().ok_or("原设备启用配置尚未确认")?;
    let _current = root::current(state, &ctx)?;
    // A positive signed remote result stays sticky even if login preparation
    // subsequently fails. It never rewrites the original pending enable task.
    legacy::Store::open(
        &state.db_path,
        ctx.anchor.clone(),
        state.device_witness(&state.db_path)?,
    )?
    .remember_enabled(observed, &ctx.keys)?;
    ctx.jobs.prepare_login(username.trim(), mode, &ctx.keys)
}
pub async fn step(
    state: &AppState,
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
    let ctx = root::context(state)?;
    {
        let _current = root::current(state, &ctx)?;
        ensure(&ctx, &id)?;
    }
    let result = ctx
        .jobs
        .step(&id, password.as_ref().map(|p| p.as_str()), &ctx.keys)
        .await?;
    let _current = root::current(state, &ctx)?;
    Ok(result)
}
pub async fn inspect(state: &AppState, id: String) -> Result<jobs::Progress, String> {
    let ctx = root::context(state)?;
    {
        let _current = root::current(state, &ctx)?;
        ensure(&ctx, &id)?;
    }
    let result = ctx.jobs.inspect(&id, &ctx.keys).await?;
    let _current = root::current(state, &ctx)?;
    Ok(result)
}
pub fn cancel(state: &AppState, id: String) -> Result<jobs::View, String> {
    let ctx = root::context(state)?;
    let _current = root::current(state, &ctx)?;
    ensure(&ctx, &id)?;
    ctx.jobs.request_cancel(&id, &ctx.keys)
}
pub fn forget(state: &AppState, id: String) -> Result<(), String> {
    let ctx = root::context(state)?;
    let _current = root::current(state, &ctx)?;
    ensure(&ctx, &id)?;
    ctx.jobs.forget_ended(&id, &ctx.keys)
}
pub async fn save(state: &AppState, id: String) -> Result<Saved, String> {
    let ctx = root::context(state)?;
    {
        let _current = root::current(state, &ctx)?;
        ensure(&ctx, &id)?;
    }
    if ctx.jobs.inspect(&id, &ctx.keys).await?.condition != jobs::Condition::Complete {
        return Err("原正式会话尚未确认有效，请继续查询原申请".into());
    }
    let (session, original, state_dir, generation) = {
        let _current = root::current(state, &ctx)?;
        let mut store = jobs::Store::open(
            &state.db_path,
            jobs::Owner::new(ctx.anchor.clone(), &ctx.anchor.root.device_id, &ctx.keys)?,
            &ctx.keys,
            state.device_witness(&state.db_path)?,
        )?;
        (
            ctx.jobs.session(&id, &ctx.keys)?,
            store.task(&id, &ctx.keys)?,
            directory(state, &ctx)?,
            liteseal_core::trusted_devices::activation::refresh::jobs::Store::open(
                &state.db_path,
                jobs::Owner::new(ctx.anchor.clone(), &ctx.anchor.root.device_id, &ctx.keys)?,
                &ctx.keys,
                state.device_witness(&state.db_path)?,
            )?
            .current_view(&ctx.keys)?
            .map(|v| v.generation),
        )
    };
    if session.account != ctx.anchor.account || session.device != ctx.anchor.root.device_id {
        return Err(bad());
    }
    let checked = ActivationApi::new(&ctx.anchor.origin)
        .map_err(|e| e.to_string())?
        .check_session(
            &session.access_token,
            &state_dir,
            original.enable(),
            &ctx.anchor.root,
            &ctx.keys,
        )
        .await
        .map_err(|e| e.to_string())?;
    {
        let _commit = state.backup_commit.lock().map_err(|_| "身份提交锁不可用")?;
        let _current = root::current(state, &ctx)?;
        if legacy::Store::open(
            &state.db_path,
            ctx.anchor.clone(),
            state.device_witness(&state.db_path)?,
        )?
        .admission(&ctx.keys)?
            != Admission::V3
        {
            return Err("请先查询并确认原设备启用配置，正式凭据未保存".into());
        }
        liteseal_core::trusted_devices::activation::refresh::jobs::Store::open(
            &state.db_path,
            jobs::Owner::new(ctx.anchor.clone(), &ctx.anchor.root.device_id, &ctx.keys)?,
            &ctx.keys,
            state.device_witness(&state.db_path)?,
        )?
        .adopt_expected(&original, checked, &ctx.keys, generation)?;
    }
    // Retire old session contexts after the CAS and all transition locks drop.
    super::device_control::invalidate(state)?;
    super::groups::invalidate(state, &ctx.saved)?;
    let saved = state.identity()?;
    Ok(Saved {
        user_id: saved.user_id,
        device_id: saved.device_id,
        server_url: saved.server_url,
        public_key: saved.public_key,
        ed25519_pk: saved.ed25519_pk,
    })
}
