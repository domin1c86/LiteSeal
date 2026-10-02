//! Selected normal identity. Independent of the immutable original keystore.
use crate::AppState;
use liteseal_core::{
    keystore::KeystoreData,
    trusted_devices::profiles::{
        active,
        selection::{self, Binding},
    },
};
use liteseal_shared::trusted_device::canonical_origin;
pub use selection::Target;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
#[derive(Default)]
pub(crate) struct Runtime {
    epoch: u64,
    suspended: bool,
}
#[derive(Clone, Serialize)]
pub struct Choice {
    pub target: Target,
    pub scope_fingerprint: String,
    pub origin: String,
    pub account: String,
    pub device: String,
    pub device_name: String,
    pub protocol: String,
    pub has_session: bool,
    pub eligible: bool,
    pub access_expired: bool,
}
struct Candidate {
    view: Choice,
    binding: Binding,
    identity: KeystoreData,
    database: PathBuf,
}
#[derive(Serialize)]
pub struct Listing {
    pub target: Target,
    pub profile: Option<Choice>,
    pub error: Option<String>,
}
#[derive(Serialize)]
pub struct Snapshot {
    pub generation: u64,
    pub explicit: bool,
    pub selected: Option<Choice>,
    pub error: Option<String>,
    pub profiles: Vec<Listing>,
}
pub(crate) struct Context {
    pub target: Target,
    pub identity: KeystoreData,
    pub database: PathBuf,
    generation: u64,
    binding: Binding,
    epoch: u64,
}
fn bad() -> String {
    "正常档案范围已变化或暂停，请重新打开原档案".into()
}
fn store(state: &AppState) -> Result<selection::Store, String> {
    selection::Store::open(&state.db_path, state.device_witness(&state.db_path)?)
}
fn candidate(state: &AppState, target: Target) -> Result<Candidate, String> {
    let (identity, database, name, protocol, has_session, eligible, access_expired, extra) =
        match &target {
            Target::Root {} => {
                let identity = state.identity()?;
                let current = super::root_refresh::store(state, &state.saved_identity()?)?
                    .map(|mut s| {
                        let keys = liteseal_core::backup::identity_keys(&identity)?;
                        s.current_view(&keys)
                    })
                    .transpose()?
                    .flatten();
                let flags = current
                    .as_ref()
                    .map(|v| (v.has_credentials, v.eligible, v.access_expired))
                    .unwrap_or((!identity.token.is_empty(), true, false));
                let protocol = match super::root_messaging::admission(state)? {
                    liteseal_core::trusted_devices::activation::legacy::Admission::Legacy => {
                        "legacy"
                    }
                    liteseal_core::trusted_devices::activation::legacy::Admission::V3 => "v3",
                    liteseal_core::trusted_devices::activation::legacy::Admission::Switching => {
                        "switching"
                    }
                };
                (
                    identity,
                    state.db_path.clone(),
                    "原设备".into(),
                    protocol.into(),
                    flags.0,
                    flags.1,
                    flags.2,
                    String::new(),
                )
            }
            Target::Join { profile_id } => {
                let profile = state.device_join_store()?.load(profile_id)?;
                let normal = active::Store::open_with_protection(
                    state.device_join_directory()?,
                    profile_id,
                    state.device_protection.clone(),
                )?
                .load()?
                .ok_or("请先保存这个加入身份的正式会话档案")?;
                let view = normal.view();
                let identity = normal.identity();
                let database = state.device_join_store()?.database(profile_id)?;
                (
                    identity,
                    database,
                    view.device_name,
                    "v3".into(),
                    view.has_saved_session,
                    view.eligible,
                    view.access_expired,
                    profile.task_id().to_string(),
                )
            }
        };
    liteseal_core::backup::identity_keys(&identity)?;
    let origin = canonical_origin(&identity.server_url).map_err(|_| bad())?;
    let fingerprint: [u8; 32] = Sha256::digest(
        serde_json::to_vec(&(
            "LiteSeal/selected-identity/v1",
            &target,
            &origin,
            &identity.user_id,
            &identity.device_id,
            &identity.public_key,
            &identity.ed25519_pk,
            extra,
        ))
        .map_err(|_| bad())?,
    )
    .into();
    let view = Choice {
        target: target.clone(),
        scope_fingerprint: hex::encode(fingerprint),
        origin,
        account: identity.user_id.clone(),
        device: identity.device_id.clone(),
        device_name: name,
        protocol,
        has_session,
        eligible,
        access_expired,
    };
    Ok(Candidate {
        view,
        binding: Binding {
            target,
            fingerprint,
        },
        identity,
        database,
    })
}
pub(crate) fn invalidate(state: &AppState, suspend: bool) -> Result<(), String> {
    let mut r = state.normal_profile_runtime.lock().map_err(|_| bad())?;
    r.epoch = r.epoch.checked_add(1).ok_or_else(bad)?;
    if suspend {
        r.suspended = true;
    }
    Ok(())
}
pub(crate) fn resume(state: &AppState) -> Result<(), String> {
    let mut r = state.normal_profile_runtime.lock().map_err(|_| bad())?;
    r.epoch = r.epoch.checked_add(1).ok_or_else(bad)?;
    r.suspended = false;
    Ok(())
}
pub(crate) fn lease(state: &AppState) -> Result<u64, String> {
    let r = state.normal_profile_runtime.lock().map_err(|_| bad())?;
    if r.suspended {
        return Err(bad());
    }
    Ok(r.epoch)
}
pub(crate) fn check(state: &AppState, epoch: u64) -> Result<(), String> {
    if lease(state)? != epoch {
        Err(bad())
    } else {
        Ok(())
    }
}
pub fn snapshot(state: &AppState) -> Result<Snapshot, String> {
    let epoch = lease(state)?;
    let selected = store(state)?.current()?;
    let mut targets = vec![Target::Root {}];
    targets.extend(
        state
            .device_join_store()?
            .list()?
            .into_iter()
            .map(|p| Target::Join { profile_id: p.id }),
    );
    let profiles = targets
        .into_iter()
        .map(|target| match candidate(state, target.clone()) {
            Ok(c) => Listing {
                target,
                profile: Some(c.view),
                error: None,
            },
            Err(error) => Listing {
                target,
                profile: None,
                error: Some(error),
            },
        })
        .collect();
    let (view, error) = if let Some(binding) = &selected.selected {
        match candidate(state, binding.target.clone()) {
            Ok(c) if c.binding == *binding => (Some(c.view), None),
            _ => (None, Some(bad())),
        }
    } else if selected.generation == 0 {
        (candidate(state, Target::Root {}).ok().map(|c| c.view), None)
    } else {
        (None, None)
    };
    check(state, epoch)?;
    if store(state)?.current()? != selected {
        return Err(bad());
    }
    Ok(Snapshot {
        generation: selected.generation,
        explicit: selected.generation != 0,
        selected: view,
        error,
        profiles,
    })
}
pub(crate) fn capture(state: &AppState) -> Result<Option<Context>, String> {
    let epoch = lease(state)?;
    let selected = store(state)?.current()?;
    let c = if let Some(binding) = &selected.selected {
        let c = candidate(state, binding.target.clone())?;
        if c.binding != *binding {
            return Err(bad());
        }
        c
    } else if selected.generation == 0 {
        match candidate(state, Target::Root {}) {
            Ok(c) => c,
            Err(error) if error.contains("No saved keypair") => return Ok(None),
            Err(error) => return Err(error),
        }
    } else {
        return Ok(None);
    };
    let ctx = Context {
        target: c.view.target,
        identity: c.identity,
        database: c.database,
        generation: selected.generation,
        binding: c.binding,
        epoch,
    };
    current(state, &ctx)?;
    Ok(Some(ctx))
}
pub(crate) fn current(state: &AppState, ctx: &Context) -> Result<(), String> {
    check(state, ctx.epoch)?;
    let selected = store(state)?.current()?;
    if selected.generation != ctx.generation
        || selected.generation != 0 && selected.selected.as_ref() != Some(&ctx.binding)
        || candidate(state, ctx.target.clone())?.binding != ctx.binding
    {
        return Err(bad());
    }
    Ok(())
}
pub(crate) fn allows_legacy(state: &AppState) -> Result<bool, String> {
    if state.db_path == std::path::Path::new(":memory:") {
        return Ok(true);
    }
    // Ordinary legacy calls do not create a new native record. Once protected,
    // even an absent selection slot must be checked against the native witness.
    let witness = state.device_witness(&state.db_path)?;
    if !witness.has_record()? {
        let conn = rusqlite::Connection::open_with_flags(
            &state.db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .map_err(|_| bad())?;
        let tasks:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='device_control_tasks')",[],|r|r.get(0)).map_err(|_|bad())?;
        if !tasks {
            return Ok(true);
        }
        let selection:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM device_control_tasks WHERE scope='normal_profile_selection')",[],|r|r.get(0)).map_err(|_|bad())?;
        if !selection {
            return Ok(true);
        }
    }
    let selected = store(state)?.current()?;
    if selected.generation == 0 {
        return Ok(true);
    }
    if selected
        .selected
        .as_ref()
        .is_some_and(|b| matches!(b.target, Target::Root {}))
    {
        return Ok(capture(state)?.is_some());
    }
    Ok(false)
}
pub async fn select(
    state: &AppState,
    target: Option<Target>,
    expected: u64,
    fingerprint: Option<String>,
) -> Result<Snapshot, String> {
    let _gate = state.normal_profile_gate.write().await;
    let epoch = lease(state)?;
    let selected = store(state)?.current()?;
    if selected.generation != expected {
        return Err(bad());
    }
    let next = target.map(|t| candidate(state, t)).transpose()?;
    if next.as_ref().map(|c| c.view.scope_fingerprint.as_str()) != fingerprint.as_deref() {
        return Err("请确认当前档案的完整范围指纹".into());
    }
    // No new normal request can start while the selection write gate is held.
    state.client.disconnect().await;
    check(state, epoch)?;
    let _commit = state.backup_commit.lock().map_err(|_| bad())?;
    if let Some(c) = &next {
        if candidate(state, c.view.target.clone())?.binding != c.binding {
            return Err(bad());
        }
    }
    {
        let runtime = state.normal_profile_runtime.lock().map_err(|_| bad())?;
        if runtime.suspended || runtime.epoch != epoch {
            return Err(bad());
        }
        store(state)?.replace(expected, next.map(|c| c.binding))?;
    }
    if let Ok(saved) = state.identity() {
        super::groups::invalidate(state, &saved)?;
    }
    super::device_control::invalidate(state)?;
    *state.scheduled_tick.lock().map_err(|_| bad())? = None;
    super::backup::invalidate(&state.backup_runtime)?;
    snapshot(state)
}
