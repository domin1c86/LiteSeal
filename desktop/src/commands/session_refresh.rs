//! Business-only refresh commands with one stable cache per identity target.
pub use super::normal_profile::Target;
use crate::AppState;
use liteseal_core::trusted_devices::{
    activation::{jobs::Owner, refresh::jobs as r},
    profiles::active,
};
use liteseal_shared::{
    crypto::KeyPair,
    trusted_device::{canonical_origin, Anchor, DeviceIdentity},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc};
use zeroize::Zeroizing;
#[derive(Default)]
pub(crate) struct Runtime {
    cache: HashMap<String, Cached>,
    epoch: u64,
    suspended: bool,
}
struct Cached {
    binding: String,
    actor: Arc<r::Coordinator>,
}
struct Context {
    target: Target,
    key: String,
    binding: String,
    epoch: u64,
    keys: KeyPair,
    actor: Arc<r::Coordinator>,
}
#[derive(Serialize)]
pub struct Snapshot {
    pub target: Target,
    pub current: Option<r::CurrentView>,
    pub tasks: Vec<r::View>,
}
fn bad() -> String {
    "续期范围已失效或暂停，请重新查询原任务".into()
}
fn key(target: &Target) -> Result<String, String> {
    serde_json::to_string(target).map_err(|_| bad())
}
fn scope(
    state: &AppState,
    target: &Target,
) -> Result<(String, std::path::PathBuf, Owner, KeyPair), String> {
    match target {
        Target::Root {} => {
            let saved = state.saved_identity()?;
            let base = Zeroizing::new(serde_json::to_vec(&saved).map_err(|_| bad())?);
            let keys = liteseal_core::backup::identity_keys(&saved)?;
            let anchor = Anchor {
                origin: canonical_origin(&saved.server_url).map_err(|_| bad())?,
                account: saved.user_id,
                root: DeviceIdentity::from_keys(saved.device_id.clone(), &keys),
            };
            Ok((
                hex::encode(Sha256::digest(base.as_slice())),
                state.db_path.clone(),
                Owner::new(anchor, &saved.device_id, &keys)?,
                keys,
            ))
        }
        Target::Join { profile_id } => {
            let store = active::Store::open_with_protection(
                state.device_join_directory()?,
                profile_id,
                state.device_protection.clone(),
            )?;
            let profile = state.device_join_store()?.load(profile_id)?;
            let keys = profile.keys()?;
            let owner = store.job_owner()?;
            let path = store.database()?;
            let normal = active::Store::open_with_protection(
                state.device_join_directory()?,
                profile_id,
                state.device_protection.clone(),
            )?
            .load()?
            .ok_or("请先保存这个加入档案的正式会话")?;
            let binding = Zeroizing::new(
                serde_json::to_vec(&(
                    profile.view(),
                    profile.task_id(),
                    &owner,
                    normal.view().revision,
                ))
                .map_err(|_| bad())?,
            );
            Ok((
                hex::encode(Sha256::digest(binding.as_slice())),
                path,
                owner,
                keys,
            ))
        }
    }
}
fn context(state: &AppState, target: Target) -> Result<Context, String> {
    let (binding, path, owner, keys) = scope(state, &target)?;
    let key = key(&target)?;
    let mut runtime = state.session_refresh_runtime.lock().map_err(|_| bad())?;
    if runtime.suspended {
        return Err(bad());
    }
    if runtime.cache.get(&key).is_none_or(|c| c.binding != binding) {
        if let Some(c) = runtime.cache.remove(&key) {
            c.actor.invalidate()?;
        }
        if runtime.cache.len() >= 129 {
            return Err("续期档案缓存达到上限".into());
        }
        let actor = Arc::new(r::Coordinator::open_with_protection(
            &path,
            owner,
            &keys,
            state.device_protection.clone(),
        )?);
        runtime.cache.insert(
            key.clone(),
            Cached {
                binding: binding.clone(),
                actor,
            },
        );
    }
    if scope(state, &target)?.0 != binding {
        return Err(bad());
    }
    Ok(Context {
        target,
        key: key.clone(),
        binding,
        epoch: runtime.epoch,
        keys,
        actor: runtime.cache.get(&key).ok_or_else(bad)?.actor.clone(),
    })
}
fn current(state: &AppState, ctx: &Context) -> Result<(), String> {
    let runtime = state.session_refresh_runtime.lock().map_err(|_| bad())?;
    if runtime.suspended
        || runtime.epoch != ctx.epoch
        || runtime
            .cache
            .get(&ctx.key)
            .is_none_or(|c| c.binding != ctx.binding)
        || scope(state, &ctx.target)?.0 != ctx.binding
    {
        return Err(bad());
    }
    Ok(())
}
pub(crate) fn invalidate(state: &AppState, suspend: bool) -> Result<(), String> {
    let mut runtime = state.session_refresh_runtime.lock().map_err(|_| bad())?;
    runtime.epoch = runtime.epoch.checked_add(1).ok_or_else(bad)?;
    if suspend {
        runtime.suspended = true;
    }
    for (_, cache) in runtime.cache.drain() {
        cache.actor.invalidate()?;
    }
    Ok(())
}
pub(crate) fn resume(state: &AppState) -> Result<(), String> {
    let mut runtime = state.session_refresh_runtime.lock().map_err(|_| bad())?;
    runtime.epoch = runtime.epoch.checked_add(1).ok_or_else(bad)?;
    runtime.suspended = false;
    Ok(())
}
pub fn snapshot(state: &AppState, target: Target) -> Result<Snapshot, String> {
    let ctx = context(state, target)?;
    let result = Snapshot {
        target: ctx.target.clone(),
        current: ctx.actor.current_view(&ctx.keys)?,
        tasks: ctx.actor.views(&ctx.keys)?,
    };
    current(state, &ctx)?;
    Ok(result)
}
pub fn prepare(state: &AppState, target: Target) -> Result<r::View, String> {
    let ctx = context(state, target)?;
    current(state, &ctx)?;
    let result = ctx.actor.prepare(&ctx.keys)?;
    current(state, &ctx)?;
    Ok(result)
}
pub async fn step(state: &AppState, target: Target, id: String) -> Result<r::Progress, String> {
    let ctx = context(state, target)?;
    let result = ctx.actor.step(&id, &ctx.keys).await?;
    current(state, &ctx)?;
    Ok(result)
}
pub fn cancel(
    state: &AppState,
    target: Target,
    id: String,
    confirmed_family_exit: bool,
) -> Result<r::View, String> {
    let ctx = context(state, target)?;
    let result = ctx
        .actor
        .request_cancel_confirmed(&id, &ctx.keys, confirmed_family_exit)?;
    current(state, &ctx)?;
    Ok(result)
}
pub fn forget(state: &AppState, target: Target, id: String) -> Result<(), String> {
    let ctx = context(state, target)?;
    ctx.actor.forget_ended(&id, &ctx.keys)?;
    current(state, &ctx)
}
// Only the selected normal identity is driven by the scheduler. Other saved
// profiles require explicit manual commands and gain no background traffic.
fn next_task(tasks: &[r::View]) -> Option<&r::View> {
    // An explicitly requested family exit takes precedence even after a
    // successful refresh advanced the current generation. Otherwise a tick
    // could keep renewing the very family the user has asked to close.
    tasks
        .iter()
        .find(|t| t.cancel_requested && !matches!(t.stage, r::Stage::Cancelled | r::Stage::Ended))
        .or_else(|| {
            tasks.iter().find(|t| {
                t.current
                    && !matches!(
                        t.stage,
                        r::Stage::Complete | r::Stage::Cancelled | r::Stage::Ended
                    )
            })
        })
}
pub async fn process(state: &AppState) -> Result<bool, String> {
    let Some(selected) = super::normal_profile::capture(state)? else {
        return Ok(false);
    };
    if selected.identity.token.is_empty() {
        return Ok(false);
    }
    if scope(state, &selected.target)?.1 != selected.database {
        return Err(bad());
    }
    if matches!(selected.target, Target::Root {})
        && super::root_refresh::store(state, &state.saved_identity()?)?.is_none()
    {
        return Ok(false);
    }
    let ctx = context(state, selected.target.clone())?;
    let Some(view) = ctx.actor.current_view(&ctx.keys)? else {
        return Ok(false);
    };
    if !view.has_credentials || !view.eligible {
        return Ok(false);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| bad())?
        .as_millis() as i64;
    let tasks = ctx.actor.views(&ctx.keys)?;
    let pending = next_task(&tasks);
    let id = if let Some(task) = pending {
        task.id.clone()
    } else {
        if view.refresh_expires_at <= now || view.access_expires_at > now + 120_000 {
            return Ok(false);
        }
        ctx.actor.prepare(&ctx.keys)?.id
    };
    let result = ctx.actor.step(&id, &ctx.keys).await?;
    super::normal_profile::current(state, &selected)?;
    current(state, &ctx)?;
    Ok(matches!(
        result.condition,
        r::Condition::Complete | r::Condition::Ended
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn task(id: &str, stage: r::Stage, current: bool, cancel_requested: bool) -> r::View {
        r::View {
            id: id.into(),
            revision: 1,
            stage,
            current,
            cancel_requested,
        }
    }
    #[test]
    fn confirmed_family_exit_precedes_new_current_refresh() {
        let tasks = [
            task("new", r::Stage::Prepared, true, false),
            task("old", r::Stage::Complete, false, true),
        ];
        assert_eq!(next_task(&tasks).unwrap().id, "old");
    }
    #[test]
    fn superseded_and_confirmed_terminal_tasks_do_not_restart() {
        let tasks = [
            task("old", r::Stage::Started, false, false),
            task("cancelled", r::Stage::Cancelled, true, true),
            task("ended", r::Stage::Ended, false, true),
            task("complete", r::Stage::Complete, false, false),
        ];
        assert!(next_task(&tasks).is_none());
    }
    #[test]
    fn current_conflict_keeps_original_number() {
        let tasks = [task("original", r::Stage::Conflict, true, false)];
        assert_eq!(next_task(&tasks).unwrap().id, "original");
    }
}
