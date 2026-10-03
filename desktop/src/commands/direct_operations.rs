//! Only scoped business intent crosses IPC; original wire and keys stay Rust.
use super::*;
use liteseal_core::trusted_devices::messages::operations::{OperationTaskView, PrepareOperation};
use liteseal_shared::direct_operation::Action;
use zeroize::Zeroizing;

fn scoped(state: &AppState, scope: &str) -> Result<Context, String> {
    let ctx = context(state)?;
    if ctx.key != scope {
        return Err(bad());
    }
    Ok(ctx)
}
pub async fn prepare(
    state: &AppState,
    scope: String,
    id: String,
    target: String,
    created_at: i64,
    action: Action,
    text: Option<String>,
) -> Result<OperationPreparation, String> {
    uuid(&id)?;
    uuid(&target)?;
    let text = text.map(Zeroizing::new);
    let ctx = scoped(state, &scope)?;
    let result = bounded(ctx.actor.prepare_operation(
        PrepareOperation {
            id: &id,
            target: &target,
            created_at,
            action,
            text: text.as_ref().map(|t| t.as_str()),
        },
        &ctx.keys,
    ))
    .await?;
    current(state, &ctx)?;
    Ok(result)
}
pub async fn step(
    state: &AppState,
    scope: String,
    id: String,
    revision: u64,
) -> Result<OperationProgress, String> {
    let ctx = scoped(state, &scope)?;
    if !ctx
        .actor
        .operation_tasks(&ctx.keys)
        .map_err(|e| e.to_string())?
        .iter()
        .any(|t| t.id == id && t.revision == revision)
    {
        return Err(bad());
    }
    let result = bounded(ctx.actor.operation_step(&id, &ctx.keys)).await?;
    current(state, &ctx)?;
    Ok(result)
}
pub fn cancel(
    state: &AppState,
    scope: String,
    id: String,
    revision: u64,
) -> Result<OperationTaskView, String> {
    let ctx = scoped(state, &scope)?;
    let result = ctx
        .actor
        .cancel_operation(&id, revision, &ctx.keys)
        .map_err(|e| e.to_string())?;
    current(state, &ctx)?;
    Ok(result)
}
pub fn forget(state: &AppState, scope: String, id: String, revision: u64) -> Result<(), String> {
    let ctx = scoped(state, &scope)?;
    ctx.actor
        .clear_operation_task(&id, revision, &ctx.keys)
        .map_err(|e| e.to_string())?;
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
    let work = async {
        let mut report = Report {
            notification_scope: Some(ctx.key.clone()),
            ..Default::default()
        };
        // A malformed/incomplete page cannot stop original result resolution.
        match ctx.actor.poll_operations(&ctx.keys).await {
            Ok(poll) => {
                report.changed = poll.received > 0;
                report.operation_poll = Some(poll);
            }
            Err(error) => report.errors.push(error.to_string()),
        }
        match ctx.actor.drive_operations(&ctx.keys).await {
            Ok(operation) => {
                report.changed |= operation.is_some();
                report.operation = operation;
            }
            Err(error) => report.errors.push(error.to_string()),
        }
        Ok::<_, liteseal_core::trusted_devices::messages::coordinator::CoordinatorError>(report)
    };
    let result = bounded(work).await?;
    current(state, &ctx)?;
    Ok(result)
}
