use super::*;
use liteseal_core::trusted_devices::messages::history_transfer::{
    HistoryRecord, PrepareHistory, View,
};
use serde::Serialize;
use std::io::{Read, Write};

#[derive(Serialize)]
pub struct Target {
    pub device: String,
    pub encryption_fingerprint: String,
    pub signing_fingerprint: String,
}
#[derive(Serialize)]
pub struct Snapshot {
    pub targets: Vec<Target>,
    pub transfers: Vec<View>,
    pub relay_jobs: Vec<liteseal_core::trusted_devices::messages::history_jobs::View>,
    pub receiving: Vec<liteseal_core::trusted_devices::messages::ReceiveView>,
}
#[derive(Serialize)]
pub struct Page {
    pub messages: Vec<HistoryRecord>,
    pub next_cursor: Option<String>,
}
fn scoped(state: &AppState, scope: &str) -> Result<Context, String> {
    let ctx = context(state)?;
    if ctx.key != scope {
        return Err(bad());
    }
    Ok(ctx)
}
pub fn snapshot(state: &AppState, scope: String) -> Result<Snapshot, String> {
    let ctx = scoped(state, &scope)?;
    let targets = ctx
        .actor
        .history_targets(&ctx.keys)
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|m| Target {
            device: m.device.device_id,
            encryption_fingerprint: hex::encode(Sha256::digest(m.device.encryption_key)),
            signing_fingerprint: hex::encode(Sha256::digest(m.device.signing_key)),
        })
        .collect();
    let transfers = ctx
        .actor
        .history_transfers(&ctx.keys)
        .map_err(|e| e.to_string())?;
    let relay_jobs = ctx
        .actor
        .history_relay_jobs(&ctx.keys)
        .map_err(|e| e.to_string())?;
    let receiving = ctx
        .actor
        .history_receives(&ctx.keys)
        .map_err(|e| e.to_string())?;
    current(state, &ctx)?;
    Ok(Snapshot {
        targets,
        transfers,
        relay_jobs,
        receiving,
    })
}
pub fn pause(
    state: &AppState,
    scope: String,
    id: String,
    revision: u64,
    receive: bool,
    paused: bool,
    abandon: bool,
) -> Result<(), String> {
    uuid(&id)?;
    let ctx = scoped(state, &scope)?;
    if receive {
        ctx.actor
            .pause_history_receive(&id, revision, paused, abandon, &ctx.keys)
            .map_err(|e| e.to_string())?;
    } else {
        if abandon {
            return Err(bad());
        }
        ctx.actor
            .pause_history_relay(&id, revision, paused, &ctx.keys)
            .map_err(|e| e.to_string())?;
    }
    current(state, &ctx)
}
pub async fn process(state: &AppState, receive: bool) -> Result<Report, String> {
    let Some(selected) = normal::capture(state)? else {
        return Ok(Report::default());
    };
    if selected.protocol != "v3" || selected.identity.token.is_empty() {
        return Ok(Report::default());
    }
    let ctx = context(state)?;
    let work = async {
        if receive {
            ctx.actor
                .drive_history_receive(&ctx.keys)
                .await
                .map(|r| r.is_some())
        } else {
            ctx.actor
                .drive_history_send(&ctx.keys)
                .await
                .map(|r| r.is_some())
        }
    };
    let result = bounded(work).await;
    current(state, &ctx)?;
    match result {
        Ok(changed) => Ok(Report {
            changed,
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
pub async fn relay_step(
    state: &AppState,
    scope: String,
    id: String,
    revision: u64,
    cancel: bool,
) -> Result<liteseal_shared::history_transfer::RelayStatus, String> {
    uuid(&id)?;
    let ctx = scoped(state, &scope)?;
    let result = if cancel {
        bounded(ctx.actor.cancel_history_relay(&id, revision, &ctx.keys)).await?
    } else {
        bounded(ctx.actor.history_relay_step(&id, revision, &ctx.keys)).await?
    };
    current(state, &ctx)?;
    Ok(result)
}
pub async fn receive_relay(
    state: &AppState,
    scope: String,
) -> Result<liteseal_core::trusted_devices::messages::coordinator::RelayReceiveProgress, String> {
    let ctx = scoped(state, &scope)?;
    let result = bounded(ctx.actor.receive_history_relay(&ctx.keys)).await?;
    current(state, &ctx)?;
    Ok(result)
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preparation {
    pub scope: String,
    pub id: String,
    pub account: String,
    pub target: String,
    pub selection: Vec<String>,
    #[serde(rename = "createdAt")]
    pub created_at: i64,
    #[serde(rename = "includeMedia")]
    pub include_media: bool,
}
pub async fn prepare(state: &AppState, request: Preparation) -> Result<View, String> {
    uuid(&request.id)?;
    uuid(&request.account)?;
    uuid(&request.target)?;
    let ctx = scoped(state, &request.scope)?;
    let view = bounded(ctx.actor.prepare_history_transfer(
        PrepareHistory {
            id: &request.id,
            peer: &request.account,
            target: &request.target,
            selection: &request.selection,
            created_at: request.created_at,
            include_media: request.include_media,
        },
        &ctx.keys,
    ))
    .await?;
    current(state, &ctx)?;
    Ok(view)
}
pub fn cancel(state: &AppState, scope: String, id: String, revision: u64) -> Result<View, String> {
    let ctx = scoped(state, &scope)?;
    let result = ctx
        .actor
        .cancel_history_transfer(&id, revision, &ctx.keys)
        .map_err(|e| e.to_string())?;
    current(state, &ctx)?;
    Ok(result)
}
pub fn page_records(mut rows: Vec<HistoryRecord>, before: Option<String>) -> Result<Page, String> {
    if let Some(before) = before {
        let index = rows
            .iter()
            .position(|r| r.id == before)
            .ok_or("迁移历史分页边界已变化，请刷新")?;
        rows.drain(..=index);
    }
    let next_cursor = if rows.len() > 50 {
        Some(rows[49].id.clone())
    } else {
        None
    };
    rows.truncate(50);
    Ok(Page {
        messages: rows,
        next_cursor,
    })
}
pub fn history(
    state: &AppState,
    scope: String,
    account: Option<String>,
    before: Option<String>,
) -> Result<Page, String> {
    let ctx = scoped(state, &scope)?;
    if let Some(account) = &account {
        uuid(account)?
    }
    let rows = ctx
        .actor
        .transferred_history(account.as_deref(), &ctx.keys)
        .map_err(|e| e.to_string())?;
    current(state, &ctx)?;
    page_records(rows, before)
}
pub fn hide(state: &AppState, scope: String, id: String) -> Result<(), String> {
    let ctx = scoped(state, &scope)?;
    ctx.actor
        .hide_transferred(&id, &ctx.keys)
        .map_err(|e| e.to_string())?;
    current(state, &ctx)
}
fn destination(path: &str) -> Result<&std::path::Path, String> {
    let path = std::path::Path::new(path);
    if !path.is_absolute() || path.file_name().is_none() {
        return Err("历史导出路径无效".into());
    }
    Ok(path)
}
fn write_new(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "目标已存在或不可写，请选择新文件")?;
    if file.write_all(bytes).and_then(|_| file.sync_all()).is_err() {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err("写入或同步失败，未保留不完整文件".into());
    }
    Ok(())
}
pub async fn write_transfer(
    state: &AppState,
    scope: String,
    id: String,
    revision: u64,
    path: String,
) -> Result<String, String> {
    let path = destination(&path)?;
    let ctx = scoped(state, &scope)?;
    let wire = bounded(ctx.actor.history_export_wire(&id, revision, &ctx.keys)).await?;
    let _commit = state.backup_commit.lock().map_err(|_| bad())?;
    current(state, &ctx)?;
    write_new(path, &wire)?;
    if current(state, &ctx).is_err() {
        let _ = std::fs::remove_file(path);
        return Err(bad());
    }
    Ok("已保存仅目标设备可解密的授权历史文件".into())
}
pub async fn read_transfer(state: &AppState, scope: String, path: String) -> Result<View, String> {
    let ctx = scoped(state, &scope)?;
    let path = std::path::Path::new(&path);
    if !path.is_absolute() {
        return Err("历史输入路径无效".into());
    }
    let info = std::fs::symlink_metadata(path).map_err(|_| "历史文件不可读")?;
    if !info.is_file()
        || info.file_type().is_symlink()
        || info.len() > liteseal_shared::history_transfer::MAX_WIRE as u64
    {
        return Err("请选择大小受限的普通授权历史文件".into());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|_| "历史文件不可读")?
        .take(liteseal_shared::history_transfer::MAX_WIRE as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "历史文件读取失败")?;
    let result = bounded(ctx.actor.import_history_transfer(&bytes, &ctx.keys)).await?;
    current(state, &ctx)?;
    Ok(result)
}
pub fn write_media(
    state: &AppState,
    scope: String,
    id: String,
    path: String,
) -> Result<String, String> {
    let ctx = scoped(state, &scope)?;
    let path = destination(&path)?;
    let _commit = state.backup_commit.lock().map_err(|_| bad())?;
    current(state, &ctx)?;
    let bytes = ctx
        .actor
        .transferred_media(&id, &ctx.keys)
        .map_err(|e| e.to_string())?;
    write_new(path, &bytes)?;
    if current(state, &ctx).is_err() || ctx.actor.transferred_media(&id, &ctx.keys).is_err() {
        let _ = std::fs::remove_file(path);
        return Err(bad());
    }
    Ok("已保存认证后的迁移附件".into())
}
