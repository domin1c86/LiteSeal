//! Selected-identity business IPC. Paths come only from the main process;
//! authenticated media bytes and file keys never cross the stdio bridge.
use super::*;
use liteseal_core::trusted_devices::messages::{
    coordinator::MediaProgress,
    media::{Info, Stage, View},
};
use std::{
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;
fn scoped(state: &AppState, scope: &str) -> Result<Context, String> {
    let ctx = context(state)?;
    if ctx.key != scope {
        return Err(bad());
    }
    Ok(ctx)
}
pub fn tasks(state: &AppState, scope: String) -> Result<Vec<View>, String> {
    let ctx = scoped(state, &scope)?;
    let result = ctx
        .actor
        .media_tasks(&ctx.keys)
        .map_err(|e| e.to_string())?;
    current(state, &ctx)?;
    Ok(result)
}
pub fn transfer(
    state: &AppState,
    scope: String,
    id: String,
    revision: u64,
    paused: bool,
) -> Result<View, String> {
    uuid(&id)?;
    let ctx = scoped(state, &scope)?;
    let result = ctx
        .actor
        .set_media_transfer(&id, revision, paused, &ctx.keys)
        .map_err(|e| e.to_string())?;
    current(state, &ctx)?;
    Ok(result)
}
pub fn info(state: &AppState, scope: String, id: String) -> Result<Info, String> {
    uuid(&id)?;
    let ctx = scoped(state, &scope)?;
    let result = ctx
        .actor
        .media_info(&id, &ctx.keys)
        .map_err(|e| e.to_string())?;
    current(state, &ctx)?;
    Ok(result)
}
pub struct StageFile {
    pub scope: String,
    pub account: String,
    pub id: String,
    pub path: String,
    pub kind: Kind,
    pub duration_ms: Option<u32>,
}
pub fn stage(state: &AppState, request: StageFile) -> Result<View, String> {
    let StageFile {
        scope,
        account,
        id,
        path,
        kind,
        duration_ms,
    } = request;
    uuid(&account)?;
    uuid(&id)?;
    let ctx = scoped(state, &scope)?;
    let path = Path::new(&path);
    if !path.is_absolute() {
        return Err("所选文件路径无效".into());
    }
    let limit = match kind {
        Kind::Attachment => 20 * 1024 * 1024,
        Kind::Voice => 11 * 1024 * 1024,
        Kind::Text => return Err("文件类型无效".into()),
    };
    let file = std::fs::File::open(path).map_err(|_| "无法读取所选文件")?;
    let metadata = file.metadata().map_err(|_| "无法读取所选文件")?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err("所选文件超过限制或不是普通文件".into());
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "所选文件读取失败")?;
    if bytes.len() as u64 > limit {
        return Err("读取期间文件超过大小限制".into());
    }
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("文件名不可用")?;
    current(state, &ctx)?;
    let result = ctx
        .actor
        .stage_media(
            Stage {
                id: &id,
                peer: &account,
                name,
                bytes: &bytes,
                kind,
                duration_ms,
            },
            &ctx.keys,
        )
        .map_err(|e| e.to_string())?;
    current(state, &ctx)?;
    Ok(result)
}
pub async fn step(state: &AppState, scope: String, id: String) -> Result<MediaProgress, String> {
    uuid(&id)?;
    let ctx = scoped(state, &scope)?;
    let result = bounded(ctx.actor.media_step(&id, &ctx.keys)).await?;
    current(state, &ctx)?;
    Ok(result)
}
pub async fn prepare(state: &AppState, scope: String, id: String) -> Result<Preparation, String> {
    uuid(&id)?;
    let ctx = scoped(state, &scope)?;
    let result = bounded(ctx.actor.prepare_media(&id, &ctx.keys)).await?;
    current(state, &ctx)?;
    Ok(result)
}
pub fn begin(state: &AppState, scope: String, id: String) -> Result<View, String> {
    uuid(&id)?;
    let ctx = scoped(state, &scope)?;
    let result = ctx
        .actor
        .start_media_download(&id, &ctx.keys)
        .map_err(|e| e.to_string())?;
    current(state, &ctx)?;
    Ok(result)
}
pub fn cancel(state: &AppState, scope: String, id: String) -> Result<View, String> {
    uuid(&id)?;
    let ctx = scoped(state, &scope)?;
    let result = ctx
        .actor
        .cancel_media(&id, &ctx.keys)
        .map_err(|e| e.to_string())?;
    current(state, &ctx)?;
    Ok(result)
}
pub fn clear(state: &AppState, scope: String, id: String) -> Result<u64, String> {
    uuid(&id)?;
    let ctx = scoped(state, &scope)?;
    let result = ctx
        .actor
        .clear_media(&id, &ctx.keys)
        .map_err(|e| e.to_string())?;
    current(state, &ctx)?;
    Ok(result)
}
pub fn storage(
    state: &AppState,
    scope: String,
) -> Result<liteseal_core::trusted_devices::messages::media::StorageStats, String> {
    let ctx = scoped(state, &scope)?;
    let result = ctx
        .actor
        .media_storage_stats(&ctx.keys)
        .map_err(|e| e.to_string())?;
    current(state, &ctx)?;
    Ok(result)
}
pub fn clear_cache(
    state: &AppState,
    scope: String,
    account: Option<String>,
) -> Result<liteseal_core::trusted_devices::messages::media::ClearResult, String> {
    if let Some(account) = &account {
        uuid(account)?;
    }
    let ctx = scoped(state, &scope)?;
    let result = ctx
        .actor
        .clear_media_cache(account.as_deref(), &ctx.keys)
        .map_err(|e| e.to_string())?;
    current(state, &ctx)?;
    Ok(result)
}
#[derive(Serialize)]
pub struct Written {
    pub info: Info,
    pub digest: String,
}
pub fn write(
    state: &AppState,
    scope: String,
    id: String,
    path: String,
    pending: bool,
) -> Result<Written, String> {
    uuid(&id)?;
    let ctx = scoped(state, &scope)?;
    let path = Path::new(&path);
    if !path.is_absolute() {
        return Err("附件导出路径无效".into());
    }
    let info = if pending {
        let row = ctx
            .actor
            .media_tasks(&ctx.keys)
            .map_err(|e| e.to_string())?
            .into_iter()
            .find(|t| t.id == id)
            .ok_or("原暂存媒体不可用")?;
        Info {
            id: row.id,
            peer: row.peer,
            kind: row.kind,
            name: row.name,
            mime: row.mime,
            size: row.size,
            duration_ms: row.duration_ms,
            cache: Some(row.phase),
        }
    } else {
        ctx.actor
            .media_info(&id, &ctx.keys)
            .map_err(|e| e.to_string())?
    };
    let plain = if pending {
        ctx.actor.media_pending_plain(&id, &ctx.keys)
    } else {
        ctx.actor.media_plain(&id, &ctx.keys)
    }
    .map_err(|e| e.to_string())?;
    let digest = hex::encode(Sha256::digest(&*plain));
    current(state, &ctx)?;
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|_| "附件目标已存在或不可写")?;
        if let Err(error) = file.write_all(&plain).and_then(|_| file.sync_all()) {
            drop(file);
            let _ = std::fs::remove_file(path);
            let _ = error;
            return Err("附件写入或同步失败".into());
        }
        drop(file);
        let visible = if pending {
            ctx.actor.media_pending_plain(&id, &ctx.keys).map(|_| ())
        } else {
            ctx.actor.media_info(&id, &ctx.keys).map(|_| ())
        };
        if current(state, &ctx).is_err() || visible.is_err() {
            let _ = std::fs::remove_file(path);
            return Err(bad());
        }
        Ok(Written { info, digest })
    })();
    result
}
