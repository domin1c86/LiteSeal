use super::groups::{context, current, local_context};
use crate::AppState;
use liteseal_core::groups::{ExtensionCommand, ExtensionView, GroupAttachmentTask};
use std::io::{Read, Write};
pub async fn extensions(
    state: &AppState,
    id: String,
    ids: Vec<String>,
) -> Result<ExtensionView, String> {
    let ctx = local_context(state).await?;
    let result = ctx.client.extension_view(&id, &ids, &ctx.keys)?;
    current(state, &ctx.saved)?;
    Ok(result)
}
pub async fn sync(state: &AppState, id: String) -> Result<bool, String> {
    let ctx = context(state).await?;
    if !ctx.client.extension_supported(&id).await? {
        return Ok(false);
    }
    ctx.client.extension_sync(&id, &ctx.keys).await?;
    current(state, &ctx.saved)?;
    Ok(true)
}
pub async fn submit(state: &AppState, id: String, command: ExtensionCommand) -> Result<(), String> {
    let ctx = context(state).await?;
    ctx.client.extension_submit(&id, command, &ctx.keys).await?;
    current(state, &ctx.saved)
}
pub async fn retry(state: &AppState, id: String, cancel: bool) -> Result<(), String> {
    let ctx = context(state).await?;
    if cancel {
        ctx.client.extension_cancel_task(&id, &ctx.keys).await?;
    } else {
        ctx.client.extension_retry(&id, &ctx.keys).await?;
    }
    current(state, &ctx.saved)
}
pub async fn stage(
    state: &AppState,
    id: String,
    path: String,
) -> Result<GroupAttachmentTask, String> {
    let path = std::path::Path::new(&path);
    let file = std::fs::File::open(path).map_err(|_| "无法读取文件")?;
    if !file.metadata().map_err(|_| "无法读取文件信息")?.is_file() {
        return Err("请选择普通文件".into());
    }
    let mut bytes = vec![];
    file.take(20 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "无法读取文件")?;
    stage_bytes(state, id, bytes, super::attachments::safe_name(path), None).await
}
pub async fn stage_bytes(
    state: &AppState,
    id: String,
    bytes: Vec<u8>,
    name: String,
    duration: Option<u32>,
) -> Result<GroupAttachmentTask, String> {
    let ctx = local_context(state).await?;
    if bytes.len() > 20 * 1024 * 1024
        || duration.is_some_and(|d| {
            !(1..=60000).contains(&d)
                || bytes.len() > 11 * 1024 * 1024
                || super::attachments::media(&bytes) != "audio/webm"
        })
    {
        return Err("群附件格式、大小或时长无效".into());
    }
    let mime = super::attachments::media(&bytes).into();
    let result = ctx.client.media_stage(
        &id,
        &bytes,
        super::attachments::safe_name(std::path::Path::new(&name)),
        mime,
        duration,
        &ctx.keys,
    )?;
    current(state, &ctx.saved)?;
    Ok(result)
}
pub async fn tasks(state: &AppState, id: String) -> Result<Vec<GroupAttachmentTask>, String> {
    let ctx = local_context(state).await?;
    let result = ctx.client.media_tasks(&id, &ctx.keys)?;
    current(state, &ctx.saved)?;
    Ok(result)
}
pub async fn step(
    state: &AppState,
    id: String,
    blob: String,
) -> Result<GroupAttachmentTask, String> {
    let ctx = context(state).await?;
    let result = ctx.client.media_step(&id, &blob, &ctx.keys).await?;
    current(state, &ctx.saved)?;
    Ok(result)
}
pub async fn publish(state: &AppState, id: String, blob: String) -> Result<String, String> {
    let ctx = context(state).await?;
    let result = ctx.client.media_publish(&id, &blob, &ctx.keys).await?;
    current(state, &ctx.saved)?;
    Ok(result)
}
pub async fn cancel(state: &AppState, id: String, blob: String) -> Result<(), String> {
    let ctx = context(state).await?;
    ctx.client.media_cancel(&id, &blob, &ctx.keys).await?;
    current(state, &ctx.saved)
}
pub async fn download(
    state: &AppState,
    id: String,
    object: String,
) -> Result<GroupAttachmentTask, String> {
    let ctx = local_context(state).await?;
    let result = ctx.client.media_download(&id, &object, &ctx.keys)?;
    current(state, &ctx.saved)?;
    Ok(result)
}
pub async fn export(
    state: &AppState,
    id: String,
    blob: String,
    path: String,
) -> Result<(), String> {
    let ctx = local_context(state).await?;
    let bytes = ctx.client.media_plain(&id, &blob, &ctx.keys)?;
    current(state, &ctx.saved)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "不能创建群附件导出文件")?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "群附件导出失败".into())
}
pub async fn clear(state: &AppState, id: Option<String>) -> Result<usize, String> {
    let ctx = local_context(state).await?;
    let count = ctx.client.media_clear(id.as_deref())?;
    current(state, &ctx.saved)?;
    Ok(count)
}
