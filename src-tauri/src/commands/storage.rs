use serde::Serialize;
use tauri::State;

use crate::AppState;

#[derive(Debug, Serialize)]
pub struct StorageStatsResult {
    pub message_count: i64,
    pub ciphertext_bytes: i64,
    pub attachment_count: i64,
    pub attachment_bytes: i64,
    pub conversation_count: i64,
    pub total_bytes: i64,
}

#[tauri::command]
pub async fn get_storage_stats(state: State<'_, AppState>) -> Result<StorageStatsResult, String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    let stats = db.get_storage_stats().map_err(|e| e.to_string())?;
    Ok(StorageStatsResult {
        message_count: stats.message_count,
        ciphertext_bytes: stats.ciphertext_bytes,
        attachment_count: stats.attachment_count,
        attachment_bytes: stats.attachment_bytes,
        conversation_count: stats.conversation_count,
        total_bytes: stats.ciphertext_bytes + stats.attachment_bytes,
    })
}

#[tauri::command]
pub async fn clear_expired_messages(state: State<'_, AppState>) -> Result<usize, String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    let now = chrono::Utc::now().timestamp();
    db.clear_expired_messages(now).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn clear_downloaded_attachments(state: State<'_, AppState>) -> Result<usize, String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.clear_unpinned_attachments().map_err(|e| e.to_string())
}
