use tauri::State;

use crate::AppState;
use liteseal_core::client::StorageStatsResult;

#[tauri::command]
pub async fn get_storage_stats(state: State<'_, AppState>) -> Result<StorageStatsResult, String> {
    state.client()?.get_storage_stats()
}

#[tauri::command]
pub async fn clear_expired_messages(state: State<'_, AppState>) -> Result<usize, String> {
    state.client()?.clear_expired_messages()
}

#[tauri::command]
pub async fn clear_downloaded_attachments(state: State<'_, AppState>) -> Result<usize, String> {
    state.client()?.clear_unpinned_attachments()
}
