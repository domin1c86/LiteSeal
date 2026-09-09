use crate::AppState;
use liteseal_core::client::StorageStatsResult;

pub async fn get_storage_stats(state: &AppState) -> Result<StorageStatsResult, String> {
    state.client.get_storage_stats()
}

pub async fn clear_expired_messages(state: &AppState) -> Result<usize, String> {
    state.client.clear_expired_messages()
}

pub async fn clear_downloaded_attachments(state: &AppState) -> Result<usize, String> {
    state.client.clear_unpinned_attachments()
}
