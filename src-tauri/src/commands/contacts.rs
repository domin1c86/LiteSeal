use serde::{Deserialize, Serialize};
use tauri::State;

use crate::AppState;
use liteseal_core::api::{self, RemoteDevice};
use liteseal_core::db::models::ContactModel;
use liteseal_shared::types::PublicKeyInfo;

#[derive(Debug, Serialize, Deserialize)]
pub struct AddContactResult {
    pub success: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RemoveContactResult {
    pub success: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SetContactTrustResult {
    pub success: bool,
}

#[tauri::command]
pub async fn add_contact(
    user_id: String,
    username: String,
    public_key: Vec<u8>,
    ed25519_pk: Option<Vec<u8>>,
    state: State<'_, AppState>,
) -> Result<AddContactResult, String> {
    state
        .client
        .add_contact(user_id, username, public_key, ed25519_pk)?;
    Ok(AddContactResult { success: true })
}

#[tauri::command]
pub async fn get_contacts(state: State<'_, AppState>) -> Result<Vec<ContactModel>, String> {
    state.client.get_contacts()
}

#[tauri::command]
pub async fn remove_contact(
    user_id: String,
    state: State<'_, AppState>,
) -> Result<RemoveContactResult, String> {
    state.client.remove_contact(&user_id)?;
    Ok(RemoveContactResult { success: true })
}

#[tauri::command]
pub async fn set_contact_trust(
    user_id: String,
    trust_state: String,
    state: State<'_, AppState>,
) -> Result<SetContactTrustResult, String> {
    state.client.set_contact_trust(&user_id, &trust_state)?;
    Ok(SetContactTrustResult { success: true })
}

#[tauri::command]
pub async fn get_user_devices(
    server_url: String,
    user_id: String,
) -> Result<Vec<RemoteDevice>, String> {
    api::get_user_devices(server_url, user_id).await
}

#[tauri::command]
pub async fn search_users(server_url: String, query: String) -> Result<Vec<PublicKeyInfo>, String> {
    api::search_users(server_url, query).await
}
