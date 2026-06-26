use serde::{Deserialize, Serialize};
use tauri::State;
use chrono::Utc;

use crate::AppState;
use crate::db::models::ContactModel;
use liteseal_shared::types::PublicKeyInfo;

#[derive(Debug, Serialize, Deserialize)]
pub struct AddContactResult {
    pub success: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RemoveContactResult {
    pub success: bool,
}

#[tauri::command]
pub async fn add_contact(
    user_id: String,
    username: String,
    public_key: Vec<u8>,
    state: State<'_, AppState>,
) -> Result<AddContactResult, String> {
    let contact = ContactModel {
        user_id,
        username,
        public_key,
        added_at: Utc::now().timestamp(),
    };

    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.insert_contact(&contact).map_err(|e| e.to_string())?;

    Ok(AddContactResult { success: true })
}

#[tauri::command]
pub async fn get_contacts(
    state: State<'_, AppState>,
) -> Result<Vec<ContactModel>, String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.get_contacts().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn remove_contact(
    user_id: String,
    state: State<'_, AppState>,
) -> Result<RemoveContactResult, String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.delete_contact(&user_id).map_err(|e| e.to_string())?;

    Ok(RemoveContactResult { success: true })
}

#[tauri::command]
pub async fn search_users(
    server_url: String,
    query: String,
) -> Result<Vec<PublicKeyInfo>, String> {
    let client = reqwest::Client::new();
    let mut url = url::Url::parse(&format!("{}/users/search", server_url))
        .map_err(|e| format!("Invalid server URL: {}", e))?;
    url.query_pairs_mut().append_pair("q", &query);

    let resp = client
        .get(url.as_str())
        .send()
        .await
        .map_err(|e| format!("Search request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Search failed with status: {}", resp.status()));
    }

    let results: Vec<PublicKeyInfo> = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse search response: {}", e))?;

    Ok(results)
}
