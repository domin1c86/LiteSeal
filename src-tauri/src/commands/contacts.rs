use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::State;

use crate::db::models::ContactModel;
use crate::AppState;
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

pub fn validate_contact_input(
    user_id: &str,
    username: &str,
    public_key: &[u8],
    ed25519_pk: Option<&[u8]>,
) -> Result<(), String> {
    if user_id.trim().is_empty() {
        return Err("User id cannot be empty".to_string());
    }
    if username.trim().is_empty() {
        return Err("Username cannot be empty".to_string());
    }
    if public_key.len() != 32 {
        return Err("Invalid public key length".to_string());
    }
    if let Some(pk) = ed25519_pk {
        if pk.len() != 32 {
            return Err("Invalid signing public key length".to_string());
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn add_contact(
    user_id: String,
    username: String,
    public_key: Vec<u8>,
    ed25519_pk: Option<Vec<u8>>,
    state: State<'_, AppState>,
) -> Result<AddContactResult, String> {
    validate_contact_input(&user_id, &username, &public_key, ed25519_pk.as_deref())?;

    let contact = ContactModel {
        user_id: user_id.trim().to_string(),
        username: username.trim().to_string(),
        fingerprint: fingerprint(ed25519_pk.as_deref().unwrap_or(&public_key)),
        public_key,
        ed25519_pk,
        trust_state: "unverified".to_string(),
        key_changed: false,
        added_at: Utc::now().timestamp(),
    };

    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.insert_contact(&contact).map_err(|e| e.to_string())?;

    Ok(AddContactResult { success: true })
}

#[tauri::command]
pub async fn get_contacts(state: State<'_, AppState>) -> Result<Vec<ContactModel>, String> {
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
pub async fn set_contact_trust(
    user_id: String,
    trust_state: String,
    state: State<'_, AppState>,
) -> Result<SetContactTrustResult, String> {
    match trust_state.as_str() {
        "unverified" | "verified" | "key_changed" => {}
        _ => return Err("Invalid trust state".to_string()),
    }
    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.update_contact_trust(&user_id, &trust_state)
        .map_err(|e| e.to_string())?;

    Ok(SetContactTrustResult { success: true })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RemoteDevice {
    pub id: String,
    pub name: String,
    pub public_key: Vec<u8>,
    pub ed25519_pk: Vec<u8>,
    pub revoked: bool,
}

#[tauri::command]
pub async fn get_user_devices(
    server_url: String,
    user_id: String,
) -> Result<Vec<RemoteDevice>, String> {
    let user_id = user_id.trim().to_string();
    if user_id.is_empty() {
        return Err("User id cannot be empty".to_string());
    }

    let server_url = normalize_server_url(&server_url)?;
    let client = reqwest::Client::new();
    let url = format!("{}/users/{}/devices", server_url, user_id);

    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Device lookup failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Device lookup failed with status: {}", resp.status()));
    }

    resp.json()
        .await
        .map_err(|e| format!("Failed to parse device list: {}", e))
}

#[tauri::command]
pub async fn search_users(server_url: String, query: String) -> Result<Vec<PublicKeyInfo>, String> {
    let query = query.trim().to_string();
    if query.is_empty() {
        return Err("Search query cannot be empty".to_string());
    }

    let client = reqwest::Client::new();
    let server_url = normalize_server_url(&server_url)?;
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

fn normalize_server_url(server_url: &str) -> Result<String, String> {
    let trimmed = server_url.trim().trim_end_matches('/');
    let parsed = url::Url::parse(trimmed).map_err(|e| format!("Invalid server URL: {}", e))?;
    match parsed.scheme() {
        "http" | "https" => Ok(trimmed.to_string()),
        _ => Err("Server URL must start with http:// or https://".to_string()),
    }
}

fn fingerprint(key: &[u8]) -> String {
    let digest = Sha256::digest(key);
    hex::encode(&digest[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contact_input_requires_ids_and_expected_key_lengths() {
        assert!(validate_contact_input("user-1", "alice", &[1; 32], Some(&[2; 32])).is_ok());
        assert!(validate_contact_input(" ", "alice", &[1; 32], None).is_err());
        assert!(validate_contact_input("user-1", " ", &[1; 32], None).is_err());
        assert!(validate_contact_input("user-1", "alice", &[1; 31], None).is_err());
        assert!(validate_contact_input("user-1", "alice", &[1; 32], Some(&[2; 31])).is_err());
    }

    #[test]
    fn fingerprint_is_stable_short_hex() {
        assert_eq!(fingerprint(&[7; 32]).len(), 32);
        assert_eq!(fingerprint(&[7; 32]), fingerprint(&[7; 32]));
    }
}
