use serde::{Deserialize, Serialize};
use tauri::State;

use crate::AppState;

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterResult {
    pub user_id: String,
    pub token: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub device_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectResult {
    pub connected: bool,
}

#[tauri::command]
pub async fn register(
    username: String,
    password: String,
    server_url: String,
    public_key: Vec<u8>,
    ed25519_pk: Vec<u8>,
) -> Result<RegisterResult, String> {
    let username = username.trim().to_string();
    if username.is_empty() {
        return Err("Username cannot be empty".to_string());
    }
    validate_public_key("Public key", &public_key)?;
    validate_public_key("Signing public key", &ed25519_pk)?;
    let server_url = normalize_server_url(&server_url)?;

    let client = reqwest::Client::new();
    let url = format!("{}/auth/register", server_url);

    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "username": username,
            "password": password,
            "device_name": "Windows desktop",
            "public_key": public_key,
            "ed25519_pk": ed25519_pk,
        }))
        .send()
        .await
        .map_err(|e| format!("Registration request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!(
            "Registration failed with status: {}",
            resp.status()
        ));
    }

    let result: RegisterResult = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse registration response: {}", e))?;

    Ok(result)
}

#[tauri::command]
pub async fn login(
    username: String,
    password: String,
    server_url: String,
    public_key: Vec<u8>,
    ed25519_pk: Vec<u8>,
) -> Result<RegisterResult, String> {
    let username = username.trim().to_string();
    if username.is_empty() {
        return Err("Username cannot be empty".to_string());
    }
    validate_public_key("Public key", &public_key)?;
    validate_public_key("Signing public key", &ed25519_pk)?;
    let server_url = normalize_server_url(&server_url)?;

    let client = reqwest::Client::new();
    let url = format!("{}/auth/login", server_url);
    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "username": username,
            "password": password,
            "device_name": "Windows desktop",
            "device_public_key": public_key,
            "ed25519_pk": ed25519_pk,
        }))
        .send()
        .await
        .map_err(|e| format!("Login request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Login failed with status: {}", resp.status()));
    }

    resp.json()
        .await
        .map_err(|e| format!("Failed to parse login response: {}", e))
}

fn validate_public_key(label: &str, key: &[u8]) -> Result<(), String> {
    if key.len() != 32 {
        return Err(format!("{} must be 32 bytes", label));
    }
    Ok(())
}

fn normalize_server_url(server_url: &str) -> Result<String, String> {
    let trimmed = server_url.trim().trim_end_matches('/');
    let parsed = url::Url::parse(trimmed).map_err(|e| format!("Invalid server URL: {}", e))?;
    match parsed.scheme() {
        "http" | "https" => Ok(trimmed.to_string()),
        _ => Err("Server URL must start with http:// or https://".to_string()),
    }
}

#[tauri::command]
pub async fn connect_relay(
    server_url: String,
    user_id: String,
    token: String,
    device_id: Option<String>,
    state: State<'_, AppState>,
) -> Result<ConnectResult, String> {
    let server_url = normalize_server_url(&server_url)?;
    let ws_url = server_url
        .replace("http://", "ws://")
        .replace("https://", "wss://");
    let ws_url = format!("{}/ws", ws_url);

    let (client, rx) = crate::network::websocket::WebSocketClient::connect(
        &ws_url,
        user_id.clone(),
        token,
        device_id.unwrap_or_else(|| "device-1".to_string()),
    )
    .await?;

    let mut ws_guard = state.ws_client.lock().await;
    *ws_guard = Some(client);

    let mut recv_guard = state.msg_receiver.lock().await;
    *recv_guard = Some(rx);

    Ok(ConnectResult { connected: true })
}

#[tauri::command]
pub async fn disconnect(state: State<'_, AppState>) -> Result<(), String> {
    let mut ws_guard = state.ws_client.lock().await;
    if let Some(client) = ws_guard.as_mut() {
        client.disconnect().await;
    }
    *ws_guard = None;

    let mut recv_guard = state.msg_receiver.lock().await;
    *recv_guard = None;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_inputs_require_valid_url_and_key_lengths() {
        assert_eq!(
            normalize_server_url(" http://localhost:3000/ ").unwrap(),
            "http://localhost:3000"
        );
        assert!(normalize_server_url("ftp://localhost:3000").is_err());
        assert!(validate_public_key("Public key", &[1; 32]).is_ok());
        assert!(validate_public_key("Public key", &[1; 31]).is_err());
    }
}
