use serde::{Deserialize, Serialize};
use tauri::State;

use crate::AppState;

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterResult {
    pub user_id: String,
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectResult {
    pub connected: bool,
}

#[tauri::command]
pub async fn register(
    username: String,
    server_url: String,
    public_key: Vec<u8>,
    ed25519_pk: Vec<u8>,
) -> Result<RegisterResult, String> {
    if username.is_empty() {
        return Err("Username cannot be empty".to_string());
    }

    let client = reqwest::Client::new();
    let url = format!("{}/register", server_url);

    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "username": username,
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
pub async fn connect_relay(
    server_url: String,
    user_id: String,
    token: String,
    state: State<'_, AppState>,
) -> Result<ConnectResult, String> {
    let ws_url = server_url
        .replace("http://", "ws://")
        .replace("https://", "wss://");
    let ws_url = format!("{}/ws", ws_url);

    let (client, rx) =
        crate::network::websocket::WebSocketClient::connect(&ws_url, user_id.clone(), token)
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
