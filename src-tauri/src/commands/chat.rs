use serde::{Deserialize, Serialize};
use tauri::State;
use uuid::Uuid;

use crate::AppState;
use crate::network::websocket::ServerMessage;

#[derive(Debug, Serialize, Deserialize)]
pub struct SendMessageResult {
    pub message_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IncomingMessage {
    pub message_id: String,
    pub from: String,
    pub conversation_id: String,
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
    pub sender_device_id: String,
    pub sender_seq: i64,
    pub timestamp: i64,
}

#[tauri::command]
pub async fn send_message(
    to: String,
    conversation_id: String,
    ciphertext: Vec<u8>,
    signature: Vec<u8>,
    sender_device_id: String,
    sender_seq: i64,
    state: State<'_, AppState>,
) -> Result<SendMessageResult, String> {
    let ws_guard = state.ws_client.lock().await;
    let client = ws_guard
        .as_ref()
        .ok_or("Not connected to relay server")?;

    let message_id = Uuid::new_v4().to_string();

    client
        .send_message(
            to,
            conversation_id,
            ciphertext,
            signature,
            sender_device_id,
            sender_seq,
        )
        .await?;

    Ok(SendMessageResult { message_id })
}

#[tauri::command]
pub async fn poll_messages(
    state: State<'_, AppState>,
) -> Result<Vec<IncomingMessage>, String> {
    let mut recv_guard = state.msg_receiver.lock().await;
    let rx = recv_guard
        .as_mut()
        .ok_or("Not connected to relay server")?;

    let mut messages = Vec::new();

    while let Ok(msg) = rx.try_recv() {
        match msg {
            ServerMessage::Message {
                message_id,
                from,
                conversation_id,
                ciphertext,
                signature,
                sender_device_id,
                sender_seq,
                timestamp,
            } => {
                if let Some(ws) = state.ws_client.lock().await.as_ref() {
                    let _ = ws.send_ack(message_id.clone()).await;
                }
                messages.push(IncomingMessage {
                    message_id,
                    from,
                    conversation_id,
                    ciphertext,
                    signature,
                    sender_device_id,
                    sender_seq,
                    timestamp,
                });
            }
            _ => {}
        }
    }

    Ok(messages)
}

#[tauri::command]
pub async fn get_local_messages(
    conversation_id: String,
    limit: i64,
    offset: i64,
    state: State<'_, AppState>,
) -> Result<Vec<crate::db::models::MessageModel>, String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.get_messages_by_conversation(&conversation_id, limit, offset)
        .map_err(|e| e.to_string())
}
