use serde::{Deserialize, Serialize};
use tauri::State;
use uuid::Uuid;

use crate::db::models::MessageModel;
use crate::AppState;
use liteseal_shared::protocol::ServerMessage;

#[derive(Debug, Serialize, Deserialize)]
pub struct SendMessageResult {
    pub message_id: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
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
    sender_id: String,
    ciphertext: Vec<u8>,
    signature: Vec<u8>,
    sender_device_id: String,
    sender_seq: i64,
    state: State<'_, AppState>,
) -> Result<SendMessageResult, String> {
    let ws_guard = state.ws_client.lock().await;
    let client = ws_guard.as_ref().ok_or("Not connected to relay server")?;

    let message_id = Uuid::new_v4().to_string();
    let timestamp = chrono::Utc::now().timestamp_millis();

    client
        .send_message(
            to,
            conversation_id.clone(),
            ciphertext.clone(),
            signature.clone(),
            sender_device_id.clone(),
            sender_seq,
        )
        .await?;

    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.insert_message(&build_outgoing_message_model(
        message_id.clone(),
        conversation_id,
        sender_id,
        sender_device_id,
        sender_seq,
        timestamp,
        ciphertext,
        signature,
    ))
    .map_err(|e| e.to_string())?;

    Ok(SendMessageResult { message_id })
}

#[tauri::command]
pub async fn poll_messages(state: State<'_, AppState>) -> Result<Vec<IncomingMessage>, String> {
    let mut recv_guard = state.msg_receiver.lock().await;
    let rx = recv_guard.as_mut().ok_or("Not connected to relay server")?;

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
                let incoming = IncomingMessage {
                    message_id,
                    from,
                    conversation_id,
                    ciphertext,
                    signature,
                    sender_device_id,
                    sender_seq,
                    timestamp,
                };
                if let Ok(db) = state.db.lock() {
                    let _ = db.insert_message(&build_incoming_message_model(incoming.clone()));
                }
                messages.push(incoming);
            }
            _ => {}
        }
    }

    Ok(messages)
}

#[tauri::command]
pub async fn encrypt_message(
    plaintext: Vec<u8>,
    recipient_public_key: Vec<u8>,
    sender_secret_key: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let pk: [u8; 32] = recipient_public_key
        .try_into()
        .map_err(|_| "Invalid public key length")?;
    let sk: [u8; 32] = sender_secret_key
        .try_into()
        .map_err(|_| "Invalid secret key length")?;
    liteseal_shared::crypto::encrypt(&plaintext, &pk, &sk)
        .map_err(|e| format!("Encryption failed: {}", e))
}

#[tauri::command]
pub async fn decrypt_message(
    ciphertext: Vec<u8>,
    sender_public_key: Vec<u8>,
    recipient_secret_key: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let pk: [u8; 32] = sender_public_key
        .try_into()
        .map_err(|_| "Invalid public key length")?;
    let sk: [u8; 32] = recipient_secret_key
        .try_into()
        .map_err(|_| "Invalid secret key length")?;
    liteseal_shared::crypto::decrypt(&ciphertext, &pk, &sk)
        .map_err(|e| format!("Decryption failed: {}", e))
}

#[tauri::command]
pub async fn sign_message(message: Vec<u8>, secret_key: Vec<u8>) -> Result<Vec<u8>, String> {
    let sk: [u8; 32] = secret_key
        .try_into()
        .map_err(|_| "Invalid secret key length")?;
    liteseal_shared::crypto::sign(&message, &sk).map_err(|e| format!("Signing failed: {}", e))
}

#[tauri::command]
pub async fn generate_keypair_cmd() -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), String> {
    let kp = liteseal_shared::crypto::generate_keypair().map_err(|e| e.to_string())?;
    Ok((
        kp.public_key.to_vec(),
        kp.secret_key.to_vec(),
        kp.ed25519_pk.to_vec(),
        kp.ed25519_sk.to_vec(),
    ))
}

#[tauri::command]
pub async fn verify_message(
    message: Vec<u8>,
    signature: Vec<u8>,
    sender_public_key: Vec<u8>,
) -> Result<bool, String> {
    let ed_pk: [u8; 32] = sender_public_key
        .try_into()
        .map_err(|_| "Invalid public key length")?;
    liteseal_shared::crypto::verify_with_public_key(&message, &signature, &ed_pk)
        .map_err(|e| format!("Verification failed: {}", e))
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

fn build_outgoing_message_model(
    message_id: String,
    conversation_id: String,
    sender_id: String,
    sender_device_id: String,
    sender_seq: i64,
    timestamp: i64,
    ciphertext: Vec<u8>,
    signature: Vec<u8>,
) -> MessageModel {
    MessageModel {
        id: message_id,
        conversation_id,
        sender_id,
        sender_device_id,
        sender_seq,
        timestamp,
        message_type: "text".to_string(),
        local_state: "sent".to_string(),
        expire_at: None,
        ciphertext,
        signature,
        prev_hash: Vec::new(),
    }
}

fn build_incoming_message_model(msg: IncomingMessage) -> MessageModel {
    MessageModel {
        id: msg.message_id,
        conversation_id: msg.conversation_id,
        sender_id: msg.from,
        sender_device_id: msg.sender_device_id,
        sender_seq: msg.sender_seq,
        timestamp: msg.timestamp,
        message_type: "text".to_string(),
        local_state: "received".to_string(),
        expire_at: None,
        ciphertext: msg.ciphertext,
        signature: msg.signature,
        prev_hash: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outgoing_message_model_is_ready_for_local_persistence() {
        let msg = build_outgoing_message_model(
            "msg-1".to_string(),
            "conv-1".to_string(),
            "alice".to_string(),
            "device-alice".to_string(),
            3,
            1234,
            vec![1, 2, 3],
            vec![4, 5, 6],
        );

        assert_eq!(msg.id, "msg-1");
        assert_eq!(msg.conversation_id, "conv-1");
        assert_eq!(msg.sender_id, "alice");
        assert_eq!(msg.sender_device_id, "device-alice");
        assert_eq!(msg.sender_seq, 3);
        assert_eq!(msg.timestamp, 1234);
        assert_eq!(msg.message_type, "text");
        assert_eq!(msg.local_state, "sent");
        assert_eq!(msg.ciphertext, vec![1, 2, 3]);
        assert_eq!(msg.signature, vec![4, 5, 6]);
        assert!(msg.prev_hash.is_empty());
    }

    #[test]
    fn incoming_message_model_is_ready_for_local_persistence() {
        let msg = build_incoming_message_model(IncomingMessage {
            message_id: "msg-2".to_string(),
            from: "bob".to_string(),
            conversation_id: "conv-1".to_string(),
            ciphertext: vec![7, 8],
            signature: vec![9, 10],
            sender_device_id: "device-bob".to_string(),
            sender_seq: 4,
            timestamp: 5678,
        });

        assert_eq!(msg.id, "msg-2");
        assert_eq!(msg.sender_id, "bob");
        assert_eq!(msg.local_state, "received");
        assert_eq!(msg.ciphertext, vec![7, 8]);
        assert_eq!(msg.signature, vec![9, 10]);
    }
}
