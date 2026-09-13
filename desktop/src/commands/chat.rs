use crate::AppState;
use liteseal_core::chat::{self, PollMessagesResult, SendMessageResult};
use liteseal_core::db::models::MessageModel;
use liteseal_shared::protocol::EncryptedPayload;

pub async fn send_message(
    sender_id: String,
    ciphertext: Vec<u8>,
    signature: Vec<u8>,
    sender_device_id: String,
    payloads: Vec<EncryptedPayload>,
    message_id: Option<String>,
    state: &AppState,
) -> Result<SendMessageResult, String> {
    state
        .client
        .send_message_with_id(
            sender_id,
            ciphertext,
            signature,
            sender_device_id,
            payloads,
            message_id,
        )
        .await
}

pub async fn poll_messages(state: &AppState) -> Result<PollMessagesResult, String> {
    state.client.poll_messages().await
}

pub async fn get_local_messages(
    conversation_id: String,
    limit: i64,
    offset: i64,
    state: &AppState,
) -> Result<Vec<MessageModel>, String> {
    state
        .client
        .get_local_messages(&conversation_id, limit, offset)
}

pub async fn encrypt_message(
    plaintext: Vec<u8>,
    recipient_public_key: Vec<u8>,
    sender_secret_key: Vec<u8>,
) -> Result<Vec<u8>, String> {
    chat::encrypt_message(plaintext, recipient_public_key, sender_secret_key)
}

pub async fn decrypt_message(
    ciphertext: Vec<u8>,
    sender_public_key: Vec<u8>,
    recipient_secret_key: Vec<u8>,
) -> Result<Vec<u8>, String> {
    chat::decrypt_message(ciphertext, sender_public_key, recipient_secret_key)
}

pub async fn sign_message(message: Vec<u8>, signing_key: Vec<u8>) -> Result<Vec<u8>, String> {
    chat::sign_message(message, signing_key)
}

pub async fn verify_message(
    message: Vec<u8>,
    signature: Vec<u8>,
    sender_public_key: Vec<u8>,
) -> Result<bool, String> {
    chat::verify_message(message, signature, sender_public_key)
}

pub async fn generate_keypair_cmd() -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), String> {
    chat::generate_keypair()
}

pub async fn retry_message(
    message_id: String,
    state: &AppState,
) -> Result<SendMessageResult, String> {
    state.client.retry_message(message_id).await
}

pub async fn get_local_message_page(
    user_id: String,
    conversation_id: String,
    limit: i64,
    before_timestamp: Option<i64>,
    before_id: Option<String>,
    state: &AppState,
) -> Result<Vec<MessageModel>, String> {
    if !(1..=101).contains(&limit) || before_timestamp.is_some() != before_id.is_some() {
        return Err("Invalid pagination cursor or limit".into());
    }
    state
        .client
        .db
        .lock()
        .map_err(|e| e.to_string())?
        .get_visible_message_page(
            &conversation_id,
            limit,
            &user_id,
            before_timestamp,
            before_id.as_deref(),
        )
        .map_err(|e| e.to_string())
}
