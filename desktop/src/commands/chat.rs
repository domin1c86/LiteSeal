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
    if payloads.is_empty() {
        return Err("Message has no recipient payloads".to_string());
    }
    let persisted = match &message_id {
        Some(id) => state
            .client
            .db
            .lock()
            .map_err(|e| e.to_string())?
            .get_message(id)
            .map_err(|e| e.to_string())?
            .is_some(),
        None => false,
    };
    // Persisted messages resend their stored envelopes; new ones are signed in Rust.
    let signing_key = if persisted {
        None
    } else {
        let saved = state.identity()?;
        if saved.user_id != sender_id || saved.device_id != sender_device_id {
            return Err("The signed-in identity does not match the sender".to_string());
        }
        Some(<[u8; 64]>::try_from(saved.ed25519_sk.as_slice()).map_err(|_| "Invalid signing key")?)
    };
    state
        .client
        .send_message_with_id(
            sender_id,
            ciphertext,
            signature,
            sender_device_id,
            payloads,
            message_id,
            signing_key.as_ref(),
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

// Crypto uses the saved identity; the renderer never holds secret keys.

pub async fn encrypt_message(
    plaintext: Vec<u8>,
    recipient_public_key: Vec<u8>,
    state: &AppState,
) -> Result<Vec<u8>, String> {
    chat::encrypt_message(
        plaintext,
        recipient_public_key,
        state.identity()?.secret_key,
    )
}

pub async fn decrypt_message(
    ciphertext: Vec<u8>,
    sender_public_key: Vec<u8>,
    state: &AppState,
) -> Result<Vec<u8>, String> {
    chat::decrypt_message(ciphertext, sender_public_key, state.identity()?.secret_key)
}

pub async fn sign_message(message: Vec<u8>, state: &AppState) -> Result<Vec<u8>, String> {
    chat::sign_message(message, state.identity()?.ed25519_sk)
}

pub async fn verify_message(
    message: Vec<u8>,
    signature: Vec<u8>,
    sender_public_key: Vec<u8>,
) -> Result<bool, String> {
    chat::verify_message(message, signature, sender_public_key)
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
    if state.identity()?.user_id != user_id { return Err("Account mismatch".into()); }
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
