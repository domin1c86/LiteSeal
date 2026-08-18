use liteseal_core::{
    api,
    chat::{canonical_conversation_id, SendMessageResult},
    client::{DisplayMessage, SecurePollResult},
};
use tauri::State;

use crate::AppState;

#[tauri::command]
pub async fn send_text(
    recipient_user_id: String,
    plaintext: String,
    state: State<'_, AppState>,
) -> Result<SendMessageResult, String> {
    let account = state.session().await?;
    let client = state.client()?;
    let contact = client
        .db
        .lock()
        .map_err(|e| e.to_string())?
        .get_contact(&recipient_user_id)
        .map_err(|e| e.to_string())?
        .ok_or("Recipient is not an accepted contact")?;
    if contact.key_changed || contact.trust_state != "verified" {
        return Err("Confirm the recipient fingerprint before sending".to_string());
    }
    let active_devices = api::get_user_devices(
        account.server_url.clone(),
        recipient_user_id.clone(),
        account.access_token.clone(),
    )
    .await?
    .into_iter()
    .filter(|device| !device.revoked)
    .collect::<Vec<_>>();
    if active_devices.len() != 1 {
        return Err("Recipient must have exactly one active device in this beta".to_string());
    }
    let device = &active_devices[0];
    if device.public_key != contact.public_key
        || contact.ed25519_pk.as_ref() != Some(&device.ed25519_pk)
    {
        client.set_contact_trust(&recipient_user_id, "key_changed")?;
        return Err("Recipient device key changed; verify the new fingerprint".to_string());
    }
    let recipient_key: [u8; 32] = device
        .public_key
        .clone()
        .try_into()
        .map_err(|_| "Recipient encryption key is invalid")?;
    client
        .send_text_v2(
            &account.user_id,
            &account.device_id,
            &account.encryption_secret()?,
            &account.signing_secret()?,
            &recipient_user_id,
            &device.id,
            &recipient_key,
            &plaintext,
        )
        .await
}

#[tauri::command]
pub async fn poll_events(state: State<'_, AppState>) -> Result<SecurePollResult, String> {
    let account = state.session().await?;
    state
        .client()?
        .poll_secure_messages(
            &account.user_id,
            &account.device_id,
            &account.encryption_secret()?,
        )
        .await
}

#[tauri::command]
pub async fn get_messages(
    recipient_user_id: String,
    limit: i64,
    offset: i64,
    state: State<'_, AppState>,
) -> Result<Vec<DisplayMessage>, String> {
    let account = state.session().await?;
    let conversation_id = canonical_conversation_id(&account.user_id, &recipient_user_id);
    state.client()?.get_display_messages(
        &account.user_id,
        &account.encryption_secret()?,
        &conversation_id,
        limit.clamp(1, 200),
        offset.max(0),
    )
}
