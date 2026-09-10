use axum::{
    extract::{
        ws::{Message, WebSocket},
        ConnectInfo, State, WebSocketUpgrade,
    },
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use liteseal_shared::{
    crypto,
    protocol::{ClientMessage, DeliveryStatus, ServerMessage, SignedEnvelopeV2, PROTOCOL_V2},
};
use std::{collections::HashMap, time::Duration};
use tokio::sync::mpsc;
use tokio::time::{timeout, Instant};

use crate::{
    db::{OfflineMessageRecord, StoreOfflineOutcome},
    state::AppState,
};

const MAX_WS_MESSAGE_BYTES: usize = 64 * 1024;
const CONNECTION_CHANNEL_CAPACITY: usize = 128;
const MAX_CIPHERTEXT_BYTES: usize = 16 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_MESSAGE_TYPE_BYTES: usize = 32;

#[derive(Clone)]
struct AuthenticatedSession {
    user_id: String,
    device_id: String,
    generation: u64,
    token_hash: String,
}

impl AuthenticatedSession {
    async fn is_active(&self, state: &AppState) -> bool {
        if !state.is_current(&self.device_id, self.generation) {
            return false;
        }
        matches!(
            state.db.validate_access_token(&self.token_hash, &self.device_id).await,
            Ok(Some(user_id)) if user_id == self.user_id
        )
    }
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<std::net::SocketAddr>,
) -> impl IntoResponse {
    ws.max_message_size(MAX_WS_MESSAGE_BYTES)
        .max_frame_size(MAX_WS_MESSAGE_BYTES)
        .on_upgrade(move |socket| handle_socket(socket, state, remote_addr.ip()))
}

async fn handle_socket(socket: WebSocket, state: AppState, remote_ip: std::net::IpAddr) {
    let (mut writer, mut reader) = socket.split();
    let first = timeout(Duration::from_secs(10), reader.next()).await;
    let Ok(Some(Ok(Message::Text(text)))) = first else {
        return;
    };
    let Ok(ClientMessage::Auth {
        user_id,
        token,
        device_id,
    }) = serde_json::from_str(&text)
    else {
        return;
    };
    if state.validate_auth(&token, &device_id).await.as_deref() != Some(&user_id) {
        let _ = writer
            .send(Message::Text(
                serde_json::to_string(&ServerMessage::AuthFail {
                    reason: "Invalid credentials".into(),
                })
                .unwrap(),
            ))
            .await;
        return;
    }
    let (tx, mut rx) = mpsc::channel::<String>(CONNECTION_CHANNEL_CAPACITY);
    let generation = state.register(device_id.clone(), tx.clone());
    let session = AuthenticatedSession {
        user_id,
        device_id,
        generation,
        token_hash: crate::auth::service::hash_token(&token),
    };
    send_message(&tx, &ServerMessage::AuthOk);
    let mut pending: HashMap<String, Instant> = HashMap::new();
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    // One writer and one durable queue: live traffic never bypasses replay.
    loop {
        tokio::select! {
            biased;
            outgoing = rx.recv() => {
                let Some(outgoing) = outgoing else { break };
                if !session.is_active(&state).await { break; }
                if !matches!(timeout(Duration::from_secs(5), writer.send(Message::Text(outgoing))).await, Ok(Ok(()))) { break; }
            }
            incoming = reader.next() => {
                let Some(Ok(incoming)) = incoming else { break };
                if !session.is_active(&state).await { break; }
                let text = match incoming {
                    Message::Text(text) => text,
                    Message::Ping(bytes) => {
                        if !matches!(timeout(Duration::from_secs(5), writer.send(Message::Pong(bytes))).await, Ok(Ok(()))) { break; }
                        continue;
                    }
                    Message::Close(_) => break,
                    _ => continue,
                };
                let Ok(message) = serde_json::from_str::<ClientMessage>(&text) else {
                    send_error(&tx, "parse_error", "Invalid message format"); continue;
                };
                match message {
                    ClientMessage::Auth { .. } => break,
                    ClientMessage::Send { .. } => send_error(&tx, "legacy_send_read_only", "New messages must use protocol v2"),
                    ClientMessage::SendV2 { envelopes } => {
                        let id = envelopes.first().map(|e| e.message_id.clone()).unwrap_or_default();
                        if let Err((code, message)) = handle_v2_send(&state, &tx, &session.user_id, &session.device_id, remote_ip, envelopes).await {
                            send_message(&tx, &ServerMessage::MessageError { message_id: id, code: code.into(), message: message.into(),
                                retryable: matches!(code, "rate_limited" | "storage_error" | "offline_quota_exceeded") });
                        }
                    }
                    ClientMessage::DeliveryQuery { message_ids } => {
                        if message_ids.len() > 100 { send_error(&tx, "query_too_large", "At most 100 message ids"); continue; }
                        match state.db.delivery_statuses(&session.device_id, &message_ids).await {
                            Ok(updates) => send_message(&tx, &ServerMessage::DeliveryUpdate { updates }),
                            Err(_) => send_error(&tx, "storage_error", "Unable to query delivery status"),
                        }
                    }
                    ClientMessage::Ack { message_id, .. } => {
                        apply_ack(&state, &session, &tx, &message_id, Default::default()).await;
                        pending.remove(&message_id);
                    }
                    ClientMessage::AckV2 { message_id, outcome } => {
                        apply_ack(&state, &session, &tx, &message_id, outcome).await;
                        pending.remove(&message_id);
                    }
                }
            }
            _ = tick.tick() => {
                if !session.is_active(&state).await { break; }
                let Ok(messages) = state.db.pending_window(&session.device_id).await else { break };
                for message in messages {
                    if pending.get(&message.message_id).is_some_and(|sent| sent.elapsed() < Duration::from_secs(15)) { continue; }
                    let outgoing = ServerMessage::MessageV2 { envelope: message.envelope(), server_timestamp: unix_millis() };
                    let serialized = serde_json::to_string(&outgoing).expect("wire message serializes");
                    if !matches!(timeout(Duration::from_secs(5), writer.send(Message::Text(serialized))).await, Ok(Ok(()))) {
                        state.unregister(&session.device_id, session.generation); return;
                    }
                    pending.insert(message.message_id, Instant::now());
                }
                // ACKs also remove entries; cap metadata across expired/revoked queues.
                pending.retain(|_, sent| sent.elapsed() < Duration::from_secs(60));
            }
        }
    }
    state.unregister(&session.device_id, session.generation);
}

async fn apply_ack(
    state: &AppState,
    session: &AuthenticatedSession,
    tx: &mpsc::Sender<String>,
    id: &str,
    outcome: liteseal_shared::protocol::AckOutcome,
) {
    if uuid::Uuid::parse_str(id).is_err() {
        send_error(tx, "invalid_message_id", "Invalid ACK message id");
        return;
    }
    match state.db.ack_message(id, &session.device_id, outcome).await {
        Ok(Some(receipt)) => {
            let message = ServerMessage::DeliveryUpdate {
                updates: vec![DeliveryStatus {
                    message_id: receipt.message_id,
                    recipient_user_id: receipt.recipient_user_id,
                    recipient_device_id: receipt.recipient_device_id,
                    status: receipt.status,
                }],
            };
            if let Ok(json) = serde_json::to_string(&message) {
                state.send_to(&receipt.sender_device_id, json);
            }
        }
        Ok(None) => send_error(tx, "ack_not_found", "Message is not queued for this device"),
        Err(_) => send_error(tx, "storage_error", "Unable to persist ACK"),
    }
}

async fn handle_v2_send(
    state: &AppState,
    sender: &mpsc::Sender<String>,
    authenticated_user: &str,
    authenticated_device: &str,
    remote_ip: std::net::IpAddr,
    mut envelopes: Vec<SignedEnvelopeV2>,
) -> Result<(), (&'static str, &'static str)> {
    if envelopes.len() != 1 {
        return Err((
            "invalid_recipient_count",
            "Single-device mode requires exactly one recipient envelope",
        ));
    }
    let envelope = envelopes.pop().expect("length checked");
    validate_envelope_shape(&envelope, authenticated_user, authenticated_device)?;
    let account_allowed = state
        .db
        .hit_rate_limit(&format!("message:account:{authenticated_user}"), 120, 60)
        .await
        .map_err(|_| ("storage_error", "Unable to apply message rate limit"))?;
    let ip_allowed = state
        .db
        .hit_rate_limit(&format!("message:ip:{remote_ip}"), 300, 60)
        .await
        .map_err(|_| ("storage_error", "Unable to apply message rate limit"))?;
    if !account_allowed || !ip_allowed {
        return Err(("rate_limited", "Message rate limit exceeded"));
    }

    let sender_device = state
        .db
        .get_user_device(authenticated_user, authenticated_device)
        .await
        .map_err(|_| ("storage_error", "Unable to validate sender device"))?
        .filter(|device| !device.revoked)
        .ok_or(("sender_device_revoked", "Sender device is not active"))?;
    let signing_key: [u8; 32] = sender_device
        .ed25519_pk
        .try_into()
        .map_err(|_| ("invalid_sender_key", "Sender signing key is invalid"))?;
    let signing_bytes = envelope
        .signing_bytes()
        .map_err(|_| ("invalid_envelope", "Envelope cannot be encoded"))?;
    if !crypto::verify_with_public_key(&signing_bytes, &envelope.signature, &signing_key)
        .map_err(|_| ("verification_error", "Unable to verify message"))?
    {
        return Err(("invalid_signature", "Message signature is invalid"));
    }

    state
        .db
        .get_user_device(&envelope.recipient_user_id, &envelope.recipient_device_id)
        .await
        .map_err(|_| ("storage_error", "Unable to validate recipient device"))?
        .filter(|device| !device.revoked)
        .ok_or((
            "invalid_recipient_device",
            "Recipient device does not belong to the recipient or is revoked",
        ))?;

    // Persist before attempting ANY socket delivery. A socket queue can be
    // lost on disconnect or process exit; the durable copy survives until ACK.
    let stored = state
        .db
        .store_offline_message(&offline_record(&envelope))
        .await
        .map_err(|_| ("storage_error", "Unable to persist message"))?;
    if stored == StoreOfflineOutcome::Conflict {
        return Err((
            "message_conflict",
            "Message id or sequence conflicts with a stored envelope",
        ));
    }
    if stored == StoreOfflineOutcome::QuotaExceeded {
        return Err(("offline_quota_exceeded", "Recipient offline queue is full"));
    }

    let updates = state
        .db
        .delivery_statuses(authenticated_device, &[envelope.message_id])
        .await
        .map_err(|_| ("storage_error", "Unable to query stored receipt"))?;
    send_message(sender, &ServerMessage::DeliveryUpdate { updates });
    Ok(())
}

fn validate_envelope_shape(
    envelope: &SignedEnvelopeV2,
    authenticated_user: &str,
    authenticated_device: &str,
) -> Result<(), (&'static str, &'static str)> {
    if envelope.protocol_version != PROTOCOL_V2 {
        return Err(("unsupported_protocol", "Unsupported protocol version"));
    }
    if envelope.sender_user_id != authenticated_user
        || envelope.sender_device_id != authenticated_device
    {
        return Err((
            "sender_mismatch",
            "Envelope sender does not match authentication",
        ));
    }
    if uuid::Uuid::parse_str(&envelope.message_id).is_err() {
        return Err(("invalid_message_id", "Message id must be a UUID"));
    }
    let expected_conversation =
        canonical_conversation_id(authenticated_user, &envelope.recipient_user_id);
    if envelope.conversation_id != expected_conversation {
        return Err(("invalid_conversation", "Conversation id is not canonical"));
    }
    let identifiers = [
        &envelope.message_id,
        &envelope.conversation_id,
        &envelope.sender_user_id,
        &envelope.sender_device_id,
        &envelope.recipient_user_id,
        &envelope.recipient_device_id,
    ];
    if identifiers
        .iter()
        .any(|value| value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES)
    {
        return Err((
            "invalid_field_length",
            "Envelope identifier length is invalid",
        ));
    }
    if envelope.message_type != "text" || envelope.message_type.len() > MAX_MESSAGE_TYPE_BYTES {
        return Err(("invalid_message_type", "Unsupported message type"));
    }
    if envelope.ciphertext.is_empty() || envelope.ciphertext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(("invalid_ciphertext", "Ciphertext length is invalid"));
    }
    if envelope.signature.len() != 64 {
        return Err(("invalid_signature", "Signature length is invalid"));
    }
    if envelope.sender_seq < 1
        || (envelope.sender_seq == 1 && !envelope.prev_hash.is_empty())
        || (envelope.sender_seq > 1 && envelope.prev_hash.len() != 32)
    {
        return Err((
            "invalid_sequence",
            "Message sequence or previous hash is invalid",
        ));
    }
    if envelope.sent_at <= 0 {
        return Err(("invalid_timestamp", "Message timestamp is invalid"));
    }
    Ok(())
}

pub(crate) fn offline_record(envelope: &SignedEnvelopeV2) -> OfflineMessageRecord {
    OfflineMessageRecord {
        protocol_version: i16::from(PROTOCOL_V2),
        message_id: envelope.message_id.clone(),
        conversation_id: envelope.conversation_id.clone(),
        from_user_id: envelope.sender_user_id.clone(),
        sender_device_id: envelope.sender_device_id.clone(),
        sender_seq: envelope.sender_seq,
        prev_hash: envelope.prev_hash.clone(),
        recipient_user_id: envelope.recipient_user_id.clone(),
        recipient_device_id: envelope.recipient_device_id.clone(),
        message_type: envelope.message_type.clone(),
        ciphertext: envelope.ciphertext.clone(),
        signature: envelope.signature.clone(),
        timestamp: envelope.sent_at,
    }
}

fn canonical_conversation_id(a: &str, b: &str) -> String {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    format!("dm:{lo}:{hi}")
}

fn send_error(sender: &mpsc::Sender<String>, code: &str, message: &str) {
    send_message(
        sender,
        &ServerMessage::Error {
            code: code.to_string(),
            message: message.to_string(),
        },
    );
}

fn send_message(sender: &mpsc::Sender<String>, message: &ServerMessage) {
    if let Ok(serialized) = serde_json::to_string(message) {
        let _ = sender.try_send(serialized);
    }
}

fn unix_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_envelope() -> SignedEnvelopeV2 {
        SignedEnvelopeV2 {
            protocol_version: PROTOCOL_V2,
            message_id: uuid::Uuid::new_v4().to_string(),
            conversation_id: "dm:alice:bob".to_string(),
            sender_user_id: "alice".to_string(),
            sender_device_id: "alice-device".to_string(),
            recipient_user_id: "bob".to_string(),
            recipient_device_id: "bob-device".to_string(),
            sender_seq: 1,
            prev_hash: Vec::new(),
            sent_at: 1,
            message_type: "text".to_string(),
            ciphertext: vec![1],
            signature: vec![2; 64],
        }
    }

    #[test]
    fn envelope_shape_rejects_spoofing_and_noncanonical_metadata() {
        let valid = valid_envelope();
        assert!(validate_envelope_shape(&valid, "alice", "alice-device").is_ok());

        let mut spoofed = valid.clone();
        spoofed.sender_device_id = "other-device".to_string();
        assert_eq!(
            validate_envelope_shape(&spoofed, "alice", "alice-device")
                .unwrap_err()
                .0,
            "sender_mismatch"
        );

        let mut wrong_conversation = valid;
        wrong_conversation.conversation_id = "dm:bob:alice".to_string();
        assert_eq!(
            validate_envelope_shape(&wrong_conversation, "alice", "alice-device")
                .unwrap_err()
                .0,
            "invalid_conversation"
        );
    }

    #[test]
    fn envelope_shape_enforces_ciphertext_and_chain_limits() {
        let mut oversized = valid_envelope();
        oversized.ciphertext = vec![0; MAX_CIPHERTEXT_BYTES + 1];
        assert_eq!(
            validate_envelope_shape(&oversized, "alice", "alice-device")
                .unwrap_err()
                .0,
            "invalid_ciphertext"
        );

        let mut invalid_first = valid_envelope();
        invalid_first.prev_hash = vec![0; 32];
        assert_eq!(
            validate_envelope_shape(&invalid_first, "alice", "alice-device")
                .unwrap_err()
                .0,
            "invalid_sequence"
        );
    }
}
