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
use tokio::sync::{mpsc, watch};

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
    let (mut ws_sender, mut ws_receiver) = socket.split();
    let (tx, mut rx) = mpsc::channel::<String>(CONNECTION_CHANNEL_CAPACITY);
    let mut authenticated: Option<AuthenticatedSession> = None;
    let (auth_tx, auth_rx) = watch::channel::<Option<AuthenticatedSession>>(None);
    let delivery_state = state.clone();

    let mut send_task = tokio::spawn(async move {
        let mut check_session = tokio::time::interval(std::time::Duration::from_secs(15));
        loop {
            let outgoing = tokio::select! {
                msg = rx.recv() => match msg {
                    Some(message) => Some(message),
                    None => break,
                },
                _ = check_session.tick() => None,
            };
            let session = auth_rx.borrow().clone();
            if let Some(session) = session {
                // Revocation and replacement apply to existing connections,
                // including receive-only clients. Database errors fail closed.
                if !session.is_active(&delivery_state).await {
                    break;
                }
            }
            if let Some(message) = outgoing {
                if ws_sender.send(Message::Text(message)).await.is_err() {
                    break;
                }
            }
        }
    });

    loop {
        let incoming = tokio::select! {
            message = StreamExt::next(&mut ws_receiver) => message,
            _ = &mut send_task => break,
        };
        let Some(Ok(msg)) = incoming else { break };
        let Message::Text(text) = msg else {
            if matches!(msg, Message::Close(_)) {
                break;
            }
            continue;
        };

        let parsed = match serde_json::from_str::<ClientMessage>(&text) {
            Ok(parsed) => parsed,
            Err(_) => {
                send_error(&tx, "parse_error", "Invalid message format");
                continue;
            }
        };

        if authenticated.is_none() {
            let ClientMessage::Auth {
                user_id,
                token,
                device_id,
            } = parsed
            else {
                send_error(&tx, "unauthorized", "The first frame must authenticate");
                break;
            };

            match state.validate_auth(&token, &device_id).await {
                Some(validated_user_id) if validated_user_id == user_id => {
                    let generation = state.register(device_id.clone(), tx.clone());
                    let session = AuthenticatedSession {
                        user_id: validated_user_id,
                        device_id: device_id.clone(),
                        generation,
                        token_hash: crate::auth::service::hash_token(&token),
                    };
                    auth_tx.send_replace(Some(session.clone()));
                    authenticated = Some(session);
                    send_message(&tx, &ServerMessage::AuthOk);
                    deliver_offline_messages(&state, &tx, &device_id).await;
                }
                _ => {
                    send_message(
                        &tx,
                        &ServerMessage::AuthFail {
                            reason: "Invalid credentials".into(),
                        },
                    );
                    break;
                }
            }
            continue;
        }

        let session = authenticated.as_ref().expect("checked above");
        if !session.is_active(&state).await {
            break;
        }
        let authenticated_user = &session.user_id;
        let authenticated_device = &session.device_id;
        match parsed {
            ClientMessage::Auth { .. } => {
                send_error(
                    &tx,
                    "reauth_forbidden",
                    "Authentication is only allowed as the first frame",
                );
                break;
            }
            ClientMessage::Send { .. } => send_error(
                &tx,
                "legacy_send_read_only",
                "New messages must use protocol v2",
            ),
            ClientMessage::SendV2 { envelopes } => {
                if let Err((code, message)) = handle_v2_send(
                    &state,
                    &tx,
                    authenticated_user,
                    authenticated_device,
                    remote_ip,
                    envelopes,
                )
                .await
                {
                    send_error(&tx, code, message);
                }
            }
            ClientMessage::Ack {
                message_id,
                recipient_device_id: _,
            }
            | ClientMessage::AckV2 { message_id } => {
                // Both legacy and v2 ACKs are bound to the authenticated
                // device. A client-supplied device id is never trusted.
                if uuid::Uuid::parse_str(&message_id).is_err() {
                    send_error(&tx, "invalid_message_id", "Invalid ACK message id");
                    continue;
                }
                match state
                    .db
                    .ack_message(&message_id, authenticated_device)
                    .await
                {
                    Ok(Some(receipt)) => {
                        // Only a durable, authenticated recipient ACK means
                        // delivered. Enqueuing a socket write is not delivery.
                        if let Ok(message) = serde_json::to_string(&ServerMessage::DeliveryUpdate {
                            updates: vec![DeliveryStatus {
                                message_id: receipt.message_id,
                                recipient_user_id: receipt.recipient_user_id,
                                recipient_device_id: receipt.recipient_device_id,
                                status: "delivered".to_string(),
                            }],
                        }) {
                            state.send_to(&receipt.sender_device_id, message);
                        }
                    }
                    Ok(None) => send_error(
                        &tx,
                        "ack_not_found",
                        "Message is not queued for this device",
                    ),
                    Err(error) => {
                        tracing::error!(%error, "Failed to persist ACK");
                        send_error(&tx, "storage_error", "Unable to persist ACK");
                    }
                }
            }
        }
    }

    if let Some(session) = authenticated {
        state.unregister(&session.device_id, session.generation);
        tracing::info!(
            device_id = session.device_id,
            generation = session.generation,
            "Device disconnected"
        );
    }
    send_task.abort();
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

    let relay_message = serde_json::to_string(&ServerMessage::MessageV2 {
        envelope: envelope.clone(),
        server_timestamp: unix_millis(),
    })
    .map_err(|_| ("serialization_error", "Unable to serialize message"))?;

    // Persist before attempting ANY socket delivery. A socket queue can be
    // lost on disconnect or process exit; the durable copy survives until ACK.
    let stored = state
        .db
        .store_offline_message(&offline_record(&envelope))
        .await
        .map_err(|_| ("storage_error", "Unable to persist message"))?;
    if stored == StoreOfflineOutcome::QuotaExceeded {
        return Err(("offline_quota_exceeded", "Recipient offline queue is full"));
    }

    send_message(
        sender,
        &ServerMessage::DeliveryUpdate {
            updates: vec![DeliveryStatus {
                message_id: envelope.message_id.clone(),
                recipient_user_id: envelope.recipient_user_id.clone(),
                recipient_device_id: envelope.recipient_device_id.clone(),
                status: "stored".to_string(),
            }],
        },
    );
    // Queue the stored status before delivery so a fast recipient ACK cannot
    // be followed by an older stored update on the sender's connection.
    // Duplicates replay the original durable envelope on reconnection.
    if stored == StoreOfflineOutcome::Stored {
        state.send_to(&envelope.recipient_device_id, relay_message);
    }
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

async fn deliver_offline_messages(
    state: &AppState,
    sender: &mpsc::Sender<String>,
    device_id: &str,
) {
    let Ok(messages) = state.db.drain_offline_messages(device_id).await else {
        tracing::error!(device_id, "Failed to load offline messages");
        return;
    };

    for message in messages {
        let server_message = if message.protocol_version == i16::from(PROTOCOL_V2) {
            ServerMessage::MessageV2 {
                envelope: SignedEnvelopeV2 {
                    protocol_version: PROTOCOL_V2,
                    message_id: message.message_id,
                    conversation_id: message.conversation_id,
                    sender_user_id: message.from_user_id,
                    sender_device_id: message.sender_device_id,
                    recipient_user_id: message.recipient_user_id,
                    recipient_device_id: message.recipient_device_id,
                    sender_seq: message.sender_seq,
                    prev_hash: message.prev_hash,
                    sent_at: message.timestamp,
                    message_type: message.message_type,
                    ciphertext: message.ciphertext,
                    signature: message.signature,
                },
                server_timestamp: unix_millis(),
            }
        } else {
            ServerMessage::Message {
                message_id: message.message_id,
                from: message.from_user_id,
                conversation_id: message.conversation_id,
                ciphertext: message.ciphertext,
                signature: message.signature,
                sender_device_id: message.sender_device_id,
                sender_seq: message.sender_seq,
                prev_hash: message.prev_hash,
                recipient_device_id: message.recipient_device_id,
                timestamp: message.timestamp,
            }
        };
        let Ok(serialized) = serde_json::to_string(&server_message) else {
            continue;
        };
        if !enqueue_replay(sender, serialized).await {
            break;
        }
    }
}

async fn enqueue_replay(sender: &mpsc::Sender<String>, message: String) -> bool {
    // Backpressure lets queues larger than 128 drain in one connection.
    // Bound stalled writes; the unacknowledged rows remain durable for retry.
    matches!(
        tokio::time::timeout(std::time::Duration::from_secs(5), sender.send(message)).await,
        Ok(Ok(()))
    )
}

fn offline_record(envelope: &SignedEnvelopeV2) -> OfflineMessageRecord {
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

    #[tokio::test]
    async fn replay_waits_for_capacity_and_delivers_more_than_one_channelful() {
        let (sender, mut receiver) = mpsc::channel(CONNECTION_CHANNEL_CAPACITY);
        for index in 0..CONNECTION_CHANNEL_CAPACITY {
            sender.try_send(index.to_string()).unwrap();
        }
        let producer = tokio::spawn(async move {
            for index in CONNECTION_CHANNEL_CAPACITY..1_000 {
                assert!(enqueue_replay(&sender, index.to_string()).await);
            }
        });
        for index in 0..1_000 {
            let message = tokio::time::timeout(std::time::Duration::from_secs(2), receiver.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(message, index.to_string());
        }
        producer.await.unwrap();
    }

    #[tokio::test]
    async fn replay_stops_when_connection_is_closed() {
        let (sender, receiver) = mpsc::channel(1);
        drop(receiver);
        assert!(!enqueue_replay(&sender, "message".to_string()).await);
    }

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
