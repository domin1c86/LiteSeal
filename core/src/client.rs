//! Stateful client facade: owns the local store, the relay connection and the
//! incoming-message channel. Platform shells (Electron sidecar, the Android FFI
//! layer) hold one instance and delegate to it.
//!
//! Locking rules: `db` is a blocking mutex guarding the rusqlite connection —
//! never hold it across an await. The websocket handles use async mutexes.

use std::sync::Mutex;
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;

use liteseal_shared::{
    crypto,
    protocol::{AckOutcome, EncryptedPayload, ServerMessage, SignedEnvelopeV2, PROTOCOL_V2},
};
use serde::{Deserialize, Serialize};

use crate::api::normalize_server_url;
use crate::chat::{
    build_incoming_message_model, build_outgoing_message_model, canonical_conversation_id,
    next_chain_state, IncomingMessage, PollMessagesResult, RelayEvent, SendMessageResult,
};
use crate::contacts::{fingerprint, validate_contact_input};
use crate::db::models::{ContactModel, MessageModel};
use crate::db::repository::{DbError, MessageRepository};
use crate::integrity::{IntegrityResult, MessageIntegrityStore};
use crate::network::websocket::{MessageReceiver, WebSocketClient};

#[derive(Debug, Serialize)]
pub struct StorageStatsResult {
    pub message_count: i64,
    pub ciphertext_bytes: i64,
    pub attachment_count: i64,
    pub attachment_bytes: i64,
    pub conversation_count: i64,
    pub total_bytes: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplayMessage {
    pub id: String,
    pub conversation_id: String,
    pub sender_id: String,
    pub sender_device_id: String,
    pub sender_seq: i64,
    pub timestamp: i64,
    pub plaintext: String,
    pub local_state: String,
    pub protocol_version: u8,
    pub verification_state: String,
}

/// An error code and message for an envelope left unacknowledged.
type PendingReason = (String, String);

pub struct LitesealClient {
    pub db: Mutex<MessageRepository>,
    connection_gate: AsyncMutex<()>,
    pub ws_client: AsyncMutex<Option<WebSocketClient>>,
    pub msg_receiver: AsyncMutex<Option<MessageReceiver>>,
}

impl LitesealClient {
    pub fn new(db_path: &str) -> Result<Self, String> {
        let db = MessageRepository::new(db_path).map_err(|e| e.to_string())?;
        Ok(Self {
            db: Mutex::new(db),
            connection_gate: AsyncMutex::new(()),
            ws_client: AsyncMutex::new(None),
            msg_receiver: AsyncMutex::new(None),
        })
    }

    // Relay connection

    pub async fn connect_relay(
        &self,
        server_url: String,
        user_id: String,
        token: String,
        device_id: String,
    ) -> Result<(), String> {
        let _gate = self.connection_gate.lock().await;
        if device_id.trim().is_empty() {
            return Err("Device id is required to connect".to_string());
        }
        let server_url = normalize_server_url(&server_url)?;
        let ws_url = server_url
            .replace("http://", "ws://")
            .replace("https://", "wss://");
        let ws_url = format!("{}/ws", ws_url);

        let (client, rx) = WebSocketClient::connect(&ws_url, user_id, token, device_id).await?;

        let mut recv_guard = self.msg_receiver.lock().await;
        let mut ws_guard = self.ws_client.lock().await;
        if let Some(old) = ws_guard.as_mut() {
            old.disconnect().await;
        }
        *ws_guard = Some(client);
        *recv_guard = Some(rx);

        Ok(())
    }

    pub async fn disconnect(&self) {
        let _gate = self.connection_gate.lock().await;
        let mut recv_guard = self.msg_receiver.lock().await;
        let mut ws_guard = self.ws_client.lock().await;
        if let Some(client) = ws_guard.as_mut() {
            client.disconnect().await;
        }
        *ws_guard = None;

        *recv_guard = None;
    }

    // Messaging

    /// Without a signing key this can only resend an already persisted message.
    pub async fn send_message(
        &self,
        sender_id: String,
        ciphertext: Vec<u8>,
        signature: Vec<u8>,
        sender_device_id: String,
        payloads: Vec<EncryptedPayload>,
    ) -> Result<SendMessageResult, String> {
        self.send_message_with_id(
            sender_id,
            ciphertext,
            signature,
            sender_device_id,
            payloads,
            None,
            None,
        )
        .await
    }

    pub async fn retry_message(&self, message_id: String) -> Result<SendMessageResult, String> {
        let (message, payloads) = {
            let db = self.db.lock().map_err(|e| e.to_string())?;
            let message = db
                .get_message(&message_id)
                .map_err(|e| e.to_string())?
                .ok_or("Message not found")?;
            let payloads = serde_json::from_str(
                &db.outgoing_payloads(&message_id)
                    .map_err(|e| e.to_string())?,
            )
            .map_err(|_| "Cannot read saved outgoing message")?;
            (message, payloads)
        };
        self.send_message_with_id(
            message.sender_id,
            message.ciphertext,
            message.signature,
            message.sender_device_id,
            payloads,
            Some(message_id),
            None,
        )
        .await
    }

    /// Each recipient payload becomes one `SignedEnvelopeV2`. Envelopes are
    /// signed and persisted before the first network write, so a retry resends
    /// identical bytes that the relay can deduplicate.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_message_with_id(
        &self,
        sender_id: String,
        ciphertext: Vec<u8>,
        signature: Vec<u8>,
        sender_device_id: String,
        payloads: Vec<EncryptedPayload>,
        message_id: Option<String>,
        signing_key: Option<&[u8; 64]>,
    ) -> Result<SendMessageResult, String> {
        if payloads.is_empty() {
            return Err("Message has no recipient payloads".to_string());
        }
        let recipient_user_id = payloads[0].recipient_user_id.clone();
        if payloads
            .iter()
            .any(|p| p.recipient_user_id != recipient_user_id)
        {
            return Err("All payloads in a direct message must target the same user".to_string());
        }
        // The relay accepts one envelope per sender chain position, so a
        // message reaches exactly one recipient device during the beta.
        if payloads.len() != 1 {
            return Err("Recipient must have exactly one active device".to_string());
        }
        let conversation_id = canonical_conversation_id(&sender_id, &recipient_user_id);

        let ws_guard = self.ws_client.lock().await;
        let client = ws_guard.as_ref().ok_or("Not connected to relay server")?;
        if client.user_id() != sender_id || client.device_id() != sender_device_id {
            return Err("Sender does not match the connected relay session".to_string());
        }

        let message_id = message_id.unwrap_or_else(|| Uuid::new_v4().to_string());
        Uuid::parse_str(&message_id).map_err(|_| "Invalid message id")?;
        let envelopes = {
            let db = self.db.lock().map_err(|e| e.to_string())?;
            let (outgoing, payloads) = if let Some(existing) =
                db.get_message(&message_id).map_err(|e| e.to_string())?
            {
                if existing.sender_id != sender_id
                    || existing.sender_device_id != sender_device_id
                    || existing.conversation_id != conversation_id
                {
                    return Err("Message id belongs to another conversation or device".into());
                }
                let saved: Vec<EncryptedPayload> = serde_json::from_str(
                    &db.outgoing_payloads(&message_id)
                        .map_err(|e| e.to_string())?,
                )
                .map_err(|_| "Cannot read saved outgoing message")?;
                (existing, saved)
            } else {
                let signing_key =
                    signing_key.ok_or("A signing key is required for new messages")?;
                let previous = db
                    .get_latest_message_for_sender(&conversation_id, &sender_device_id)
                    .map_err(|e| e.to_string())?;
                let (seq, hash) = next_chain_state(previous.as_ref());
                let outgoing = build_outgoing_message_model(
                    message_id.clone(),
                    conversation_id.clone(),
                    sender_id,
                    sender_device_id.clone(),
                    seq,
                    chrono::Utc::now().timestamp_millis(),
                    ciphertext,
                    signature,
                    hash,
                    "pending",
                );
                let signed = db
                    .prepare_outgoing(&outgoing, payloads, |payload, sender_seq, prev_hash| {
                        let envelope =
                            outgoing_envelope(&outgoing, payload, sender_seq, prev_hash.to_vec());
                        let bytes = envelope.signing_bytes().map_err(|e| e.to_string())?;
                        crypto::sign(&bytes, signing_key).map_err(|e| e.to_string())
                    })
                    .map_err(|e| e.to_string())?;
                (outgoing, signed)
            };
            let chains = db.outgoing_chains(&message_id).map_err(|e| e.to_string())?;
            payloads
                .iter()
                .map(|payload| {
                    let (sender_seq, prev_hash) = chains
                        .get(&payload.recipient_device_id)
                        .cloned()
                        .ok_or("Saved outgoing chain is incomplete")?;
                    Ok(outgoing_envelope(&outgoing, payload, sender_seq, prev_hash))
                })
                .collect::<Result<Vec<_>, String>>()?
        };

        if let Err(err) = client.send_v2(envelopes).await {
            if let Ok(db) = self.db.lock() {
                let _ = db.update_message_state(&message_id, "failed");
            }
            return Err(err);
        }

        Ok(SendMessageResult { message_id })
    }

    pub async fn poll_messages(&self) -> Result<PollMessagesResult, String> {
        let mut recv_guard = self.msg_receiver.lock().await;
        let rx = recv_guard.as_mut().ok_or("Not connected to relay server")?;
        if rx.is_closed() && rx.is_empty() {
            return Err("Relay disconnected".into());
        }
        let (user_id, device_id) = {
            let ws = self.ws_client.lock().await;
            let client = ws.as_ref().ok_or("Not connected to relay server")?;
            (client.user_id().to_string(), client.device_id().to_string())
        };

        let mut messages = Vec::new();
        let mut events = Vec::new();

        while let Ok(msg) = rx.try_recv() {
            match msg {
                ServerMessage::MessageV2 { envelope, .. } => {
                    let message_id = envelope.message_id.clone();
                    match self.receive_envelope(&user_id, &device_id, envelope) {
                        Ok((outcome, stored)) => {
                            if outcome == AckOutcome::Rejected {
                                events.push(RelayEvent::Error {
                                    code: "message_rejected".into(),
                                    message: "A received message failed verification".into(),
                                });
                            }
                            // Acknowledge only after durable local storage. Replay gets an ACK again.
                            if let Some(ws) = self.ws_client.lock().await.as_ref() {
                                ws.send_ack(message_id, outcome).await?;
                            }
                            messages.extend(stored);
                        }
                        // Unacknowledged envelopes are replayed by the relay later.
                        Err((code, message)) => events.push(RelayEvent::Error { code, message }),
                    }
                }
                ServerMessage::Delivered { message_id } => {
                    if let Ok(db) = self.db.lock() {
                        let _ = db.update_message_state(&message_id, "delivered");
                    }
                    events.push(RelayEvent::Delivered { message_id });
                }
                ServerMessage::Offline { message_id, to } => {
                    if let Ok(db) = self.db.lock() {
                        let _ = db.update_message_state(&message_id, "offline");
                    }
                    events.push(RelayEvent::Offline { message_id, to });
                }
                ServerMessage::DeliveryUpdate { updates } => {
                    for update in updates {
                        // Durable relay receipts, in the desktop's delivery vocabulary.
                        let status = match update.status.as_str() {
                            "delivered" => "received",
                            "stored" => "stored_offline",
                            "rejected" => "failed",
                            _ => continue,
                        };
                        let status = {
                            let db = self.db.lock().map_err(|e| e.to_string())?;
                            db.record_delivery(
                                &update.message_id,
                                &update.recipient_device_id,
                                status,
                            )
                            .map_err(|e| e.to_string())?
                        };
                        events.push(RelayEvent::DeliveryUpdate {
                            message_id: update.message_id,
                            recipient_device_id: update.recipient_device_id,
                            status,
                        });
                    }
                }
                ServerMessage::MessageError {
                    message_id,
                    code,
                    message,
                    ..
                } => {
                    if let Ok(db) = self.db.lock() {
                        let _ = db.update_message_state(&message_id, "failed");
                    }
                    events.push(RelayEvent::DeliveryUpdate {
                        message_id,
                        recipient_device_id: String::new(),
                        status: "failed".into(),
                    });
                    events.push(RelayEvent::Error { code, message });
                }
                ServerMessage::Error { code, message } => {
                    events.push(RelayEvent::Error { code, message });
                }
                _ => {}
            }
        }

        Ok(PollMessagesResult { messages, events })
    }

    /// Verifies and stores one relay envelope. `Err` leaves it unacknowledged,
    /// for example until the sender becomes a contact.
    fn receive_envelope(
        &self,
        user_id: &str,
        device_id: &str,
        envelope: SignedEnvelopeV2,
    ) -> Result<(AckOutcome, Vec<IncomingMessage>), PendingReason> {
        let storage = |e: DbError| ("storage_error".to_string(), e.to_string());
        if envelope.protocol_version != PROTOCOL_V2
            || envelope.recipient_user_id != user_id
            || envelope.recipient_device_id != device_id
            || envelope.conversation_id
                != canonical_conversation_id(user_id, &envelope.sender_user_id)
        {
            return Ok((AckOutcome::Rejected, Vec::new()));
        }
        let db = self
            .db
            .lock()
            .map_err(|e| ("storage_error".to_string(), e.to_string()))?;
        let contact = db
            .get_contact(&envelope.sender_user_id)
            .map_err(storage)?
            .ok_or((
                "sender_key_unavailable".to_string(),
                "Sender is not a contact; message left pending".to_string(),
            ))?;
        if contact.key_changed {
            return Err((
                "sender_key_changed".to_string(),
                "Sender key changed; message left pending for verification".to_string(),
            ));
        }
        let signing_key: [u8; 32] = contact
            .ed25519_pk
            .and_then(|key| key.try_into().ok())
            .ok_or((
                "sender_key_unavailable".to_string(),
                "Sender signing key is unavailable".to_string(),
            ))?;
        let Ok(signed) = envelope.signing_bytes() else {
            return Ok((AckOutcome::Rejected, Vec::new()));
        };
        if !crypto::verify_with_public_key(&signed, &envelope.signature, &signing_key)
            .unwrap_or(false)
        {
            return Ok((AckOutcome::Rejected, Vec::new()));
        }

        let mut incoming = IncomingMessage {
            message_id: envelope.message_id,
            from: envelope.sender_user_id,
            conversation_id: envelope.conversation_id,
            ciphertext: envelope.ciphertext,
            signature: envelope.signature,
            sender_device_id: envelope.sender_device_id,
            sender_seq: envelope.sender_seq,
            prev_hash: envelope.prev_hash,
            recipient_device_id: envelope.recipient_device_id,
            timestamp: envelope.sent_at,
            local_state: "received".to_string(),
        };
        let mut model = build_incoming_message_model(incoming.clone());
        if let Some(existing) = db.get_message(&model.id).map_err(storage)? {
            let replay = existing.conversation_id == model.conversation_id
                && existing.sender_id == model.sender_id
                && existing.sender_device_id == model.sender_device_id
                && existing.sender_seq == model.sender_seq
                && existing.prev_hash == model.prev_hash
                && existing.ciphertext == model.ciphertext
                && existing.signature == model.signature
                && db.incoming_chain_version(&model.id).map_err(storage)? == 2;
            let outcome = if replay {
                AckOutcome::Processed
            } else {
                AckOutcome::Rejected
            };
            return Ok((outcome, Vec::new()));
        }
        let previous = db
            .get_latest_received_for_version(&model.conversation_id, &model.sender_device_id, 2)
            .map_err(storage)?;
        if MessageIntegrityStore::validate_next(previous.as_ref(), &model) != IntegrityResult::Valid
        {
            model.local_state = "integrity_failed".into();
            incoming.local_state = "integrity_failed".into();
        }
        let mut stored: Vec<IncomingMessage> = db
            .insert_received(&model, 2)
            .map_err(storage)?
            .into_iter()
            .map(|m| IncomingMessage {
                message_id: m.id,
                from: m.sender_id,
                conversation_id: m.conversation_id,
                ciphertext: m.ciphertext,
                signature: m.signature,
                sender_device_id: m.sender_device_id,
                sender_seq: m.sender_seq,
                prev_hash: m.prev_hash,
                recipient_device_id: incoming.recipient_device_id.clone(),
                timestamp: m.timestamp,
                local_state: m.local_state,
            })
            .collect();
        stored.push(incoming);
        Ok((AckOutcome::Processed, stored))
    }

    pub fn get_local_messages(
        &self,
        conversation_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<MessageModel>, String> {
        let db = self.db.lock().map_err(|e| e.to_string())?;
        db.get_messages_by_conversation(conversation_id, limit, offset)
            .map_err(|e| e.to_string())
    }

    // Contacts

    pub fn add_contact(
        &self,
        user_id: String,
        username: String,
        public_key: Vec<u8>,
        ed25519_pk: Option<Vec<u8>>,
    ) -> Result<(), String> {
        validate_contact_input(&user_id, &username, &public_key, ed25519_pk.as_deref())?;

        let contact = ContactModel {
            user_id: user_id.trim().to_string(),
            username: username.trim().to_string(),
            fingerprint: fingerprint(ed25519_pk.as_deref().unwrap_or(&public_key)),
            public_key,
            ed25519_pk,
            trust_state: "unverified".to_string(),
            key_changed: false,
            added_at: chrono::Utc::now().timestamp(),
        };

        let db = self.db.lock().map_err(|e| e.to_string())?;
        db.insert_contact(&contact).map_err(|e| e.to_string())
    }

    pub fn get_contacts(&self) -> Result<Vec<ContactModel>, String> {
        let db = self.db.lock().map_err(|e| e.to_string())?;
        db.get_contacts().map_err(|e| e.to_string())
    }

    pub fn remove_contact(&self, user_id: &str) -> Result<(), String> {
        let db = self.db.lock().map_err(|e| e.to_string())?;
        db.delete_contact(user_id).map_err(|e| e.to_string())
    }

    pub fn set_contact_trust(&self, user_id: &str, trust_state: &str) -> Result<(), String> {
        match trust_state {
            "unverified" | "verified" | "key_changed" => {}
            _ => return Err("Invalid trust state".to_string()),
        }
        let db = self.db.lock().map_err(|e| e.to_string())?;
        db.update_contact_trust(user_id, trust_state)
            .map_err(|e| e.to_string())
    }

    // Storage

    pub fn get_storage_stats(&self) -> Result<StorageStatsResult, String> {
        let db = self.db.lock().map_err(|e| e.to_string())?;
        let stats = db.get_storage_stats().map_err(|e| e.to_string())?;
        Ok(StorageStatsResult {
            message_count: stats.message_count,
            ciphertext_bytes: stats.ciphertext_bytes,
            attachment_count: stats.attachment_count,
            attachment_bytes: stats.attachment_bytes,
            conversation_count: stats.conversation_count,
            total_bytes: stats.ciphertext_bytes + stats.attachment_bytes,
        })
    }

    pub fn clear_expired_messages(&self) -> Result<usize, String> {
        let db = self.db.lock().map_err(|e| e.to_string())?;
        let now = chrono::Utc::now().timestamp();
        db.clear_expired_messages(now).map_err(|e| e.to_string())
    }

    pub fn clear_unpinned_attachments(&self) -> Result<usize, String> {
        let db = self.db.lock().map_err(|e| e.to_string())?;
        db.clear_unpinned_attachments().map_err(|e| e.to_string())
    }
}

/// The wire envelope for one recipient device of a locally stored message.
fn outgoing_envelope(
    message: &MessageModel,
    payload: &EncryptedPayload,
    sender_seq: i64,
    prev_hash: Vec<u8>,
) -> SignedEnvelopeV2 {
    SignedEnvelopeV2 {
        protocol_version: PROTOCOL_V2,
        message_id: message.id.clone(),
        conversation_id: message.conversation_id.clone(),
        sender_user_id: message.sender_id.clone(),
        sender_device_id: message.sender_device_id.clone(),
        recipient_user_id: payload.recipient_user_id.clone(),
        recipient_device_id: payload.recipient_device_id.clone(),
        sender_seq,
        prev_hash,
        sent_at: message.timestamp,
        message_type: message.message_type.clone(),
        ciphertext: payload.ciphertext.clone(),
        signature: payload.signature.clone(),
    }
}
