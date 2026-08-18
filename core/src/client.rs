//! Stateful client facade: owns the local store, the relay connection and the
//! incoming-message channel. Platform shells (Tauri commands, the Android FFI
//! layer) hold one instance and delegate to it.
//!
//! Locking rules: `db` is a blocking mutex guarding the rusqlite connection —
//! never hold it across an await. The websocket handles use async mutexes.

use std::sync::Mutex;
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;

use liteseal_shared::{
    crypto,
    protocol::{EncryptedPayload, ServerMessage, SignedEnvelopeV2, PROTOCOL_V2},
};
use serde::{Deserialize, Serialize};

use crate::api::normalize_server_url;
use crate::chat::{
    build_incoming_message_model, build_outgoing_message_model, canonical_conversation_id,
    next_chain_state, IncomingMessage, PollMessagesResult, RelayEvent, SendMessageResult,
};
use crate::contacts::{fingerprint, validate_contact_input};
use crate::db::models::{ContactModel, MessageModel};
use crate::db::repository::MessageRepository;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurePollResult {
    pub messages: Vec<DisplayMessage>,
    pub events: Vec<RelayEvent>,
}

pub struct LitesealClient {
    pub db: Mutex<MessageRepository>,
    pub ws_client: AsyncMutex<Option<WebSocketClient>>,
    pub msg_receiver: AsyncMutex<Option<MessageReceiver>>,
}

impl LitesealClient {
    pub fn new(db_path: &str) -> Result<Self, String> {
        let db = MessageRepository::new(db_path).map_err(|e| e.to_string())?;
        Ok(Self {
            db: Mutex::new(db),
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
        if device_id.trim().is_empty() {
            return Err("Device id is required to connect".to_string());
        }
        let server_url = normalize_server_url(&server_url)?;
        let ws_url = server_url
            .replace("http://", "ws://")
            .replace("https://", "wss://");
        let ws_url = format!("{}/ws", ws_url);

        let (client, rx) = WebSocketClient::connect(&ws_url, user_id, token, device_id).await?;

        let mut ws_guard = self.ws_client.lock().await;
        *ws_guard = Some(client);

        let mut recv_guard = self.msg_receiver.lock().await;
        *recv_guard = Some(rx);

        Ok(())
    }

    pub async fn disconnect(&self) {
        let mut ws_guard = self.ws_client.lock().await;
        if let Some(client) = ws_guard.as_mut() {
            client.disconnect().await;
        }
        *ws_guard = None;

        let mut recv_guard = self.msg_receiver.lock().await;
        *recv_guard = None;
    }

    // Messaging

    pub async fn send_message(
        &self,
        sender_id: String,
        ciphertext: Vec<u8>,
        signature: Vec<u8>,
        sender_device_id: String,
        payloads: Vec<EncryptedPayload>,
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
        let conversation_id = canonical_conversation_id(&sender_id, &recipient_user_id);

        let ws_guard = self.ws_client.lock().await;
        let client = ws_guard.as_ref().ok_or("Not connected to relay server")?;

        let message_id = Uuid::new_v4().to_string();
        let timestamp = chrono::Utc::now().timestamp_millis();

        // The sender owns its hash chain: seq and prev_hash come from the last
        // message this device stored for the conversation, matching what
        // recipients validate in MessageIntegrityStore::validate_next.
        let (sender_seq, prev_hash) = {
            let db = self.db.lock().map_err(|e| e.to_string())?;
            let previous = db
                .get_latest_message_for_sender(&conversation_id, &sender_device_id)
                .map_err(|e| e.to_string())?;
            next_chain_state(previous.as_ref())
        };

        let outgoing = build_outgoing_message_model(
            message_id.clone(),
            conversation_id.clone(),
            sender_id,
            sender_device_id.clone(),
            sender_seq,
            timestamp,
            ciphertext.clone(),
            signature.clone(),
            prev_hash.clone(),
            "pending",
        );

        {
            let db = self.db.lock().map_err(|e| e.to_string())?;
            db.insert_message(&outgoing).map_err(|e| e.to_string())?;
        }

        if let Err(err) = client
            .send_message(
                message_id.clone(),
                conversation_id,
                ciphertext,
                signature,
                sender_device_id,
                sender_seq,
                prev_hash,
                payloads,
            )
            .await
        {
            if let Ok(db) = self.db.lock() {
                let _ = db.update_message_state(&message_id, "failed");
            }
            return Err(err);
        }

        Ok(SendMessageResult { message_id })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn send_text_v2(
        &self,
        sender_user_id: &str,
        sender_device_id: &str,
        sender_secret_key: &[u8; 32],
        signing_secret_key: &[u8; 64],
        recipient_user_id: &str,
        recipient_device_id: &str,
        recipient_public_key: &[u8; 32],
        plaintext: &str,
    ) -> Result<SendMessageResult, String> {
        if plaintext.is_empty() || plaintext.len() > 8 * 1024 {
            return Err("Text messages must contain between 1 and 8192 bytes".to_string());
        }
        let conversation_id = canonical_conversation_id(sender_user_id, recipient_user_id);
        let message_id = Uuid::new_v4().to_string();
        let timestamp = chrono::Utc::now().timestamp_millis();
        let (sender_seq, prev_hash) = {
            let db = self.db.lock().map_err(|e| e.to_string())?;
            let previous = db
                .get_latest_message_for_sender(&conversation_id, sender_device_id)
                .map_err(|e| e.to_string())?;
            next_chain_state(previous.as_ref())
        };
        let ciphertext = crypto::encrypt(
            plaintext.as_bytes(),
            recipient_public_key,
            sender_secret_key,
        )
        .map_err(|e| e.to_string())?;
        let mut envelope = SignedEnvelopeV2 {
            protocol_version: PROTOCOL_V2,
            message_id: message_id.clone(),
            conversation_id: conversation_id.clone(),
            sender_user_id: sender_user_id.to_string(),
            sender_device_id: sender_device_id.to_string(),
            recipient_user_id: recipient_user_id.to_string(),
            recipient_device_id: recipient_device_id.to_string(),
            sender_seq,
            prev_hash: prev_hash.clone(),
            sent_at: timestamp,
            message_type: "text".to_string(),
            ciphertext: ciphertext.clone(),
            signature: Vec::new(),
        };
        envelope.signature = crypto::sign(
            &envelope.signing_bytes().map_err(|e| e.to_string())?,
            signing_secret_key,
        )
        .map_err(|e| e.to_string())?;

        let outgoing = build_outgoing_message_model(
            message_id.clone(),
            conversation_id,
            sender_user_id.to_string(),
            sender_device_id.to_string(),
            sender_seq,
            timestamp,
            ciphertext,
            envelope.signature.clone(),
            prev_hash,
            "pending_v2",
        );
        self.db
            .lock()
            .map_err(|e| e.to_string())?
            .insert_message(&outgoing)
            .map_err(|e| e.to_string())?;

        let send_result = {
            let ws = self.ws_client.lock().await;
            let client = ws.as_ref().ok_or("Not connected to relay server")?;
            client.send_v2(envelope).await
        };
        if let Err(error) = send_result {
            if let Ok(db) = self.db.lock() {
                let _ = db.update_message_state(&message_id, "failed_v2");
            }
            return Err(error);
        }
        Ok(SendMessageResult { message_id })
    }

    pub async fn poll_secure_messages(
        &self,
        user_id: &str,
        device_id: &str,
        recipient_secret_key: &[u8; 32],
    ) -> Result<SecurePollResult, String> {
        let mut recv_guard = self.msg_receiver.lock().await;
        let rx = recv_guard.as_mut().ok_or("Not connected to relay server")?;
        let mut messages = Vec::new();
        let mut events = Vec::new();

        while let Ok(message) = rx.try_recv() {
            match message {
                ServerMessage::MessageV2 { envelope, .. } => {
                    match self.process_v2_message(
                        user_id,
                        device_id,
                        recipient_secret_key,
                        envelope,
                    ) {
                        Ok((display, should_ack)) => {
                            if should_ack {
                                self.ack_after_persist(&display.id).await?;
                            }
                            if display.local_state != "quarantined" {
                                messages.push(display);
                            }
                        }
                        Err((code, message)) => {
                            events.push(RelayEvent::Error { code, message });
                        }
                    }
                }
                ServerMessage::Message {
                    message_id,
                    from,
                    conversation_id: _,
                    ciphertext,
                    signature,
                    sender_device_id,
                    sender_seq,
                    prev_hash,
                    recipient_device_id,
                    timestamp,
                } => {
                    match self.process_v1_message(
                        user_id,
                        device_id,
                        recipient_secret_key,
                        message_id,
                        from,
                        ciphertext,
                        signature,
                        sender_device_id,
                        sender_seq,
                        prev_hash,
                        recipient_device_id,
                        timestamp,
                    ) {
                        Ok((display, should_ack)) => {
                            if should_ack {
                                self.ack_after_persist(&display.id).await?;
                            }
                            if display.local_state != "quarantined" {
                                messages.push(display);
                            }
                        }
                        Err((code, message)) => {
                            events.push(RelayEvent::Error { code, message });
                        }
                    }
                }
                ServerMessage::Delivered { message_id } => {
                    self.update_delivery_state(&message_id, "delivered", &mut events)?;
                }
                ServerMessage::Offline { message_id, to } => {
                    if let Ok(db) = self.db.lock() {
                        let _ = db.update_message_state(&message_id, "offline");
                    }
                    events.push(RelayEvent::Offline { message_id, to });
                }
                ServerMessage::DeliveryUpdate { updates } => {
                    for update in updates {
                        if let Ok(db) = self.db.lock() {
                            let _ = db.update_message_state(&update.message_id, &update.status);
                        }
                        events.push(RelayEvent::DeliveryUpdate {
                            message_id: update.message_id,
                            recipient_device_id: update.recipient_device_id,
                            status: update.status,
                        });
                    }
                }
                ServerMessage::Error { code, message } => {
                    events.push(RelayEvent::Error { code, message });
                }
                ServerMessage::AuthOk | ServerMessage::AuthFail { .. } => {}
            }
        }
        Ok(SecurePollResult { messages, events })
    }

    fn process_v2_message(
        &self,
        user_id: &str,
        device_id: &str,
        recipient_secret_key: &[u8; 32],
        envelope: SignedEnvelopeV2,
    ) -> Result<(DisplayMessage, bool), (String, String)> {
        if envelope.protocol_version != PROTOCOL_V2
            || envelope.recipient_user_id != user_id
            || envelope.recipient_device_id != device_id
            || envelope.conversation_id
                != canonical_conversation_id(user_id, &envelope.sender_user_id)
        {
            return self.quarantine_v2(envelope, "metadata_invalid");
        }
        let contact = self
            .db
            .lock()
            .map_err(|e| ("storage_error".to_string(), e.to_string()))?
            .get_contact(&envelope.sender_user_id)
            .map_err(|e| ("storage_error".to_string(), e.to_string()))?
            .ok_or((
                "sender_key_unavailable".to_string(),
                "Sender is not an accepted contact; message left pending".to_string(),
            ))?;
        if contact.key_changed {
            return Err((
                "sender_key_changed".to_string(),
                "Sender key changed; message left pending for verification".to_string(),
            ));
        }
        let signing_key: [u8; 32] = contact
            .ed25519_pk
            .ok_or((
                "sender_key_unavailable".to_string(),
                "Sender signing key is unavailable".to_string(),
            ))?
            .try_into()
            .map_err(|_| {
                (
                    "sender_key_invalid".to_string(),
                    "Sender signing key is invalid".to_string(),
                )
            })?;
        let valid_signature = crypto::verify_with_public_key(
            &envelope
                .signing_bytes()
                .map_err(|e| ("invalid_envelope".to_string(), e.to_string()))?,
            &envelope.signature,
            &signing_key,
        )
        .map_err(|e| ("verification_error".to_string(), e.to_string()))?;
        if !valid_signature {
            return self.quarantine_v2(envelope, "signature_invalid");
        }

        let incoming = IncomingMessage {
            message_id: envelope.message_id.clone(),
            from: envelope.sender_user_id.clone(),
            conversation_id: envelope.conversation_id.clone(),
            ciphertext: envelope.ciphertext.clone(),
            signature: envelope.signature.clone(),
            sender_device_id: envelope.sender_device_id.clone(),
            sender_seq: envelope.sender_seq,
            prev_hash: envelope.prev_hash.clone(),
            recipient_device_id: envelope.recipient_device_id.clone(),
            timestamp: envelope.sent_at,
            local_state: "received_v2".to_string(),
        };
        let model = build_incoming_message_model(incoming);
        let db = self
            .db
            .lock()
            .map_err(|e| ("storage_error".to_string(), e.to_string()))?;
        let previous = db
            .get_latest_message_for_sender(&model.conversation_id, &model.sender_device_id)
            .map_err(|e| ("storage_error".to_string(), e.to_string()))?;
        if MessageIntegrityStore::validate_next(previous.as_ref(), &model) != IntegrityResult::Valid
        {
            drop(db);
            return self.quarantine_v2(envelope, "chain_invalid");
        }
        let sender_public_key: [u8; 32] = contact.public_key.try_into().map_err(|_| {
            (
                "sender_key_invalid".to_string(),
                "Sender encryption key is invalid".to_string(),
            )
        })?;
        let plaintext = match crypto::decrypt(
            &envelope.ciphertext,
            &sender_public_key,
            recipient_secret_key,
        ) {
            Ok(plaintext) => plaintext,
            Err(_) => {
                drop(db);
                return self.quarantine_v2(envelope, "decryption_failed");
            }
        };
        let plaintext = match String::from_utf8(plaintext) {
            Ok(plaintext) => plaintext,
            Err(_) => {
                drop(db);
                return self.quarantine_v2(envelope, "invalid_plaintext");
            }
        };
        db.insert_message(&model)
            .map_err(|e| ("storage_error".to_string(), e.to_string()))?;
        Ok((
            display_from_model(&model, plaintext, PROTOCOL_V2, "verified_v2"),
            true,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn process_v1_message(
        &self,
        user_id: &str,
        device_id: &str,
        recipient_secret_key: &[u8; 32],
        message_id: String,
        from: String,
        ciphertext: Vec<u8>,
        signature: Vec<u8>,
        sender_device_id: String,
        sender_seq: i64,
        prev_hash: Vec<u8>,
        recipient_device_id: String,
        timestamp: i64,
    ) -> Result<(DisplayMessage, bool), (String, String)> {
        if recipient_device_id != device_id {
            return Err((
                "recipient_mismatch".to_string(),
                "Legacy message targets a different device".to_string(),
            ));
        }
        let conversation_id = canonical_conversation_id(user_id, &from);
        let contact = self
            .db
            .lock()
            .map_err(|e| ("storage_error".to_string(), e.to_string()))?
            .get_contact(&from)
            .map_err(|e| ("storage_error".to_string(), e.to_string()))?
            .ok_or((
                "sender_key_unavailable".to_string(),
                "Legacy sender key is unavailable; message left pending".to_string(),
            ))?;
        let signing_key: [u8; 32] = contact
            .ed25519_pk
            .ok_or((
                "sender_key_unavailable".to_string(),
                "Legacy sender signing key is unavailable".to_string(),
            ))?
            .try_into()
            .map_err(|_| {
                (
                    "sender_key_invalid".to_string(),
                    "Invalid sender key".to_string(),
                )
            })?;
        let mut model = build_incoming_message_model(IncomingMessage {
            message_id,
            from: from.clone(),
            conversation_id,
            ciphertext: ciphertext.clone(),
            signature: signature.clone(),
            sender_device_id,
            sender_seq,
            prev_hash,
            recipient_device_id,
            timestamp,
            local_state: "received_v1_legacy".to_string(),
        });
        if !crypto::verify_with_public_key(&ciphertext, &signature, &signing_key)
            .map_err(|e| ("verification_error".to_string(), e.to_string()))?
        {
            return self.quarantine_model(&mut model, 1, "legacy_signature_invalid");
        }
        let sender_public_key: [u8; 32] = contact.public_key.try_into().map_err(|_| {
            (
                "sender_key_invalid".to_string(),
                "Invalid sender key".to_string(),
            )
        })?;
        let plaintext = match crypto::decrypt(&ciphertext, &sender_public_key, recipient_secret_key)
        {
            Ok(plaintext) => plaintext,
            Err(_) => return self.quarantine_model(&mut model, 1, "decryption_failed"),
        };
        let plaintext = match String::from_utf8(plaintext) {
            Ok(plaintext) => plaintext,
            Err(_) => return self.quarantine_model(&mut model, 1, "invalid_plaintext"),
        };
        self.db
            .lock()
            .map_err(|e| ("storage_error".to_string(), e.to_string()))?
            .insert_message(&model)
            .map_err(|e| ("storage_error".to_string(), e.to_string()))?;
        Ok((
            display_from_model(&model, plaintext, 1, "legacy_ciphertext_verified"),
            true,
        ))
    }

    fn quarantine_v2(
        &self,
        envelope: SignedEnvelopeV2,
        reason: &str,
    ) -> Result<(DisplayMessage, bool), (String, String)> {
        let model = build_incoming_message_model(IncomingMessage {
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
            local_state: "quarantined".to_string(),
        });
        self.db
            .lock()
            .map_err(|e| ("storage_error".to_string(), e.to_string()))?
            .insert_message(&model)
            .map_err(|e| ("storage_error".to_string(), e.to_string()))?;
        Ok((
            display_from_model(&model, String::new(), PROTOCOL_V2, reason),
            true,
        ))
    }

    fn quarantine_model(
        &self,
        model: &mut MessageModel,
        protocol_version: u8,
        reason: &str,
    ) -> Result<(DisplayMessage, bool), (String, String)> {
        model.local_state = "quarantined".to_string();
        model.protocol_version = i64::from(protocol_version);
        model.verification_state = reason.to_string();
        model.quarantined = true;
        self.db
            .lock()
            .map_err(|e| ("storage_error".to_string(), e.to_string()))?
            .insert_message(model)
            .map_err(|e| ("storage_error".to_string(), e.to_string()))?;
        Ok((
            display_from_model(model, String::new(), protocol_version, reason),
            true,
        ))
    }

    async fn ack_after_persist(&self, message_id: &str) -> Result<(), String> {
        let ws = self.ws_client.lock().await;
        let client = ws.as_ref().ok_or("Not connected to relay server")?;
        client.send_ack(message_id.to_string()).await
    }

    fn update_delivery_state(
        &self,
        message_id: &str,
        state: &str,
        events: &mut Vec<RelayEvent>,
    ) -> Result<(), String> {
        if let Ok(db) = self.db.lock() {
            let _ = db.update_message_state(message_id, state);
        }
        events.push(RelayEvent::Delivered {
            message_id: message_id.to_string(),
        });
        Ok(())
    }

    pub async fn poll_messages(&self) -> Result<PollMessagesResult, String> {
        let mut recv_guard = self.msg_receiver.lock().await;
        let rx = recv_guard.as_mut().ok_or("Not connected to relay server")?;

        let mut messages = Vec::new();
        let mut events = Vec::new();

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
                    prev_hash,
                    recipient_device_id,
                    timestamp,
                } => {
                    if let Some(ws) = self.ws_client.lock().await.as_ref() {
                        let _ = ws.send_ack(message_id.clone()).await;
                    }
                    let mut incoming = IncomingMessage {
                        message_id,
                        from,
                        conversation_id,
                        ciphertext,
                        signature,
                        sender_device_id,
                        sender_seq,
                        prev_hash,
                        recipient_device_id,
                        timestamp,
                        local_state: "received".to_string(),
                    };
                    if let Ok(db) = self.db.lock() {
                        let mut model = build_incoming_message_model(incoming.clone());
                        let previous = db
                            .get_latest_message_for_sender(
                                &model.conversation_id,
                                &model.sender_device_id,
                            )
                            .ok()
                            .flatten();
                        if MessageIntegrityStore::validate_next(previous.as_ref(), &model)
                            != IntegrityResult::Valid
                        {
                            model.local_state = "integrity_failed".to_string();
                            incoming.local_state = "integrity_failed".to_string();
                        }
                        let _ = db.insert_message(&model);
                    }
                    messages.push(incoming);
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
                        if let Ok(db) = self.db.lock() {
                            let _ = db.update_message_state(&update.message_id, &update.status);
                        }
                        events.push(RelayEvent::DeliveryUpdate {
                            message_id: update.message_id,
                            recipient_device_id: update.recipient_device_id,
                            status: update.status,
                        });
                    }
                }
                ServerMessage::Error { code, message } => {
                    events.push(RelayEvent::Error { code, message });
                }
                _ => {}
            }
        }

        Ok(PollMessagesResult { messages, events })
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

    pub fn get_display_messages(
        &self,
        user_id: &str,
        recipient_secret_key: &[u8; 32],
        conversation_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DisplayMessage>, String> {
        let db = self.db.lock().map_err(|e| e.to_string())?;
        let stored = db
            .get_messages_by_conversation(conversation_id, limit, offset)
            .map_err(|e| e.to_string())?;
        let mut display = Vec::with_capacity(stored.len());
        for message in stored {
            let protocol_version = if message.local_state.contains("v1_legacy") {
                1
            } else {
                PROTOCOL_V2
            };
            if message.local_state == "quarantined" {
                display.push(display_from_model(
                    &message,
                    String::new(),
                    protocol_version,
                    "quarantined",
                ));
                continue;
            }
            let peer_id = if message.sender_id == user_id {
                conversation_id
                    .strip_prefix("dm:")
                    .and_then(|members| members.split(':').find(|member| *member != user_id))
                    .unwrap_or_default()
            } else {
                &message.sender_id
            };
            let Some(contact) = db.get_contact(peer_id).map_err(|e| e.to_string())? else {
                continue;
            };
            let peer_key: [u8; 32] = match contact.public_key.try_into() {
                Ok(key) => key,
                Err(_) => continue,
            };
            let plaintext = crypto::decrypt(&message.ciphertext, &peer_key, recipient_secret_key)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .unwrap_or_else(|| "[decryption unavailable]".to_string());
            let verification = if protocol_version == 1 {
                "legacy_ciphertext_verified"
            } else if message.sender_id == user_id {
                "authored_v2"
            } else {
                "verified_v2"
            };
            display.push(display_from_model(
                &message,
                plaintext,
                protocol_version,
                verification,
            ));
        }
        Ok(display)
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

fn display_from_model(
    model: &MessageModel,
    plaintext: String,
    protocol_version: u8,
    verification_state: &str,
) -> DisplayMessage {
    DisplayMessage {
        id: model.id.clone(),
        conversation_id: model.conversation_id.clone(),
        sender_id: model.sender_id.clone(),
        sender_device_id: model.sender_device_id.clone(),
        sender_seq: model.sender_seq,
        timestamp: model.timestamp,
        plaintext,
        local_state: model.local_state.clone(),
        protocol_version,
        verification_state: verification_state.to_string(),
    }
}
