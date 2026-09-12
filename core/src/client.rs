//! Stateful client facade: owns the local store, the relay connection and the
//! incoming-message channel. Platform shells (Electron sidecar, the Android FFI
//! layer) hold one instance and delegate to it.
//!
//! Locking rules: `db` is a blocking mutex guarding the rusqlite connection —
//! never hold it across an await. The websocket handles use async mutexes.

use std::sync::Mutex;
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;

use liteseal_shared::protocol::{EncryptedPayload, ServerMessage};
use serde::Serialize;

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
        )
        .await
    }

    pub async fn send_message_with_id(
        &self,
        sender_id: String,
        ciphertext: Vec<u8>,
        signature: Vec<u8>,
        sender_device_id: String,
        payloads: Vec<EncryptedPayload>,
        message_id: Option<String>,
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

        let message_id = message_id.unwrap_or_else(|| Uuid::new_v4().to_string());
        Uuid::parse_str(&message_id).map_err(|_| "Invalid message id")?;
        let (outgoing, payloads) = {
            let db = self.db.lock().map_err(|e| e.to_string())?;
            if let Some(existing) = db.get_message(&message_id).map_err(|e| e.to_string())? {
                if existing.sender_id != sender_id
                    || existing.sender_device_id != sender_device_id
                    || existing.conversation_id != conversation_id
                {
                    return Err("Message id belongs to another conversation or device".into());
                }
                let saved = serde_json::from_str(
                    &db.outgoing_payloads(&message_id)
                        .map_err(|e| e.to_string())?,
                )
                .map_err(|_| "Cannot read saved outgoing message")?;
                (existing, saved)
            } else {
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
                db.prepare_outgoing(
                    &outgoing,
                    &serde_json::to_string(&payloads).map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())?;
                (outgoing, payloads)
            }
        };

        if let Err(err) = client
            .send_message(
                message_id.clone(),
                conversation_id,
                outgoing.ciphertext,
                outgoing.signature,
                sender_device_id,
                outgoing.sender_seq,
                outgoing.prev_hash,
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

    pub async fn poll_messages(&self) -> Result<PollMessagesResult, String> {
        let mut recv_guard = self.msg_receiver.lock().await;
        let rx = recv_guard.as_mut().ok_or("Not connected to relay server")?;
        if rx.is_closed() && rx.is_empty() {
            return Err("Relay disconnected".into());
        }

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
