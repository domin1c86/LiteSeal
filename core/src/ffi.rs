//! UniFFI bindings for the React Native Android app (feature `ffi`).
//!
//! Mirrors the core DTOs as uniffi records instead of annotating the core
//! types directly, so the desktop build stays free of uniffi and the FFI
//! surface can evolve independently of the serde/JSON shapes.

use std::sync::Arc;

use liteseal_shared::protocol::EncryptedPayload;

use crate::api;
use crate::chat;
use crate::client::LitesealClient;
use crate::db::models::{ContactModel, MessageModel};

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CoreError {
    #[error("{message}")]
    Failure { message: String },
}

impl From<String> for CoreError {
    fn from(message: String) -> Self {
        CoreError::Failure { message }
    }
}

type FfiResult<T> = Result<T, CoreError>;

// ---- Records mirrored from core/shared types ----

#[derive(uniffi::Record)]
pub struct FfiEncryptedPayload {
    pub recipient_user_id: String,
    pub recipient_device_id: String,
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
}

impl From<FfiEncryptedPayload> for EncryptedPayload {
    fn from(p: FfiEncryptedPayload) -> Self {
        EncryptedPayload {
            recipient_user_id: p.recipient_user_id,
            recipient_device_id: p.recipient_device_id,
            ciphertext: p.ciphertext,
            signature: p.signature,
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiMessage {
    pub id: String,
    pub conversation_id: String,
    pub sender_id: String,
    pub sender_device_id: String,
    pub sender_seq: i64,
    pub timestamp: i64,
    pub message_type: String,
    pub local_state: String,
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
    pub prev_hash: Vec<u8>,
}

impl From<MessageModel> for FfiMessage {
    fn from(m: MessageModel) -> Self {
        FfiMessage {
            id: m.id,
            conversation_id: m.conversation_id,
            sender_id: m.sender_id,
            sender_device_id: m.sender_device_id,
            sender_seq: m.sender_seq,
            timestamp: m.timestamp,
            message_type: m.message_type,
            local_state: m.local_state,
            ciphertext: m.ciphertext,
            signature: m.signature,
            prev_hash: m.prev_hash,
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiContact {
    pub user_id: String,
    pub username: String,
    pub public_key: Vec<u8>,
    pub ed25519_pk: Option<Vec<u8>>,
    pub trust_state: String,
    pub fingerprint: String,
    pub key_changed: bool,
    pub added_at: i64,
}

impl From<ContactModel> for FfiContact {
    fn from(c: ContactModel) -> Self {
        FfiContact {
            user_id: c.user_id,
            username: c.username,
            public_key: c.public_key,
            ed25519_pk: c.ed25519_pk,
            trust_state: c.trust_state,
            fingerprint: c.fingerprint,
            key_changed: c.key_changed,
            added_at: c.added_at,
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiIncomingMessage {
    pub message_id: String,
    pub from_user_id: String,
    pub conversation_id: String,
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
    pub sender_device_id: String,
    pub sender_seq: i64,
    pub prev_hash: Vec<u8>,
    pub recipient_device_id: String,
    pub timestamp: i64,
    pub local_state: String,
}

#[derive(uniffi::Enum)]
pub enum FfiRelayEvent {
    Delivered {
        message_id: String,
    },
    Offline {
        message_id: String,
        to: String,
    },
    DeliveryUpdate {
        message_id: String,
        recipient_device_id: String,
        status: String,
    },
    Error {
        code: String,
        message: String,
    },
}

#[derive(uniffi::Record)]
pub struct FfiPollResult {
    pub messages: Vec<FfiIncomingMessage>,
    pub events: Vec<FfiRelayEvent>,
}

#[derive(uniffi::Record)]
pub struct FfiStorageStats {
    pub message_count: i64,
    pub ciphertext_bytes: i64,
    pub attachment_count: i64,
    pub attachment_bytes: i64,
    pub conversation_count: i64,
    pub total_bytes: i64,
}

#[derive(uniffi::Record)]
pub struct FfiAuthResult {
    pub user_id: String,
    pub token: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub device_id: Option<String>,
}

impl From<api::RegisterResult> for FfiAuthResult {
    fn from(r: api::RegisterResult) -> Self {
        FfiAuthResult {
            user_id: r.user_id,
            token: r.token,
            access_token: r.access_token,
            refresh_token: r.refresh_token,
            device_id: r.device_id,
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiRemoteDevice {
    pub id: String,
    pub name: String,
    pub public_key: Vec<u8>,
    pub ed25519_pk: Vec<u8>,
    pub revoked: bool,
}

#[derive(uniffi::Record)]
pub struct FfiUserSearchResult {
    pub user_id: String,
    pub username: String,
    pub public_key: Vec<u8>,
    pub ed25519_pk: Option<Vec<u8>>,
}

#[derive(uniffi::Record)]
pub struct FfiKeypair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub ed25519_pk: Vec<u8>,
    pub ed25519_sk: Vec<u8>,
}

// ---- Stateless functions ----

#[uniffi::export(async_runtime = "tokio")]
pub async fn register(
    username: String,
    password: String,
    server_url: String,
    device_name: String,
    public_key: Vec<u8>,
    ed25519_pk: Vec<u8>,
) -> FfiResult<FfiAuthResult> {
    api::register(
        String::new(), // Mobile registration needs an invite field before it can use this server.
        username,
        password,
        server_url,
        &device_name,
        public_key,
        ed25519_pk,
    )
    .await
    .map(Into::into)
    .map_err(Into::into)
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn login(
    username: String,
    password: String,
    server_url: String,
    device_name: String,
    public_key: Vec<u8>,
    ed25519_pk: Vec<u8>,
    device_id: Option<String>,
) -> FfiResult<FfiAuthResult> {
    api::login(
        username,
        password,
        server_url,
        &device_name,
        public_key,
        ed25519_pk,
        device_id,
    )
    .await
    .map(Into::into)
    .map_err(Into::into)
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn refresh_session(
    server_url: String,
    refresh_token: String,
) -> FfiResult<FfiAuthResult> {
    api::refresh_session(server_url, refresh_token)
        .await
        .map(Into::into)
        .map_err(Into::into)
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn get_user_devices(
    server_url: String,
    user_id: String,
    access_token: String,
) -> FfiResult<Vec<FfiRemoteDevice>> {
    let devices = api::get_user_devices(server_url, user_id, access_token).await?;
    Ok(devices
        .into_iter()
        .map(|d| FfiRemoteDevice {
            id: d.id,
            name: d.name,
            public_key: d.public_key,
            ed25519_pk: d.ed25519_pk,
            revoked: d.revoked,
        })
        .collect())
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn search_users(
    server_url: String,
    query: String,
    access_token: String,
) -> FfiResult<Vec<FfiUserSearchResult>> {
    let results = api::search_users(server_url, query, access_token).await?;
    Ok(results
        .into_iter()
        .map(|r| FfiUserSearchResult {
            user_id: r.user_id,
            username: r.username,
            public_key: r.public_key,
            ed25519_pk: r.ed25519_pk,
        })
        .collect())
}

#[uniffi::export]
pub fn generate_keypair() -> FfiResult<FfiKeypair> {
    let (public_key, secret_key, ed25519_pk, ed25519_sk) = chat::generate_keypair()?;
    Ok(FfiKeypair {
        public_key,
        secret_key,
        ed25519_pk,
        ed25519_sk,
    })
}

#[uniffi::export]
pub fn encrypt_message(
    plaintext: Vec<u8>,
    recipient_public_key: Vec<u8>,
    sender_secret_key: Vec<u8>,
) -> FfiResult<Vec<u8>> {
    chat::encrypt_message(plaintext, recipient_public_key, sender_secret_key).map_err(Into::into)
}

#[uniffi::export]
pub fn decrypt_message(
    ciphertext: Vec<u8>,
    sender_public_key: Vec<u8>,
    recipient_secret_key: Vec<u8>,
) -> FfiResult<Vec<u8>> {
    chat::decrypt_message(ciphertext, sender_public_key, recipient_secret_key).map_err(Into::into)
}

#[uniffi::export]
pub fn sign_message(message: Vec<u8>, signing_key: Vec<u8>) -> FfiResult<Vec<u8>> {
    chat::sign_message(message, signing_key).map_err(Into::into)
}

#[uniffi::export]
pub fn verify_message(
    message: Vec<u8>,
    signature: Vec<u8>,
    sender_public_key: Vec<u8>,
) -> FfiResult<bool> {
    chat::verify_message(message, signature, sender_public_key).map_err(Into::into)
}

#[uniffi::export]
pub fn canonical_conversation_id(a: String, b: String) -> String {
    chat::canonical_conversation_id(&a, &b)
}

/// Same fingerprint derivation contacts are stored with, for displaying the
/// user's own key.
#[uniffi::export]
pub fn key_fingerprint(key: Vec<u8>) -> String {
    crate::contacts::fingerprint(&key)
}

// ---- Stateful client object ----

#[derive(uniffi::Object)]
pub struct LitesealCore {
    inner: LitesealClient,
}

#[uniffi::export(async_runtime = "tokio")]
impl LitesealCore {
    #[uniffi::constructor]
    pub fn new(db_path: String) -> FfiResult<Arc<Self>> {
        Ok(Arc::new(Self {
            inner: LitesealClient::new(&db_path)?,
        }))
    }

    pub async fn connect_relay(
        &self,
        server_url: String,
        user_id: String,
        token: String,
        device_id: String,
    ) -> FfiResult<()> {
        self.inner
            .connect_relay(server_url, user_id, token, device_id)
            .await
            .map_err(Into::into)
    }

    pub async fn disconnect(&self) {
        self.inner.disconnect().await;
    }

    pub async fn send_message(
        &self,
        sender_id: String,
        ciphertext: Vec<u8>,
        signature: Vec<u8>,
        sender_device_id: String,
        payloads: Vec<FfiEncryptedPayload>,
        signing_key: Vec<u8>,
    ) -> FfiResult<String> {
        let payloads = payloads.into_iter().map(Into::into).collect();
        // Signs the relay envelope; each payload's own signature is replaced.
        let signing_key: [u8; 64] = signing_key
            .try_into()
            .map_err(|_| "Invalid signing key length".to_string())?;
        let result = self
            .inner
            .send_message_with_id(
                sender_id,
                ciphertext,
                signature,
                sender_device_id,
                payloads,
                None,
                Some(&signing_key),
            )
            .await?;
        Ok(result.message_id)
    }

    pub async fn poll_messages(&self) -> FfiResult<FfiPollResult> {
        let result = self.inner.poll_messages().await?;
        Ok(FfiPollResult {
            messages: result
                .messages
                .into_iter()
                .map(|m| FfiIncomingMessage {
                    message_id: m.message_id,
                    from_user_id: m.from,
                    conversation_id: m.conversation_id,
                    ciphertext: m.ciphertext,
                    signature: m.signature,
                    sender_device_id: m.sender_device_id,
                    sender_seq: m.sender_seq,
                    prev_hash: m.prev_hash,
                    recipient_device_id: m.recipient_device_id,
                    timestamp: m.timestamp,
                    local_state: m.local_state,
                })
                .collect(),
            events: result
                .events
                .into_iter()
                .map(|e| match e {
                    chat::RelayEvent::Delivered { message_id } => {
                        FfiRelayEvent::Delivered { message_id }
                    }
                    chat::RelayEvent::Offline { message_id, to } => {
                        FfiRelayEvent::Offline { message_id, to }
                    }
                    chat::RelayEvent::DeliveryUpdate {
                        message_id,
                        recipient_device_id,
                        status,
                    } => FfiRelayEvent::DeliveryUpdate {
                        message_id,
                        recipient_device_id,
                        status,
                    },
                    chat::RelayEvent::Error { code, message } => {
                        FfiRelayEvent::Error { code, message }
                    }
                })
                .collect(),
        })
    }

    pub fn get_local_messages(
        &self,
        conversation_id: String,
        limit: i64,
        offset: i64,
    ) -> FfiResult<Vec<FfiMessage>> {
        let messages = self
            .inner
            .get_local_messages(&conversation_id, limit, offset)?;
        Ok(messages.into_iter().map(Into::into).collect())
    }

    pub fn add_contact(
        &self,
        user_id: String,
        username: String,
        public_key: Vec<u8>,
        ed25519_pk: Option<Vec<u8>>,
    ) -> FfiResult<()> {
        self.inner
            .add_contact(user_id, username, public_key, ed25519_pk)
            .map_err(Into::into)
    }

    pub fn get_contacts(&self) -> FfiResult<Vec<FfiContact>> {
        let contacts = self.inner.get_contacts()?;
        Ok(contacts.into_iter().map(Into::into).collect())
    }

    pub fn remove_contact(&self, user_id: String) -> FfiResult<()> {
        self.inner.remove_contact(&user_id).map_err(Into::into)
    }

    pub fn set_contact_trust(&self, user_id: String, trust_state: String) -> FfiResult<()> {
        self.inner
            .set_contact_trust(&user_id, &trust_state)
            .map_err(Into::into)
    }

    pub fn get_storage_stats(&self) -> FfiResult<FfiStorageStats> {
        let stats = self.inner.get_storage_stats()?;
        Ok(FfiStorageStats {
            message_count: stats.message_count,
            ciphertext_bytes: stats.ciphertext_bytes,
            attachment_count: stats.attachment_count,
            attachment_bytes: stats.attachment_bytes,
            conversation_count: stats.conversation_count,
            total_bytes: stats.total_bytes,
        })
    }

    pub fn clear_expired_messages(&self) -> FfiResult<u64> {
        Ok(self.inner.clear_expired_messages()? as u64)
    }

    pub fn clear_unpinned_attachments(&self) -> FfiResult<u64> {
        Ok(self.inner.clear_unpinned_attachments()? as u64)
    }
}
