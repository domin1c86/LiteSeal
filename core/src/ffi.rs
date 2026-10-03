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
use crate::mobile_identity::{MobileIdentity, PublicIdentity};
use zeroize::Zeroizing;

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
    Typing {
        from_user_id: String,
        active: bool,
        expires_at: i64,
    },
}

#[derive(uniffi::Record)]
pub struct FfiPollResult {
    pub messages: Vec<FfiIncomingMessage>,
    pub events: Vec<FfiRelayEvent>,
    pub operations_changed: bool,
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
pub struct FfiUserSearchResult {
    pub user_id: String,
    pub username: String,
    pub public_key: Vec<u8>,
    pub ed25519_pk: Option<Vec<u8>>,
}

#[derive(uniffi::Record)]
pub struct FfiPublicIdentity {
    pub user_id: String,
    pub device_id: String,
    pub server_url: String,
    pub public_key: Vec<u8>,
    pub ed25519_pk: Vec<u8>,
    pub has_session: bool,
}
impl From<PublicIdentity> for FfiPublicIdentity {
    fn from(value: PublicIdentity) -> Self {
        Self {
            user_id: value.user_id,
            device_id: value.device_id,
            server_url: value.server_url,
            public_key: value.public_key,
            ed25519_pk: value.ed25519_pk,
            has_session: value.has_session,
        }
    }
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
    identity: MobileIdentity,
    auth_gate: tokio::sync::Mutex<()>,
}

#[uniffi::export(async_runtime = "tokio")]
impl LitesealCore {
    #[uniffi::constructor]
    pub fn new(db_path: String) -> FfiResult<Arc<Self>> {
        #[cfg(target_os = "android")]
        let db_path = {
            let root = crate::android_secret_store::native(7, &[])?;
            if root.is_empty() || root.len() > 4096 {
                return Err("移动存储目录无法验证".to_string().into());
            }
            let root = std::path::PathBuf::from(
                std::str::from_utf8(&root).map_err(|_| "移动存储目录无法验证".to_string())?,
            );
            let requested = std::path::Path::new(&db_path);
            if requested.file_name() != Some(std::ffi::OsStr::new("liteseal.db"))
                || requested
                    .parent()
                    .and_then(|p| std::fs::canonicalize(p).ok())
                    != Some(root.clone())
                || requested.exists()
                    && !std::fs::symlink_metadata(requested)
                        .map_err(|_| "移动存储目录无法验证".to_string())?
                        .is_file()
            {
                return Err("移动业务仅使用固定应用存储，拒绝任意路径"
                    .to_string()
                    .into());
            }
            root.join("liteseal.db")
                .to_str()
                .ok_or_else(|| "移动存储目录无法验证".to_string())?
                .to_owned()
        };
        #[cfg(target_os = "android")]
        let mut registry = android_cores()
            .lock()
            .map_err(|_| "移动运行时不可用".to_string())?;
        #[cfg(target_os = "android")]
        if let Some(core) = registry.get(&db_path).and_then(std::sync::Weak::upgrade) {
            return Ok(core);
        }
        let core = Arc::new(Self {
            inner: LitesealClient::new(&db_path)?,
            identity: MobileIdentity::open(
                &std::path::Path::new(&db_path).with_file_name("mobile-identity.bin"),
            )?,
            auth_gate: tokio::sync::Mutex::new(()),
        });
        #[cfg(target_os = "android")]
        registry.insert(db_path, Arc::downgrade(&core));
        Ok(core)
    }

    pub async fn restore_identity(&self) -> FfiResult<Option<FfiPublicIdentity>> {
        self.identity
            .restore_legacy()
            .map(|value| value.map(Into::into))
            .map_err(Into::into)
    }
    pub async fn native_register(
        &self,
        invite_code: String,
        username: String,
        password: String,
        server_url: String,
    ) -> FfiResult<FfiPublicIdentity> {
        crate::mobile_runtime::require_foreground()?;
        let _gate = self.auth_gate.lock().await;
        self.identity.restore_legacy()?;
        let snapshot = self.identity.begin_auth(&username, &server_url, true)?;
        let password = Zeroizing::new(password);
        let result = api::register(
            invite_code,
            username,
            password.to_string(),
            snapshot.data.server_url.clone(),
            "Android phone",
            snapshot.data.public_key.clone(),
            snapshot.data.ed25519_pk.clone(),
        )
        .await?;
        self.identity
            .commit_auth(&snapshot, result)
            .map(Into::into)
            .map_err(Into::into)
    }
    pub async fn native_login(
        &self,
        username: String,
        password: String,
        server_url: String,
    ) -> FfiResult<FfiPublicIdentity> {
        crate::mobile_runtime::require_foreground()?;
        let _gate = self.auth_gate.lock().await;
        self.identity.restore_legacy()?;
        let snapshot = self.identity.begin_auth(&username, &server_url, false)?;
        let password = Zeroizing::new(password);
        let result = api::login(
            username,
            password.to_string(),
            snapshot.data.server_url.clone(),
            "Android phone",
            snapshot.data.public_key.clone(),
            snapshot.data.ed25519_pk.clone(),
            Some(snapshot.data.device_id.clone()),
        )
        .await?;
        self.identity
            .commit_auth(&snapshot, result)
            .map(Into::into)
            .map_err(Into::into)
    }
    pub async fn resume_native(&self) -> FfiResult<()> {
        let _network = crate::mobile_runtime::NETWORK.lock().await;
        self.resume_native_inner().await
    }
}

#[cfg(target_os = "android")]
fn android_cores(
) -> &'static std::sync::Mutex<std::collections::HashMap<String, std::sync::Weak<LitesealCore>>> {
    static CORES: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, std::sync::Weak<LitesealCore>>>,
    > = std::sync::OnceLock::new();
    CORES.get_or_init(Default::default)
}

impl LitesealCore {
    fn foreground_local<T>(
        &self,
        action: impl FnOnce(&LitesealClient) -> Result<T, String>,
    ) -> FfiResult<T> {
        let _commit = crate::mobile_runtime::COMMIT
            .lock()
            .map_err(|_| "移动本机业务不可用".to_string())?;
        crate::mobile_runtime::require_foreground()?;
        let snapshot = self.identity.snapshot(false)?;
        self.identity.check(&snapshot)?;
        let value =
            action(&self.inner).map_err(|_| "移动本机业务失败；原数据已保留".to_string())?;
        self.identity.check(&snapshot)?;
        Ok(value)
    }
    /// Private worker entry. The caller supplies only the fixed app-private DB
    /// path through JNI; no result contains plaintext, credentials or keys.
    #[cfg(target_os = "android")]
    pub(crate) async fn background_round(&self) -> Result<usize, String> {
        let _network = crate::mobile_runtime::NETWORK.lock().await;
        if crate::mobile_runtime::foreground() {
            return Ok(0);
        }
        let epoch = crate::mobile_runtime::epoch();
        self.resume_native_inner()
            .await
            .map_err(|_| "原生会话补收暂不可用".to_string())?;
        crate::mobile_runtime::check(epoch)?;
        let result = async {
            let snapshot = self.identity.snapshot(true)?;
            let mut count = 0;
            // Bounded sleep yields to the runtime, letting initial offline
            // envelopes arrive. A process death leaves unacknowledged work at
            // the relay; already persisted messages can be safely replayed.
            for _ in 0..8 {
                crate::mobile_runtime::check(epoch)?;
                self.identity.check(&snapshot)?;
                let result = self.inner.poll_messages_bounded(32).await?;
                count += result.messages.len();
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
            count += crate::mobile_operations::poll(&self.inner, &self.identity).await?;
            crate::mobile_runtime::check(epoch)?;
            self.identity.check(&snapshot)?;
            Ok(count)
        }
        .await;
        self.inner.disconnect().await;
        result
    }
}
impl LitesealCore {
    pub(crate) async fn resume_native_inner(&self) -> FfiResult<()> {
        let _gate = self.auth_gate.lock().await;
        let mut snapshot = self.identity.snapshot(true)?;
        let connected = self
            .inner
            .connect_relay(
                snapshot.data.server_url.clone(),
                snapshot.data.user_id.clone(),
                snapshot.data.token.clone(),
                snapshot.data.device_id.clone(),
            )
            .await;
        if let Err(error) = connected {
            if !(error.contains("401") || error.contains("403"))
                || snapshot.data.refresh_token.is_empty()
            {
                return Err(error.into());
            }
            self.identity.check(&snapshot)?;
            let result = api::refresh_session(
                snapshot.data.server_url.clone(),
                snapshot.data.refresh_token.clone(),
            )
            .await?;
            self.identity.commit_auth(&snapshot, result)?;
            snapshot = self.identity.snapshot(true)?;
            self.inner
                .connect_relay(
                    snapshot.data.server_url.clone(),
                    snapshot.data.user_id.clone(),
                    snapshot.data.token.clone(),
                    snapshot.data.device_id.clone(),
                )
                .await?;
        }
        if let Err(error) = self.identity.check(&snapshot) {
            self.inner.disconnect().await;
            return Err(error.into());
        }
        Ok(())
    }
}
#[uniffi::export(async_runtime = "tokio")]
impl LitesealCore {
    pub async fn native_sign_out(&self) -> FfiResult<()> {
        let result = self.identity.clear_session();
        self.inner.disconnect().await;
        result.map_err(Into::into)
    }
    pub async fn search_users(&self, query: String) -> FfiResult<Vec<FfiUserSearchResult>> {
        let snapshot = self.identity.snapshot(true)?;
        let users = api::search_users(
            snapshot.data.server_url.clone(),
            query,
            snapshot.data.token.clone(),
        )
        .await?;
        self.identity.check(&snapshot)?;
        Ok(users
            .into_iter()
            .map(|r| FfiUserSearchResult {
                user_id: r.user_id,
                username: r.username,
                public_key: r.public_key,
                ed25519_pk: r.ed25519_pk,
            })
            .collect())
    }

    pub async fn disconnect(&self) {
        self.inner.disconnect().await;
    }

    pub async fn send_text(&self, peer: String, text: String) -> FfiResult<String> {
        crate::mobile_runtime::require_foreground()?;
        let _network = crate::mobile_runtime::NETWORK.lock().await;
        let snapshot = self.identity.snapshot(true)?;
        if text.is_empty() || text.len() > 16 * 1024 {
            return Err("文字为空或超出 16 KiB".to_string().into());
        }
        let contact = self
            .inner
            .db
            .lock()
            .map_err(|_| "移动本机存储不可用".to_string())?
            .get_contact(&peer)
            .map_err(|_| "联系人存储不可用".to_string())?
            .ok_or("联系人不存在".to_string())?;
        if contact.key_changed || contact.trust_state == "key_changed" {
            return Err("联系人身份已改变；停止发送".to_string().into());
        }
        let devices = api::get_user_devices(
            snapshot.data.server_url.clone(),
            peer.clone(),
            snapshot.data.token.clone(),
        )
        .await?;
        self.identity.check(&snapshot)?;
        let devices: Vec<_> = devices
            .into_iter()
            .filter(|device| !device.revoked)
            .collect();
        if devices.len() != 1
            || devices[0].public_key != contact.public_key
            || contact.ed25519_pk.as_ref() != Some(&devices[0].ed25519_pk)
        {
            return Err("当前设备与独立钉住的联系人身份不符；不能降级或替换"
                .to_string()
                .into());
        }
        let plain = Zeroizing::new(text);
        let ciphertext = chat::encrypt_message(
            plain.as_bytes().to_vec(),
            contact.public_key.clone(),
            snapshot.data.secret_key.clone(),
        )?;
        let signature = chat::sign_message(ciphertext.clone(), snapshot.data.ed25519_sk.clone())?;
        let signing_key = Zeroizing::new(
            <[u8; 64]>::try_from(snapshot.data.ed25519_sk.as_slice())
                .map_err(|_| "原生签名身份无效".to_string())?,
        );
        let payload = EncryptedPayload {
            recipient_user_id: peer,
            recipient_device_id: devices[0].id.clone(),
            ciphertext: ciphertext.clone(),
            signature: signature.clone(),
        };
        self.identity.check(&snapshot)?;
        let result = self
            .inner
            .send_message_with_id(
                snapshot.data.user_id.clone(),
                ciphertext,
                signature,
                snapshot.data.device_id.clone(),
                vec![payload],
                None,
                Some(&signing_key),
            )
            .await?;
        self.identity.check(&snapshot)?;
        Ok(result.message_id)
    }
    pub fn read_message(&self, id: String) -> FfiResult<String> {
        crate::mobile_runtime::require_foreground()?;
        let snapshot = self.identity.snapshot(false)?;
        let db = self
            .inner
            .db
            .lock()
            .map_err(|_| "移动本机存储不可用".to_string())?;
        let text = crate::mobile_messages::read(&db, &snapshot.data, &id)?;
        self.identity.check(&snapshot)?;
        Ok(text)
    }
    pub async fn poll_messages(&self) -> FfiResult<FfiPollResult> {
        crate::mobile_runtime::require_foreground()?;
        let _network = crate::mobile_runtime::NETWORK.lock().await;
        let snapshot = self.identity.snapshot(true)?;
        let mut result = self.inner.poll_messages().await?;
        let operations_changed =
            match crate::mobile_operations::poll(&self.inner, &self.identity).await {
                Ok(count) => count > 0,
                Err(_) => {
                    result.events.push(chat::RelayEvent::Error {
                        code: "operations_pending".into(),
                        message: "消息变更补收暂未完成".into(),
                    });
                    false
                }
            };
        self.identity.check(&snapshot)?;
        Ok(FfiPollResult {
            operations_changed,
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
                    chat::RelayEvent::Typing {
                        from,
                        active,
                        expires_at,
                    } => FfiRelayEvent::Typing {
                        from_user_id: from,
                        active,
                        expires_at,
                    },
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
        crate::mobile_runtime::require_foreground()?;
        if !(1..=1000).contains(&limit) || !(0..=10_000).contains(&offset) {
            return Err("历史分页超出本机范围".to_string().into());
        }
        let snapshot = self.identity.snapshot(false)?;
        let hidden = {
            let db = self
                .inner
                .db
                .lock()
                .map_err(|_| "移动本机存储不可用".to_string())?;
            if !db
                .get_contacts()
                .map_err(|_| "联系人存储不可用".to_string())?
                .iter()
                .any(|c| {
                    chat::canonical_conversation_id(&snapshot.data.user_id, &c.user_id)
                        == conversation_id
                })
            {
                return Err("会话不属于当前原生身份".to_string().into());
            }
            db.locally_deleted_ids(&snapshot.data.user_id, &conversation_id)
                .map_err(|_| "本机隐藏记录不可用".to_string())?
        };
        let messages = self
            .inner
            .get_local_messages(&conversation_id, limit, offset)?;
        self.identity.check(&snapshot)?;
        Ok(messages
            .into_iter()
            .filter(|m| !hidden.contains(&m.id))
            .map(Into::into)
            .collect())
    }

    pub fn add_contact(
        &self,
        user_id: String,
        username: String,
        public_key: Vec<u8>,
        ed25519_pk: Option<Vec<u8>>,
    ) -> FfiResult<()> {
        self.foreground_local(|client| {
            client.add_contact(user_id, username, public_key, ed25519_pk)
        })
    }

    pub fn get_contacts(&self) -> FfiResult<Vec<FfiContact>> {
        let contacts = self.foreground_local(LitesealClient::get_contacts)?;
        Ok(contacts.into_iter().map(Into::into).collect())
    }

    pub fn remove_contact(&self, user_id: String) -> FfiResult<()> {
        self.foreground_local(|client| client.remove_contact(&user_id))
    }

    pub fn set_contact_trust(&self, user_id: String, trust_state: String) -> FfiResult<()> {
        self.foreground_local(|client| client.set_contact_trust(&user_id, &trust_state))
    }

    pub fn get_storage_stats(&self) -> FfiResult<FfiStorageStats> {
        let stats = self.foreground_local(LitesealClient::get_storage_stats)?;
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
        Ok(self.foreground_local(LitesealClient::clear_expired_messages)? as u64)
    }

    pub fn clear_unpinned_attachments(&self) -> FfiResult<u64> {
        Ok(self.foreground_local(LitesealClient::clear_unpinned_attachments)? as u64)
    }
}

#[cfg(test)]
mod local_boundary_tests {
    use super::*;

    #[test]
    fn local_business_without_confirmed_identity_cannot_read_or_mutate_storage() {
        let work = crate::backup::WorkDirectory::create(&std::env::temp_dir()).unwrap();
        let core =
            LitesealCore::new(work.0.join("isolated.db").to_str().unwrap().to_string()).unwrap();
        assert!(core.get_contacts().is_err());
        assert!(core.get_storage_stats().is_err());
        assert!(core
            .add_contact(
                "synthetic-peer".into(),
                "synthetic-name".into(),
                vec![0; 32],
                Some(vec![0; 32]),
            )
            .is_err());
        assert!(core.remove_contact("synthetic-peer".into()).is_err());
        assert!(core
            .set_contact_trust("synthetic-peer".into(), "verified".into())
            .is_err());
        assert!(core.clear_expired_messages().is_err());
        assert!(core.clear_unpinned_attachments().is_err());
        assert!(core.inner.get_contacts().unwrap().is_empty());
        assert!(!work.0.join("mobile-identity.bin").exists());
    }
}
