use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageModel {
    pub id: String,
    pub conversation_id: String,
    pub sender_id: String,
    pub sender_device_id: String,
    pub sender_seq: i64,
    pub timestamp: i64,
    pub message_type: String,
    pub local_state: String,
    pub expire_at: Option<i64>,
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
    pub prev_hash: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationModel {
    pub id: String,
    pub conversation_type: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub storage_policy: Option<String>,
    pub privacy_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentModel {
    pub id: String,
    pub message_id: String,
    pub blob_id: String,
    pub encrypted_name: Vec<u8>,
    pub encrypted_mime: Vec<u8>,
    pub size: i64,
    pub downloaded: bool,
    pub pinned: bool,
    pub expire_at: Option<i64>,
    pub last_accessed_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceModel {
    pub id: String,
    pub user_id: String,
    pub public_key: Vec<u8>,
    pub created_at: i64,
    pub last_seen: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactModel {
    pub user_id: String,
    pub username: String,
    pub public_key: Vec<u8>,
    pub ed25519_pk: Option<Vec<u8>>,
    pub added_at: i64,
}
