use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub user_id: String,
    pub public_key: [u8; 32],
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub conversation_id: String,
    pub sender_id: String,
    pub sender_device_id: String,
    pub sender_seq: i64,
    pub timestamp: i64,
    pub message_type: String,
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
    pub prev_hash: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conversation {
    pub id: String,
    pub conversation_type: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub user_id: String,
    pub username: String,
    pub public_key: Vec<u8>,
    pub added_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyInfo {
    pub user_id: String,
    pub username: String,
    pub public_key: Vec<u8>,
    pub ed25519_pk: Option<Vec<u8>>,
}
