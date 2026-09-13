use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedPayload {
    pub recipient_user_id: String,
    pub recipient_device_id: String,
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientChain {
    pub sender_seq: i64,
    pub prev_hash: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryStatus {
    pub message_id: String,
    pub recipient_user_id: String,
    pub recipient_device_id: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientMessage {
    #[serde(rename = "auth")]
    Auth {
        user_id: String,
        token: String,
        device_id: String,
    },
    #[serde(rename = "send")]
    Send {
        message_id: String,
        conversation_id: String,
        ciphertext: Vec<u8>,
        signature: Vec<u8>,
        sender_device_id: String,
        sender_seq: i64,
        prev_hash: Vec<u8>,
        payloads: Vec<EncryptedPayload>,
    },
    #[serde(rename = "send_v2")]
    SendV2 {
        message_id: String,
        conversation_id: String,
        ciphertext: Vec<u8>,
        signature: Vec<u8>,
        sender_device_id: String,
        sender_seq: i64,
        prev_hash: Vec<u8>,
        payloads: Vec<EncryptedPayload>,
        recipient_chains: std::collections::BTreeMap<String, RecipientChain>,
    },
    #[serde(rename = "ack")]
    Ack {
        message_id: String,
        recipient_device_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ServerMessage {
    #[serde(rename = "auth_ok")]
    AuthOk,
    #[serde(rename = "auth_fail")]
    AuthFail { reason: String },
    #[serde(rename = "message")]
    Message {
        message_id: String,
        from: String,
        conversation_id: String,
        ciphertext: Vec<u8>,
        signature: Vec<u8>,
        sender_device_id: String,
        sender_seq: i64,
        prev_hash: Vec<u8>,
        recipient_device_id: String,
        timestamp: i64,
    },
    #[serde(rename = "message_v2")]
    MessageV2 {
        message_id: String,
        from: String,
        conversation_id: String,
        ciphertext: Vec<u8>,
        signature: Vec<u8>,
        sender_device_id: String,
        sender_seq: i64,
        prev_hash: Vec<u8>,
        recipient_device_id: String,
        timestamp: i64,
    },
    #[serde(rename = "error")]
    Error { code: String, message: String },
    #[serde(rename = "delivered")]
    Delivered { message_id: String },
    #[serde(rename = "delivery_update")]
    DeliveryUpdate { updates: Vec<DeliveryStatus> },
    #[serde(rename = "offline")]
    Offline { message_id: String, to: String },
}
