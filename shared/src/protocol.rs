use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientMessage {
    #[serde(rename = "auth")]
    Auth { user_id: String, token: String },
    #[serde(rename = "send")]
    Send {
        to: String,
        conversation_id: String,
        ciphertext: Vec<u8>,
        signature: Vec<u8>,
        sender_device_id: String,
        sender_seq: i64,
    },
    #[serde(rename = "ack")]
    Ack { message_id: String },
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
        timestamp: i64,
    },
    #[serde(rename = "error")]
    Error { code: String, message: String },
    #[serde(rename = "delivered")]
    Delivered { message_id: String },
    #[serde(rename = "offline")]
    Offline { to: String },
}
