use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PROTOCOL_V2: u8 = 2;
const SIGNED_ENVELOPE_V2_DOMAIN: &[u8] = b"LiteSeal SignedEnvelopeV2\0";

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProtocolError {
    #[error("{field} exceeds the protocol encoding limit")]
    FieldTooLarge { field: &'static str },
}

/// Authenticated wire representation for all newly-created messages.
///
/// The signature is computed over [`SignedEnvelopeV2::signing_bytes`], which
/// covers every routing and ordering field as well as the ciphertext. The
/// signature field itself is deliberately excluded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedEnvelopeV2 {
    pub protocol_version: u8,
    pub message_id: String,
    pub conversation_id: String,
    pub sender_user_id: String,
    pub sender_device_id: String,
    pub recipient_user_id: String,
    pub recipient_device_id: String,
    pub sender_seq: i64,
    pub prev_hash: Vec<u8>,
    pub sent_at: i64,
    pub message_type: String,
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
}

impl SignedEnvelopeV2 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(SIGNED_ENVELOPE_V2_DOMAIN);
        encoded.push(self.protocol_version);
        append_length_prefixed(&mut encoded, "message_id", self.message_id.as_bytes())?;
        append_length_prefixed(
            &mut encoded,
            "conversation_id",
            self.conversation_id.as_bytes(),
        )?;
        append_length_prefixed(
            &mut encoded,
            "sender_user_id",
            self.sender_user_id.as_bytes(),
        )?;
        append_length_prefixed(
            &mut encoded,
            "sender_device_id",
            self.sender_device_id.as_bytes(),
        )?;
        append_length_prefixed(
            &mut encoded,
            "recipient_user_id",
            self.recipient_user_id.as_bytes(),
        )?;
        append_length_prefixed(
            &mut encoded,
            "recipient_device_id",
            self.recipient_device_id.as_bytes(),
        )?;
        encoded.extend_from_slice(&self.sender_seq.to_be_bytes());
        append_length_prefixed(&mut encoded, "prev_hash", &self.prev_hash)?;
        encoded.extend_from_slice(&self.sent_at.to_be_bytes());
        append_length_prefixed(&mut encoded, "message_type", self.message_type.as_bytes())?;
        append_length_prefixed(&mut encoded, "ciphertext", &self.ciphertext)?;
        Ok(encoded)
    }
}

fn append_length_prefixed(
    output: &mut Vec<u8>,
    field: &'static str,
    value: &[u8],
) -> Result<(), ProtocolError> {
    let length = u32::try_from(value.len()).map_err(|_| ProtocolError::FieldTooLarge { field })?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedPayload {
    pub recipient_user_id: String,
    pub recipient_device_id: String,
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
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
    #[serde(rename = "ack")]
    Ack {
        message_id: String,
        recipient_device_id: String,
    },
    #[serde(rename = "send_v2")]
    SendV2 { envelopes: Vec<SignedEnvelopeV2> },
    #[serde(rename = "ack_v2")]
    AckV2 { message_id: String },
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
    #[serde(rename = "error")]
    Error { code: String, message: String },
    #[serde(rename = "delivered")]
    Delivered { message_id: String },
    #[serde(rename = "delivery_update")]
    DeliveryUpdate { updates: Vec<DeliveryStatus> },
    #[serde(rename = "offline")]
    Offline { message_id: String, to: String },
    #[serde(rename = "message_v2")]
    MessageV2 {
        envelope: SignedEnvelopeV2,
        server_timestamp: i64,
    },
}
