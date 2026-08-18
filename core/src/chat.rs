//! Message types and pure chat logic: canonical conversation ids, the
//! per-device hash chain, message model construction and crypto passthroughs.

use serde::{Deserialize, Serialize};

use crate::db::models::MessageModel;
use crate::integrity::MessageIntegrityStore;

#[derive(Debug, Serialize, Deserialize)]
pub struct SendMessageResult {
    pub message_id: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IncomingMessage {
    pub message_id: String,
    pub from: String,
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

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum RelayEvent {
    #[serde(rename = "delivered")]
    Delivered { message_id: String },
    #[serde(rename = "offline")]
    Offline { message_id: String, to: String },
    #[serde(rename = "delivery_update")]
    DeliveryUpdate {
        message_id: String,
        recipient_device_id: String,
        status: String,
    },
    #[serde(rename = "error")]
    Error { code: String, message: String },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PollMessagesResult {
    pub messages: Vec<IncomingMessage>,
    pub events: Vec<RelayEvent>,
}

/// Both sides derive the same id regardless of who sends first.
pub fn canonical_conversation_id(a: &str, b: &str) -> String {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    format!("dm:{}:{}", lo, hi)
}

pub fn next_chain_state(previous: Option<&MessageModel>) -> (i64, Vec<u8>) {
    match previous {
        Some(prev) => (
            prev.sender_seq + 1,
            MessageIntegrityStore::hash_message(prev),
        ),
        None => (1, Vec::new()),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_outgoing_message_model(
    message_id: String,
    conversation_id: String,
    sender_id: String,
    sender_device_id: String,
    sender_seq: i64,
    timestamp: i64,
    ciphertext: Vec<u8>,
    signature: Vec<u8>,
    prev_hash: Vec<u8>,
    local_state: &str,
) -> MessageModel {
    MessageModel {
        id: message_id,
        conversation_id,
        sender_id,
        sender_device_id,
        sender_seq,
        timestamp,
        message_type: "text".to_string(),
        local_state: local_state.to_string(),
        expire_at: None,
        ciphertext,
        signature,
        prev_hash,
        protocol_version: 2,
        verification_state: "authored_v2".to_string(),
        quarantined: false,
    }
}

pub fn build_incoming_message_model(msg: IncomingMessage) -> MessageModel {
    let legacy = msg.local_state.contains("v1_legacy");
    let quarantined = msg.local_state == "quarantined";
    MessageModel {
        id: msg.message_id,
        conversation_id: msg.conversation_id,
        sender_id: msg.from,
        sender_device_id: msg.sender_device_id,
        sender_seq: msg.sender_seq,
        timestamp: msg.timestamp,
        message_type: "text".to_string(),
        local_state: msg.local_state,
        expire_at: None,
        ciphertext: msg.ciphertext,
        signature: msg.signature,
        prev_hash: msg.prev_hash,
        protocol_version: if legacy { 1 } else { 2 },
        verification_state: if legacy {
            "legacy_ciphertext_verified".to_string()
        } else {
            "verified_v2".to_string()
        },
        quarantined,
    }
}

// Crypto passthroughs so platform shells never talk to libsodium directly.

pub fn encrypt_message(
    plaintext: Vec<u8>,
    recipient_public_key: Vec<u8>,
    sender_secret_key: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let pk: [u8; 32] = recipient_public_key
        .try_into()
        .map_err(|_| "Invalid public key length")?;
    let sk: [u8; 32] = sender_secret_key
        .try_into()
        .map_err(|_| "Invalid secret key length")?;
    liteseal_shared::crypto::encrypt(&plaintext, &pk, &sk)
        .map_err(|e| format!("Encryption failed: {}", e))
}

pub fn decrypt_message(
    ciphertext: Vec<u8>,
    sender_public_key: Vec<u8>,
    recipient_secret_key: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let pk: [u8; 32] = sender_public_key
        .try_into()
        .map_err(|_| "Invalid public key length")?;
    let sk: [u8; 32] = recipient_secret_key
        .try_into()
        .map_err(|_| "Invalid secret key length")?;
    liteseal_shared::crypto::decrypt(&ciphertext, &pk, &sk)
        .map_err(|e| format!("Decryption failed: {}", e))
}

pub fn sign_message(message: Vec<u8>, signing_key: Vec<u8>) -> Result<Vec<u8>, String> {
    let sk: [u8; 64] = signing_key
        .try_into()
        .map_err(|_| "Invalid signing key length (expected 64-byte ed25519 secret key)")?;
    liteseal_shared::crypto::sign(&message, &sk).map_err(|e| format!("Signing failed: {}", e))
}

pub fn verify_message(
    message: Vec<u8>,
    signature: Vec<u8>,
    sender_public_key: Vec<u8>,
) -> Result<bool, String> {
    let ed_pk: [u8; 32] = sender_public_key
        .try_into()
        .map_err(|_| "Invalid public key length")?;
    liteseal_shared::crypto::verify_with_public_key(&message, &signature, &ed_pk)
        .map_err(|e| format!("Verification failed: {}", e))
}

pub type ExportedKeypair = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

pub fn generate_keypair() -> Result<ExportedKeypair, String> {
    let kp = liteseal_shared::crypto::generate_keypair().map_err(|e| e.to_string())?;
    Ok((
        kp.public_key.to_vec(),
        kp.secret_key.to_vec(),
        kp.ed25519_pk.to_vec(),
        kp.ed25519_sk.to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integrity::IntegrityResult;

    #[test]
    fn canonical_conversation_id_is_order_independent() {
        assert_eq!(
            canonical_conversation_id("alice", "bob"),
            canonical_conversation_id("bob", "alice")
        );
        assert_eq!(canonical_conversation_id("alice", "bob"), "dm:alice:bob");
    }

    #[test]
    fn outgoing_message_model_is_ready_for_local_persistence() {
        let msg = build_outgoing_message_model(
            "msg-1".to_string(),
            "conv-1".to_string(),
            "alice".to_string(),
            "device-alice".to_string(),
            3,
            1234,
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![7; 32],
            "pending",
        );

        assert_eq!(msg.id, "msg-1");
        assert_eq!(msg.conversation_id, "conv-1");
        assert_eq!(msg.sender_id, "alice");
        assert_eq!(msg.sender_device_id, "device-alice");
        assert_eq!(msg.sender_seq, 3);
        assert_eq!(msg.timestamp, 1234);
        assert_eq!(msg.message_type, "text");
        assert_eq!(msg.local_state, "pending");
        assert_eq!(msg.ciphertext, vec![1, 2, 3]);
        assert_eq!(msg.signature, vec![4, 5, 6]);
        assert_eq!(msg.prev_hash, vec![7; 32]);
    }

    #[test]
    fn outgoing_chain_state_passes_receiver_validation() {
        // First message in a chain: seq 1, empty prev_hash.
        let (seq, prev_hash) = next_chain_state(None);
        assert_eq!(seq, 1);
        assert!(prev_hash.is_empty());

        let first = build_outgoing_message_model(
            "msg-1".to_string(),
            "conv-1".to_string(),
            "alice".to_string(),
            "device-alice".to_string(),
            seq,
            1234,
            vec![1, 2, 3],
            vec![4, 5, 6],
            prev_hash,
            "pending",
        );
        assert_eq!(
            MessageIntegrityStore::validate_next(None, &first),
            IntegrityResult::Valid
        );

        // Second message must extend the chain the receiver validates.
        let (seq, prev_hash) = next_chain_state(Some(&first));
        assert_eq!(seq, 2);
        let second = build_outgoing_message_model(
            "msg-2".to_string(),
            "conv-1".to_string(),
            "alice".to_string(),
            "device-alice".to_string(),
            seq,
            1235,
            vec![9],
            vec![8],
            prev_hash,
            "pending",
        );
        assert_eq!(
            MessageIntegrityStore::validate_next(Some(&first), &second),
            IntegrityResult::Valid
        );
    }

    #[test]
    fn incoming_message_model_is_ready_for_local_persistence() {
        let msg = build_incoming_message_model(IncomingMessage {
            message_id: "msg-2".to_string(),
            from: "bob".to_string(),
            conversation_id: "conv-1".to_string(),
            ciphertext: vec![7, 8],
            signature: vec![9, 10],
            sender_device_id: "device-bob".to_string(),
            sender_seq: 4,
            prev_hash: vec![1; 32],
            recipient_device_id: "device-alice".to_string(),
            timestamp: 5678,
            local_state: "received".to_string(),
        });

        assert_eq!(msg.id, "msg-2");
        assert_eq!(msg.sender_id, "bob");
        assert_eq!(msg.local_state, "received");
        assert_eq!(msg.ciphertext, vec![7, 8]);
        assert_eq!(msg.signature, vec![9, 10]);
        assert_eq!(msg.prev_hash, vec![1; 32]);
    }
}
