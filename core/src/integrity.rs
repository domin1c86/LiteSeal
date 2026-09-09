use sha2::{Digest, Sha256};

use crate::db::models::MessageModel;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityResult {
    Valid,
    Replay,
    Gap,
    PrevHashMismatch,
}

pub struct MessageIntegrityStore;

impl MessageIntegrityStore {
    pub fn hash_message(msg: &MessageModel) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(msg.id.as_bytes());
        hasher.update(msg.conversation_id.as_bytes());
        hasher.update(msg.sender_id.as_bytes());
        hasher.update(msg.sender_device_id.as_bytes());
        hasher.update(msg.sender_seq.to_be_bytes());
        hasher.update(&msg.prev_hash);
        hasher.update(&msg.ciphertext);
        hasher.update(&msg.signature);
        hasher.finalize().to_vec()
    }

    pub fn validate_next(previous: Option<&MessageModel>, next: &MessageModel) -> IntegrityResult {
        let Some(previous) = previous else {
            return if next.sender_seq <= 1 || next.prev_hash.is_empty() {
                IntegrityResult::Valid
            } else {
                IntegrityResult::Gap
            };
        };

        if next.sender_seq <= previous.sender_seq {
            return IntegrityResult::Replay;
        }
        if next.sender_seq != previous.sender_seq + 1 {
            return IntegrityResult::Gap;
        }
        if next.prev_hash != Self::hash_message(previous) {
            return IntegrityResult::PrevHashMismatch;
        }
        IntegrityResult::Valid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(id: &str, seq: i64, prev_hash: Vec<u8>) -> MessageModel {
        MessageModel {
            id: id.to_string(),
            conversation_id: "conv".to_string(),
            sender_id: "alice".to_string(),
            sender_device_id: "device-a".to_string(),
            sender_seq: seq,
            timestamp: seq,
            message_type: "text".to_string(),
            local_state: "received".to_string(),
            expire_at: None,
            ciphertext: vec![seq as u8],
            signature: vec![seq as u8, 9],
            prev_hash,
        }
    }

    #[test]
    fn validates_hash_chain() {
        let first = message("m1", 1, Vec::new());
        let second = message("m2", 2, MessageIntegrityStore::hash_message(&first));

        assert_eq!(
            MessageIntegrityStore::validate_next(Some(&first), &second),
            IntegrityResult::Valid
        );
    }

    #[test]
    fn rejects_replay_gap_and_prev_hash_mismatch() {
        let first = message("m1", 1, Vec::new());
        assert_eq!(
            MessageIntegrityStore::validate_next(Some(&first), &message("replay", 1, Vec::new())),
            IntegrityResult::Replay
        );
        assert_eq!(
            MessageIntegrityStore::validate_next(Some(&first), &message("gap", 3, Vec::new())),
            IntegrityResult::Gap
        );
        assert_eq!(
            MessageIntegrityStore::validate_next(Some(&first), &message("bad", 2, vec![7; 32])),
            IntegrityResult::PrevHashMismatch
        );
    }
}
