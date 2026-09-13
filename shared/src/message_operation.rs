use serde::{Deserialize, Serialize};

pub const OPERATION_WINDOW_MS: i64 = 48 * 60 * 60 * 1000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperationHeader {
    pub id: String,
    pub target_id: String,
    pub conversation_id: String,
    pub sender_id: String,
    pub sender_device_id: String,
    pub kind: String,
    pub base_revision: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperationPayload {
    pub device_id: String,
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperationRequest {
    pub header: OperationHeader,
    pub payloads: Vec<OperationPayload>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperationDelivery {
    pub header: OperationHeader,
    pub payload: OperationPayload,
    pub revision: i64,
    pub accepted_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperationTarget {
    pub device_id: String,
    pub public_key: Vec<u8>,
}
// Length-delimited serialization binds action, target, author, version, recipient and ciphertext.
pub fn signing_bytes(header: &OperationHeader, device: &str, ciphertext: &[u8]) -> Vec<u8> {
    serde_json::to_vec(&("liteseal-message-operation-v1", header, device, ciphertext))
        .expect("Operation signing data is serializable")
}
