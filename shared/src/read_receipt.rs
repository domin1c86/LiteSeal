use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReadReceipt {
    pub id: String,
    pub target_id: String,
    pub conversation_id: String,
    pub reader: String,
    pub device: String,
    pub peer: String,
    pub signature: Vec<u8>,
}

impl ReadReceipt {
    pub fn signing_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&(
            "LiteSeal/read-receipt/v1",
            &self.id,
            &self.target_id,
            &self.conversation_id,
            &self.reader,
            &self.device,
            &self.peer,
        ))
        .expect("serializable read receipt")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReadReceiptDelivery {
    pub seq: i64,
    pub event: ReadReceipt,
}
