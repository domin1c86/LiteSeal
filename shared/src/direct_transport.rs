//! Typed HTTP transport for immutable v3 batches. A missing result is never
//! proof of non-acceptance; cancellation is a durable, digest-bound fence.
use crate::direct_message::{Ack, Batch};
use serde::{Deserialize, Serialize};
pub const MAX_PAGE_BYTES: usize = 512 * 1024;
pub const MAX_PAGE_ITEMS: usize = 100;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub id: String,
    pub digest: [u8; 32],
    pub accepted_at: i64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum Result {
    Unknown {
        id: String,
        digest: [u8; 32],
    },
    Cancelled {
        id: String,
        digest: [u8; 32],
    },
    Accepted {
        receipt: Receipt,
        acknowledgements: Vec<Ack>,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delivery {
    pub order: i64,
    pub batch: Batch,
    pub receipt: Receipt,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    pub items: Vec<Delivery>,
    pub has_more: bool,
}
