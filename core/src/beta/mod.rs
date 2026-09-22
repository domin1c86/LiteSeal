//! Durable Windows beta state. The legacy mobile FFI remains independent.
pub mod account;
pub mod engine;
pub mod store;
#[cfg(all(test, windows))]
mod tests;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub user_id: String,
    pub username: String,
    pub device_id: String,
    pub public_key: Vec<u8>,
    pub ed25519_pk: Vec<u8>,
    pub fingerprint: String,
    pub accepted: bool,
    pub verified: bool,
    pub blocked: bool,
    pub key_changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageRequest {
    pub peer: Peer,
    pub count: i64,
    pub first_at: i64,
    pub last_at: i64,
}
