use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("encryption failed: {0}")]
    EncryptFailed(String),
    #[error("decryption failed: {0}")]
    DecryptFailed(String),
    #[error("signature failed: {0}")]
    SignFailed(String),
    #[error("verification failed")]
    VerifyFailed,
    #[error("key generation failed: {0}")]
    KeyGenFailed(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub public_key: [u8; 32],
    pub secret_key: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub signature: Vec<u8>,
}

pub fn generate_keypair() -> Result<KeyPair, CryptoError> {
    Err(CryptoError::KeyGenFailed("not yet implemented".into()))
}

pub fn encrypt(_public_key: &[u8], _plaintext: &[u8]) -> Result<EncryptedMessage, CryptoError> {
    Err(CryptoError::EncryptFailed("not yet implemented".into()))
}

pub fn decrypt(_private_key: &[u8], _msg: &EncryptedMessage) -> Result<Vec<u8>, CryptoError> {
    Err(CryptoError::DecryptFailed("not yet implemented".into()))
}

pub fn sign(_private_key: &[u8], _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Err(CryptoError::SignFailed("not yet implemented".into()))
}

pub fn verify(_public_key: &[u8], _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
    Err(CryptoError::VerifyFailed)
}
