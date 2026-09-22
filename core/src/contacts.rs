//! Contact validation and fingerprint derivation.

use sha2::{Digest, Sha256};

pub fn validate_contact_input(
    user_id: &str,
    username: &str,
    public_key: &[u8],
    ed25519_pk: Option<&[u8]>,
) -> Result<(), String> {
    if user_id.trim().is_empty() {
        return Err("User id cannot be empty".to_string());
    }
    if username.trim().is_empty() {
        return Err("Username cannot be empty".to_string());
    }
    if public_key.len() != 32 {
        return Err("Invalid public key length".to_string());
    }
    if let Some(pk) = ed25519_pk {
        if pk.len() != 32 {
            return Err("Invalid signing public key length".to_string());
        }
    }
    Ok(())
}

pub fn fingerprint(key: &[u8]) -> String {
    let digest = Sha256::digest(key);
    hex::encode(&digest[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contact_input_requires_ids_and_expected_key_lengths() {
        assert!(validate_contact_input("user-1", "alice", &[1; 32], Some(&[2; 32])).is_ok());
        assert!(validate_contact_input(" ", "alice", &[1; 32], None).is_err());
        assert!(validate_contact_input("user-1", " ", &[1; 32], None).is_err());
        assert!(validate_contact_input("user-1", "alice", &[1; 31], None).is_err());
        assert!(validate_contact_input("user-1", "alice", &[1; 32], Some(&[2; 31])).is_err());
    }

    #[test]
    fn fingerprint_is_stable_short_hex() {
        assert_eq!(fingerprint(&[7; 32]).len(), 32);
        assert_eq!(fingerprint(&[7; 32]), fingerprint(&[7; 32]));
    }
}
