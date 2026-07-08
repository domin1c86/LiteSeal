use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use sha2::{Digest, Sha256};

pub fn hash_password(password: &str) -> Result<String, String> {
    if password.len() < 8 {
        return Err("Password must be at least 8 characters".to_string());
    }
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| e.to_string())
}

pub fn verify_password(password: &str, password_hash: &str) -> bool {
    let Ok(parsed_hash) = PasswordHash::new(password_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

pub fn validate_key_material(public_key: &[u8], ed25519_pk: &[u8]) -> Result<(), String> {
    if public_key.len() != 32 {
        return Err("Invalid public key length".to_string());
    }
    if ed25519_pk.len() != 32 {
        return Err("Invalid signing public key length".to_string());
    }
    if public_key.iter().all(|&b| b == 0) || ed25519_pk.iter().all(|&b| b == 0) {
        return Err("Key material must not be all zeros".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_verifies_only_matching_password() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &hash));
        assert!(!verify_password("wrong password", &hash));
    }

    #[test]
    fn key_material_rejects_wrong_length_and_all_zero_keys() {
        assert!(validate_key_material(&[1; 32], &[2; 32]).is_ok());
        assert!(validate_key_material(&[1; 31], &[2; 32]).is_err());
        assert!(validate_key_material(&[1; 32], &[2; 31]).is_err());
        assert!(validate_key_material(&[0; 32], &[2; 32]).is_err());
        assert!(validate_key_material(&[1; 32], &[0; 32]).is_err());
    }

    #[test]
    fn token_hash_is_stable_and_not_plaintext() {
        let token = generate_token();
        let hash = hash_token(&token);
        assert_eq!(hash, hash_token(&token));
        assert_ne!(hash, token);
    }
}
