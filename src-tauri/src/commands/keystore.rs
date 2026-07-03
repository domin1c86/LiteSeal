use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct KeystoreData {
    user_id: String,
    #[serde(default)]
    token: String,
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
    ed25519_pk: Vec<u8>,
    ed25519_sk: Vec<u8>,
}

fn keystore_path() -> Result<std::path::PathBuf, String> {
    let base = dirs::data_local_dir().ok_or("Cannot find local data directory")?;
    let dir = base.join("liteseal");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("keystore.json"))
}

#[tauri::command]
pub fn save_keypair(
    user_id: String,
    token: String,
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
    ed25519_pk: Vec<u8>,
    ed25519_sk: Vec<u8>,
) -> Result<(), String> {
    let data = KeystoreData {
        user_id,
        token,
        public_key,
        secret_key,
        ed25519_pk,
        ed25519_sk,
    };
    validate_keystore_data(&data)?;
    let json = serde_json::to_string_pretty(&data).map_err(|e| e.to_string())?;
    std::fs::write(keystore_path()?, json).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn load_keypair() -> Result<(String, String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), String> {
    let path = keystore_path()?;
    if !path.exists() {
        return Err("No saved keypair found".to_string());
    }
    let json = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let data: KeystoreData = serde_json::from_str(&json).map_err(|e| e.to_string())?;
    validate_keystore_data(&data)?;
    Ok((
        data.user_id,
        data.token,
        data.public_key,
        data.secret_key,
        data.ed25519_pk,
        data.ed25519_sk,
    ))
}

#[tauri::command]
pub fn clear_keypair() -> Result<(), String> {
    let path = keystore_path()?;
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn validate_keystore_data(data: &KeystoreData) -> Result<(), String> {
    if data.user_id.trim().is_empty() {
        return Err("Missing user id".to_string());
    }
    if data.token.trim().is_empty() {
        return Err("Missing auth token".to_string());
    }
    if data.public_key.len() != 32 {
        return Err("Invalid public key length".to_string());
    }
    if data.secret_key.len() != 32 {
        return Err("Invalid secret key length".to_string());
    }
    if data.ed25519_pk.len() != 32 {
        return Err("Invalid ed25519 public key length".to_string());
    }
    if data.ed25519_sk.len() != 64 {
        return Err("Invalid ed25519 secret key length".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keystore_data_requires_token_and_expected_key_lengths() {
        let data = KeystoreData {
            user_id: "user-1".to_string(),
            token: "token-1".to_string(),
            public_key: vec![0; 32],
            secret_key: vec![0; 32],
            ed25519_pk: vec![0; 32],
            ed25519_sk: vec![0; 64],
        };

        assert!(validate_keystore_data(&data).is_ok());

        let invalid = KeystoreData {
            secret_key: vec![0; 31],
            ..data
        };
        assert!(validate_keystore_data(&invalid).is_err());
    }
}
