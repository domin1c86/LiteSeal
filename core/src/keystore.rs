use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct KeystoreData {
    pub user_id: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub refresh_token: String,
    #[serde(default)]
    pub device_id: String,
    #[serde(default)]
    pub server_url: String,
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub ed25519_pk: Vec<u8>,
    pub ed25519_sk: Vec<u8>,
}

fn keystore_path() -> Result<std::path::PathBuf, String> {
    let base = dirs::data_local_dir().ok_or("Cannot find local data directory")?;
    let dir = base.join("liteseal");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("keystore.bin"))
}

fn legacy_keystore_path() -> Result<std::path::PathBuf, String> {
    let base = dirs::data_local_dir().ok_or("Cannot find local data directory")?;
    Ok(base.join("liteseal").join("keystore.json"))
}

pub fn save_keypair(data: KeystoreData) -> Result<(), String> {
    validate_keystore_data(&data)?;
    let json = serde_json::to_string_pretty(&data).map_err(|e| e.to_string())?;
    crate::secret_store::secret_store(keystore_path()?).save(json.as_bytes())
}

pub fn load_keypair() -> Result<KeystoreData, String> {
    let path = keystore_path()?;
    if !path.exists() {
        migrate_legacy_keystore()?;
    }
    if !path.exists() {
        return Err("No saved keypair found".to_string());
    }
    let json = String::from_utf8(crate::secret_store::secret_store(path).load()?)
        .map_err(|e| e.to_string())?;
    let data: KeystoreData = serde_json::from_str(&json).map_err(|e| e.to_string())?;
    validate_keystore_data(&data)?;
    Ok(data)
}

pub fn clear_keypair() -> Result<(), String> {
    crate::secret_store::secret_store(keystore_path()?).clear()
}

fn migrate_legacy_keystore() -> Result<(), String> {
    let legacy = legacy_keystore_path()?;
    if !legacy.exists() {
        return Ok(());
    }
    let json = std::fs::read_to_string(&legacy).map_err(|e| e.to_string())?;
    let data: KeystoreData = serde_json::from_str(&json).map_err(|e| e.to_string())?;
    validate_keystore_data(&data)?;
    crate::secret_store::secret_store(keystore_path()?).save(json.as_bytes())?;
    let backup = legacy.with_extension("json.migrated.bak");
    std::fs::rename(legacy, backup).map_err(|e| e.to_string())?;
    Ok(())
}

fn validate_keystore_data(data: &KeystoreData) -> Result<(), String> {
    if data.user_id.trim().is_empty() {
        return Err("Missing user id".to_string());
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

/// Sign out without destroying the identity needed to decrypt local history.
pub fn clear_session() -> Result<(), String> {
    let mut data = load_keypair()?;
    data.token.clear();
    data.refresh_token.clear();
    save_keypair(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_data() -> KeystoreData {
        KeystoreData {
            user_id: "user-1".to_string(),
            token: "token-1".to_string(),
            refresh_token: "refresh-1".to_string(),
            device_id: "device-abc".to_string(),
            server_url: "http://localhost:3000".to_string(),
            public_key: vec![0; 32],
            secret_key: vec![0; 32],
            ed25519_pk: vec![0; 32],
            ed25519_sk: vec![0; 64],
        }
    }

    #[test]
    fn keystore_data_requires_token_and_expected_key_lengths() {
        assert!(validate_keystore_data(&valid_data()).is_ok());

        let invalid = KeystoreData {
            secret_key: vec![0; 31],
            ..valid_data()
        };
        assert!(validate_keystore_data(&invalid).is_err());
    }

    #[test]
    fn legacy_keystore_json_without_new_fields_still_loads() {
        let legacy_json = r#"{
            "user_id": "user-1",
            "token": "token-1",
            "public_key": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "secret_key": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "ed25519_pk": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "ed25519_sk": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                           0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
        }"#;
        let data: KeystoreData = serde_json::from_str(legacy_json).unwrap();
        assert!(data.device_id.is_empty());
        assert!(data.server_url.is_empty());
        assert!(data.refresh_token.is_empty());
        assert!(validate_keystore_data(&data).is_ok());
    }
}
