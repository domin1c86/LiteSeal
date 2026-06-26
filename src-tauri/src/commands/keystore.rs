use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct KeystoreData {
    user_id: String,
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
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
    ed25519_pk: Vec<u8>,
    ed25519_sk: Vec<u8>,
) -> Result<(), String> {
    let data = KeystoreData {
        user_id,
        public_key,
        secret_key,
        ed25519_pk,
        ed25519_sk,
    };
    let json = serde_json::to_string_pretty(&data).map_err(|e| e.to_string())?;
    std::fs::write(keystore_path()?, json).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn load_keypair() -> Result<(String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), String> {
    let path = keystore_path()?;
    if !path.exists() {
        return Err("No saved keypair found".to_string());
    }
    let json = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let data: KeystoreData = serde_json::from_str(&json).map_err(|e| e.to_string())?;
    Ok((
        data.user_id,
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
