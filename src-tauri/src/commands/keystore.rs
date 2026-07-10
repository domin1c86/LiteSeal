use liteseal_core::keystore::{self, KeystoreData};

#[tauri::command]
pub fn save_keypair(data: KeystoreData) -> Result<(), String> {
    keystore::save_keypair(data)
}

#[tauri::command]
pub fn load_keypair() -> Result<KeystoreData, String> {
    keystore::load_keypair()
}

#[tauri::command]
pub fn clear_keypair() -> Result<(), String> {
    keystore::clear_keypair()
}
