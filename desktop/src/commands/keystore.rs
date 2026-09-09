use liteseal_core::keystore::{self, KeystoreData};

pub fn save_keypair(data: KeystoreData) -> Result<(), String> {
    keystore::save_keypair(data)
}

pub fn load_keypair() -> Result<KeystoreData, String> {
    keystore::load_keypair()
}

pub fn clear_keypair() -> Result<(), String> {
    keystore::clear_keypair()
}
