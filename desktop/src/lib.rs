pub mod commands;
pub mod protocol;

use liteseal_core::keystore::{self, KeystoreData};
use std::{path::PathBuf, sync::Mutex};

pub struct AppState {
    pub db_path: PathBuf,
    pub client: liteseal_core::LitesealClient,
    keystore_path: Option<PathBuf>,
    identity: Mutex<Option<KeystoreData>>,
    pending_keys: Mutex<Option<KeystoreData>>,
    pub(crate) scheduled_tick: Mutex<Option<(String, i64)>>,
    pub(crate) groups_runtime: Mutex<commands::groups::Runtime>,
    pub(crate) groups_gate: tokio::sync::Mutex<()>,
}

impl AppState {
    pub fn new(db_path: &str) -> Result<Self, String> {
        Self::with_keystore(db_path, None)
    }

    /// `keystore_path` replaces the per-user keystore, for example in tests.
    pub fn with_keystore(db_path: &str, keystore_path: Option<PathBuf>) -> Result<Self, String> {
        Ok(Self {
            db_path: PathBuf::from(db_path),
            client: liteseal_core::LitesealClient::new(db_path)?,
            keystore_path,
            identity: Mutex::new(None),
            pending_keys: Mutex::new(None),
            scheduled_tick: Mutex::new(None),
            groups_runtime: Mutex::new(commands::groups::Runtime::default()),
            groups_gate: tokio::sync::Mutex::new(()),
        })
    }

    /// The saved identity including secret keys. Never return it to the renderer.
    pub fn identity(&self) -> Result<KeystoreData, String> {
        let mut cached = self.identity.lock().map_err(|e| e.to_string())?;
        if let Some(identity) = cached.as_ref() {
            return Ok(identity.clone());
        }
        let loaded = match &self.keystore_path {
            Some(path) => keystore::load_keypair_from(path)?,
            None => keystore::load_keypair()?,
        };
        *cached = Some(loaded.clone());
        Ok(loaded)
    }

    pub fn save_identity(&self, data: KeystoreData) -> Result<(), String> {
        let mut cached = self.identity.lock().map_err(|e| e.to_string())?;
        let previous = cached.clone();
        let changed = previous.as_ref().is_some_and(|old| {
            old.user_id != data.user_id
                || old.device_id != data.device_id
                || old.server_url != data.server_url
                || old.token != data.token
                || old.public_key != data.public_key
                || old.ed25519_pk != data.ed25519_pk
                || old.secret_key != data.secret_key
                || old.ed25519_sk != data.ed25519_sk
        });
        match &self.keystore_path {
            Some(path) => keystore::save_keypair_to(path, data.clone())?,
            None => keystore::save_keypair(data.clone())?,
        }
        *cached = Some(data);
        drop(cached);
        if changed {
            if let Some(previous) = previous {
                commands::groups::invalidate(self, &previous)?;
            }
        }
        Ok(())
    }

    pub fn clear_identity(&self) -> Result<(), String> {
        let mut cached = self.identity.lock().map_err(|e| e.to_string())?;
        let previous = cached.clone();
        match &self.keystore_path {
            Some(path) => keystore::clear_keypair_at(path)?,
            None => keystore::clear_keypair()?,
        }
        *cached = None;
        drop(cached);
        if let Some(previous) = previous {
            commands::groups::invalidate(self, &previous)?;
        }
        Ok(())
    }

    /// Keys for an account that is not bound yet; generated once and kept in
    /// memory until a session is saved with them.
    pub fn pending_keys(&self) -> Result<KeystoreData, String> {
        let mut pending = self.pending_keys.lock().map_err(|e| e.to_string())?;
        if let Some(keys) = pending.as_ref() {
            return Ok(keys.clone());
        }
        let generated = liteseal_shared::crypto::generate_keypair().map_err(|e| e.to_string())?;
        let keys = KeystoreData {
            user_id: String::new(),
            token: String::new(),
            refresh_token: String::new(),
            device_id: String::new(),
            server_url: String::new(),
            public_key: generated.public_key.to_vec(),
            secret_key: generated.secret_key.to_vec(),
            ed25519_pk: generated.ed25519_pk.to_vec(),
            ed25519_sk: generated.ed25519_sk.to_vec(),
        };
        *pending = Some(keys.clone());
        Ok(keys)
    }

    pub fn existing_pending_keys(&self) -> Result<Option<KeystoreData>, String> {
        Ok(self.pending_keys.lock().map_err(|e| e.to_string())?.clone())
    }

    pub fn clear_pending_keys(&self) -> Result<(), String> {
        *self.pending_keys.lock().map_err(|e| e.to_string())? = None;
        Ok(())
    }
}
