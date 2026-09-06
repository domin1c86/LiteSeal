pub mod commands;

use liteseal_core::LitesealClient;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use tokio::sync::Mutex as AsyncMutex;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Thin Tauri wrapper around the shared client core; all business logic
/// lives in `liteseal-core`.
pub struct AppState {
    base_dir: PathBuf,
    legacy_secret_dir: PathBuf,
    client: Mutex<Option<Arc<LitesealClient>>>,
    session: AsyncMutex<Option<StoredAccount>>,
}

impl AppState {
    pub fn new(base_dir: PathBuf, legacy_secret_dir: PathBuf) -> Result<Self, String> {
        std::fs::create_dir_all(base_dir.join("profiles")).map_err(|e| e.to_string())?;
        Ok(Self {
            base_dir,
            legacy_secret_dir,
            client: Mutex::new(None),
            session: AsyncMutex::new(None),
        })
    }

    pub fn client(&self) -> Result<Arc<LitesealClient>, String> {
        self.client
            .lock()
            .map_err(|e| e.to_string())?
            .clone()
            .ok_or_else(|| "No active account".to_string())
    }

    pub async fn session(&self) -> Result<StoredAccount, String> {
        self.session
            .lock()
            .await
            .clone()
            .ok_or_else(|| "No active session".to_string())
    }

    pub async fn activate(
        &self,
        account: StoredAccount,
        migrate_legacy: bool,
    ) -> Result<(), String> {
        let profile_dir = self.profile_dir(&account.server_url, &account.user_id)?;
        std::fs::create_dir_all(&profile_dir).map_err(|e| e.to_string())?;
        let db_path = profile_dir.join("data.db");
        if migrate_legacy && !db_path.exists() {
            self.migrate_legacy_database(&db_path)?;
        }
        let client = Arc::new(LitesealClient::new(
            db_path.to_str().ok_or("Profile database path is invalid")?,
        )?);
        save_account(&profile_dir.join("keystore.bin"), &account)?;
        let profile_id = profile_dir
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("Profile id is invalid")?;
        std::fs::write(self.base_dir.join("active_profile"), profile_id)
            .map_err(|e| e.to_string())?;
        *self.client.lock().map_err(|e| e.to_string())? = Some(client);
        *self.session.lock().await = Some(account);
        Ok(())
    }

    pub async fn update_session(&self, account: StoredAccount) -> Result<(), String> {
        let profile_dir = self.profile_dir(&account.server_url, &account.user_id)?;
        save_account(&profile_dir.join("keystore.bin"), &account)?;
        *self.session.lock().await = Some(account);
        Ok(())
    }

    pub async fn clear_runtime_session(&self) {
        if let Ok(mut client) = self.client.lock() {
            *client = None;
        }
        *self.session.lock().await = None;
    }

    pub fn load_active_account(&self) -> Result<Option<StoredAccount>, String> {
        let active_path = self.base_dir.join("active_profile");
        if !active_path.exists() {
            return self.load_legacy_account();
        }
        let profile_id = std::fs::read_to_string(active_path).map_err(|e| e.to_string())?;
        let path = self
            .base_dir
            .join("profiles")
            .join(profile_id.trim())
            .join("keystore.bin");
        load_account(&path).map(Some)
    }

    pub fn find_account(&self, username: &str, server_url: &str) -> Option<StoredAccount> {
        let entries = std::fs::read_dir(self.base_dir.join("profiles")).ok()?;
        for entry in entries.flatten() {
            let path = entry.path().join("keystore.bin");
            if let Ok(account) = load_account(&path) {
                if account.username.eq_ignore_ascii_case(username)
                    && normalized_origin(&account.server_url).ok()
                        == normalized_origin(server_url).ok()
                {
                    return Some(account);
                }
            }
        }
        None
    }

    fn profile_dir(&self, server_url: &str, user_id: &str) -> Result<PathBuf, String> {
        let origin = normalized_origin(server_url)?;
        let mut digest = Sha256::new();
        digest.update(origin.as_bytes());
        digest.update(user_id.as_bytes());
        Ok(self
            .base_dir
            .join("profiles")
            .join(hex::encode(digest.finalize())))
    }

    fn migrate_legacy_database(&self, destination: &Path) -> Result<(), String> {
        let legacy = self.base_dir.join("data.db");
        if !legacy.exists() {
            return Ok(());
        }
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let backup = self.base_dir.join(format!("data.db.{timestamp}.bak"));
        let temporary = destination.with_extension("db.migrating");
        std::fs::copy(&legacy, &backup).map_err(|e| e.to_string())?;
        if let Err(error) = std::fs::copy(&legacy, &temporary)
            .map_err(|e| e.to_string())
            .and_then(|_| {
                LitesealClient::new(temporary.to_str().ok_or("Migration path is invalid")?)
                    .map(|_| ())
            })
            .and_then(|_| std::fs::rename(&temporary, destination).map_err(|e| e.to_string()))
        {
            let _ = std::fs::remove_file(&temporary);
            return Err(format!("Legacy database migration failed: {error}"));
        }
        Ok(())
    }

    fn load_legacy_account(&self) -> Result<Option<StoredAccount>, String> {
        let encrypted = self.legacy_secret_dir.join("keystore.bin");
        let plaintext = self.legacy_secret_dir.join("keystore.json");
        let bytes = if encrypted.exists() {
            liteseal_core::secret_store::secret_store(encrypted).load()?
        } else if plaintext.exists() {
            std::fs::read(plaintext).map_err(|e| e.to_string())?
        } else {
            return Ok(None);
        };
        let legacy: liteseal_core::keystore::KeystoreData =
            serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        Ok(Some(StoredAccount {
            username: String::new(),
            user_id: legacy.user_id,
            access_token: legacy.token,
            refresh_token: legacy.refresh_token,
            device_id: legacy.device_id,
            server_url: legacy.server_url,
            public_key: legacy.public_key,
            secret_key: legacy.secret_key,
            signing_public_key: legacy.ed25519_pk,
            signing_secret_key: legacy.ed25519_sk,
            pending_revocation: false,
            pending_revocation_all: false,
        }))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct StoredAccount {
    pub username: String,
    pub user_id: String,
    pub access_token: String,
    pub refresh_token: String,
    pub device_id: String,
    pub server_url: String,
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub signing_public_key: Vec<u8>,
    pub signing_secret_key: Vec<u8>,
    #[serde(default)]
    pub pending_revocation: bool,
    #[serde(default)]
    pub pending_revocation_all: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionView {
    pub user_id: String,
    pub username: String,
    pub device_id: String,
    pub server_url: String,
    pub connected: bool,
}

impl StoredAccount {
    pub fn view(&self, connected: bool) -> SessionView {
        SessionView {
            user_id: self.user_id.clone(),
            username: self.username.clone(),
            device_id: self.device_id.clone(),
            server_url: self.server_url.clone(),
            connected,
        }
    }

    pub fn encryption_secret(&self) -> Result<[u8; 32], String> {
        self.secret_key
            .clone()
            .try_into()
            .map_err(|_| "Stored encryption key is invalid".to_string())
    }

    pub fn signing_secret(&self) -> Result<[u8; 64], String> {
        self.signing_secret_key
            .clone()
            .try_into()
            .map_err(|_| "Stored signing key is invalid".to_string())
    }
}

fn normalized_origin(server_url: &str) -> Result<String, String> {
    let normalized = liteseal_core::api::normalize_server_url(server_url)?;
    let parsed = url::Url::parse(&normalized).map_err(|e| e.to_string())?;
    Ok(parsed.origin().ascii_serialization())
}

fn save_account(path: &Path, account: &StoredAccount) -> Result<(), String> {
    let bytes = serde_json::to_vec(account).map_err(|e| e.to_string())?;
    liteseal_core::secret_store::secret_store(path.to_path_buf()).save(&bytes)
}

fn load_account(path: &Path) -> Result<StoredAccount, String> {
    let bytes = liteseal_core::secret_store::secret_store(path.to_path_buf()).load()?;
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_profiles_are_stable_and_isolated_by_origin_and_user() {
        let root = std::env::temp_dir().join(format!(
            "liteseal-profile-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let state = AppState::new(root.clone(), root.join("legacy")).unwrap();
        let first = state
            .profile_dir("http://localhost:3000/", "user-a")
            .unwrap();
        let equivalent = state
            .profile_dir("http://localhost:3000", "user-a")
            .unwrap();
        let other_user = state
            .profile_dir("http://localhost:3000", "user-b")
            .unwrap();
        let other_origin = state.profile_dir("https://example.com", "user-a").unwrap();
        assert_eq!(first, equivalent);
        assert_ne!(first, other_user);
        assert_ne!(first, other_origin);
        std::fs::remove_dir_all(root).unwrap();
    }
}
