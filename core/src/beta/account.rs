use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Account {
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

impl Account {
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
