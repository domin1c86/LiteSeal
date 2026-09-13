use crate::AppState;
use liteseal_core::keystore::KeystoreData;
use serde::Serialize;

/// The renderer-visible part of an identity; secret keys stay in Rust.
#[derive(Serialize)]
pub struct IdentityView {
    pub user_id: String,
    pub token: String,
    pub refresh_token: String,
    pub device_id: String,
    pub server_url: String,
    pub public_key: Vec<u8>,
    pub ed25519_pk: Vec<u8>,
    /// False for freshly generated keys not yet bound to an account.
    pub saved: bool,
}

fn view(data: &KeystoreData, saved: bool) -> IdentityView {
    IdentityView {
        user_id: data.user_id.clone(),
        token: data.token.clone(),
        refresh_token: data.refresh_token.clone(),
        device_id: data.device_id.clone(),
        server_url: data.server_url.clone(),
        public_key: data.public_key.clone(),
        ed25519_pk: data.ed25519_pk.clone(),
        saved,
    }
}

fn missing_identity(error: &str) -> bool {
    error.contains("No saved keypair")
}

pub fn load_identity(state: &AppState) -> Result<IdentityView, String> {
    Ok(view(&state.identity()?, true))
}

/// Returns the saved identity, or generates keys for a new account. Any other
/// keystore error is returned so a damaged identity is never overwritten.
pub fn prepare_identity(state: &AppState) -> Result<IdentityView, String> {
    match state.identity() {
        Ok(saved) => Ok(view(&saved, true)),
        Err(error) if missing_identity(&error) => Ok(view(&state.pending_keys()?, false)),
        Err(error) => Err(error),
    }
}

/// Binds session credentials to the saved identity, or to the generated keys
/// the account was just registered or logged in with.
pub fn save_session(
    user_id: String,
    token: String,
    refresh_token: String,
    device_id: String,
    server_url: String,
    state: &AppState,
) -> Result<IdentityView, String> {
    let keys = match state.identity() {
        Ok(saved) if saved.user_id == user_id => saved,
        Ok(_) => return Err("账号与本机历史不匹配，原密钥未修改。".to_string()),
        Err(error) if missing_identity(&error) => state
            .existing_pending_keys()?
            .ok_or("No generated keys to bind to this session")?,
        Err(error) => return Err(error),
    };
    let data = KeystoreData {
        user_id,
        token,
        refresh_token,
        device_id,
        server_url,
        ..keys
    };
    state.save_identity(data.clone())?;
    // Only discard generated keys once they are durably saved.
    state.clear_pending_keys()?;
    Ok(view(&data, true))
}

pub fn clear_keypair(state: &AppState) -> Result<(), String> {
    state.clear_identity()
}

pub async fn sign_out(state: &AppState) -> Result<Option<String>, String> {
    let saved = state.identity()?;
    // Clear local login capability first, even when the server is unreachable.
    state.save_identity(KeystoreData {
        token: String::new(),
        refresh_token: String::new(),
        ..saved.clone()
    })?;
    if saved.token.is_empty() {
        return Ok(None);
    }
    let url = liteseal_core::api::normalize_server_url(&saved.server_url)?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;
    match client
        .post(format!("{url}/auth/logout"))
        .json(&serde_json::json!({ "access_token": saved.token }))
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => Ok(None),
        _ => Ok(Some(
            "已退出本机，密钥保留；服务器暂不可达，远端会话尚未确认撤销。".into(),
        )),
    }
}
