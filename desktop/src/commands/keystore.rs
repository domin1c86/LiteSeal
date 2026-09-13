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

pub async fn sign_out() -> Result<Option<String>, String> {
    let saved = keystore::load_keypair()?;
    // Clear local login capability first, even when the server is unreachable.
    keystore::clear_session()?;
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
