use crate::AppState;
use liteseal_core::api::{self, RegisterResult};

const DEVICE_NAME: &str = "Windows desktop";

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ConnectResult {
    pub connected: bool,
}

pub async fn register(
    invite_code: String,
    username: String,
    password: String,
    server_url: String,
    public_key: Vec<u8>,
    ed25519_pk: Vec<u8>,
) -> Result<RegisterResult, String> {
    api::register(
        invite_code,
        username,
        password,
        server_url,
        DEVICE_NAME,
        public_key,
        ed25519_pk,
    )
    .await
}

pub async fn login(
    username: String,
    password: String,
    server_url: String,
    public_key: Vec<u8>,
    ed25519_pk: Vec<u8>,
    device_id: Option<String>,
) -> Result<RegisterResult, String> {
    api::login(
        username,
        password,
        server_url,
        DEVICE_NAME,
        public_key,
        ed25519_pk,
        device_id,
    )
    .await
}

pub async fn refresh_session(
    server_url: String,
    refresh_token: String,
) -> Result<RegisterResult, String> {
    api::refresh_session(server_url, refresh_token).await
}

pub async fn connect_relay(
    server_url: String,
    user_id: String,
    token: String,
    device_id: String,
    state: &AppState,
) -> Result<ConnectResult, String> {
    state
        .client
        .connect_relay(server_url, user_id, token, device_id)
        .await?;
    Ok(ConnectResult { connected: true })
}

pub async fn disconnect(state: &AppState) -> Result<(), String> {
    state.client.disconnect().await;
    Ok(())
}

pub async fn validate_invite(server_url: String, invite_code: String) -> Result<bool, String> {
    api::validate_invite(server_url, invite_code).await
}
