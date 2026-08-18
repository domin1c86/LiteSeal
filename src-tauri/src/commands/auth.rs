use liteseal_core::api;
use serde::{Deserialize, Serialize};
use tauri::State;

use crate::{AppState, SessionView, StoredAccount};

const DEVICE_NAME: &str = "Windows desktop";

#[derive(Debug, Serialize, Deserialize)]
pub struct BootstrapState {
    pub session: Option<SessionView>,
    pub offline: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum AuthOutcome {
    Authenticated { session: SessionView },
    DeviceReplacementRequired,
}

#[tauri::command]
pub async fn bootstrap(state: State<'_, AppState>) -> Result<BootstrapState, String> {
    let Some(mut account) = state.load_active_account()? else {
        return Ok(BootstrapState {
            session: None,
            offline: false,
        });
    };
    if account.server_url.is_empty() {
        account.server_url = "http://localhost:3000".to_string();
    }
    state.activate(account.clone(), true).await?;
    let client = state.client()?;

    if account.pending_revocation
        && api::logout(account.server_url.clone(), account.access_token.clone())
            .await
            .is_ok()
    {
        account.pending_revocation = false;
        account.access_token.clear();
        account.refresh_token.clear();
        state.update_session(account).await?;
        state.clear_runtime_session().await;
        return Ok(BootstrapState {
            session: None,
            offline: false,
        });
    }

    if !account.access_token.is_empty()
        && !account.device_id.is_empty()
        && client
            .connect_relay(
                account.server_url.clone(),
                account.user_id.clone(),
                account.access_token.clone(),
                account.device_id.clone(),
            )
            .await
            .is_ok()
    {
        return Ok(BootstrapState {
            session: Some(account.view(true)),
            offline: false,
        });
    }

    if !account.refresh_token.is_empty() && !account.device_id.is_empty() {
        if let Ok(refreshed) =
            api::refresh_session(account.server_url.clone(), account.refresh_token.clone()).await
        {
            account.access_token = refreshed.access_token.unwrap_or(refreshed.token);
            account.refresh_token = refreshed.refresh_token.unwrap_or_default();
            state.update_session(account.clone()).await?;
            if client
                .connect_relay(
                    account.server_url.clone(),
                    account.user_id.clone(),
                    account.access_token.clone(),
                    account.device_id.clone(),
                )
                .await
                .is_ok()
            {
                return Ok(BootstrapState {
                    session: Some(account.view(true)),
                    offline: false,
                });
            }
        }
    }

    Ok(BootstrapState {
        session: Some(account.view(false)),
        offline: true,
    })
}

#[tauri::command]
pub async fn register(
    username: String,
    password: String,
    invite_code: String,
    server_url: String,
    state: State<'_, AppState>,
) -> Result<SessionView, String> {
    let keys = liteseal_shared::crypto::generate_keypair().map_err(|e| e.to_string())?;
    let result = api::register(
        username.clone(),
        password,
        invite_code,
        server_url.clone(),
        DEVICE_NAME,
        keys.public_key.to_vec(),
        keys.ed25519_pk.to_vec(),
    )
    .await?;
    let account = StoredAccount {
        username,
        user_id: result.user_id,
        access_token: result.access_token.unwrap_or(result.token),
        refresh_token: result.refresh_token.unwrap_or_default(),
        device_id: result.device_id.unwrap_or_default(),
        server_url,
        public_key: keys.public_key.to_vec(),
        secret_key: keys.secret_key.to_vec(),
        signing_public_key: keys.ed25519_pk.to_vec(),
        signing_secret_key: keys.ed25519_sk.to_vec(),
        pending_revocation: false,
    };
    state.activate(account.clone(), false).await?;
    state
        .client()?
        .connect_relay(
            account.server_url.clone(),
            account.user_id.clone(),
            account.access_token.clone(),
            account.device_id.clone(),
        )
        .await?;
    Ok(account.view(true))
}

#[tauri::command]
pub async fn login(
    username: String,
    password: String,
    server_url: String,
    replace_device: bool,
    state: State<'_, AppState>,
) -> Result<AuthOutcome, String> {
    let stored = state.find_account(username.trim(), &server_url);
    let keys = match (replace_device, stored.as_ref()) {
        (false, Some(stored)) => liteseal_shared::crypto::KeyPair {
            public_key: stored
                .public_key
                .clone()
                .try_into()
                .map_err(|_| "Stored public key is invalid")?,
            secret_key: stored.encryption_secret()?,
            ed25519_pk: stored
                .signing_public_key
                .clone()
                .try_into()
                .map_err(|_| "Stored signing public key is invalid")?,
            ed25519_sk: stored.signing_secret()?,
        },
        _ => liteseal_shared::crypto::generate_keypair().map_err(|e| e.to_string())?,
    };
    let device_id = if replace_device {
        None
    } else {
        stored.as_ref().map(|account| account.device_id.clone())
    };
    let result = match api::login(
        username.clone(),
        password,
        server_url.clone(),
        DEVICE_NAME,
        keys.public_key.to_vec(),
        keys.ed25519_pk.to_vec(),
        device_id,
        replace_device,
    )
    .await
    {
        Ok(result) => result,
        Err(error) if error == "device_replacement_required" => {
            return Ok(AuthOutcome::DeviceReplacementRequired)
        }
        Err(error) => return Err(error),
    };
    let account = StoredAccount {
        username,
        user_id: result.user_id,
        access_token: result.access_token.unwrap_or(result.token),
        refresh_token: result.refresh_token.unwrap_or_default(),
        device_id: result.device_id.unwrap_or_default(),
        server_url,
        public_key: keys.public_key.to_vec(),
        secret_key: keys.secret_key.to_vec(),
        signing_public_key: keys.ed25519_pk.to_vec(),
        signing_secret_key: keys.ed25519_sk.to_vec(),
        pending_revocation: false,
    };
    state.activate(account.clone(), false).await?;
    state
        .client()?
        .connect_relay(
            account.server_url.clone(),
            account.user_id.clone(),
            account.access_token.clone(),
            account.device_id.clone(),
        )
        .await?;
    Ok(AuthOutcome::Authenticated {
        session: account.view(true),
    })
}

#[tauri::command]
pub async fn logout(state: State<'_, AppState>) -> Result<(), String> {
    revoke_and_clear(&state, false).await
}

#[tauri::command]
pub async fn logout_all(state: State<'_, AppState>) -> Result<(), String> {
    revoke_and_clear(&state, true).await
}

async fn revoke_and_clear(state: &AppState, all: bool) -> Result<(), String> {
    let mut account = state.session().await?;
    let result = if all {
        api::logout_all(account.server_url.clone(), account.access_token.clone()).await
    } else {
        api::logout(account.server_url.clone(), account.access_token.clone()).await
    };
    account.pending_revocation = result.is_err();
    if result.is_ok() {
        account.access_token.clear();
        account.refresh_token.clear();
    }
    state.update_session(account).await?;
    if let Ok(client) = state.client() {
        client.disconnect().await;
    }
    state.clear_runtime_session().await;
    result.or(Ok(()))
}
