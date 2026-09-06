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
    bootstrap_state(&state).await
}

async fn bootstrap_state(state: &AppState) -> Result<BootstrapState, String> {
    let Some(mut account) = state.load_active_account()? else {
        return Ok(BootstrapState {
            session: None,
            offline: false,
        });
    };
    if account.server_url.is_empty() {
        account.server_url = "http://localhost:3000".to_string();
    }
    // A deliberate logout must never become an offline login on restart.
    // Retry a pending revocation without activating the account or socket.
    if account.pending_revocation
        || (account.access_token.is_empty() && account.refresh_token.is_empty())
    {
        if account.pending_revocation
            && revoke_remote(&account, account.pending_revocation_all)
                .await
                .is_ok()
        {
            account.pending_revocation = false;
            account.pending_revocation_all = false;
            account.access_token.clear();
            account.refresh_token.clear();
            state.update_session(account).await?;
        }
        state.clear_runtime_session().await;
        return Ok(BootstrapState {
            session: None,
            offline: false,
        });
    }

    state.activate(account.clone(), true).await?;
    let client = state.client()?;

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
        pending_revocation_all: false,
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
        pending_revocation_all: false,
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
    let result = revoke_remote(&account, all).await;
    account.pending_revocation = result.is_err();
    account.pending_revocation_all = result.is_err() && all;
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

async fn revoke_remote(account: &StoredAccount, all: bool) -> Result<(), String> {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        if all {
            api::logout_all(account.server_url.clone(), account.access_token.clone()).await
        } else {
            api::logout(account.server_url.clone(), account.access_token.clone()).await
        }
    })
    .await
    .map_err(|_| "Session revocation timed out; will retry on next startup".to_string())?
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct Fixture {
        state: AppState,
        root: std::path::PathBuf,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            // This fixture owns its unique temporary profile directory.
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    async fn fixture(server_url: String, pending: bool, all: bool) -> Fixture {
        let root = std::env::temp_dir().join(format!(
            "liteseal-logout-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let state = AppState::new(root.clone(), root.join("legacy")).unwrap();
        let keys = liteseal_shared::crypto::generate_keypair().unwrap();
        state
            .activate(
                StoredAccount {
                    username: "test".to_string(),
                    user_id: "test-user".to_string(),
                    device_id: "test-device".to_string(),
                    server_url,
                    access_token: if pending {
                        "test-access".to_string()
                    } else {
                        String::new()
                    },
                    refresh_token: if pending {
                        "test-refresh".to_string()
                    } else {
                        String::new()
                    },
                    public_key: keys.public_key.to_vec(),
                    secret_key: keys.secret_key.to_vec(),
                    signing_public_key: keys.ed25519_pk.to_vec(),
                    signing_secret_key: keys.ed25519_sk.to_vec(),
                    pending_revocation: pending,
                    pending_revocation_all: all,
                },
                false,
            )
            .await
            .unwrap();
        state.clear_runtime_session().await;
        Fixture { state, root }
    }

    #[tokio::test]
    async fn completed_logout_does_not_restore_offline_history_session() {
        let fixture = fixture("http://127.0.0.1:1".to_string(), false, false).await;
        let result = bootstrap_state(&fixture.state).await.unwrap();
        assert!(result.session.is_none());
        assert!(!result.offline);
        assert!(fixture.state.client().is_err());
        assert!(fixture.state.session().await.is_err());
    }

    #[tokio::test]
    async fn failed_revocation_stays_logged_out_and_preserves_retry() {
        let fixture = fixture("http://127.0.0.1:1".to_string(), true, true).await;
        let result = bootstrap_state(&fixture.state).await.unwrap();
        assert!(result.session.is_none());
        assert!(fixture.state.client().is_err());
        let stored = fixture.state.load_active_account().unwrap().unwrap();
        assert!(stored.pending_revocation);
        assert!(stored.pending_revocation_all);
        assert!(!stored.refresh_token.is_empty());
    }

    #[tokio::test]
    async fn pending_logout_all_retries_the_original_scope_without_login() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let request = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut buffer = [0; 1024];
            loop {
                let count = socket.read(&mut buffer).await.unwrap();
                assert_ne!(count, 0);
                bytes.extend_from_slice(&buffer[..count]);
                if bytes.windows(4).any(|part| part == b"\r\n\r\n") {
                    break;
                }
            }
            socket
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            String::from_utf8(bytes)
                .unwrap()
                .lines()
                .next()
                .unwrap()
                .to_string()
        });
        let fixture = fixture(format!("http://{address}"), true, true).await;
        let result = bootstrap_state(&fixture.state).await.unwrap();
        assert!(result.session.is_none());
        assert!(fixture.state.client().is_err());
        assert_eq!(request.await.unwrap(), "POST /auth/logout_all HTTP/1.1");
        let stored = fixture.state.load_active_account().unwrap().unwrap();
        assert!(!stored.pending_revocation);
        assert!(stored.access_token.is_empty());
        assert!(stored.refresh_token.is_empty());
    }
}
