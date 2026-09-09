use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{auth::service, state::AppState};

#[derive(Deserialize)]
pub struct RegisterRequest {
    #[serde(default)]
    pub invite_code: String,
    pub username: String,
    pub password: String,
    #[serde(default = "default_device_name")]
    pub device_name: String,
    pub public_key: Option<Vec<u8>>,
    pub ed25519_pk: Option<Vec<u8>>,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub user_id: String,
    pub access_token: String,
    pub refresh_token: String,
    pub device_id: String,
    pub token: String,
}

pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, StatusCode> {
    if !state.accepts_invite(&req.invite_code) {
        return Err(StatusCode::FORBIDDEN);
    }
    let username = req.username.trim();
    if username.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    enforce_auth_rate_limit(&state, username).await?;
    let public_key = req.public_key.unwrap_or_default();
    let ed25519_pk = req.ed25519_pk.unwrap_or_default();
    service::validate_key_material(&public_key, &ed25519_pk)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let password_hash =
        service::hash_password(&req.password).map_err(|_| StatusCode::BAD_REQUEST)?;
    let user = state
        .db
        .create_user(username, &password_hash)
        .await
        .map_err(|_| StatusCode::CONFLICT)?;
    let device = state
        .db
        .register_device(&user.id, &req.device_name, &public_key, &ed25519_pk)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let access_token = service::generate_token();
    let refresh_token = service::generate_token();
    state
        .db
        .create_session(
            &user.id,
            &device.id,
            &service::hash_token(&access_token),
            &service::hash_token(&refresh_token),
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    tracing::info!("User registered: {} ({})", username, user.id);
    let _ = state
        .db
        .insert_audit_event(Some(&user.id), "register")
        .await;

    Ok(Json(RegisterResponse {
        user_id: user.id,
        token: access_token.clone(),
        access_token,
        refresh_token,
        device_id: device.id,
    }))
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    #[serde(default = "default_device_name")]
    pub device_name: String,
    pub device_id: Option<String>,
    pub device_public_key: Option<Vec<u8>>,
    pub ed25519_pk: Option<Vec<u8>>,
}

pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<RegisterResponse>, StatusCode> {
    enforce_auth_rate_limit(&state, req.username.trim()).await?;
    let user = state
        .db
        .get_user_by_username(req.username.trim())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if !service::verify_password(&req.password, &user.password_hash) {
        let _ = state
            .db
            .insert_audit_event(Some(&user.id), "login_failed")
            .await;
        return Err(StatusCode::UNAUTHORIZED);
    }
    tracing::info!("User logged in: {} ({})", user.username, user.id);

    let public_key = req.device_public_key.ok_or(StatusCode::BAD_REQUEST)?;
    let ed25519_pk = req.ed25519_pk.ok_or(StatusCode::BAD_REQUEST)?;
    service::validate_key_material(&public_key, &ed25519_pk)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let device = match req.device_id {
        Some(device_id) => {
            let existing = state
                .db
                .get_user_device(&user.id, &device_id)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            match existing {
                Some(device) if !device.revoked => {
                    state
                        .db
                        .update_device_keys(&user.id, &device.id, &public_key, &ed25519_pk)
                        .await
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                    crate::db::DeviceRecord {
                        public_key: public_key.clone(),
                        ed25519_pk: ed25519_pk.clone(),
                        ..device
                    }
                }
                _ => return Err(StatusCode::FORBIDDEN),
            }
        }
        None => state
            .db
            .register_device(&user.id, &req.device_name, &public_key, &ed25519_pk)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    };
    let access_token = service::generate_token();
    let refresh_token = service::generate_token();
    state
        .db
        .create_session(
            &user.id,
            &device.id,
            &service::hash_token(&access_token),
            &service::hash_token(&refresh_token),
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let _ = state.db.insert_audit_event(Some(&user.id), "login").await;

    Ok(Json(RegisterResponse {
        user_id: user.id,
        token: access_token.clone(),
        access_token,
        refresh_token,
        device_id: device.id,
    }))
}

#[derive(Deserialize)]
pub struct LogoutRequest {
    pub access_token: String,
}

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

pub async fn refresh(
    State(state): State<AppState>,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<RegisterResponse>, StatusCode> {
    let refresh_token_hash = service::hash_token(&req.refresh_token);
    let (user_id, device_id) = state
        .db
        .validate_refresh_token(&refresh_token_hash)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    state
        .db
        .revoke_refresh_token(&refresh_token_hash)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let access_token = service::generate_token();
    let refresh_token = service::generate_token();
    state
        .db
        .create_session(
            &user_id,
            &device_id,
            &service::hash_token(&access_token),
            &service::hash_token(&refresh_token),
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(RegisterResponse {
        user_id,
        token: access_token.clone(),
        access_token,
        refresh_token,
        device_id,
    }))
}

pub async fn logout(
    State(state): State<AppState>,
    Json(req): Json<LogoutRequest>,
) -> Result<StatusCode, StatusCode> {
    state
        .db
        .revoke_session(&service::hash_token(&req.access_token))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let _ = state.db.insert_audit_event(None, "logout").await;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn logout_all(
    State(state): State<AppState>,
    Json(req): Json<LogoutRequest>,
) -> Result<StatusCode, StatusCode> {
    let user_id = state
        .db
        .user_for_access_token(&service::hash_token(&req.access_token))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    state
        .db
        .revoke_all_sessions(&user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let _ = state
        .db
        .insert_audit_event(Some(&user_id), "logout_all")
        .await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
pub struct DeviceResponse {
    pub id: String,
    pub name: String,
    pub public_key: Vec<u8>,
    pub ed25519_pk: Vec<u8>,
    pub revoked: bool,
}

pub async fn list_devices(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<DeviceResponse>>, StatusCode> {
    let user_id = user_from_bearer(&state, &headers).await?;
    let devices = state
        .db
        .list_user_devices(&user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(
        devices
            .into_iter()
            .map(|d| DeviceResponse {
                id: d.id,
                name: d.name,
                public_key: d.public_key,
                ed25519_pk: d.ed25519_pk,
                revoked: d.revoked,
            })
            .collect(),
    ))
}

pub async fn revoke_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let user_id = user_from_bearer(&state, &headers).await?;
    state
        .db
        .revoke_device(&user_id, &device_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct RegisterDeviceRequest {
    pub device_name: String,
    pub public_key: Vec<u8>,
    pub ed25519_pk: Vec<u8>,
}

pub async fn register_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegisterDeviceRequest>,
) -> Result<Json<DeviceResponse>, StatusCode> {
    service::validate_key_material(&req.public_key, &req.ed25519_pk)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let user_id = user_from_bearer(&state, &headers).await?;
    let device = state
        .db
        .register_device(
            &user_id,
            req.device_name.trim(),
            &req.public_key,
            &req.ed25519_pk,
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(DeviceResponse {
        id: device.id,
        name: device.name,
        public_key: device.public_key,
        ed25519_pk: device.ed25519_pk,
        revoked: device.revoked,
    }))
}

pub async fn rotate_device_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
    Json(req): Json<RegisterDeviceRequest>,
) -> Result<StatusCode, StatusCode> {
    service::validate_key_material(&req.public_key, &req.ed25519_pk)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let user_id = user_from_bearer(&state, &headers).await?;
    state
        .db
        .update_device_keys(&user_id, &device_id, &req.public_key, &req.ed25519_pk)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let _ = state
        .db
        .insert_audit_event(Some(&user_id), "device_keys_rotated")
        .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn user_from_bearer(state: &AppState, headers: &HeaderMap) -> Result<String, StatusCode> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let token = value
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;
    state
        .db
        .user_for_access_token(&service::hash_token(token))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)
}

async fn enforce_auth_rate_limit(state: &AppState, username: &str) -> Result<(), StatusCode> {
    let key = format!("auth:{}", username.to_lowercase());
    let allowed = state
        .db
        .hit_rate_limit(&key, 20, 60)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if allowed {
        Ok(())
    } else {
        Err(StatusCode::TOO_MANY_REQUESTS)
    }
}

fn default_device_name() -> String {
    "Windows desktop".to_string()
}

#[derive(Deserialize)]
pub struct InviteRequest {
    pub invite_code: String,
}

pub async fn validate_invite(
    State(state): State<AppState>,
    Json(req): Json<InviteRequest>,
) -> Json<bool> {
    Json(state.accepts_invite(&req.invite_code))
}

#[cfg(test)]
mod invite_tests {
    use super::*;
    use axum::{routing::post, Router};
    use std::sync::Arc;

    #[tokio::test]
    async fn invitation_gate_is_reusable_and_cannot_be_bypassed_over_http() {
        // A lazy pool deliberately has no database: rejected requests must never create users.
        let db = crate::db::Db::connect_lazy("postgres://localhost/liteseal_invite_test").unwrap();
        let mut state = AppState::new(db);
        assert!(!state.accepts_invite("LITESEAL-WIN-ALPHA"));
        assert!(!state.accepts_invite(""));
        state.invite_codes = Arc::new(vec!["LITESEAL-WIN-ALPHA".into()]);
        let app = Router::new()
            .route("/auth/invite/validate", post(validate_invite))
            .route("/auth/register", post(register))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = reqwest::Client::new();
        for _ in 0..3 {
            let valid = client
                .post(format!("{base}/auth/invite/validate"))
                .json(&serde_json::json!({"invite_code": " LITESEAL-WIN-ALPHA "}))
                .send()
                .await
                .unwrap()
                .json::<bool>()
                .await
                .unwrap();
            assert!(valid, "validation must not consume reusable invitations");
        }
        for code in ["", "invalid", "liteseal-win-alpha"] {
            let valid = client
                .post(format!("{base}/auth/invite/validate"))
                .json(&serde_json::json!({"invite_code": code}))
                .send()
                .await
                .unwrap()
                .json::<bool>()
                .await
                .unwrap();
            assert!(!valid);
            let response = client.post(format!("{base}/auth/register"))
                .json(&serde_json::json!({"username": "test", "password": "password123", "invite_code": code}))
                .send().await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
        let response = client
            .post(format!("{base}/auth/register"))
            .json(&serde_json::json!({"username": "test", "password": "password123"}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        task.abort();
    }
}
