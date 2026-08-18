use axum::{
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{auth::service, state::AppState};

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    pub invite_code: String,
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
    ConnectInfo(remote_addr): ConnectInfo<std::net::SocketAddr>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, StatusCode> {
    let username = req.username.trim();
    if username.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    enforce_auth_rate_limit(&state, username, remote_addr.ip()).await?;
    let public_key = req.public_key.unwrap_or_default();
    let ed25519_pk = req.ed25519_pk.unwrap_or_default();
    service::validate_key_material(&public_key, &ed25519_pk)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let password_hash =
        service::hash_password(&req.password).map_err(|_| StatusCode::BAD_REQUEST)?;
    let access_token = service::generate_token();
    let refresh_token = service::generate_token();
    let (user, device) = state
        .db
        .register_with_invite(
            username,
            &password_hash,
            &service::hash_token(req.invite_code.trim()),
            req.device_name.trim(),
            &public_key,
            &ed25519_pk,
            &service::hash_token(&access_token),
            &service::hash_token(&refresh_token),
        )
        .await
        .map_err(|error| {
            if error
                .as_database_error()
                .and_then(|db| db.code())
                .as_deref()
                == Some("23505")
            {
                StatusCode::CONFLICT
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        })?
        .ok_or(StatusCode::FORBIDDEN)?;

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
    #[serde(default)]
    pub replace_device: bool,
}

pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<std::net::SocketAddr>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<RegisterResponse>, StatusCode> {
    enforce_auth_rate_limit(&state, req.username.trim(), remote_addr.ip()).await?;
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
    let access_token = service::generate_token();
    let refresh_token = service::generate_token();
    let access_token_hash = service::hash_token(&access_token);
    let refresh_token_hash = service::hash_token(&refresh_token);
    let device = match req.device_id {
        Some(device_id) => {
            let existing = state
                .db
                .get_user_device(&user.id, &device_id)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            match existing {
                Some(device) if !device.revoked => {
                    // A login is not a key-rotation endpoint. Unexpected key
                    // changes must be resolved explicitly to preserve pinning.
                    if device.public_key != public_key || device.ed25519_pk != ed25519_pk {
                        return Err(StatusCode::FORBIDDEN);
                    }
                    state
                        .db
                        .create_session(
                            &user.id,
                            &device.id,
                            &access_token_hash,
                            &refresh_token_hash,
                        )
                        .await
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                    device
                }
                _ => return Err(StatusCode::FORBIDDEN),
            }
        }
        None => {
            let has_active_device = state
                .db
                .has_active_device(&user.id)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            if has_active_device && !req.replace_device {
                return Err(StatusCode::CONFLICT);
            }
            state
                .db
                .create_device_and_session(
                    &user.id,
                    req.device_name.trim(),
                    &public_key,
                    &ed25519_pk,
                    &access_token_hash,
                    &refresh_token_hash,
                    has_active_device,
                )
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        }
    };
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
    let access_token = service::generate_token();
    let refresh_token = service::generate_token();
    let (user_id, device_id) = state
        .db
        .rotate_refresh_session(
            &refresh_token_hash,
            &service::hash_token(&access_token),
            &service::hash_token(&refresh_token),
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

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
    if state
        .db
        .has_active_device(&user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        return Err(StatusCode::CONFLICT);
    }
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

pub(crate) async fn user_from_bearer(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<String, StatusCode> {
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

async fn enforce_auth_rate_limit(
    state: &AppState,
    username: &str,
    remote_ip: std::net::IpAddr,
) -> Result<(), StatusCode> {
    let account_key = format!("auth:account:{}", username.to_lowercase());
    let account_allowed = state
        .db
        .hit_rate_limit(&account_key, 20, 60)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let ip_key = format!("auth:ip:{remote_ip}");
    let ip_allowed = state
        .db
        .hit_rate_limit(&ip_key, 60, 60)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if account_allowed && ip_allowed {
        Ok(())
    } else {
        Err(StatusCode::TOO_MANY_REQUESTS)
    }
}

fn default_device_name() -> String {
    "Windows desktop".to_string()
}
