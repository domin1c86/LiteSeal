use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::state::AppState;

#[derive(Deserialize)]
pub struct SearchQuery {
    pub q: String,
}

#[derive(Serialize)]
pub struct UserSearchResult {
    pub user_id: String,
    pub username: String,
    pub public_key: Option<Vec<u8>>,
    pub ed25519_pk: Option<Vec<u8>>,
}

#[derive(Serialize)]
pub struct PublicKeyResponse {
    pub user_id: String,
    pub username: String,
    pub public_key: Option<Vec<u8>>,
    pub ed25519_pk: Option<Vec<u8>>,
}

#[derive(Serialize)]
pub struct DeviceResponse {
    pub id: String,
    pub name: String,
    pub public_key: Vec<u8>,
    pub ed25519_pk: Vec<u8>,
    pub revoked: bool,
}

#[derive(Deserialize)]
pub struct TrustContactRequest {
    pub fingerprint: String,
    pub state: String,
}

fn escape_like_pattern(query: &str) -> String {
    query
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

pub async fn search_users(
    State(state): State<AppState>,
    Query(params): Query<SearchQuery>,
) -> Json<Vec<UserSearchResult>> {
    let query = params.q.trim().to_lowercase();
    let mut results = Vec::new();

    if query.is_empty() {
        return Json(results);
    }

    // One row per user (their newest active device), wildcards escaped.
    let rows = sqlx::query(
        r#"SELECT DISTINCT ON (u.id) u.id, u.username, d.public_key, d.ed25519_pk
         FROM users u
         JOIN devices d ON d.user_id = u.id AND d.revoked = false
         WHERE lower(u.username) LIKE $1 ESCAPE '\' OR u.id LIKE $1 ESCAPE '\'
         ORDER BY u.id, d.created_at DESC
         LIMIT 50"#,
    )
    .bind(format!("%{}%", escape_like_pattern(&query)))
    .fetch_all(state.db.pool())
    .await
    .unwrap_or_default();

    for row in rows {
        use sqlx::Row;
        let public_key: Vec<u8> = row.get("public_key");
        if public_key.len() == 32 {
            results.push(UserSearchResult {
                user_id: row.get("id"),
                username: row.get("username"),
                public_key: Some(public_key),
                ed25519_pk: Some(row.get("ed25519_pk")),
            });
        }
    }

    results.sort_by(|a, b| a.username.cmp(&b.username));
    Json(results)
}

pub async fn get_public_key(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<Json<PublicKeyResponse>, StatusCode> {
    let username = state
        .db
        .get_username(&user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let rows = state
        .db
        .list_user_devices(&user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    match rows.into_iter().rev().find(|device| !device.revoked) {
        Some(device) => Ok(Json(PublicKeyResponse {
            user_id,
            username,
            public_key: Some(device.public_key),
            ed25519_pk: Some(device.ed25519_pk),
        })),
        None => Err(StatusCode::NOT_FOUND),
    }
}

pub async fn list_user_devices(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<Json<Vec<DeviceResponse>>, StatusCode> {
    let devices = state
        .db
        .list_user_devices(&user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(
        devices
            .into_iter()
            .map(|device| DeviceResponse {
                id: device.id,
                name: device.name,
                public_key: device.public_key,
                ed25519_pk: device.ed25519_pk,
                revoked: device.revoked,
            })
            .collect(),
    ))
}

pub async fn trust_contact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(contact_user_id): Path<String>,
    Json(req): Json<TrustContactRequest>,
) -> Result<StatusCode, StatusCode> {
    match req.state.as_str() {
        "unverified" | "verified" | "key_changed" => {}
        _ => return Err(StatusCode::BAD_REQUEST),
    }
    let owner_user_id = user_from_bearer(&state, &headers).await?;
    state
        .db
        .upsert_trusted_contact(
            &owner_user_id,
            &contact_user_id,
            req.fingerprint.trim(),
            &req.state,
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
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
        .user_for_access_token(&crate::auth::service::hash_token(token))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)
}
