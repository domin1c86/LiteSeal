use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::state::AppState;

pub const MIGRATION: &str = "ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL DEFAULT ''; ALTER TABLE users ADD COLUMN avatar_png BYTEA";

#[derive(Serialize)]
pub struct Profile {
    user_id: String,
    username: String,
    display_name: String,
    avatar_png: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateProfile {
    display_name: String,
    avatar_png: Option<String>,
}

fn valid_name(name: &str) -> bool {
    name.chars().count() <= 40 && !name.chars().any(char::is_control)
}

fn decode_avatar(encoded: Option<String>) -> Result<Option<Vec<u8>>, StatusCode> {
    let Some(encoded) = encoded else {
        return Ok(None);
    };
    if encoded.len() > 90_000 {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if bytes.len() > 64 * 1024
        || bytes.len() < 24
        || !bytes.starts_with(b"\x89PNG\r\n\x1a\n")
        || &bytes[12..16] != b"IHDR"
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let width = u32::from_be_bytes(bytes[16..20].try_into().unwrap());
    let height = u32::from_be_bytes(bytes[20..24].try_into().unwrap());
    if !(1..=512).contains(&width) || !(1..=512).contains(&height) {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(Some(bytes))
}

pub async fn get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Result<Json<Profile>, StatusCode> {
    crate::auth::handlers::user_from_bearer(&state, &headers).await?;
    let row = sqlx::query("SELECT username,display_name,avatar_png FROM users WHERE id=$1")
        .bind(&user_id)
        .fetch_optional(state.db.pool())
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let avatar: Option<Vec<u8>> = row.get("avatar_png");
    Ok(Json(Profile {
        user_id,
        username: row.get("username"),
        display_name: row.get("display_name"),
        avatar_png: avatar.map(|bytes| STANDARD.encode(bytes)),
    }))
}

pub async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<UpdateProfile>,
) -> Result<Json<Profile>, StatusCode> {
    let user_id = crate::auth::handlers::user_from_bearer(&state, &headers).await?;
    if !state
        .db
        .hit_rate_limit(&format!("profile:{user_id}"), 10, 60)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let display_name = input.display_name.trim();
    if !valid_name(display_name) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let avatar = decode_avatar(input.avatar_png)?;
    let row = sqlx::query(
        "UPDATE users SET display_name=$1,avatar_png=$2 WHERE id=$3 RETURNING username",
    )
    .bind(display_name)
    .bind(&avatar)
    .bind(&user_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(Json(Profile {
        user_id,
        username: row.get("username"),
        display_name: display_name.to_string(),
        avatar_png: avatar.map(|bytes| STANDARD.encode(bytes)),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_input_rejects_control_characters_and_bad_avatar_shapes() {
        assert!(valid_name("公开昵称"));
        assert!(!valid_name(&"字".repeat(41)));
        assert!(!valid_name("bad\nname"));
        assert!(decode_avatar(Some("not-base64".into())).is_err());
        let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
        png.extend_from_slice(&513u32.to_be_bytes());
        png.extend_from_slice(&1u32.to_be_bytes());
        assert!(decode_avatar(Some(STANDARD.encode(png))).is_err());
    }
}
