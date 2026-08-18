//! Stateless REST calls against the relay server's HTTP endpoints.

use serde::{Deserialize, Serialize};

use liteseal_shared::types::PublicKeyInfo;

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterResult {
    pub user_id: String,
    pub token: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub device_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RemoteDevice {
    pub id: String,
    pub name: String,
    pub public_key: Vec<u8>,
    pub ed25519_pk: Vec<u8>,
    pub revoked: bool,
}

pub async fn register(
    username: String,
    password: String,
    invite_code: String,
    server_url: String,
    device_name: &str,
    public_key: Vec<u8>,
    ed25519_pk: Vec<u8>,
) -> Result<RegisterResult, String> {
    let username = username.trim().to_string();
    if username.is_empty() {
        return Err("Username cannot be empty".to_string());
    }
    validate_public_key("Public key", &public_key)?;
    validate_public_key("Signing public key", &ed25519_pk)?;
    let server_url = normalize_server_url(&server_url)?;

    let client = reqwest::Client::new();
    let url = format!("{}/auth/register", server_url);

    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "username": username,
            "password": password,
            "invite_code": invite_code,
            "device_name": device_name,
            "public_key": public_key,
            "ed25519_pk": ed25519_pk,
        }))
        .send()
        .await
        .map_err(|e| format!("Registration request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!(
            "Registration failed with status: {}",
            resp.status()
        ));
    }

    resp.json()
        .await
        .map_err(|e| format!("Failed to parse registration response: {}", e))
}

#[allow(clippy::too_many_arguments)]
pub async fn login(
    username: String,
    password: String,
    server_url: String,
    device_name: &str,
    public_key: Vec<u8>,
    ed25519_pk: Vec<u8>,
    device_id: Option<String>,
    replace_device: bool,
) -> Result<RegisterResult, String> {
    let username = username.trim().to_string();
    if username.is_empty() {
        return Err("Username cannot be empty".to_string());
    }
    validate_public_key("Public key", &public_key)?;
    validate_public_key("Signing public key", &ed25519_pk)?;
    let server_url = normalize_server_url(&server_url)?;

    let client = reqwest::Client::new();
    let url = format!("{}/auth/login", server_url);
    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "username": username,
            "password": password,
            "device_name": device_name,
            "device_id": device_id,
            "device_public_key": public_key,
            "ed25519_pk": ed25519_pk,
            "replace_device": replace_device,
        }))
        .send()
        .await
        .map_err(|e| format!("Login request failed: {}", e))?;

    if resp.status() == reqwest::StatusCode::CONFLICT && device_id.is_none() {
        return Err("device_replacement_required".to_string());
    }
    if !resp.status().is_success() {
        return Err(format!("Login failed with status: {}", resp.status()));
    }

    resp.json()
        .await
        .map_err(|e| format!("Failed to parse login response: {}", e))
}

pub async fn refresh_session(
    server_url: String,
    refresh_token: String,
) -> Result<RegisterResult, String> {
    if refresh_token.trim().is_empty() {
        return Err("No refresh token available".to_string());
    }
    let server_url = normalize_server_url(&server_url)?;

    let client = reqwest::Client::new();
    let url = format!("{}/auth/refresh", server_url);
    let resp = client
        .post(&url)
        .json(&serde_json::json!({ "refresh_token": refresh_token }))
        .send()
        .await
        .map_err(|e| format!("Refresh request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Refresh failed with status: {}", resp.status()));
    }

    resp.json()
        .await
        .map_err(|e| format!("Failed to parse refresh response: {}", e))
}

pub async fn get_user_devices(
    server_url: String,
    user_id: String,
    access_token: String,
) -> Result<Vec<RemoteDevice>, String> {
    let user_id = user_id.trim().to_string();
    if user_id.is_empty() {
        return Err("User id cannot be empty".to_string());
    }

    let server_url = normalize_server_url(&server_url)?;
    let client = reqwest::Client::new();
    let url = format!("{}/users/{}/devices", server_url, user_id);

    let resp = client
        .get(&url)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| format!("Device lookup failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!(
            "Device lookup failed with status: {}",
            resp.status()
        ));
    }

    resp.json()
        .await
        .map_err(|e| format!("Failed to parse device list: {}", e))
}

pub async fn search_users(
    server_url: String,
    query: String,
    access_token: String,
) -> Result<Vec<PublicKeyInfo>, String> {
    let query = query.trim().to_string();
    if query.is_empty() {
        return Err("Search query cannot be empty".to_string());
    }

    let client = reqwest::Client::new();
    let server_url = normalize_server_url(&server_url)?;
    let mut url = url::Url::parse(&format!("{}/users/search", server_url))
        .map_err(|e| format!("Invalid server URL: {}", e))?;
    url.query_pairs_mut().append_pair("q", &query);

    let resp = client
        .get(url.as_str())
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| format!("Search request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Search failed with status: {}", resp.status()));
    }

    resp.json()
        .await
        .map_err(|e| format!("Failed to parse search response: {}", e))
}

pub fn validate_public_key(label: &str, key: &[u8]) -> Result<(), String> {
    if key.len() != 32 {
        return Err(format!("{} must be 32 bytes", label));
    }
    Ok(())
}

pub fn normalize_server_url(server_url: &str) -> Result<String, String> {
    let trimmed = server_url.trim().trim_end_matches('/');
    let parsed = url::Url::parse(trimmed).map_err(|e| format!("Invalid server URL: {}", e))?;
    match parsed.scheme() {
        "https" => Ok(trimmed.to_string()),
        "http" if is_loopback_host(&parsed) => Ok(trimmed.to_string()),
        "http" => Err("Remote servers must use HTTPS".to_string()),
        _ => {
            Err("Server URL must start with https:// (HTTP is local development only)".to_string())
        }
    }
}

pub async fn logout(server_url: String, access_token: String) -> Result<(), String> {
    revoke(server_url, access_token, "/auth/logout").await
}

pub async fn logout_all(server_url: String, access_token: String) -> Result<(), String> {
    revoke(server_url, access_token, "/auth/logout_all").await
}

async fn revoke(server_url: String, access_token: String, path: &str) -> Result<(), String> {
    let server_url = normalize_server_url(&server_url)?;
    let response = reqwest::Client::new()
        .post(format!("{server_url}{path}"))
        .json(&serde_json::json!({ "access_token": access_token }))
        .send()
        .await
        .map_err(|e| format!("Session revocation failed: {e}"))?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!(
            "Session revocation failed with status: {}",
            response.status()
        ))
    }
}

fn is_loopback_host(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_inputs_require_valid_url_and_key_lengths() {
        assert_eq!(
            normalize_server_url(" http://localhost:3000/ ").unwrap(),
            "http://localhost:3000"
        );
        assert!(normalize_server_url("ftp://localhost:3000").is_err());
        assert!(normalize_server_url("http://example.com:3000").is_err());
        assert!(normalize_server_url("http://127.0.0.1:3000").is_ok());
        assert!(normalize_server_url("https://example.com").is_ok());
        assert!(validate_public_key("Public key", &[1; 32]).is_ok());
        assert!(validate_public_key("Public key", &[1; 31]).is_err());
    }
}
