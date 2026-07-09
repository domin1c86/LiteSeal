//! Registers mock users against a running relay server for UI testing.
//!
//! Usage (server must be running):
//!   cargo run -p liteseal-server --example seed_mock_users            # http://localhost:3000
//!   cargo run -p liteseal-server --example seed_mock_users -- http://192.168.1.10:3000
//!
//! Every user gets the password `password123` and one seed device with a real
//! keypair, so they show up in user search, can be added as contacts, and can
//! receive (offline-queued) messages. To chat back as one of them, log in from
//! a second client instance with their username and the password above.

use liteseal_shared::crypto;
use serde_json::json;

const MOCK_USERS: &[&str] = &["alice", "bob", "carol", "dave", "erin"];
const PASSWORD: &str = "password123";

#[tokio::main]
async fn main() {
    let server_url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://localhost:3000".to_string());
    let client = reqwest::Client::new();

    println!("Seeding mock users at {server_url} (password: {PASSWORD})");
    for username in MOCK_USERS {
        let keypair = match crypto::generate_keypair() {
            Ok(kp) => kp,
            Err(err) => {
                eprintln!("  {username}: keypair generation failed: {err:?}");
                continue;
            }
        };
        let body = json!({
            "username": username,
            "password": PASSWORD,
            "device_name": "seed-device",
            "public_key": keypair.public_key.to_vec(),
            "ed25519_pk": keypair.ed25519_pk.to_vec(),
        });
        match client
            .post(format!("{server_url}/auth/register"))
            .json(&body)
            .send()
            .await
        {
            Ok(res) if res.status().is_success() => {
                let user_id = res
                    .json::<serde_json::Value>()
                    .await
                    .ok()
                    .and_then(|v| v["user_id"].as_str().map(str::to_string))
                    .unwrap_or_default();
                println!("  {username}: registered ({user_id})");
            }
            Ok(res) if res.status() == reqwest::StatusCode::CONFLICT => {
                println!("  {username}: already exists, skipped");
            }
            Ok(res) => {
                eprintln!("  {username}: server returned {}", res.status());
            }
            Err(err) => {
                eprintln!("  {username}: request failed: {err}");
                eprintln!("Is the server running at {server_url}?");
                std::process::exit(1);
            }
        }
    }
    println!("Done.");
}
