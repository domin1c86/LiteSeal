//! Bounded native-only legacy operation catch-up shared by foreground/worker.
use crate::{
    client::LitesealClient, db::repository::LocalOperation, mobile_identity::MobileIdentity,
};
use liteseal_shared::{
    crypto,
    message_operation::{self as op, OperationDelivery},
};
use zeroize::Zeroizing;
fn bad() -> String {
    "消息变更补收未完成；原证据保留".into()
}
pub(crate) async fn poll(
    client: &LitesealClient,
    identity: &MobileIdentity,
) -> Result<usize, String> {
    let snapshot = identity.snapshot(true)?;
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|_| bad())?;
    let mut response = http
        .get(format!("{}/message-operations", snapshot.data.server_url))
        .query(&[("device_id", &snapshot.data.device_id)])
        .bearer_auth(&snapshot.data.token)
        .send()
        .await
        .map_err(|_| bad())?;
    if !response.status().is_success() {
        return Err(bad());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| bad())? {
        if bytes.len() + chunk.len() > 512 * 1024 {
            return Err(bad());
        }
        bytes.extend_from_slice(&chunk);
    }
    let deliveries: Vec<OperationDelivery> = serde_json::from_slice(&bytes).map_err(|_| bad())?;
    if deliveries.len() > 128 {
        return Err(bad());
    }
    identity.check(&snapshot)?;
    let mut ids = Vec::new();
    {
        let _commit = crate::mobile_runtime::COMMIT.lock().map_err(|_| bad())?;
        identity.check(&snapshot)?;
        let db = client.db.lock().map_err(|_| bad())?;
        for delivery in &deliveries {
            let h = &delivery.header;
            if h.id.is_empty()
                || h.id.len() > 128
                || delivery.payload.device_id != snapshot.data.device_id
                || h.base_revision < 0
                || Some(delivery.revision) != h.base_revision.checked_add(1)
                || !matches!(h.kind.as_str(), "edit" | "revoke")
            {
                return Err(bad());
            }
            let Some(original) = db.get_message(&h.target_id).map_err(|_| bad())? else {
                continue;
            };
            if h.conversation_id != original.conversation_id
                || h.sender_id != original.sender_id
                || h.sender_device_id != original.sender_device_id
            {
                return Err(bad());
            }
            let (pk, box_pk): (Vec<u8>, Vec<u8>) = if h.sender_id == snapshot.data.user_id {
                (
                    snapshot.data.ed25519_pk.clone(),
                    snapshot.data.public_key.clone(),
                )
            } else {
                let contact = db
                    .get_contact(&h.sender_id)
                    .map_err(|_| bad())?
                    .ok_or_else(bad)?;
                if contact.key_changed || contact.trust_state == "key_changed" {
                    return Err(bad());
                }
                (contact.ed25519_pk.ok_or_else(bad)?, contact.public_key)
            };
            let pk = <[u8; 32]>::try_from(pk.as_slice()).map_err(|_| bad())?;
            if !crypto::verify_with_public_key(
                &op::signing_bytes(h, &delivery.payload.device_id, &delivery.payload.ciphertext),
                &delivery.payload.signature,
                &pk,
            )
            .map_err(|_| bad())?
            {
                return Err(bad());
            }
            let key = Zeroizing::new(
                <[u8; 32]>::try_from(snapshot.data.secret_key.as_slice()).map_err(|_| bad())?,
            );
            let box_pk = <[u8; 32]>::try_from(box_pk.as_slice()).map_err(|_| bad())?;
            let plain = Zeroizing::new(
                crypto::decrypt(&delivery.payload.ciphertext, &box_pk, &key).map_err(|_| bad())?,
            );
            if plain.len() > 64 * 1024 || std::str::from_utf8(&plain).is_err() {
                return Err(bad());
            }
            let body = serde_json::to_string(delivery).map_err(|_| bad())?;
            if db
                .operations(
                    &snapshot.data.user_id,
                    &snapshot.data.device_id,
                    Some(&h.conversation_id),
                )
                .map_err(|_| bad())?
                .iter()
                .any(|old| old.id == h.id && old.status == "accepted" && old.body != body)
            {
                return Err(bad());
            }
            db.save_operation(
                &snapshot.data.user_id,
                &snapshot.data.device_id,
                &LocalOperation {
                    id: h.id.clone(),
                    target_id: h.target_id.clone(),
                    conversation_id: h.conversation_id.clone(),
                    body,
                    status: "accepted".into(),
                    error: None,
                },
            )
            .map_err(|_| bad())?;
            ids.push(h.id.clone());
        }
    }
    if !ids.is_empty() {
        identity.check(&snapshot)?;
        let response = http
            .post(format!(
                "{}/message-operations/ack",
                snapshot.data.server_url
            ))
            .bearer_auth(&snapshot.data.token)
            .json(&serde_json::json!({"device_id": snapshot.data.device_id, "ids": ids}))
            .send()
            .await
            .map_err(|_| bad())?;
        if !response.status().is_success() {
            return Err(bad());
        }
    }
    identity.check(&snapshot)?;
    Ok(ids.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use liteseal_shared::message_operation::{OperationHeader, OperationPayload};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    async fn scenario(tamper: bool) {
        let (db, mut saved, peer, message) = crate::mobile_messages::tests::fixture(false);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        saved.server_url = format!("http://{}", listener.local_addr().unwrap());
        let header = OperationHeader {
            id: "synthetic-op".into(),
            target_id: message.id.clone(),
            conversation_id: message.conversation_id.clone(),
            sender_id: message.sender_id.clone(),
            sender_device_id: message.sender_device_id.clone(),
            kind: "edit".into(),
            base_revision: 0,
        };
        let pk = saved.public_key.as_slice().try_into().unwrap();
        let ciphertext = crypto::encrypt("变更后的正文".as_bytes(), &pk, &peer.secret_key).unwrap();
        let mut signature = crypto::sign(
            &op::signing_bytes(&header, &saved.device_id, &ciphertext),
            &peer.ed25519_sk,
        )
        .unwrap();
        if tamper {
            signature[0] ^= 1;
        }
        let delivery = OperationDelivery {
            header,
            payload: OperationPayload {
                device_id: saved.device_id.clone(),
                ciphertext,
                signature,
            },
            revision: 1,
            accepted_at: 1235,
        };
        let response = serde_json::to_vec(&vec![delivery]).unwrap();
        let client = Arc::new(LitesealClient::new(":memory:").unwrap());
        *client.db.lock().unwrap() = db;
        let identity = crate::mobile_identity::tests::saved(saved);
        let inspect = client.clone();
        let server = tokio::spawn(async move {
            for request in 0..if tamper { 1 } else { 2 } {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let mut buffer = [0; 2048];
                loop {
                    let length = stream.read(&mut buffer).await.unwrap();
                    assert!(length > 0);
                    bytes.extend_from_slice(&buffer[..length]);
                    assert!(bytes.len() < 8192);
                    let Some(end) = bytes.windows(4).position(|v| v == b"\r\n\r\n") else {
                        continue;
                    };
                    let headers = std::str::from_utf8(&bytes[..end]).unwrap();
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            line.to_lowercase()
                                .strip_prefix("content-length:")
                                .and_then(|v| v.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if bytes.len() >= end + 4 + content_length {
                        break;
                    }
                }
                if request == 0 {
                    assert!(bytes.starts_with(b"GET /message-operations?device_id=alice-phone "));
                } else {
                    assert!(bytes.starts_with(b"POST /message-operations/ack "));
                    assert_eq!(
                        inspect
                            .db
                            .lock()
                            .unwrap()
                            .operations("alice", "alice-phone", None)
                            .unwrap()
                            .len(),
                        1,
                        "ACK follows durable native storage"
                    );
                    let end = bytes.windows(4).position(|v| v == b"\r\n\r\n").unwrap() + 4;
                    let ack: serde_json::Value = serde_json::from_slice(&bytes[end..]).unwrap();
                    assert_eq!(ack["ids"], serde_json::json!(["synthetic-op"]));
                }
                let body = if request == 0 {
                    response.as_slice()
                } else {
                    b"{}"
                };
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).as_bytes()).await.unwrap();
                stream.write_all(body).await.unwrap();
            }
        });
        let result = poll(&client, &identity).await;
        server.await.unwrap();
        let db = client.db.lock().unwrap();
        if tamper {
            assert!(result.is_err());
            assert!(db
                .operations("alice", "alice-phone", None)
                .unwrap()
                .is_empty());
        } else {
            assert_eq!(result.unwrap(), 1);
            assert_eq!(
                crate::mobile_messages::read(
                    &db,
                    &identity.snapshot(false).unwrap().data,
                    &message.id
                )
                .unwrap(),
                "变更后的正文"
            );
        }
    }
    #[tokio::test]
    async fn native_http_operation_verification_persists_before_ack_and_changes_projection() {
        scenario(false).await;
    }
    #[tokio::test]
    async fn invalid_native_http_operation_is_not_stored_or_acknowledged() {
        scenario(true).await;
    }
}
