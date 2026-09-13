use crate::AppState;
use liteseal_core::{
    api::normalize_server_url, db::repository::LocalOperation, keystore::KeystoreData,
};
use liteseal_shared::{crypto, message_operation::*};
use serde::Serialize;
use std::sync::OnceLock;
static GATE: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())
}
fn keys(saved: &KeystoreData) -> Result<([u8; 32], [u8; 64]), String> {
    Ok((
        saved
            .secret_key
            .clone()
            .try_into()
            .map_err(|_| "Invalid encryption key")?,
        saved
            .ed25519_sk
            .clone()
            .try_into()
            .map_err(|_| "Invalid signing key")?,
    ))
}
fn save(state: &AppState, saved: &KeystoreData, op: &LocalOperation) -> Result<(), String> {
    state
        .client
        .db
        .lock()
        .map_err(|e| e.to_string())?
        .save_operation(&saved.user_id, &saved.device_id, op)
        .map_err(|e| e.to_string())
}
fn rows(
    state: &AppState,
    saved: &KeystoreData,
    conversation: Option<&str>,
) -> Result<Vec<LocalOperation>, String> {
    state
        .client
        .db
        .lock()
        .map_err(|e| e.to_string())?
        .operations(&saved.user_id, &saved.device_id, conversation)
        .map_err(|e| e.to_string())
}
fn store_delivery(
    state: &AppState,
    saved: &KeystoreData,
    delivery: OperationDelivery,
) -> Result<(), String> {
    if delivery.payload.device_id != saved.device_id
        || Some(delivery.revision) != delivery.header.base_revision.checked_add(1)
        || !["edit", "revoke"].contains(&delivery.header.kind.as_str())
    {
        return Err("无效的变更投递".into());
    }
    save(
        state,
        saved,
        &LocalOperation {
            id: delivery.header.id.clone(),
            target_id: delivery.header.target_id.clone(),
            conversation_id: delivery.header.conversation_id.clone(),
            body: serde_json::to_string(&delivery).map_err(|e| e.to_string())?,
            status: "accepted".into(),
            error: None,
        },
    )
}
async fn publish(
    state: &AppState,
    saved: &KeystoreData,
    mut row: LocalOperation,
) -> Result<(), String> {
    let request: OperationRequest = serde_json::from_str(&row.body).map_err(|e| e.to_string())?;
    let response = client()?
        .post(format!(
            "{}/message-operations",
            normalize_server_url(&saved.server_url)?
        ))
        .bearer_auth(&saved.token)
        .json(&request)
        .send()
        .await
        .map_err(|_| "变更发送未确认；已保存，重连后重试原操作")?;
    let status = response.status();
    if status.is_success() {
        return store_delivery(
            state,
            saved,
            response
                .json()
                .await
                .map_err(|_| "无法读取变更确认，稍后重试")?,
        );
    }
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err("Authentication failed: message operation session expired".into());
    }
    let reason = response.text().await.unwrap_or_else(|_| status.to_string());
    if status.is_client_error() && status != reqwest::StatusCode::TOO_MANY_REQUESTS {
        row.status = "rejected".into();
        row.error = Some(reason.clone());
        save(state, saved, &row)?;
    }
    Err(format!("消息变更未完成：{reason}"))
}

pub async fn submit(
    target_id: String,
    kind: String,
    content: String,
    base_revision: i64,
    state: &AppState,
) -> Result<String, String> {
    let _gate = GATE
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let saved = state.identity()?;
    if saved.token.is_empty() {
        return Err("请先登录".into());
    }
    if !["edit", "revoke"].contains(&kind.as_str())
        || content.len() > 64 * 1024
        || (kind == "edit" && content.trim().is_empty())
    {
        return Err("无效的变更内容或内容超过 64 KiB".into());
    }
    let (original, peer) = {
        let db = state.client.db.lock().map_err(|e| e.to_string())?;
        let original = db
            .get_message(&target_id)
            .map_err(|e| e.to_string())?
            .ok_or("找不到原消息")?;
        if original.sender_id != saved.user_id || original.sender_device_id != saved.device_id {
            return Err("仅原发送设备可修改".into());
        }
        let payloads: Vec<liteseal_shared::protocol::EncryptedPayload> = serde_json::from_str(
            &db.outgoing_payloads(&target_id)
                .map_err(|e| e.to_string())?,
        )
        .map_err(|_| "原消息发件数据不可读")?;
        let peer_id = &payloads
            .first()
            .ok_or("原消息没有收件人")?
            .recipient_user_id;
        let peer = db
            .get_contact(peer_id)
            .map_err(|e| e.to_string())?
            .ok_or("请先恢复原联系人")?;
        (original, peer)
    };
    if rows(state, &saved, Some(&original.conversation_id))?
        .iter()
        .any(|r| r.target_id == target_id && r.status == "pending")
    {
        return Err("原消息有待确认操作，请等待自动重试".into());
    }
    let url = normalize_server_url(&saved.server_url)?;
    let response = client()?
        .get(format!("{url}/message-operations/targets/{target_id}"))
        .query(&[("device_id", &saved.device_id)])
        .bearer_auth(&saved.token)
        .send()
        .await
        .map_err(|_| "无法查询原收件设备")?;
    if !response.status().is_success() {
        return Err(response
            .text()
            .await
            .unwrap_or_else(|_| "无法查询原收件设备".into()));
    }
    let mut targets: Vec<OperationTarget> =
        response.json().await.map_err(|_| "无效的收件设备列表")?;
    targets.retain(|t| t.device_id != saved.device_id);
    targets.push(OperationTarget {
        device_id: saved.device_id.clone(),
        public_key: peer.public_key,
    });
    let header = OperationHeader {
        id: uuid::Uuid::new_v4().to_string(),
        target_id,
        conversation_id: original.conversation_id,
        sender_id: saved.user_id.clone(),
        sender_device_id: saved.device_id.clone(),
        kind: kind.clone(),
        base_revision,
    };
    let (sk, signing_key) = keys(&saved)?;
    let plaintext = if kind == "revoke" { "" } else { &content };
    let mut payloads = Vec::new();
    for target in targets {
        let pk: [u8; 32] = target
            .public_key
            .try_into()
            .map_err(|_| "Invalid recipient key")?;
        let ciphertext =
            crypto::encrypt(plaintext.as_bytes(), &pk, &sk).map_err(|e| e.to_string())?;
        let signature = crypto::sign(
            &signing_bytes(&header, &target.device_id, &ciphertext),
            &signing_key,
        )
        .map_err(|e| e.to_string())?;
        payloads.push(OperationPayload {
            device_id: target.device_id,
            ciphertext,
            signature,
        });
    }
    if payloads.len() > 100
        || payloads.iter().map(|p| p.ciphertext.len()).sum::<usize>() > 384 * 1024
    {
        return Err("正文与设备副本合计过大，请缩短编辑内容".into());
    }
    payloads.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    let row = LocalOperation {
        id: header.id.clone(),
        target_id: header.target_id.clone(),
        conversation_id: header.conversation_id.clone(),
        body: serde_json::to_string(&OperationRequest {
            header: header.clone(),
            payloads,
        })
        .map_err(|e| e.to_string())?,
        status: "pending".into(),
        error: None,
    };
    save(state, &saved, &row)?;
    publish(state, &saved, row).await?;
    Ok(header.id)
}

pub async fn sync(state: &AppState) -> Result<usize, String> {
    let _gate = GATE
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let saved = state.identity()?;
    if saved.token.is_empty() {
        return Ok(0);
    }
    let mut changed = 0;
    for row in rows(state, &saved, None)?
        .into_iter()
        .filter(|r| r.status == "pending")
        .take(20)
    {
        let id = row.id.clone();
        if let Err(error) = publish(state, &saved, row).await {
            // Definitive rejection is persisted and shown on the original message.
            if rows(state, &saved, None)?
                .iter()
                .any(|r| r.id == id && r.status == "rejected")
            {
                changed += 1;
                continue;
            }
            return Err(error);
        }
        changed += 1;
    }
    let url = normalize_server_url(&saved.server_url)?;
    let http = client()?;
    let response = http
        .get(format!("{url}/message-operations"))
        .query(&[("device_id", &saved.device_id)])
        .bearer_auth(&saved.token)
        .send()
        .await
        .map_err(|_| "变更补收暂不可用")?;
    if !response.status().is_success() {
        return Err(format!("变更补收失败：{}", response.status()));
    }
    let deliveries: Vec<OperationDelivery> =
        response.json().await.map_err(|_| "无法读取变更队列")?;
    let mut ids = Vec::new();
    for delivery in deliveries {
        ids.push(delivery.header.id.clone());
        store_delivery(state, &saved, delivery)?;
        changed += 1;
    }
    if !ids.is_empty() {
        let response = http
            .post(format!("{url}/message-operations/ack"))
            .bearer_auth(&saved.token)
            .json(&serde_json::json!({"device_id": saved.device_id, "ids": ids}))
            .send()
            .await
            .map_err(|_| "变更已保存，确认将在重连后重试")?;
        if !response.status().is_success() {
            return Err("变更已保存，服务器尚未确认".into());
        }
    }
    Ok(changed)
}

#[derive(Serialize)]
pub struct OperationView {
    pub id: String,
    pub target_id: String,
    pub kind: String,
    pub revision: i64,
    pub status: String,
    pub content: Option<String>,
    pub error: Option<String>,
}
pub fn views(
    conversation_id: Option<String>,
    state: &AppState,
) -> Result<Vec<OperationView>, String> {
    let saved = state.identity()?;
    let (sk, _) = keys(&saved)?;
    let mut result = Vec::new();
    for row in rows(state, &saved, conversation_id.as_deref())? {
        if row.status != "accepted" {
            let request: OperationRequest =
                serde_json::from_str(&row.body).map_err(|e| e.to_string())?;
            result.push(OperationView {
                id: row.id,
                target_id: row.target_id,
                kind: request.header.kind,
                revision: request.header.base_revision,
                status: row.status,
                content: None,
                error: row.error,
            });
            continue;
        }
        let delivery: OperationDelivery =
            serde_json::from_str(&row.body).map_err(|e| e.to_string())?;
        let h = &delivery.header;
        let verification = (|| -> Result<String, String> {
            let db = state.client.db.lock().map_err(|e| e.to_string())?;
            let original = db
                .get_message(&h.target_id)
                .map_err(|e| e.to_string())?
                .ok_or("等待原消息补收")?;
            if original.sender_id != h.sender_id
                || original.sender_device_id != h.sender_device_id
                || original.conversation_id != h.conversation_id
            {
                return Err("变更与原消息身份不匹配".into());
            }
            if original.local_state == "integrity_failed" {
                return Err("原消息完整性异常，未应用变更".into());
            }
            let peer_id = if original.sender_id == saved.user_id {
                let payloads: Vec<liteseal_shared::protocol::EncryptedPayload> =
                    serde_json::from_str(
                        &db.outgoing_payloads(&original.id)
                            .map_err(|e| e.to_string())?,
                    )
                    .map_err(|_| "原消息载荷不可读")?;
                payloads
                    .first()
                    .ok_or("原消息无收件人")?
                    .recipient_user_id
                    .clone()
            } else {
                original.sender_id.clone()
            };
            let contact = db
                .get_contact(&peer_id)
                .map_err(|e| e.to_string())?
                .ok_or("联系人不可用，无法校验变更")?;
            let signing_pk: [u8; 32] = if h.sender_id == saved.user_id {
                saved.ed25519_pk.clone()
            } else {
                contact.ed25519_pk.clone().ok_or("联系人签名密钥不可用")?
            }
            .try_into()
            .map_err(|_| "签名密钥不可用")?;
            if !crypto::verify_with_public_key(
                &signing_bytes(h, &delivery.payload.device_id, &delivery.payload.ciphertext),
                &delivery.payload.signature,
                &signing_pk,
            )
            .unwrap_or(false)
            {
                return Err("消息变更签名无效".into());
            }
            let pk: [u8; 32] = contact.public_key.try_into().map_err(|_| "解密密钥无效")?;
            let bytes = crypto::decrypt(&delivery.payload.ciphertext, &pk, &sk)
                .map_err(|_| "无法解密变更")?;
            String::from_utf8(bytes).map_err(|_| "无效的变更正文".into())
        })();
        let (status, content, error) = match verification {
            Ok(text) => ("accepted".into(), Some(text), None),
            Err(error) => ("unverified".into(), None, Some(error)),
        };
        result.push(OperationView {
            id: row.id,
            target_id: row.target_id,
            kind: h.kind.clone(),
            revision: delivery.revision,
            status,
            content,
            error,
        });
    }
    Ok(result)
}
