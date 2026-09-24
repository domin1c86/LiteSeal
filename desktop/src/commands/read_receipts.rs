use crate::AppState;
use liteseal_core::{api::normalize_server_url, chat::canonical_conversation_id};
use liteseal_shared::{
    crypto,
    read_receipt::{ReadReceipt, ReadReceiptDelivery},
};
use std::{collections::HashMap, sync::OnceLock};

static GATE: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())
}
fn rows(state: &AppState) -> Result<Vec<(i64, ReadReceipt)>, String> {
    let user = state.identity()?.user_id;
    state
        .client
        .db
        .lock()
        .map_err(|e| e.to_string())?
        .read_receipt_rows(&user)
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|(seq, body)| {
            Ok((
                seq,
                serde_json::from_str(&body).map_err(|_| "阅读回执数据损坏")?,
            ))
        })
        .collect()
}
fn store(state: &AppState, event: &ReadReceipt, seq: i64) -> Result<(), String> {
    let user = state.identity()?.user_id;
    state
        .client
        .db
        .lock()
        .map_err(|e| e.to_string())?
        .save_read_receipt(
            &user,
            &event.id,
            seq,
            &serde_json::to_string(event).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())
}
pub fn enabled(state: &AppState) -> Result<bool, String> {
    let user = state.identity()?.user_id;
    state
        .client
        .db
        .lock()
        .map_err(|e| e.to_string())?
        .read_receipts_enabled(&user)
        .map_err(|e| e.to_string())
}
pub async fn set_enabled(state: &AppState, value: bool) -> Result<(), String> {
    let _guard = GATE
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let user = state.identity()?.user_id;
    state
        .client
        .db
        .lock()
        .map_err(|e| e.to_string())?
        .set_read_receipts_enabled(&user, value)
        .map_err(|e| e.to_string())
}
pub async fn mark_visible(state: &AppState, user: String, ids: Vec<String>) -> Result<(), String> {
    let _guard = GATE
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let saved = state.identity()?;
    if user != saved.user_id {
        return Err("已读账号不匹配".into());
    }
    let candidates = {
        let db = state.client.db.lock().map_err(|e| e.to_string())?;
        if db.read_receipts_enabled(&user).map_err(|e| e.to_string())? {
            db.new_visible_candidates(&user, &ids)
                .map_err(|e| e.to_string())?
        } else {
            Vec::new()
        }
    };
    let mut events = HashMap::new();
    for (id, conversation, peer) in candidates {
        if conversation != canonical_conversation_id(&user, &peer) {
            continue;
        }
        let mut event = ReadReceipt {
            id: uuid::Uuid::new_v4().to_string(),
            target_id: id.clone(),
            conversation_id: conversation,
            reader: user.clone(),
            device: saved.device_id.clone(),
            peer,
            signature: Vec::new(),
        };
        event.signature =
            liteseal_core::chat::sign_message(event.signing_bytes(), saved.ed25519_sk.clone())?;
        events.insert(
            id,
            (
                event.id.clone(),
                serde_json::to_string(&event).map_err(|e| e.to_string())?,
            ),
        );
    }
    state
        .client
        .db
        .lock()
        .map_err(|e| e.to_string())?
        .mark_visible_with_receipts(&user, &ids, &events)
        .map_err(|e| e.to_string())
}
async fn publish(state: &AppState, event: &ReadReceipt) -> Result<(), String> {
    let saved = state.identity()?;
    let response = client()?
        .post(format!(
            "{}/read-receipts",
            normalize_server_url(&saved.server_url)?
        ))
        .bearer_auth(saved.token)
        .json(event)
        .send()
        .await
        .map_err(|_| "阅读回执发送中断，已保存待重试")?;
    if !response.status().is_success() {
        if response.status().is_client_error()
            && response.status() != reqwest::StatusCode::TOO_MANY_REQUESTS
            && response.status() != reqwest::StatusCode::UNAUTHORIZED
        {
            store(state, event, -1)?;
        }
        return Err(format!("阅读回执未被接受：{}", response.status()));
    }
    let delivery: ReadReceiptDelivery =
        response.json().await.map_err(|_| "阅读回执确认格式无效")?;
    if delivery.event.signing_bytes() != event.signing_bytes()
        || delivery.event.signature != event.signature
    {
        return Err("阅读回执确认内容不一致".into());
    }
    store(state, event, -2)
}
pub async fn sync(state: &AppState) -> Result<usize, String> {
    let _guard = GATE
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let saved = state.identity()?;
    let history = rows(state)?;
    if enabled(state)? {
        for (seq, event) in &history {
            if *seq == 0 {
                publish(state, event).await?;
            }
        }
    }
    let after = history
        .iter()
        .map(|(seq, _)| *seq)
        .max()
        .unwrap_or(0)
        .max(0);
    let response = client()?
        .get(format!(
            "{}/read-receipts",
            normalize_server_url(&saved.server_url)?
        ))
        .bearer_auth(&saved.token)
        .query(&[
            ("device_id", saved.device_id.clone()),
            ("after", after.to_string()),
        ])
        .send()
        .await
        .map_err(|_| "阅读回执同步失败")?;
    if !response.status().is_success() {
        return Err(format!("阅读回执同步失败：{}", response.status()));
    }
    let deliveries: Vec<ReadReceiptDelivery> =
        response.json().await.map_err(|_| "阅读回执同步数据无效")?;
    for delivery in &deliveries {
        if delivery.event.reader != saved.user_id && delivery.event.peer != saved.user_id {
            return Err("阅读回执账号不匹配".into());
        }
        store(state, &delivery.event, delivery.seq)?;
    }
    Ok(deliveries.len())
}
pub fn views(state: &AppState, conversation: String) -> Result<Vec<String>, String> {
    let saved = state.identity()?;
    let mut result = Vec::new();
    for (seq, event) in rows(state)? {
        if seq <= 0
            || event.peer != saved.user_id
            || event.reader == saved.user_id
            || event.conversation_id != conversation
            || conversation != canonical_conversation_id(&saved.user_id, &event.reader)
        {
            continue;
        }
        let (peer, target) = {
            let db = state.client.db.lock().map_err(|e| e.to_string())?;
            (
                db.get_contact(&event.reader).map_err(|e| e.to_string())?,
                db.get_message(&event.target_id)
                    .map_err(|e| e.to_string())?,
            )
        };
        let (Some(peer), Some(target)) = (peer, target) else {
            continue;
        };
        if target.sender_id != saved.user_id || target.conversation_id != conversation {
            continue;
        }
        let Ok(key): Result<[u8; 32], _> = peer.ed25519_pk.unwrap_or_default().try_into() else {
            continue;
        };
        if crypto::verify_with_public_key(&event.signing_bytes(), &event.signature, &key)
            .unwrap_or(false)
        {
            result.push(event.target_id);
        }
    }
    Ok(result)
}
