use crate::state::AppState;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use liteseal_shared::message_operation::*;
use serde::Deserialize;
use sqlx::Row;

type Failure = (StatusCode, String);
fn database(_: sqlx::Error) -> Failure {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "变更存储暂不可用，请重试原操作".into(),
    )
}
fn reject(message: &str) -> Failure {
    (StatusCode::CONFLICT, message.into())
}
#[derive(Deserialize)]
pub struct DeviceQuery {
    device_id: String,
}
async fn authorize(state: &AppState, headers: &HeaderMap, device: &str) -> Result<String, Failure> {
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or((StatusCode::UNAUTHORIZED, "需要登录".into()))?;
    let user = state
        .db
        .validate_access_token(&crate::auth::service::hash_token(token), device)
        .await
        .map_err(database)?
        .ok_or((StatusCode::UNAUTHORIZED, "会话失效".into()))?;
    let record = state
        .db
        .get_user_device(&user, device)
        .await
        .map_err(database)?;
    if !record.is_some_and(|record| !record.revoked) {
        return Err((StatusCode::UNAUTHORIZED, "设备已撤销".into()));
    }
    Ok(user)
}
// Original messages are located through durable receipts: acknowledged
// ciphertext is deleted from the offline queue, its receipt is not.
pub async fn targets(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<DeviceQuery>,
) -> Result<Json<Vec<OperationTarget>>, Failure> {
    let user = authorize(&state, &headers, &q.device_id).await?;
    let rows = sqlx::query("SELECT DISTINCT d.id, d.public_key FROM beta_receipts r JOIN devices d ON d.id = r.recipient_device_id
        WHERE r.message_id = $1 AND r.sender_user_id = $2 AND r.sender_device_id = $3 AND d.revoked = false")
        .bind(id).bind(user).bind(q.device_id).fetch_all(state.db.pool()).await.map_err(database)?;
    if rows.is_empty() {
        return Err(reject("原消息不存在、尚未到达服务器或没有可用收件设备"));
    }
    Ok(Json(
        rows.into_iter()
            .map(|r| OperationTarget {
                device_id: r.get("id"),
                public_key: r.get("public_key"),
            })
            .collect(),
    ))
}
pub async fn submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<OperationRequest>,
) -> Result<Json<OperationDelivery>, Failure> {
    let h = &request.header;
    let user = authorize(&state, &headers, &h.sender_device_id).await?;
    if user != h.sender_id
        || !["edit", "revoke"].contains(&h.kind.as_str())
        || h.base_revision < 0
        || h.base_revision > 1_000_000
        || uuid::Uuid::parse_str(&h.id).is_err()
        || request.payloads.is_empty()
        || request.payloads.len() > 100
        || request
            .payloads
            .iter()
            .map(|p| p.ciphertext.len())
            .sum::<usize>()
            > 384 * 1024
    {
        return Err((StatusCode::BAD_REQUEST, "无效的消息变更".into()));
    }
    let body = serde_json::to_string(&request).map_err(|_| reject("无效的消息变更"))?;
    let device = state
        .db
        .get_user_device(&user, &h.sender_device_id)
        .await
        .map_err(database)?
        .ok_or(reject("发送设备不存在"))?;
    let key: [u8; 32] = device
        .ed25519_pk
        .try_into()
        .map_err(|_| reject("签名密钥无效"))?;
    let mut tx = state.db.pool().begin().await.map_err(database)?;
    sqlx::query("SET LOCAL statement_timeout = '10s'")
        .execute(&mut *tx)
        .await
        .map_err(database)?;
    // Serialize operations on the same original message, including concurrent revocation/editing.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(&h.target_id)
        .execute(&mut *tx)
        .await
        .map_err(database)?;
    if let Some(row) =
        sqlx::query("SELECT request, revision, accepted_at FROM message_operations WHERE id = $1")
            .bind(&h.id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(database)?
    {
        if row.get::<String, _>("request") != body {
            return Err(reject("操作编号已绑定不同内容"));
        }
        let payload = request
            .payloads
            .iter()
            .find(|p| p.device_id == h.sender_device_id)
            .ok_or(reject("缺少本机副本"))?
            .clone();
        return Ok(Json(OperationDelivery {
            header: h.clone(),
            payload,
            revision: row.get("revision"),
            accepted_at: row.get("accepted_at"),
        }));
    }
    let original = sqlx::query("SELECT sender_user_id, sender_device_id, conversation_id, MIN(received_at) AS received_at FROM beta_receipts
        WHERE message_id = $1 GROUP BY sender_user_id, sender_device_id, conversation_id")
        .bind(&h.target_id).fetch_all(&mut *tx).await.map_err(database)?;
    if original.len() != 1 {
        return Err(reject("原消息不存在或编号冲突"));
    }
    let original = &original[0];
    if original.get::<String, _>("sender_user_id") != user
        || original.get::<String, _>("sender_device_id") != h.sender_device_id
        || original.get::<String, _>("conversation_id") != h.conversation_id
    {
        return Err((
            StatusCode::FORBIDDEN,
            "仅原发送设备可以编辑或撤回此消息".into(),
        ));
    }
    let now: i64 =
        sqlx::query_scalar("SELECT (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(&mut *tx)
            .await
            .map_err(database)?;
    if now - original.get::<i64, _>("received_at") > OPERATION_WINDOW_MS {
        return Err(reject("已超过首次接收后的 48 小时操作期限"));
    }
    let latest = sqlx::query("SELECT revision, kind FROM message_operations WHERE target_id = $1 ORDER BY revision DESC LIMIT 1").bind(&h.target_id).fetch_optional(&mut *tx).await.map_err(database)?;
    let revision = latest.as_ref().map_or(0, |r| r.get::<i64, _>("revision"));
    if latest
        .as_ref()
        .is_some_and(|r| r.get::<String, _>("kind") == "revoke")
    {
        return Err(reject("消息已撤回，不能再次修改"));
    }
    if revision != h.base_revision {
        return Err(reject("消息版本已变化，请同步后重新操作"));
    }
    let targets = sqlx::query("SELECT DISTINCT d.id FROM beta_receipts r JOIN devices d ON d.id = r.recipient_device_id WHERE r.message_id = $1 AND d.revoked = false")
        .bind(&h.target_id).fetch_all(&mut *tx).await.map_err(database)?;
    let mut expected: std::collections::BTreeSet<String> =
        targets.iter().map(|r| r.get("id")).collect();
    expected.insert(h.sender_device_id.clone());
    let supplied: std::collections::BTreeSet<String> = request
        .payloads
        .iter()
        .map(|p| p.device_id.clone())
        .collect();
    if supplied != expected || supplied.len() != request.payloads.len() {
        return Err(reject("收件设备发生变化，请重新创建操作"));
    }
    for payload in &request.payloads {
        if payload.ciphertext.len() < 40
            || payload.ciphertext.len() > 128 * 1024
            || !liteseal_shared::crypto::verify_with_public_key(
                &signing_bytes(h, &payload.device_id, &payload.ciphertext),
                &payload.signature,
                &key,
            )
            .unwrap_or(false)
        {
            return Err((StatusCode::FORBIDDEN, "消息变更签名无效".into()));
        }
    }
    sqlx::query("INSERT INTO message_operations(id, target_id, kind, revision, accepted_at, request) VALUES ($1,$2,$3,$4,$5,$6)")
        .bind(&h.id).bind(&h.target_id).bind(&h.kind).bind(revision+1).bind(now).bind(body).execute(&mut *tx).await.map_err(database)?;
    for payload in &request.payloads {
        let delivery = OperationDelivery {
            header: h.clone(),
            payload: payload.clone(),
            revision: revision + 1,
            accepted_at: now,
        };
        sqlx::query(
            "INSERT INTO operation_deliveries(operation_id, device_id, body) VALUES ($1,$2,$3)",
        )
        .bind(&h.id)
        .bind(&payload.device_id)
        .bind(serde_json::to_string(&delivery).unwrap())
        .execute(&mut *tx)
        .await
        .map_err(database)?;
    }
    tx.commit().await.map_err(database)?;
    let payload = request
        .payloads
        .into_iter()
        .find(|p| p.device_id == h.sender_device_id)
        .unwrap();
    Ok(Json(OperationDelivery {
        header: h.clone(),
        payload,
        revision: revision + 1,
        accepted_at: now,
    }))
}
pub async fn pending(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<DeviceQuery>,
) -> Result<Json<Vec<OperationDelivery>>, Failure> {
    authorize(&state, &headers, &q.device_id).await?;
    let rows = sqlx::query("SELECT body FROM operation_deliveries WHERE device_id = $1 AND acked = false ORDER BY operation_id LIMIT 100")
        .bind(q.device_id).fetch_all(state.db.pool()).await.map_err(database)?;
    let result = rows
        .into_iter()
        .map(|r| serde_json::from_str(&r.get::<String, _>("body")))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| reject("变更队列数据损坏"))?;
    Ok(Json(result))
}
#[derive(Deserialize)]
pub struct Ack {
    device_id: String,
    ids: Vec<String>,
}
pub async fn ack(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(q): Json<Ack>,
) -> Result<Json<bool>, Failure> {
    authorize(&state, &headers, &q.device_id).await?;
    if q.ids.len() > 100 {
        return Err(reject("确认批次过大"));
    }
    sqlx::query("UPDATE operation_deliveries SET acked = true WHERE device_id = $1 AND operation_id = ANY($2)")
        .bind(q.device_id).bind(q.ids).execute(state.db.pool()).await.map_err(database)?;
    Ok(Json(true))
}
