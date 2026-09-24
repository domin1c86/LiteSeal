use crate::state::AppState;
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use liteseal_shared::{
    crypto,
    read_receipt::{ReadReceipt, ReadReceiptDelivery},
};
use serde::Deserialize;
use sqlx::Row;

type Failure = (StatusCode, String);
fn database(_: sqlx::Error) -> Failure {
    (StatusCode::SERVICE_UNAVAILABLE, "阅读回执暂不可用".into())
}
fn invalid() -> Failure {
    (StatusCode::CONFLICT, "阅读回执身份或原消息不匹配".into())
}
fn insert_failure(error: sqlx::Error) -> Failure {
    if error
        .as_database_error()
        .and_then(|detail| detail.code())
        .as_deref()
        == Some("23505")
    {
        invalid()
    } else {
        database(error)
    }
}

pub async fn submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(event): Json<ReadReceipt>,
) -> Result<Json<ReadReceiptDelivery>, Failure> {
    let user = crate::message_operations::authorize(&state, &headers, &event.device).await?;
    if user != event.reader
        || event.reader == event.peer
        || uuid::Uuid::parse_str(&event.id).is_err()
        || uuid::Uuid::parse_str(&event.target_id).is_err()
        || event.conversation_id.len() > 256
        || event.peer.len() > 128
        || event.signature.len() != 64
    {
        return Err(invalid());
    }
    let device = state
        .db
        .get_user_device(&user, &event.device)
        .await
        .map_err(database)?
        .ok_or_else(invalid)?;
    let key: [u8; 32] = device.ed25519_pk.try_into().map_err(|_| invalid())?;
    if !crypto::verify_with_public_key(&event.signing_bytes(), &event.signature, &key)
        .map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    if !state
        .db
        .hit_rate_limit(&format!("read-receipts:{user}"), 120, 60)
        .await
        .map_err(database)?
    {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "阅读回执过于频繁，请稍后重试".into(),
        ));
    }
    let mut tx = state.db.pool().begin().await.map_err(database)?;
    sqlx::query("SELECT pg_advisory_xact_lock(1818850405,11)")
        .execute(&mut *tx)
        .await
        .map_err(database)?;
    let body = serde_json::to_string(&event).map_err(|_| invalid())?;
    if let Some(row) = sqlx::query("SELECT seq,body FROM read_receipt_events WHERE id=$1")
        .bind(&event.id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(database)?
    {
        if row.get::<String, _>("body") != body {
            return Err(invalid());
        }
        return Ok(Json(ReadReceiptDelivery {
            seq: row.get("seq"),
            event,
        }));
    }
    let allowed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM beta_receipts WHERE message_id=$1 AND conversation_id=$2 AND sender_user_id=$3 AND recipient_user_id=$4 AND status!='rejected')")
        .bind(&event.target_id).bind(&event.conversation_id).bind(&event.peer).bind(&event.reader)
        .fetch_one(&mut *tx).await.map_err(database)?;
    let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM contact_policy WHERE user_id=$1 AND peer_id=$2 AND status!='accepted')")
        .bind(&event.peer).bind(&event.reader).fetch_one(&mut *tx).await.map_err(database)?;
    let revoked: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM message_operations WHERE target_id=$1 AND kind='revoke')",
    )
    .bind(&event.target_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(database)?;
    if !allowed || blocked || revoked {
        return Err(invalid());
    }
    let seq: i64 = sqlx::query_scalar("INSERT INTO read_receipt_events(id,target_id,reader,peer,body) VALUES($1,$2,$3,$4,$5) RETURNING seq")
        .bind(&event.id).bind(&event.target_id).bind(&event.reader).bind(&event.peer).bind(body)
        .fetch_one(&mut *tx).await.map_err(insert_failure)?;
    tx.commit().await.map_err(database)?;
    Ok(Json(ReadReceiptDelivery { seq, event }))
}

#[derive(Deserialize)]
pub struct Cursor {
    device_id: String,
    after: i64,
}

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<Cursor>,
) -> Result<Json<Vec<ReadReceiptDelivery>>, Failure> {
    let user = crate::message_operations::authorize(&state, &headers, &q.device_id).await?;
    let rows = sqlx::query("SELECT seq,body FROM read_receipt_events WHERE seq>$1 AND (reader=$2 OR peer=$2) ORDER BY seq LIMIT 100")
        .bind(q.after.max(0)).bind(user).fetch_all(state.db.pool()).await.map_err(database)?;
    rows.into_iter()
        .map(|row| {
            Ok(ReadReceiptDelivery {
                seq: row.get("seq"),
                event: serde_json::from_str(&row.get::<String, _>("body"))
                    .map_err(|_| invalid())?,
            })
        })
        .collect::<Result<Vec<_>, Failure>>()
        .map(Json)
}

pub const MIGRATION: &str = "CREATE TABLE IF NOT EXISTS read_receipt_events(seq BIGSERIAL UNIQUE,id TEXT PRIMARY KEY,target_id TEXT NOT NULL,reader TEXT NOT NULL,peer TEXT NOT NULL,body TEXT NOT NULL,UNIQUE(target_id,reader)); CREATE INDEX IF NOT EXISTS read_receipt_delivery ON read_receipt_events(seq,reader,peer);";
