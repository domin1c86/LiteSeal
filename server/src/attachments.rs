use axum::{body::Bytes, extract::{Path, Query, State}, http::{HeaderMap, StatusCode}, Json};
use serde::Deserialize;
use sqlx::Row;
use crate::state::AppState;
type Failure = (StatusCode, String);
fn db(_: sqlx::Error) -> Failure { (StatusCode::SERVICE_UNAVAILABLE, "附件存储暂不可用".into()) }
#[derive(Deserialize)]
pub struct Access { pub device_id: String }
#[derive(Deserialize)]
pub struct Create { pub device_id: String, pub id: String, pub message_id: String, pub recipient: String, pub size: i64 }

pub async fn create(State(state): State<AppState>, headers: HeaderMap, Json(input): Json<Create>) -> Result<Json<serde_json::Value>, Failure> {
    let user = super::message_operations::authorize(&state, &headers, &input.device_id).await?;
    if uuid::Uuid::parse_str(&input.id).is_err() || uuid::Uuid::parse_str(&input.message_id).is_err()
        || !(40..=20 * 1024 * 1024 + 40).contains(&input.size) || user == input.recipient {
        return Err((StatusCode::BAD_REQUEST, "附件大小或标识无效".into()));
    }
    let mut tx = state.db.pool().begin().await.map_err(db)?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 1))").bind(&user).execute(&mut *tx).await.map_err(db)?;
    // Unsent objects expire after one day; published objects remain downloadable for 30 days.
    sqlx::query("DELETE FROM attachment_objects a WHERE expires_at < now() OR (created_at < now() - interval '1 day' AND NOT EXISTS (SELECT 1 FROM beta_receipts r WHERE r.message_id = a.message_id AND r.sender_user_id = a.owner))").execute(&mut *tx).await.map_err(db)?;
    if let Some(row) = sqlx::query("SELECT owner, message_id, recipient, size FROM attachment_objects WHERE id = $1").bind(&input.id).fetch_optional(&mut *tx).await.map_err(db)? {
        if row.get::<String,_>("owner") != user || row.get::<String,_>("message_id") != input.message_id || row.get::<String,_>("recipient") != input.recipient || row.get::<i64,_>("size") != input.size {
            return Err((StatusCode::CONFLICT, "附件编号已绑定其他任务".into()));
        }
    } else {
        let used: i64 = sqlx::query_scalar("SELECT COALESCE(SUM(size),0)::BIGINT FROM attachment_objects WHERE owner=$1").bind(&user).fetch_one(&mut *tx).await.map_err(db)?;
        if used + input.size > 512 * 1024 * 1024 { return Err((StatusCode::PAYLOAD_TOO_LARGE, "附件配额为每账号 512 MiB".into())); }
        sqlx::query("INSERT INTO attachment_objects(id,owner,message_id,recipient,size) VALUES ($1,$2,$3,$4,$5)")
            .bind(&input.id).bind(&user).bind(&input.message_id).bind(&input.recipient).bind(input.size).execute(&mut *tx).await.map_err(db)?;
    }
    tx.commit().await.map_err(db)?;
    Ok(Json(serde_json::json!({"id":input.id})))
}

pub async fn upload(State(state): State<AppState>, headers: HeaderMap, Path((id, part)): Path<(String, i32)>, Query(q): Query<Access>, bytes: Bytes) -> Result<StatusCode, Failure> {
    let user = super::message_operations::authorize(&state, &headers, &q.device_id).await?;
    let mut tx = state.db.pool().begin().await.map_err(db)?;
    let row = sqlx::query("SELECT size,owner FROM attachment_objects WHERE id=$1 AND expires_at > now() FOR UPDATE").bind(&id).fetch_optional(&mut *tx).await.map_err(db)?.ok_or((StatusCode::NOT_FOUND,"附件已过期".into()))?;
    if row.get::<String,_>("owner") != user { return Err((StatusCode::FORBIDDEN,"无上传权限".into())); }
    let size: i64 = row.get("size");
    let offset = i64::from(part) * 1024 * 1024;
    if part < 0 || offset >= size || bytes.len() as i64 != (size-offset).min(1024*1024) { return Err((StatusCode::BAD_REQUEST,"分块大小无效".into())); }
    if let Some(old) = sqlx::query("SELECT data FROM attachment_chunks WHERE object_id=$1 AND part=$2").bind(&id).bind(part).fetch_optional(&mut *tx).await.map_err(db)? {
        if old.get::<Vec<u8>,_>("data") != bytes.as_ref() { return Err((StatusCode::CONFLICT,"禁止改写已上传密文".into())); }
    } else {
        sqlx::query("INSERT INTO attachment_chunks(object_id,part,data) VALUES ($1,$2,$3)").bind(id).bind(part).bind(bytes.as_ref()).execute(&mut *tx).await.map_err(db)?;
    }
    tx.commit().await.map_err(db)?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn download(State(state): State<AppState>, headers: HeaderMap, Path((id, part)): Path<(String,i32)>, Query(q): Query<Access>) -> Result<Bytes, Failure> {
    let user = super::message_operations::authorize(&state, &headers, &q.device_id).await?;
    let row = sqlx::query("SELECT a.owner,a.recipient,a.message_id,c.data FROM attachment_objects a JOIN attachment_chunks c ON c.object_id=a.id WHERE a.id=$1 AND c.part=$2 AND a.expires_at > now()")
        .bind(&id).bind(part).fetch_optional(state.db.pool()).await.map_err(db)?.ok_or((StatusCode::NOT_FOUND,"附件未完成或已过期".into()))?;
    let owner: String = row.get("owner");
    if user != owner {
        if user != row.get::<String,_>("recipient") { return Err((StatusCode::FORBIDDEN,"无下载权限".into())); }
        let receipt: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM beta_receipts WHERE message_id=$1 AND sender_user_id=$2 AND recipient_user_id=$3 AND recipient_device_id=$4)")
            .bind(row.get::<String,_>("message_id")).bind(owner).bind(user).bind(q.device_id).fetch_one(state.db.pool()).await.map_err(db)?;
        if !receipt { return Err((StatusCode::FORBIDDEN,"附件尚未绑定到已签名消息".into())); }
    }
    Ok(Bytes::from(row.get::<Vec<u8>,_>("data")))
}

pub const MIGRATION: &str = "
CREATE TABLE IF NOT EXISTS attachment_objects (
 id TEXT PRIMARY KEY, owner TEXT NOT NULL, message_id TEXT NOT NULL, recipient TEXT NOT NULL,
 size BIGINT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), expires_at TIMESTAMPTZ NOT NULL DEFAULT now()+interval '30 days'
);
CREATE TABLE IF NOT EXISTS attachment_chunks (
 object_id TEXT NOT NULL REFERENCES attachment_objects(id) ON DELETE CASCADE, part INTEGER NOT NULL, data BYTEA NOT NULL,
 PRIMARY KEY(object_id,part)
);
CREATE INDEX IF NOT EXISTS attachment_owner ON attachment_objects(owner);
";
