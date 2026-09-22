use axum::{extract::{State,Query},http::{HeaderMap,StatusCode},Json};
use serde::Deserialize;
use sqlx::Row;
use crate::state::AppState;
type Failure=(StatusCode,String);
fn db(_:sqlx::Error)->Failure{(StatusCode::SERVICE_UNAVAILABLE,"联系请求暂不可用".into())}
#[derive(Deserialize)]
pub struct Change{device_id:String,peer_id:String,status:String}
pub async fn list(State(state):State<AppState>,headers:HeaderMap,Query(q):Query<crate::attachments::Access>)->Result<Json<serde_json::Value>,Failure>{
    let user=crate::message_operations::authorize(&state,&headers,&q.device_id).await?;
    let rows=sqlx::query("SELECT p.peer_id,p.status,u.username FROM contact_policy p JOIN users u ON u.id=p.peer_id WHERE p.user_id=$1 ORDER BY p.updated_at DESC LIMIT 200")
        .bind(user).fetch_all(state.db.pool()).await.map_err(db)?;
    Ok(Json(serde_json::Value::Array(rows.iter().map(|r|serde_json::json!({"peer_id":r.get::<String,_>("peer_id"),"status":r.get::<String,_>("status"),"username":r.get::<String,_>("username")})).collect())))
}
pub async fn change(State(state):State<AppState>,headers:HeaderMap,Json(input):Json<Change>)->Result<StatusCode,Failure>{
    let user=crate::message_operations::authorize(&state,&headers,&input.device_id).await?;
    if !["accepted","blocked","rejected","pending"].contains(&input.status.as_str()) || user==input.peer_id {return Err((StatusCode::BAD_REQUEST,"无效请求状态".into()));}
    let mut tx=state.db.pool().begin().await.map_err(db)?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 2))").bind(&user).execute(&mut *tx).await.map_err(db)?;
    sqlx::query("INSERT INTO contact_policy(user_id,peer_id,status) VALUES($1,$2,$3) ON CONFLICT(user_id,peer_id) DO UPDATE SET status=excluded.status,updated_at=now()")
        .bind(user).bind(input.peer_id).bind(input.status).execute(&mut *tx).await.map_err(db)?;
    tx.commit().await.map_err(db)?;Ok(StatusCode::NO_CONTENT)
}
pub const MIGRATION:&str="CREATE TABLE IF NOT EXISTS contact_policy (
 user_id TEXT NOT NULL REFERENCES users(id), peer_id TEXT NOT NULL REFERENCES users(id), status TEXT NOT NULL,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY(user_id,peer_id)
); CREATE INDEX IF NOT EXISTS contact_policy_requests ON contact_policy(user_id,status);";
