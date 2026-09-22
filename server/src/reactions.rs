use axum::{extract::{State,Query},http::{HeaderMap,StatusCode},Json};
use serde::Deserialize;
use sqlx::Row;
use liteseal_shared::{crypto,reaction::{Reaction,ReactionDelivery}};
use crate::state::AppState;
type Failure=(StatusCode,String);
fn db(_:sqlx::Error)->Failure{(StatusCode::SERVICE_UNAVAILABLE,"回应存储暂不可用".into())}
fn invalid()->Failure{(StatusCode::CONFLICT,"回应身份、版本或原消息不可用".into())}
pub async fn submit(State(state):State<AppState>,headers:HeaderMap,Json(event):Json<Reaction>)->Result<Json<ReactionDelivery>,Failure>{
    let user=crate::message_operations::authorize(&state,&headers,&event.device).await?;
    if user!=event.actor || !(1..=1_000_000).contains(&event.revision) || event.ciphertext.len()>256 || uuid::Uuid::parse_str(&event.id).is_err(){return Err(invalid());}
    let device=state.db.get_user_device(&user,&event.device).await.map_err(db)?.ok_or_else(invalid)?;
    if !state.db.hit_rate_limit(&format!("reactions:{user}"),120,60).await.map_err(db)? {return Err((StatusCode::TOO_MANY_REQUESTS,"回应过于频繁，请稍后重试".into()));}
    let key:[u8;32]=device.ed25519_pk.try_into().map_err(|_|invalid())?;
    if !crypto::verify_with_public_key(&event.signing_bytes(),&event.signature,&key).map_err(|_|invalid())?{return Err(invalid());}
    let mut tx=state.db.pool().begin().await.map_err(db)?;
    // Commit order equals cursor order; duplicate IDs return the original event.
    sqlx::query("SELECT pg_advisory_xact_lock(1818850405,10)").execute(&mut *tx).await.map_err(db)?;
    let body=serde_json::to_string(&event).map_err(|_|invalid())?;
    if let Some(row)=sqlx::query("SELECT seq,body FROM reaction_events WHERE id=$1").bind(&event.id).fetch_optional(&mut *tx).await.map_err(db)?{
        if row.get::<String,_>("body")!=body{return Err(invalid());}
        return Ok(Json(ReactionDelivery{seq:row.get("seq"),event}));
    }
    let allowed:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM beta_receipts WHERE message_id=$1 AND conversation_id=$2 AND ((sender_user_id=$3 AND recipient_user_id=$4) OR (sender_user_id=$4 AND recipient_user_id=$3)))")
        .bind(&event.target_id).bind(&event.conversation_id).bind(&event.actor).bind(&event.peer).fetch_one(&mut *tx).await.map_err(db)?;
    let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM contact_policy WHERE user_id=$1 AND peer_id=$2 AND status!='accepted')")
        .bind(&event.peer).bind(&event.actor).fetch_one(&mut *tx).await.map_err(db)?;
    let revoked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM message_operations WHERE target_id=$1 AND kind='revoke')").bind(&event.target_id).fetch_one(&mut *tx).await.map_err(db)?;
    let revision:i64=sqlx::query_scalar("SELECT COALESCE(MAX(revision),0) FROM reaction_events WHERE target_id=$1 AND actor=$2").bind(&event.target_id).bind(&event.actor).fetch_one(&mut *tx).await.map_err(db)?;
    if !allowed||blocked||revoked||event.revision!=revision+1{return Err(invalid());}
    let seq:i64=sqlx::query_scalar("INSERT INTO reaction_events(id,target_id,actor,peer,revision,body) VALUES($1,$2,$3,$4,$5,$6) RETURNING seq")
        .bind(&event.id).bind(&event.target_id).bind(&event.actor).bind(&event.peer).bind(event.revision).bind(body).fetch_one(&mut *tx).await.map_err(db)?;
    tx.commit().await.map_err(db)?;Ok(Json(ReactionDelivery{seq,event}))
}
#[derive(Deserialize)]pub struct Cursor{device_id:String,after:i64}
pub async fn list(State(state):State<AppState>,headers:HeaderMap,Query(q):Query<Cursor>)->Result<Json<Vec<ReactionDelivery>>,Failure>{
    let user=crate::message_operations::authorize(&state,&headers,&q.device_id).await?;
    let rows=sqlx::query("SELECT seq,body FROM reaction_events WHERE seq>$1 AND (actor=$2 OR peer=$2) ORDER BY seq LIMIT 100").bind(q.after.max(0)).bind(user).fetch_all(state.db.pool()).await.map_err(db)?;
    let mut deliveries=Vec::new();for row in rows {deliveries.push(ReactionDelivery{seq:row.get("seq"),event:serde_json::from_str(&row.get::<String,_>("body")).map_err(|_|invalid())?});}Ok(Json(deliveries))
}
pub const MIGRATION:&str="CREATE TABLE IF NOT EXISTS reaction_events(seq BIGSERIAL UNIQUE,id TEXT PRIMARY KEY,target_id TEXT NOT NULL,actor TEXT NOT NULL,peer TEXT NOT NULL,revision BIGINT NOT NULL,body TEXT NOT NULL,UNIQUE(target_id,actor,revision)); CREATE INDEX IF NOT EXISTS reaction_delivery ON reaction_events(seq,actor,peer);";
