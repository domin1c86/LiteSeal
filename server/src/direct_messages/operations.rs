use super::*;
use axum::body::Bytes;
use liteseal_shared::direct_operation::{self as op, Action, Event, Operation, Page};
use serde::Serialize;
pub const MIGRATION:&str="
CREATE TABLE direct_v3_operation_subjects(target TEXT PRIMARY KEY REFERENCES direct_v3_batches(id),revision BIGINT NOT NULL DEFAULT 0 CHECK(revision BETWEEN 0 AND 10000),retracted BOOLEAN NOT NULL DEFAULT false);
CREATE TABLE direct_v3_operations(id TEXT PRIMARY KEY,target TEXT NOT NULL REFERENCES direct_v3_batches(id),owner TEXT NOT NULL REFERENCES users(id),source TEXT NOT NULL,revision BIGINT NOT NULL CHECK(revision BETWEEN 1 AND 10000),digest BYTEA NOT NULL CHECK(octet_length(digest)=32),wire BYTEA NOT NULL CHECK(octet_length(wire)<=524288),event_order BIGSERIAL UNIQUE,accepted_at BIGINT NOT NULL CHECK(accepted_at>0),UNIQUE(target,revision));
CREATE INDEX direct_v3_operations_owner ON direct_v3_operations(owner);
CREATE TABLE direct_v3_operation_audience(event TEXT NOT NULL REFERENCES direct_v3_operations(id),account TEXT NOT NULL REFERENCES users(id),device TEXT NOT NULL,authority BYTEA NOT NULL CHECK(octet_length(authority)=32),PRIMARY KEY(event,device));
CREATE INDEX direct_v3_operation_reader ON direct_v3_operation_audience(account,device);
";
pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/direct/v3/operations", post(publish).get(page))
        .route("/direct/v3/operations/:id", get(result))
        .layer(DefaultBodyLimit::max(op::MAX_WIRE))
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub id: String,
    pub digest: [u8; 32],
    pub revision: u64,
    pub order: i64,
    pub accepted_at: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Read {
    device_id: String,
    after: Option<i64>,
    limit: Option<usize>,
}
fn receipt(row: &sqlx::postgres::PgRow) -> Result<Receipt, Failure> {
    Ok(Receipt {
        id: row.try_get("id").map_err(storage)?,
        digest: row
            .try_get::<Vec<u8>, _>("digest")
            .map_err(storage)?
            .try_into()
            .map_err(|_| denied())?,
        revision: row.try_get::<i64, _>("revision").map_err(storage)? as u64,
        order: row.try_get("event_order").map_err(storage)?,
        accepted_at: row.try_get("accepted_at").map_err(storage)?,
    })
}
async fn publish(
    State(state): State<AppState>,
    headers: HeaderMap,
    wire: Bytes,
) -> Result<Json<Receipt>, Failure> {
    let operation = Operation::from_wire(&wire).map_err(codec)?;
    let original = &operation.original;
    uuid(&operation.header.id)?;
    uuid(&original.header.id)?;
    let (user, hash) = admit(&state, &headers, &original.header.sender_device).await?;
    if user != original.header.sender || original.header.origin != origin(&state)? {
        return Err(denied());
    }
    let mut tx = state.db.pool().begin().await.map_err(storage)?;
    lock_accounts(&mut tx, &[&user, &original.header.peer]).await?;
    let (sender, _) = current(&mut tx, &user, origin(&state)?).await?;
    let authority = session(
        &mut tx,
        &hash,
        &user,
        &original.header.sender_device,
        &sender,
    )
    .await?;
    let (old_sender, old_peer) = historical(&mut tx, original, origin(&state)?).await?;
    operation
        .verify_original(&old_sender, &old_peer)
        .map_err(codec)?;
    let author = original
        .header
        .sender_directory
        .members
        .iter()
        .find(|m| m.device.device_id == original.header.sender_device)
        .ok_or_else(denied)?;
    if author.authorization_hash != authority {
        return Err(denied());
    }
    let accepted=sqlx::query("SELECT digest,sender,source,peer FROM direct_v3_batches WHERE id=$1 AND state='accepted' FOR SHARE").bind(&original.header.id).fetch_optional(&mut *tx).await.map_err(storage)?.ok_or_else(denied)?;
    if accepted.get::<Vec<u8>, _>("digest") != operation.header.original
        || accepted.get::<String, _>("sender") != user
        || accepted.get::<String, _>("source") != original.header.sender_device
        || accepted.get::<String, _>("peer") != original.header.peer
    {
        return Err(denied());
    }
    let digest = operation.digest().map_err(codec)?;
    if let Some(row)=sqlx::query("SELECT id,owner,source,digest,revision,event_order,accepted_at FROM direct_v3_operations WHERE id=$1").bind(&operation.header.id).fetch_optional(&mut *tx).await.map_err(storage)?{
        if row.get::<String,_>("owner")!=user||row.get::<String,_>("source")!=original.header.sender_device||row.get::<Vec<u8>,_>("digest")!=digest{return Err(conflict());}
        let result=receipt(&row)?;tx.commit().await.map_err(storage)?;return Ok(Json(result));
    }
    let (peer, _) = current(&mut tx, &original.header.peer, origin(&state)?).await?;
    operation
        .verify_current(&old_sender, &old_peer, &sender, &peer)
        .map_err(codec)?;
    policy(&mut tx, &user, &original.header.peer).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,7))")
        .bind(&user)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
    // Another exact submission can commit while this transaction waits on the
    // policy/quota locks. Resolve it before checking the updated object version.
    if let Some(row)=sqlx::query("SELECT id,owner,source,digest,revision,event_order,accepted_at FROM direct_v3_operations WHERE id=$1").bind(&operation.header.id).fetch_optional(&mut *tx).await.map_err(storage)? {
        if row.get::<String,_>("owner")!=user||row.get::<String,_>("source")!=original.header.sender_device||row.get::<Vec<u8>,_>("digest")!=digest{return Err(conflict());}
        let result=receipt(&row)?;tx.commit().await.map_err(storage)?;return Ok(Json(result));
    }
    let usage=sqlx::query("SELECT COUNT(*) AS count,COALESCE(SUM(octet_length(wire)),0)::BIGINT AS bytes FROM direct_v3_operations WHERE owner=$1").bind(&user).fetch_one(&mut *tx).await.map_err(storage)?;
    if usage.get::<i64, _>("count") >= op::MAX_EVENTS
        || usage.get::<i64, _>("bytes") + wire.len() as i64 > 32 * 1024 * 1024
    {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "操作日志达到 10000 项或 32 MiB 上限，原消息保留".into(),
        ));
    }
    sqlx::query(
        "INSERT INTO direct_v3_operation_subjects(target) VALUES($1) ON CONFLICT DO NOTHING",
    )
    .bind(&original.header.id)
    .execute(&mut *tx)
    .await
    .map_err(storage)?;
    let subject = sqlx::query(
        "SELECT revision,retracted FROM direct_v3_operation_subjects WHERE target=$1 FOR UPDATE",
    )
    .bind(&original.header.id)
    .fetch_one(&mut *tx)
    .await
    .map_err(storage)?;
    if subject.get::<i64, _>("revision") != operation.header.base as i64
        || subject.get::<bool, _>("retracted")
    {
        return Err(conflict());
    }
    let at: i64 = sqlx::query_scalar("SELECT (EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT")
        .fetch_one(&mut *tx)
        .await
        .map_err(storage)?;
    let row=sqlx::query("INSERT INTO direct_v3_operations(id,target,owner,source,revision,digest,wire,accepted_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id,digest,revision,event_order,accepted_at").bind(&operation.header.id).bind(&original.header.id).bind(&user).bind(&original.header.sender_device).bind(operation.header.revision as i64).bind(digest.as_slice()).bind(wire.as_ref()).bind(at).fetch_one(&mut *tx).await.map_err(storage)?;
    for target in &operation.payloads {
        sqlx::query("INSERT INTO direct_v3_operation_audience(event,account,device,authority) VALUES($1,$2,$3,$4)").bind(&operation.header.id).bind(&target.account).bind(&target.device).bind(target.authority.as_slice()).execute(&mut *tx).await.map_err(storage)?;
    }
    sqlx::query("UPDATE direct_v3_operation_subjects SET revision=$2,retracted=$3 WHERE target=$1")
        .bind(&original.header.id)
        .bind(operation.header.revision as i64)
        .bind(operation.header.action == Action::Retract)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
    let result = receipt(&row)?;
    tx.commit().await.map_err(storage)?;
    Ok(Json(result))
}
async fn result(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(input): Query<Read>,
) -> Result<Json<Option<Receipt>>, Failure> {
    uuid(&id)?;
    if input.after.is_some() || input.limit.is_some() {
        return Err(bad());
    }
    let (user, hash) = admit(&state, &headers, &input.device_id).await?;
    let mut tx = state.db.pool().begin().await.map_err(storage)?;
    lock_accounts(&mut tx, &[&user]).await?;
    let (directory, _) = current(&mut tx, &user, origin(&state)?).await?;
    let authority = session(&mut tx, &hash, &user, &input.device_id, &directory).await?;
    let row=sqlx::query("SELECT o.id,o.digest,o.revision,o.event_order,o.accepted_at FROM direct_v3_operations o JOIN direct_v3_operation_audience a ON a.event=o.id WHERE o.id=$1 AND o.owner=$2 AND o.source=$3 AND a.account=$2 AND a.device=$3 AND a.authority=$4").bind(id).bind(user).bind(input.device_id).bind(authority.as_slice()).fetch_optional(&mut *tx).await.map_err(storage)?;
    let result = row.as_ref().map(receipt).transpose()?;
    tx.commit().await.map_err(storage)?;
    Ok(Json(result))
}
async fn page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(input): Query<Read>,
) -> Result<Json<Page>, Failure> {
    let after = input.after.unwrap_or(0);
    let limit = input.limit.unwrap_or(op::MAX_PAGE);
    if after < 0 || !(1..=op::MAX_PAGE).contains(&limit) {
        return Err(bad());
    }
    let (user, hash) = admit(&state, &headers, &input.device_id).await?;
    let mut tx = state.db.pool().begin().await.map_err(storage)?;
    lock_accounts(&mut tx, &[&user]).await?;
    let (directory, _) = current(&mut tx, &user, origin(&state)?).await?;
    let authority = session(&mut tx, &hash, &user, &input.device_id, &directory).await?;
    let rows=sqlx::query("SELECT o.id,o.event_order,o.accepted_at,octet_length(o.wire) AS wire_size FROM direct_v3_operations o JOIN direct_v3_operation_audience a ON a.event=o.id WHERE a.account=$1 AND a.device=$2 AND a.authority=$3 AND o.event_order>$4 ORDER BY o.event_order LIMIT $5").bind(user).bind(input.device_id).bind(authority.as_slice()).bind(after).bind(limit as i64+1).fetch_all(&mut *tx).await.map_err(storage)?;
    let mut result = Page {
        events: vec![],
        through: after,
        has_more: false,
    };
    let mut bytes = 128usize;
    for row in rows {
        if result.events.len() == limit {
            result.has_more = true;
            break;
        }
        let size = row.get::<i32, _>("wire_size") as usize;
        if bytes + size + 128 > op::MAX_PAGE_BYTES {
            result.has_more = true;
            if result.events.is_empty() {
                return Err((
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "单个操作超过分页字节限制".into(),
                ));
            }
            break;
        }
        let wire: Vec<u8> = sqlx::query_scalar("SELECT wire FROM direct_v3_operations WHERE id=$1")
            .bind(row.get::<String, _>("id"))
            .fetch_one(&mut *tx)
            .await
            .map_err(storage)?;
        let event = Event {
            order: row.get("event_order"),
            accepted_at: row.get("accepted_at"),
            operation: Operation::from_wire(&wire).map_err(codec)?,
        };
        bytes += size + 128;
        result.events.push(event);
        if serde_json::to_vec(&result).map_err(|_| bad())?.len() > op::MAX_PAGE_BYTES - 64 {
            result.events.pop();
            result.has_more = true;
            if result.events.is_empty() {
                return Err((
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "单个操作超过分页字节限制".into(),
                ));
            }
            break;
        }
        result.through = result.events.last().unwrap().order;
    }
    tx.commit().await.map_err(storage)?;
    Ok(Json(result))
}
