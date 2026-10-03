use super::*;
use axum::body::Bytes;
use liteseal_shared::direct_operation::{self as op, Action, Event, Operation, Page};
use op::Outcome as OperationOutcome;
pub use op::Receipt;
pub const MIGRATION:&str="
CREATE TABLE direct_v3_operation_subjects(target TEXT PRIMARY KEY REFERENCES direct_v3_batches(id),revision BIGINT NOT NULL DEFAULT 0 CHECK(revision BETWEEN 0 AND 10000),retracted BOOLEAN NOT NULL DEFAULT false);
CREATE TABLE direct_v3_operations(id TEXT PRIMARY KEY,target TEXT NOT NULL REFERENCES direct_v3_batches(id),owner TEXT NOT NULL REFERENCES users(id),source TEXT NOT NULL,revision BIGINT NOT NULL CHECK(revision BETWEEN 1 AND 10000),digest BYTEA NOT NULL CHECK(octet_length(digest)=32),wire BYTEA NOT NULL CHECK(octet_length(wire)<=524288),event_order BIGSERIAL UNIQUE,accepted_at BIGINT NOT NULL CHECK(accepted_at>0),UNIQUE(target,revision));
CREATE INDEX direct_v3_operations_owner ON direct_v3_operations(owner);
CREATE TABLE direct_v3_operation_audience(event TEXT NOT NULL REFERENCES direct_v3_operations(id),account TEXT NOT NULL REFERENCES users(id),device TEXT NOT NULL,authority BYTEA NOT NULL CHECK(octet_length(authority)=32),PRIMARY KEY(event,device));
CREATE INDEX direct_v3_operation_reader ON direct_v3_operation_audience(account,device);
";
pub const CANCEL_MIGRATION:&str="
CREATE TABLE direct_v3_operation_cancels(id TEXT PRIMARY KEY,target TEXT NOT NULL REFERENCES direct_v3_batches(id),owner TEXT NOT NULL REFERENCES users(id),source TEXT NOT NULL,authority BYTEA NOT NULL CHECK(octet_length(authority)=32),digest BYTEA NOT NULL CHECK(octet_length(digest)=32));
CREATE INDEX direct_v3_operation_cancels_owner ON direct_v3_operation_cancels(owner);
";
pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/direct/v3/operations", post(publish).get(page))
        .route("/direct/v3/operations/:id", get(result))
        .route("/direct/v3/operations/:id/outcome", get(outcome))
        .route("/direct/v3/operations/:id/cancel", post(cancel))
        .layer(DefaultBodyLimit::max(op::MAX_WIRE))
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
struct Admission {
    sender: DeviceState,
    old_sender: DeviceState,
    old_peer: DeviceState,
    authority: [u8; 32],
    accepted_at: i64,
}
async fn authorize(
    tx: &mut Tx<'_>,
    state: &AppState,
    hash: &str,
    user: &str,
    operation: &Operation,
) -> Result<Admission, Failure> {
    let original = &operation.original;
    if user != original.header.sender || original.header.origin != origin(state)? {
        return Err(denied());
    }
    lock_accounts(tx, &[user, &original.header.peer]).await?;
    let (sender, _) = current(tx, user, origin(state)?).await?;
    let authority = session(tx, hash, user, &original.header.sender_device, &sender).await?;
    let (old_sender, old_peer) = historical(tx, original, origin(state)?).await?;
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
    let accepted=sqlx::query("SELECT digest,sender,source,peer,accepted_at FROM direct_v3_batches WHERE id=$1 AND state='accepted' FOR SHARE").bind(&original.header.id).fetch_optional(&mut **tx).await.map_err(storage)?.ok_or_else(denied)?;
    if accepted.get::<Vec<u8>, _>("digest") != operation.header.original
        || accepted.get::<String, _>("sender") != user
        || accepted.get::<String, _>("source") != original.header.sender_device
        || accepted.get::<String, _>("peer") != original.header.peer
    {
        return Err(denied());
    }
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,8))")
        .bind(&operation.header.id)
        .execute(&mut **tx)
        .await
        .map_err(storage)?;
    Ok(Admission {
        sender,
        old_sender,
        old_peer,
        authority,
        accepted_at: accepted.get("accepted_at"),
    })
}
async fn existing(
    tx: &mut Tx<'_>,
    id: &str,
    user: &str,
    device: &str,
    authority: [u8; 32],
    digest: [u8; 32],
) -> Result<Option<OperationOutcome>, Failure> {
    if let Some(row)=sqlx::query("SELECT o.id,o.owner,o.source,o.digest,o.revision,o.event_order,o.accepted_at,a.authority FROM direct_v3_operations o LEFT JOIN direct_v3_operation_audience a ON a.event=o.id AND a.account=o.owner AND a.device=o.source WHERE o.id=$1").bind(id).fetch_optional(&mut **tx).await.map_err(storage)? {
        if row.get::<String,_>("owner")!=user||row.get::<String,_>("source")!=device||row.get::<Option<Vec<u8>>,_>("authority").as_deref()!=Some(authority.as_slice()){return Err(denied());}
        if row.get::<Vec<u8>,_>("digest")!=digest{return Err(conflict());}
        return Ok(Some(OperationOutcome::Accepted{receipt:receipt(&row)?}));
    }
    if let Some(row) = sqlx::query(
        "SELECT owner,source,authority,digest FROM direct_v3_operation_cancels WHERE id=$1",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(storage)?
    {
        if row.get::<String, _>("owner") != user
            || row.get::<String, _>("source") != device
            || row.get::<Vec<u8>, _>("authority") != authority
        {
            return Err(denied());
        }
        if row.get::<Vec<u8>, _>("digest") != digest {
            return Err(conflict());
        }
        return Ok(Some(OperationOutcome::Cancelled {
            id: id.into(),
            digest,
        }));
    }
    Ok(None)
}
fn published(result: OperationOutcome) -> Result<Json<Receipt>, Failure> {
    match result {
        OperationOutcome::Accepted { receipt } => Ok(Json(receipt)),
        OperationOutcome::Cancelled { .. } => {
            Err((StatusCode::GONE, "原操作已取消，禁止再次发布".into()))
        }
        OperationOutcome::Unknown { .. } => Err(bad()),
    }
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
    let Admission {
        sender,
        old_sender,
        old_peer,
        authority,
        accepted_at,
    } = authorize(&mut tx, &state, &hash, &user, &operation).await?;
    let digest = operation.digest().map_err(codec)?;
    if let Some(result) = existing(
        &mut tx,
        &operation.header.id,
        &user,
        &original.header.sender_device,
        authority,
        digest,
    )
    .await?
    {
        tx.commit().await.map_err(storage)?;
        return published(result);
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
    if let Some(result) = existing(
        &mut tx,
        &operation.header.id,
        &user,
        &original.header.sender_device,
        authority,
        digest,
    )
    .await?
    {
        tx.commit().await.map_err(storage)?;
        return published(result);
    }
    let now: i64 =
        sqlx::query_scalar("SELECT (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(&mut *tx)
            .await
            .map_err(storage)?;
    if now.saturating_sub(accepted_at) > 48 * 60 * 60 * 1000 {
        return Err((
            StatusCode::GONE,
            "已超过首次接收后的 48 小时操作期限；原结果仍可查询".into(),
        ));
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
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Lookup {
    device_id: String,
    digest: String,
}
async fn outcome(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(input): Query<Lookup>,
) -> Result<Json<OperationOutcome>, Failure> {
    uuid(&id)?;
    let digest: [u8; 32] = hex::decode(&input.digest)
        .map_err(|_| bad())?
        .try_into()
        .map_err(|_| bad())?;
    let (user, hash) = admit(&state, &headers, &input.device_id).await?;
    let mut tx = state.db.pool().begin().await.map_err(storage)?;
    lock_accounts(&mut tx, &[&user]).await?;
    let (directory, _) = current(&mut tx, &user, origin(&state)?).await?;
    let authority = session(&mut tx, &hash, &user, &input.device_id, &directory).await?;
    let result = existing(&mut tx, &id, &user, &input.device_id, authority, digest)
        .await?
        .unwrap_or(OperationOutcome::Unknown { id, digest });
    tx.commit().await.map_err(storage)?;
    Ok(Json(result))
}
async fn cancel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    wire: Bytes,
) -> Result<Json<OperationOutcome>, Failure> {
    uuid(&id)?;
    let operation = Operation::from_wire(&wire).map_err(codec)?;
    if id != operation.header.id {
        return Err(bad());
    }
    uuid(&operation.original.header.id)?;
    let (user, hash) = admit(&state, &headers, &operation.original.header.sender_device).await?;
    let mut tx = state.db.pool().begin().await.map_err(storage)?;
    let proof = authorize(&mut tx, &state, &hash, &user, &operation).await?;
    let digest = operation.digest().map_err(codec)?;
    if let Some(result) = existing(
        &mut tx,
        &id,
        &user,
        &operation.original.header.sender_device,
        proof.authority,
        digest,
    )
    .await?
    {
        tx.commit().await.map_err(storage)?;
        return Ok(Json(result));
    }
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,7))")
        .bind(&user)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM direct_v3_operation_cancels WHERE owner=$1")
            .bind(&user)
            .fetch_one(&mut *tx)
            .await
            .map_err(storage)?;
    if count >= 1000 {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "操作取消记录达到 1000 项上限，请保留原任务".into(),
        ));
    }
    sqlx::query("INSERT INTO direct_v3_operation_cancels(id,target,owner,source,authority,digest) VALUES($1,$2,$3,$4,$5,$6)").bind(&id).bind(&operation.original.header.id).bind(&user).bind(&operation.original.header.sender_device).bind(proof.authority.as_slice()).bind(digest.as_slice()).execute(&mut *tx).await.map_err(storage)?;
    tx.commit().await.map_err(storage)?;
    Ok(Json(OperationOutcome::Cancelled { id, digest }))
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
