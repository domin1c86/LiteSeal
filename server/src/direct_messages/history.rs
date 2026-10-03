//! Root-selected ciphertext transfer. A permit is relay admission, not an
//! original delivery ACK or a claim that the target has committed local data.
use super::*;
use axum::body::Bytes;
use liteseal_shared::history_transfer::{self as h, Offer, RelayState, RelayStatus};
use sha2::{Digest, Sha256};
pub const MIGRATION:&str="
CREATE TABLE direct_v3_history_transfers (
 id TEXT PRIMARY KEY,owner TEXT NOT NULL REFERENCES users(id),source TEXT NOT NULL,target TEXT NOT NULL,
 peer TEXT NOT NULL REFERENCES users(id),digest BYTEA NOT NULL CHECK(octet_length(digest)=32),
 offer BYTEA NOT NULL CHECK(octet_length(offer)<=32768),size BIGINT NOT NULL CHECK(size BETWEEN 40 AND 134217768),
 state TEXT NOT NULL CHECK(state IN ('staging','ready','permitted','received','cancelled','expired')),
 received BYTEA CHECK(octet_length(received)<=4096),CHECK((state='received')=(received IS NOT NULL)),
 expires_at BIGINT NOT NULL CHECK(expires_at>0),created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE INDEX direct_v3_history_owner ON direct_v3_history_transfers(owner,state);
CREATE INDEX direct_v3_history_target ON direct_v3_history_transfers(owner,target,state);
CREATE TABLE direct_v3_history_chunks (
 transfer TEXT NOT NULL REFERENCES direct_v3_history_transfers(id),part INTEGER NOT NULL CHECK(part BETWEEN 0 AND 128),
 data BYTEA NOT NULL CHECK(octet_length(data) BETWEEN 1 AND 1048576),PRIMARY KEY(transfer,part));
";
pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/direct/v3/history", post(create))
        .route("/direct/v3/history/pending", get(pending))
        .route("/direct/v3/history/:id", get(status))
        .route("/direct/v3/history/:id/publish", post(publish))
        .route("/direct/v3/history/:id/cancel", post(cancel))
        .route("/direct/v3/history/:id/permit", post(permit))
        .route("/direct/v3/history/:id/received", post(received))
        .layer(DefaultBodyLimit::max(h::MAX_METADATA))
        .route(
            "/direct/v3/history/:id/chunks/:part",
            get(download)
                .put(upload)
                .layer(DefaultBodyLimit::max(h::CHUNK)),
        )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Access {
    device_id: String,
    digest: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Read {
    device_id: String,
}
fn missing() -> Failure {
    (
        StatusCode::NOT_FOUND,
        "此设备的授权历史不可用或已过期".into(),
    )
}
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |n| n.as_millis() as i64)
}
fn decode(row: &sqlx::postgres::PgRow) -> Result<Offer, Failure> {
    serde_json::from_slice(&row.try_get::<Vec<u8>, _>("offer").map_err(storage)?)
        .map_err(|_| denied())
}
fn state(value: &str) -> Result<RelayState, Failure> {
    match value {
        "staging" => Ok(RelayState::Staging),
        "ready" => Ok(RelayState::Ready),
        "permitted" => Ok(RelayState::Permitted),
        "received" => Ok(RelayState::Received),
        "cancelled" => Ok(RelayState::Cancelled),
        "expired" => Ok(RelayState::Expired),
        _ => Err(denied()),
    }
}
async fn result(
    tx: &mut Tx<'_>,
    offer: &Offer,
    stored: &str,
    current: &DeviceState,
) -> Result<RelayStatus, Failure> {
    let mut outcome = state(stored)?;
    if matches!(outcome, RelayState::Staging | RelayState::Ready) {
        if now() >= offer.header.expires_at {
            outcome = RelayState::Expired;
        } else if Directory::from_state(current) != offer.header.directory {
            outcome = RelayState::Ineligible;
        }
    }
    let next: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM direct_v3_history_chunks WHERE transfer=$1")
            .bind(&offer.header.id)
            .fetch_one(&mut **tx)
            .await
            .map_err(storage)?;
    Ok(RelayStatus {
        id: offer.header.id.clone(),
        digest: offer.digest().map_err(codec)?,
        state: outcome,
        next: next as usize,
    })
}
async fn original_scope(tx: &mut Tx<'_>, offer: &Offer) -> Result<(), Failure> {
    for reference in &offer.header.selection {
        let row=sqlx::query("SELECT sender,source,peer,digest FROM direct_v3_batches WHERE id=$1 AND state='accepted'").bind(&reference.id).fetch_optional(&mut **tx).await.map_err(storage)?.ok_or_else(denied)?;
        let sender: String = row.get("sender");
        let peer: String = row.get("peer");
        if row.get::<Vec<u8>, _>("digest") != reference.digest
            || !((sender == offer.header.account && peer == offer.header.peer)
                || (peer == offer.header.account && sender == offer.header.peer))
        {
            return Err(denied());
        }
        // Source must actually be in the old original audience or its author.
        if !(sender == offer.header.account
            && row.get::<String, _>("source") == offer.header.source.device_id)
        {
            let allowed:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM direct_v3_deliveries WHERE batch=$1 AND account=$2 AND device=$3 AND state<>'ineligible')").bind(&reference.id).bind(&offer.header.account).bind(&offer.header.source.device_id).fetch_one(&mut **tx).await.map_err(storage)?;
            if !allowed {
                return Err(denied());
            }
        }
        let revision: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(revision),0) FROM direct_v3_operations WHERE target=$1",
        )
        .bind(&reference.id)
        .fetch_one(&mut **tx)
        .await
        .map_err(storage)?;
        if revision as u64 != reference.operation_revision {
            return Err(conflict());
        }
    }
    Ok(())
}
async fn load(
    tx: &mut Tx<'_>,
    state: &AppState,
    hash: &str,
    user: &str,
    device: &str,
    reference: (&str, &str),
    requirements: (bool, bool),
) -> Result<(Offer, String, DeviceState), Failure> {
    let (id, digest) = reference;
    let (source, fresh) = requirements;
    uuid(id)?;
    let peek = sqlx::query("SELECT owner,offer FROM direct_v3_history_transfers WHERE id=$1")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(storage)?
        .ok_or_else(missing)?;
    if peek.get::<String, _>("owner") != user {
        return Err(denied());
    }
    let scope = decode(&peek)?;
    lock_accounts(tx, &[user, &scope.header.peer]).await?;
    let (own, events) = current(tx, user, origin(state)?).await?;
    session(tx, hash, user, device, &own).await?;
    let row=sqlx::query("SELECT owner,source,target,offer,state FROM direct_v3_history_transfers WHERE id=$1 FOR UPDATE").bind(id).fetch_optional(&mut **tx).await.map_err(storage)?.ok_or_else(missing)?;
    if row.get::<String, _>("owner") != user
        || row.get::<String, _>(if source { "source" } else { "target" }) != device
    {
        return Err(denied());
    }
    let offer = decode(&row)?;
    if hex::encode(offer.digest().map_err(codec)?) != digest {
        return Err(conflict());
    }
    offer
        .verify(&prefix(&own, &events, &offer.header.directory)?)
        .map_err(codec)?;
    if fresh {
        offer.verify(&own).map_err(codec)?;
        if now() < offer.header.created_at || now() >= offer.header.expires_at {
            return Err(missing());
        }
    }
    Ok((offer, row.get("state"), own))
}
pub(crate) async fn cleanup(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    // Keep permanent IDs/offer digests; disposable ciphertext expires quickly.
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE direct_v3_history_transfers SET state='expired' WHERE state IN ('staging','ready') AND expires_at<=$1").bind(now()).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM direct_v3_history_chunks c USING direct_v3_history_transfers t WHERE t.id=c.transfer AND (t.expires_at<=$1 OR t.state IN ('cancelled','expired'))").bind(now()).execute(&mut *tx).await?;
    tx.commit().await
}
async fn create(
    State(app): State<AppState>,
    headers: HeaderMap,
    Json(offer): Json<Offer>,
) -> Result<Json<RelayStatus>, Failure> {
    let (user, hash) = admit(&app, &headers, &offer.header.source.device_id).await?;
    if user != offer.header.account || offer.header.origin != origin(&app)? {
        return Err(denied());
    }
    uuid(&offer.header.id)?;
    uuid(&offer.header.target.device.device_id)?;
    uuid(&offer.header.peer)?;
    let mut tx = app.db.pool().begin().await.map_err(storage)?;
    lock_accounts(&mut tx, &[&user, &offer.header.peer]).await?;
    let (own, events) = current(&mut tx, &user, origin(&app)?).await?;
    session(&mut tx, &hash, &user, &offer.header.source.device_id, &own).await?;
    offer
        .verify(&prefix(&own, &events, &offer.header.directory)?)
        .map_err(codec)?;
    if let Some(row) = sqlx::query(
        "SELECT owner,source,offer,state FROM direct_v3_history_transfers WHERE id=$1 FOR UPDATE",
    )
    .bind(&offer.header.id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(storage)?
    {
        if row.get::<String, _>("owner") != user || decode(&row)? != offer {
            return Err(conflict());
        }
        let view = result(&mut tx, &offer, &row.get::<String, _>("state"), &own).await?;
        tx.commit().await.map_err(storage)?;
        return Ok(Json(view));
    }
    offer.verify(&own).map_err(codec)?;
    if now() < offer.header.created_at || now() >= offer.header.expires_at {
        return Err(missing());
    }
    original_scope(&mut tx, &offer).await?;
    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM direct_v3_history_transfers WHERE owner=$1")
            .bind(&user)
            .fetch_one(&mut *tx)
            .await
            .map_err(storage)?;
    if total >= 1024 {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "历史授权编号达到账号上限".into(),
        ));
    }
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,1))")
        .bind(&user)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
    let (used, count) = crate::attachments::usage(&mut tx, &user).await?;
    if count >= 100 || used.saturating_add(offer.size as i64) > 200 * 1024 * 1024 {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "授权历史与附件共用额度不足".into(),
        ));
    }
    sqlx::query("INSERT INTO direct_v3_history_transfers(id,owner,source,target,peer,digest,offer,size,state,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'staging',$9)")
      .bind(&offer.header.id).bind(&user).bind(&offer.header.source.device_id).bind(&offer.header.target.device.device_id).bind(&offer.header.peer).bind(offer.digest().map_err(codec)?.as_slice()).bind(serde_json::to_vec(&offer).map_err(|_|bad())?).bind(offer.size as i64).bind(offer.header.expires_at).execute(&mut *tx).await.map_err(storage)?;
    let view = result(&mut tx, &offer, "staging", &own).await?;
    tx.commit().await.map_err(storage)?;
    Ok(Json(view))
}
async fn status(
    State(app): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(input): Query<Access>,
) -> Result<Json<RelayStatus>, Failure> {
    let (user, hash) = admit(&app, &headers, &input.device_id).await?;
    let mut tx = app.db.pool().begin().await.map_err(storage)?;
    let (offer, stored, own) = load(
        &mut tx,
        &app,
        &hash,
        &user,
        &input.device_id,
        (&id, &input.digest),
        (true, false),
    )
    .await?;
    let view = result(&mut tx, &offer, &stored, &own).await?;
    tx.commit().await.map_err(storage)?;
    Ok(Json(view))
}
async fn upload(
    State(app): State<AppState>,
    headers: HeaderMap,
    Path((id, part)): Path<(String, usize)>,
    Query(input): Query<Access>,
    bytes: Bytes,
) -> Result<Json<RelayStatus>, Failure> {
    let (user, hash) = admit(&app, &headers, &input.device_id).await?;
    let mut tx = app.db.pool().begin().await.map_err(storage)?;
    let (offer, stored, own) = load(
        &mut tx,
        &app,
        &hash,
        &user,
        &input.device_id,
        (&id, &input.digest),
        (true, true),
    )
    .await?;
    if stored != "staging" || bytes.len() != offer.chunk_len(part).map_err(codec)? {
        return Err(conflict());
    }
    let view = result(&mut tx, &offer, &stored, &own).await?;
    if part < view.next {
        let old: Vec<u8> = sqlx::query_scalar(
            "SELECT data FROM direct_v3_history_chunks WHERE transfer=$1 AND part=$2",
        )
        .bind(&id)
        .bind(part as i32)
        .fetch_one(&mut *tx)
        .await
        .map_err(storage)?;
        if old.as_slice() != bytes.as_ref() {
            return Err(conflict());
        }
    } else {
        if part != view.next {
            return Err(conflict());
        }
        sqlx::query("INSERT INTO direct_v3_history_chunks(transfer,part,data) VALUES($1,$2,$3)")
            .bind(&id)
            .bind(part as i32)
            .bind(bytes.as_ref())
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
    }
    let view = result(&mut tx, &offer, &stored, &own).await?;
    tx.commit().await.map_err(storage)?;
    Ok(Json(view))
}
async fn publish(
    State(app): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<Access>,
) -> Result<Json<RelayStatus>, Failure> {
    let (user, hash) = admit(&app, &headers, &input.device_id).await?;
    let mut tx = app.db.pool().begin().await.map_err(storage)?;
    let (offer, stored, own) = load(
        &mut tx,
        &app,
        &hash,
        &user,
        &input.device_id,
        (&id, &input.digest),
        (true, true),
    )
    .await?;
    if !matches!(stored.as_str(), "staging" | "ready" | "permitted") {
        return Err(conflict());
    }
    if stored == "staging" {
        original_scope(&mut tx, &offer).await?;
        let mut hash = Sha256::new();
        for part in 0..offer.size.div_ceil(h::CHUNK) {
            let bytes: Vec<u8> = sqlx::query_scalar(
                "SELECT data FROM direct_v3_history_chunks WHERE transfer=$1 AND part=$2",
            )
            .bind(&id)
            .bind(part as i32)
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage)?
            .ok_or_else(conflict)?;
            if bytes.len() != offer.chunk_len(part).map_err(codec)? {
                return Err(conflict());
            }
            hash.update(bytes);
        }
        if hash.finalize().as_slice() != offer.digest {
            return Err(denied());
        }
        sqlx::query("UPDATE direct_v3_history_transfers SET state='ready' WHERE id=$1")
            .bind(&id)
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
    }
    let next = if stored == "staging" {
        "ready"
    } else {
        &stored
    };
    let view = result(&mut tx, &offer, next, &own).await?;
    tx.commit().await.map_err(storage)?;
    Ok(Json(view))
}
async fn cancel(
    State(app): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<Access>,
) -> Result<Json<RelayStatus>, Failure> {
    let (user, hash) = admit(&app, &headers, &input.device_id).await?;
    let mut tx = app.db.pool().begin().await.map_err(storage)?;
    let (offer, stored, own) = load(
        &mut tx,
        &app,
        &hash,
        &user,
        &input.device_id,
        (&id, &input.digest),
        (true, false),
    )
    .await?;
    let next = if matches!(stored.as_str(), "permitted" | "received") {
        &stored
    } else {
        "cancelled"
    };
    if next == "cancelled" {
        sqlx::query("UPDATE direct_v3_history_transfers SET state='cancelled' WHERE id=$1")
            .bind(&id)
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        sqlx::query("DELETE FROM direct_v3_history_chunks WHERE transfer=$1")
            .bind(&id)
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
    }
    let view = result(&mut tx, &offer, next, &own).await?;
    tx.commit().await.map_err(storage)?;
    Ok(Json(view))
}
async fn received(
    State(app): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(receipt): Json<h::Received>,
) -> Result<Json<RelayStatus>, Failure> {
    if id != receipt.id || receipt.confirmed_at > now() + 60000 {
        return Err(bad());
    }
    let (user, hash) = admit(&app, &headers, &receipt.target.device.device_id).await?;
    let mut tx = app.db.pool().begin().await.map_err(storage)?;
    let (offer, stored, own) = load(
        &mut tx,
        &app,
        &hash,
        &user,
        &receipt.target.device.device_id,
        (&id, &hex::encode(receipt.digest)),
        (false, false),
    )
    .await?;
    receipt.verify(&offer).map_err(codec)?;
    if !matches!(stored.as_str(), "permitted" | "received") {
        return Err(conflict());
    }
    if stored != "received" {
        sqlx::query(
            "UPDATE direct_v3_history_transfers SET state='received',received=$2 WHERE id=$1",
        )
        .bind(&id)
        .bind(serde_json::to_vec(&receipt).map_err(|_| bad())?)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
        sqlx::query("DELETE FROM direct_v3_history_chunks WHERE transfer=$1")
            .bind(&id)
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
    }
    let view = result(&mut tx, &offer, "received", &own).await?;
    tx.commit().await.map_err(storage)?;
    Ok(Json(view))
}
async fn pending(
    State(app): State<AppState>,
    headers: HeaderMap,
    Query(input): Query<Read>,
) -> Result<Json<Vec<Offer>>, Failure> {
    let (user, hash) = admit(&app, &headers, &input.device_id).await?;
    let mut tx = app.db.pool().begin().await.map_err(storage)?;
    lock_accounts(&mut tx, &[&user]).await?;
    let (own, _) = current(&mut tx, &user, origin(&app)?).await?;
    session(&mut tx, &hash, &user, &input.device_id, &own).await?;
    let rows=sqlx::query("SELECT offer FROM direct_v3_history_transfers WHERE owner=$1 AND target=$2 AND state IN ('ready','permitted') AND expires_at>$3 ORDER BY created_at,id LIMIT 8").bind(&user).bind(&input.device_id).bind(now()).fetch_all(&mut *tx).await.map_err(storage)?;
    let mut offers = Vec::new();
    for row in rows {
        let offer = decode(&row)?;
        if offer.verify(&own).is_ok() {
            offers.push(offer);
        }
    }
    tx.commit().await.map_err(storage)?;
    Ok(Json(offers))
}
async fn download(
    State(app): State<AppState>,
    headers: HeaderMap,
    Path((id, part)): Path<(String, usize)>,
    Query(input): Query<Access>,
) -> Result<Bytes, Failure> {
    let (user, hash) = admit(&app, &headers, &input.device_id).await?;
    let mut tx = app.db.pool().begin().await.map_err(storage)?;
    let (offer, stored, _) = load(
        &mut tx,
        &app,
        &hash,
        &user,
        &input.device_id,
        (&id, &input.digest),
        (false, true),
    )
    .await?;
    if !matches!(stored.as_str(), "ready" | "permitted") {
        return Err(missing());
    }
    let length = offer.chunk_len(part).map_err(codec)?;
    let bytes: Vec<u8> = sqlx::query_scalar(
        "SELECT data FROM direct_v3_history_chunks WHERE transfer=$1 AND part=$2",
    )
    .bind(&id)
    .bind(part as i32)
    .fetch_optional(&mut *tx)
    .await
    .map_err(storage)?
    .ok_or_else(missing)?;
    if bytes.len() != length {
        return Err(denied());
    }
    tx.commit().await.map_err(storage)?;
    Ok(Bytes::from(bytes))
}
async fn permit(
    State(app): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<Access>,
) -> Result<Json<RelayStatus>, Failure> {
    let (user, hash) = admit(&app, &headers, &input.device_id).await?;
    let mut tx = app.db.pool().begin().await.map_err(storage)?;
    let (offer, stored, own) = load(
        &mut tx,
        &app,
        &hash,
        &user,
        &input.device_id,
        (&id, &input.digest),
        (false, true),
    )
    .await?;
    if !matches!(stored.as_str(), "ready" | "permitted") {
        return Err(missing());
    }
    original_scope(&mut tx, &offer).await?;
    sqlx::query("UPDATE direct_v3_history_transfers SET state='permitted' WHERE id=$1")
        .bind(&id)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
    let view = result(&mut tx, &offer, "permitted", &own).await?;
    tx.commit().await.map_err(storage)?;
    Ok(Json(view))
}
