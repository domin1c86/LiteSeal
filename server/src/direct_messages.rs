//! Independent v3 delivery queue. Control-plane grants alone are not sessions.
use crate::{auth::service, state::AppState, trusted_devices};
use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use liteseal_shared::{
    direct_message::{Ack, Batch, ChainHead, DirectError, Directory, Kind},
    direct_transport::{self as transport, Delivery, Page, Receipt, Result as Outcome},
    trusted_device::{DeviceEvent, DeviceState},
};
use serde::Deserialize;
use sqlx::{Postgres, Row, Transaction};
type Failure = (StatusCode, String);
type Tx<'a> = Transaction<'a, Postgres>;
pub(crate) mod history;
pub(crate) mod audio;
pub(crate) mod media;
pub(crate) mod operations;
pub const MIGRATION: &str = "
CREATE TABLE direct_v3_batches (
 id TEXT PRIMARY KEY, sender TEXT NOT NULL REFERENCES users(id), source TEXT NOT NULL,
 peer TEXT NOT NULL REFERENCES users(id), epoch BYTEA NOT NULL CHECK(octet_length(epoch)=32), sequence BIGINT NOT NULL CHECK(sequence>0),
 digest BYTEA NOT NULL CHECK(octet_length(digest)=32), state TEXT NOT NULL CHECK(state IN ('accepted','cancelled')),
 accepted_at BIGINT, wire BYTEA CHECK(octet_length(wire)<=262144), wire_size BIGINT NOT NULL CHECK(wire_size BETWEEN 1 AND 262144),
 CHECK((state='accepted' AND accepted_at IS NOT NULL AND accepted_at>0) OR (state='cancelled' AND accepted_at IS NULL AND wire IS NULL))
);
CREATE UNIQUE INDEX direct_v3_sequence ON direct_v3_batches(source,epoch,sequence) WHERE state='accepted';
CREATE INDEX direct_v3_sender ON direct_v3_batches(sender,source,id);
CREATE TABLE direct_v3_heads (
 source TEXT NOT NULL, epoch BYTEA NOT NULL CHECK(octet_length(epoch)=32), sequence BIGINT NOT NULL CHECK(sequence>0),
 digest BYTEA NOT NULL CHECK(octet_length(digest)=32), PRIMARY KEY(source,epoch)
);
CREATE TABLE direct_v3_deliveries (
 batch TEXT NOT NULL REFERENCES direct_v3_batches(id), account TEXT NOT NULL REFERENCES users(id), device TEXT NOT NULL,
 authority_hash BYTEA NOT NULL CHECK(octet_length(authority_hash)=32), delivery_order BIGSERIAL NOT NULL,
 state TEXT NOT NULL DEFAULT 'stored' CHECK(state IN ('stored','processed','rejected','ineligible')),
 ack BYTEA CHECK(octet_length(ack)<=8192), PRIMARY KEY(batch,device),
 CHECK((state IN ('processed','rejected') AND ack IS NOT NULL) OR (state IN ('stored','ineligible') AND ack IS NULL))
);
CREATE INDEX direct_v3_pending ON direct_v3_deliveries(device,delivery_order) WHERE state='stored';
";
fn storage(_: sqlx::Error) -> Failure {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "单聊 v3 存储暂不可用，请查询或重试原批次".into(),
    )
}
fn bad() -> Failure {
    (StatusCode::BAD_REQUEST, "无效单聊 v3 参数".into())
}
fn conflict() -> Failure {
    (
        StatusCode::CONFLICT,
        "原批次编号、目录或链阶段冲突；请查询原结果".into(),
    )
}
fn denied() -> Failure {
    (
        StatusCode::FORBIDDEN,
        "设备资格、签名或联系权限不匹配".into(),
    )
}
fn unauthorized() -> Failure {
    (StatusCode::UNAUTHORIZED, "需要有效设备会话".into())
}
fn codec(error: DirectError) -> Failure {
    match error {
        DirectError::Shape => bad(),
        DirectError::Chain | DirectError::Directory => conflict(),
        _ => denied(),
    }
}
fn origin(state: &AppState) -> Result<&str, Failure> {
    state
        .device_authorization_origin
        .as_deref()
        .ok_or((StatusCode::NOT_FOUND, "单聊 v3 未启用".into()))
}
fn uuid(value: &str) -> Result<(), Failure> {
    if uuid::Uuid::parse_str(value)
        .ok()
        .is_none_or(|id| id.to_string() != value)
    {
        Err(bad())
    } else {
        Ok(())
    }
}
fn token(headers: &HeaderMap) -> Result<String, Failure> {
    Ok(service::hash_token(
        headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .ok_or_else(unauthorized)?,
    ))
}
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/direct/v3/batches", post(publish))
        .route("/direct/v3/batches/:id", get(result))
        .route("/direct/v3/cancel", post(cancel))
        .route("/direct/v3/pending", get(pending))
        .route(
            "/direct/v3/ack",
            post(ack).layer(DefaultBodyLimit::max(
                liteseal_shared::direct_message::MAX_ACK_WIRE,
            )),
        )
        .layer(DefaultBodyLimit::max(
            liteseal_shared::direct_message::MAX_WIRE,
        ))
}
async fn admit(
    state: &AppState,
    headers: &HeaderMap,
    device: &str,
) -> Result<(String, String), Failure> {
    origin(state)?;
    uuid(device)?;
    let hash = token(headers)?;
    let user = state
        .db
        .validate_access_token(&hash, device)
        .await
        .map_err(storage)?
        .ok_or_else(unauthorized)?;
    if !state
        .db
        .hit_rate_limit(&format!("direct-v3:{device}"), 120, 60)
        .await
        .map_err(storage)?
    {
        return Err((StatusCode::TOO_MANY_REQUESTS, "单聊 v3 请求过于频繁".into()));
    }
    Ok((user, hash))
}
async fn lock_accounts(tx: &mut Tx<'_>, accounts: &[&str]) -> Result<(), Failure> {
    sqlx::query("SET LOCAL lock_timeout='5s'")
        .execute(&mut **tx)
        .await
        .map_err(storage)?;
    sqlx::query("SET LOCAL statement_timeout='10s'")
        .execute(&mut **tx)
        .await
        .map_err(storage)?;
    let mut accounts = accounts.to_vec();
    accounts.sort_unstable();
    accounts.dedup();
    for account in accounts {
        uuid(account)?;
        // Serialize account/directory mutations, while allowing the KEY SHARE
        // locks taken by legacy/group blob foreign keys under the quota lock.
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR NO KEY UPDATE")
            .bind(account)
            .fetch_optional(&mut **tx)
            .await
            .map_err(storage)?
            .ok_or_else(denied)?;
    }
    Ok(())
}
async fn session(
    tx: &mut Tx<'_>,
    hash: &str,
    user: &str,
    device: &str,
    current: &DeviceState,
) -> Result<[u8; 32], Failure> {
    let member = Directory::from_state(current)
        .members
        .into_iter()
        .find(|m| m.device.device_id == device)
        .ok_or_else(denied)?;
    let row=sqlx::query("SELECT d.public_key,d.ed25519_pk FROM sessions s JOIN devices d ON d.id=s.device_id WHERE s.access_token_hash=$1 AND s.user_id=$2 AND d.user_id=$2 AND s.device_id=$3 AND s.revoked=false AND s.expires_at>now() AND d.revoked=false FOR SHARE OF s,d")
        .bind(hash).bind(user).bind(device).fetch_optional(&mut **tx).await.map_err(storage)?.ok_or_else(unauthorized)?;
    if row.try_get::<Vec<u8>, _>("public_key").map_err(storage)? != member.device.encryption_key
        || row.try_get::<Vec<u8>, _>("ed25519_pk").map_err(storage)? != member.device.signing_key
    {
        return Err(denied());
    }
    Ok(member.authorization_hash)
}
async fn current(
    tx: &mut Tx<'_>,
    account: &str,
    origin: &str,
) -> Result<(DeviceState, Vec<DeviceEvent>), Failure> {
    let (state, events) = trusted_devices::directory(tx, account, origin).await?;
    let root = &state.anchor().root;
    let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM devices WHERE id=$1 AND user_id=$2 AND revoked=false AND public_key=$3 AND ed25519_pk=$4)")
        .bind(&root.device_id).bind(account).bind(root.encryption_key.as_slice()).bind(root.signing_key.as_slice()).fetch_one(&mut **tx).await.map_err(storage)?;
    if !valid {
        return Err(denied());
    }
    Ok((state, events))
}
fn prefix(
    state: &DeviceState,
    events: &[DeviceEvent],
    snapshot: &Directory,
) -> Result<DeviceState, Failure> {
    let mut old =
        DeviceState::pin(state.anchor().clone()).map_err(|_| storage(sqlx::Error::RowNotFound))?;
    for event in events
        .iter()
        .filter(|event| event.revision <= snapshot.revision)
    {
        old = old.apply(event).map_err(|_| denied())?;
    }
    if Directory::from_state(&old) != *snapshot {
        return Err(conflict());
    }
    Ok(old)
}
async fn historical(
    tx: &mut Tx<'_>,
    batch: &Batch,
    realm: &str,
) -> Result<(DeviceState, DeviceState), Failure> {
    let (s, se) = current(tx, &batch.header.sender, realm).await?;
    let (p, pe) = current(tx, &batch.header.peer, realm).await?;
    let s = prefix(&s, &se, &batch.header.sender_directory)?;
    let p = prefix(&p, &pe, &batch.header.peer_directory)?;
    batch.verify(&s, &p).map_err(codec)?;
    Ok((s, p))
}
async fn policy(tx: &mut Tx<'_>, sender: &str, peer: &str) -> Result<(), Failure> {
    policy_locks(tx, vec![sender.into(), peer.into()]).await?;
    let allowed:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM contact_policy WHERE user_id=$1 AND peer_id=$2 AND status='accepted') AND NOT EXISTS(SELECT 1 FROM contact_policy WHERE user_id=$2 AND peer_id=$1 AND status IN ('blocked','rejected'))")
        .bind(peer).bind(sender).fetch_one(&mut **tx).await.map_err(storage)?;
    if !allowed {
        return Err(denied());
    }
    Ok(())
}
async fn policy_locks(tx: &mut Tx<'_>, mut accounts: Vec<String>) -> Result<(), Failure> {
    accounts.sort_unstable();
    accounts.dedup();
    for account in accounts {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2))")
            .bind(account)
            .execute(&mut **tx)
            .await
            .map_err(storage)?;
    }
    Ok(())
}
async fn existing(
    tx: &mut Tx<'_>,
    id: &str,
    user: &str,
    device: &str,
    digest: [u8; 32],
) -> Result<Option<Outcome>, Failure> {
    let row = sqlx::query(
        "SELECT sender,source,digest,state,accepted_at FROM direct_v3_batches WHERE id=$1",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(storage)?;
    let Some(row) = row else { return Ok(None) };
    if row.try_get::<String, _>("sender").map_err(storage)? != user
        || row.try_get::<String, _>("source").map_err(storage)? != device
        || row.try_get::<Vec<u8>, _>("digest").map_err(storage)? != digest
    {
        return Err(conflict());
    }
    if row.try_get::<String, _>("state").map_err(storage)? == "cancelled" {
        return Ok(Some(Outcome::Cancelled {
            id: id.into(),
            digest,
        }));
    }
    let accepted_at = row.try_get("accepted_at").map_err(storage)?;
    let acknowledgements=sqlx::query_scalar::<_,Vec<u8>>("SELECT ack FROM direct_v3_deliveries WHERE batch=$1 AND ack IS NOT NULL ORDER BY account,device").bind(id).fetch_all(&mut **tx).await.map_err(storage)?.into_iter().map(|wire|Ack::from_wire(&wire).map_err(codec)).collect::<Result<Vec<_>,_>>()?;
    Ok(Some(Outcome::Accepted {
        receipt: Receipt {
            id: id.into(),
            digest,
            accepted_at,
        },
        acknowledgements,
    }))
}
async fn publish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(batch): Json<Batch>,
) -> Result<Json<Outcome>, Failure> {
    publish_batch(state, headers, batch, None).await
}
async fn publish_batch(
    state: AppState,
    headers: HeaderMap,
    batch: Batch,
    media: Option<liteseal_shared::direct_media::Submission>,
) -> Result<Json<Outcome>, Failure> {
    let wire = batch.to_wire().map_err(codec)?;
    uuid(&batch.header.id)?;
    let (user, hash) = admit(&state, &headers, &batch.header.sender_device).await?;
    if user != batch.header.sender || batch.header.origin != origin(&state)? {
        return Err(denied());
    }
    let digest = batch.digest().map_err(codec)?;
    let mut tx = state.db.pool().begin().await.map_err(storage)?;
    lock_accounts(&mut tx, &[&user, &batch.header.peer]).await?;
    let (sender, _) = current(&mut tx, &user, origin(&state)?).await?;
    let authority = session(&mut tx, &hash, &user, &batch.header.sender_device, &sender).await?;
    if let Some(result) = existing(
        &mut tx,
        &batch.header.id,
        &user,
        &batch.header.sender_device,
        digest,
    )
    .await?
    {
        if let Some(media) = &media {
            if matches!(result, Outcome::Accepted { .. }) {
                media::verify_existing(&mut tx, media).await?;
            }
        }
        tx.commit().await.map_err(storage)?;
        return Ok(Json(result));
    }
    let (peer, _) = current(&mut tx, &batch.header.peer, origin(&state)?).await?;
    batch.verify(&sender, &peer).map_err(codec)?;
    if !crate::device_activation::enabled(&mut tx, &user)
        .await
        .map_err(storage)?
        || !crate::device_activation::enabled(&mut tx, &batch.header.peer)
            .await
            .map_err(storage)?
    {
        return Err((
            StatusCode::UPGRADE_REQUIRED,
            "双方原设备需要明确启用 v3".into(),
        ));
    }
    if batch.header.kind != Kind::Text && media.is_none() {
        return Err((StatusCode::BAD_REQUEST, "v3 媒体投递尚未启用".into()));
    }
    let mut devices = batch
        .payloads
        .iter()
        .map(|p| p.device.as_str())
        .collect::<Vec<_>>();
    devices.sort_unstable();
    // Same order as legacy admission: queue quota locks precede policy locks.
    for device in &devices {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(device)
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
    }
    policy(&mut tx, &user, &batch.header.peer).await?;
    if let Some(media) = &media {
        media::validate_publication(&mut tx, media, authority).await?;
    }
    let epoch = batch.header.epoch().map_err(codec)?;
    let prior =
        sqlx::query("SELECT sequence,digest FROM direct_v3_heads WHERE source=$1 AND epoch=$2")
            .bind(&batch.header.sender_device)
            .bind(epoch.as_slice())
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage)?;
    let prior = prior
        .map(|r| {
            Ok::<_, Failure>(ChainHead {
                epoch,
                sequence: r.try_get("sequence").map_err(storage)?,
                digest: r
                    .try_get::<Vec<u8>, _>("digest")
                    .map_err(storage)?
                    .try_into()
                    .map_err(|_| denied())?,
            })
        })
        .transpose()?;
    batch.verify_next(prior.as_ref()).map_err(codec)?;
    for device in devices {
        let (count, bytes) = queue_usage(&mut tx, device).await?;
        if count >= 1000 || bytes.saturating_add(wire.len() as i64) > 10 * 1024 * 1024 {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                "设备待收配额已满；请保留原批次".into(),
            ));
        }
    }
    let accepted_at: i64 =
        sqlx::query_scalar("SELECT (EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT")
            .fetch_one(&mut *tx)
            .await
            .map_err(storage)?;
    sqlx::query("INSERT INTO direct_v3_batches(id,sender,source,peer,epoch,sequence,digest,state,accepted_at,wire,wire_size) VALUES($1,$2,$3,$4,$5,$6,$7,'accepted',$8,$9,$10)")
        .bind(&batch.header.id).bind(&user).bind(&batch.header.sender_device).bind(&batch.header.peer).bind(epoch.as_slice()).bind(batch.header.sequence).bind(digest.as_slice()).bind(accepted_at).bind(&wire).bind(wire.len() as i64).execute(&mut *tx).await.map_err(storage)?;
    for payload in &batch.payloads {
        let directory = if payload.account == user {
            &batch.header.sender_directory
        } else {
            &batch.header.peer_directory
        };
        let member = directory
            .members
            .iter()
            .find(|m| m.device.device_id == payload.device)
            .ok_or_else(denied)?;
        sqlx::query("INSERT INTO direct_v3_deliveries(batch,account,device,authority_hash) VALUES($1,$2,$3,$4)")
            .bind(&batch.header.id).bind(&payload.account).bind(&payload.device).bind(member.authorization_hash.as_slice()).execute(&mut *tx).await.map_err(storage)?;
    }
    sqlx::query("INSERT INTO direct_v3_heads(source,epoch,sequence,digest) VALUES($1,$2,$3,$4) ON CONFLICT(source,epoch) DO UPDATE SET sequence=excluded.sequence,digest=excluded.digest")
        .bind(&batch.header.sender_device).bind(epoch.as_slice()).bind(batch.header.sequence).bind(digest.as_slice()).execute(&mut *tx).await.map_err(storage)?;
    if let Some(media) = &media {
        media::commit_publication(&mut tx, media).await?;
    }
    tx.commit().await.map_err(storage)?;
    Ok(Json(Outcome::Accepted {
        receipt: Receipt {
            id: batch.header.id,
            digest,
            accepted_at,
        },
        acknowledgements: vec![],
    }))
}
pub(crate) async fn queue_usage(tx: &mut Tx<'_>, device: &str) -> Result<(i64, i64), Failure> {
    let row=sqlx::query("SELECT (SELECT COUNT(*) FROM offline_messages WHERE recipient_device_id=$1 AND acked=false)+(SELECT COUNT(*) FROM direct_v3_deliveries WHERE device=$1 AND state='stored') AS count, (SELECT COALESCE(SUM(octet_length(ciphertext)+octet_length(signature)),0)::BIGINT FROM offline_messages WHERE recipient_device_id=$1 AND acked=false)+(SELECT COALESCE(SUM(b.wire_size),0)::BIGINT FROM direct_v3_deliveries d JOIN direct_v3_batches b ON b.id=d.batch WHERE d.device=$1 AND d.state='stored') AS bytes")
        .bind(device).fetch_one(&mut **tx).await.map_err(storage)?;
    Ok((
        row.try_get("count").map_err(storage)?,
        row.try_get("bytes").map_err(storage)?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Lookup {
    device_id: String,
    digest: String,
}
async fn result(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(input): Query<Lookup>,
) -> Result<Json<Outcome>, Failure> {
    uuid(&id)?;
    let bytes = hex::decode(&input.digest).map_err(|_| bad())?;
    let digest: [u8; 32] = bytes.try_into().map_err(|_| bad())?;
    let (user, hash) = admit(&state, &headers, &input.device_id).await?;
    let mut tx = state.db.pool().begin().await.map_err(storage)?;
    lock_accounts(&mut tx, &[&user]).await?;
    let (current, _) = current(&mut tx, &user, origin(&state)?).await?;
    session(&mut tx, &hash, &user, &input.device_id, &current).await?;
    let result = existing(&mut tx, &id, &user, &input.device_id, digest)
        .await?
        .unwrap_or(Outcome::Unknown { id, digest });
    tx.commit().await.map_err(storage)?;
    Ok(Json(result))
}
async fn cancel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(batch): Json<Batch>,
) -> Result<Json<Outcome>, Failure> {
    let wire = batch.to_wire().map_err(codec)?;
    uuid(&batch.header.id)?;
    let (user, hash) = admit(&state, &headers, &batch.header.sender_device).await?;
    if user != batch.header.sender || batch.header.origin != origin(&state)? {
        return Err(denied());
    }
    let digest = batch.digest().map_err(codec)?;
    let mut tx = state.db.pool().begin().await.map_err(storage)?;
    lock_accounts(&mut tx, &[&user, &batch.header.peer]).await?;
    let (current, _) = current(&mut tx, &user, origin(&state)?).await?;
    session(&mut tx, &hash, &user, &batch.header.sender_device, &current).await?;
    if let Some(result) = existing(
        &mut tx,
        &batch.header.id,
        &user,
        &batch.header.sender_device,
        digest,
    )
    .await?
    {
        tx.commit().await.map_err(storage)?;
        return Ok(Json(result));
    }
    historical(&mut tx, &batch, origin(&state)?).await?;
    let cancelled: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM direct_v3_batches WHERE sender=$1 AND state='cancelled'",
    )
    .bind(&user)
    .fetch_one(&mut *tx)
    .await
    .map_err(storage)?;
    if cancelled >= 1000 {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "原批次取消记录已达上限".into(),
        ));
    }
    sqlx::query("INSERT INTO direct_v3_batches(id,sender,source,peer,epoch,sequence,digest,state,wire_size) VALUES($1,$2,$3,$4,$5,$6,$7,'cancelled',$8)")
        .bind(&batch.header.id).bind(user).bind(&batch.header.sender_device).bind(&batch.header.peer).bind(batch.header.epoch().map_err(codec)?.as_slice()).bind(batch.header.sequence).bind(digest.as_slice()).bind(wire.len() as i64).execute(&mut *tx).await.map_err(storage)?;
    tx.commit().await.map_err(storage)?;
    Ok(Json(Outcome::Cancelled {
        id: batch.header.id,
        digest,
    }))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    device_id: String,
    #[serde(default = "page_limit")]
    limit: usize,
}
fn page_limit() -> usize {
    100
}
async fn pending(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(input): Query<Pending>,
) -> Result<Json<Page>, Failure> {
    if input.limit == 0 || input.limit > transport::MAX_PAGE_ITEMS {
        return Err(bad());
    }
    let (user, hash) = admit(&state, &headers, &input.device_id).await?;
    let mut tx = state.db.pool().begin().await.map_err(storage)?;
    lock_accounts(&mut tx, &[&user]).await?;
    let (current, _) = current(&mut tx, &user, origin(&state)?).await?;
    let authority = session(&mut tx, &hash, &user, &input.device_id, &current).await?;
    // Publication needs this account row too, so this candidate set cannot
    // grow while policy snapshots are locked. Both sides' block changes use
    // the same advisory namespace; no queue or peer account lock follows it.
    let mut policies:Vec<String>=sqlx::query_scalar("SELECT DISTINCT b.sender FROM direct_v3_deliveries d JOIN direct_v3_batches b ON b.id=d.batch WHERE d.account=$1 AND d.device=$2 AND d.authority_hash=$3 AND d.state='stored'")
        .bind(&user).bind(&input.device_id).bind(authority.as_slice()).fetch_all(&mut *tx).await.map_err(storage)?;
    policies.push(user.clone());
    policy_locks(&mut tx, policies).await?;
    let rows=sqlx::query("SELECT b.id,b.wire,b.digest,b.accepted_at,d.delivery_order FROM direct_v3_deliveries d JOIN direct_v3_batches b ON b.id=d.batch WHERE d.account=$1 AND d.device=$2 AND d.authority_hash=$3 AND d.state='stored' AND (b.sender=$1 OR (EXISTS(SELECT 1 FROM contact_policy WHERE user_id=$1 AND peer_id=b.sender AND status='accepted') AND NOT EXISTS(SELECT 1 FROM contact_policy WHERE user_id=b.sender AND peer_id=$1 AND status IN ('blocked','rejected')))) ORDER BY d.delivery_order LIMIT $4")
        .bind(&user).bind(&input.device_id).bind(authority.as_slice()).bind((input.limit+1) as i64).fetch_all(&mut *tx).await.map_err(storage)?;
    let total = rows.len();
    let mut page = Page {
        items: vec![],
        has_more: false,
    };
    for row in rows.into_iter().take(input.limit) {
        let wire: Vec<u8> = row.try_get("wire").map_err(storage)?;
        let batch = Batch::from_wire(&wire).map_err(codec)?;
        let digest: Vec<u8> = row.try_get("digest").map_err(storage)?;
        let digest: [u8; 32] = digest.try_into().map_err(|_| denied())?;
        if digest != batch.digest().map_err(codec)? {
            return Err(denied());
        }
        page.items.push(Delivery {
            order: row.try_get("delivery_order").map_err(storage)?,
            batch,
            receipt: Receipt {
                id: row.try_get("id").map_err(storage)?,
                digest,
                accepted_at: row.try_get("accepted_at").map_err(storage)?,
            },
        });
        if serde_json::to_vec(&page).map_err(|_| bad())?.len() > transport::MAX_PAGE_BYTES {
            page.items.pop();
            break;
        }
    }
    page.has_more = total > page.items.len();
    tx.commit().await.map_err(storage)?;
    Ok(Json(page))
}
async fn ack(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(ack): Json<Ack>,
) -> Result<StatusCode, Failure> {
    let ack_wire = ack.to_wire().map_err(codec)?;
    uuid(&ack.id)?;
    let (user, hash) = admit(&state, &headers, &ack.device).await?;
    if user != ack.account || ack.origin != origin(&state)? {
        return Err(denied());
    }
    let mut tx = state.db.pool().begin().await.map_err(storage)?;
    lock_accounts(&mut tx, &[&user]).await?;
    let (current, _) = current(&mut tx, &user, origin(&state)?).await?;
    if session(&mut tx, &hash, &user, &ack.device, &current).await? != ack.authorization_hash {
        return Err(denied());
    }
    // Recipient qualification is locked before this batch row; no peer account
    // is acquired here, avoiding cross-account ACK/publication deadlocks.
    let row=sqlx::query("SELECT b.wire,b.digest,d.authority_hash,d.state,d.ack FROM direct_v3_batches b JOIN direct_v3_deliveries d ON d.batch=b.id WHERE b.id=$1 AND d.account=$2 AND d.device=$3 FOR UPDATE OF b,d")
        .bind(&ack.id).bind(&user).bind(&ack.device).fetch_optional(&mut *tx).await.map_err(storage)?.ok_or_else(denied)?;
    if row.try_get::<Vec<u8>, _>("digest").map_err(storage)? != ack.batch
        || row
            .try_get::<Vec<u8>, _>("authority_hash")
            .map_err(storage)?
            != ack.authorization_hash
    {
        return Err(denied());
    }
    if let Some(old) = row.try_get::<Option<Vec<u8>>, _>("ack").map_err(storage)? {
        if old != ack_wire {
            return Err(conflict());
        }
        tx.commit().await.map_err(storage)?;
        return Ok(StatusCode::NO_CONTENT);
    }
    if row.try_get::<String, _>("state").map_err(storage)? != "stored" {
        return Err(denied());
    }
    let wire: Vec<u8> = row.try_get("wire").map_err(storage)?;
    let batch = Batch::from_wire(&wire).map_err(codec)?;
    // Rebuild historical prefixes directly; root accounts can be changing now,
    // but signed append-only events up to these exact revisions never change.
    let sender = accepted_prefix(
        &mut tx,
        &batch.header.origin,
        &batch.header.sender,
        &batch.header.sender_directory,
    )
    .await?;
    let peer = accepted_prefix(
        &mut tx,
        &batch.header.origin,
        &batch.header.peer,
        &batch.header.peer_directory,
    )
    .await?;
    ack.verify(&batch, &sender, &peer).map_err(codec)?;
    let outcome = match ack.outcome {
        liteseal_shared::protocol::AckOutcome::Processed => "processed",
        liteseal_shared::protocol::AckOutcome::Rejected => "rejected",
    };
    sqlx::query("UPDATE direct_v3_deliveries SET state=$4,ack=$5 WHERE batch=$1 AND account=$2 AND device=$3")
        .bind(&ack.id).bind(&user).bind(&ack.device).bind(outcome).bind(ack_wire).execute(&mut *tx).await.map_err(storage)?;
    release(&mut tx, &ack.id).await?;
    tx.commit().await.map_err(storage)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn release(tx: &mut Tx<'_>, id: &str) -> Result<(), Failure> {
    sqlx::query("UPDATE direct_v3_batches SET wire=NULL WHERE id=$1 AND NOT EXISTS(SELECT 1 FROM direct_v3_deliveries WHERE batch=$1 AND state='stored')").bind(id).execute(&mut **tx).await.map_err(storage)?;
    Ok(())
}
async fn accepted_prefix(
    tx: &mut Tx<'_>,
    realm: &str,
    account: &str,
    snapshot: &Directory,
) -> Result<DeviceState, Failure> {
    let bytes: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT anchor FROM device_authorization_roots WHERE user_id=$1")
            .bind(account)
            .fetch_optional(&mut **tx)
            .await
            .map_err(storage)?;
    let anchor = if let Some(bytes) = bytes {
        serde_json::from_slice(&bytes).map_err(|_| denied())?
    } else {
        // This snapshot is from a batch already accepted by this server, never
        // from an untrusted ACK or a newly supplied client root.
        let root = snapshot
            .members
            .iter()
            .find(|m| m.authorization_hash == snapshot.anchor_hash)
            .ok_or_else(denied)?;
        liteseal_shared::trusted_device::Anchor {
            origin: realm.into(),
            account: account.into(),
            root: root.device.clone(),
        }
    };
    let old = DeviceState::pin(anchor).map_err(|_| denied())?;
    let bytes:Vec<Vec<u8>>=sqlx::query_scalar("SELECT payload FROM device_authorization_events WHERE user_id=$1 AND revision<=$2 ORDER BY revision").bind(account).bind(snapshot.revision as i64).fetch_all(&mut **tx).await.map_err(storage)?;
    let events = bytes
        .iter()
        .map(|b| serde_json::from_slice(b).map_err(|_| denied()))
        .collect::<Result<Vec<_>, _>>()?;
    prefix(&old, &events, snapshot)
}
pub(crate) async fn revoke_target(
    tx: &mut Tx<'_>,
    account: &str,
    device: &str,
) -> Result<(), Failure> {
    let ids:Vec<String>=sqlx::query_scalar("SELECT batch FROM direct_v3_deliveries WHERE account=$1 AND device=$2 AND state='stored' ORDER BY batch").bind(account).bind(device).fetch_all(&mut **tx).await.map_err(storage)?;
    for id in ids {
        sqlx::query("SELECT id FROM direct_v3_batches WHERE id=$1 FOR UPDATE")
            .bind(&id)
            .fetch_one(&mut **tx)
            .await
            .map_err(storage)?;
        sqlx::query("UPDATE direct_v3_deliveries SET state='ineligible' WHERE batch=$1 AND account=$2 AND device=$3 AND state='stored'").bind(&id).bind(account).bind(device).execute(&mut **tx).await.map_err(storage)?;
        release(tx, &id).await?;
    }
    Ok(())
}
