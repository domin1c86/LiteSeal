use super::*;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

const MAX_BODY: usize = 512 * 1024;
const MAX_PENDING: i64 = 1000;
const MAX_PENDING_BYTES: i64 = 10 * 1024 * 1024;
const MAX_RETAINED_BATCHES: i64 = 10_000;

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/groups/:group_id/messages", get(pending).post(send))
        .route("/groups/:group_id/messages/ack", post(ack))
        .route(
            "/groups/:group_id/messages/:message_id/cancel",
            post(cancel),
        )
        .route(
            "/groups/:group_id/messages/:message_id/receipt",
            get(receipt),
        )
        .layer(DefaultBodyLimit::max(MAX_BODY))
}

/// Canonical recipient order makes retransmission independent of array order.
fn prepare(id: &str, envelopes: &mut [GroupEnvelope]) -> Result<Vec<u8>, Failure> {
    if !(1..MAX_GROUP_MEMBERS).contains(&envelopes.len()) {
        return Err(bad());
    }
    for envelope in envelopes.iter() {
        group_id(&envelope.message_id)?;
        if envelope.group_id != id {
            return Err(bad());
        }
    }
    envelopes.sort_by(|left, right| left.recipient_device_id.cmp(&right.recipient_device_id));
    let bytes = serde_json::to_vec(envelopes).map_err(|_| bad())?;
    if bytes.len() > MAX_BODY {
        return Err(bad());
    }
    let mut hash = Sha256::new();
    hash.update(b"LiteSeal/group-batch/v1\0");
    hash.update(bytes);
    Ok(hash.finalize().to_vec())
}
fn timely(sent_at: i64, now: i64) -> bool {
    sent_at >= 0 && sent_at.abs_diff(now) <= 60_000
}
fn fits_quota(count: i64, bytes: i64, extra: usize) -> bool {
    count < MAX_PENDING
        && bytes
            .checked_add(extra as i64)
            .is_some_and(|total| total <= MAX_PENDING_BYTES)
}
async fn receipt_in(
    tx: &mut Transaction<'_, Postgres>,
    group: &str,
    message: &str,
) -> Result<Json<GroupMessageReceipt>, Failure> {
    let rows = sqlx::query("SELECT recipient_user_id,recipient_device_id,recipient_join_epoch,status FROM group_message_receipts WHERE group_id=$1 AND message_id=$2 ORDER BY recipient_device_id")
        .bind(group).bind(message).fetch_all(&mut **tx).await.map_err(unavailable)?;
    let recipients = rows
        .into_iter()
        .map(|row| GroupDeliveryStatus {
            recipient_user_id: row.get("recipient_user_id"),
            recipient_device_id: row.get("recipient_device_id"),
            recipient_join_epoch: row.get::<i64, _>("recipient_join_epoch") as u64,
            status: row.get("status"),
        })
        .collect();
    Ok(Json(GroupMessageReceipt {
        group_id: group.into(),
        message_id: message.into(),
        recipients,
    }))
}
async fn stored_batch(
    tx: &mut Transaction<'_, Postgres>,
    group: &str,
    message: &str,
) -> Result<Option<sqlx::postgres::PgRow>, Failure> {
    sqlx::query("SELECT sender_user_id,sender_device_id,batch_hash FROM group_message_batches WHERE group_id=$1 AND message_id=$2")
        .bind(group).bind(message).fetch_optional(&mut **tx).await.map_err(unavailable)
}
async fn current_join(
    tx: &mut Transaction<'_, Postgres>,
    group: &str,
    actor: &GroupIdentity,
) -> Result<i64, Failure> {
    sqlx::query_scalar("SELECT m.joined_epoch FROM group_memberships m JOIN private_groups g ON g.id=m.group_id WHERE m.group_id=$1 AND m.user_id=$2 AND m.device_id=$3 AND m.removed_epoch IS NULL AND g.closed=false")
        .bind(group).bind(&actor.user_id).bind(&actor.device_id).fetch_optional(&mut **tx).await.map_err(unavailable)?.ok_or_else(missing)
}
async fn sending_policy(
    tx: &mut Transaction<'_, Postgres>,
    group: &GroupState,
    sender: &str,
) -> Result<(), Failure> {
    let mut users: Vec<_> = group
        .members()
        .iter()
        .map(|member| member.identity.user_id.clone())
        .collect();
    users.sort();
    // Acquire the whole set once in a stable order across all groups.
    for user in &users {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2))")
            .bind(user)
            .execute(&mut **tx)
            .await
            .map_err(unavailable)?;
    }
    users.retain(|user| user != sender);
    let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM contact_policy WHERE ((user_id=$1 AND peer_id=ANY($2)) OR (peer_id=$1 AND user_id=ANY($2))) AND status IN ('blocked','rejected'))")
        .bind(sender).bind(&users).fetch_one(&mut **tx).await.map_err(unavailable)?;
    if blocked {
        return Err(conflict());
    }
    Ok(())
}
async fn send(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(mut request): Json<GroupSendRequest>,
) -> Result<Json<GroupMessageReceipt>, Failure> {
    let user = crate::message_operations::authorize(&state, &headers, &request.device_id).await?;
    group_id(&id)?;
    let digest = prepare(&id, &mut request.envelopes)?;
    let first = &request.envelopes[0];
    if first.sender_user_id != user || first.sender_device_id != request.device_id {
        return Err(conflict());
    }
    if !state
        .db
        .hit_rate_limit(&format!("group-messages:{user}"), 120, 60)
        .await
        .map_err(unavailable)?
    {
        return Err((StatusCode::TOO_MANY_REQUESTS, "群消息过于频繁".into()));
    }
    let mut tx = state.db.pool().begin().await.map_err(unavailable)?;
    lock_group(&mut tx, &id).await?;
    let actor = authorize_tx(&mut tx, &headers, &request.device_id).await?;
    if let Some(stored) = stored_batch(&mut tx, &id, &first.message_id).await? {
        if stored.get::<String, _>("sender_user_id") != actor.user_id
            || stored.get::<String, _>("sender_device_id") != actor.device_id
            || stored.get::<Vec<u8>, _>("batch_hash") != digest
        {
            return Err(conflict());
        }
        return receipt_in(&mut tx, &id, &first.message_id).await;
    }
    let meta = metadata(&mut tx, &id, true).await?;
    let cancelled:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM group_message_cancellations WHERE group_id=$1 AND message_id=$2 AND sender_device_id=$3)")
        .bind(&id).bind(&first.message_id).bind(&actor.device_id).fetch_one(&mut *tx).await.map_err(unavailable)?;
    if cancelled {
        return Err(conflict());
    }
    let group = replay(&mut tx, &id, &meta).await?;
    if group
        .member(&user)
        .is_none_or(|member| member.identity != actor)
    {
        return Err(conflict());
    }
    validate_batch(&group, &request.envelopes).map_err(|_| conflict())?;
    if !timely(first.sent_at, timestamp()) {
        return Err(conflict());
    }
    let mut members: Vec<_> = group.members().iter().collect();
    members.sort_by(|a, b| a.identity.device_id.cmp(&b.identity.device_id));
    for member in members {
        bind_device(&mut tx, &member.identity).await?;
    }
    sending_policy(&mut tx, &group, &user).await?;
    let retained: i64 =
        sqlx::query_scalar("SELECT (SELECT COUNT(*) FROM group_message_batches WHERE group_id=$1)+(SELECT COUNT(*) FROM group_message_cancellations WHERE group_id=$1)")
            .bind(&id)
            .fetch_one(&mut *tx)
            .await
            .map_err(unavailable)?;
    if retained >= MAX_RETAINED_BATCHES {
        return Err((
            StatusCode::INSUFFICIENT_STORAGE,
            "群消息保留记录已达试验上限".into(),
        ));
    }
    let mut bodies = Vec::new();
    for envelope in &request.envelopes {
        let previous: Option<String> = sqlx::query_scalar("SELECT chain_head FROM group_message_receipts WHERE group_id=$1 AND sender_device_id=$2 AND sender_join_epoch=$3 AND recipient_device_id=$4 AND recipient_join_epoch=$5 ORDER BY sender_seq DESC LIMIT 1")
            .bind(&id).bind(&envelope.sender_device_id).bind(epoch(envelope.sender_join_epoch)?).bind(&envelope.recipient_device_id).bind(epoch(envelope.recipient_join_epoch)?).fetch_optional(&mut *tx).await.map_err(unavailable)?;
        let head: Option<GroupChainHead> = previous
            .map(|body| serde_json::from_str(&body).map_err(|_| corrupt()))
            .transpose()?;
        validate_chain_head(envelope, head.as_ref()).map_err(|_| conflict())?;
        let body = serde_json::to_string(envelope).map_err(|_| bad())?;
        // All batches lock recipients in the same device order. ACK/removal
        // only decrease usage, so they need no extra quota lock.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,5))")
            .bind(&envelope.recipient_device_id)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        let usage = sqlx::query("SELECT COUNT(*) AS count,COALESCE(SUM(octet_length(p.body)),0)::bigint AS bytes FROM group_message_payloads p WHERE p.recipient_device_id=$1")
            .bind(&envelope.recipient_device_id).fetch_one(&mut *tx).await.map_err(unavailable)?;
        if !fits_quota(usage.get("count"), usage.get("bytes"), body.len()) {
            return Err((
                StatusCode::INSUFFICIENT_STORAGE,
                "收件设备待收群消息已达上限".into(),
            ));
        }
        bodies.push(body);
    }
    sqlx::query("INSERT INTO group_message_batches(group_id,message_id,sender_user_id,sender_device_id,sender_join_epoch,epoch,batch_hash) VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind(&id).bind(&first.message_id).bind(&user).bind(&actor.device_id).bind(epoch(first.sender_join_epoch)?).bind(epoch(first.epoch)?).bind(digest).execute(&mut *tx).await.map_err(unavailable)?;
    for (envelope, body) in request.envelopes.iter().zip(bodies) {
        let head = GroupChainHead::from_verified(envelope);
        sqlx::query("INSERT INTO group_message_receipts(group_id,message_id,sender_device_id,sender_join_epoch,recipient_user_id,recipient_device_id,recipient_join_epoch,sender_seq,chain_head,signature,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'pending')")
            .bind(&id).bind(&envelope.message_id).bind(&actor.device_id).bind(epoch(envelope.sender_join_epoch)?).bind(&envelope.recipient_user_id).bind(&envelope.recipient_device_id).bind(epoch(envelope.recipient_join_epoch)?).bind(envelope.sender_seq).bind(serde_json::to_string(&head).map_err(|_|bad())?).bind(&envelope.signature).execute(&mut *tx).await.map_err(unavailable)?;
        sqlx::query("INSERT INTO group_message_payloads(group_id,message_id,recipient_device_id,body) VALUES($1,$2,$3,$4)")
            .bind(&id).bind(&envelope.message_id).bind(&envelope.recipient_device_id).bind(body).execute(&mut *tx).await.map_err(unavailable)?;
    }
    let result = receipt_in(&mut tx, &id, &first.message_id).await?;
    tx.commit().await.map_err(unavailable)?;
    Ok(result)
}

#[derive(Deserialize)]
struct Access {
    device_id: String,
}
async fn pending(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(access): Query<Access>,
) -> Result<Json<GroupMessagePage>, Failure> {
    crate::message_operations::authorize(&state, &headers, &access.device_id).await?;
    group_id(&id)?;
    let mut tx = state.db.pool().begin().await.map_err(unavailable)?;
    lock_group(&mut tx, &id).await?;
    let actor = authorize_tx(&mut tx, &headers, &access.device_id).await?;
    let joined = current_join(&mut tx, &id, &actor).await?;
    let rows = sqlx::query("SELECT p.body FROM group_message_receipts r JOIN group_message_payloads p USING(group_id,message_id,recipient_device_id) JOIN group_message_batches b USING(group_id,message_id) WHERE r.group_id=$1 AND r.recipient_user_id=$2 AND r.recipient_device_id=$3 AND r.recipient_join_epoch=$4 AND r.status='pending' AND NOT EXISTS(SELECT 1 FROM contact_policy c WHERE ((c.user_id=$2 AND c.peer_id=b.sender_user_id) OR (c.peer_id=$2 AND c.user_id=b.sender_user_id)) AND c.status IN ('blocked','rejected')) ORDER BY r.delivery_seq LIMIT 101")
        .bind(&id).bind(&actor.user_id).bind(&actor.device_id).bind(joined).fetch_all(&mut *tx).await.map_err(unavailable)?;
    let mut envelopes = Vec::new();
    // Include the JSON page wrapper and commas, reserving the longer `false`.
    let mut bytes = serde_json::to_vec(&GroupMessagePage {
        envelopes: Vec::new(),
        has_more: false,
    })
    .map_err(|_| corrupt())?
    .len();
    let available = rows.len();
    for row in rows.into_iter().take(PAGE_SIZE) {
        let body: String = row.get("body");
        if body.len() + 64 > MAX_BODY {
            return Err(corrupt());
        }
        let extra = body.len() + usize::from(!envelopes.is_empty());
        if bytes + extra > MAX_BODY {
            break;
        }
        bytes += extra;
        envelopes.push(serde_json::from_str(&body).map_err(|_| corrupt())?);
    }
    let has_more = available > envelopes.len();
    tx.commit().await.map_err(unavailable)?;
    Ok(Json(GroupMessagePage {
        envelopes,
        has_more,
    }))
}
fn ack_shape(request: &GroupAckRequest) -> Result<(), Failure> {
    epoch(request.recipient_join_epoch)?;
    if !(1..=100).contains(&request.message_ids.len()) {
        return Err(bad());
    }
    let mut unique = HashSet::new();
    for id in &request.message_ids {
        group_id(id)?;
        if !unique.insert(id) {
            return Err(bad());
        }
    }
    Ok(())
}
async fn ack(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<GroupAckRequest>,
) -> Result<StatusCode, Failure> {
    crate::message_operations::authorize(&state, &headers, &request.device_id).await?;
    group_id(&id)?;
    ack_shape(&request)?;
    let mut tx = state.db.pool().begin().await.map_err(unavailable)?;
    lock_group(&mut tx, &id).await?;
    let actor = authorize_tx(&mut tx, &headers, &request.device_id).await?;
    let joined = current_join(&mut tx, &id, &actor).await?;
    if joined != epoch(request.recipient_join_epoch)? {
        return Err(conflict());
    }
    let rows = sqlx::query("SELECT status FROM group_message_receipts WHERE group_id=$1 AND recipient_user_id=$2 AND recipient_device_id=$3 AND recipient_join_epoch=$4 AND message_id=ANY($5) FOR UPDATE")
        .bind(&id).bind(&actor.user_id).bind(&actor.device_id).bind(joined).bind(&request.message_ids).fetch_all(&mut *tx).await.map_err(unavailable)?;
    if rows.len() != request.message_ids.len()
        || rows
            .iter()
            .any(|row| row.get::<String, _>("status") == "removed")
    {
        return Err(missing());
    }
    sqlx::query("UPDATE group_message_receipts SET status='delivered' WHERE group_id=$1 AND recipient_device_id=$2 AND recipient_join_epoch=$3 AND message_id=ANY($4) AND status='pending'")
        .bind(&id).bind(&actor.device_id).bind(joined).bind(&request.message_ids).execute(&mut *tx).await.map_err(unavailable)?;
    sqlx::query("DELETE FROM group_message_payloads WHERE group_id=$1 AND recipient_device_id=$2 AND message_id=ANY($3)")
        .bind(&id).bind(&actor.device_id).bind(&request.message_ids).execute(&mut *tx).await.map_err(unavailable)?;
    tx.commit().await.map_err(unavailable)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn receipt(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, message)): Path<(String, String)>,
    Query(access): Query<Access>,
) -> Result<Json<GroupMessageReceipt>, Failure> {
    crate::message_operations::authorize(&state, &headers, &access.device_id).await?;
    group_id(&id)?;
    group_id(&message)?;
    let mut tx = state.db.pool().begin().await.map_err(unavailable)?;
    lock_group(&mut tx, &id).await?;
    let actor = authorize_tx(&mut tx, &headers, &access.device_id).await?;
    let record = stored_batch(&mut tx, &id, &message)
        .await?
        .ok_or_else(missing)?;
    if record.get::<String, _>("sender_user_id") != actor.user_id
        || record.get::<String, _>("sender_device_id") != actor.device_id
    {
        return Err(missing());
    }
    let result = receipt_in(&mut tx, &id, &message).await?;
    tx.commit().await.map_err(unavailable)?;
    Ok(result)
}
async fn cancel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((group, message)): Path<(String, String)>,
    Json(request): Json<GroupCancelRequest>,
) -> Result<Json<GroupCancelResult>, Failure> {
    let user = admit(&state, &headers, &request.device_id).await?;
    group_id(&group)?;
    group_id(&message)?;
    let mut tx = state.db.pool().begin().await.map_err(unavailable)?;
    lock_group(&mut tx, &group).await?;
    let actor = authorize_tx(&mut tx, &headers, &request.device_id).await?;
    if let Some(batch) = stored_batch(&mut tx, &group, &message).await? {
        if batch.get::<String, _>("sender_user_id") != actor.user_id
            || batch.get::<String, _>("sender_device_id") != actor.device_id
        {
            return Err(missing());
        }
        let receipt = receipt_in(&mut tx, &group, &message).await?.0;
        tx.commit().await.map_err(unavailable)?;
        return Ok(Json(GroupCancelResult {
            group_id: group,
            message_id: message,
            cancelled: false,
            receipt: Some(receipt),
        }));
    }
    let member:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM group_memberships WHERE group_id=$1 AND user_id=$2 AND device_id=$3)")
        .bind(&group).bind(&user).bind(&actor.device_id).fetch_one(&mut *tx).await.map_err(unavailable)?;
    if !member {
        return Err(missing());
    }
    let meta = metadata(&mut tx, &group, true).await?;
    let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM group_message_cancellations WHERE group_id=$1 AND message_id=$2 AND sender_device_id=$3)")
        .bind(&group).bind(&message).bind(&actor.device_id).fetch_one(&mut *tx).await.map_err(unavailable)?;
    if !exists && !meta.closed {
        let retained:i64=sqlx::query_scalar("SELECT (SELECT COUNT(*) FROM group_message_batches WHERE group_id=$1)+(SELECT COUNT(*) FROM group_message_cancellations WHERE group_id=$1)")
            .bind(&group).fetch_one(&mut *tx).await.map_err(unavailable)?;
        if retained >= MAX_RETAINED_BATCHES {
            return Err((
                StatusCode::INSUFFICIENT_STORAGE,
                "群保留记录已达上限".into(),
            ));
        }
        sqlx::query("INSERT INTO group_message_cancellations(group_id,message_id,sender_user_id,sender_device_id) VALUES($1,$2,$3,$4)")
            .bind(&group).bind(&message).bind(&user).bind(&actor.device_id).execute(&mut *tx).await.map_err(unavailable)?;
    }
    tx.commit().await.map_err(unavailable)?;
    Ok(Json(GroupCancelResult {
        group_id: group,
        message_id: message,
        cancelled: true,
        receipt: None,
    }))
}

pub(super) const CANCEL_MIGRATION:&str="
CREATE TABLE group_message_cancellations(group_id TEXT NOT NULL REFERENCES private_groups(id),message_id TEXT NOT NULL,sender_user_id TEXT NOT NULL REFERENCES users(id),sender_device_id TEXT NOT NULL REFERENCES devices(id),PRIMARY KEY(group_id,message_id,sender_device_id));
CREATE INDEX group_message_cancellations_user ON group_message_cancellations(sender_user_id);
CREATE INDEX group_message_cancellations_device ON group_message_cancellations(sender_device_id);
";

pub(super) async fn expire_recipient(
    tx: &mut Transaction<'_, Postgres>,
    group: &str,
    device: &str,
    joined: u64,
) -> Result<(), Failure> {
    sqlx::query("DELETE FROM group_message_payloads p USING group_message_receipts r WHERE p.group_id=r.group_id AND p.message_id=r.message_id AND p.recipient_device_id=r.recipient_device_id AND r.group_id=$1 AND r.recipient_device_id=$2 AND r.recipient_join_epoch=$3 AND r.status='pending'")
        .bind(group).bind(device).bind(epoch(joined)?).execute(&mut **tx).await.map_err(unavailable)?;
    sqlx::query("UPDATE group_message_receipts SET status='removed' WHERE group_id=$1 AND recipient_device_id=$2 AND recipient_join_epoch=$3 AND status='pending'")
        .bind(group).bind(device).bind(epoch(joined)?).execute(&mut **tx).await.map_err(unavailable)?;
    Ok(())
}

pub(super) const MIGRATION: &str = "
CREATE TABLE group_message_batches(group_id TEXT NOT NULL REFERENCES private_groups(id),message_id TEXT NOT NULL,sender_user_id TEXT NOT NULL REFERENCES users(id),sender_device_id TEXT NOT NULL REFERENCES devices(id),sender_join_epoch BIGINT NOT NULL CHECK(sender_join_epoch BETWEEN 1 AND 1000),epoch BIGINT NOT NULL CHECK(epoch BETWEEN 1 AND 1000),batch_hash BYTEA NOT NULL CHECK(octet_length(batch_hash)=32),PRIMARY KEY(group_id,message_id));
CREATE INDEX group_message_batches_user ON group_message_batches(sender_user_id);
CREATE INDEX group_message_batches_device ON group_message_batches(sender_device_id);
CREATE TABLE group_message_receipts(group_id TEXT NOT NULL,message_id TEXT NOT NULL,sender_device_id TEXT NOT NULL REFERENCES devices(id),sender_join_epoch BIGINT NOT NULL CHECK(sender_join_epoch BETWEEN 1 AND 1000),recipient_user_id TEXT NOT NULL REFERENCES users(id),recipient_device_id TEXT NOT NULL REFERENCES devices(id),recipient_join_epoch BIGINT NOT NULL CHECK(recipient_join_epoch BETWEEN 1 AND 1000),sender_seq BIGINT NOT NULL CHECK(sender_seq>0),chain_head TEXT NOT NULL,signature BYTEA NOT NULL CHECK(octet_length(signature)=64),status TEXT NOT NULL CHECK(status IN ('pending','delivered','removed')),delivery_seq BIGSERIAL NOT NULL,PRIMARY KEY(group_id,message_id,recipient_device_id),FOREIGN KEY(group_id,message_id) REFERENCES group_message_batches(group_id,message_id),UNIQUE(group_id,sender_device_id,sender_join_epoch,recipient_device_id,recipient_join_epoch,sender_seq));
CREATE INDEX group_message_receipts_sender ON group_message_receipts(sender_device_id);
CREATE INDEX group_message_receipts_user ON group_message_receipts(recipient_user_id);
CREATE INDEX group_message_receipts_device ON group_message_receipts(recipient_device_id);
CREATE INDEX group_message_receipts_pending ON group_message_receipts(group_id,recipient_device_id,recipient_join_epoch,delivery_seq) WHERE status='pending';
CREATE TABLE group_message_payloads(group_id TEXT NOT NULL,message_id TEXT NOT NULL,recipient_device_id TEXT NOT NULL,body TEXT NOT NULL,PRIMARY KEY(group_id,message_id,recipient_device_id),FOREIGN KEY(group_id,message_id,recipient_device_id) REFERENCES group_message_receipts(group_id,message_id,recipient_device_id));
CREATE INDEX group_message_payloads_device ON group_message_payloads(recipient_device_id);
";

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn batch_digest_survives_recipient_reordering_but_binds_content() {
        let original:GroupEnvelope=serde_json::from_value(serde_json::json!({"version":1,"message_id":uuid::Uuid::new_v4().to_string(),"group_id":"group","epoch":1,"membership_hash":vec![1;32],"sender_user_id":"sender","sender_device_id":"sender-device","sender_join_epoch":1,"recipient_user_id":"bob","recipient_device_id":"bob-device","recipient_join_epoch":1,"sender_seq":1,"prev_hash":[],"sent_at":1,"ciphertext":vec![255;4136],"signature":vec![1;64]})).unwrap();
        let mut other = original.clone();
        other.recipient_device_id = "carol-device".into();
        other.recipient_user_id = "carol".into();
        let mut batch = vec![original.clone(), other.clone()];
        let digest = prepare("group", &mut batch).unwrap();
        let mut reverse = vec![other, original];
        assert_eq!(prepare("group", &mut reverse).unwrap(), digest);
        reverse[0].ciphertext[0] ^= 1;
        assert_ne!(prepare("group", &mut reverse).unwrap(), digest);
        assert!(prepare("other-group", &mut reverse).is_err());
        let mut too_many = vec![batch[0].clone(); 10];
        assert!(prepare("group", &mut too_many).is_err());
    }
    #[test]
    fn message_time_and_queue_boundaries_reject_overflows() {
        assert!(timely(100_000, 160_000));
        assert!(!timely(100_000, 160_001));
        assert!(!timely(i64::MAX, 0));
        assert!(!timely(-1, 0));
        assert!(fits_quota(999, MAX_PENDING_BYTES - 10, 10));
        assert!(!fits_quota(1000, 0, 1));
        assert!(!fits_quota(0, MAX_PENDING_BYTES, 1));
        assert!(!fits_quota(0, i64::MAX, 1));
    }
    #[test]
    fn ack_requests_are_bounded_and_cannot_repeat_ids() {
        let mut request = GroupAckRequest {
            device_id: "device".into(),
            recipient_join_epoch: 1,
            message_ids: vec![],
        };
        assert!(ack_shape(&request).is_err());
        let id = uuid::Uuid::new_v4().to_string();
        request.message_ids = vec![id.clone()];
        assert!(ack_shape(&request).is_ok());
        request.message_ids.push(id);
        assert!(ack_shape(&request).is_err());
        request.message_ids = (0..101).map(|_| uuid::Uuid::new_v4().to_string()).collect();
        assert!(ack_shape(&request).is_err());
    }
}
