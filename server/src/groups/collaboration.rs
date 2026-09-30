use super::*;
use liteseal_shared::collaboration as c;
use sqlx::Row;

pub const MIGRATION:&str="
CREATE TABLE group_collab_events (
 seq BIGSERIAL UNIQUE NOT NULL, group_id TEXT NOT NULL REFERENCES private_groups(id), id TEXT NOT NULL,
 object_id TEXT NOT NULL, revision BIGINT NOT NULL, kind TEXT NOT NULL, header TEXT NOT NULL,
 PRIMARY KEY(group_id,id), UNIQUE(group_id,object_id,revision)
);
CREATE TABLE group_collab_objects (
 group_id TEXT NOT NULL REFERENCES private_groups(id), id TEXT NOT NULL, body TEXT NOT NULL,
 PRIMARY KEY(group_id,id)
);
CREATE TABLE group_collab_deliveries (
 group_id TEXT NOT NULL, event_id TEXT NOT NULL, device_id TEXT NOT NULL, joined BIGINT NOT NULL,
 ciphertext BYTEA, acked BOOLEAN NOT NULL DEFAULT FALSE,
 PRIMARY KEY(group_id,event_id,device_id,joined),
 FOREIGN KEY(group_id,event_id) REFERENCES group_collab_events(group_id,id)
);
CREATE INDEX group_collab_pending ON group_collab_deliveries(device_id,joined) WHERE acked=false;
";
pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/groups/:group_id/collaboration", get(list).post(submit))
        .route("/groups/:group_id/collaboration/ack", post(ack))
        .route(
            "/groups/:group_id/collaboration/capabilities",
            get(capabilities),
        )
        .layer(DefaultBodyLimit::max(512 * 1024))
}
#[derive(Deserialize)]
struct Access {
    device_id: String,
    #[serde(default)]
    after: i64,
}
async fn member(
    tx: &mut Transaction<'_, Postgres>,
    headers: &HeaderMap,
    id: &str,
    device: &str,
) -> Result<(GroupIdentity, GroupState), Failure> {
    lock_group(tx, id).await?;
    let actor = authorize_tx(tx, headers, device).await?;
    let meta = metadata(tx, id, false).await?;
    let group = replay(tx, id, &meta).await?;
    if group.closed()
        || group
            .member(&actor.user_id)
            .is_none_or(|m| m.identity != actor)
    {
        return Err(missing());
    }
    Ok((actor, group))
}
async fn capabilities(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(access): Query<Access>,
) -> Result<Json<u8>, Failure> {
    let mut tx = state.db.pool().begin().await.map_err(unavailable)?;
    member(&mut tx, &headers, &id, &access.device_id).await?;
    Ok(Json(1))
}
async fn submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<c::Submission>,
) -> Result<Json<i64>, Failure> {
    group_id(&id)?;
    group_id(&request.event.id)?;
    group_id(&request.event.object)?;
    let event = &request.event;
    admit(&state, &headers, &event.actor.device).await?;
    c::validate_boxes(&request).map_err(|_| bad())?;
    if event.group != id {
        return Err(bad());
    }
    let header = serde_json::to_string(event).map_err(|_| bad())?;
    let mut tx = state.db.pool().begin().await.map_err(unavailable)?;
    lock_group(&mut tx, &id).await?;
    let actor = authorize_tx(&mut tx, &headers, &event.actor.device).await?;
    if actor.user_id != event.actor.user {
        return Err(conflict());
    }
    if let Some(row) =
        sqlx::query("SELECT seq,header FROM group_collab_events WHERE group_id=$1 AND id=$2")
            .bind(&id)
            .bind(&event.id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(unavailable)?
    {
        if row.get::<String, _>("header") != header {
            return Err(conflict());
        }
        return Ok(Json(row.get("seq")));
    }
    let collision:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM group_message_batches WHERE group_id=$1 AND message_id=$2) OR EXISTS(SELECT 1 FROM group_message_cancellations WHERE group_id=$1 AND message_id=$2) OR EXISTS(SELECT 1 FROM group_extension_events WHERE group_id=$1 AND id=$2) OR EXISTS(SELECT 1 FROM group_extension_cancellations WHERE group_id=$1 AND id=$2)").bind(&id).bind(&event.id).fetch_one(&mut *tx).await.map_err(unavailable)?;
    if collision {
        return Err(conflict());
    }
    let meta = metadata(&mut tx, &id, true).await?;
    let group = replay(&mut tx, &id, &meta).await?;
    if group
        .member(&actor.user_id)
        .is_none_or(|m| m.identity != actor)
    {
        return Err(conflict());
    }
    if event.at.abs_diff(timestamp()) > 60_000 {
        return Err(conflict());
    }
    let previous: Option<String> =
        sqlx::query_scalar("SELECT body FROM group_collab_objects WHERE group_id=$1 AND id=$2")
            .bind(&id)
            .bind(&event.object)
            .fetch_optional(&mut *tx)
            .await
            .map_err(unavailable)?;
    let previous: Option<c::Object> = previous
        .map(|s| serde_json::from_str(&s).map_err(|_| corrupt()))
        .transpose()?;
    let next = c::transition(previous.as_ref(), &group, event).map_err(|_| conflict())?;
    if let c::Action::Pin { .. } = &event.action {
        let expected = if let Some(target) = &request.pin_target {
            group_id(target)?;
            let rows=sqlx::query("SELECT b.sender_user_id,b.sender_device_id,r.sender_join_epoch,r.recipient_user_id,r.recipient_device_id,r.recipient_join_epoch FROM group_message_batches b JOIN group_message_receipts r USING(group_id,message_id) WHERE b.group_id=$1 AND b.message_id=$2")
    .bind(&id).bind(target).fetch_all(&mut *tx).await.map_err(unavailable)?;
            if rows.is_empty() {
                let body: Option<String> = sqlx::query_scalar(
                    "SELECT body FROM group_collab_objects WHERE group_id=$1 AND id=$2",
                )
                .bind(&id)
                .bind(target)
                .fetch_optional(&mut *tx)
                .await
                .map_err(unavailable)?;
                let object: c::Object =
                    serde_json::from_str(&body.ok_or_else(conflict)?).map_err(|_| corrupt())?;
                if !matches!(object.action, c::Action::Mention | c::Action::Poll { .. }) {
                    return Err(conflict());
                }
                object
                    .audience
                    .into_iter()
                    .filter(|m| c::members(&group).contains(m))
                    .collect()
            } else {
                c::members(&group)
                    .into_iter()
                    .filter(|m| {
                        rows.iter().any(|r| {
                            (r.get::<String, _>("sender_user_id") == m.user
                                && r.get::<String, _>("sender_device_id") == m.device
                                && r.get::<i64, _>("sender_join_epoch") == m.joined as i64)
                                || (r.get::<String, _>("recipient_user_id") == m.user
                                    && r.get::<String, _>("recipient_device_id") == m.device
                                    && r.get::<i64, _>("recipient_join_epoch") == m.joined as i64)
                        })
                    })
                    .collect::<Vec<_>>()
            }
        } else {
            c::members(&group)
        };
        if expected != event.audience {
            return Err(conflict());
        }
    }
    for recipient in &event.audience {
        let m = group.member(&recipient.user).ok_or_else(conflict)?;
        bind_device(&mut tx, &m.identity).await?;
    }
    messages::sending_policy(&mut tx, &group, &actor.user_id).await?;
    let retained: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM group_collab_events WHERE group_id=$1")
            .bind(&id)
            .fetch_one(&mut *tx)
            .await
            .map_err(unavailable)?;
    if retained >= 10000 {
        return Err((
            StatusCode::INSUFFICIENT_STORAGE,
            "群协作记录已达上限".into(),
        ));
    }
    let mut devices: Vec<_> = event.audience.iter().map(|m| &m.device).collect();
    devices.sort();
    for device in devices {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,7))")
            .bind(device)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        let (count,bytes):(i64,i64)=sqlx::query_as("SELECT COUNT(*),COALESCE(SUM(octet_length(ciphertext)),0)::BIGINT FROM group_collab_deliveries WHERE device_id=$1 AND acked=false").bind(device).fetch_one(&mut *tx).await.map_err(unavailable)?;
        if count >= 1000 || bytes + 8192 > 10 * 1024 * 1024 {
            return Err((
                StatusCode::INSUFFICIENT_STORAGE,
                "群协作待收队列已满".into(),
            ));
        }
    }
    let kind = if matches!(event.action, c::Action::Pin { .. }) {
        "pin"
    } else {
        "content"
    };
    let seq:i64=sqlx::query_scalar("INSERT INTO group_collab_events(group_id,id,object_id,revision,kind,header) VALUES($1,$2,$3,$4,$5,$6) RETURNING seq")
 .bind(&id).bind(&event.id).bind(&event.object).bind(event.revision as i64).bind(kind).bind(header).fetch_one(&mut *tx).await.map_err(unavailable)?;
    sqlx::query("INSERT INTO group_collab_objects(group_id,id,body) VALUES($1,$2,$3) ON CONFLICT(group_id,id) DO UPDATE SET body=excluded.body")
 .bind(&id).bind(&event.object).bind(serde_json::to_string(&next).map_err(|_|bad())?).execute(&mut *tx).await.map_err(unavailable)?;
    for recipient in &event.audience {
        let cipher = request
            .boxes
            .iter()
            .find(|b| &b.member == recipient)
            .map(|b| &b.ciphertext);
        sqlx::query("INSERT INTO group_collab_deliveries(group_id,event_id,device_id,joined,ciphertext) VALUES($1,$2,$3,$4,$5)")
 .bind(&id).bind(&event.id).bind(&recipient.device).bind(recipient.joined as i64).bind(cipher).execute(&mut *tx).await.map_err(unavailable)?;
    }
    tx.commit().await.map_err(unavailable)?;
    Ok(Json(seq))
}
async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(access): Query<Access>,
) -> Result<Json<c::Page>, Failure> {
    if access.after < 0 {
        return Err(bad());
    }
    let mut tx = state.db.pool().begin().await.map_err(unavailable)?;
    let (actor, group) = member(&mut tx, &headers, &id, &access.device_id).await?;
    let joined = group
        .member(&actor.user_id)
        .ok_or_else(missing)?
        .joined_epoch as i64;
    let rows=sqlx::query("SELECT e.seq,e.header,d.ciphertext FROM group_collab_events e LEFT JOIN group_collab_deliveries d ON d.group_id=e.group_id AND d.event_id=e.id AND d.device_id=$2 AND d.joined=$3 WHERE e.group_id=$1 AND e.seq>$4 AND (e.kind='pin' OR d.device_id IS NOT NULL) ORDER BY e.seq LIMIT 101")
 .bind(&id).bind(&actor.device_id).bind(joined).bind(access.after).fetch_all(&mut *tx).await.map_err(unavailable)?;
    let more = rows.len() > 100;
    let mut items = Vec::new();
    let mut cursor = access.after;
    for row in rows.into_iter().take(100) {
        cursor = row.get("seq");
        let event: c::Event =
            serde_json::from_str(&row.get::<String, _>("header")).map_err(|_| corrupt())?;
        if !policy_read(&mut tx, &actor.user_id, &event.actor.user).await? {
            return Err(conflict());
        }
        items.push(c::Delivery {
            seq: cursor,
            event,
            ciphertext: row.get("ciphertext"),
        });
    }
    Ok(Json(c::Page {
        items,
        cursor,
        more,
    }))
}
#[derive(Deserialize)]
struct Ack {
    device_id: String,
    ids: Vec<String>,
}
async fn ack(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<Ack>,
) -> Result<StatusCode, Failure> {
    if request.ids.len() > 100 {
        return Err(bad());
    }
    let mut tx = state.db.pool().begin().await.map_err(unavailable)?;
    let (actor, group) = member(&mut tx, &headers, &id, &request.device_id).await?;
    let joined = group
        .member(&actor.user_id)
        .ok_or_else(missing)?
        .joined_epoch as i64;
    sqlx::query("UPDATE group_collab_deliveries SET acked=true WHERE group_id=$1 AND device_id=$2 AND joined=$3 AND event_id=ANY($4)").bind(&id).bind(&actor.device_id).bind(joined).bind(&request.ids).execute(&mut *tx).await.map_err(unavailable)?;
    tx.commit().await.map_err(unavailable)?;
    Ok(StatusCode::NO_CONTENT)
}
