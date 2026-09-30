use super::*;
use liteseal_shared::{collaboration as c, group_extension as e};
pub const MIGRATION:&str="
CREATE TABLE group_extension_events(seq BIGSERIAL UNIQUE NOT NULL,group_id TEXT NOT NULL REFERENCES private_groups(id),id TEXT NOT NULL,object_id TEXT NOT NULL,revision BIGINT NOT NULL,header TEXT NOT NULL,submission_hash BYTEA NOT NULL,PRIMARY KEY(group_id,id),UNIQUE(group_id,object_id,revision));
CREATE TABLE group_extension_objects(group_id TEXT NOT NULL REFERENCES private_groups(id),id TEXT NOT NULL,body TEXT NOT NULL,PRIMARY KEY(group_id,id));
CREATE TABLE group_extension_boxes(group_id TEXT NOT NULL,event_id TEXT NOT NULL,device_id TEXT NOT NULL,joined BIGINT NOT NULL,ciphertext BYTEA NOT NULL,PRIMARY KEY(group_id,event_id,device_id,joined),FOREIGN KEY(group_id,event_id) REFERENCES group_extension_events(group_id,id));
CREATE TABLE group_extension_cancellations(group_id TEXT NOT NULL REFERENCES private_groups(id),id TEXT NOT NULL,device_id TEXT NOT NULL,root_id TEXT,PRIMARY KEY(group_id,id));
";
pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/groups/:group_id/extensions", get(list).post(submit))
        .route(
            "/groups/:group_id/extensions/capabilities",
            get(capabilities),
        )
        .route(
            "/groups/:group_id/extensions/:event_id/cancel",
            post(cancel),
        )
        .layer(DefaultBodyLimit::max(512 * 1024))
}
#[derive(Deserialize)]
struct Access {
    device_id: String,
    #[serde(default)]
    after: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    device_id: String,
    submission: e::Submission,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cancel {
    device_id: String,
    root: Option<String>,
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
    group_id(&id)?;
    let mut tx = state.db.pool().begin().await.map_err(unavailable)?;
    member(&mut tx, &headers, &id, &access.device_id).await?;
    Ok(Json(1))
}
async fn receipt(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
    event: &e::Event,
    seq: i64,
) -> Result<e::Receipt, Failure> {
    let root = if event.action.creates() {
        Some(messages::receipt_in(tx, id, &event.object).await?.0)
    } else {
        None
    };
    Ok(e::Receipt {
        event_id: event.id.clone(),
        hash: event.hash(),
        seq,
        root,
    })
}
pub(super) async fn policy(
    tx: &mut Transaction<'_, Postgres>,
    viewer: &str,
    sender: &str,
) -> Result<bool, Failure> {
    let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM contact_policy WHERE ((user_id=$1 AND peer_id=$2) OR (user_id=$2 AND peer_id=$1)) AND status IN ('blocked','rejected'))").bind(viewer).bind(sender).fetch_one(&mut **tx).await.map_err(unavailable)?;
    Ok(!blocked)
}
async fn submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(mut request): Json<Request>,
) -> Result<Json<e::Receipt>, Failure> {
    group_id(&id)?;
    group_id(&request.submission.event.id)?;
    group_id(&request.submission.event.object)?;
    let user = admit(&state, &headers, &request.device_id).await?;
    let mut tx = state.db.pool().begin().await.map_err(unavailable)?;
    lock_group(&mut tx, &id).await?;
    let actor = authorize_tx(&mut tx, &headers, &request.device_id).await?;
    let event = &request.submission.event;
    if event.group != id || event.actor.user != user || event.actor.device != actor.device_id {
        return Err(conflict());
    }
    let encoded = serde_json::to_vec(&request.submission).map_err(|_| bad())?;
    if encoded.len() > 512 * 1024 {
        return Err(bad());
    }
    let digest = c::digest(&encoded);
    if let Some(stored) = sqlx::query(
        "SELECT seq,submission_hash,header FROM group_extension_events WHERE group_id=$1 AND id=$2",
    )
    .bind(&id)
    .bind(&event.id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(unavailable)?
    {
        if stored.get::<Vec<u8>, _>("submission_hash") != digest {
            return Err(conflict());
        }
        let original: e::Event =
            serde_json::from_str(&stored.get::<String, _>("header")).map_err(|_| corrupt())?;
        if original.actor.user != actor.user_id || original.actor.device != actor.device_id {
            return Err(missing());
        }
        let response = receipt(&mut tx, &id, event, stored.get("seq")).await?;
        tx.commit().await.map_err(unavailable)?;
        return Ok(Json(response));
    }
    let cancelled: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM group_extension_cancellations WHERE group_id=$1 AND id=$2)",
    )
    .bind(&id)
    .bind(&event.id)
    .fetch_one(&mut *tx)
    .await
    .map_err(unavailable)?;
    let collision:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM group_message_batches WHERE group_id=$1 AND message_id=$2) OR EXISTS(SELECT 1 FROM group_collab_events WHERE group_id=$1 AND id=$2)").bind(&id).bind(&event.id).fetch_one(&mut *tx).await.map_err(unavailable)?;
    if cancelled || collision || event.at.abs_diff(timestamp()) > 60_000 {
        return Err(conflict());
    }
    let meta = metadata(&mut tx, &id, true).await?;
    let group = replay(&mut tx, &id, &meta).await?;
    if group
        .member(&actor.user_id)
        .is_none_or(|m| m.identity != actor)
    {
        return Err(missing());
    }
    e::validate_submission(&group, &request.submission).map_err(|_| conflict())?;
    let previous: Option<String> =
        sqlx::query_scalar("SELECT body FROM group_extension_objects WHERE group_id=$1 AND id=$2")
            .bind(&id)
            .bind(&event.object)
            .fetch_optional(&mut *tx)
            .await
            .map_err(unavailable)?;
    let previous: Option<e::Object> = previous
        .map(|s| serde_json::from_str(&s).map_err(|_| corrupt()))
        .transpose()?;
    let next = e::transition(previous.as_ref(), &group, event).map_err(|_| conflict())?;
    messages::sending_policy(&mut tx, &group, &actor.user_id).await?;
    let count:i64=sqlx::query_scalar("SELECT (SELECT COUNT(*) FROM group_extension_events WHERE group_id=$1)+(SELECT COUNT(*) FROM group_extension_cancellations WHERE group_id=$1)").bind(&id).fetch_one(&mut *tx).await.map_err(unavailable)?;
    if count >= 10000 {
        return Err((
            StatusCode::INSUFFICIENT_STORAGE,
            "群扩展保留记录已达上限".into(),
        ));
    }
    if event.action.creates() {
        let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM group_message_batches WHERE group_id=$1 AND message_id=$2) OR EXISTS(SELECT 1 FROM group_collab_events WHERE group_id=$1 AND id=$2) OR EXISTS(SELECT 1 FROM group_extension_events WHERE group_id=$1 AND id=$2)").bind(&id).bind(&event.object).fetch_one(&mut *tx).await.map_err(unavailable)?;
        if exists {
            return Err(conflict());
        }
        // Group attachment publication also validates the uploaded object here.
        if let e::Action::Attachment { blob, size, hash } = &event.action {
            super::attachments::publish(&mut tx, &id, event, blob, *size, hash).await?;
        }
        let _ = messages::store_batch(&mut tx, &id, &actor, &mut request.submission.roots).await?;
    }
    let seq:i64=sqlx::query_scalar("INSERT INTO group_extension_events(group_id,id,object_id,revision,header,submission_hash) VALUES($1,$2,$3,$4,$5,$6) RETURNING seq").bind(&id).bind(&event.id).bind(&event.object).bind(event.revision as i64).bind(serde_json::to_string(event).map_err(|_|bad())?).bind(digest).fetch_one(&mut *tx).await.map_err(unavailable)?;
    sqlx::query("INSERT INTO group_extension_objects(group_id,id,body) VALUES($1,$2,$3) ON CONFLICT(group_id,id) DO UPDATE SET body=excluded.body").bind(&id).bind(&event.object).bind(serde_json::to_string(&next).map_err(|_|bad())?).execute(&mut *tx).await.map_err(unavailable)?;
    for boxed in &request.submission.boxes {
        sqlx::query("INSERT INTO group_extension_boxes VALUES($1,$2,$3,$4,$5)")
            .bind(&id)
            .bind(&event.id)
            .bind(&boxed.member.device)
            .bind(epoch(boxed.member.joined)?)
            .bind(&boxed.ciphertext)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
    }
    let response = receipt(&mut tx, &id, event, seq).await?;
    tx.commit().await.map_err(unavailable)?;
    Ok(Json(response))
}
async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(access): Query<Access>,
) -> Result<Json<e::Page>, Failure> {
    group_id(&id)?;
    if access.after < 0 {
        return Err(bad());
    }
    let mut tx = state.db.pool().begin().await.map_err(unavailable)?;
    let (actor, group) = member(&mut tx, &headers, &id, &access.device_id).await?;
    let joined = group
        .member(&actor.user_id)
        .ok_or_else(missing)?
        .joined_epoch;
    let rows=sqlx::query("SELECT e.seq,e.header,b.ciphertext FROM group_extension_events e LEFT JOIN group_extension_boxes b ON b.group_id=e.group_id AND b.event_id=e.id AND b.device_id=$2 AND b.joined=$3 WHERE e.group_id=$1 AND e.seq>$4 ORDER BY e.seq LIMIT 101").bind(&id).bind(&actor.device_id).bind(epoch(joined)?).bind(access.after).fetch_all(&mut *tx).await.map_err(unavailable)?;
    let mut page = e::Page {
        items: vec![],
        cursor: access.after,
        more: false,
    };
    let available = rows.len();
    let mut bytes = 64;
    for row in rows.into_iter().take(100) {
        let event: e::Event =
            serde_json::from_str(&row.get::<String, _>("header")).map_err(|_| corrupt())?;
        if !policy(&mut tx, &actor.user_id, &event.actor.user).await? {
            return Err(conflict());
        }
        let item = e::Delivery {
            seq: row.get("seq"),
            event,
            ciphertext: row.get("ciphertext"),
        };
        let n = serde_json::to_vec(&item).map_err(|_| corrupt())?.len() + 1;
        if bytes + n > 512 * 1024 {
            break;
        }
        bytes += n;
        page.cursor = item.seq;
        page.items.push(item);
    }
    page.more = available > page.items.len();
    Ok(Json(page))
}
async fn cancel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, event_id)): Path<(String, String)>,
    Json(request): Json<Cancel>,
) -> Result<Json<e::CancelResult>, Failure> {
    group_id(&id)?;
    group_id(&event_id)?;
    let mut tx = state.db.pool().begin().await.map_err(unavailable)?;
    lock_group(&mut tx, &id).await?;
    let actor = authorize_tx(&mut tx, &headers, &request.device_id).await?;
    if let Some(row) =
        sqlx::query("SELECT seq,header FROM group_extension_events WHERE group_id=$1 AND id=$2")
            .bind(&id)
            .bind(&event_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(unavailable)?
    {
        let event: e::Event =
            serde_json::from_str(&row.get::<String, _>("header")).map_err(|_| corrupt())?;
        if event.actor.user != actor.user_id || event.actor.device != actor.device_id {
            return Err(missing());
        }
        let result = receipt(&mut tx, &id, &event, row.get("seq")).await?;
        tx.commit().await.map_err(unavailable)?;
        return Ok(Json(e::CancelResult {
            cancelled: false,
            receipt: Some(result),
        }));
    }
    let eligible:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM group_memberships WHERE group_id=$1 AND user_id=$2 AND device_id=$3)").bind(&id).bind(&actor.user_id).bind(&actor.device_id).fetch_one(&mut *tx).await.map_err(unavailable)?;
    if !eligible {
        return Err(missing());
    }
    if let Some(row) = sqlx::query(
        "SELECT device_id,root_id FROM group_extension_cancellations WHERE group_id=$1 AND id=$2",
    )
    .bind(&id)
    .bind(&event_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(unavailable)?
    {
        if row.get::<String, _>("device_id") != actor.device_id
            || row.get::<Option<String>, _>("root_id") != request.root
        {
            return Err(conflict());
        }
        tx.commit().await.map_err(unavailable)?;
        return Ok(Json(e::CancelResult {
            cancelled: true,
            receipt: None,
        }));
    }
    let count:i64=sqlx::query_scalar("SELECT (SELECT COUNT(*) FROM group_extension_events WHERE group_id=$1)+(SELECT COUNT(*) FROM group_extension_cancellations WHERE group_id=$1)").bind(&id).fetch_one(&mut *tx).await.map_err(unavailable)?;
    if count >= 10000 {
        return Err((
            StatusCode::INSUFFICIENT_STORAGE,
            "群扩展取消记录已达上限".into(),
        ));
    }
    sqlx::query("INSERT INTO group_extension_cancellations VALUES($1,$2,$3,$4)")
        .bind(&id)
        .bind(&event_id)
        .bind(&actor.device_id)
        .bind(&request.root)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
    if let Some(root) = request.root {
        group_id(&root)?;
        let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM group_message_batches WHERE group_id=$1 AND message_id=$2)").bind(&id).bind(&root).fetch_one(&mut *tx).await.map_err(unavailable)?;
        if exists {
            return Err(conflict());
        }
        sqlx::query("INSERT INTO group_message_cancellations(group_id,message_id,sender_user_id,sender_device_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING").bind(&id).bind(root).bind(&actor.user_id).bind(&actor.device_id).execute(&mut *tx).await.map_err(unavailable)?;
    }
    tx.commit().await.map_err(unavailable)?;
    Ok(Json(e::CancelResult {
        cancelled: true,
        receipt: None,
    }))
}
