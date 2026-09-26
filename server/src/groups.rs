use crate::state::AppState;
use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{delete, get, post},
    Json, Router,
};
use liteseal_shared::group::*;
use serde::Deserialize;
use sqlx::{Postgres, Row, Transaction};

type Failure = (StatusCode, String);
const MAX_EPOCH: i64 = 1000;
const PAGE_SIZE: usize = 100;
fn unavailable(_: sqlx::Error) -> Failure {
    (StatusCode::SERVICE_UNAVAILABLE, "群存储暂不可用".into())
}
fn conflict() -> Failure {
    (
        StatusCode::CONFLICT,
        "群版本、邀请或操作权限不符合要求".into(),
    )
}
fn missing() -> Failure {
    (StatusCode::NOT_FOUND, "没有可访问的群记录".into())
}
fn bad() -> Failure {
    (StatusCode::BAD_REQUEST, "无效群参数".into())
}
fn corrupt() -> Failure {
    (StatusCode::SERVICE_UNAVAILABLE, "群签名记录无法验证".into())
}
fn timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
fn group_id(value: &str) -> Result<(), Failure> {
    uuid::Uuid::parse_str(value).map(|_| ()).map_err(|_| bad())
}
fn epoch(value: u64) -> Result<i64, Failure> {
    let value = i64::try_from(value).map_err(|_| bad())?;
    if !(1..=MAX_EPOCH + 1).contains(&value) {
        return Err(bad());
    }
    Ok(value)
}
fn bearer(headers: &HeaderMap) -> Result<&str, Failure> {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or((StatusCode::UNAUTHORIZED, "需要登录".into()))
}
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/groups", get(list).post(create))
        .route("/groups/:group_id/changes", get(changes).post(submit))
        .route("/groups/:group_id/invites", post(invite))
        .route("/group-invites", get(invites))
        .route("/group-invites/:id", delete(cancel_invite))
        .layer(DefaultBodyLimit::max(32 * 1024))
}
async fn admit(state: &AppState, headers: &HeaderMap, device: &str) -> Result<String, Failure> {
    let user = crate::message_operations::authorize(state, headers, device).await?;
    if !state
        .db
        .hit_rate_limit(&format!("group-actions:{user}"), 40, 60)
        .await
        .map_err(unavailable)?
    {
        return Err((StatusCode::TOO_MANY_REQUESTS, "群操作过于频繁".into()));
    }
    Ok(user)
}
/// Devices are locked before sessions, matching the revocation update order.
async fn authorize_tx(
    tx: &mut Transaction<'_, Postgres>,
    headers: &HeaderMap,
    device: &str,
) -> Result<GroupIdentity, Failure> {
    let token = crate::auth::service::hash_token(bearer(headers)?);
    let record = sqlx::query(
        "SELECT user_id,public_key,ed25519_pk FROM devices WHERE id=$1 AND revoked=false FOR SHARE",
    )
    .bind(device)
    .fetch_optional(&mut **tx)
    .await
    .map_err(unavailable)?
    .ok_or((StatusCode::UNAUTHORIZED, "设备不可用".into()))?;
    let user: String = record.get("user_id");
    let valid:Option<String>=sqlx::query_scalar("SELECT user_id FROM sessions WHERE access_token_hash=$1 AND device_id=$2 AND revoked=false AND expires_at>now() FOR SHARE")
        .bind(token).bind(device).fetch_optional(&mut **tx).await.map_err(unavailable)?;
    if valid.as_deref() != Some(&user) {
        return Err((StatusCode::UNAUTHORIZED, "会话失效".into()));
    }
    let identity = GroupIdentity {
        user_id: user,
        device_id: device.into(),
        public_key: record.get("public_key"),
        signing_key: record.get("ed25519_pk"),
    };
    identity.validate().map_err(|_| corrupt())?;
    Ok(identity)
}
async fn bind_device(
    tx: &mut Transaction<'_, Postgres>,
    identity: &GroupIdentity,
) -> Result<(), Failure> {
    let row=sqlx::query("SELECT public_key,ed25519_pk FROM devices WHERE user_id=$1 AND id=$2 AND revoked=false FOR SHARE")
        .bind(&identity.user_id).bind(&identity.device_id).fetch_optional(&mut **tx).await.map_err(unavailable)?.ok_or_else(conflict)?;
    if row.get::<Vec<u8>, _>("public_key") != identity.public_key
        || row.get::<Vec<u8>, _>("ed25519_pk") != identity.signing_key
    {
        return Err(conflict());
    }
    Ok(())
}
async fn lock_group(tx: &mut Transaction<'_, Postgres>, id: &str) -> Result<(), Failure> {
    // Serialize before taking device/session locks, so an owner waiting for
    // this group cannot hold up revocation while a join checks that owner.
    sqlx::query("SET LOCAL lock_timeout = '5s'")
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
    sqlx::query("SET LOCAL statement_timeout = '10s'")
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,3))")
        .bind(id)
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
    Ok(())
}
async fn lock_user(tx: &mut Transaction<'_, Postgres>, user: &str) -> Result<(), Failure> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,4))")
        .bind(user)
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
    Ok(())
}
async fn policy_allowed(
    tx: &mut Transaction<'_, Postgres>,
    left: &str,
    right: &str,
) -> Result<bool, Failure> {
    let mut users = [left, right];
    users.sort();
    for user in users {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2))")
            .bind(user)
            .execute(&mut **tx)
            .await
            .map_err(unavailable)?;
    }
    policy_read(tx, left, right).await
}
async fn policy_read(
    tx: &mut Transaction<'_, Postgres>,
    left: &str,
    right: &str,
) -> Result<bool, Failure> {
    let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM contact_policy WHERE ((user_id=$1 AND peer_id=$2) OR (user_id=$2 AND peer_id=$1)) AND status IN ('blocked','rejected'))")
        .bind(left).bind(right).fetch_one(&mut **tx).await.map_err(unavailable)?;
    Ok(!blocked)
}
async fn active_count(tx: &mut Transaction<'_, Postgres>, user: &str) -> Result<i64, Failure> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM group_memberships WHERE user_id=$1 AND removed_epoch IS NULL",
    )
    .bind(user)
    .fetch_one(&mut **tx)
    .await
    .map_err(unavailable)
}
struct Metadata {
    head: i64,
    hash: Vec<u8>,
    root: GroupIdentity,
    closed: bool,
}
async fn metadata(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
    write: bool,
) -> Result<Metadata, Failure> {
    let query = if write {
        "SELECT head_epoch,current_hash,root_identity,closed FROM private_groups WHERE id=$1 FOR UPDATE"
    } else {
        "SELECT head_epoch,current_hash,root_identity,closed FROM private_groups WHERE id=$1 FOR SHARE"
    };
    let row = sqlx::query(query)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(unavailable)?
        .ok_or_else(missing)?;
    Ok(Metadata {
        head: row.get("head_epoch"),
        hash: row.get("current_hash"),
        root: serde_json::from_str(&row.get::<String, _>("root_identity"))
            .map_err(|_| corrupt())?,
        closed: row.get("closed"),
    })
}
async fn replay(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
    meta: &Metadata,
) -> Result<GroupState, Failure> {
    let events=sqlx::query("SELECT epoch,body FROM group_changes WHERE group_id=$1 AND epoch<=$2 ORDER BY epoch LIMIT 1001")
        .bind(id).bind(meta.head).fetch_all(&mut **tx).await.map_err(unavailable)?;
    let mut current = None;
    for row in events {
        let event: GroupChange =
            serde_json::from_str(&row.get::<String, _>("body")).map_err(|_| corrupt())?;
        if i64::try_from(event.epoch).ok() != Some(row.get("epoch")) {
            return Err(corrupt());
        }
        current = Some(
            match current.as_ref() {
                None => pin_creation(&event, &meta.root),
                Some(state) => apply_change(Some(state), &event),
            }
            .map_err(|_| corrupt())?,
        );
    }
    let current = current.ok_or_else(corrupt)?;
    if current.group_id() != id
        || i64::try_from(current.epoch()).ok() != Some(meta.head)
        || current.revision_hash() != meta.hash
        || current.closed() != meta.closed
    {
        return Err(corrupt());
    }
    Ok(current)
}
async fn projection(
    tx: &mut Transaction<'_, Postgres>,
    previous: Option<&GroupState>,
    next: &GroupState,
) -> Result<(), Failure> {
    let next_epoch = epoch(next.epoch())?;
    if let Some(previous) = previous {
        for member in previous.members() {
            if next.closed() || next.member(&member.identity.user_id).is_none() {
                sqlx::query("UPDATE group_memberships SET removed_epoch=$4 WHERE group_id=$1 AND user_id=$2 AND joined_epoch=$3 AND removed_epoch IS NULL")
                    .bind(next.group_id()).bind(&member.identity.user_id).bind(epoch(member.joined_epoch)?).bind(next_epoch).execute(&mut **tx).await.map_err(unavailable)?;
            }
        }
    }
    for member in next.members() {
        if previous.is_none_or(|previous| previous.member(&member.identity.user_id).is_none()) {
            sqlx::query("INSERT INTO group_memberships(group_id,user_id,device_id,joined_epoch) VALUES($1,$2,$3,$4)")
                .bind(next.group_id()).bind(&member.identity.user_id).bind(&member.identity.device_id).bind(epoch(member.joined_epoch)?).execute(&mut **tx).await.map_err(unavailable)?;
        }
    }
    Ok(())
}
fn shape(change: &GroupChange) -> Result<String, Failure> {
    group_id(&change.group_id)?;
    epoch(change.epoch)?;
    let body = serde_json::to_string(change).map_err(|_| bad())?;
    if body.len() > 32 * 1024 {
        return Err(bad());
    }
    Ok(body)
}
pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<GroupChangeRequest>,
) -> Result<Json<GroupChange>, Failure> {
    let user = admit(&state, &headers, &request.device_id).await?;
    let body = shape(&request.change)?;
    let mut tx = state.db.pool().begin().await.map_err(unavailable)?;
    lock_group(&mut tx, &request.change.group_id).await?;
    let identity = authorize_tx(&mut tx, &headers, &request.device_id).await?;
    if identity.user_id != user || request.change.actor != user {
        return Err(conflict());
    }
    pin_creation(&request.change, &identity).map_err(|_| conflict())?;
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM private_groups WHERE id=$1)")
            .bind(&request.change.group_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(unavailable)?;
    if exists {
        let stored: Option<String> =
            sqlx::query_scalar("SELECT body FROM group_changes WHERE group_id=$1 AND epoch=1")
                .bind(&request.change.group_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(unavailable)?;
        if request.change.epoch == 1 && stored.as_deref() == Some(&body) {
            return Ok(Json(request.change));
        }
        return Err(conflict());
    }
    let next = validate_submission(None, &request.change, timestamp()).map_err(|_| conflict())?;
    lock_user(&mut tx, &user).await?;
    let owned: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM private_groups WHERE owner_user_id=$1 AND closed=false",
    )
    .bind(&user)
    .fetch_one(&mut *tx)
    .await
    .map_err(unavailable)?;
    if owned >= 20 || active_count(&mut tx, &user).await? >= 100 {
        return Err(conflict());
    }
    sqlx::query("INSERT INTO private_groups(id,owner_user_id,owner_device_id,head_epoch,current_hash,root_identity,closed) VALUES($1,$2,$3,1,$4,$5,false)")
        .bind(next.group_id()).bind(&user).bind(&identity.device_id).bind(next.revision_hash()).bind(serde_json::to_string(&identity).map_err(|_|bad())?).execute(&mut *tx).await.map_err(unavailable)?;
    sqlx::query("INSERT INTO group_changes(group_id,epoch,actor,body) VALUES($1,1,$2,$3)")
        .bind(next.group_id())
        .bind(&user)
        .bind(body)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
    projection(&mut tx, None, &next).await?;
    tx.commit().await.map_err(unavailable)?;
    Ok(Json(request.change))
}
pub async fn submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<GroupChangeRequest>,
) -> Result<Json<GroupChange>, Failure> {
    let user = admit(&state, &headers, &request.device_id).await?;
    group_id(&id)?;
    let body = shape(&request.change)?;
    if request.change.group_id != id || request.change.actor != user {
        return Err(conflict());
    }
    let mut tx = state.db.pool().begin().await.map_err(unavailable)?;
    lock_group(&mut tx, &id).await?;
    let actor = authorize_tx(&mut tx, &headers, &request.device_id).await?;
    let meta = metadata(&mut tx, &id, true).await?;
    if request.change.epoch <= meta.head as u64 {
        let previous: Option<String> =
            sqlx::query_scalar("SELECT body FROM group_changes WHERE group_id=$1 AND epoch=$2")
                .bind(&id)
                .bind(epoch(request.change.epoch)?)
                .fetch_optional(&mut *tx)
                .await
                .map_err(unavailable)?;
        if previous.as_deref() == Some(&body) {
            return Ok(Json(request.change));
        }
        return Err(conflict());
    }
    let previous = replay(&mut tx, &id, &meta).await?;
    if meta.head >= MAX_EPOCH && !matches!(&request.change.action, GroupAction::Close) {
        return Err(conflict());
    }
    if let GroupAction::Join { invite, .. } = &request.change.action {
        if invite.member != actor {
            return Err(conflict());
        }
        bind_device(
            &mut tx,
            &previous
                .member(previous.owner())
                .ok_or_else(conflict)?
                .identity,
        )
        .await?;
        let record = sqlx::query(
            "SELECT body,status FROM group_invites WHERE id=$1 AND group_id=$2 FOR UPDATE",
        )
        .bind(&invite.id)
        .bind(&id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(unavailable)?
        .ok_or_else(conflict)?;
        if record.get::<String, _>("status") != "pending"
            || record.get::<String, _>("body")
                != serde_json::to_string(invite).map_err(|_| bad())?
            || !policy_allowed(&mut tx, previous.owner(), &user).await?
        {
            return Err(conflict());
        }
        lock_user(&mut tx, &user).await?;
        if active_count(&mut tx, &user).await? >= 100 {
            return Err(conflict());
        }
    } else if previous
        .member(&user)
        .is_none_or(|member| member.identity != actor)
    {
        return Err(conflict());
    }
    let next = validate_submission(Some(&previous), &request.change, timestamp())
        .map_err(|_| conflict())?;
    sqlx::query("INSERT INTO group_changes(group_id,epoch,actor,body) VALUES($1,$2,$3,$4)")
        .bind(&id)
        .bind(epoch(next.epoch())?)
        .bind(&user)
        .bind(body)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
    projection(&mut tx, Some(&previous), &next).await?;
    if let GroupAction::Join { invite, .. } = &request.change.action {
        sqlx::query("UPDATE group_invites SET status='accepted' WHERE id=$1")
            .bind(&invite.id)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
    }
    sqlx::query("UPDATE private_groups SET head_epoch=$2,current_hash=$3,closed=$4 WHERE id=$1")
        .bind(&id)
        .bind(epoch(next.epoch())?)
        .bind(next.revision_hash())
        .bind(next.closed())
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
    tx.commit().await.map_err(unavailable)?;
    Ok(Json(request.change))
}
pub async fn invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<GroupInviteRequest>,
) -> Result<Json<GroupInviteStatus>, Failure> {
    let user = admit(&state, &headers, &request.device_id).await?;
    group_id(&id)?;
    group_id(&request.invite.id)?;
    if request.invite.group_id != id {
        return Err(conflict());
    }
    let mut tx = state.db.pool().begin().await.map_err(unavailable)?;
    lock_group(&mut tx, &id).await?;
    let actor = authorize_tx(&mut tx, &headers, &request.device_id).await?;
    let meta = metadata(&mut tx, &id, true).await?;
    let group = replay(&mut tx, &id, &meta).await?;
    if group.owner() != user
        || group
            .member(&user)
            .is_none_or(|member| member.identity != actor)
    {
        return Err(conflict());
    }
    let body = serde_json::to_string(&request.invite).map_err(|_| bad())?;
    if let Some(record) = sqlx::query("SELECT body,status FROM group_invites WHERE id=$1")
        .bind(&request.invite.id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(unavailable)?
    {
        if record.get::<String, _>("body") != body {
            return Err(conflict());
        }
        return Ok(Json(GroupInviteStatus {
            invite: request.invite,
            status: record.get("status"),
        }));
    }
    if meta.head >= MAX_EPOCH {
        return Err(conflict());
    }
    validate_invite(&group, &request.invite, timestamp()).map_err(|_| conflict())?;
    bind_device(&mut tx, &request.invite.member).await?;
    if !policy_allowed(&mut tx, &user, &request.invite.member.user_id).await? {
        return Err(conflict());
    }
    lock_user(&mut tx, &request.invite.member.user_id).await?;
    let pending:i64=sqlx::query_scalar("SELECT COUNT(*) FROM group_invites i JOIN private_groups g ON g.id=i.group_id WHERE i.target_user_id=$1 AND i.status='pending' AND i.expires_at>$2 AND i.base_epoch=g.head_epoch AND g.closed=false")
        .bind(&request.invite.member.user_id).bind(timestamp()).fetch_one(&mut *tx).await.map_err(unavailable)?;
    let retained: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM group_invites WHERE group_id=$1")
        .bind(&id)
        .fetch_one(&mut *tx)
        .await
        .map_err(unavailable)?;
    if pending >= 100 || retained >= 2000 {
        return Err(conflict());
    }
    sqlx::query("INSERT INTO group_invites(id,group_id,target_user_id,target_device_id,base_epoch,expires_at,body,status) VALUES($1,$2,$3,$4,$5,$6,$7,'pending')")
        .bind(&request.invite.id).bind(&id).bind(&request.invite.member.user_id).bind(&request.invite.member.device_id).bind(epoch(request.invite.epoch)?).bind(request.invite.expires_at).bind(body).execute(&mut *tx).await.map_err(unavailable)?;
    tx.commit().await.map_err(unavailable)?;
    Ok(Json(GroupInviteStatus {
        invite: request.invite,
        status: "pending".into(),
    }))
}

#[derive(Deserialize)]
pub struct Cursor {
    device_id: String,
    #[serde(default)]
    after_id: Option<String>,
}
#[derive(Deserialize)]
pub struct EventCursor {
    device_id: String,
    #[serde(default)]
    after_epoch: u64,
}
pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(cursor): Query<Cursor>,
) -> Result<Json<GroupListPage>, Failure> {
    let user = crate::message_operations::authorize(&state, &headers, &cursor.device_id).await?;
    if let Some(id) = &cursor.after_id {
        group_id(id)?;
    }
    let records=sqlx::query("SELECT DISTINCT ON(m.group_id) m.group_id,m.joined_epoch,m.removed_epoch,g.head_epoch FROM group_memberships m JOIN private_groups g ON g.id=m.group_id WHERE m.user_id=$1 AND m.device_id=$2 AND m.group_id>$3 ORDER BY m.group_id,m.joined_epoch DESC LIMIT 101")
        .bind(user).bind(cursor.device_id).bind(cursor.after_id.unwrap_or_default()).fetch_all(state.db.pool()).await.map_err(unavailable)?;
    let more = records.len() > PAGE_SIZE;
    let groups: Vec<_> = records
        .into_iter()
        .take(PAGE_SIZE)
        .map(|row| {
            let end: Option<i64> = row.get("removed_epoch");
            GroupListEntry {
                group_id: row.get("group_id"),
                joined_epoch: row.get::<i64, _>("joined_epoch") as u64,
                visible_epoch: end.unwrap_or_else(|| row.get("head_epoch")) as u64,
                active: end.is_none(),
            }
        })
        .collect();
    let next_cursor = more.then(|| groups.last().unwrap().group_id.clone());
    Ok(Json(GroupListPage {
        groups,
        next_cursor,
    }))
}
pub async fn changes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(cursor): Query<EventCursor>,
) -> Result<Json<GroupEventPage>, Failure> {
    let user = crate::message_operations::authorize(&state, &headers, &cursor.device_id).await?;
    group_id(&id)?;
    let after = i64::try_from(cursor.after_epoch).map_err(|_| bad())?;
    let mut tx = state.db.pool().begin().await.map_err(unavailable)?;
    let meta = metadata(&mut tx, &id, false).await?;
    let through:Option<i64>=sqlx::query_scalar("SELECT MAX(COALESCE(removed_epoch,$4)) FROM group_memberships WHERE group_id=$1 AND user_id=$2 AND device_id=$3")
        .bind(&id).bind(&user).bind(&cursor.device_id).bind(meta.head).fetch_one(&mut *tx).await.map_err(unavailable)?;
    let invitation:Option<i64>=sqlx::query_scalar("SELECT MAX(base_epoch) FROM group_invites WHERE group_id=$1 AND target_user_id=$2 AND target_device_id=$3 AND status='pending' AND expires_at>$4 AND base_epoch=$5")
        .bind(&id).bind(&user).bind(&cursor.device_id).bind(timestamp()).bind(meta.head).fetch_one(&mut *tx).await.map_err(unavailable)?;
    let through = visible_epoch(
        meta.head,
        through,
        if invitation.is_some()
            && !meta.closed
            && policy_read(&mut tx, &meta.root.user_id, &user).await?
        {
            invitation
        } else {
            None
        },
    )
    .ok_or_else(missing)?;
    let events=sqlx::query("SELECT body FROM group_changes WHERE group_id=$1 AND epoch>$2 AND epoch<=$3 ORDER BY epoch LIMIT 100").bind(&id).bind(after).bind(through).fetch_all(&mut *tx).await.map_err(unavailable)?;
    let changes: Vec<GroupChange> = events
        .into_iter()
        .map(|row| serde_json::from_str(&row.get::<String, _>("body")).map_err(|_| corrupt()))
        .collect::<Result<_, _>>()?;
    let last = changes
        .last()
        .map(|change| change.epoch)
        .unwrap_or(cursor.after_epoch);
    tx.commit().await.map_err(unavailable)?;
    Ok(Json(GroupEventPage {
        changes,
        through_epoch: through as u64,
        has_more: last < through as u64,
    }))
}
fn visible_epoch(head: i64, membership: Option<i64>, invitation: Option<i64>) -> Option<i64> {
    membership
        .into_iter()
        .chain(invitation)
        .max()
        .map(|epoch| epoch.min(head))
}
pub async fn invites(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(cursor): Query<Cursor>,
) -> Result<Json<GroupInvitePage>, Failure> {
    let user = crate::message_operations::authorize(&state, &headers, &cursor.device_id).await?;
    if let Some(id) = &cursor.after_id {
        group_id(id)?;
    }
    let records=sqlx::query("SELECT i.id,i.body FROM group_invites i JOIN private_groups g ON g.id=i.group_id WHERE i.target_user_id=$1 AND i.target_device_id=$2 AND i.status='pending' AND i.expires_at>$3 AND i.base_epoch=g.head_epoch AND g.closed=false AND i.id>$4 AND NOT EXISTS(SELECT 1 FROM contact_policy p WHERE ((p.user_id=i.target_user_id AND p.peer_id=g.owner_user_id) OR (p.user_id=g.owner_user_id AND p.peer_id=i.target_user_id)) AND p.status IN ('blocked','rejected')) ORDER BY i.id LIMIT 101")
        .bind(user).bind(cursor.device_id).bind(timestamp()).bind(cursor.after_id.unwrap_or_default()).fetch_all(state.db.pool()).await.map_err(unavailable)?;
    let more = records.len() > PAGE_SIZE;
    let invites: Vec<GroupInvite> = records
        .into_iter()
        .take(PAGE_SIZE)
        .map(|row| serde_json::from_str(&row.get::<String, _>("body")).map_err(|_| corrupt()))
        .collect::<Result<_, _>>()?;
    let next_cursor = more.then(|| invites.last().unwrap().id.clone());
    Ok(Json(GroupInvitePage {
        invites,
        next_cursor,
    }))
}
pub async fn cancel_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(cursor): Query<Cursor>,
) -> Result<StatusCode, Failure> {
    let user = admit(&state, &headers, &cursor.device_id).await?;
    group_id(&id)?;
    let mut tx = state.db.pool().begin().await.map_err(unavailable)?;
    let group: Option<String> =
        sqlx::query_scalar("SELECT group_id FROM group_invites WHERE id=$1")
            .bind(&id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(unavailable)?;
    let group = group.ok_or_else(missing)?;
    lock_group(&mut tx, &group).await?;
    authorize_tx(&mut tx, &headers, &cursor.device_id).await?;
    let record=sqlx::query("SELECT i.target_user_id,i.target_device_id,i.status,g.owner_user_id,g.owner_device_id FROM group_invites i JOIN private_groups g ON g.id=i.group_id WHERE i.id=$1 FOR UPDATE OF i")
        .bind(&id).fetch_one(&mut *tx).await.map_err(unavailable)?;
    let target = record.get::<String, _>("target_user_id") == user
        && record.get::<String, _>("target_device_id") == cursor.device_id;
    let owner = record.get::<String, _>("owner_user_id") == user
        && record.get::<String, _>("owner_device_id") == cursor.device_id;
    if !target && !owner {
        return Err(missing());
    }
    if record.get::<String, _>("status") == "accepted" {
        return Err(conflict());
    }
    sqlx::query("UPDATE group_invites SET status=$2 WHERE id=$1 AND status='pending'")
        .bind(&id)
        .bind(if target { "rejected" } else { "revoked" })
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
    tx.commit().await.map_err(unavailable)?;
    Ok(StatusCode::NO_CONTENT)
}

pub const MIGRATION:&str="
CREATE TABLE private_groups(id TEXT PRIMARY KEY,owner_user_id TEXT NOT NULL REFERENCES users(id),owner_device_id TEXT NOT NULL REFERENCES devices(id),head_epoch BIGINT NOT NULL CHECK(head_epoch BETWEEN 1 AND 1001),current_hash BYTEA NOT NULL CHECK(octet_length(current_hash)=32),root_identity TEXT NOT NULL,closed BOOLEAN NOT NULL);
CREATE INDEX private_groups_owner ON private_groups(owner_user_id,closed);
CREATE INDEX private_groups_device ON private_groups(owner_device_id);
CREATE TABLE group_changes(group_id TEXT NOT NULL REFERENCES private_groups(id),epoch BIGINT NOT NULL CHECK(epoch BETWEEN 1 AND 1001),actor TEXT NOT NULL REFERENCES users(id),body TEXT NOT NULL,PRIMARY KEY(group_id,epoch));
CREATE INDEX group_changes_actor ON group_changes(actor);
CREATE TABLE group_memberships(group_id TEXT NOT NULL REFERENCES private_groups(id),user_id TEXT NOT NULL REFERENCES users(id),device_id TEXT NOT NULL REFERENCES devices(id),joined_epoch BIGINT NOT NULL CHECK(joined_epoch BETWEEN 1 AND 1001),removed_epoch BIGINT CHECK(removed_epoch>=joined_epoch AND removed_epoch<=1001),PRIMARY KEY(group_id,user_id,joined_epoch));
CREATE UNIQUE INDEX group_memberships_active ON group_memberships(group_id,user_id) WHERE removed_epoch IS NULL;
CREATE INDEX group_memberships_user ON group_memberships(user_id,device_id,group_id,joined_epoch DESC);
CREATE INDEX group_memberships_device ON group_memberships(device_id);
CREATE TABLE group_invites(id TEXT PRIMARY KEY,group_id TEXT NOT NULL REFERENCES private_groups(id),target_user_id TEXT NOT NULL REFERENCES users(id),target_device_id TEXT NOT NULL REFERENCES devices(id),base_epoch BIGINT NOT NULL CHECK(base_epoch BETWEEN 1 AND 1000),expires_at BIGINT NOT NULL,body TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('pending','accepted','rejected','revoked')));
CREATE INDEX group_invites_group ON group_invites(group_id);
CREATE INDEX group_invites_target ON group_invites(target_user_id,target_device_id,id);
CREATE INDEX group_invites_device ON group_invites(target_device_id);
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removal_history_is_visible_without_future_updates() {
        assert_eq!(visible_epoch(9, Some(4), None), Some(4));
        assert_eq!(visible_epoch(9, Some(9), None), Some(9));
        assert_eq!(visible_epoch(9, None, None), None);
    }

    #[test]
    fn explicit_invitation_can_extend_history_only_to_current_head() {
        assert_eq!(visible_epoch(9, Some(4), Some(9)), Some(9));
        assert_eq!(visible_epoch(9, None, Some(9)), Some(9));
        assert_eq!(visible_epoch(9, Some(20), None), Some(9));
    }
}
