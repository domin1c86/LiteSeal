//! Group blobs have their own original audience and membership phase.
use super::*;
use axum::body::Bytes;
use liteseal_shared::{collaboration::Member, group_extension as e};
pub const MIGRATION:&str="
CREATE TABLE group_attachment_objects(id TEXT PRIMARY KEY,group_id TEXT NOT NULL REFERENCES private_groups(id),owner TEXT NOT NULL REFERENCES users(id),device_id TEXT NOT NULL,joined BIGINT NOT NULL,size BIGINT NOT NULL,object_id TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT now(),expires_at TIMESTAMPTZ NOT NULL);
CREATE TABLE group_attachment_chunks(object_id TEXT NOT NULL REFERENCES group_attachment_objects(id) ON DELETE CASCADE,part INTEGER NOT NULL,data BYTEA NOT NULL,PRIMARY KEY(object_id,part));
CREATE TABLE group_attachment_audience(blob TEXT NOT NULL REFERENCES group_attachment_objects(id) ON DELETE CASCADE,user_id TEXT NOT NULL,device_id TEXT NOT NULL,joined BIGINT NOT NULL,PRIMARY KEY(blob,device_id,joined));
CREATE TABLE group_attachment_published(id TEXT PRIMARY KEY,group_id TEXT NOT NULL REFERENCES private_groups(id),object_id TEXT NOT NULL);
";
pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/groups/:group_id/attachments", post(create))
        .route(
            "/groups/:group_id/attachments/:blob/:part",
            get(download).put(upload),
        )
        .layer(DefaultBodyLimit::max(1024 * 1024))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    device_id: String,
    id: String,
    size: i64,
}
#[derive(Deserialize)]
struct Access {
    device_id: String,
}
pub(crate) async fn cleanup(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM group_attachment_objects WHERE expires_at<now() OR (object_id IS NULL AND created_at<now()-make_interval(hours=>$1))").bind(crate::attachments::orphan_hours()).execute(pool).await?;
    Ok(())
}
async fn active(
    tx: &mut Transaction<'_, Postgres>,
    headers: &HeaderMap,
    id: &str,
    device: &str,
) -> Result<(GroupIdentity, GroupState), Failure> {
    lock_group(tx, id).await?;
    let actor = authorize_tx(tx, headers, device).await?;
    let meta = metadata(tx, id, true).await?;
    let state = replay(tx, id, &meta).await?;
    if state.closed()
        || state
            .member(&actor.user_id)
            .is_none_or(|m| m.identity != actor)
    {
        return Err(missing());
    }
    Ok((actor, state))
}
async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<Create>,
) -> Result<Json<String>, Failure> {
    group_id(&id)?;
    group_id(&input.id)?;
    if !(40..=20 * 1024 * 1024 + 40).contains(&input.size) {
        return Err(bad());
    }
    let mut tx = state.db.pool().begin().await.map_err(unavailable)?;
    let (actor, group) = active(&mut tx, &headers, &id, &input.device_id).await?;
    let joined = group
        .member(&actor.user_id)
        .ok_or_else(missing)?
        .joined_epoch;
    // Group -> device/session -> account quota. Direct uploads take only account quota.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,1))")
        .bind(&actor.user_id)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
    sqlx::query("DELETE FROM group_attachment_objects WHERE owner=$1 AND object_id IS NULL AND (expires_at<now() OR created_at<now()-make_interval(hours=>$2))").bind(&actor.user_id).bind(crate::attachments::orphan_hours()).execute(&mut *tx).await.map_err(unavailable)?;
    if let Some(row)=sqlx::query("SELECT group_id,owner,device_id,joined,size FROM group_attachment_objects WHERE id=$1 AND expires_at>now()").bind(&input.id).fetch_optional(&mut *tx).await.map_err(unavailable)?{if row.get::<String,_>("group_id")!=id||row.get::<String,_>("owner")!=actor.user_id||row.get::<String,_>("device_id")!=actor.device_id||row.get::<i64,_>("joined")!=epoch(joined)?||row.get::<i64,_>("size")!=input.size{return Err(conflict());}}
    else{
        let published:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM group_attachment_published WHERE id=$1)").bind(&input.id).fetch_one(&mut *tx).await.map_err(unavailable)?;
        if published{return Err(conflict());}
        let usage=sqlx::query("SELECT COALESCE(SUM(size),0)::BIGINT AS bytes,COUNT(*) AS count FROM (SELECT size FROM attachment_objects WHERE owner=$1 UNION ALL SELECT size FROM group_attachment_objects WHERE owner=$1) a").bind(&actor.user_id).fetch_one(&mut *tx).await.map_err(unavailable)?;
        if usage.get::<i64,_>("bytes")+input.size>512*1024*1024||usage.get::<i64,_>("count")>=2000{return Err((StatusCode::PAYLOAD_TOO_LARGE,"附件共享配额为 512 MiB / 2000 对象".into()));}
        sqlx::query("INSERT INTO group_attachment_objects(id,group_id,owner,device_id,joined,size,expires_at) VALUES($1,$2,$3,$4,$5,$6,now()+make_interval(days=>$7))").bind(&input.id).bind(&id).bind(&actor.user_id).bind(&actor.device_id).bind(epoch(joined)?).bind(input.size).bind(crate::attachments::days()).execute(&mut *tx).await.map_err(unavailable)?;
    }
    tx.commit().await.map_err(unavailable)?;
    Ok(Json(input.id))
}
async fn upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, blob, part)): Path<(String, String, i32)>,
    Query(access): Query<Access>,
    bytes: Bytes,
) -> Result<StatusCode, Failure> {
    group_id(&id)?;
    group_id(&blob)?;
    let mut tx = state.db.pool().begin().await.map_err(unavailable)?;
    let (actor, group) = active(&mut tx, &headers, &id, &access.device_id).await?;
    let row=sqlx::query("SELECT owner,device_id,joined,size,object_id FROM group_attachment_objects WHERE id=$1 AND group_id=$2 AND expires_at>now() FOR UPDATE").bind(&blob).bind(&id).fetch_optional(&mut *tx).await.map_err(unavailable)?.ok_or_else(missing)?;
    if row.get::<String, _>("owner") != actor.user_id
        || row.get::<String, _>("device_id") != actor.device_id
        || row.get::<i64, _>("joined")
            != epoch(
                group
                    .member(&actor.user_id)
                    .ok_or_else(missing)?
                    .joined_epoch,
            )?
    {
        return Err(missing());
    }
    let size: i64 = row.get("size");
    let offset = i64::from(part) * 1024 * 1024;
    if part < 0 || offset >= size || bytes.len() as i64 != (size - offset).min(1024 * 1024) {
        return Err(bad());
    }
    if let Some(old) = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT data FROM group_attachment_chunks WHERE object_id=$1 AND part=$2",
    )
    .bind(&blob)
    .bind(part)
    .fetch_optional(&mut *tx)
    .await
    .map_err(unavailable)?
    {
        if old != bytes.as_ref() {
            return Err(conflict());
        }
    } else {
        if row.get::<Option<String>, _>("object_id").is_some() {
            return Err(conflict());
        }
        sqlx::query("INSERT INTO group_attachment_chunks VALUES($1,$2,$3)")
            .bind(&blob)
            .bind(part)
            .bind(bytes.as_ref())
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
    }
    tx.commit().await.map_err(unavailable)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn download(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, blob, part)): Path<(String, String, i32)>,
    Query(access): Query<Access>,
) -> Result<Bytes, Failure> {
    group_id(&id)?;
    group_id(&blob)?;
    if part < 0 {
        return Err(bad());
    }
    let mut tx = state.db.pool().begin().await.map_err(unavailable)?;
    let (actor, group) = active(&mut tx, &headers, &id, &access.device_id).await?;
    let joined = epoch(
        group
            .member(&actor.user_id)
            .ok_or_else(missing)?
            .joined_epoch,
    )?;
    let row=sqlx::query("SELECT o.owner,c.data FROM group_attachment_objects o JOIN group_attachment_audience a ON a.blob=o.id JOIN group_attachment_chunks c ON c.object_id=o.id WHERE o.id=$1 AND o.group_id=$2 AND o.object_id IS NOT NULL AND o.expires_at>now() AND a.user_id=$3 AND a.device_id=$4 AND a.joined=$5 AND c.part=$6").bind(&blob).bind(&id).bind(&actor.user_id).bind(&actor.device_id).bind(joined).bind(part).fetch_optional(&mut *tx).await.map_err(unavailable)?.ok_or_else(missing)?;
    let owner: String = row.get("owner");
    if !super::extensions::policy(&mut tx, &actor.user_id, &owner).await? {
        return Err(conflict());
    }
    Ok(Bytes::from(row.get::<Vec<u8>, _>("data")))
}
pub(super) async fn publish(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
    event: &e::Event,
    blob: &str,
    size: u64,
    hash: &[u8],
) -> Result<(), Failure> {
    group_id(blob)?;
    let row=sqlx::query("SELECT owner,device_id,joined,size,object_id FROM group_attachment_objects WHERE id=$1 AND group_id=$2 AND expires_at>now() FOR UPDATE").bind(blob).bind(id).fetch_optional(&mut **tx).await.map_err(unavailable)?.ok_or_else(missing)?;
    if row.get::<String, _>("owner") != event.actor.user
        || row.get::<String, _>("device_id") != event.actor.device
        || row.get::<i64, _>("joined") != epoch(event.actor.joined)?
        || row.get::<i64, _>("size") != size as i64 + 40
        || row.get::<Option<String>, _>("object_id").is_some()
    {
        return Err(conflict());
    }
    let chunks = sqlx::query(
        "SELECT part,data FROM group_attachment_chunks WHERE object_id=$1 ORDER BY part",
    )
    .bind(blob)
    .fetch_all(&mut **tx)
    .await
    .map_err(unavailable)?;
    let mut bytes = Vec::new();
    for (part, row) in chunks.into_iter().enumerate() {
        if row.get::<i32, _>("part") != part as i32 {
            return Err(conflict());
        }
        bytes.extend(row.get::<Vec<u8>, _>("data"));
    }
    if bytes.len() != size as usize + 40 || liteseal_shared::collaboration::digest(&bytes) != hash {
        return Err(conflict());
    }
    sqlx::query("UPDATE group_attachment_objects SET object_id=$2 WHERE id=$1")
        .bind(blob)
        .bind(&event.object)
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
    sqlx::query("INSERT INTO group_attachment_published VALUES($1,$2,$3)")
        .bind(blob)
        .bind(id)
        .bind(&event.object)
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
    for Member {
        user,
        device,
        joined,
    } in &event.audience
    {
        sqlx::query("INSERT INTO group_attachment_audience VALUES($1,$2,$3,$4)")
            .bind(blob)
            .bind(user)
            .bind(device)
            .bind(epoch(*joined)?)
            .execute(&mut **tx)
            .await
            .map_err(unavailable)?;
    }
    Ok(())
}
