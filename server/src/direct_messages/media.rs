//! Separate v3 blob authorization; never borrow beta recipient permissions.
use super::*;
use axum::body::Bytes;
use liteseal_shared::direct_media::{Reference, Submission, CHUNK};
use sha2::{Digest, Sha256};
pub const MIGRATION:&str="
CREATE TABLE direct_v3_media_objects (
 id TEXT PRIMARY KEY,owner TEXT NOT NULL REFERENCES users(id),source TEXT NOT NULL,peer TEXT NOT NULL REFERENCES users(id),
 authority BYTEA NOT NULL CHECK(octet_length(authority)=32),size BIGINT NOT NULL CHECK(size BETWEEN 40 AND 20971560),
 hash BYTEA NOT NULL CHECK(octet_length(hash)=32),published BOOLEAN NOT NULL DEFAULT false,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),expires_at TIMESTAMPTZ NOT NULL);
CREATE INDEX direct_v3_media_owner ON direct_v3_media_objects(owner);
CREATE TABLE direct_v3_media_chunks (
 object_id TEXT NOT NULL REFERENCES direct_v3_media_objects(id) ON DELETE CASCADE,
 part INTEGER NOT NULL CHECK(part>=0 AND part<=20),data BYTEA NOT NULL CHECK(octet_length(data) BETWEEN 1 AND 1048576),PRIMARY KEY(object_id,part));
CREATE TABLE direct_v3_media_audience (
 object_id TEXT NOT NULL REFERENCES direct_v3_media_objects(id) ON DELETE CASCADE,
 account TEXT NOT NULL REFERENCES users(id),device TEXT NOT NULL,authority BYTEA NOT NULL CHECK(octet_length(authority)=32),
 PRIMARY KEY(object_id,device));
CREATE TABLE direct_v3_media_published (
 id TEXT PRIMARY KEY REFERENCES direct_v3_batches(id),binding BYTEA NOT NULL CHECK(octet_length(binding)=32));
";
pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/direct/v3/media/objects",
            post(create).layer(DefaultBodyLimit::max(4096)),
        )
        .route(
            "/direct/v3/media/objects/:id/:part",
            get(download)
                .put(upload)
                .layer(DefaultBodyLimit::max(CHUNK)),
        )
        .route(
            "/direct/v3/media/batches",
            post(publish_media).layer(DefaultBodyLimit::max(
                liteseal_shared::direct_media::MAX_SUBMISSION,
            )),
        )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    device_id: String,
    id: String,
    peer: String,
    size: u64,
    hash: [u8; 32],
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Access {
    device_id: String,
}
fn missing() -> Failure {
    (StatusCode::NOT_FOUND, "此设备的原附件不可用或已过期".into())
}
pub(crate) async fn cleanup(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM direct_v3_media_objects WHERE expires_at<now() OR (published=false AND created_at<now()-make_interval(hours=>$1))").bind(crate::attachments::orphan_hours()).execute(pool).await?;
    Ok(())
}
async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<Create>,
) -> Result<Json<String>, Failure> {
    uuid(&input.id)?;
    uuid(&input.peer)?;
    let reference = Reference {
        size: input.size,
        hash: input.hash,
    };
    reference.validate(Kind::Attachment).map_err(codec)?;
    let (user, hash) = admit(&state, &headers, &input.device_id).await?;
    if user == input.peer {
        return Err(bad());
    }
    let mut tx = state.db.pool().begin().await.map_err(storage)?;
    lock_accounts(&mut tx, &[&user, &input.peer]).await?;
    let (sender, _) = current(&mut tx, &user, origin(&state)?).await?;
    let authority = session(&mut tx, &hash, &user, &input.device_id, &sender).await?;
    if !crate::device_activation::enabled(&mut tx, &user)
        .await
        .map_err(storage)?
        || !crate::device_activation::enabled(&mut tx, &input.peer)
            .await
            .map_err(storage)?
    {
        return Err((
            StatusCode::UPGRADE_REQUIRED,
            "双方原设备需要明确启用 v3".into(),
        ));
    }
    policy(&mut tx, &user, &input.peer).await?;
    // Same quota lock as beta and group uploads. Account/session/policy locks
    // precede this lock; quota holders never acquire those locks afterward.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,1))")
        .bind(&user)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
    sqlx::query("DELETE FROM direct_v3_media_objects WHERE owner=$1 AND (expires_at<now() OR (published=false AND created_at<now()-make_interval(hours=>$2)))").bind(&user).bind(crate::attachments::orphan_hours()).execute(&mut *tx).await.map_err(storage)?;
    let old=sqlx::query("SELECT owner,source,peer,authority,size,hash FROM direct_v3_media_objects WHERE id=$1 FOR UPDATE").bind(&input.id).fetch_optional(&mut *tx).await.map_err(storage)?;
    if let Some(old) = old {
        if old.get::<String, _>("owner") != user
            || old.get::<String, _>("source") != input.device_id
            || old.get::<String, _>("peer") != input.peer
            || old.get::<Vec<u8>, _>("authority") != authority
            || old.get::<i64, _>("size") != input.size as i64
            || old.get::<Vec<u8>, _>("hash") != input.hash
        {
            return Err(conflict());
        }
    } else {
        let used: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM direct_v3_batches WHERE id=$1)")
                .bind(&input.id)
                .fetch_one(&mut *tx)
                .await
                .map_err(storage)?;
        if used {
            return Err(conflict());
        }
        let (bytes, count) = crate::attachments::usage(&mut tx, &user).await?;
        if bytes + input.size as i64 > 512 * 1024 * 1024 || count >= 2000 {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                "附件共享配额为 512 MiB / 2000 对象".into(),
            ));
        }
        sqlx::query("INSERT INTO direct_v3_media_objects(id,owner,source,peer,authority,size,hash,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,now()+make_interval(days=>$8))").bind(&input.id).bind(&user).bind(&input.device_id).bind(&input.peer).bind(authority.as_slice()).bind(input.size as i64).bind(input.hash.as_slice()).bind(crate::attachments::days()).execute(&mut *tx).await.map_err(storage)?;
    }
    tx.commit().await.map_err(storage)?;
    Ok(Json(input.id))
}
async fn access(
    state: &AppState,
    headers: &HeaderMap,
    id: &str,
    device: &str,
    write: bool,
) -> Result<(Tx<'static>, String, [u8; 32]), Failure> {
    uuid(id)?;
    let (user, hash) = admit(state, headers, device).await?;
    let mut tx = state.db.pool().begin().await.map_err(storage)?;
    let route = sqlx::query(
        "SELECT owner,peer FROM direct_v3_media_objects WHERE id=$1 AND expires_at>now()",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(storage)?
    .ok_or_else(missing)?;
    let owner: String = route.get("owner");
    let peer: String = route.get("peer");
    if user != owner && user != peer {
        return Err(missing());
    }
    lock_accounts(&mut tx, &[&owner, &peer]).await?;
    let (current, _) = current(&mut tx, &user, origin(state)?).await?;
    let authority = session(&mut tx, &hash, &user, device, &current).await?;
    // Lock order is accounts -> session -> policy -> object everywhere.
    policy(&mut tx, &owner, &peer).await?;
    let lock = if write { "FOR UPDATE" } else { "FOR SHARE" };
    sqlx::query(&format!(
        "SELECT id FROM direct_v3_media_objects WHERE id=$1 AND expires_at>now() {lock}"
    ))
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(storage)?
    .ok_or_else(missing)?;
    Ok((tx, user, authority))
}
async fn upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, part)): Path<(String, i32)>,
    Query(input): Query<Access>,
    bytes: Bytes,
) -> Result<StatusCode, Failure> {
    let (mut tx, user, authority) = access(&state, &headers, &id, &input.device_id, true).await?;
    let row=sqlx::query("SELECT owner,source,authority,size,hash,published FROM direct_v3_media_objects WHERE id=$1").bind(&id).fetch_one(&mut *tx).await.map_err(storage)?;
    if row.get::<String, _>("owner") != user
        || row.get::<String, _>("source") != input.device_id
        || row.get::<Vec<u8>, _>("authority") != authority
    {
        return Err(missing());
    }
    let reference = Reference {
        size: row.get::<i64, _>("size") as u64,
        hash: row
            .get::<Vec<u8>, _>("hash")
            .try_into()
            .map_err(|_| missing())?,
    };
    if bytes.len() != reference.chunk_len(part).map_err(codec)? {
        return Err(bad());
    }
    let old = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT data FROM direct_v3_media_chunks WHERE object_id=$1 AND part=$2",
    )
    .bind(&id)
    .bind(part)
    .fetch_optional(&mut *tx)
    .await
    .map_err(storage)?;
    if let Some(old) = old {
        if old != bytes.as_ref() {
            return Err(conflict());
        }
    } else {
        if row.get::<bool, _>("published") {
            return Err(conflict());
        }
        sqlx::query("INSERT INTO direct_v3_media_chunks(object_id,part,data) VALUES($1,$2,$3)")
            .bind(&id)
            .bind(part)
            .bind(bytes.as_ref())
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
    }
    tx.commit().await.map_err(storage)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn download(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, part)): Path<(String, i32)>,
    Query(input): Query<Access>,
) -> Result<Bytes, Failure> {
    if !(0..=20).contains(&part) {
        return Err(bad());
    }
    let (mut tx, user, authority) = access(&state, &headers, &id, &input.device_id, false).await?;
    let data=sqlx::query_scalar::<_,Vec<u8>>("SELECT c.data FROM direct_v3_media_objects o JOIN direct_v3_media_audience a ON a.object_id=o.id JOIN direct_v3_media_chunks c ON c.object_id=o.id WHERE o.id=$1 AND o.published=true AND a.account=$2 AND a.device=$3 AND a.authority=$4 AND c.part=$5").bind(&id).bind(&user).bind(&input.device_id).bind(authority.as_slice()).bind(part).fetch_optional(&mut *tx).await.map_err(storage)?.ok_or_else(missing)?;
    tx.commit().await.map_err(storage)?;
    Ok(Bytes::from(data))
}
async fn publish_media(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<Submission>,
) -> Result<Json<Outcome>, Failure> {
    input.to_wire().map_err(codec)?;
    publish_batch(state, headers, input.batch.clone(), Some(input)).await
}
pub(super) async fn verify_existing(tx: &mut Tx<'_>, input: &Submission) -> Result<(), Failure> {
    let old: Vec<u8> =
        sqlx::query_scalar("SELECT binding FROM direct_v3_media_published WHERE id=$1")
            .bind(&input.batch.header.id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(storage)?
            .ok_or_else(conflict)?;
    if old != input.digest().map_err(codec)? {
        return Err(conflict());
    }
    Ok(())
}
pub(super) async fn validate_publication(
    tx: &mut Tx<'_>,
    input: &Submission,
    authority: [u8; 32],
) -> Result<(), Failure> {
    let batch = &input.batch;
    let row=sqlx::query("SELECT owner,source,peer,authority,size,hash,published FROM direct_v3_media_objects WHERE id=$1 AND expires_at>now() FOR UPDATE").bind(&batch.header.id).fetch_optional(&mut **tx).await.map_err(storage)?.ok_or_else(missing)?;
    if row.get::<String, _>("owner") != batch.header.sender
        || row.get::<String, _>("source") != batch.header.sender_device
        || row.get::<String, _>("peer") != batch.header.peer
        || row.get::<Vec<u8>, _>("authority") != authority
        || row.get::<i64, _>("size") as u64 != input.object.size
        || row.get::<Vec<u8>, _>("hash") != input.object.hash
        || row.get::<bool, _>("published")
    {
        return Err(conflict());
    }
    let chunks = sqlx::query(
        "SELECT part,data FROM direct_v3_media_chunks WHERE object_id=$1 ORDER BY part",
    )
    .bind(&batch.header.id)
    .fetch_all(&mut **tx)
    .await
    .map_err(storage)?;
    if chunks.len() != input.object.size.div_ceil(CHUNK as u64) as usize {
        return Err(conflict());
    }
    let mut digest = Sha256::new();
    for (part, row) in chunks.iter().enumerate() {
        let bytes: Vec<u8> = row.get("data");
        if row.get::<i32, _>("part") != part as i32
            || bytes.len() != input.object.chunk_len(part as i32).map_err(codec)?
        {
            return Err(conflict());
        }
        digest.update(&bytes);
    }
    if digest.finalize().as_slice() != input.object.hash {
        return Err(conflict());
    }
    Ok(())
}
pub(super) async fn commit_publication(tx: &mut Tx<'_>, input: &Submission) -> Result<(), Failure> {
    let h = &input.batch.header;
    sqlx::query("UPDATE direct_v3_media_objects SET published=true WHERE id=$1")
        .bind(&h.id)
        .execute(&mut **tx)
        .await
        .map_err(storage)?;
    for (account, directory) in [
        (&h.sender, &h.sender_directory),
        (&h.peer, &h.peer_directory),
    ] {
        for member in &directory.members {
            sqlx::query("INSERT INTO direct_v3_media_audience(object_id,account,device,authority) VALUES($1,$2,$3,$4)").bind(&h.id).bind(account).bind(&member.device.device_id).bind(member.authorization_hash.as_slice()).execute(&mut **tx).await.map_err(storage)?;
        }
    }
    sqlx::query("INSERT INTO direct_v3_media_published(id,binding) VALUES($1,$2)")
        .bind(&h.id)
        .bind(input.digest().map_err(codec)?.as_slice())
        .execute(&mut **tx)
        .await
        .map_err(storage)?;
    Ok(())
}
