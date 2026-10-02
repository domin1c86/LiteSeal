//! Atomic old-capability consumption with a recoverable encrypted successor.
use super::*;
use liteseal_shared::{device_activation::refresh as r, trusted_device::DeviceState};
pub const MIGRATION:&str="
ALTER TABLE sessions ADD COLUMN v3_family TEXT REFERENCES sessions(id);
UPDATE sessions SET v3_family=id WHERE v3_authority IS NOT NULL;
CREATE INDEX session_v3_family ON sessions(v3_family);
CREATE TABLE device_session_refreshes (
 id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),device_id TEXT NOT NULL REFERENCES devices(id),
 previous_session TEXT NOT NULL REFERENCES sessions(id),refresh_hash TEXT NOT NULL,
 digest BYTEA NOT NULL CHECK(octet_length(digest)=32),request BYTEA NOT NULL CHECK(octet_length(request)<=8192),
 challenge BYTEA NOT NULL CHECK(octet_length(challenge)<=8192),
 proof_hash BYTEA CHECK(octet_length(proof_hash)=32),response BYTEA CHECK(octet_length(response)<=16384),
 successor_session TEXT REFERENCES sessions(id),
 CHECK((proof_hash IS NULL AND response IS NULL AND successor_session IS NULL) OR (proof_hash IS NOT NULL AND response IS NOT NULL AND successor_session IS NOT NULL))
);
CREATE INDEX device_refresh_owner ON device_session_refreshes(user_id,device_id);
CREATE INDEX device_refresh_parent ON device_session_refreshes(previous_session);
";
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/v3/refresh/begin", post(begin))
        .route("/auth/v3/refresh/:id/proof", post(prove))
}
async fn scope(
    tx: &mut Tx<'_>,
    request: &r::Start,
    realm: &str,
) -> Result<(DeviceState, Enable, bool), Failure> {
    let (current, events) = trusted_devices::directory(tx, &request.account, realm).await?;
    let event = mode(tx, &current).await?;
    if !Directory::from_state(&current)
        .members
        .iter()
        .any(|m| m.device == request.device && m.authorization_hash == request.authorization)
    {
        return Err(denied());
    }
    let device = sqlx::query(
        "SELECT public_key,ed25519_pk FROM devices WHERE id=$1 AND user_id=$2 AND revoked=false",
    )
    .bind(&request.device.device_id)
    .bind(&request.account)
    .fetch_optional(&mut **tx)
    .await
    .map_err(storage)?
    .ok_or_else(denied)?;
    if device.get::<Vec<u8>, _>("public_key") != request.device.encryption_key
        || device.get::<Vec<u8>, _>("ed25519_pk") != request.device.signing_key
    {
        return Err(denied());
    }
    if request.revision > current.revision() {
        return Err(conflict());
    }
    let mut original = DeviceState::pin(current.anchor().clone()).map_err(|_| denied())?;
    for e in events.iter().take(request.revision as usize) {
        original = original.apply(e).map_err(|_| denied())?;
    }
    request
        .verify_state(&original, &event, request.issued_at)
        .map_err(|_| denied())?;
    Ok((original, event, request.revision == current.revision()))
}
async fn previous(
    tx: &mut Tx<'_>,
    request: &r::Start,
    token_hash: &str,
) -> Result<sqlx::postgres::PgRow, Failure> {
    let row=sqlx::query("SELECT revoked,v3_authority,v3_family,refresh_expires_at>now() AS live FROM sessions WHERE id=$1 AND user_id=$2 AND device_id=$3 AND refresh_token_hash=$4 FOR UPDATE")
        .bind(&request.session).bind(&request.account).bind(&request.device.device_id).bind(token_hash).fetch_optional(&mut **tx).await.map_err(storage)?.ok_or_else(unauthorized)?;
    if row.get::<Option<Vec<u8>>, _>("v3_authority").as_deref()
        != Some(request.authorization.as_slice())
        || hex::decode(token_hash).map_err(|_| unauthorized())? != request.refresh_hash
    {
        return Err(unauthorized());
    }
    Ok(row)
}
async fn replay(
    tx: &mut Tx<'_>,
    row: &sqlx::postgres::PgRow,
    request: &r::Start,
) -> Result<Option<r::Reply>, Failure> {
    if row.get::<String, _>("user_id") != request.account
        || row.get::<String, _>("device_id") != request.device.device_id
        || row.get::<String, _>("previous_session") != request.session
        || row.get::<Vec<u8>, _>("digest") != request.digest().map_err(|_| bad())?
    {
        return Err(conflict());
    }
    let Some(response) = row.get::<Option<Vec<u8>>, _>("response") else {
        return Ok(None);
    };
    let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sessions WHERE id=$1 AND user_id=$2 AND device_id=$3 AND v3_authority=$4 AND revoked=false AND refresh_expires_at>now())")
        .bind(row.get::<Option<String>,_>("successor_session")).bind(&request.account).bind(&request.device.device_id).bind(request.authorization.as_slice()).fetch_one(&mut **tx).await.map_err(storage)?;
    if !valid {
        return Err(gone());
    }
    serde_json::from_slice(&response)
        .map(Some)
        .map_err(|_| denied())
}
async fn begin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<r::Start>,
) -> Result<Json<r::Reply>, Failure> {
    let realm = origin(&state)?;
    uuid(&request.id)?;
    uuid(&request.account)?;
    let token_hash = service::hash_token(bearer(&headers)?);
    let known:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sessions WHERE id=$1 AND user_id=$2 AND device_id=$3 AND refresh_token_hash=$4 AND v3_authority IS NOT NULL)")
        .bind(&request.session).bind(&request.account).bind(&request.device.device_id).bind(&token_hash).fetch_one(state.db.pool()).await.map_err(storage)?;
    if !known {
        return Err(unauthorized());
    }
    let mut tx = state.db.pool().begin().await.map_err(storage)?;
    trusted_devices::lock(&mut tx, &request.account).await?;
    let (directory, event, current) = scope(&mut tx, &request, realm).await?;
    let old = previous(&mut tx, &request, &token_hash).await?;
    let stored = sqlx::query("SELECT * FROM device_session_refreshes WHERE id=$1 FOR UPDATE")
        .bind(&request.id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage)?;
    let reply = if let Some(stored) = stored {
        if let Some(result) = replay(&mut tx, &stored, &request).await? {
            tx.commit().await.map_err(storage)?;
            return Ok(Json(result));
        }
        if old.get::<bool, _>("revoked") || !old.get::<bool, _>("live") {
            return Err(gone());
        }
        let challenge: Challenge =
            serde_json::from_slice(&stored.get::<Vec<u8>, _>("challenge")).map_err(|_| denied())?;
        challenge
            .verify_state(&directory, &event, now())
            .map_err(|_| gone())?;
        r::Reply::Pending {
            request: request.digest().map_err(|_| bad())?,
            challenge: Box::new(challenge),
        }
    } else {
        if !current {
            return Err(conflict());
        }
        request
            .verify_state(&directory, &event, now())
            .map_err(|_| gone())?;
        if old.get::<bool, _>("revoked") || !old.get::<bool, _>("live") {
            return Err(gone());
        }
        // Delete only unusable capabilities. Live originals retain ID fences.
        sqlx::query("DELETE FROM device_session_refreshes r USING sessions s WHERE r.user_id=$1 AND r.previous_session=s.id AND ((r.successor_session IS NULL AND (s.refresh_expires_at<=now() OR s.revoked=true)) OR EXISTS(SELECT 1 FROM sessions next WHERE next.id=r.successor_session AND (next.revoked=true OR next.refresh_expires_at<=now())))")
            .bind(&request.account).execute(&mut *tx).await.map_err(storage)?;
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM device_session_refreshes WHERE user_id=$1")
                .bind(&request.account)
                .fetch_one(&mut *tx)
                .await
                .map_err(storage)?;
        if count >= 4096 {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                "原设备续期记录达到上限，请稍后查询原任务".into(),
            ));
        }
        let challenge = Challenge::make(
            &directory,
            &event,
            &request.id,
            &request.device.device_id,
            now(),
        )
        .map_err(|_| bad())?;
        let encoded = encode(&request)?;
        if encoded.len() > 8192 {
            return Err(bad());
        }
        sqlx::query("INSERT INTO device_session_refreshes(id,user_id,device_id,previous_session,refresh_hash,digest,request,challenge) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(&request.id).bind(&request.account).bind(&request.device.device_id).bind(&request.session).bind(&token_hash).bind(request.digest().map_err(|_|bad())?.as_slice()).bind(encoded).bind(encode(&challenge)?).execute(&mut *tx).await.map_err(storage)?;
        r::Reply::Pending {
            request: request.digest().map_err(|_| bad())?,
            challenge: Box::new(challenge),
        }
    };
    tx.commit().await.map_err(storage)?;
    Ok(Json(reply))
}
async fn prove(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(proof): Json<Proof>,
) -> Result<Json<r::Reply>, Failure> {
    let realm = origin(&state)?;
    uuid(&id)?;
    let token_hash = service::hash_token(bearer(&headers)?);
    let user: String = sqlx::query_scalar(
        "SELECT user_id FROM device_session_refreshes WHERE id=$1 AND refresh_hash=$2",
    )
    .bind(&id)
    .bind(&token_hash)
    .fetch_optional(state.db.pool())
    .await
    .map_err(storage)?
    .ok_or_else(unauthorized)?;
    let mut tx = state.db.pool().begin().await.map_err(storage)?;
    trusted_devices::lock(&mut tx, &user).await?;
    let row=sqlx::query("SELECT * FROM device_session_refreshes WHERE id=$1 AND user_id=$2 AND refresh_hash=$3 FOR UPDATE").bind(&id).bind(&user).bind(&token_hash).fetch_one(&mut *tx).await.map_err(storage)?;
    let request: r::Start =
        serde_json::from_slice(&row.get::<Vec<u8>, _>("request")).map_err(|_| denied())?;
    let challenge: Challenge =
        serde_json::from_slice(&row.get::<Vec<u8>, _>("challenge")).map_err(|_| denied())?;
    let (directory, event, _) = scope(&mut tx, &request, realm).await?;
    let old = previous(&mut tx, &request, &token_hash).await?;
    proof.verify(&challenge).map_err(|_| denied())?;
    let digest = proof.digest().map_err(|_| bad())?;
    if let Some(stored) = row.get::<Option<Vec<u8>>, _>("proof_hash") {
        if stored != digest {
            return Err(conflict());
        }
    }
    if let Some(result) = replay(&mut tx, &row, &request).await? {
        tx.commit().await.map_err(storage)?;
        return Ok(Json(result));
    }
    if old.get::<bool, _>("revoked") || !old.get::<bool, _>("live") {
        return Err(gone());
    }
    challenge
        .verify_state(&directory, &event, now())
        .map_err(|_| gone())?;
    let at = now();
    let session = Session {
        id: uuid::Uuid::new_v4().to_string(),
        account: request.account.clone(),
        device: request.device.device_id.clone(),
        authorization: request.authorization,
        mode: request.mode,
        access_token: service::generate_token(),
        refresh_token: service::generate_token(),
        expires_at: at + 30 * 60 * 1000,
        refresh_expires_at: at + 30 * 24 * 60 * 60 * 1000,
    };
    let result = r::Reply::Accepted {
        request: request.digest().map_err(|_| bad())?,
        challenge: Box::new(challenge.clone()),
        envelope: r::Envelope::seal(&request, &challenge, &session).map_err(|_| denied())?,
    };
    let consumed=sqlx::query("UPDATE sessions SET revoked=true WHERE id=$1 AND revoked=false AND refresh_expires_at>now()").bind(&request.session).execute(&mut *tx).await.map_err(storage)?;
    if consumed.rows_affected() != 1 {
        return Err(gone());
    }
    sqlx::query("INSERT INTO sessions(id,user_id,device_id,access_token_hash,refresh_token_hash,expires_at,refresh_expires_at,created_at,v3_authority,v3_family) VALUES($1,$2,$3,$4,$5,to_timestamp($6::DOUBLE PRECISION/1000),to_timestamp($7::DOUBLE PRECISION/1000),now(),$8,$9)")
        .bind(&session.id).bind(&session.account).bind(&session.device).bind(service::hash_token(&session.access_token)).bind(service::hash_token(&session.refresh_token)).bind(session.expires_at).bind(session.refresh_expires_at).bind(session.authorization.as_slice()).bind(old.get::<Option<String>,_>("v3_family").unwrap_or_else(||request.session.clone())).execute(&mut *tx).await.map_err(storage)?;
    sqlx::query("UPDATE device_session_refreshes SET proof_hash=$2,response=$3,successor_session=$4 WHERE id=$1").bind(&id).bind(digest.as_slice()).bind(encode(&result)?).bind(&session.id).execute(&mut *tx).await.map_err(storage)?;
    tx.commit().await.map_err(storage)?;
    Ok(Json(result))
}
