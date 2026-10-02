//! T23 control plane. Authorization records are deliberately separate from
//! operational devices until the complete multi-device message protocol exists.
use crate::{
    auth::{handlers, service},
    state::AppState,
};
use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use liteseal_shared::trusted_device::*;
use serde::Deserialize;
use sqlx::{Postgres, Row, Transaction};
type Failure = (StatusCode, String);
type Tx<'a> = Transaction<'a, Postgres>;
pub const MIGRATION: &str = "
CREATE TABLE device_authorization_roots (
 user_id TEXT PRIMARY KEY REFERENCES users(id), anchor BYTEA NOT NULL CHECK(octet_length(anchor)<=2048),
 revision BIGINT NOT NULL CHECK(revision BETWEEN 0 AND 4096), head BYTEA NOT NULL CHECK(octet_length(head)=32)
);
CREATE TABLE device_authorization_events (
 user_id TEXT NOT NULL REFERENCES users(id), revision BIGINT NOT NULL CHECK(revision BETWEEN 1 AND 4096),
 event_id TEXT NOT NULL, payload BYTEA NOT NULL CHECK(octet_length(payload)<=16384),
 digest BYTEA NOT NULL CHECK(octet_length(digest)=32), PRIMARY KEY(user_id,revision), UNIQUE(user_id,event_id)
);
CREATE TABLE device_join_requests (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), token_hash TEXT, password_state TEXT NOT NULL CHECK(length(password_state)=64),
 phase TEXT NOT NULL CHECK(phase IN ('begun','ready','challenged','proved','authorized','cancelled','revoked')),
 expires_at BIGINT NOT NULL, payload BYTEA NOT NULL CHECK(octet_length(payload)<=16384)
);
CREATE INDEX device_join_active ON device_join_requests(user_id,expires_at) WHERE phase IN ('begun','ready','challenged','proved');
CREATE TABLE device_authorizations (
 device_id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), name TEXT NOT NULL,
 encryption_key BYTEA NOT NULL CHECK(octet_length(encryption_key)=32), signing_key BYTEA NOT NULL CHECK(octet_length(signing_key)=32),
 grant_hash BYTEA NOT NULL CHECK(octet_length(grant_hash)=32), request_id TEXT NOT NULL REFERENCES device_join_requests(id),
 revoked BOOLEAN NOT NULL DEFAULT false, UNIQUE(user_id,encryption_key), UNIQUE(user_id,signing_key)
);
CREATE UNIQUE INDEX one_secondary_authorization ON device_authorizations(user_id) WHERE revoked=false;
";
pub const CANCEL_MIGRATION: &str = "
CREATE TABLE device_event_cancellations (
 user_id TEXT NOT NULL REFERENCES users(id), event_id TEXT NOT NULL,
 digest BYTEA NOT NULL CHECK(octet_length(digest)=32), PRIMARY KEY(user_id,event_id)
);
";
fn unavailable(_: sqlx::Error) -> Failure {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "设备授权存储暂不可用".into(),
    )
}
fn corrupt() -> Failure {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "设备授权记录无法验证".into(),
    )
}
fn bad() -> Failure {
    (StatusCode::BAD_REQUEST, "无效设备授权参数".into())
}
fn conflict() -> Failure {
    (StatusCode::CONFLICT, "设备授权版本、编号或阶段冲突".into())
}
fn gone() -> Failure {
    (StatusCode::GONE, "设备申请已过期、取消或撤销".into())
}
fn unauthorized() -> Failure {
    (
        StatusCode::UNAUTHORIZED,
        "需要有效设备会话或申请凭据".into(),
    )
}
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
fn origin(state: &AppState) -> Result<&str, Failure> {
    state
        .device_authorization_origin
        .as_deref()
        .ok_or((StatusCode::NOT_FOUND, "设备授权未启用".into()))
}
fn uuid(value: &str) -> Result<(), Failure> {
    uuid::Uuid::parse_str(value).map(|_| ()).map_err(|_| bad())
}
fn bearer(headers: &HeaderMap) -> Result<&str, Failure> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(unauthorized)
}
fn device_error(error: DeviceError) -> Failure {
    match error {
        DeviceError::Expired => gone(),
        DeviceError::Chain | DeviceError::Conflict => conflict(),
        DeviceError::Shape => bad(),
        DeviceError::Proof => (StatusCode::FORBIDDEN, "设备签名或密钥证明无效".into()),
    }
}
fn phase(phase: &JoinPhase) -> &'static str {
    match phase {
        JoinPhase::Begun => "begun",
        JoinPhase::Ready => "ready",
        JoinPhase::Challenged => "challenged",
        JoinPhase::Proved => "proved",
        JoinPhase::Authorized => "authorized",
        JoinPhase::Cancelled => "cancelled",
        JoinPhase::Revoked => "revoked",
        JoinPhase::Expired => "expired",
    }
}
fn active(status: &JoinStatus, at: i64) -> bool {
    matches!(
        status.phase,
        JoinPhase::Begun | JoinPhase::Ready | JoinPhase::Challenged | JoinPhase::Proved
    ) && status.ticket.expires_at > at
}
fn public_status(mut status: JoinStatus, at: i64) -> JoinStatus {
    if matches!(
        status.phase,
        JoinPhase::Begun | JoinPhase::Ready | JoinPhase::Challenged | JoinPhase::Proved
    ) && status.ticket.expires_at <= at
    {
        status.phase = JoinPhase::Expired;
    }
    status
}
fn encode(value: &impl serde::Serialize) -> Result<Vec<u8>, Failure> {
    let bytes = serde_json::to_vec(value).map_err(|_| bad())?;
    if bytes.len() > MAX_DEVICE_EVENT_BYTES {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "设备记录过大".into()));
    }
    Ok(bytes)
}
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/devices/join_requests", post(begin).get(list))
        .route("/devices/join_requests/:id", get(status).delete(cancel))
        .route("/devices/join_requests/:id/intent", post(intent))
        .route("/devices/join_requests/:id/challenge", post(challenge))
        .route("/devices/join_requests/:id/proof", post(proof))
        .route("/devices/join_requests/:id/manifest", get(join_manifest))
        .route("/devices/grants", post(grant))
        .route("/devices/revoke", post(revoke))
        .route("/devices/events/cancel", post(cancel_event))
        .route("/users/:user_id/device_manifest", get(manifest))
        .layer(DefaultBodyLimit::max(MAX_DEVICE_EVENT_BYTES))
}
pub(crate) async fn lock(tx: &mut Tx<'_>, user: &str) -> Result<(), Failure> {
    sqlx::query("SET LOCAL lock_timeout='5s'")
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
    sqlx::query("SET LOCAL statement_timeout='10s'")
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(user)
        .fetch_optional(&mut **tx)
        .await
        .map_err(unavailable)?
        .ok_or_else(unauthorized)?;
    Ok(())
}
pub(crate) async fn directory(
    tx: &mut Tx<'_>,
    user: &str,
    expected_origin: &str,
) -> Result<(DeviceState, Vec<DeviceEvent>), Failure> {
    let stored =
        sqlx::query("SELECT anchor,revision,head FROM device_authorization_roots WHERE user_id=$1")
            .bind(user)
            .fetch_optional(&mut **tx)
            .await
            .map_err(unavailable)?;
    let (anchor, revision, head) = if let Some(row) = stored {
        let bytes: Vec<u8> = row.try_get("anchor").map_err(unavailable)?;
        if bytes.len() > 2048 {
            return Err(corrupt());
        }
        let anchor: Anchor = serde_json::from_slice(&bytes).map_err(|_| corrupt())?;
        let revision: i64 = row.try_get("revision").map_err(unavailable)?;
        let head: Vec<u8> = row.try_get("head").map_err(unavailable)?;
        (anchor, revision, head)
    } else {
        let row = sqlx::query("SELECT id,public_key,ed25519_pk,revoked FROM devices WHERE user_id=$1 ORDER BY created_at,id LIMIT 1")
            .bind(user).fetch_optional(&mut **tx).await.map_err(unavailable)?.ok_or_else(corrupt)?;
        if row.try_get::<bool, _>("revoked").map_err(unavailable)? {
            return Err(gone());
        }
        let encryption: Vec<u8> = row.try_get("public_key").map_err(unavailable)?;
        let signing: Vec<u8> = row.try_get("ed25519_pk").map_err(unavailable)?;
        let anchor = Anchor {
            origin: expected_origin.into(),
            account: user.into(),
            root: DeviceIdentity {
                device_id: row.try_get("id").map_err(unavailable)?,
                encryption_key: encryption.try_into().map_err(|_| corrupt())?,
                signing_key: signing.try_into().map_err(|_| corrupt())?,
            },
        };
        let head = anchor.hash();
        (anchor, 0, head)
    };
    if anchor.origin != expected_origin || anchor.account != user {
        return Err(corrupt());
    }
    let mut state = DeviceState::pin(anchor).map_err(|_| corrupt())?;
    let rows = sqlx::query("SELECT revision,event_id,payload,digest FROM device_authorization_events WHERE user_id=$1 ORDER BY revision LIMIT 4097")
        .bind(user).fetch_all(&mut **tx).await.map_err(unavailable)?;
    let mut events = vec![];
    for row in rows {
        let payload: Vec<u8> = row.try_get("payload").map_err(unavailable)?;
        if payload.len() > MAX_DEVICE_EVENT_BYTES {
            return Err(corrupt());
        }
        let event: DeviceEvent = serde_json::from_slice(&payload).map_err(|_| corrupt())?;
        if row.try_get::<i64, _>("revision").map_err(unavailable)? != event.revision as i64
            || event.revision != state.revision() + 1
            || row.try_get::<String, _>("event_id").map_err(unavailable)? != event.id
            || row.try_get::<Vec<u8>, _>("digest").map_err(unavailable)? != event.hash()
        {
            return Err(corrupt());
        }
        state = state.apply(&event).map_err(|_| corrupt())?;
        events.push(event);
    }
    if revision < 0 || revision as u64 != state.revision() || head != state.head() {
        return Err(corrupt());
    }
    // The operational device table is untouched; this separate projection must match the chain.
    let rows = sqlx::query("SELECT device_id,encryption_key,signing_key,grant_hash FROM device_authorizations WHERE user_id=$1 AND revoked=false")
        .bind(user).fetch_all(&mut **tx).await.map_err(unavailable)?;
    match (state.secondary(), rows.as_slice()) {
        (None, []) => {}
        (Some(device), [row])
            if row.try_get::<String, _>("device_id").map_err(unavailable)? == device.device_id
                && row
                    .try_get::<Vec<u8>, _>("encryption_key")
                    .map_err(unavailable)?
                    == device.encryption_key
                && row
                    .try_get::<Vec<u8>, _>("signing_key")
                    .map_err(unavailable)?
                    == device.signing_key
                && row
                    .try_get::<Vec<u8>, _>("grant_hash")
                    .map_err(unavailable)?
                    == state.grant_hash().unwrap_or_default() => {}
        _ => return Err(corrupt()),
    }
    Ok((state, events))
}
async fn save_root(tx: &mut Tx<'_>, state: &DeviceState) -> Result<(), Failure> {
    sqlx::query(
        "INSERT INTO device_authorization_roots(user_id,anchor,revision,head) VALUES($1,$2,$3,$4)
        ON CONFLICT(user_id) DO UPDATE SET revision=EXCLUDED.revision,head=EXCLUDED.head",
    )
    .bind(&state.anchor().account)
    .bind(encode(state.anchor())?)
    .bind(state.revision() as i64)
    .bind(state.head())
    .execute(&mut **tx)
    .await
    .map_err(unavailable)?;
    Ok(())
}
pub(crate) async fn root_session(
    tx: &mut Tx<'_>,
    headers: &HeaderMap,
    state: &DeviceState,
    device: &str,
) -> Result<(), Failure> {
    if device != state.anchor().root.device_id {
        return Err((StatusCode::FORBIDDEN, "仅原设备可授权或撤销".into()));
    }
    let row = sqlx::query("SELECT public_key,ed25519_pk FROM devices WHERE id=$1 AND user_id=$2 AND revoked=false FOR SHARE")
        .bind(device).bind(&state.anchor().account).fetch_optional(&mut **tx).await.map_err(unavailable)?.ok_or_else(unauthorized)?;
    if row
        .try_get::<Vec<u8>, _>("public_key")
        .map_err(unavailable)?
        != state.anchor().root.encryption_key
        || row
            .try_get::<Vec<u8>, _>("ed25519_pk")
            .map_err(unavailable)?
            != state.anchor().root.signing_key
    {
        return Err(corrupt());
    }
    let valid = sqlx::query(
        "SELECT 1 FROM sessions WHERE access_token_hash=$1 AND user_id=$2 AND device_id=$3
        AND revoked=false AND expires_at>now() FOR SHARE",
    )
    .bind(service::hash_token(bearer(headers)?))
    .bind(&state.anchor().account)
    .bind(device)
    .fetch_optional(&mut **tx)
    .await
    .map_err(unavailable)?;
    if valid.is_none() {
        return Err(unauthorized());
    }
    Ok(())
}
async fn admit(state: &AppState, headers: &HeaderMap) -> Result<String, Failure> {
    origin(state)?;
    let user = handlers::user_from_bearer(state, headers)
        .await
        .map_err(|s| (s, "会话不可用".into()))?;
    rate(state, &user, 60).await?;
    Ok(user)
}
async fn rate(state: &AppState, key: &str, limit: i64) -> Result<(), Failure> {
    if !state
        .db
        .hit_rate_limit(&format!("device-control:{key}"), limit, 60)
        .await
        .map_err(unavailable)?
    {
        return Err((StatusCode::TOO_MANY_REQUESTS, "设备授权请求过于频繁".into()));
    }
    Ok(())
}
async fn read_join(tx: &mut Tx<'_>, id: &str) -> Result<(JoinStatus, Option<String>), Failure> {
    uuid(id)?;
    let row = sqlx::query("SELECT r.payload,r.token_hash,r.phase,r.password_state,u.password_hash FROM device_join_requests r JOIN users u ON u.id=r.user_id WHERE r.id=$1")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(unavailable)?
        .ok_or((StatusCode::NOT_FOUND, "申请不存在".into()))?;
    let bytes: Vec<u8> = row.try_get("payload").map_err(unavailable)?;
    if bytes.len() > MAX_DEVICE_EVENT_BYTES {
        return Err(corrupt());
    }
    let mut status: JoinStatus = serde_json::from_slice(&bytes).map_err(|_| corrupt())?;
    if status.ticket.id != id
        || row.try_get::<String, _>("phase").map_err(unavailable)? != phase(&status.phase)
    {
        return Err(corrupt());
    }
    let current: String = row.try_get("password_hash").map_err(unavailable)?;
    if active(&status, now())
        && row
            .try_get::<String, _>("password_state")
            .map_err(unavailable)?
            != service::hash_token(&current)
    {
        status.phase = JoinPhase::Cancelled;
    }
    Ok((status, row.try_get("token_hash").map_err(unavailable)?))
}
async fn save_join(tx: &mut Tx<'_>, status: &JoinStatus, clear_token: bool) -> Result<(), Failure> {
    sqlx::query("UPDATE device_join_requests SET phase=$2,payload=$3,token_hash=CASE WHEN $4 THEN NULL ELSE token_hash END WHERE id=$1")
        .bind(&status.ticket.id).bind(phase(&status.phase)).bind(encode(status)?).bind(clear_token)
        .execute(&mut **tx).await.map_err(unavailable)?;
    Ok(())
}
async fn join_account(state: &AppState, headers: &HeaderMap, id: &str) -> Result<String, Failure> {
    origin(state)?;
    uuid(id)?;
    let row = sqlx::query(
        "SELECT r.user_id,r.password_state,r.phase,u.password_hash FROM device_join_requests r JOIN users u ON u.id=r.user_id WHERE r.id=$1 AND r.token_hash=$2",
    )
    .bind(id)
    .bind(service::hash_token(bearer(headers)?))
    .fetch_optional(state.db.pool())
    .await
    .map_err(unavailable)?;
    let row = row.ok_or_else(unauthorized)?;
    let current: String = row.try_get("password_hash").map_err(unavailable)?;
    if row.try_get::<String, _>("phase").map_err(unavailable)? != "authorized"
        && row
            .try_get::<String, _>("password_state")
            .map_err(unavailable)?
            != service::hash_token(&current)
    {
        return Err(unauthorized());
    }
    let user: String = row.try_get("user_id").map_err(unavailable)?;
    rate(state, &user, 120).await?;
    Ok(user)
}
fn join_token(stored: &Option<String>, headers: &HeaderMap) -> Result<(), Failure> {
    if stored.as_deref() != Some(&service::hash_token(bearer(headers)?)) {
        return Err(unauthorized());
    }
    Ok(())
}

async fn begin(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<std::net::SocketAddr>,
    Json(input): Json<JoinStartRequest>,
) -> Result<Json<JoinStatus>, Failure> {
    let configured = origin(&state)?;
    uuid(&input.request_id)?;
    if input.request_token.len() != 64
        || !input.request_token.bytes().all(|b| b.is_ascii_hexdigit())
        || input.username.len() > 128
        || input.password.len() > 1024
        || input.device_name.trim().is_empty()
        || input.device_name.chars().count() > 80
        || input.device_name.chars().any(char::is_control)
    {
        return Err(bad());
    }
    service::validate_key_material(&input.encryption_key, &input.signing_key).map_err(|_| bad())?;
    handlers::enforce_auth_rate_limit(&state, input.username.trim(), remote.ip())
        .await
        .map_err(|s| (s, "申请验证不可用".into()))?;
    let user = state
        .db
        .get_user_by_username(input.username.trim())
        .await
        .map_err(unavailable)?
        .ok_or_else(unauthorized)?;
    if !service::verify_password(&input.password, &user.password_hash) {
        return Err(unauthorized());
    }
    let mut tx = state.db.pool().begin().await.map_err(unavailable)?;
    lock(&mut tx, &user.id).await?;
    // Password changes and intent creation serialize on the account row.
    let current: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id=$1")
        .bind(&user.id)
        .fetch_one(&mut *tx)
        .await
        .map_err(unavailable)?;
    if current != user.password_hash {
        return Err(unauthorized());
    }
    let (directory, _) = directory(&mut tx, &user.id, configured).await?;
    let exists = sqlx::query("SELECT user_id FROM device_join_requests WHERE id=$1")
        .bind(&input.request_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(unavailable)?;
    if let Some(row) = exists {
        if row.try_get::<String, _>("user_id").map_err(unavailable)? != user.id {
            return Err(conflict());
        }
        let (status, token) = read_join(&mut tx, &input.request_id).await?;
        if token.as_deref() != Some(&service::hash_token(&input.request_token))
            || status.ticket.device.encryption_key != input.encryption_key
            || status.ticket.device.signing_key != input.signing_key
            || status.ticket.device_name != input.device_name
            || status.ticket.anchor != *directory.anchor()
        {
            return Err(conflict());
        }
        tx.commit().await.map_err(unavailable)?;
        return Ok(Json(public_status(status, now())));
    }
    if directory.secondary().is_some() {
        return Err(conflict());
    }
    let at = now();
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM device_join_requests WHERE user_id=$1")
            .bind(&user.id)
            .fetch_one(&mut *tx)
            .await
            .map_err(unavailable)?;
    let pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM device_join_requests WHERE user_id=$1 AND expires_at>$2 AND password_state=$3
        AND phase IN ('begun','ready','challenged','proved')",
    )
    .bind(&user.id)
    .bind(at)
    .bind(service::hash_token(&current))
    .fetch_one(&mut *tx)
    .await
    .map_err(unavailable)?;
    if count >= 4096 || pending != 0 {
        return Err(conflict());
    }
    if input.encryption_key == directory.anchor().root.encryption_key
        || input.signing_key == directory.anchor().root.signing_key
    {
        return Err(conflict());
    }
    let status = JoinStatus {
        ticket: JoinTicket {
            id: input.request_id,
            anchor: directory.anchor().clone(),
            device: DeviceIdentity {
                device_id: uuid::Uuid::new_v4().to_string(),
                encryption_key: input.encryption_key,
                signing_key: input.signing_key,
            },
            device_name: input.device_name,
            server_challenge: liteseal_shared::crypto::random_challenge()
                .map_err(|_| corrupt())?
                .to_vec(),
            issued_at: at,
            expires_at: at + JOIN_LIFETIME_MS,
        },
        phase: JoinPhase::Begun,
        intent: None,
        challenge: None,
        proof: None,
        authorization_id: None,
    };
    save_root(&mut tx, &directory).await?;
    sqlx::query("INSERT INTO device_join_requests(id,user_id,token_hash,phase,expires_at,payload,password_state) VALUES($1,$2,$3,'begun',$4,$5,$6)")
        .bind(&status.ticket.id).bind(&user.id).bind(service::hash_token(&input.request_token)).bind(status.ticket.expires_at)
        .bind(encode(&status)?).bind(service::hash_token(&current)).execute(&mut *tx).await.map_err(unavailable)?;
    tx.commit().await.map_err(unavailable)?;
    Ok(Json(status))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RootAccess {
    device_id: Option<String>,
}
async fn status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(access): Query<RootAccess>,
) -> Result<Json<JoinStatus>, Failure> {
    let user = if access.device_id.is_some() {
        admit(&state, &headers).await?
    } else {
        join_account(&state, &headers, &id).await?
    };
    let mut tx = state.db.pool().begin().await.map_err(unavailable)?;
    lock(&mut tx, &user).await?;
    let (directory, _) = directory(&mut tx, &user, origin(&state)?).await?;
    let (status, token) = read_join(&mut tx, &id).await?;
    if status.ticket.anchor != *directory.anchor() {
        return Err((StatusCode::NOT_FOUND, "申请不存在".into()));
    }
    if let Some(device) = access.device_id {
        root_session(&mut tx, &headers, &directory, &device).await?;
    } else {
        join_token(&token, &headers)?;
    }
    tx.commit().await.map_err(unavailable)?;
    Ok(Json(public_status(status, now())))
}
async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(access): Query<RootAccess>,
) -> Result<Json<Vec<JoinStatus>>, Failure> {
    let user = admit(&state, &headers).await?;
    let device = access.device_id.ok_or_else(bad)?;
    let mut tx = state.db.pool().begin().await.map_err(unavailable)?;
    lock(&mut tx, &user).await?;
    let (directory, _) = directory(&mut tx, &user, origin(&state)?).await?;
    root_session(&mut tx, &headers, &directory, &device).await?;
    let password: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id=$1")
        .bind(&user)
        .fetch_one(&mut *tx)
        .await
        .map_err(unavailable)?;
    let ids: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM device_join_requests WHERE user_id=$1 AND expires_at>$2 AND password_state=$3
        AND phase IN ('ready','challenged','proved') ORDER BY expires_at LIMIT 1",
    )
    .bind(user)
    .bind(now())
    .bind(service::hash_token(&password))
    .fetch_all(&mut *tx)
    .await
    .map_err(unavailable)?;
    let mut result = vec![];
    for id in ids {
        let (status, _) = read_join(&mut tx, &id).await?;
        if active(&status, now()) {
            result.push(status);
        }
    }
    tx.commit().await.map_err(unavailable)?;
    Ok(Json(result))
}
async fn intent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<JoinIntent>,
) -> Result<Json<JoinStatus>, Failure> {
    let user = join_account(&state, &headers, &id).await?;
    let mut tx = state.db.pool().begin().await.map_err(unavailable)?;
    lock(&mut tx, &user).await?;
    let (mut status, token) = read_join(&mut tx, &id).await?;
    join_token(&token, &headers)?;
    if !active(&status, now()) {
        return Err(gone());
    }
    if !status.ticket.matches(&input) {
        return Err(conflict());
    }
    input
        .verify(&status.ticket.anchor, now())
        .map_err(device_error)?;
    if let Some(previous) = &status.intent {
        if previous != &input {
            return Err(conflict());
        }
    } else {
        if status.phase != JoinPhase::Begun {
            return Err(conflict());
        }
        status.intent = Some(input);
        status.phase = JoinPhase::Ready;
        save_join(&mut tx, &status, false).await?;
    }
    tx.commit().await.map_err(unavailable)?;
    Ok(Json(status))
}
async fn challenge(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<ChallengeSubmission>,
) -> Result<Json<JoinStatus>, Failure> {
    let user = admit(&state, &headers).await?;
    let mut tx = state.db.pool().begin().await.map_err(unavailable)?;
    lock(&mut tx, &user).await?;
    let (directory, _) = directory(&mut tx, &user, origin(&state)?).await?;
    root_session(&mut tx, &headers, &directory, &input.device_id).await?;
    let (mut status, _) = read_join(&mut tx, &id).await?;
    if status.ticket.anchor != *directory.anchor() {
        return Err(conflict());
    }
    if !active(&status, now()) {
        return Err(gone());
    }
    input
        .challenge
        .verify(
            &directory,
            status.intent.as_ref().ok_or_else(conflict)?,
            now(),
        )
        .map_err(device_error)?;
    if let Some(previous) = &status.challenge {
        if previous != &input.challenge {
            return Err(conflict());
        }
    } else {
        if status.phase != JoinPhase::Ready {
            return Err(conflict());
        }
        status.challenge = Some(input.challenge);
        status.phase = JoinPhase::Challenged;
        save_join(&mut tx, &status, false).await?;
    }
    tx.commit().await.map_err(unavailable)?;
    Ok(Json(status))
}
async fn proof(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<DeviceProof>,
) -> Result<Json<JoinStatus>, Failure> {
    let user = join_account(&state, &headers, &id).await?;
    let mut tx = state.db.pool().begin().await.map_err(unavailable)?;
    lock(&mut tx, &user).await?;
    let (directory, _) = directory(&mut tx, &user, origin(&state)?).await?;
    let (mut status, token) = read_join(&mut tx, &id).await?;
    join_token(&token, &headers)?;
    if !active(&status, now()) {
        return Err(gone());
    }
    let challenge = status.challenge.as_ref().ok_or_else(conflict)?;
    challenge
        .verify(
            &directory,
            status.intent.as_ref().ok_or_else(conflict)?,
            now(),
        )
        .map_err(device_error)?;
    input
        .verify(challenge, &status.ticket.device)
        .map_err(device_error)?;
    if let Some(previous) = &status.proof {
        if previous != &input {
            return Err(conflict());
        }
    } else {
        if status.phase != JoinPhase::Challenged {
            return Err(conflict());
        }
        status.proof = Some(input);
        status.phase = JoinPhase::Proved;
        save_join(&mut tx, &status, false).await?;
    }
    tx.commit().await.map_err(unavailable)?;
    Ok(Json(status))
}
async fn cancel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(access): Query<RootAccess>,
) -> Result<Json<JoinStatus>, Failure> {
    let user = if access.device_id.is_some() {
        admit(&state, &headers).await?
    } else {
        join_account(&state, &headers, &id).await?
    };
    let mut tx = state.db.pool().begin().await.map_err(unavailable)?;
    lock(&mut tx, &user).await?;
    let (directory, _) = directory(&mut tx, &user, origin(&state)?).await?;
    let (mut status, token) = read_join(&mut tx, &id).await?;
    if status.ticket.anchor != *directory.anchor() {
        return Err(conflict());
    }
    if let Some(device) = access.device_id {
        root_session(&mut tx, &headers, &directory, &device).await?;
    } else {
        join_token(&token, &headers)?;
    }
    match status.phase {
        JoinPhase::Authorized | JoinPhase::Revoked => return Err(conflict()),
        JoinPhase::Cancelled => {}
        _ => {
            status.phase = JoinPhase::Cancelled;
            save_join(&mut tx, &status, false).await?;
        }
    }
    tx.commit().await.map_err(unavailable)?;
    Ok(Json(status))
}
async fn grant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<DeviceEventSubmission>,
) -> Result<Json<DeviceReceipt>, Failure> {
    if !matches!(input.event.action, DeviceAction::Grant { .. }) {
        return Err(bad());
    }
    submit(state, headers, input).await
}
async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<DeviceEventSubmission>,
) -> Result<Json<DeviceReceipt>, Failure> {
    if !matches!(input.event.action, DeviceAction::Revoke { .. }) {
        return Err(bad());
    }
    submit(state, headers, input).await
}
async fn submit(
    state: AppState,
    headers: HeaderMap,
    input: DeviceEventSubmission,
) -> Result<Json<DeviceReceipt>, Failure> {
    let user = admit(&state, &headers).await?;
    let payload = encode(&input.event)?;
    let mut tx = state.db.pool().begin().await.map_err(unavailable)?;
    lock(&mut tx, &user).await?;
    let (directory, events) = directory(&mut tx, &user, origin(&state)?).await?;
    root_session(&mut tx, &headers, &directory, &input.device_id).await?;
    let event = &input.event;
    let cancelled: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT digest FROM device_event_cancellations WHERE user_id=$1 AND event_id=$2",
    )
    .bind(&user)
    .bind(&event.id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(unavailable)?;
    if let Some(hash) = cancelled {
        return Err(if hash == event.hash() {
            gone()
        } else {
            conflict()
        });
    }
    let next = directory.apply_live(event, now()).map_err(device_error)?;
    let duplicate = events.iter().any(|old| old.id == event.id);
    if !duplicate {
        event_capacity(&mut tx, &user).await?;
        match &event.action {
            DeviceAction::Grant {
                intent,
                challenge,
                proof,
            } => {
                let (mut status, _) = read_join(&mut tx, &intent.id).await?;
                if status.ticket.anchor != *directory.anchor()
                    || !active(&status, now())
                    || status.phase != JoinPhase::Proved
                    || !status.ticket.matches(intent)
                    || status.intent.as_ref() != Some(intent.as_ref())
                    || status.challenge.as_ref() != Some(challenge.as_ref())
                    || status.proof.as_ref() != Some(proof)
                {
                    return Err(conflict());
                }
                let occupied = sqlx::query("SELECT 1 FROM devices WHERE id=$1")
                    .bind(&intent.device.device_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(unavailable)?;
                if occupied.is_some() {
                    return Err(conflict());
                }
                sqlx::query("INSERT INTO device_authorizations(device_id,user_id,name,encryption_key,signing_key,grant_hash,request_id)
                    VALUES($1,$2,$3,$4,$5,$6,$7)").bind(&intent.device.device_id).bind(&user).bind(&status.ticket.device_name)
                    .bind(intent.device.encryption_key.as_slice()).bind(intent.device.signing_key.as_slice()).bind(event.hash())
                    .bind(&intent.id).execute(&mut *tx).await.map_err(unavailable)?;
                status.phase = JoinPhase::Authorized;
                status.authorization_id = Some(event.id.clone());
                save_join(&mut tx, &status, false).await?;
            }
            DeviceAction::Revoke {
                device_id,
                grant_hash,
            } => {
                let request: String = sqlx::query_scalar("UPDATE device_authorizations SET revoked=true
                    WHERE user_id=$1 AND device_id=$2 AND grant_hash=$3 AND revoked=false RETURNING request_id")
                    .bind(&user).bind(device_id).bind(grant_hash).fetch_optional(&mut *tx).await.map_err(unavailable)?.ok_or_else(conflict)?;
                let (mut status, _) = read_join(&mut tx, &request).await?;
                status.phase = JoinPhase::Revoked;
                save_join(&mut tx, &status, true).await?;
                crate::direct_messages::revoke_target(&mut tx, &user, device_id).await?;
                // An explicitly activated projection must lose every legacy
                // and v3 session as well; control-plane-only grants have no row.
                sqlx::query("UPDATE devices SET revoked=true WHERE id=$1 AND user_id=$2")
                    .bind(device_id)
                    .bind(&user)
                    .execute(&mut *tx)
                    .await
                    .map_err(unavailable)?;
                sqlx::query("UPDATE sessions SET revoked=true WHERE device_id=$1 AND user_id=$2")
                    .bind(device_id)
                    .bind(&user)
                    .execute(&mut *tx)
                    .await
                    .map_err(unavailable)?;
            }
        }
        sqlx::query("INSERT INTO device_authorization_events(user_id,revision,event_id,payload,digest) VALUES($1,$2,$3,$4,$5)")
            .bind(&user).bind(event.revision as i64).bind(&event.id).bind(payload).bind(event.hash()).execute(&mut *tx).await.map_err(unavailable)?;
        save_root(&mut tx, &next).await?;
    }
    let receipt = DeviceReceipt {
        event_id: event.id.clone(),
        event_hash: event.hash(),
        accepted_revision: event.revision,
        current_revision: next.revision(),
        current_hash: next.head().to_vec(),
        messaging_enabled: false,
    };
    tx.commit().await.map_err(unavailable)?;
    Ok(Json(receipt))
}
async fn event_capacity(tx: &mut Tx<'_>, user: &str) -> Result<(), Failure> {
    let count: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM device_authorization_events WHERE user_id=$1)
        +(SELECT COUNT(*) FROM device_event_cancellations WHERE user_id=$1)",
    )
    .bind(user)
    .fetch_one(&mut **tx)
    .await
    .map_err(unavailable)?;
    if count >= MAX_DEVICE_EVENTS as i64 {
        return Err(conflict());
    }
    Ok(())
}
async fn cancel_event(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<DeviceEventSubmission>,
) -> Result<Json<DeviceCancelResult>, Failure> {
    let user = admit(&state, &headers).await?;
    encode(&input.event)?;
    let mut tx = state.db.pool().begin().await.map_err(unavailable)?;
    lock(&mut tx, &user).await?;
    let (directory, events) = directory(&mut tx, &user, origin(&state)?).await?;
    root_session(&mut tx, &headers, &directory, &input.device_id).await?;
    let event = &input.event;
    if event.version != 1
        || event.anchor_hash != directory.anchor().hash()
        || !liteseal_shared::crypto::verify_with_public_key(
            &event.signing_bytes(),
            &event.signature,
            &directory.anchor().root.signing_key,
        )
        .unwrap_or(false)
    {
        return Err((StatusCode::FORBIDDEN, "取消记录未绑定原根签名".into()));
    }
    let result = if let Some(accepted) = events.iter().find(|old| old.id == event.id) {
        if accepted.hash() != event.hash() {
            return Err(conflict());
        }
        DeviceCancelResult {
            cancelled: false,
            receipt: Some(DeviceReceipt {
                event_id: event.id.clone(),
                event_hash: event.hash(),
                accepted_revision: event.revision,
                current_revision: directory.revision(),
                current_hash: directory.head().to_vec(),
                messaging_enabled: false,
            }),
        }
    } else {
        // Cancellation may concern a stale or expired original task, but it
        // must still be a valid signed transition from a known historical head.
        let mut prior = DeviceState::pin(directory.anchor().clone()).map_err(|_| corrupt())?;
        for accepted in events.iter().filter(|old| old.revision < event.revision) {
            prior = prior.apply(accepted).map_err(|_| corrupt())?;
        }
        prior.apply(event).map_err(device_error)?;
        let old: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT digest FROM device_event_cancellations WHERE user_id=$1 AND event_id=$2",
        )
        .bind(&user)
        .bind(&event.id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(unavailable)?;
        if let Some(old) = old {
            if old != event.hash() {
                return Err(conflict());
            }
        } else {
            event_capacity(&mut tx, &user).await?;
            sqlx::query(
                "INSERT INTO device_event_cancellations(user_id,event_id,digest) VALUES($1,$2,$3)",
            )
            .bind(&user)
            .bind(&event.id)
            .bind(event.hash())
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        }
        DeviceCancelResult {
            cancelled: true,
            receipt: None,
        }
    };
    tx.commit().await.map_err(unavailable)?;
    Ok(Json(result))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestQuery {
    #[serde(default)]
    after_revision: u64,
    #[serde(default = "page_limit")]
    limit: usize,
}
fn page_limit() -> usize {
    100
}
async fn manifest(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user): Path<String>,
    Query(query): Query<ManifestQuery>,
) -> Result<Json<DeviceManifestPage>, Failure> {
    admit(&state, &headers).await?;
    uuid(&user)?;
    if !(1..=100).contains(&query.limit) || query.after_revision > MAX_DEVICE_EVENTS {
        return Err(bad());
    }
    let mut tx = state.db.pool().begin().await.map_err(unavailable)?;
    lock(&mut tx, &user).await?;
    let (directory, events) = directory(&mut tx, &user, origin(&state)?).await?;
    let page = manifest_page(&directory, events, &query)?;
    tx.commit().await.map_err(unavailable)?;
    Ok(Json(page))
}
async fn join_manifest(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<ManifestQuery>,
) -> Result<Json<DeviceManifestPage>, Failure> {
    let user = join_account(&state, &headers, &id).await?;
    let mut tx = state.db.pool().begin().await.map_err(unavailable)?;
    lock(&mut tx, &user).await?;
    let (status, token) = read_join(&mut tx, &id).await?;
    join_token(&token, &headers)?;
    if !active(&status, now()) && status.phase != JoinPhase::Authorized {
        return Err(gone());
    }
    let (directory, events) = directory(&mut tx, &user, origin(&state)?).await?;
    if status.ticket.anchor != *directory.anchor() {
        return Err(corrupt());
    }
    let page = manifest_page(&directory, events, &query)?;
    tx.commit().await.map_err(unavailable)?;
    Ok(Json(page))
}
fn manifest_page(
    directory: &DeviceState,
    events: Vec<DeviceEvent>,
    query: &ManifestQuery,
) -> Result<DeviceManifestPage, Failure> {
    if !(1..=100).contains(&query.limit) || query.after_revision > MAX_DEVICE_EVENTS {
        return Err(bad());
    }
    if query.after_revision > directory.revision() {
        return Err(conflict());
    }
    let mut page = DeviceManifestPage {
        anchor: directory.anchor().clone(),
        events: vec![],
        through_revision: query.after_revision,
        current_revision: directory.revision(),
        current_hash: directory.head().to_vec(),
        more: query.after_revision < directory.revision(),
    };
    for event in events
        .into_iter()
        .filter(|e| e.revision > query.after_revision)
        .take(query.limit)
    {
        let previous = page.through_revision;
        page.through_revision = event.revision;
        page.events.push(event);
        page.more = page.through_revision < directory.revision();
        if serde_json::to_vec(&page).map_err(|_| corrupt())?.len() > MAX_DEVICE_PAGE_BYTES {
            page.events.pop();
            page.through_revision = previous;
            page.more = true;
            break;
        }
    }
    Ok(page)
}
