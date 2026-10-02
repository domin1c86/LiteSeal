//! Operational sessions require explicit v3 enablement and both device keys.
use crate::{
    auth::{handlers, service},
    state::AppState,
    trusted_devices,
};
use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use liteseal_shared::device_activation::{ModeQuery, ModeReply, SessionInfo};
use liteseal_shared::{
    device_activation::{
        self as a, ActivationCancel, ActivationCancelResult, Challenge, ClosedReason, Closure,
        Enable, EnableCancel, EnableCancelResult, Envelope, Inspection, InspectionResult, Proof,
        Session, Start,
    },
    direct_message::Directory,
};
use serde::Serialize;
use sqlx::{Postgres, Row, Transaction};
type Tx<'a> = Transaction<'a, Postgres>;
type Failure = (StatusCode, String);
pub mod refresh;
pub const MIGRATION:&str="
CREATE TABLE device_messaging_modes (
 user_id TEXT PRIMARY KEY REFERENCES users(id),root_device TEXT NOT NULL REFERENCES devices(id),
 event_id TEXT NOT NULL UNIQUE,digest BYTEA NOT NULL CHECK(octet_length(digest)=32),payload BYTEA NOT NULL CHECK(octet_length(payload)<=8192),root_authority BYTEA NOT NULL CHECK(octet_length(root_authority)=32)
);
ALTER TABLE sessions ADD COLUMN v3_authority BYTEA CHECK(v3_authority IS NULL OR octet_length(v3_authority)=32);
CREATE TABLE device_session_attempts (
 id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),device_id TEXT NOT NULL,
 token_hash TEXT NOT NULL,password_state TEXT NOT NULL,challenge BYTEA NOT NULL CHECK(octet_length(challenge)<=8192),expires_at BIGINT NOT NULL,
 proof_hash BYTEA CHECK(octet_length(proof_hash)=32),response BYTEA CHECK(octet_length(response)<=16384),session_id TEXT REFERENCES sessions(id),
 CHECK((proof_hash IS NULL AND response IS NULL AND session_id IS NULL) OR (proof_hash IS NOT NULL AND response IS NOT NULL AND session_id IS NOT NULL))
);
CREATE INDEX device_session_live ON device_session_attempts(user_id,expires_at);
";
pub const CANCEL_MIGRATION: &str = "
CREATE TABLE device_mode_cancellations (
 id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),
 digest BYTEA NOT NULL CHECK(octet_length(digest)=32)
);
CREATE INDEX device_mode_cancel_user ON device_mode_cancellations(user_id);
CREATE TABLE device_session_cancellations (
 id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),device_id TEXT NOT NULL,
 token_hash TEXT NOT NULL,digest BYTEA NOT NULL CHECK(octet_length(digest)=32)
);
CREATE INDEX device_session_cancel_user ON device_session_cancellations(user_id);
";
pub const CLOSURE_MIGRATION: &str = "
CREATE TABLE device_session_closures (
 id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),device_id TEXT NOT NULL,
 token_hash TEXT NOT NULL,payload BYTEA NOT NULL CHECK(octet_length(payload)<=8192)
);
CREATE INDEX device_session_closure_user ON device_session_closures(user_id);
";
fn storage(_: sqlx::Error) -> Failure {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "设备会话存储暂不可用，保留原申请".into(),
    )
}
fn bad() -> Failure {
    (StatusCode::BAD_REQUEST, "无效设备会话参数".into())
}
fn denied() -> Failure {
    (StatusCode::FORBIDDEN, "设备、密钥或协议资格不匹配".into())
}
fn conflict() -> Failure {
    (
        StatusCode::CONFLICT,
        "设备会话编号、版本或旧任务队列冲突".into(),
    )
}
fn unauthorized() -> Failure {
    (StatusCode::UNAUTHORIZED, "凭据、口令或会话已失效".into())
}
fn gone() -> Failure {
    (
        StatusCode::GONE,
        "设备挑战或原会话已结束，请明确新建申请".into(),
    )
}
fn origin(state: &AppState) -> Result<&str, Failure> {
    state
        .device_authorization_origin
        .as_deref()
        .ok_or((StatusCode::NOT_FOUND, "设备激活未启用".into()))
}
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
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
fn bearer(headers: &HeaderMap) -> Result<&str, Failure> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(unauthorized)
}
fn encode(value: &impl Serialize) -> Result<Vec<u8>, Failure> {
    let data = serde_json::to_vec(value).map_err(|_| bad())?;
    if data.len() > a::MAX_WIRE {
        return Err(bad());
    }
    Ok(data)
}
pub fn router() -> Router<AppState> {
    Router::new()
        .merge(refresh::router())
        .route("/devices/messaging/enable", post(enable))
        .route("/devices/messaging/cancel", post(cancel_enable))
        .route("/users/:user/device_messaging", get(status))
        .route("/auth/v3/begin", post(begin))
        .route("/auth/v3/mode", post(bootstrap_mode))
        .route("/auth/v3/cancel", post(cancel_activation))
        .route("/auth/v3/inspect", post(inspect))
        .route("/auth/v3/session/:device", get(session_info))
        .route("/auth/v3/:id", get(challenge))
        .route("/auth/v3/:id/proof", post(prove))
        .layer(DefaultBodyLimit::max(a::MAX_WIRE))
}
pub(crate) async fn root_device(
    pool: &sqlx::PgPool,
    user: &str,
    device: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM devices d WHERE d.user_id=$1 AND d.id=$2 AND NOT EXISTS(SELECT 1 FROM device_authorizations a WHERE a.device_id=d.id))").bind(user).bind(device).fetch_one(pool).await
}
pub(crate) async fn beta_device(
    pool: &sqlx::PgPool,
    user: &str,
    device: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM devices d WHERE d.user_id=$1 AND d.id=$2 AND d.revoked=false AND NOT EXISTS(SELECT 1 FROM device_authorizations a WHERE a.device_id=d.id)) AND NOT EXISTS(SELECT 1 FROM device_messaging_modes WHERE user_id=$1)").bind(user).bind(device).fetch_one(pool).await
}
pub(crate) async fn beta_pair(tx: &mut Tx<'_>, a: &str, b: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT NOT EXISTS(SELECT 1 FROM device_messaging_modes WHERE user_id=$1 OR user_id=$2)",
    )
    .bind(a)
    .bind(b)
    .fetch_one(&mut **tx)
    .await
}
pub(crate) async fn lock_pair(tx: &mut Tx<'_>, a: &str, b: &str) -> Result<(), sqlx::Error> {
    let mut users = [a, b];
    users.sort_unstable();
    for user in users {
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
            .bind(user)
            .fetch_optional(&mut **tx)
            .await?;
    }
    Ok(())
}
pub(crate) async fn enabled(tx: &mut Tx<'_>, user: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM device_messaging_modes WHERE user_id=$1)")
        .bind(user)
        .fetch_one(&mut **tx)
        .await
}
async fn mode(
    tx: &mut Tx<'_>,
    state: &liteseal_shared::trusted_device::DeviceState,
) -> Result<Enable, Failure> {
    let bytes: Vec<u8> =
        sqlx::query_scalar("SELECT payload FROM device_messaging_modes WHERE user_id=$1")
            .bind(&state.anchor().account)
            .fetch_optional(&mut **tx)
            .await
            .map_err(storage)?
            .ok_or((
                StatusCode::UPGRADE_REQUIRED,
                "原设备尚未明确启用单聊 v3".into(),
            ))?;
    let event: Enable = serde_json::from_slice(&bytes).map_err(|_| denied())?;
    event.verify_root(state.anchor()).map_err(|_| denied())?;
    Ok(event)
}
#[derive(Serialize)]
struct Status {
    enabled: bool,
    event: Option<Enable>,
}
async fn status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user): Path<String>,
) -> Result<Json<Status>, Failure> {
    origin(&state)?;
    handlers::user_from_bearer(&state, &headers)
        .await
        .map_err(|_| unauthorized())?;
    uuid(&user)?;
    let mut tx = state.db.pool().begin().await.map_err(storage)?;
    trusted_devices::lock(&mut tx, &user).await?;
    let (directory, _) = trusted_devices::directory(&mut tx, &user, origin(&state)?).await?;
    let event = if enabled(&mut tx, &user).await.map_err(storage)? {
        Some(mode(&mut tx, &directory).await?)
    } else {
        None
    };
    tx.commit().await.map_err(storage)?;
    Ok(Json(Status {
        enabled: event.is_some(),
        event,
    }))
}
async fn bootstrap_mode(
    State(state): State<AppState>,
    Json(query): Json<ModeQuery>,
) -> Result<Json<ModeReply>, Failure> {
    let realm = origin(&state)?;
    query.verify_signature(now()).map_err(|_| denied())?;
    uuid(&query.account)?;
    if query.origin != realm {
        return Err(denied());
    }
    let mut tx = state.db.pool().begin().await.map_err(storage)?;
    trusted_devices::lock(&mut tx, &query.account).await?;
    let (directory, _) = trusted_devices::directory(&mut tx, &query.account, realm).await?;
    query
        .verify_current(&directory, now())
        .map_err(|_| denied())?;
    if query.device == directory.anchor().root {
        let active: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM devices WHERE id=$1 AND user_id=$2 AND revoked=false)",
        )
        .bind(&query.device.device_id)
        .bind(&query.account)
        .fetch_one(&mut *tx)
        .await
        .map_err(storage)?;
        if !active {
            return Err(denied());
        }
    } else {
        let revoked: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM devices WHERE id=$1 AND user_id=$2 AND revoked=true)",
        )
        .bind(&query.device.device_id)
        .bind(&query.account)
        .fetch_one(&mut *tx)
        .await
        .map_err(storage)?;
        if revoked {
            return Err(denied());
        }
    }
    let event = if enabled(&mut tx, &query.account).await.map_err(storage)? {
        Some(mode(&mut tx, &directory).await?)
    } else {
        None
    };
    let reply = ModeReply {
        version: 1,
        request: query.digest().map_err(|_| bad())?,
        event,
    };
    tx.commit().await.map_err(storage)?;
    // Release the account lock and pool connection before using the rate store.
    if !state
        .db
        .hit_rate_limit(&format!("device-mode:{}", query.device.device_id), 60, 60)
        .await
        .map_err(storage)?
    {
        return Err((StatusCode::TOO_MANY_REQUESTS, "设备配置查询过于频繁".into()));
    }
    Ok(Json(reply))
}
async fn enable(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(event): Json<Enable>,
) -> Result<Json<Enable>, Failure> {
    let user = handlers::user_from_bearer(&state, &headers)
        .await
        .map_err(|_| unauthorized())?;
    origin(&state)?;
    uuid(&event.id)?;
    if user != event.account {
        return Err(denied());
    }
    let mut tx = state.db.pool().begin().await.map_err(storage)?;
    trusted_devices::lock(&mut tx, &user).await?;
    let (directory, _) = trusted_devices::directory(&mut tx, &user, origin(&state)?).await?;
    trusted_devices::root_session(&mut tx, &headers, &directory, &event.root).await?;
    if enabled(&mut tx, &user).await.map_err(storage)? {
        let old = mode(&mut tx, &directory).await?;
        if old != event {
            return Err(conflict());
        }
        tx.commit().await.map_err(storage)?;
        return Ok(Json(old));
    }
    event.verify_current(&directory).map_err(|_| denied())?;
    if fenced(&mut tx, "device_mode_cancellations", &event.id).await? {
        return Err(gone());
    }
    let pending:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM offline_messages WHERE acked=false AND (from_user_id=$1 OR recipient_user_id=$1)) OR EXISTS(SELECT 1 FROM operation_deliveries d JOIN message_operations m ON m.id=d.operation_id WHERE d.acked=false AND (d.device_id=$2 OR m.request::jsonb->'header'->>'sender_id'=$1))")
        .bind(&user).bind(&event.root).fetch_one(&mut *tx).await.map_err(storage)?;
    if pending {
        return Err((
            StatusCode::CONFLICT,
            "旧单聊消息或操作尚未确认，不能切换协议".into(),
        ));
    }
    sqlx::query("INSERT INTO device_messaging_modes(user_id,root_device,event_id,digest,payload,root_authority) VALUES($1,$2,$3,$4,$5,$6)").bind(user).bind(&event.root).bind(&event.id).bind(event.digest().map_err(|_|bad())?.as_slice()).bind(encode(&event)?).bind(directory.anchor().hash()).execute(&mut *tx).await.map_err(storage)?;
    tx.commit().await.map_err(storage)?;
    Ok(Json(event))
}
async fn live(
    tx: &mut Tx<'_>,
    user: &str,
    device: &str,
    authority: [u8; 32],
    realm: &str,
) -> Result<(liteseal_shared::trusted_device::DeviceState, Enable), Failure> {
    let (directory, _) = trusted_devices::directory(tx, user, realm).await?;
    let event = mode(tx, &directory).await?;
    let member = Directory::from_state(&directory)
        .members
        .into_iter()
        .find(|m| m.device.device_id == device && m.authorization_hash == authority)
        .ok_or_else(denied)?;
    if member.device == directory.anchor().root {
        let active: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM devices WHERE id=$1 AND user_id=$2 AND revoked=false)",
        )
        .bind(device)
        .bind(user)
        .fetch_one(&mut **tx)
        .await
        .map_err(storage)?;
        if !active {
            return Err(denied());
        }
    }
    Ok((directory, event))
}
async fn fenced(tx: &mut Tx<'_>, table: &str, id: &str) -> Result<bool, Failure> {
    let sql = match table {
        "device_mode_cancellations" => {
            "SELECT EXISTS(SELECT 1 FROM device_mode_cancellations WHERE id=$1)"
        }
        "device_session_cancellations" => {
            "SELECT EXISTS(SELECT 1 FROM device_session_cancellations WHERE id=$1)"
        }
        "device_session_closures" => {
            "SELECT EXISTS(SELECT 1 FROM device_session_closures WHERE id=$1)"
        }
        _ => return Err(bad()),
    };
    sqlx::query_scalar(sql)
        .bind(id)
        .fetch_one(&mut **tx)
        .await
        .map_err(storage)
}
async fn cancel_enable(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(cancel): Json<EnableCancel>,
) -> Result<Json<EnableCancelResult>, Failure> {
    let user = handlers::user_from_bearer(&state, &headers)
        .await
        .map_err(|_| unauthorized())?;
    let realm = origin(&state)?;
    if user != cancel.event.account {
        return Err(denied());
    }
    let mut tx = state.db.pool().begin().await.map_err(storage)?;
    trusted_devices::lock(&mut tx, &user).await?;
    let (directory, _) = trusted_devices::directory(&mut tx, &user, realm).await?;
    trusted_devices::root_session(&mut tx, &headers, &directory, &cancel.event.root).await?;
    cancel.verify(directory.anchor()).map_err(|_| denied())?;
    let digest = cancel.event.digest().map_err(|_| bad())?;
    let old = sqlx::query("SELECT user_id,digest FROM device_mode_cancellations WHERE id=$1")
        .bind(&cancel.event.id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage)?;
    if let Some(old) = old {
        if old.get::<String, _>("user_id") != user || old.get::<Vec<u8>, _>("digest") != digest {
            return Err(conflict());
        }
        tx.commit().await.map_err(storage)?;
        return Ok(Json(EnableCancelResult::Cancelled { event: digest }));
    }
    if enabled(&mut tx, &user).await.map_err(storage)? {
        let old = mode(&mut tx, &directory).await?;
        if old != cancel.event {
            return Err(conflict());
        }
        tx.commit().await.map_err(storage)?;
        return Ok(Json(EnableCancelResult::Accepted { event: old }));
    }
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM device_mode_cancellations WHERE user_id=$1")
            .bind(&user)
            .fetch_one(&mut *tx)
            .await
            .map_err(storage)?;
    if count >= 4096 {
        return Err((StatusCode::TOO_MANY_REQUESTS, "启用取消记录达到上限".into()));
    }
    sqlx::query("INSERT INTO device_mode_cancellations(id,user_id,digest) VALUES($1,$2,$3)")
        .bind(&cancel.event.id)
        .bind(user)
        .bind(digest.as_slice())
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
    tx.commit().await.map_err(storage)?;
    Ok(Json(EnableCancelResult::Cancelled { event: digest }))
}
async fn cancel_activation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(cancel): Json<ActivationCancel>,
) -> Result<Json<ActivationCancelResult>, Failure> {
    let realm = origin(&state)?;
    uuid(&cancel.id)?;
    let token = bearer(&headers)?;
    let mut tx = state.db.pool().begin().await.map_err(storage)?;
    trusted_devices::lock(&mut tx, &cancel.account).await?;
    let (directory, event) = live(
        &mut tx,
        &cancel.account,
        &cancel.device.device_id,
        cancel.authorization,
        realm,
    )
    .await?;
    cancel
        .verify(&directory, &event, token)
        .map_err(|_| denied())?;
    let digest = cancel.digest().map_err(|_| bad())?;
    let token_hash = service::hash_token(token);
    let old = sqlx::query(
        "SELECT user_id,device_id,token_hash,digest FROM device_session_cancellations WHERE id=$1",
    )
    .bind(&cancel.id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(storage)?;
    if let Some(old) = old {
        if old.get::<String, _>("user_id") != cancel.account
            || old.get::<String, _>("device_id") != cancel.device.device_id
            || old.get::<String, _>("token_hash") != token_hash
            || old.get::<Vec<u8>, _>("digest") != digest
        {
            return Err(conflict());
        }
        tx.commit().await.map_err(storage)?;
        return Ok(Json(ActivationCancelResult::Cancelled {
            cancellation: digest,
        }));
    }
    let attempt = sqlx::query("SELECT a.*,u.password_hash FROM device_session_attempts a JOIN users u ON u.id=a.user_id WHERE a.id=$1 FOR UPDATE OF a")
        .bind(&cancel.id).fetch_optional(&mut *tx).await.map_err(storage)?;
    if let Some(row) = attempt {
        if row.get::<String, _>("user_id") != cancel.account
            || row.get::<String, _>("device_id") != cancel.device.device_id
            || row.get::<String, _>("token_hash") != token_hash
        {
            return Err(conflict());
        }
        let challenge: Challenge =
            serde_json::from_slice(&row.get::<Vec<u8>, _>("challenge")).map_err(|_| denied())?;
        if challenge.authorization != cancel.authorization
            || challenge.mode != cancel.mode
            || challenge.device != cancel.device
        {
            return Err(conflict());
        }
        if row.get::<Option<Vec<u8>>, _>("proof_hash").is_some() {
            if row.get::<String, _>("password_state") != row.get::<String, _>("password_hash") {
                return Err(unauthorized());
            }
            let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sessions WHERE id=$1 AND revoked=false AND refresh_expires_at>now())")
                .bind(row.get::<String,_>("session_id")).fetch_one(&mut *tx).await.map_err(storage)?;
            if !valid {
                return Err(gone());
            }
            let envelope =
                serde_json::from_slice(&row.get::<Vec<u8>, _>("response")).map_err(|_| denied())?;
            tx.commit().await.map_err(storage)?;
            return Ok(Json(ActivationCancelResult::Accepted {
                challenge: Box::new(challenge),
                envelope,
            }));
        }
    }
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM device_session_cancellations WHERE user_id=$1")
            .bind(&cancel.account)
            .fetch_one(&mut *tx)
            .await
            .map_err(storage)?;
    if count >= 4096 {
        return Err((StatusCode::TOO_MANY_REQUESTS, "激活取消记录达到上限".into()));
    }
    sqlx::query("INSERT INTO device_session_cancellations(id,user_id,device_id,token_hash,digest) VALUES($1,$2,$3,$4,$5)")
        .bind(&cancel.id).bind(&cancel.account).bind(&cancel.device.device_id).bind(token_hash).bind(digest.as_slice())
        .execute(&mut *tx).await.map_err(storage)?;
    tx.commit().await.map_err(storage)?;
    Ok(Json(ActivationCancelResult::Cancelled {
        cancellation: digest,
    }))
}
async fn begin(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<std::net::SocketAddr>,
    Json(input): Json<Start>,
) -> Result<Json<Challenge>, Failure> {
    let realm = origin(&state)?;
    uuid(&input.id)?;
    uuid(&input.device)?;
    if input.request_token.len() < 32
        || input.request_token.len() > 256
        || input.username.is_empty()
        || input.username.len() > 128
        || input.password.len() > 1024
    {
        return Err(bad());
    }
    handlers::enforce_auth_rate_limit(&state, input.username.trim(), remote.ip())
        .await
        .map_err(|s| (s, "设备会话请求过于频繁".into()))?;
    let user = state
        .db
        .get_user_by_username(input.username.trim())
        .await
        .map_err(storage)?
        .ok_or_else(unauthorized)?;
    if !service::verify_password(&input.password, &user.password_hash) {
        return Err(unauthorized());
    }
    let mut tx = state.db.pool().begin().await.map_err(storage)?;
    trusted_devices::lock(&mut tx, &user.id).await?;
    let current_hash: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id=$1")
        .bind(&user.id)
        .fetch_one(&mut *tx)
        .await
        .map_err(storage)?;
    if current_hash != user.password_hash {
        return Err(unauthorized());
    }
    let (directory, event) =
        live(&mut tx, &user.id, &input.device, input.authorization, realm).await?;
    if fenced(&mut tx, "device_session_cancellations", &input.id).await? {
        return Err(gone());
    }
    if fenced(&mut tx, "device_session_closures", &input.id).await? {
        return Err(gone());
    }
    let old=sqlx::query("SELECT user_id,device_id,token_hash,password_state,challenge,expires_at FROM device_session_attempts WHERE id=$1").bind(&input.id).fetch_optional(&mut *tx).await.map_err(storage)?;
    let challenge = if let Some(row) = old {
        if row.get::<String, _>("user_id") != user.id
            || row.get::<String, _>("device_id") != input.device
            || row.get::<String, _>("token_hash") != service::hash_token(&input.request_token)
            || row.get::<String, _>("password_state") != current_hash
        {
            return Err(conflict());
        }
        if row.get::<i64, _>("expires_at") <= now() {
            return Err(gone());
        }
        let challenge: Challenge =
            serde_json::from_slice(&row.get::<Vec<u8>, _>("challenge")).map_err(|_| denied())?;
        challenge
            .verify_state(&directory, &event, now())
            .map_err(|_| conflict())?;
        challenge
    } else {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM device_session_attempts WHERE user_id=$1")
                .bind(&user.id)
                .fetch_one(&mut *tx)
                .await
                .map_err(storage)?;
        let pending:i64=sqlx::query_scalar("SELECT COUNT(*) FROM device_session_attempts a WHERE user_id=$1 AND expires_at>$2 AND proof_hash IS NULL AND NOT EXISTS(SELECT 1 FROM device_session_cancellations c WHERE c.id=a.id)").bind(&user.id).bind(now()).fetch_one(&mut *tx).await.map_err(storage)?;
        if count >= 4096 || pending >= 8 {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                "设备会话申请数量达到上限".into(),
            ));
        }
        let challenge = Challenge::make(&directory, &event, &input.id, &input.device, now())
            .map_err(|_| bad())?;
        sqlx::query("INSERT INTO device_session_attempts(id,user_id,device_id,token_hash,password_state,challenge,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)").bind(&input.id).bind(&user.id).bind(&input.device).bind(service::hash_token(&input.request_token)).bind(current_hash).bind(encode(&challenge)?).bind(challenge.expires_at).execute(&mut *tx).await.map_err(storage)?;
        challenge
    };
    tx.commit().await.map_err(storage)?;
    Ok(Json(challenge))
}
async fn close_inspected(
    tx: &mut Tx<'_>,
    request: &Inspection,
    token_hash: &str,
    challenge: Option<[u8; 32]>,
    accepted: bool,
    reason: ClosedReason,
) -> Result<InspectionResult, Failure> {
    let closed = Closure::make(request, challenge, accepted, reason).map_err(|_| bad())?;
    sqlx::query("INSERT INTO device_session_closures(id,user_id,device_id,token_hash,payload) VALUES($1,$2,$3,$4,$5)")
        .bind(&closed.id).bind(&closed.account).bind(&closed.device.device_id).bind(token_hash).bind(encode(&closed)?)
        .execute(&mut **tx).await.map_err(storage)?;
    Ok(InspectionResult::Closed {
        closure: Box::new(closed),
    })
}
async fn inspect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<Inspection>,
) -> Result<Json<InspectionResult>, Failure> {
    let realm = origin(&state)?;
    let intent = &request.intent;
    let token = bearer(&headers)?;
    let mut tx = state.db.pool().begin().await.map_err(storage)?;
    trusted_devices::lock(&mut tx, &intent.account).await?;
    let (directory, mode) = live(
        &mut tx,
        &intent.account,
        &intent.device.device_id,
        intent.authorization,
        realm,
    )
    .await?;
    request
        .verify(&directory, &mode, token)
        .map_err(|_| denied())?;
    let token_hash = service::hash_token(token);
    let old = sqlx::query(
        "SELECT user_id,device_id,token_hash,payload FROM device_session_closures WHERE id=$1",
    )
    .bind(&intent.id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(storage)?;
    if let Some(old) = old {
        if old.get::<String, _>("user_id") != intent.account
            || old.get::<String, _>("device_id") != intent.device.device_id
            || old.get::<String, _>("token_hash") != token_hash
        {
            return Err(conflict());
        }
        let mut closed: Closure =
            serde_json::from_slice(&old.get::<Vec<u8>, _>("payload")).map_err(|_| denied())?;
        // The facts are immutable; bind each response to this signed inspection.
        closed.request = request.digest().map_err(|_| bad())?;
        closed.verify(&request).map_err(|_| denied())?;
        tx.commit().await.map_err(storage)?;
        return Ok(Json(InspectionResult::Closed {
            closure: Box::new(closed),
        }));
    }
    let row = sqlx::query("SELECT a.*,u.password_hash FROM device_session_attempts a JOIN users u ON u.id=a.user_id WHERE a.id=$1 FOR UPDATE OF a")
        .bind(&intent.id).fetch_optional(&mut *tx).await.map_err(storage)?;
    let mut challenge = None;
    if let Some(row) = &row {
        if row.get::<String, _>("user_id") != intent.account
            || row.get::<String, _>("device_id") != intent.device.device_id
            || row.get::<String, _>("token_hash") != token_hash
        {
            return Err(conflict());
        }
        let saved: Challenge =
            serde_json::from_slice(&row.get::<Vec<u8>, _>("challenge")).map_err(|_| denied())?;
        if saved.origin != realm
            || saved.account != intent.account
            || saved.device != intent.device
            || saved.authorization != intent.authorization
            || saved.mode != intent.mode
        {
            return Err(conflict());
        }
        saved.digest().map_err(|_| denied())?;
        challenge = Some(saved);
    }
    let fence = sqlx::query(
        "SELECT user_id,device_id,token_hash FROM device_session_cancellations WHERE id=$1",
    )
    .bind(&intent.id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(storage)?;
    let result = if let Some(fence) = fence {
        if fence.get::<String, _>("user_id") != intent.account
            || fence.get::<String, _>("device_id") != intent.device.device_id
            || fence.get::<String, _>("token_hash") != token_hash
        {
            return Err(conflict());
        }
        if row
            .as_ref()
            .is_some_and(|r| r.get::<Option<Vec<u8>>, _>("proof_hash").is_some())
        {
            return Err(denied());
        }
        close_inspected(
            &mut tx,
            &request,
            &token_hash,
            challenge
                .as_ref()
                .map(|c| c.digest())
                .transpose()
                .map_err(|_| bad())?,
            false,
            ClosedReason::Cancelled,
        )
        .await?
    } else if let (Some(row), Some(challenge)) = (row, challenge) {
        let accepted = row.get::<Option<Vec<u8>>, _>("proof_hash").is_some();
        let digest = Some(challenge.digest().map_err(|_| bad())?);
        if row.get::<String, _>("password_state") != row.get::<String, _>("password_hash") {
            close_inspected(
                &mut tx,
                &request,
                &token_hash,
                digest,
                accepted,
                ClosedReason::CredentialsChanged,
            )
            .await?
        } else if accepted {
            let session = sqlx::query("SELECT user_id,device_id,v3_authority,revoked,refresh_expires_at>now() AS live FROM sessions WHERE id=$1")
                .bind(row.get::<String,_>("session_id")).fetch_one(&mut *tx).await.map_err(storage)?;
            if session.get::<String, _>("user_id") != intent.account
                || session.get::<String, _>("device_id") != intent.device.device_id
                || session.get::<Option<Vec<u8>>, _>("v3_authority").as_deref()
                    != Some(intent.authorization.as_slice())
            {
                return Err(denied());
            }
            if session.get::<bool, _>("revoked") || !session.get::<bool, _>("live") {
                close_inspected(
                    &mut tx,
                    &request,
                    &token_hash,
                    digest,
                    true,
                    ClosedReason::SessionEnded,
                )
                .await?
            } else {
                let envelope: Envelope = serde_json::from_slice(&row.get::<Vec<u8>, _>("response"))
                    .map_err(|_| denied())?;
                InspectionResult::Accepted {
                    request: request.digest().map_err(|_| bad())?,
                    challenge: Box::new(challenge),
                    envelope,
                }
            }
        } else if row.get::<i64, _>("expires_at") <= now() || challenge.expires_at <= now() {
            close_inspected(
                &mut tx,
                &request,
                &token_hash,
                digest,
                false,
                ClosedReason::Expired,
            )
            .await?
        } else if challenge.verify_state(&directory, &mode, now()).is_err() {
            close_inspected(
                &mut tx,
                &request,
                &token_hash,
                digest,
                false,
                ClosedReason::DirectoryChanged,
            )
            .await?
        } else {
            InspectionResult::Pending {
                request: request.digest().map_err(|_| bad())?,
                challenge: Box::new(challenge),
            }
        }
    } else {
        InspectionResult::Unknown {
            request: request.digest().map_err(|_| bad())?,
        }
    };
    tx.commit().await.map_err(storage)?;
    Ok(Json(result))
}
async fn attempt<'a>(
    state: &'a AppState,
    headers: &HeaderMap,
    id: &str,
) -> Result<(Tx<'a>, sqlx::postgres::PgRow, Challenge), Failure> {
    origin(state)?;
    uuid(id)?;
    let user: String = sqlx::query_scalar(
        "SELECT user_id FROM device_session_attempts WHERE id=$1 AND token_hash=$2",
    )
    .bind(id)
    .bind(service::hash_token(bearer(headers)?))
    .fetch_optional(state.db.pool())
    .await
    .map_err(storage)?
    .ok_or_else(unauthorized)?;
    let mut tx = state.db.pool().begin().await.map_err(storage)?;
    trusted_devices::lock(&mut tx, &user).await?;
    if fenced(&mut tx, "device_session_cancellations", id).await? {
        return Err(gone());
    }
    if fenced(&mut tx, "device_session_closures", id).await? {
        return Err(gone());
    }
    let row=sqlx::query("SELECT a.*,u.password_hash FROM device_session_attempts a JOIN users u ON u.id=a.user_id WHERE a.id=$1 AND a.token_hash=$2 FOR UPDATE OF a").bind(id).bind(service::hash_token(bearer(headers)?)).fetch_optional(&mut *tx).await.map_err(storage)?.ok_or_else(unauthorized)?;
    if row.get::<String, _>("password_state") != row.get::<String, _>("password_hash") {
        return Err(unauthorized());
    }
    let challenge: Challenge =
        serde_json::from_slice(&row.get::<Vec<u8>, _>("challenge")).map_err(|_| denied())?;
    live(
        &mut tx,
        &user,
        &challenge.device.device_id,
        challenge.authorization,
        origin(state)?,
    )
    .await?;
    Ok((tx, row, challenge))
}
async fn challenge(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Challenge>, Failure> {
    let (tx, row, challenge) = attempt(&state, &headers, &id).await?;
    if row.get::<i64, _>("expires_at") <= now() {
        return Err(gone());
    }
    tx.commit().await.map_err(storage)?;
    Ok(Json(challenge))
}
async fn session_info(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device): Path<String>,
) -> Result<Json<SessionInfo>, Failure> {
    let realm = origin(&state)?;
    uuid(&device)?;
    let hash = service::hash_token(bearer(&headers)?);
    let user = state
        .db
        .validate_access_token(&hash, &device)
        .await
        .map_err(storage)?
        .ok_or_else(unauthorized)?;
    let mut tx = state.db.pool().begin().await.map_err(storage)?;
    trusted_devices::lock(&mut tx, &user).await?;
    let row = sqlx::query("SELECT s.id,s.v3_authority,s.refresh_token_hash,(EXTRACT(EPOCH FROM s.expires_at)*1000)::BIGINT AS expires,(EXTRACT(EPOCH FROM s.refresh_expires_at)*1000)::BIGINT AS refresh,d.public_key,d.ed25519_pk FROM sessions s JOIN devices d ON d.id=s.device_id WHERE s.access_token_hash=$1 AND s.user_id=$2 AND s.device_id=$3 AND d.user_id=s.user_id AND s.revoked=false AND s.expires_at>now() AND d.revoked=false")
        .bind(hash).bind(&user).bind(&device).fetch_optional(&mut *tx).await.map_err(storage)?.ok_or_else(unauthorized)?;
    let authority: Vec<u8> = row.get::<Option<Vec<u8>>, _>("v3_authority").ok_or((
        StatusCode::UPGRADE_REQUIRED,
        "此会话尚未通过双密钥激活".into(),
    ))?;
    let authority: [u8; 32] = authority.try_into().map_err(|_| denied())?;
    let (directory, mode) = live(&mut tx, &user, &device, authority, realm).await?;
    let member = Directory::from_state(&directory)
        .members
        .into_iter()
        .find(|m| m.device.device_id == device && m.authorization_hash == authority)
        .ok_or_else(denied)?;
    if member.device.encryption_key.as_slice() != row.get::<Vec<u8>, _>("public_key")
        || member.device.signing_key.as_slice() != row.get::<Vec<u8>, _>("ed25519_pk")
    {
        return Err(denied());
    }
    let info = SessionInfo {
        version: 1,
        id: row.get("id"),
        account: user,
        device: member.device,
        authorization: authority,
        mode: mode.digest().map_err(|_| denied())?,
        expires_at: row.get("expires"),
        refresh_expires_at: row.get("refresh"),
        refresh_hash: hex::decode(row.get::<String, _>("refresh_token_hash"))
            .map_err(|_| denied())?
            .try_into()
            .map_err(|_| denied())?,
    };
    info.verify(&directory, &mode, &info.device, now())
        .map_err(|_| denied())?;
    tx.commit().await.map_err(storage)?;
    Ok(Json(info))
}
async fn prove(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(proof): Json<Proof>,
) -> Result<Json<Envelope>, Failure> {
    let (mut tx, row, challenge) = attempt(&state, &headers, &id).await?;
    proof.verify(&challenge).map_err(|_| denied())?;
    let digest = proof.digest().map_err(|_| bad())?;
    if let Some(old) = row.get::<Option<Vec<u8>>, _>("proof_hash") {
        if old != digest {
            return Err(conflict());
        }
        let session_id: String = row.get("session_id");
        let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sessions WHERE id=$1 AND revoked=false AND refresh_expires_at>now())").bind(session_id).fetch_one(&mut *tx).await.map_err(storage)?;
        if !valid {
            return Err(gone());
        }
        let envelope =
            serde_json::from_slice(&row.get::<Vec<u8>, _>("response")).map_err(|_| denied())?;
        tx.commit().await.map_err(storage)?;
        return Ok(Json(envelope));
    }
    if row.get::<i64, _>("expires_at") <= now() {
        return Err(gone());
    }
    let (directory, event) = live(
        &mut tx,
        &challenge.account,
        &challenge.device.device_id,
        challenge.authorization,
        origin(&state)?,
    )
    .await?;
    challenge
        .verify_state(&directory, &event, now())
        .map_err(|_| gone())?;
    let session = Session {
        id: uuid::Uuid::new_v4().to_string(),
        account: challenge.account.clone(),
        device: challenge.device.device_id.clone(),
        authorization: challenge.authorization,
        mode: challenge.mode,
        access_token: service::generate_token(),
        refresh_token: service::generate_token(),
        expires_at: now() + 30 * 60 * 1000,
        refresh_expires_at: now() + 30 * 24 * 60 * 60 * 1000,
    };
    let old = sqlx::query("SELECT user_id,public_key,ed25519_pk,revoked FROM devices WHERE id=$1")
        .bind(&session.device)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage)?;
    if let Some(old) = old {
        if old.get::<String, _>("user_id") != session.account
            || old.get::<Vec<u8>, _>("public_key") != challenge.device.encryption_key
            || old.get::<Vec<u8>, _>("ed25519_pk") != challenge.device.signing_key
            || old.get::<bool, _>("revoked")
        {
            return Err(denied());
        }
    } else {
        let name: String = sqlx::query_scalar(
            "SELECT name FROM device_authorizations WHERE device_id=$1 AND revoked=false",
        )
        .bind(&session.device)
        .fetch_one(&mut *tx)
        .await
        .map_err(storage)?;
        sqlx::query("INSERT INTO devices(id,user_id,name,public_key,ed25519_pk,created_at,last_seen) VALUES($1,$2,$3,$4,$5,now(),now())").bind(&session.device).bind(&session.account).bind(name).bind(challenge.device.encryption_key.as_slice()).bind(challenge.device.signing_key.as_slice()).execute(&mut *tx).await.map_err(storage)?;
        sqlx::query("INSERT INTO device_keys(id,device_id,public_key,ed25519_pk,created_at) VALUES($1,$2,$3,$4,now())").bind(uuid::Uuid::new_v4().to_string()).bind(&session.device).bind(challenge.device.encryption_key.as_slice()).bind(challenge.device.signing_key.as_slice()).execute(&mut *tx).await.map_err(storage)?;
    }
    sqlx::query("INSERT INTO sessions(id,user_id,device_id,access_token_hash,refresh_token_hash,expires_at,refresh_expires_at,created_at,v3_authority,v3_family) VALUES($1,$2,$3,$4,$5,to_timestamp($6::DOUBLE PRECISION/1000),to_timestamp($7::DOUBLE PRECISION/1000),now(),$8,$1)").bind(&session.id).bind(&session.account).bind(&session.device).bind(service::hash_token(&session.access_token)).bind(service::hash_token(&session.refresh_token)).bind(session.expires_at).bind(session.refresh_expires_at).bind(session.authorization.as_slice()).execute(&mut *tx).await.map_err(storage)?;
    let envelope = Envelope::seal(&challenge, &session).map_err(|_| denied())?;
    sqlx::query(
        "UPDATE device_session_attempts SET proof_hash=$2,response=$3,session_id=$4 WHERE id=$1",
    )
    .bind(&id)
    .bind(digest.as_slice())
    .bind(encode(&envelope)?)
    .bind(&session.id)
    .execute(&mut *tx)
    .await
    .map_err(storage)?;
    tx.commit().await.map_err(storage)?;
    Ok(Json(envelope))
}
