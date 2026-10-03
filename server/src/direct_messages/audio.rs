//! Foreground-only, bounded ephemeral audio relay. No database ciphertext,
//! chat receipts, notifications or reconnect/offline replay are created.
use super::*;
use liteseal_shared::{crypto, voice_call as v};
use std::{collections::HashMap, time::{Duration, Instant}};

const PRESENCE: Duration = Duration::from_secs(10);
const SETUP: Duration = Duration::from_secs(30);
const MAX_ROOMS: usize = 64;
const MAX_PRESENCE: usize = 1024;
const MAX_CLOSED: usize = 1024;
struct Presence { hash: String, until: Instant }
struct Room {
    admission: v::Admission,
    ticket: String,
    hashes: [String; 2],
    queues: [Option<v::Envelope>; 2],
    last: [Option<v::Receipt>; 2],
    fences: [v::ReplayFence; 2],
    created: Instant,
    answered: bool,
    awaiting: Option<usize>,
}
struct Closed { digest: [u8; 32], until: Instant }
#[derive(Default)]
pub(crate) struct Hub {
    presence: HashMap<String, Presence>,
    rooms: HashMap<String, Room>,
    closed: HashMap<String, Closed>,
}
impl Room {
    fn index(&self, user: &str, device: &str) -> Result<usize, Failure> {
        let h = &self.admission.header;
        if h.sender == user && h.source.device.device_id == device { Ok(0) }
        else if h.peer == user && h.target.device.device_id == device { Ok(1) }
        else { Err(denied()) }
    }
    fn devices(&self) -> [&str; 2] {
        [&self.admission.header.source.device.device_id, &self.admission.header.target.device.device_id]
    }
}
impl Hub {
    fn close(&mut self, id: &str) {
        if let Some(room) = self.rooms.remove(id) {
            // Admission freshness is <=30s. Preserve a terminal barrier twice
            // that long, including a lost admission/stop HTTP response.
            self.closed.insert(id.into(), Closed {
                digest: room.admission.digest().expect("validated admission"),
                until: Instant::now() + Duration::from_secs(60),
            });
        }
    }
    fn trim(&mut self) {
        let now = Instant::now();
        self.presence.retain(|_, p| now < p.until);
        self.closed.retain(|_, c| now < c.until);
        let expired: Vec<_> = self.rooms.iter().filter(|(_, r)| {
            now.duration_since(r.created) >= Duration::from_secs(3600)
                || (!r.answered && now.duration_since(r.created) >= SETUP)
                || r.devices().iter().enumerate().any(|(i, device)| {
                    self.presence.get(*device).is_none_or(|p| p.hash != r.hashes[i])
                })
                || r.queues.iter().flatten().any(|e| now_ms() >= e.header.expires_at)
        }).map(|(id, _)| id.clone()).collect();
        for id in expired { self.close(&id); }
    }
}
fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64).unwrap_or(0)
}
fn capacity() -> Failure { (StatusCode::TOO_MANY_REQUESTS, "audio call capacity reached".into()) }
fn unavailable() -> Failure { (StatusCode::CONFLICT, "audio participant unavailable; start a new call".into()) }
fn proof(_: v::CallError) -> Failure { denied() }
fn valid_id(id: &str) -> Result<(), Failure> {
    if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        Err(bad())
    } else { Ok(()) }
}
async fn actor(state: &AppState, headers: &HeaderMap, device: &str) -> Result<(String, String), Failure> {
    origin(state)?;
    uuid(device)?;
    let hash = token(headers)?;
    let user = state.db.validate_access_token(&hash, device).await.map_err(storage)?.ok_or_else(unauthorized)?;
    // Polling cannot consume the durable message delivery rate bucket.
    if !state.db.hit_rate_limit(&format!("audio-v1:{device}"), 180, 60).await.map_err(storage)? {
        return Err(capacity());
    }
    Ok((user, hash))
}
async fn directories(tx: &mut Tx<'_>, admission: &v::Admission, realm: &str)
    -> Result<(DeviceState, DeviceState), Failure> {
    let h = &admission.header;
    lock_accounts(tx, &[&h.sender, &h.peer]).await?;
    if !crate::device_activation::enabled(tx, &h.sender).await.map_err(storage)?
        || !crate::device_activation::enabled(tx, &h.peer).await.map_err(storage)? { return Err(denied()); }
    let (sender, _) = current(tx, &h.sender, realm).await?;
    let (peer, _) = current(tx, &h.peer, realm).await?;
    admission.verify(&sender, &peer).map_err(proof)?;
    Ok((sender, peer))
}
async fn live(tx: &mut Tx<'_>, room: &Room, realm: &str) -> Result<(DeviceState, DeviceState), Failure> {
    let (sender, peer) = directories(tx, &room.admission, realm).await?;
    let h = &room.admission.header;
    session(tx, &room.hashes[0], &h.sender, &h.source.device.device_id, &sender).await?;
    session(tx, &room.hashes[1], &h.peer, &h.target.device.device_id, &peer).await?;
    policy(tx, &h.sender, &h.peer).await?;
    policy(tx, &h.peer, &h.sender).await?;
    Ok((sender, peer))
}
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/audio/v1/admit", post(reserve))
        .route("/audio/v1/signal", post(signal))
        .route("/audio/v1/stop", post(stop))
        .route("/audio/v1/pending", get(pending))
        .route("/audio/v1/ack", post(acknowledge))
        .layer(DefaultBodyLimit::max(v::MAX_WIRE * 2))
}
async fn reserve(State(state): State<AppState>, headers: HeaderMap, Json(admission): Json<v::Admission>)
    -> Result<Json<v::Reservation>, Failure> {
    let h = &admission.header;
    let (user, hash) = actor(&state, &headers, &h.source.device.device_id).await?;
    if user != h.sender || h.origin != origin(&state)? { return Err(denied()); }
    let mut hub = state.audio.lock().await;
    hub.trim();
    let mut tx = state.db.pool().begin().await.map_err(storage)?;
    let (sender, peer) = directories(&mut tx, &admission, origin(&state)?).await?;
    session(&mut tx, &hash, &user, &h.source.device.device_id, &sender).await?;
    admission.fresh(now_ms()).map_err(proof)?;
    let digest = admission.digest().map_err(proof)?;
    if let Some(closed) = hub.closed.get(&h.id) {
        return Err(if closed.digest == digest { unavailable() } else { conflict() });
    }
    if let Some(room) = hub.rooms.get(&h.id) {
        live(&mut tx, room, origin(&state)?).await?;
        if room.admission.digest().map_err(proof)? != digest || room.hashes[0] != hash { return Err(conflict()); }
        return Ok(Json(v::Reservation { id: h.id.clone(), ticket: room.ticket.clone() }));
    }
    if hub.rooms.len() >= MAX_ROOMS || hub.closed.len() + hub.rooms.len() >= MAX_CLOSED { return Err(capacity()); }
    let target_hash = hub.presence.get(&h.target.device.device_id).ok_or_else(unavailable)?.hash.clone();
    session(&mut tx, &target_hash, &h.peer, &h.target.device.device_id, &peer).await?;
    policy(&mut tx, &h.sender, &h.peer).await?;
    policy(&mut tx, &h.peer, &h.sender).await?;
    if hub.rooms.values().any(|r| r.devices().iter().any(|d|
        *d == h.source.device.device_id || *d == h.target.device.device_id)) { return Err(unavailable()); }
    if !hub.presence.contains_key(&h.source.device.device_id) && hub.presence.len() >= MAX_PRESENCE { return Err(capacity()); }
    let ticket = hex::encode(crypto::random_challenge().map_err(|_| unavailable())?);
    hub.presence.insert(h.source.device.device_id.clone(), Presence { hash: hash.clone(), until: Instant::now() + PRESENCE });
    let response = v::Reservation { id: h.id.clone(), ticket: ticket.clone() };
    hub.rooms.insert(h.id.clone(), Room { admission, ticket, hashes: [hash, target_hash],
        queues: [None, None], last: [None, None], fences: Default::default(),
        created: Instant::now(), answered: false, awaiting: None });
    tx.commit().await.map_err(storage)?;
    Ok(Json(response))
}
async fn signal(State(state): State<AppState>, headers: HeaderMap, Json(input): Json<v::Submission>)
    -> Result<Json<v::Receipt>, Failure> {
    let h = &input.envelope.header;
    let (user, hash) = actor(&state, &headers, &h.source.device.device_id).await?;
    let mut hub = state.audio.lock().await;
    hub.trim();
    let mut tx = state.db.pool().begin().await.map_err(storage)?;
    let room = hub.rooms.get_mut(&h.id).ok_or_else(unavailable)?;
    let i = room.index(&user, &h.source.device.device_id)?;
    if input.ticket != room.ticket || room.hashes[i] != hash { return Err(denied()); }
    let (sender, peer) = live(&mut tx, room, origin(&state)?).await?;
    let original = &room.admission.header;
    let (source, target) = if i == 0 { (&original.source, &original.target) } else { (&original.target, &original.source) };
    if &h.source != source || &h.target != target || h.origin != original.origin { return Err(denied()); }
    if i == 0 { input.envelope.verify(&sender, &peer) } else { input.envelope.verify(&peer, &sender) }.map_err(proof)?;
    if now_ms() < h.sent_at || now_ms() >= h.expires_at { return Err(unavailable()); }
    let digest = input.envelope.digest().map_err(proof)?;
    let receipt = v::Receipt { id: h.id.clone(), sequence: h.sequence, digest };
    if room.last[i].as_ref().is_some_and(|last| last.sequence == h.sequence && last.digest == digest) { return Ok(Json(receipt)); }
    if room.queues[i].is_some() { return Err(conflict()); }
    let (awaiting, answered) = match h.kind {
        v::Kind::Offer if i == 0 && h.sequence == 1 && room.awaiting.is_none() && !room.answered => (Some(1), false),
        v::Kind::Answer if room.awaiting == Some(i) => (None, true),
        v::Kind::Restart if room.answered && room.awaiting.is_none() => (Some(1 - i), true),
        v::Kind::Reject if i == 1 && !room.answered => (room.awaiting, false),
        v::Kind::Hangup => (room.awaiting, room.answered),
        _ => return Err(conflict()),
    };
    room.fences[i].admit(&input.envelope).map_err(proof)?;
    room.awaiting = awaiting;
    room.answered = answered;
    let terminal = matches!(h.kind, v::Kind::Reject | v::Kind::Hangup);
    room.last[i] = Some(v::Receipt { id: h.id.clone(), sequence: h.sequence, digest });
    room.queues[i] = Some(input.envelope);
    let id = receipt.id.clone();
    if terminal { hub.close(&id); }
    tx.commit().await.map_err(storage)?;
    Ok(Json(receipt))
}
#[derive(Deserialize)]
struct Poll { device: String, active: Option<String> }
async fn pending(State(state): State<AppState>, headers: HeaderMap, Query(query): Query<Poll>)
    -> Result<Json<v::Pending>, Failure> {
    if let Some(id) = &query.active { valid_id(id)?; }
    let (user, hash) = actor(&state, &headers, &query.device).await?;
    let mut hub = state.audio.lock().await;
    let mut tx = state.db.pool().begin().await.map_err(storage)?;
    lock_accounts(&mut tx, &[&user]).await?;
    if !crate::device_activation::enabled(&mut tx, &user).await.map_err(storage)? { return Err(denied()); }
    let (directory, _) = current(&mut tx, &user, origin(&state)?).await?;
    session(&mut tx, &hash, &user, &query.device, &directory).await?;
    // Release the one-account transaction before acquiring ordered two-account
    // locks. A policy/directory writer can never invert our lock order.
    tx.commit().await.map_err(storage)?;
    if !hub.presence.contains_key(&query.device) && hub.presence.len() >= MAX_PRESENCE { return Err(capacity()); }
    hub.presence.insert(query.device.clone(), Presence { hash: hash.clone(), until: Instant::now() + PRESENCE });
    hub.trim();
    let id = hub.rooms.iter().find(|(_, r)| r.index(&user, &query.device).is_ok()).map(|(id, _)| id.clone());
    if let Some(id) = id {
        let mut tx = state.db.pool().begin().await.map_err(storage)?;
        let room = &hub.rooms[&id];
        let i = room.index(&user, &query.device)?;
        if room.hashes[i] != hash || live(&mut tx, room, origin(&state)?).await.is_err() {
            hub.close(&id);
        } else {
            let delivery = room.queues[1 - i].as_ref().map(|envelope| v::Delivery {
                admission: room.admission.clone(), ticket: room.ticket.clone(), envelope: envelope.clone(),
            });
            tx.commit().await.map_err(storage)?;
            return Ok(Json(v::Pending { delivery, closed: query.active.filter(|active| active != &id) }));
        }
    }
    Ok(Json(v::Pending { delivery: None, closed: query.active }))
}
async fn acknowledge(State(state): State<AppState>, headers: HeaderMap, Json(input): Json<v::Acknowledge>)
    -> Result<Json<v::Receipt>, Failure> {
    let (user, hash) = actor(&state, &headers, &input.device).await?;
    let mut hub = state.audio.lock().await;
    hub.trim();
    let mut tx = state.db.pool().begin().await.map_err(storage)?;
    let room = hub.rooms.get_mut(&input.receipt.id).ok_or_else(unavailable)?;
    let i = room.index(&user, &input.device)?;
    if room.hashes[i] != hash || room.ticket != input.ticket { return Err(denied()); }
    live(&mut tx, room, origin(&state)?).await?;
    let last = room.last[1 - i].as_ref().ok_or_else(conflict)?;
    if last.sequence != input.receipt.sequence || last.digest != input.receipt.digest { return Err(conflict()); }
    room.queues[1 - i] = None;
    tx.commit().await.map_err(storage)?;
    Ok(Json(input.receipt))
}
async fn stop(State(state): State<AppState>, headers: HeaderMap, Json(input): Json<v::Stop>)
    -> Result<Json<String>, Failure> {
    let (user, hash) = actor(&state, &headers, &input.actor.device.device_id).await?;
    let mut hub = state.audio.lock().await;
    hub.trim();
    let mut tx = state.db.pool().begin().await.map_err(storage)?;
    let (sender, peer) = directories(&mut tx, &input.admission, origin(&state)?).await?;
    input.verify(&sender, &peer).map_err(proof)?;
    let h = &input.admission.header;
    let own = if input.actor == h.source && user == h.sender { &sender }
        else if input.actor == h.target && user == h.peer { &peer } else { return Err(denied()); };
    session(&mut tx, &hash, &user, &input.actor.device.device_id, own).await?;
    let digest = input.admission.digest().map_err(proof)?;
    if let Some(room) = hub.rooms.get(&h.id) {
        if room.admission.digest().map_err(proof)? != digest { return Err(conflict()); }
        hub.close(&h.id);
    } else if let Some(closed) = hub.closed.get(&h.id) {
        if closed.digest != digest { return Err(conflict()); }
    } else {
        input.admission.fresh(now_ms()).map_err(proof)?;
        if hub.closed.len() + hub.rooms.len() >= MAX_CLOSED { return Err(capacity()); }
        hub.closed.insert(h.id.clone(), Closed { digest, until: Instant::now() + Duration::from_secs(60) });
    }
    tx.commit().await.map_err(storage)?;
    Ok(Json(h.id.clone()))
}
