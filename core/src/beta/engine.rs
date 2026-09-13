use super::{
    account::Account,
    store::{decode, Store},
    MessageRequest, Peer,
};
use crate::{api, client::DisplayMessage, secret_store};
use futures_util::{SinkExt, StreamExt};
use liteseal_shared::{
    crypto,
    protocol::{ClientMessage, ServerMessage, SignedEnvelopeV2},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    sync::{watch, Mutex as AsyncMutex, Notify},
    time::{timeout, Instant},
};
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{protocol::WebSocketConfig, Message},
    MaybeTlsStream, WebSocketStream,
};

type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Connecting,
    Online,
    Reconnecting,
    Offline,
    AuthRequired,
    LoggedOut,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub connection: ConnectionState,
    pub revision: u64,
    pub generation: String,
    pub last_error: Option<String>,
}

pub struct Engine {
    store: Mutex<Store>,
    account: AsyncMutex<Account>,
    account_path: PathBuf,
    state: Mutex<(ConnectionState, Option<String>)>,
    revision: AtomicU64,
    generation: String,
    stop: watch::Sender<bool>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    wake: Notify,
    attempts: Mutex<HashMap<String, Instant>>,
}

impl Engine {
    pub fn new(database: &str, account_path: PathBuf, account: Account) -> Result<Arc<Self>> {
        let (stop, _) = watch::channel(false);
        Ok(Arc::new(Self {
            store: Mutex::new(Store::open(database)?),
            account: AsyncMutex::new(account),
            account_path,
            state: Mutex::new((ConnectionState::Offline, None)),
            revision: AtomicU64::new(1),
            generation: uuid::Uuid::new_v4().to_string(),
            stop,
            task: Mutex::new(None),
            wake: Notify::new(),
            attempts: Mutex::new(HashMap::new()),
        }))
    }
    pub fn start(self: &Arc<Self>) {
        let mut task = self.task.lock().unwrap();
        if task.is_some() {
            return;
        }
        let engine = self.clone();
        let mut cancel = self.stop.subscribe();
        *task = Some(tokio::spawn(async move {
            tokio::select! {_ = cancel.changed()=>{},_ = engine.run()=>{}}
        }));
    }
    pub async fn stop(&self) {
        self.stop.send_replace(true);
        let task = self.task.lock().unwrap().take();
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
        self.set_state(ConnectionState::LoggedOut, None);
    }
    pub async fn account(&self) -> Account {
        self.account.lock().await.clone()
    }
    pub fn with_store<T>(&self, f: impl FnOnce(&Store) -> Result<T>) -> Result<T> {
        if *self.stop.borrow() {
            return Err("Account session has ended".into());
        }
        let store = self.store.lock().map_err(|_| "Local store lock failed")?;
        f(&store)
    }
    fn changed(&self) {
        self.revision.fetch_add(1, Ordering::Relaxed);
    }
    fn set_state(&self, state: ConnectionState, error: Option<String>) {
        *self.state.lock().unwrap() = (state, error);
        self.changed();
    }
    fn report(&self, error: String) {
        self.state.lock().unwrap().1 = Some(error);
        self.changed();
    }
    pub fn snapshot(&self) -> Snapshot {
        let state = self.state.lock().unwrap();
        Snapshot {
            connection: state.0,
            last_error: state.1.clone(),
            revision: self.revision.load(Ordering::Relaxed),
            generation: self.generation.clone(),
        }
    }
    pub fn reconnect(&self) {
        self.wake.notify_one();
    }
    pub async fn queue(&self, recipient: &str, plaintext: &str) -> Result<String> {
        let account = self.account().await;
        let id = self.with_store(|s| s.queue(&account.user_id, recipient, plaintext))?;
        self.changed();
        self.wake.notify_one();
        Ok(id)
    }
    pub fn retry(&self, id: &str) -> Result<()> {
        self.with_store(|s| s.retry(id))?;
        self.attempts.lock().unwrap().remove(id);
        self.changed();
        self.wake.notify_one();
        Ok(())
    }
    pub fn contacts(&self) -> Result<Vec<Peer>> {
        self.with_store(|s| s.contacts())
    }
    pub fn requests(&self) -> Result<Vec<MessageRequest>> {
        self.with_store(|s| s.requests())
    }
    pub fn verify(&self, id: &str, fingerprint: &str, verified: bool) -> Result<()> {
        self.with_store(|s| s.accept(id, fingerprint, verified))?;
        self.changed();
        self.wake.notify_one();
        Ok(())
    }
    pub fn block(&self, id: &str, blocked: bool) -> Result<()> {
        self.with_store(|s| s.block(id, blocked))?;
        self.changed();
        self.wake.notify_one();
        Ok(())
    }
    pub async fn add_contact(&self, id: &str) -> Result<()> {
        let peer = self.resolve_peer(id).await?;
        self.verify(id, &peer.fingerprint, false)
    }
    pub async fn history(
        &self,
        recipient: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DisplayMessage>> {
        let a = self.account().await;
        self.with_store(|s| s.history(&a.user_id, &a.device_id, recipient, limit, offset))
    }

    async fn resolve_peer(&self, id: &str) -> Result<Peer> {
        let a = self.account().await;
        let devices =
            api::get_user_devices(a.server_url.clone(), id.into(), a.access_token.clone()).await?;
        let active: Vec<_> = devices.into_iter().filter(|d| !d.revoked).collect();
        if active.len() != 1 {
            return Err("Contact must have exactly one active device".into());
        }
        let d = &active[0];
        let old = self.with_store(|s| s.peer(id))?;
        let username = if let Some(old) = old.filter(|p| p.username != p.user_id) {
            old.username
        } else {
            api::search_users(a.server_url.clone(), id.into(), a.access_token.clone())
                .await?
                .into_iter()
                .find(|user| user.user_id == id)
                .map(|user| user.username)
                .unwrap_or_else(|| id.into())
        };
        let peer = Peer {
            user_id: id.into(),
            username,
            device_id: d.id.clone(),
            public_key: d.public_key.clone(),
            ed25519_pk: d.ed25519_pk.clone(),
            fingerprint: crate::contacts::fingerprint(&d.ed25519_pk),
            accepted: false,
            verified: false,
            blocked: false,
            key_changed: false,
        };
        self.with_store(|s| s.discover(&peer))?;
        self.changed();
        Ok(peer)
    }

    async fn run(&self) {
        let mut attempt = 0;
        loop {
            self.set_state(
                if attempt == 0 {
                    ConnectionState::Connecting
                } else {
                    ConnectionState::Reconnecting
                },
                None,
            );
            match self.connect().await {
                Ok(mut socket) => {
                    attempt = 0;
                    self.attempts.lock().unwrap().clear();
                    self.set_state(ConnectionState::Online, None);
                    if let Err(error) = self.drive(&mut socket).await {
                        self.report(error);
                    }
                }
                Err(error) if error == "authentication_refused" => {
                    let a = self.account().await;
                    let refreshed =
                        api::refresh_session(a.server_url.clone(), a.refresh_token.clone()).await;
                    match refreshed {
                        Ok(tokens) => {
                            let mut next = a;
                            next.access_token = tokens.access_token.unwrap_or(tokens.token);
                            next.refresh_token = tokens.refresh_token.unwrap_or_default();
                            if let Err(e) = self.save_account(&next) {
                                self.set_state(ConnectionState::AuthRequired, Some(e));
                                return;
                            }
                            *self.account.lock().await = next;
                            match self.connect().await {
                                Ok(mut socket) => {
                                    attempt = 0;
                                    self.set_state(ConnectionState::Online, None);
                                    if let Err(e) = self.drive(&mut socket).await {
                                        self.report(e);
                                    }
                                }
                                Err(e) if e == "authentication_refused" => {
                                    self.set_state(
                                        ConnectionState::AuthRequired,
                                        Some("Sign in again to resume synchronization".into()),
                                    );
                                    return;
                                }
                                Err(e) => self.report(e),
                            }
                        }
                        Err(e)
                            if e.contains("401")
                                || e.contains("403")
                                || a.refresh_token.is_empty() =>
                        {
                            self.set_state(
                                ConnectionState::AuthRequired,
                                Some("Sign in again to resume synchronization".into()),
                            );
                            return;
                        }
                        Err(e) => self.report(e),
                    }
                }
                Err(error) => self.report(error),
            }
            self.state.lock().unwrap().0 = ConnectionState::Reconnecting;
            self.changed();
            let delay = retry_delay(attempt);
            attempt = (attempt + 1).min(5);
            tokio::select! {_ = tokio::time::sleep(delay)=>{},_ = self.wake.notified()=>{}}
        }
    }

    fn save_account(&self, account: &Account) -> Result<()> {
        let bytes = serde_json::to_vec(account).map_err(|e| e.to_string())?;
        secret_store::secret_store(self.account_path.clone()).save(&bytes)
    }

    async fn connect(&self) -> Result<Socket> {
        let a = self.account().await;
        let base = api::normalize_server_url(&a.server_url)?;
        let url = format!(
            "{}/ws",
            base.replacen("https://", "wss://", 1)
                .replacen("http://", "ws://", 1)
        );
        let config = WebSocketConfig {
            max_message_size: Some(64 * 1024),
            max_frame_size: Some(64 * 1024),
            ..Default::default()
        };
        let (mut socket, _) = timeout(
            Duration::from_secs(10),
            connect_async_with_config(url, Some(config), false),
        )
        .await
        .map_err(|_| "Connection timed out")?
        .map_err(|_| "Unable to connect to relay")?;
        send(
            &mut socket,
            ClientMessage::Auth {
                user_id: a.user_id.clone(),
                device_id: a.device_id.clone(),
                token: a.access_token.clone(),
            },
        )
        .await?;
        let auth = timeout(Duration::from_secs(5), socket.next())
            .await
            .map_err(|_| "Authentication timed out")?
            .ok_or("Relay closed")?
            .map_err(|_| "Authentication transport failed")?;
        let Message::Text(auth) = auth else {
            return Err("Invalid authentication response".into());
        };
        match serde_json::from_str::<ServerMessage>(&auth)
            .map_err(|_| "Invalid authentication response")?
        {
            ServerMessage::AuthOk => Ok(socket),
            ServerMessage::AuthFail { .. } => Err("authentication_refused".into()),
            _ => Err("Unsupported relay response".into()),
        }
    }

    async fn drive(&self, socket: &mut Socket) -> Result<()> {
        self.query(socket).await?;
        let mut work = tokio::time::interval(Duration::from_millis(250));
        let mut query = tokio::time::interval(Duration::from_secs(30));
        query.tick().await;
        let mut ping = tokio::time::interval(Duration::from_secs(20));
        ping.tick().await;
        let mut ping_sent: Option<Instant> = None;
        loop {
            tokio::select! {
                biased;
                message=socket.next()=>{
                    let message=message.ok_or("Relay disconnected")?.map_err(|_|"Relay transport failed")?;
                    match message {
                        Message::Text(text)=>{
                            let message=serde_json::from_str::<ServerMessage>(&text).map_err(|_|"Unsupported relay message")?;
                            match message {
                                ServerMessage::MessageV2{envelope,..}=>{let a=self.account().await;if let Err(e)=self.with_store(|s|s.receive(&a.user_id,&a.device_id,&envelope)){self.report(e);}self.changed();}
                                ServerMessage::DeliveryUpdate{updates}=>for update in updates {
                                    if update.status=="unknown" {self.with_store(|s|s.status(&update.message_id,"retry_wait",""))?;}
                                    else {self.with_store(|s|s.status(&update.message_id,&update.status,""))?;}
                                    self.attempts.lock().unwrap().remove(&update.message_id);self.changed();
                                },
                                ServerMessage::MessageError{message_id,code,retryable,..}=>{
                                    self.with_store(|s|s.status(&message_id,if retryable{"retry_wait"}else{"failed"},&code))?;
                                    self.attempts.lock().unwrap().insert(message_id,Instant::now()+Duration::from_secs(30));self.report(code);
                                }
                                ServerMessage::Error{code,..}=>self.report(code),
                                _=>{},
                            }
                        }
                        Message::Pong(_)=>ping_sent=None,
                        Message::Ping(bytes)=>{timeout(Duration::from_secs(5),socket.send(Message::Pong(bytes))).await.map_err(|_|"Pong timed out")?.map_err(|_|"Pong failed")?;}
                        Message::Close(_)=>return Err("Relay disconnected".into()),
                        _=>{},
                    }
                }
                _=ping.tick()=>{
                    timeout(Duration::from_secs(5),socket.send(Message::Ping(Vec::new()))).await.map_err(|_|"Heartbeat send timed out")?.map_err(|_|"Heartbeat failed")?;
                    ping_sent=Some(Instant::now());
                }
                _=query.tick()=>self.query(socket).await?,
                _=work.tick()=>{
                    if ping_sent.is_some_and(|sent|sent.elapsed()>Duration::from_secs(10)){return Err("Heartbeat timed out".into());}
                    match timeout(Duration::from_secs(5),self.flush(socket)).await {Ok(result)=>result?,Err(_)=>self.report("Synchronization request timed out; retrying".into())}
                }
                _=self.wake.notified()=>{self.flush(socket).await?;}
            }
        }
    }

    async fn query(&self, socket: &mut Socket) -> Result<()> {
        let ids = self.with_store(|s| s.unresolved())?;
        for chunk in ids.chunks(100) {
            send(
                socket,
                ClientMessage::DeliveryQuery {
                    message_ids: chunk.to_vec(),
                },
            )
            .await?;
        }
        Ok(())
    }

    async fn flush(&self, socket: &mut Socket) -> Result<()> {
        let account = self.account().await;
        let secret = account.encryption_secret()?;
        let mut resolved = false;
        for item in self.with_store(|s| s.pending())? {
            let peer = self.with_store(|s| s.peer(&item.sender_user_id))?;
            if peer.is_some_and(|p| p.device_id.is_empty()) {
                if resolved {
                    continue;
                }
                resolved = true;
                if let Err(e) = self.resolve_peer(&item.sender_user_id).await {
                    self.report(e);
                    continue;
                }
            }
            match self.with_store(|s| s.process(&secret, &item)) {
                Ok(true) => self.changed(),
                Ok(false) => {}
                Err(e) => self.report(e),
            }
        }
        for (id, outcome) in self.with_store(|s| s.acks())? {
            send(
                socket,
                ClientMessage::AckV2 {
                    message_id: id.clone(),
                    outcome,
                },
            )
            .await?;
            self.with_store(|s| s.ack_sent(&id))?;
        }
        for outgoing in self.with_store(|s| s.ready())?.into_iter().take(4) {
            if self
                .attempts
                .lock()
                .unwrap()
                .get(&outgoing.id)
                .is_some_and(|at| *at > Instant::now())
            {
                continue;
            }
            let result: Result<SignedEnvelopeV2> = async {
                let peer = self.resolve_peer(&outgoing.recipient).await?;
                let current = self
                    .with_store(|s| s.peer(&outgoing.recipient))?
                    .ok_or("Contact unavailable")?;
                if !current.verified || current.blocked || current.key_changed {
                    return Err("Contact verification required".into());
                }
                if let Some(envelope) = outgoing.envelope {
                    return Ok(envelope);
                }
                let body = decode(&outgoing.body)?;
                let signing = account.signing_secret()?;
                let recipient: [u8; 32] = peer
                    .public_key
                    .try_into()
                    .map_err(|_| "Invalid recipient key")?;
                let conversation =
                    crate::chat::canonical_conversation_id(&account.user_id, &outgoing.recipient);
                self.with_store(|store| {
                    store.seal(
                        &outgoing.id,
                        &conversation,
                        &account.device_id,
                        |seq, prev_hash| {
                            let mut e = SignedEnvelopeV2 {
                                protocol_version: 2,
                                message_id: outgoing.id.clone(),
                                conversation_id: conversation.clone(),
                                sender_user_id: account.user_id.clone(),
                                sender_device_id: account.device_id.clone(),
                                recipient_user_id: outgoing.recipient.clone(),
                                recipient_device_id: peer.device_id,
                                sender_seq: seq,
                                prev_hash,
                                sent_at: chrono::Utc::now().timestamp_millis(),
                                message_type: "text".into(),
                                ciphertext: crypto::encrypt(body.as_bytes(), &recipient, &secret)
                                    .map_err(|e| e.to_string())?,
                                signature: vec![],
                            };
                            e.signature = crypto::sign(
                                &e.signing_bytes().map_err(|e| e.to_string())?,
                                &signing,
                            )
                            .map_err(|e| e.to_string())?;
                            Ok(e)
                        },
                    )
                })
            }
            .await;
            match result {
                Ok(envelope) => {
                    self.with_store(|s| s.status(&outgoing.id, "sending", ""))?;
                    self.attempts
                        .lock()
                        .unwrap()
                        .insert(outgoing.id, Instant::now() + Duration::from_secs(15));
                    send(
                        socket,
                        ClientMessage::SendV2 {
                            envelopes: vec![envelope],
                        },
                    )
                    .await?;
                    self.changed();
                }
                Err(e) => {
                    let permanent = e.contains("identity changed")
                        || e.contains("verification required")
                        || e.contains("one active device");
                    self.with_store(|s| {
                        s.status(
                            &outgoing.id,
                            if permanent { "failed" } else { "retry_wait" },
                            &e,
                        )
                    })?;
                    self.attempts
                        .lock()
                        .unwrap()
                        .insert(outgoing.id, Instant::now() + Duration::from_secs(5));
                    self.report(e);
                }
            }
        }
        Ok(())
    }
}

async fn send(socket: &mut Socket, message: ClientMessage) -> Result<()> {
    let json = serde_json::to_string(&message).map_err(|e| e.to_string())?;
    timeout(Duration::from_secs(5), socket.send(Message::Text(json)))
        .await
        .map_err(|_| "Relay write timed out")?
        .map_err(|_| "Relay write failed".into())
}

fn retry_delay(attempt: u32) -> Duration {
    let seconds = (1u64 << attempt.min(5)).min(30);
    let noise =
        u16::from_le_bytes(uuid::Uuid::new_v4().as_bytes()[..2].try_into().unwrap()) as u64 % 401;
    Duration::from_millis(seconds * (800 + noise))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn backoff_is_bounded() {
        for attempt in 0..20 {
            let delay = retry_delay(attempt);
            let base = (1u64 << attempt.min(5)).min(30);
            assert!(delay >= Duration::from_millis(base * 800));
            assert!(delay <= Duration::from_millis(base * 1200));
        }
    }
}
