//! Isolated T24 test gateway. Fresh synthetic keys stay in this Rust process.
//! It cannot load production identities, sessions, files or network addresses.
use liteseal_shared::{
    crypto::{self, KeyPair},
    trusted_device::{Anchor, DeviceIdentity, DeviceState},
    voice_call::{Envelope, Header, Kind, ReplayFence, Signal, SignalSpec, MAX_WIRE},
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    io::{self, BufRead, Read, Write},
    time::{SystemTime, UNIX_EPOCH},
};
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Begin { actor: String },
    Seal { actor: String, signal: Signal },
    Open { actor: String, wire: Box<Envelope> },
    Retire { actor: String, id: String },
}
struct Identity {
    keys: KeyPair,
    state: DeviceState,
}
impl Drop for Identity {
    fn drop(&mut self) {
        unsafe {
            libsodium_sys::sodium_memzero(
                self.keys.secret_key.as_mut_ptr().cast(),
                self.keys.secret_key.len(),
            );
            libsodium_sys::sodium_memzero(
                self.keys.ed25519_sk.as_mut_ptr().cast(),
                self.keys.ed25519_sk.len(),
            );
        }
    }
}
impl Identity {
    fn new(account: &str) -> Self {
        let keys = crypto::generate_keypair().expect("synthetic key generation");
        let state = DeviceState::pin(Anchor {
            origin: "https://voice-trial.invalid".into(),
            account: account.into(),
            root: DeviceIdentity::from_keys(format!("{account}-root"), &keys),
        })
        .expect("synthetic anchor");
        Self { keys, state }
    }
}
struct Call {
    caller: usize,
    sequence: [u64; 2],
    receive: [ReplayFence; 2],
    offered: bool,
    established: bool,
    terminal: bool,
    retired: [bool; 2],
}
struct Gateway {
    identities: [Identity; 2],
    calls: HashMap<String, Call>,
}
fn actor(name: &str) -> std::result::Result<usize, ()> {
    match name {
        "alice" => Ok(0),
        "bob" => Ok(1),
        _ => Err(()),
    }
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis() as i64
}
impl Gateway {
    fn run(&mut self, request: Request) -> std::result::Result<Value, ()> {
        match request {
            Request::Begin { actor: name } => {
                let caller = actor(&name)?;
                if self.calls.len() >= 256
                    || self
                        .calls
                        .values()
                        .any(|c| !c.terminal && !c.retired.iter().all(|v| *v))
                {
                    return Err(());
                }
                let id = crypto::random_challenge()
                    .map_err(|_| ())?
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>();
                self.calls.insert(
                    id.clone(),
                    Call {
                        caller,
                        sequence: [0, 0],
                        receive: Default::default(),
                        offered: false,
                        established: false,
                        terminal: false,
                        retired: [false, false],
                    },
                );
                Ok(json!(id))
            }
            Request::Seal {
                actor: name,
                signal,
            } => {
                let index = actor(&name)?;
                let call = self.calls.get_mut(&signal.id).ok_or(())?;
                if call.terminal || call.retired[index] {
                    return Err(());
                }
                match signal.kind {
                    Kind::Offer
                        if call.caller == index && !call.offered && call.sequence[index] == 0 => {}
                    Kind::Answer if call.offered && (call.caller != index || call.established) => {}
                    Kind::Restart if call.established => {}
                    Kind::Reject if call.offered && !call.established && call.caller != index => {}
                    Kind::Hangup => {}
                    _ => return Err(()),
                }
                let own = &self.identities[index];
                let peer = &self.identities[1 - index];
                let header = Header::new(
                    &own.state,
                    &own.state.anchor().root.device_id,
                    &peer.state,
                    &peer.state.anchor().root.device_id,
                    SignalSpec {
                        id: signal.id.clone(),
                        sequence: call.sequence[index] + 1,
                        sent_at: now(),
                        kind: signal.kind,
                    },
                )
                .map_err(|_| ())?;
                let wire = Envelope::seal(
                    header,
                    &own.state,
                    &peer.state,
                    &own.keys,
                    signal.sdp.clone(),
                )
                .map_err(|_| ())?;
                call.sequence[index] += 1;
                if signal.kind == Kind::Offer {
                    call.offered = true;
                }
                if signal.kind == Kind::Answer {
                    call.established = true;
                }
                if matches!(signal.kind, Kind::Reject | Kind::Hangup) {
                    call.terminal = true;
                }
                serde_json::to_value(wire).map_err(|_| ())
            }
            Request::Open { actor: name, wire } => {
                let index = actor(&name)?;
                let own = &self.identities[index];
                let peer = &self.identities[1 - index];
                let signal = wire
                    .open(&peer.state, &own.state, &own.keys, now())
                    .map_err(|_| ())?;
                let call = self.calls.get_mut(&signal.id).ok_or(())?;
                if call.retired[index] || (wire.header.kind == Kind::Offer && call.caller == index)
                {
                    return Err(());
                }
                if !call.receive[index].admit(&wire).map_err(|_| ())? {
                    return Ok(Value::Null);
                }
                serde_json::to_value(signal).map_err(|_| ())
            }
            Request::Retire { actor: name, id } => {
                let index = actor(&name)?;
                let call = self.calls.get_mut(&id).ok_or(())?;
                call.retired[index] = true;
                if !call.offered {
                    call.terminal = true;
                }
                Ok(Value::Null)
            }
        }
    }
}
fn main() {
    let mut gateway = Gateway {
        identities: [Identity::new("alice"), Identity::new("bob")],
        calls: HashMap::new(),
    };
    let input = io::stdin();
    let mut input = input.lock();
    let output = io::stdout();
    let mut output = output.lock();
    loop {
        let mut frame = String::new();
        let read = (&mut input)
            .take((MAX_WIRE + 40 * 1024) as u64)
            .read_line(&mut frame);
        match read {
            Ok(0) => break,
            Ok(_) if frame.ends_with('\n') => {}
            _ => break,
        }
        let response = serde_json::from_str::<Request>(&frame)
            .map_err(|_| ())
            .and_then(|request| gateway.run(request));
        // Requests can carry plaintext SDP. Never print or retain failed input.
        unsafe { libsodium_sys::sodium_memzero(frame.as_mut_ptr().cast(), frame.len()) };
        let response = match response {
            Ok(value) => json!({"ok":true,"value":value}),
            Err(()) => json!({"ok":false,"error":"voice trial request rejected"}),
        };
        if serde_json::to_writer(&mut output, &response).is_err()
            || writeln!(output).is_err()
            || output.flush().is_err()
        {
            break;
        }
    }
}
