//! T24 ephemeral audio signalling. These primitives do not grant a session,
//! create a relay, or persist a call. Callers must supply freshly verified,
//! independently pinned device directories and enforce call lifecycle admission.
use crate::{
    crypto::{self, KeyPair},
    direct_message::{Directory, Member},
    trusted_device::{canonical_origin, DeviceState},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const LIFETIME_MS: i64 = 30_000;
pub const MAX_SDP: usize = 32 * 1024;
pub const MAX_WIRE: usize = 256 * 1024;
pub const MAX_SIGNALS: u64 = 128;
const DOMAIN: &[u8] = b"LiteSeal/audio-call-signal/v1\0";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CallError {
    #[error("invalid audio signal or resource limit")]
    Shape,
    #[error("audio signal does not match the current trusted device scope")]
    Scope,
    #[error("audio signal authentication failed")]
    Proof,
    #[error("audio signal expired or not yet valid")]
    Expired,
    #[error("audio signal replay or sequence conflict")]
    Sequence,
}
type Result<T> = std::result::Result<T, CallError>;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Offer,
    Answer,
    Restart,
    Reject,
    Hangup,
}
impl Kind {
    fn has_sdp(self) -> bool {
        matches!(self, Self::Offer | Self::Answer | Self::Restart)
    }
    fn terminal(self) -> bool {
        matches!(self, Self::Reject | Self::Hangup)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub version: u8,
    pub id: String,
    pub origin: String,
    pub sender: String,
    pub source: Member,
    pub sender_directory: Directory,
    pub peer: String,
    pub target: Member,
    pub peer_directory: Directory,
    pub sequence: u64,
    pub sent_at: i64,
    pub expires_at: i64,
    pub kind: Kind,
}
pub struct SignalSpec {
    pub id: String,
    pub sequence: u64,
    pub sent_at: i64,
    pub kind: Kind,
}
fn member(state: &DeviceState, device: &str) -> Result<Member> {
    Directory::from_state(state)
        .members
        .into_iter()
        .find(|m| m.device.device_id == device)
        .ok_or(CallError::Scope)
}
impl Header {
    pub fn new(
        sender: &DeviceState,
        source: &str,
        peer: &DeviceState,
        target: &str,
        spec: SignalSpec,
    ) -> Result<Self> {
        let header = Self {
            version: 1,
            id: spec.id,
            origin: sender.anchor().origin.clone(),
            sender: sender.anchor().account.clone(),
            source: member(sender, source)?,
            sender_directory: Directory::from_state(sender),
            peer: peer.anchor().account.clone(),
            target: member(peer, target)?,
            peer_directory: Directory::from_state(peer),
            sequence: spec.sequence,
            sent_at: spec.sent_at,
            expires_at: spec
                .sent_at
                .checked_add(LIFETIME_MS)
                .ok_or(CallError::Shape)?,
            kind: spec.kind,
        };
        header.current(sender, peer)?;
        Ok(header)
    }
    fn shape(&self) -> Result<()> {
        if self.version != 1
            || self.id.len() != 64
            || !self
                .id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !(1..=MAX_SIGNALS).contains(&self.sequence)
            || self.sent_at <= 0
            || self.expires_at <= self.sent_at
            || self.expires_at - self.sent_at > LIFETIME_MS
            || self.expires_at > 8_640_000_000_000_000
            || canonical_origin(&self.origin).map_err(|_| CallError::Shape)? != self.origin
        {
            return Err(CallError::Shape);
        }
        Ok(())
    }
    fn current(&self, sender: &DeviceState, peer: &DeviceState) -> Result<()> {
        self.shape()?;
        if self.origin != sender.anchor().origin
            || self.origin != peer.anchor().origin
            || self.sender != sender.anchor().account
            || self.peer != peer.anchor().account
            || self.sender == self.peer
            || self.sender_directory != Directory::from_state(sender)
            || self.peer_directory != Directory::from_state(peer)
            || self.source != member(sender, &self.source.device.device_id)?
            || self.target != member(peer, &self.target.device.device_id)?
        {
            return Err(CallError::Scope);
        }
        Ok(())
    }
    fn bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = DOMAIN.to_vec();
        bytes.extend_from_slice(&serde_json::to_vec(self).map_err(|_| CallError::Shape)?);
        Ok(bytes)
    }
}
/// A caller's explicit, device-bound reservation. It authorizes only this
/// ephemeral call and never creates a messaging grant or an offline delivery.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Admission {
    pub header: Header,
    pub signature: Vec<u8>,
}
impl Admission {
    fn signing(&self) -> Result<Vec<u8>> {
        let mut bytes = b"LiteSeal/audio-call-admission/v1\0".to_vec();
        bytes.extend(serde_json::to_vec(&self.header).map_err(|_| CallError::Shape)?);
        Ok(bytes)
    }
    pub fn make(header: Header, keys: &KeyPair) -> Result<Self> {
        header.shape()?;
        if header.kind != Kind::Offer
            || header.sequence != 1
            || keys.public_key != header.source.device.encryption_key
            || keys.ed25519_pk != header.source.device.signing_key
        {
            return Err(CallError::Scope);
        }
        let mut value = Self {
            header,
            signature: vec![],
        };
        value.signature =
            crypto::sign(&value.signing()?, &keys.ed25519_sk).map_err(|_| CallError::Proof)?;
        Ok(value)
    }
    pub fn verify(&self, sender: &DeviceState, peer: &DeviceState) -> Result<()> {
        self.header.current(sender, peer)?;
        if self.header.kind != Kind::Offer
            || self.header.sequence != 1
            || self.signature.len() != 64
            || serde_json::to_vec(self)
                .map_err(|_| CallError::Shape)?
                .len()
                > MAX_WIRE
        {
            return Err(CallError::Shape);
        }
        if !crypto::verify_with_public_key(
            &self.signing()?,
            &self.signature,
            &self.header.source.device.signing_key,
        )
        .map_err(|_| CallError::Proof)?
        {
            return Err(CallError::Proof);
        }
        Ok(())
    }
    pub fn fresh(&self, now: i64) -> Result<()> {
        self.header.shape()?;
        if now < self.header.sent_at || now >= self.header.expires_at {
            return Err(CallError::Expired);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(serde_json::to_vec(self).map_err(|_| CallError::Shape)?).into())
    }
}
/// Either original participant may close the original reservation, including
/// after a lost admission response. Domain separation prevents signal reuse.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stop {
    pub admission: Admission,
    pub actor: Member,
    pub signature: Vec<u8>,
}
impl Stop {
    fn signing(&self) -> Result<Vec<u8>> {
        let mut bytes = b"LiteSeal/audio-call-stop/v1\0".to_vec();
        bytes.extend(self.admission.digest()?);
        bytes.extend(serde_json::to_vec(&self.actor).map_err(|_| CallError::Shape)?);
        Ok(bytes)
    }
    pub fn make(admission: Admission, actor: Member, keys: &KeyPair) -> Result<Self> {
        if actor != admission.header.source && actor != admission.header.target
            || actor.device.encryption_key != keys.public_key
            || actor.device.signing_key != keys.ed25519_pk
        {
            return Err(CallError::Scope);
        }
        let mut value = Self {
            admission,
            actor,
            signature: vec![],
        };
        value.signature =
            crypto::sign(&value.signing()?, &keys.ed25519_sk).map_err(|_| CallError::Proof)?;
        Ok(value)
    }
    pub fn verify(&self, sender: &DeviceState, peer: &DeviceState) -> Result<()> {
        self.admission.verify(sender, peer)?;
        if self.actor != self.admission.header.source && self.actor != self.admission.header.target
        {
            return Err(CallError::Scope);
        }
        if !crypto::verify_with_public_key(
            &self.signing()?,
            &self.signature,
            &self.actor.device.signing_key,
        )
        .map_err(|_| CallError::Proof)?
        {
            return Err(CallError::Proof);
        }
        Ok(())
    }
}
// These capabilities remain in native memory. They are not renderer contracts.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reservation {
    pub id: String,
    pub ticket: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub ticket: String,
    pub envelope: Envelope,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub id: String,
    pub sequence: u64,
    pub digest: [u8; 32],
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acknowledge {
    pub device: String,
    pub ticket: String,
    pub receipt: Receipt,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delivery {
    pub admission: Admission,
    pub ticket: String,
    pub envelope: Envelope,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    pub delivery: Option<Delivery>,
    pub closed: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signal {
    pub id: String,
    pub kind: Kind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdp: Option<String>,
}
impl Drop for Signal {
    fn drop(&mut self) {
        if let Some(sdp) = &mut self.sdp {
            unsafe { libsodium_sys::sodium_memzero(sdp.as_mut_ptr().cast(), sdp.len()) };
        }
    }
}
struct Plain(Vec<u8>);
impl Drop for Plain {
    fn drop(&mut self) {
        unsafe { libsodium_sys::sodium_memzero(self.0.as_mut_ptr().cast(), self.0.len()) };
    }
}
/// An audio-only DTLS-SRTP SDP with a SHA-256 certificate fingerprint. The full
/// SDP (including fingerprint and ICE credentials) is signed and encrypted.
pub fn validate_sdp(sdp: &str) -> Result<()> {
    if sdp.is_empty()
        || sdp.len() > MAX_SDP
        || !sdp.starts_with("v=0\r\n")
        || sdp
            .bytes()
            .any(|b| b == 0 || (b < 32 && !matches!(b, b'\r' | b'\n' | b'\t')))
    {
        return Err(CallError::Shape);
    }
    let lines: Vec<_> = sdp.lines().collect();
    let media: Vec<_> = lines.iter().filter(|line| line.starts_with("m=")).collect();
    if media.len() != 1
        || !media[0].starts_with("m=audio ")
        || media[0].split_ascii_whitespace().nth(2) != Some("UDP/TLS/RTP/SAVPF")
        || !lines.contains(&"a=rtcp-mux")
        || !lines.iter().any(|line| line.starts_with("a=ice-ufrag:"))
        || !lines.iter().any(|line| line.starts_with("a=ice-pwd:"))
        || !lines
            .iter()
            .any(|line| line.starts_with("a=rtpmap:") && line.contains(" opus/48000/"))
        || lines.iter().any(|line| line.starts_with("a=crypto:"))
    {
        return Err(CallError::Shape);
    }
    let mut fingerprint: Option<&str> = None;
    for line in lines
        .iter()
        .filter(|line| line.starts_with("a=fingerprint:"))
    {
        let value = line
            .strip_prefix("a=fingerprint:sha-256 ")
            .ok_or(CallError::Shape)?;
        if value.len() != 95
            || value.split(':').count() != 32
            || value
                .split(':')
                .any(|octet| octet.len() != 2 || !octet.bytes().all(|b| b.is_ascii_hexdigit()))
            || fingerprint.is_some_and(|previous| !previous.eq_ignore_ascii_case(value))
        {
            return Err(CallError::Shape);
        }
        fingerprint = Some(value);
    }
    if fingerprint.is_none() {
        return Err(CallError::Shape);
    }
    Ok(())
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub header: Header,
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
}
impl Envelope {
    fn signing(&self) -> Result<Vec<u8>> {
        let mut bytes = self.header.bytes()?;
        bytes.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&Sha256::digest(&self.ciphertext));
        Ok(bytes)
    }
    pub fn seal(
        header: Header,
        sender: &DeviceState,
        peer: &DeviceState,
        keys: &KeyPair,
        sdp: Option<String>,
    ) -> Result<Self> {
        header.current(sender, peer)?;
        if keys.public_key != header.source.device.encryption_key
            || keys.ed25519_pk != header.source.device.signing_key
        {
            return Err(CallError::Scope);
        }
        if header.kind.has_sdp() != sdp.is_some() {
            return Err(CallError::Shape);
        }
        if let Some(sdp) = &sdp {
            validate_sdp(sdp)?;
        }
        let signal = Signal {
            id: header.id.clone(),
            kind: header.kind,
            sdp,
        };
        let mut plain = Plain(Sha256::digest(header.bytes()?).to_vec());
        serde_json::to_writer(&mut plain.0, &signal).map_err(|_| CallError::Shape)?;
        let ciphertext = crypto::encrypt(
            &plain.0,
            &header.target.device.encryption_key,
            &keys.secret_key,
        )
        .map_err(|_| CallError::Proof)?;
        let mut value = Self {
            header,
            ciphertext,
            signature: vec![],
        };
        value.signature =
            crypto::sign(&value.signing()?, &keys.ed25519_sk).map_err(|_| CallError::Proof)?;
        value.verify(sender, peer)?;
        Ok(value)
    }
    pub fn verify(&self, sender: &DeviceState, peer: &DeviceState) -> Result<()> {
        self.header.current(sender, peer)?;
        // JSON may escape SDP characters; the ciphertext bound accommodates it.
        if !(72..=MAX_SDP * 6 + 1024).contains(&self.ciphertext.len())
            || self.signature.len() != 64
            || serde_json::to_vec(self)
                .map_err(|_| CallError::Shape)?
                .len()
                > MAX_WIRE
        {
            return Err(CallError::Shape);
        }
        if !crypto::verify_with_public_key(
            &self.signing()?,
            &self.signature,
            &self.header.source.device.signing_key,
        )
        .map_err(|_| CallError::Proof)?
        {
            return Err(CallError::Proof);
        }
        Ok(())
    }
    pub fn open(
        &self,
        sender: &DeviceState,
        peer: &DeviceState,
        keys: &KeyPair,
        now: i64,
    ) -> Result<Signal> {
        self.verify(sender, peer)?;
        if now < self.header.sent_at || now >= self.header.expires_at {
            return Err(CallError::Expired);
        }
        if keys.public_key != self.header.target.device.encryption_key
            || keys.ed25519_pk != self.header.target.device.signing_key
        {
            return Err(CallError::Scope);
        }
        let plain = Plain(
            crypto::decrypt(
                &self.ciphertext,
                &self.header.source.device.encryption_key,
                &keys.secret_key,
            )
            .map_err(|_| CallError::Proof)?,
        );
        let binding: [u8; 32] = Sha256::digest(self.header.bytes()?).into();
        if plain.0.len() < 32 || plain.0[..32] != binding {
            return Err(CallError::Proof);
        }
        let signal: Signal =
            serde_json::from_slice(&plain.0[32..]).map_err(|_| CallError::Proof)?;
        if signal.id != self.header.id
            || signal.kind != self.header.kind
            || signal.kind.has_sdp() != signal.sdp.is_some()
        {
            return Err(CallError::Proof);
        }
        if let Some(sdp) = &signal.sdp {
            validate_sdp(sdp)?;
        }
        Ok(signal)
    }
    pub fn digest(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(serde_json::to_vec(self).map_err(|_| CallError::Shape)?).into())
    }
}
/// One direction of one admitted call. Only advance after `Envelope::open`.
/// This in-memory fence intentionally dies with the call and has a hard limit.
#[derive(Default)]
pub struct ReplayFence {
    sequence: u64,
    digest: [u8; 32],
    terminal: bool,
}
impl ReplayFence {
    pub fn admit(&mut self, envelope: &Envelope) -> Result<bool> {
        let digest = envelope.digest()?;
        if envelope.header.sequence == self.sequence && digest == self.digest {
            return Ok(false);
        }
        if self.terminal
            || envelope.header.sequence != self.sequence + 1
            || self.sequence >= MAX_SIGNALS
        {
            return Err(CallError::Sequence);
        }
        self.sequence = envelope.header.sequence;
        self.digest = digest;
        self.terminal = envelope.header.kind.terminal();
        Ok(true)
    }
}
