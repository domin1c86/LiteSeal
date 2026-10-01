//! T23 authorization primitives; not a login or device-replacement endpoint.
//! The root must be pinned through the existing trusted contact identity.
use crate::crypto::{self, KeyPair};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const JOIN_LIFETIME_MS: i64 = 10 * 60 * 1000;
pub const MAX_DEVICE_EVENTS: u64 = 4096;
pub const MAX_DEVICE_EVENT_BYTES: usize = 16 * 1024;
pub const MAX_DEVICE_PAGE_BYTES: usize = 512 * 1024;
const MAX_TIME: i64 = 8_640_000_000_000_000;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DeviceError {
    #[error("invalid device authorization shape")]
    Shape,
    #[error("invalid device signature or encryption proof")]
    Proof,
    #[error("device authorization expired or not yet valid")]
    Expired,
    #[error("device authorization chain is stale or out of order")]
    Chain,
    #[error("device authorization conflicts with current or retired identity")]
    Conflict,
}
type Result<T> = std::result::Result<T, DeviceError>;
fn hash(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}
fn bytes(value: &impl Serialize) -> Vec<u8> {
    serde_json::to_vec(value).expect("serializable device authorization")
}
fn id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}
fn time(at: i64) -> bool {
    (0..=MAX_TIME).contains(&at)
}
fn window(issued: i64, expires: i64, at: i64) -> Result<()> {
    if !time(issued) || !time(expires) || expires <= issued || expires - issued > JOIN_LIFETIME_MS {
        return Err(DeviceError::Shape);
    }
    if at < issued || at >= expires {
        return Err(DeviceError::Expired);
    }
    Ok(())
}
fn verify(data: &[u8], signature: &[u8], key: &[u8; 32]) -> Result<()> {
    if crypto::verify_with_public_key(data, signature, key).unwrap_or(false) {
        Ok(())
    } else {
        Err(DeviceError::Proof)
    }
}
fn sign(data: &[u8], keys: &KeyPair) -> Result<Vec<u8>> {
    crypto::sign(data, &keys.ed25519_sk).map_err(|_| DeviceError::Proof)
}

/// Reject aliases in signed inputs; callers normalize a user-selected URL first.
pub fn canonical_origin(input: &str) -> Result<String> {
    let url = url::Url::parse(input).map_err(|_| DeviceError::Shape)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(DeviceError::Shape);
    }
    Ok(url.origin().ascii_serialization())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceIdentity {
    pub device_id: String,
    pub encryption_key: [u8; 32],
    pub signing_key: [u8; 32],
}
impl DeviceIdentity {
    pub fn from_keys(device_id: String, keys: &KeyPair) -> Self {
        Self {
            device_id,
            encryption_key: keys.public_key,
            signing_key: keys.ed25519_pk,
        }
    }
    fn validate(&self) -> Result<()> {
        if !id(&self.device_id) || self.encryption_key == [0; 32] || self.signing_key == [0; 32] {
            return Err(DeviceError::Shape);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Anchor {
    pub origin: String,
    pub account: String,
    pub root: DeviceIdentity,
}
impl Anchor {
    pub fn validate(&self) -> Result<()> {
        self.root.validate()?;
        if !id(&self.account) || canonical_origin(&self.origin)? != self.origin {
            return Err(DeviceError::Shape);
        }
        Ok(())
    }
    pub fn hash(&self) -> Vec<u8> {
        hash(&bytes(&("LiteSeal/device-anchor/v1", self)))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JoinIntent {
    pub id: String,
    pub anchor_hash: Vec<u8>,
    pub device: DeviceIdentity,
    pub server_challenge: Vec<u8>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub signature: Vec<u8>,
}
impl JoinIntent {
    pub fn signing_bytes(&self) -> Vec<u8> {
        bytes(&(
            "LiteSeal/device-join/v1",
            &self.id,
            &self.anchor_hash,
            &self.device,
            &self.server_challenge,
            self.issued_at,
            self.expires_at,
        ))
    }
    pub fn hash(&self) -> Vec<u8> {
        hash(&bytes(&(self.signing_bytes(), &self.signature)))
    }
    pub fn verify(&self, anchor: &Anchor, at: i64) -> Result<()> {
        anchor.validate()?;
        self.device.validate()?;
        if !id(&self.id) || self.anchor_hash != anchor.hash() || self.server_challenge.len() != 32 {
            return Err(DeviceError::Shape);
        }
        window(self.issued_at, self.expires_at, at)?;
        verify(
            &self.signing_bytes(),
            &self.signature,
            &self.device.signing_key,
        )
    }
}
pub fn make_intent(
    anchor: &Anchor,
    id: String,
    device_id: String,
    server_challenge: [u8; 32],
    issued_at: i64,
    keys: &KeyPair,
) -> Result<JoinIntent> {
    let mut intent = JoinIntent {
        id,
        anchor_hash: anchor.hash(),
        device: DeviceIdentity::from_keys(device_id, keys),
        server_challenge: server_challenge.to_vec(),
        issued_at,
        expires_at: issued_at
            .checked_add(JOIN_LIFETIME_MS)
            .ok_or(DeviceError::Shape)?,
        signature: vec![],
    };
    intent.signature = sign(&intent.signing_bytes(), keys)?;
    intent.verify(anchor, issued_at)?;
    Ok(intent)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub intent_hash: Vec<u8>,
    pub revision: u64,
    pub previous: Vec<u8>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub nonce_commitment: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
}
impl Challenge {
    pub fn signing_bytes(&self) -> Vec<u8> {
        bytes(&(
            "LiteSeal/device-challenge/v1",
            &self.intent_hash,
            self.revision,
            &self.previous,
            self.issued_at,
            self.expires_at,
            &self.nonce_commitment,
            &self.ciphertext,
        ))
    }
    pub fn hash(&self) -> Vec<u8> {
        hash(&bytes(&(self.signing_bytes(), &self.signature)))
    }
    pub fn verify(&self, state: &DeviceState, intent: &JoinIntent, at: i64) -> Result<()> {
        intent.verify(&state.anchor, at)?;
        state.check_candidate(intent)?;
        if self.intent_hash != intent.hash()
            || self.nonce_commitment.len() != 32
            || self.ciphertext.len() != 72
            || self.issued_at < intent.issued_at
            || self.expires_at > intent.expires_at
        {
            return Err(DeviceError::Shape);
        }
        window(self.issued_at, self.expires_at, at)?;
        state.check_next(self.revision, &self.previous, at)?;
        verify(
            &self.signing_bytes(),
            &self.signature,
            &state.anchor.root.signing_key,
        )
    }
}
pub fn make_challenge(
    state: &DeviceState,
    intent: &JoinIntent,
    at: i64,
    root: &KeyPair,
) -> Result<Challenge> {
    intent.verify(&state.anchor, at)?;
    state.check_candidate(intent)?;
    if root.public_key != state.anchor.root.encryption_key
        || root.ed25519_pk != state.anchor.root.signing_key
    {
        return Err(DeviceError::Proof);
    }
    let mut nonce = crypto::random_challenge().map_err(|_| DeviceError::Proof)?;
    let ciphertext = crypto::encrypt(&nonce, &intent.device.encryption_key, &root.secret_key)
        .map_err(|_| DeviceError::Proof)?;
    let mut challenge = Challenge {
        intent_hash: intent.hash(),
        revision: state.revision + 1,
        previous: state.head.clone(),
        issued_at: at,
        expires_at: intent.expires_at,
        nonce_commitment: hash(&nonce),
        ciphertext,
        signature: vec![],
    };
    // Erase the unpublished plaintext challenge after sealing it.
    unsafe { libsodium_sys::sodium_memzero(nonce.as_mut_ptr().cast(), nonce.len()) };
    challenge.signature = sign(&challenge.signing_bytes(), root)?;
    challenge.verify(state, intent, at)?;
    Ok(challenge)
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceProof {
    pub challenge_hash: Vec<u8>,
    /// Public only after decryption. Signing the public commitment is insufficient.
    pub nonce: Vec<u8>,
    pub signature: Vec<u8>,
}
impl DeviceProof {
    pub fn signing_bytes(&self) -> Vec<u8> {
        bytes(&(
            "LiteSeal/device-proof/v1",
            &self.challenge_hash,
            &self.nonce,
        ))
    }
    pub fn verify(&self, challenge: &Challenge, device: &DeviceIdentity) -> Result<()> {
        if self.challenge_hash != challenge.hash()
            || self.nonce.len() != 32
            || hash(&self.nonce) != challenge.nonce_commitment
        {
            return Err(DeviceError::Proof);
        }
        verify(&self.signing_bytes(), &self.signature, &device.signing_key)
    }
}
pub fn answer_challenge(
    state: &DeviceState,
    intent: &JoinIntent,
    challenge: &Challenge,
    at: i64,
    keys: &KeyPair,
) -> Result<DeviceProof> {
    challenge.verify(state, intent, at)?;
    if DeviceIdentity::from_keys(intent.device.device_id.clone(), keys) != intent.device {
        return Err(DeviceError::Proof);
    }
    let nonce = crypto::decrypt(
        &challenge.ciphertext,
        &state.anchor.root.encryption_key,
        &keys.secret_key,
    )
    .map_err(|_| DeviceError::Proof)?;
    let mut proof = DeviceProof {
        challenge_hash: challenge.hash(),
        nonce,
        signature: vec![],
    };
    proof.signature = sign(&proof.signing_bytes(), keys)?;
    proof.verify(challenge, &intent.device)?;
    Ok(proof)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DeviceAction {
    Grant {
        intent: Box<JoinIntent>,
        challenge: Box<Challenge>,
        proof: DeviceProof,
    },
    Revoke {
        device_id: String,
        grant_hash: Vec<u8>,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceEvent {
    pub version: u8,
    pub id: String,
    pub anchor_hash: Vec<u8>,
    pub revision: u64,
    pub previous: Vec<u8>,
    pub created_at: i64,
    pub action: DeviceAction,
    pub signature: Vec<u8>,
}
impl DeviceEvent {
    pub fn signing_bytes(&self) -> Vec<u8> {
        bytes(&(
            "LiteSeal/device-grant/v1",
            self.version,
            &self.id,
            &self.anchor_hash,
            self.revision,
            &self.previous,
            self.created_at,
            &self.action,
        ))
    }
    pub fn hash(&self) -> Vec<u8> {
        hash(&bytes(&(self.signing_bytes(), &self.signature)))
    }
}

/// No Deserialize: reconstruct from the pinned anchor and verified events only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceState {
    anchor: Anchor,
    revision: u64,
    head: Vec<u8>,
    last_at: i64,
    secondary: Option<(DeviceIdentity, Vec<u8>)>,
    retired_devices: BTreeSet<String>,
    retired_encryption: BTreeSet<[u8; 32]>,
    retired_signing: BTreeSet<[u8; 32]>,
    consumed_intents: BTreeSet<String>,
    accepted: BTreeMap<String, Vec<u8>>,
}
impl DeviceState {
    pub fn pin(anchor: Anchor) -> Result<Self> {
        anchor.validate()?;
        Ok(Self {
            head: anchor.hash(),
            anchor,
            revision: 0,
            last_at: 0,
            secondary: None,
            retired_devices: BTreeSet::new(),
            retired_encryption: BTreeSet::new(),
            retired_signing: BTreeSet::new(),
            consumed_intents: BTreeSet::new(),
            accepted: BTreeMap::new(),
        })
    }
    pub fn anchor(&self) -> &Anchor {
        &self.anchor
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn head(&self) -> &[u8] {
        &self.head
    }
    pub fn secondary(&self) -> Option<&DeviceIdentity> {
        self.secondary.as_ref().map(|s| &s.0)
    }
    pub fn grant_hash(&self) -> Option<&[u8]> {
        self.secondary.as_ref().map(|s| s.1.as_slice())
    }
    fn check_next(&self, revision: u64, previous: &[u8], at: i64) -> Result<()> {
        if self.revision >= MAX_DEVICE_EVENTS
            || revision != self.revision + 1
            || previous != self.head
            || !time(at)
            || at < self.last_at
        {
            return Err(DeviceError::Chain);
        }
        Ok(())
    }
    fn check_candidate(&self, intent: &JoinIntent) -> Result<()> {
        let device = &intent.device;
        if self.secondary.is_some()
            || self.consumed_intents.contains(&intent.id)
            || device.device_id == self.anchor.root.device_id
            || device.encryption_key == self.anchor.root.encryption_key
            || device.signing_key == self.anchor.root.signing_key
            || self.retired_devices.contains(&device.device_id)
            || self.retired_encryption.contains(&device.encryption_key)
            || self.retired_signing.contains(&device.signing_key)
        {
            return Err(DeviceError::Conflict);
        }
        Ok(())
    }
    /// Idempotent only for identical accepted bytes. Callers persist atomically.
    pub fn apply(&self, event: &DeviceEvent) -> Result<Self> {
        if let Some(previous) = self.accepted.get(&event.id) {
            return if *previous == event.hash() {
                Ok(self.clone())
            } else {
                Err(DeviceError::Conflict)
            };
        }
        if event.version != 1 || !id(&event.id) || event.anchor_hash != self.anchor.hash() {
            return Err(DeviceError::Shape);
        }
        self.check_next(event.revision, &event.previous, event.created_at)?;
        verify(
            &event.signing_bytes(),
            &event.signature,
            &self.anchor.root.signing_key,
        )?;
        let mut next = self.clone();
        match &event.action {
            DeviceAction::Grant {
                intent,
                challenge,
                proof,
            } => {
                challenge.verify(self, intent, event.created_at)?;
                proof.verify(challenge, &intent.device)?;
                next.secondary = Some((intent.device.clone(), event.hash()));
                next.consumed_intents.insert(intent.id.clone());
            }
            DeviceAction::Revoke {
                device_id,
                grant_hash,
            } => {
                let (device, original) = self.secondary.as_ref().ok_or(DeviceError::Conflict)?;
                if device.device_id != *device_id || original != grant_hash {
                    return Err(DeviceError::Conflict);
                }
                next.retired_devices.insert(device.device_id.clone());
                next.retired_encryption.insert(device.encryption_key);
                next.retired_signing.insert(device.signing_key);
                next.secondary = None;
            }
        }
        next.revision = event.revision;
        next.head = event.hash();
        next.last_at = event.created_at;
        next.accepted.insert(event.id.clone(), event.hash());
        Ok(next)
    }
    /// Used at live admission, never when replaying historical accepted events.
    pub fn apply_live(&self, event: &DeviceEvent, now: i64) -> Result<Self> {
        if !time(now) || event.created_at > now {
            return Err(DeviceError::Expired);
        }
        if !self.accepted.contains_key(&event.id) {
            if let DeviceAction::Grant {
                intent, challenge, ..
            } = &event.action
            {
                challenge.verify(self, intent, now)?;
            }
        }
        self.apply(event)
    }
}
pub fn make_event(
    state: &DeviceState,
    id: String,
    action: DeviceAction,
    at: i64,
    root: &KeyPair,
) -> Result<DeviceEvent> {
    let mut event = DeviceEvent {
        version: 1,
        id,
        anchor_hash: state.anchor.hash(),
        revision: state.revision + 1,
        previous: state.head.clone(),
        created_at: at,
        action,
        signature: vec![],
    };
    event.signature = sign(&event.signing_bytes(), root)?;
    state.apply_live(&event, at)?;
    Ok(event)
}

/// A retryable, join-only credential. Never log this request or accept its token
/// as a normal account session. The requester generates 32 random token bytes.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinStartRequest {
    pub request_id: String,
    pub request_token: String,
    pub username: String,
    pub password: String,
    pub device_name: String,
    pub encryption_key: [u8; 32],
    pub signing_key: [u8; 32],
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JoinTicket {
    pub id: String,
    pub anchor: Anchor,
    pub device: DeviceIdentity,
    pub device_name: String,
    pub server_challenge: Vec<u8>,
    pub issued_at: i64,
    pub expires_at: i64,
}
impl JoinTicket {
    pub fn sign_intent(&self, keys: &KeyPair) -> Result<JoinIntent> {
        if DeviceIdentity::from_keys(self.device.device_id.clone(), keys) != self.device {
            return Err(DeviceError::Proof);
        }
        let mut intent = JoinIntent {
            id: self.id.clone(),
            anchor_hash: self.anchor.hash(),
            device: self.device.clone(),
            server_challenge: self.server_challenge.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            signature: vec![],
        };
        intent.signature = sign(&intent.signing_bytes(), keys)?;
        intent.verify(&self.anchor, self.issued_at)?;
        Ok(intent)
    }
    pub fn matches(&self, intent: &JoinIntent) -> bool {
        self.id == intent.id
            && self.anchor.hash() == intent.anchor_hash
            && self.device == intent.device
            && self.server_challenge == intent.server_challenge
            && self.issued_at == intent.issued_at
            && self.expires_at == intent.expires_at
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JoinPhase {
    Begun,
    Ready,
    Challenged,
    Proved,
    Authorized,
    Cancelled,
    Revoked,
    Expired,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JoinStatus {
    pub ticket: JoinTicket,
    pub phase: JoinPhase,
    pub intent: Option<JoinIntent>,
    pub challenge: Option<Challenge>,
    pub proof: Option<DeviceProof>,
    pub authorization_id: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeSubmission {
    pub device_id: String,
    pub challenge: Challenge,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceEventSubmission {
    pub device_id: String,
    pub event: DeviceEvent,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceReceipt {
    pub event_id: String,
    pub event_hash: Vec<u8>,
    pub accepted_revision: u64,
    pub current_revision: u64,
    pub current_hash: Vec<u8>,
    pub messaging_enabled: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceManifestPage {
    pub anchor: Anchor,
    pub events: Vec<DeviceEvent>,
    pub through_revision: u64,
    pub current_revision: u64,
    pub current_hash: Vec<u8>,
    pub more: bool,
}
