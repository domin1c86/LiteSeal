//! Explicit, one-way account protocol enablement and dual-key session proof.
//! Session credentials are transported only in a box to the authorized device.
use crate::{
    backup_crypto,
    crypto::{self, KeyPair},
    direct_message::Directory,
    trusted_device::{canonical_origin, Anchor, DeviceIdentity, DeviceState},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub const MAX_WIRE: usize = 16 * 1024;
pub const LIFETIME: i64 = 10 * 60 * 1000;
type Result<T> = std::result::Result<T, &'static str>;
fn bad() -> &'static str {
    "设备激活身份、阶段或密钥证明不匹配"
}
fn bytes(value: &impl Serialize) -> Vec<u8> {
    serde_json::to_vec(value).expect("activation serialization")
}
fn hash(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}
fn id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
fn realm(value: &str) -> bool {
    canonical_origin(value).is_ok_and(|canonical| canonical == value)
}
fn key_check(keys: &KeyPair, device: &DeviceIdentity) -> Result<()> {
    if keys.public_key != device.encryption_key || keys.ed25519_pk != device.signing_key {
        return Err(bad());
    }
    backup_crypto::validate_identity(
        &keys.public_key,
        &keys.secret_key,
        &keys.ed25519_pk,
        &keys.ed25519_sk,
    )
    .map_err(|_| bad())
}
fn wipe(value: &mut [u8]) {
    unsafe { libsodium_sys::sodium_memzero(value.as_mut_ptr().cast(), value.len()) }
}
struct Secret([u8; 32]);
impl Drop for Secret {
    fn drop(&mut self) {
        wipe(&mut self.0)
    }
}
struct Plain(Vec<u8>);
impl Drop for Plain {
    fn drop(&mut self) {
        wipe(&mut self.0)
    }
}
struct Ephemeral(KeyPair);
impl Drop for Ephemeral {
    fn drop(&mut self) {
        wipe(&mut self.0.secret_key);
        wipe(&mut self.0.ed25519_sk)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Enable {
    pub version: u8,
    pub id: String,
    pub origin: String,
    pub account: String,
    pub root: String,
    pub revision: u64,
    pub head: [u8; 32],
    pub signature: Vec<u8>,
}
impl Enable {
    fn signing(&self) -> Result<Vec<u8>> {
        if self.version != 1
            || !id(&self.id)
            || !id(&self.account)
            || !id(&self.root)
            || !realm(&self.origin)
            || self.revision > 4096
            || self.head == [0; 32]
            || self.signature.len() != 64
        {
            return Err(bad());
        }
        Ok(bytes(&(
            "LiteSeal/enable-direct-v3/v1",
            self.version,
            &self.id,
            &self.origin,
            &self.account,
            &self.root,
            self.revision,
            self.head,
        )))
    }
    pub fn make(state: &DeviceState, id_: &str, keys: &KeyPair) -> Result<Self> {
        key_check(keys, &state.anchor().root)?;
        let mut event = Self {
            version: 1,
            id: id_.into(),
            origin: state.anchor().origin.clone(),
            account: state.anchor().account.clone(),
            root: state.anchor().root.device_id.clone(),
            revision: state.revision(),
            head: state.head().try_into().map_err(|_| bad())?,
            signature: vec![0; 64],
        };
        event.signature = crypto::sign(&event.signing()?, &keys.ed25519_sk).map_err(|_| bad())?;
        event.verify_current(state)?;
        Ok(event)
    }
    pub fn verify_root(&self, anchor: &Anchor) -> Result<()> {
        anchor.validate().map_err(|_| bad())?;
        if self.origin != anchor.origin
            || self.account != anchor.account
            || self.root != anchor.root.device_id
            || !crypto::verify_with_public_key(
                &self.signing()?,
                &self.signature,
                &anchor.root.signing_key,
            )
            .unwrap_or(false)
        {
            return Err(bad());
        }
        Ok(())
    }
    pub fn verify_current(&self, state: &DeviceState) -> Result<()> {
        self.verify_root(state.anchor())?;
        if self.revision != state.revision() || self.head.as_slice() != state.head() {
            return Err(bad());
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<[u8; 32]> {
        let mut data = self.signing()?;
        data.extend_from_slice(&self.signature);
        Ok(hash(&data))
    }
}
/// Separate signatures authorize cancellation; publishing an enable event does
/// not itself authorize its cancellation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnableCancel {
    pub event: Enable,
    pub signature: Vec<u8>,
}
impl EnableCancel {
    fn signing(&self) -> Result<Vec<u8>> {
        if self.signature.len() != 64 {
            return Err(bad());
        }
        Ok(bytes(&(
            "LiteSeal/cancel-enable-direct/v1",
            self.event.digest()?,
        )))
    }
    pub fn make(event: Enable, anchor: &Anchor, keys: &KeyPair) -> Result<Self> {
        event.verify_root(anchor)?;
        key_check(keys, &anchor.root)?;
        let mut cancel = Self {
            event,
            signature: vec![0; 64],
        };
        cancel.signature = crypto::sign(&cancel.signing()?, &keys.ed25519_sk).map_err(|_| bad())?;
        cancel.verify(anchor)?;
        Ok(cancel)
    }
    pub fn verify(&self, anchor: &Anchor) -> Result<()> {
        self.event.verify_root(anchor)?;
        if !crypto::verify_with_public_key(
            &self.signing()?,
            &self.signature,
            &anchor.root.signing_key,
        )
        .unwrap_or(false)
        {
            return Err(bad());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActivationCancel {
    pub version: u8,
    pub id: String,
    pub origin: String,
    pub account: String,
    pub device: DeviceIdentity,
    pub authorization: [u8; 32],
    pub mode: [u8; 32],
    pub token_hash: [u8; 32],
    pub signature: Vec<u8>,
}
impl ActivationCancel {
    fn signing(&self) -> Result<Vec<u8>> {
        if self.version != 1
            || !id(&self.id)
            || !id(&self.account)
            || !id(&self.device.device_id)
            || !realm(&self.origin)
            || self.authorization == [0; 32]
            || self.mode == [0; 32]
            || self.token_hash == [0; 32]
            || self.device.encryption_key == [0; 32]
            || self.device.signing_key == [0; 32]
            || self.signature.len() != 64
        {
            return Err(bad());
        }
        Ok(bytes(&(
            "LiteSeal/cancel-device-session/v3",
            self.version,
            &self.id,
            &self.origin,
            &self.account,
            &self.device,
            self.authorization,
            self.mode,
            self.token_hash,
        )))
    }
    pub fn make(
        state: &DeviceState,
        mode: &Enable,
        id_: &str,
        token: &str,
        device: &str,
        keys: &KeyPair,
    ) -> Result<Self> {
        mode.verify_root(state.anchor())?;
        if token.len() < 32 || token.len() > 256 || token.bytes().any(|b| !b.is_ascii_graphic()) {
            return Err(bad());
        }
        let member = Directory::from_state(state)
            .members
            .into_iter()
            .find(|m| m.device.device_id == device)
            .ok_or_else(bad)?;
        key_check(keys, &member.device)?;
        let mut cancel = Self {
            version: 1,
            id: id_.into(),
            origin: state.anchor().origin.clone(),
            account: state.anchor().account.clone(),
            device: member.device,
            authorization: member.authorization_hash,
            mode: mode.digest()?,
            token_hash: hash(token.as_bytes()),
            signature: vec![0; 64],
        };
        cancel.signature = crypto::sign(&cancel.signing()?, &keys.ed25519_sk).map_err(|_| bad())?;
        cancel.verify(state, mode, token)?;
        Ok(cancel)
    }
    pub fn verify(&self, state: &DeviceState, mode: &Enable, token: &str) -> Result<()> {
        mode.verify_root(state.anchor())?;
        if self.origin != state.anchor().origin
            || self.account != state.anchor().account
            || self.mode != mode.digest()?
            || self.token_hash != hash(token.as_bytes())
            || token.len() < 32
            || token.len() > 256
            || token.bytes().any(|b| !b.is_ascii_graphic())
            || !Directory::from_state(state)
                .members
                .iter()
                .any(|m| m.device == self.device && m.authorization_hash == self.authorization)
            || !crypto::verify_with_public_key(
                &self.signing()?,
                &self.signature,
                &self.device.signing_key,
            )
            .unwrap_or(false)
        {
            return Err(bad());
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<[u8; 32]> {
        let mut data = self.signing()?;
        data.extend_from_slice(&self.signature);
        Ok(hash(&data))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum EnableCancelResult {
    Cancelled { event: [u8; 32] },
    Accepted { event: Enable },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActivationCancelResult {
    Cancelled {
        cancellation: [u8; 32],
    },
    Accepted {
        challenge: Box<Challenge>,
        envelope: Envelope,
    },
}
// This private request is never a renderer DTO and must not be logged.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Start {
    pub id: String,
    pub request_token: String,
    pub username: String,
    pub password: String,
    pub device: String,
    pub authorization: [u8; 32],
}
impl Drop for Start {
    fn drop(&mut self) {
        unsafe {
            wipe(self.password.as_mut_vec());
            wipe(self.request_token.as_mut_vec());
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub version: u8,
    pub id: String,
    pub origin: String,
    pub account: String,
    pub device: DeviceIdentity,
    pub authorization: [u8; 32],
    pub revision: u64,
    pub head: [u8; 32],
    pub mode: [u8; 32],
    pub issued_at: i64,
    pub expires_at: i64,
    pub secret_hash: [u8; 32],
    pub server_key: [u8; 32],
    pub encrypted: Vec<u8>,
}
impl Challenge {
    fn context(&self) -> Result<[u8; 32]> {
        if self.version != 1
            || !id(&self.id)
            || !id(&self.account)
            || !id(&self.device.device_id)
            || !realm(&self.origin)
            || self.device.encryption_key == [0; 32]
            || self.device.signing_key == [0; 32]
            || self.authorization == [0; 32]
            || self.mode == [0; 32]
            || self.head == [0; 32]
            || self.revision > 4096
            || self.issued_at <= 0
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at != LIFETIME
            || self.expires_at > 8_640_000_000_000_000
        {
            return Err(bad());
        }
        Ok(hash(&bytes(&(
            "LiteSeal/session-context/v3",
            self.version,
            &self.id,
            &self.origin,
            &self.account,
            &self.device,
            self.authorization,
            self.revision,
            self.head,
            self.mode,
            self.issued_at,
            self.expires_at,
        ))))
    }
    pub fn digest(&self) -> Result<[u8; 32]> {
        self.context()?;
        if self.server_key == [0; 32] || self.secret_hash == [0; 32] || self.encrypted.len() != 104
        {
            return Err(bad());
        }
        Ok(hash(&bytes(&("LiteSeal/session-challenge/v3", self))))
    }
    pub fn make(
        state: &DeviceState,
        mode: &Enable,
        id_: &str,
        device: &str,
        at: i64,
    ) -> Result<Self> {
        mode.verify_root(state.anchor())?;
        let member = Directory::from_state(state)
            .members
            .into_iter()
            .find(|m| m.device.device_id == device)
            .ok_or_else(bad)?;
        let ephemeral = Ephemeral(crypto::generate_keypair().map_err(|_| bad())?);
        let secret = Secret(crypto::random_challenge().map_err(|_| bad())?);
        let mut challenge = Self {
            version: 1,
            id: id_.into(),
            origin: state.anchor().origin.clone(),
            account: state.anchor().account.clone(),
            device: member.device,
            authorization: member.authorization_hash,
            revision: state.revision(),
            head: state.head().try_into().map_err(|_| bad())?,
            mode: mode.digest()?,
            issued_at: at,
            expires_at: at.checked_add(LIFETIME).ok_or_else(bad)?,
            secret_hash: hash(&secret.0),
            server_key: ephemeral.0.public_key,
            encrypted: vec![],
        };
        let mut plain = Plain(Vec::with_capacity(64));
        plain.0.extend_from_slice(&challenge.context()?);
        plain.0.extend_from_slice(&secret.0);
        challenge.encrypted = crypto::encrypt(
            &plain.0,
            &challenge.device.encryption_key,
            &ephemeral.0.secret_key,
        )
        .map_err(|_| bad())?;
        challenge.digest()?;
        Ok(challenge)
    }
    pub fn verify_state(&self, state: &DeviceState, mode: &Enable, at: i64) -> Result<()> {
        self.digest()?;
        mode.verify_root(state.anchor())?;
        let member = Directory::from_state(state)
            .members
            .into_iter()
            .find(|m| m.device == self.device)
            .ok_or_else(bad)?;
        if self.origin != state.anchor().origin
            || self.account != state.anchor().account
            || self.mode != mode.digest()?
            || self.authorization != member.authorization_hash
            || self.revision != state.revision()
            || self.head.as_slice() != state.head()
            || at < self.issued_at
            || at >= self.expires_at
        {
            return Err(bad());
        }
        Ok(())
    }
    pub fn answer(
        &self,
        state: &DeviceState,
        mode: &Enable,
        at: i64,
        keys: &KeyPair,
    ) -> Result<Proof> {
        self.verify_state(state, mode, at)?;
        let secret = self.open_secret(keys)?;
        let mut proof = Proof {
            version: 1,
            id: self.id.clone(),
            challenge: self.digest()?,
            secret: secret.0,
            signature: vec![0; 64],
        };
        let signing = Plain(proof.signing()?);
        proof.signature = crypto::sign(&signing.0, &keys.ed25519_sk).map_err(|_| bad())?;
        proof.verify(self)?;
        Ok(proof)
    }
    /// Authenticate saved ciphertext without generating a proof. Historical
    /// validation does not assert that the challenge is still live now.
    pub fn authenticate(&self, state: &DeviceState, mode: &Enable, keys: &KeyPair) -> Result<()> {
        self.verify_state(state, mode, self.issued_at)?;
        self.open_secret(keys).map(|_| ())
    }
    fn open_secret(&self, keys: &KeyPair) -> Result<Secret> {
        key_check(keys, &self.device)?;
        let plain = Plain(
            crypto::decrypt(&self.encrypted, &self.server_key, &keys.secret_key)
                .map_err(|_| bad())?,
        );
        if plain.0.len() != 64 || plain.0[..32] != self.context()? {
            return Err(bad());
        }
        let secret = Secret(plain.0[32..].try_into().map_err(|_| bad())?);
        if hash(&secret.0) != self.secret_hash {
            return Err(bad());
        }
        Ok(secret)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub version: u8,
    pub id: String,
    pub challenge: [u8; 32],
    secret: [u8; 32],
    pub signature: Vec<u8>,
}
impl Drop for Proof {
    fn drop(&mut self) {
        wipe(&mut self.secret)
    }
}
impl Proof {
    fn signing(&self) -> Result<Vec<u8>> {
        if self.version != 1
            || !id(&self.id)
            || self.signature.len() != 64
            || self.secret == [0; 32]
            || self.challenge == [0; 32]
        {
            return Err(bad());
        }
        Ok(bytes(&(
            "LiteSeal/session-possession/v3",
            self.version,
            &self.id,
            self.challenge,
            self.secret,
        )))
    }
    pub fn verify(&self, challenge: &Challenge) -> Result<()> {
        let data = Plain(self.signing()?);
        if self.id != challenge.id
            || self.challenge != challenge.digest()?
            || hash(&self.secret) != challenge.secret_hash
            || !crypto::verify_with_public_key(
                &data.0,
                &self.signature,
                &challenge.device.signing_key,
            )
            .unwrap_or(false)
        {
            return Err(bad());
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<[u8; 32]> {
        let mut data = Plain(self.signing()?);
        data.0.extend_from_slice(&self.signature);
        Ok(hash(&data.0))
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub id: String,
    pub account: String,
    pub device: String,
    pub authorization: [u8; 32],
    pub mode: [u8; 32],
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: i64,
    pub refresh_expires_at: i64,
}
impl Drop for Session {
    fn drop(&mut self) {
        unsafe {
            wipe(self.access_token.as_mut_vec());
            wipe(self.refresh_token.as_mut_vec());
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub challenge: [u8; 32],
    pub server_key: [u8; 32],
    pub encrypted: Vec<u8>,
}
impl Envelope {
    pub fn seal(challenge: &Challenge, session: &Session) -> Result<Self> {
        if session.id.is_empty()
            || session.account != challenge.account
            || session.device != challenge.device.device_id
            || session.authorization != challenge.authorization
            || session.mode != challenge.mode
        {
            return Err(bad());
        }
        let ephemeral = Ephemeral(crypto::generate_keypair().map_err(|_| bad())?);
        let digest = challenge.digest()?;
        let body = Plain(bytes(&("LiteSeal/device-session/v3", digest, session)));
        let encrypted = crypto::encrypt(
            &body.0,
            &challenge.device.encryption_key,
            &ephemeral.0.secret_key,
        )
        .map_err(|_| bad())?;
        if encrypted.len() > 8192 {
            return Err(bad());
        }
        Ok(Self {
            challenge: digest,
            server_key: ephemeral.0.public_key,
            encrypted,
        })
    }
    pub fn open(&self, challenge: &Challenge, keys: &KeyPair) -> Result<Session> {
        key_check(keys, &challenge.device)?;
        if self.challenge != challenge.digest()?
            || self.server_key == [0; 32]
            || self.encrypted.len() > 8192
        {
            return Err(bad());
        }
        let plain = Plain(
            crypto::decrypt(&self.encrypted, &self.server_key, &keys.secret_key)
                .map_err(|_| bad())?,
        );
        let (domain, digest, session): (String, [u8; 32], Session) =
            serde_json::from_slice(&plain.0).map_err(|_| bad())?;
        if domain != "LiteSeal/device-session/v3"
            || digest != self.challenge
            || !id(&session.id)
            || session.account != challenge.account
            || session.device != challenge.device.device_id
            || session.authorization != challenge.authorization
            || session.mode != challenge.mode
            || session.access_token.is_empty()
            || session.access_token.len() > 256
            || session.refresh_token.is_empty()
            || session.refresh_token.len() > 256
            || session.expires_at <= challenge.issued_at
            || session.refresh_expires_at <= session.expires_at
        {
            return Err(bad());
        }
        Ok(session)
    }
}
