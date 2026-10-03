//! T23 direct-message batches. Admission must use current verified directories;
//! stored history uses the exact independently reconstructed signed snapshots.
//! This module does not enable a login, a relay route, or legacy fallback.
use crate::{
    crypto::{self, KeyPair},
    trusted_device::{canonical_origin, DeviceIdentity, DeviceState, MAX_DEVICE_EVENTS},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const VERSION: u8 = 3;
pub const MAX_BODY: usize = 16 * 1024;
pub const MAX_CIPHERTEXT: usize = MAX_BODY + 76 + 40;
pub const MAX_WIRE: usize = 256 * 1024;
pub const MAX_TARGETS: usize = 3;
pub const MAX_ACK_WIRE: usize = 8192;
const MAX_TIME: i64 = 8_640_000_000_000_000;
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DirectError {
    #[error("invalid direct-message shape or resource limit")]
    Shape,
    #[error("direct-message directory or complete audience does not match")]
    Directory,
    #[error("invalid direct-message device signature or encrypted content")]
    Proof,
    #[error("direct-message is not addressed to this device")]
    Recipient,
    #[error("direct-message chain is discontinuous or belongs to another audience epoch")]
    Chain,
}
type Result<T> = std::result::Result<T, DirectError>;
fn identifier(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 128
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}
fn object_id(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 128
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}
fn wipe(bytes: &mut [u8]) {
    unsafe { libsodium_sys::sodium_memzero(bytes.as_mut_ptr().cast(), bytes.len()) }
}
struct Plain(Vec<u8>);
impl Drop for Plain {
    fn drop(&mut self) {
        wipe(&mut self.0)
    }
}
struct Salt([u8; 32]);
impl Drop for Salt {
    fn drop(&mut self) {
        wipe(&mut self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Member {
    pub device: DeviceIdentity,
    /// Root anchor hash for the original device; grant event hash for a secondary.
    pub authorization_hash: [u8; 32],
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Directory {
    pub anchor_hash: [u8; 32],
    pub revision: u64,
    pub head: [u8; 32],
    pub members: Vec<Member>,
}
impl Directory {
    pub fn from_state(state: &DeviceState) -> Self {
        let anchor_hash = state
            .anchor()
            .hash()
            .try_into()
            .expect("verified anchor hash");
        let mut members = vec![Member {
            device: state.anchor().root.clone(),
            authorization_hash: anchor_hash,
        }];
        if let Some(secondary) = state.secondary() {
            members.push(Member {
                device: secondary.clone(),
                authorization_hash: state
                    .grant_hash()
                    .expect("verified grant")
                    .try_into()
                    .expect("verified grant hash"),
            });
        }
        members.sort_by(|a, b| a.device.device_id.cmp(&b.device.device_id));
        Self {
            anchor_hash,
            revision: state.revision(),
            head: state.head().try_into().expect("verified head"),
            members,
        }
    }
    fn shape(&self) -> Result<()> {
        if self.revision > MAX_DEVICE_EVENTS
            || self.anchor_hash == [0; 32]
            || self.head == [0; 32]
            || !(1..=2).contains(&self.members.len())
        {
            return Err(DirectError::Shape);
        }
        for member in &self.members {
            if !object_id(&member.device.device_id)
                || member.device.encryption_key == [0; 32]
                || member.device.signing_key == [0; 32]
                || member.authorization_hash == [0; 32]
            {
                return Err(DirectError::Shape);
            }
        }
        if self.members.windows(2).any(|p| {
            p[0].device.device_id >= p[1].device.device_id
                || p[0].device.encryption_key == p[1].device.encryption_key
                || p[0].device.signing_key == p[1].device.signing_key
        }) {
            return Err(DirectError::Shape);
        }
        Ok(())
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.anchor_hash);
        out.extend_from_slice(&self.revision.to_be_bytes());
        out.extend_from_slice(&self.head);
        out.push(self.members.len() as u8);
        for member in &self.members {
            field(out, member.device.device_id.as_bytes());
            out.extend_from_slice(&member.device.encryption_key);
            out.extend_from_slice(&member.device.signing_key);
            out.extend_from_slice(&member.authorization_hash);
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Text,
    Attachment,
    Voice,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub version: u8,
    pub origin: String,
    pub id: String,
    pub conversation: String,
    pub sender: String,
    pub sender_device: String,
    pub peer: String,
    pub sender_directory: Directory,
    pub peer_directory: Directory,
    pub sequence: i64,
    pub previous: Vec<u8>,
    pub sent_at: i64,
    pub kind: Kind,
}
pub struct MessageSpec {
    pub id: String,
    pub sequence: i64,
    pub previous: Vec<u8>,
    pub sent_at: i64,
    pub kind: Kind,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainHead {
    pub epoch: [u8; 32],
    pub sequence: i64,
    pub digest: [u8; 32],
}
pub fn conversation(sender: &str, peer: &str) -> Result<String> {
    if !identifier(sender) || !identifier(peer) || sender == peer {
        return Err(DirectError::Shape);
    }
    let (lo, hi) = if sender < peer {
        (sender, peer)
    } else {
        (peer, sender)
    };
    Ok(format!("dm:{lo}:{hi}"))
}
impl Header {
    pub fn new(
        sender: &DeviceState,
        peer: &DeviceState,
        device: &str,
        message: MessageSpec,
    ) -> Result<Self> {
        if sender.anchor().origin != peer.anchor().origin {
            return Err(DirectError::Directory);
        }
        let header = Self {
            version: VERSION,
            origin: sender.anchor().origin.clone(),
            id: message.id,
            conversation: conversation(&sender.anchor().account, &peer.anchor().account)?,
            sender: sender.anchor().account.clone(),
            sender_device: device.into(),
            peer: peer.anchor().account.clone(),
            sender_directory: Directory::from_state(sender),
            peer_directory: Directory::from_state(peer),
            sequence: message.sequence,
            previous: message.previous,
            sent_at: message.sent_at,
            kind: message.kind,
        };
        header.shape()?;
        Ok(header)
    }
    fn shape(&self) -> Result<()> {
        if self.version != VERSION
            || !object_id(&self.id)
            || !object_id(&self.sender_device)
            || self.origin.len() > 2048
            || canonical_origin(&self.origin).map_err(|_| DirectError::Shape)? != self.origin
            || self.conversation != conversation(&self.sender, &self.peer)?
            || self.sequence < 1
            || self.sequence == 1 && !self.previous.is_empty()
            || self.sequence > 1 && self.previous.len() != 32
            || !(1..=MAX_TIME).contains(&self.sent_at)
        {
            return Err(DirectError::Shape);
        }
        self.sender_directory.shape()?;
        self.peer_directory.shape()?;
        if self
            .sender_directory
            .members
            .iter()
            .all(|m| m.device.device_id != self.sender_device)
        {
            return Err(DirectError::Directory);
        }
        Ok(())
    }
    fn encode(&self) -> Vec<u8> {
        let mut out = b"LiteSeal/direct-header/v3\0".to_vec();
        out.push(self.version);
        for value in [
            &self.origin,
            &self.id,
            &self.conversation,
            &self.sender,
            &self.sender_device,
            &self.peer,
        ] {
            field(&mut out, value.as_bytes());
        }
        self.sender_directory.encode(&mut out);
        self.peer_directory.encode(&mut out);
        out.extend_from_slice(&self.sequence.to_be_bytes());
        field(&mut out, &self.previous);
        out.extend_from_slice(&self.sent_at.to_be_bytes());
        out.push(match self.kind {
            Kind::Text => 0,
            Kind::Attachment => 1,
            Kind::Voice => 2,
        });
        out
    }
    fn targets(&self) -> Vec<(String, &Member)> {
        let mut targets = self
            .sender_directory
            .members
            .iter()
            .filter(|m| m.device.device_id != self.sender_device)
            .map(|m| (self.sender.clone(), m))
            .chain(
                self.peer_directory
                    .members
                    .iter()
                    .map(|m| (self.peer.clone(), m)),
            )
            .collect::<Vec<_>>();
        targets.sort_by(|a, b| (&a.0, &a.1.device.device_id).cmp(&(&b.0, &b.1.device.device_id)));
        targets
    }
    fn source(&self) -> Result<&DeviceIdentity> {
        self.sender_directory
            .members
            .iter()
            .find(|m| m.device.device_id == self.sender_device)
            .map(|m| &m.device)
            .ok_or(DirectError::Directory)
    }
    fn verify_directories(&self, sender: &DeviceState, peer: &DeviceState) -> Result<()> {
        if self.origin != sender.anchor().origin
            || self.origin != peer.anchor().origin
            || self.sender != sender.anchor().account
            || self.peer != peer.anchor().account
            || self.sender_directory != Directory::from_state(sender)
            || self.peer_directory != Directory::from_state(peer)
        {
            return Err(DirectError::Directory);
        }
        Ok(())
    }
    /// Directory changes start a fresh chain epoch, allowing a newly authorized
    /// device to verify new messages without inheriting old history. Callers
    /// select durable heads by this epoch; never reset an existing head on retry.
    pub fn epoch(&self) -> Result<[u8; 32]> {
        self.shape()?;
        let mut bytes = b"LiteSeal/direct-chain-epoch/v3\0".to_vec();
        for value in [
            &self.origin,
            &self.conversation,
            &self.sender,
            &self.sender_device,
            &self.peer,
        ] {
            field(&mut bytes, value.as_bytes());
        }
        self.sender_directory.encode(&mut bytes);
        self.peer_directory.encode(&mut bytes);
        Ok(hash(&bytes))
    }
}

/// Per-recipient receipt authentication. A caller signs only after durable
/// local processing/rejection; a signature cannot prove local persistence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ack {
    pub version: u8,
    pub origin: String,
    pub id: String,
    pub batch: [u8; 32],
    pub account: String,
    pub device: String,
    pub authorization_hash: [u8; 32],
    pub outcome: crate::protocol::AckOutcome,
    pub signature: Vec<u8>,
}
impl Ack {
    fn bytes(&self) -> Result<Vec<u8>> {
        if self.version != VERSION
            || self.signature.len() != 64
            || self.origin.len() > 2048
            || canonical_origin(&self.origin).map_err(|_| DirectError::Shape)? != self.origin
            || !object_id(&self.id)
            || !identifier(&self.account)
            || !object_id(&self.device)
        {
            return Err(DirectError::Shape);
        }
        let mut bytes = b"LiteSeal/direct-ack/v3\0".to_vec();
        bytes.push(self.version);
        for value in [&self.origin, &self.id, &self.account, &self.device] {
            field(&mut bytes, value.as_bytes());
        }
        bytes.extend_from_slice(&self.batch);
        bytes.extend_from_slice(&self.authorization_hash);
        bytes.push(match self.outcome {
            crate::protocol::AckOutcome::Processed => 0,
            crate::protocol::AckOutcome::Rejected => 1,
        });
        Ok(bytes)
    }
    pub fn make(
        batch: &Batch,
        sender: &DeviceState,
        peer: &DeviceState,
        account: &str,
        device: &str,
        keys: &KeyPair,
        outcome: crate::protocol::AckOutcome,
    ) -> Result<Self> {
        batch.verify(sender, peer)?;
        let member = batch
            .header
            .targets()
            .into_iter()
            .find(|(a, m)| a == account && m.device.device_id == device)
            .ok_or(DirectError::Recipient)?
            .1;
        if member.device.encryption_key != keys.public_key
            || member.device.signing_key != keys.ed25519_pk
        {
            return Err(DirectError::Recipient);
        }
        let mut ack = Self {
            version: VERSION,
            origin: batch.header.origin.clone(),
            id: batch.header.id.clone(),
            batch: batch.digest()?,
            account: account.into(),
            device: device.into(),
            authorization_hash: member.authorization_hash,
            outcome,
            signature: vec![0; 64],
        };
        ack.signature =
            crypto::sign(&ack.bytes()?, &keys.ed25519_sk).map_err(|_| DirectError::Proof)?;
        ack.verify(batch, sender, peer)?;
        Ok(ack)
    }
    pub fn verify(&self, batch: &Batch, sender: &DeviceState, peer: &DeviceState) -> Result<()> {
        batch.verify(sender, peer)?;
        let bytes = self.bytes()?;
        if self.origin != batch.header.origin
            || self.id != batch.header.id
            || self.batch != batch.digest()?
        {
            return Err(DirectError::Proof);
        }
        let member = batch
            .header
            .targets()
            .into_iter()
            .find(|(a, m)| a == &self.account && m.device.device_id == self.device)
            .ok_or(DirectError::Recipient)?
            .1;
        if self.authorization_hash != member.authorization_hash
            || !crypto::verify_with_public_key(&bytes, &self.signature, &member.device.signing_key)
                .unwrap_or(false)
        {
            return Err(DirectError::Proof);
        }
        Ok(())
    }
    pub fn to_wire(&self) -> Result<Vec<u8>> {
        self.bytes()?;
        let bytes = serde_json::to_vec(self).map_err(|_| DirectError::Shape)?;
        if bytes.len() > MAX_ACK_WIRE {
            return Err(DirectError::Shape);
        }
        Ok(bytes)
    }
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_ACK_WIRE {
            return Err(DirectError::Shape);
        }
        let ack: Self = serde_json::from_slice(bytes).map_err(|_| DirectError::Shape)?;
        ack.bytes()?;
        Ok(ack)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    pub account: String,
    pub device: String,
    pub ciphertext: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Batch {
    pub header: Header,
    pub commitment: [u8; 32],
    pub payloads: Vec<Payload>,
    pub signature: Vec<u8>,
}
fn commitment(context: &[u8; 32], salt: &[u8; 32], body: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"LiteSeal/direct-content/v3\0");
    digest.update(context);
    digest.update(salt);
    digest.update((body.len() as u32).to_be_bytes());
    digest.update(body);
    digest.finalize().into()
}
impl Batch {
    fn shape(&self) -> Result<()> {
        self.header.shape()?;
        let targets = self.header.targets();
        if self.signature.len() != 64
            || self.payloads.len() != targets.len()
            || !(1..=MAX_TARGETS).contains(&self.payloads.len())
        {
            return Err(DirectError::Shape);
        }
        for (payload, (account, member)) in self.payloads.iter().zip(targets) {
            if payload.account != account || payload.device != member.device.device_id {
                return Err(DirectError::Directory);
            }
            if !(117..=MAX_CIPHERTEXT).contains(&payload.ciphertext.len()) {
                return Err(DirectError::Shape);
            }
        }
        Ok(())
    }
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        self.shape()?;
        let mut out = b"LiteSeal/direct-batch/v3\0".to_vec();
        field(&mut out, &self.header.encode());
        out.extend_from_slice(&self.commitment);
        out.push(self.payloads.len() as u8);
        for payload in &self.payloads {
            field(&mut out, payload.account.as_bytes());
            field(&mut out, payload.device.as_bytes());
            out.extend_from_slice(&(payload.ciphertext.len() as u32).to_be_bytes());
            out.extend_from_slice(&hash(&payload.ciphertext));
        }
        Ok(out)
    }
    pub fn digest(&self) -> Result<[u8; 32]> {
        let mut bytes = self.signing_bytes()?;
        bytes.extend_from_slice(&self.signature);
        Ok(hash(&bytes))
    }
    /// The same batch hash chains all recipient copies. Persist/receipt equality
    /// must compare this digest, never an individual ciphertext or message id.
    pub fn chain_hash(&self) -> Result<[u8; 32]> {
        self.digest()
    }
    pub fn chain_head(&self) -> Result<ChainHead> {
        Ok(ChainHead {
            epoch: self.header.epoch()?,
            sequence: self.header.sequence,
            digest: self.digest()?,
        })
    }
    /// Call in addition to signature/directory validation and before persistence
    /// or ACK. Already accepted replay is handled by exact digest equality.
    pub fn verify_next(&self, previous: Option<&ChainHead>) -> Result<()> {
        self.shape()?;
        match previous {
            None if self.header.sequence == 1 && self.header.previous.is_empty() => Ok(()),
            Some(head)
                if head.epoch == self.header.epoch()?
                    && head.sequence.checked_add(1) == Some(self.header.sequence)
                    && self.header.previous == head.digest =>
            {
                Ok(())
            }
            _ => Err(DirectError::Chain),
        }
    }
    pub fn verify(&self, sender: &DeviceState, peer: &DeviceState) -> Result<()> {
        let bytes = self.signing_bytes()?;
        self.header.verify_directories(sender, peer)?;
        if !crypto::verify_with_public_key(
            &bytes,
            &self.signature,
            &self.header.source()?.signing_key,
        )
        .unwrap_or(false)
        {
            return Err(DirectError::Proof);
        }
        Ok(())
    }
    pub fn make(
        header: Header,
        sender: &DeviceState,
        peer: &DeviceState,
        keys: &KeyPair,
        body: &[u8],
    ) -> Result<Self> {
        header.shape()?;
        header.verify_directories(sender, peer)?;
        if body.is_empty()
            || body.len() > MAX_BODY
            || header.kind == Kind::Text && std::str::from_utf8(body).is_err()
        {
            return Err(DirectError::Shape);
        }
        let source = header.source()?;
        if source.encryption_key != keys.public_key || source.signing_key != keys.ed25519_pk {
            return Err(DirectError::Proof);
        }
        // Verify both private/public pairs before emitting any recipient ciphertext.
        let probe = b"LiteSeal/direct-key-pair/v3\0";
        let proof = crypto::sign(probe, &keys.ed25519_sk).map_err(|_| DirectError::Proof)?;
        let mut derived = [0; 32];
        let ok = unsafe {
            libsodium_sys::crypto_scalarmult_base(derived.as_mut_ptr(), keys.secret_key.as_ptr())
        };
        if ok != 0
            || derived != keys.public_key
            || !crypto::verify_with_public_key(probe, &proof, &keys.ed25519_pk).unwrap_or(false)
        {
            return Err(DirectError::Proof);
        }
        let salt = Salt(crypto::random_challenge().map_err(|_| DirectError::Proof)?);
        let context = hash(&header.encode());
        let commitment = commitment(&context, &salt.0, body);
        // Allocate before appending the private salt/body, avoiding freed secret
        // copies from Vec growth. The used buffer is wiped on every exit path.
        let mut plain = Plain(Vec::with_capacity(76 + body.len()));
        plain.0.extend_from_slice(b"LSEALD03");
        plain.0.extend_from_slice(&context);
        plain.0.extend_from_slice(&salt.0);
        plain
            .0
            .extend_from_slice(&(body.len() as u32).to_be_bytes());
        plain.0.extend_from_slice(body);
        let payloads = header
            .targets()
            .iter()
            .map(|(account, member)| {
                Ok(Payload {
                    account: account.clone(),
                    device: member.device.device_id.clone(),
                    ciphertext: crypto::encrypt(
                        &plain.0,
                        &member.device.encryption_key,
                        &keys.secret_key,
                    )
                    .map_err(|_| DirectError::Proof)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut batch = Self {
            header,
            commitment,
            payloads,
            signature: vec![0; 64],
        };
        batch.signature = crypto::sign(&batch.signing_bytes()?, &keys.ed25519_sk)
            .map_err(|_| DirectError::Proof)?;
        batch.verify(sender, peer)?;
        Ok(batch)
    }
    pub fn open(
        &self,
        sender: &DeviceState,
        peer: &DeviceState,
        account: &str,
        device: &str,
        keys: &KeyPair,
    ) -> Result<Vec<u8>> {
        self.verify(sender, peer)?;
        let payload = self
            .payloads
            .iter()
            .find(|p| p.account == account && p.device == device)
            .ok_or(DirectError::Recipient)?;
        let member = self
            .header
            .targets()
            .into_iter()
            .find(|(a, m)| a == account && m.device.device_id == device)
            .ok_or(DirectError::Recipient)?
            .1;
        if member.device.encryption_key != keys.public_key
            || member.device.signing_key != keys.ed25519_pk
        {
            return Err(DirectError::Recipient);
        }
        let plain = Plain(
            crypto::decrypt(
                &payload.ciphertext,
                &self.header.source()?.encryption_key,
                &keys.secret_key,
            )
            .map_err(|_| DirectError::Proof)?,
        );
        self.open_plain(&plain.0)
    }
    /// Authenticate the local author's cached body against an original signed
    /// recipient ciphertext. The source device has no self-delivery payload.
    pub fn open_authored(
        &self,
        sender: &DeviceState,
        peer: &DeviceState,
        keys: &KeyPair,
    ) -> Result<Vec<u8>> {
        self.verify(sender, peer)?;
        let source = self.header.source()?;
        if source.encryption_key != keys.public_key || source.signing_key != keys.ed25519_pk {
            return Err(DirectError::Recipient);
        }
        let payload = self.payloads.first().ok_or(DirectError::Recipient)?;
        let member = self
            .header
            .targets()
            .into_iter()
            .find(|(account, member)| {
                *account == payload.account && member.device.device_id == payload.device
            })
            .ok_or(DirectError::Recipient)?
            .1;
        let plain = Plain(
            crypto::decrypt(
                &payload.ciphertext,
                &member.device.encryption_key,
                &keys.secret_key,
            )
            .map_err(|_| DirectError::Proof)?,
        );
        self.open_plain(&plain.0)
    }
    fn open_plain(&self, plain: &[u8]) -> Result<Vec<u8>> {
        if plain.len() < 77 || plain[..8] != *b"LSEALD03" {
            return Err(DirectError::Proof);
        }
        let context: [u8; 32] = plain[8..40].try_into().map_err(|_| DirectError::Proof)?;
        let salt = Salt(plain[40..72].try_into().map_err(|_| DirectError::Proof)?);
        let size =
            u32::from_be_bytes(plain[72..76].try_into().map_err(|_| DirectError::Proof)?) as usize;
        if context != hash(&self.header.encode())
            || !(1..=MAX_BODY).contains(&size)
            || plain.len() != 76 + size
            || commitment(&context, &salt.0, &plain[76..]) != self.commitment
            || self.header.kind == Kind::Text && std::str::from_utf8(&plain[76..]).is_err()
        {
            return Err(DirectError::Proof);
        }
        Ok(plain[76..].to_vec())
    }
    pub fn to_wire(&self) -> Result<Vec<u8>> {
        self.shape()?;
        let bytes = serde_json::to_vec(self).map_err(|_| DirectError::Shape)?;
        if bytes.len() > MAX_WIRE {
            return Err(DirectError::Shape);
        }
        Ok(bytes)
    }
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_WIRE {
            return Err(DirectError::Shape);
        }
        let batch: Self = serde_json::from_slice(bytes).map_err(|_| DirectError::Shape)?;
        batch.shape()?;
        Ok(batch)
    }
}
