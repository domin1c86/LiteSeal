//! Explicit root-authorized snapshots of selected history. A transfer is never
//! an original delivery and does not confer message-author or relay rights.
use crate::{
    crypto::{self, KeyPair},
    direct_media::Descriptor,
    direct_message::{Batch, DirectError, Directory, Kind, Member},
    direct_operation::{Action, Operation},
    trusted_device::{Anchor, DeviceEvent, DeviceIdentity, DeviceState, MAX_DEVICE_EVENTS},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
type Result<T> = std::result::Result<T, DirectError>;
pub const MAX_ITEMS: usize = 64;
pub const MAX_PLAIN: usize = 128 * 1024 * 1024;
pub const MAX_METADATA: usize = 32 * 1024;
pub const MAX_WIRE: usize = MAX_PLAIN + 40 + MAX_METADATA + 12;
pub const LIFETIME: i64 = 10 * 60 * 1000;
pub const CHUNK: usize = 1024 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayState {
    Staging,
    Ready,
    Permitted,
    Received,
    Cancelled,
    Expired,
    Ineligible,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayStatus {
    pub id: String,
    pub digest: [u8; 32],
    pub state: RelayState,
    pub next: usize,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Received {
    pub id: String,
    pub digest: [u8; 32],
    pub target: Member,
    pub confirmed_at: i64,
    pub signature: Vec<u8>,
}
impl Received {
    fn signing(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&(
            "LiteSeal/authorized-history-received/v1",
            &self.id,
            self.digest,
            &self.target,
            self.confirmed_at,
        ))
        .map_err(|_| DirectError::Shape)
    }
    pub fn make(offer: &Offer, confirmed_at: i64, keys: &KeyPair) -> Result<Self> {
        if DeviceIdentity::from_keys(offer.header.target.device.device_id.clone(), keys)
            != offer.header.target.device
        {
            return Err(DirectError::Recipient);
        }
        let mut value = Self {
            id: offer.header.id.clone(),
            digest: offer.digest()?,
            target: offer.header.target.clone(),
            confirmed_at,
            signature: vec![0; 64],
        };
        value.signature =
            crypto::sign(&value.signing()?, &keys.ed25519_sk).map_err(|_| DirectError::Proof)?;
        value.verify(offer)?;
        Ok(value)
    }
    pub fn verify(&self, offer: &Offer) -> Result<()> {
        if self.id != offer.header.id
            || self.digest != offer.digest()?
            || self.target != offer.header.target
            || !time(self.confirmed_at)
            || self.confirmed_at < offer.header.created_at
            || self.signature.len() != 64
        {
            return Err(DirectError::Shape);
        }
        if !crypto::verify_with_public_key(
            &self.signing()?,
            &self.signature,
            &self.target.device.signing_key,
        )
        .map_err(|_| DirectError::Proof)?
        {
            return Err(DirectError::Proof);
        }
        Ok(())
    }
}
const MAGIC: &[u8; 8] = b"LSEALH01";
const DOMAIN: &str = "LiteSeal/authorized-history-transfer/v1";
fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}
fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
fn time(value: i64) -> bool {
    (1..=8_640_000_000_000_000).contains(&value)
}
struct Plain(Vec<u8>);
impl std::io::Write for Plain {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_PLAIN.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("history payload limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl Drop for Plain {
    fn drop(&mut self) {
        unsafe { libsodium_sys::sodium_memzero(self.0.as_mut_ptr().cast(), self.0.len()) }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    pub id: String,
    pub digest: [u8; 32],
    pub operation_revision: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub version: u8,
    pub id: String,
    pub origin: String,
    pub account: String,
    pub source: DeviceIdentity,
    pub target: Member,
    pub directory: Directory,
    pub peer: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub selection: Vec<Reference>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub anchor: Anchor,
    pub events: Vec<DeviceEvent>,
}
impl Evidence {
    pub fn replay(&self, directory: &Directory) -> Result<DeviceState> {
        if self.events.len() > MAX_DEVICE_EVENTS as usize
            || self.events.len() as u64 != directory.revision
        {
            return Err(DirectError::Directory);
        }
        let mut state =
            DeviceState::pin(self.anchor.clone()).map_err(|_| DirectError::Directory)?;
        for event in &self.events {
            state = state.apply(event).map_err(|_| DirectError::Directory)?;
        }
        if Directory::from_state(&state) != *directory {
            return Err(DirectError::Directory);
        }
        Ok(state)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Media {
    pub descriptor: Descriptor,
    pub ciphertext: Option<Vec<u8>>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub original: Batch,
    pub sender: Evidence,
    pub peer: Evidence,
    pub accepted_at: i64,
    pub operations: Vec<Operation>,
    pub text: Option<String>,
    pub media: Option<Media>,
}
impl Drop for Record {
    fn drop(&mut self) {
        if let Some(text) = &mut self.text {
            unsafe { libsodium_sys::sodium_memzero(text.as_mut_ptr().cast(), text.len()) }
        }
    }
}
impl Record {
    /// Count without creating another plaintext copy. Source stores use this
    /// budget before collecting large media batches.
    pub fn bounded_plain_size(&self, limit: usize) -> Result<usize> {
        struct Count {
            size: usize,
            limit: usize,
        }
        impl std::io::Write for Count {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if bytes.len() > self.limit.saturating_sub(self.size) {
                    return Err(std::io::Error::other("history selection limit"));
                }
                self.size += bytes.len();
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut count = Count {
            size: 0,
            limit: limit.min(MAX_PLAIN),
        };
        serde_json::to_writer(&mut count, self).map_err(|_| DirectError::Shape)?;
        Ok(count.size)
    }
    pub fn reference(&self) -> Result<Reference> {
        Ok(Reference {
            id: self.original.header.id.clone(),
            digest: self.original.digest()?,
            operation_revision: self.operations.last().map_or(0, |o| o.header.revision),
        })
    }
    fn checked(&self, header: &Header) -> Result<(DeviceState, DeviceState)> {
        if !time(self.accepted_at)
            || self.operations.len() > crate::direct_operation::MAX_EVENTS as usize
            || self.original.header.origin != header.origin
            || !uuid(&self.original.header.id)
        {
            return Err(DirectError::Shape);
        }
        let own = if self.original.header.sender == header.account {
            &self.sender
        } else if self.original.header.peer == header.account {
            &self.peer
        } else {
            return Err(DirectError::Recipient);
        };
        let other = if self.original.header.sender == header.account {
            &self.original.header.peer
        } else {
            &self.original.header.sender
        };
        if other != &header.peer
            || own.anchor.origin != header.origin
            || own.anchor.account != header.account
            || own.anchor.root != header.source
        {
            return Err(DirectError::Directory);
        }
        let sender = self.sender.replay(&self.original.header.sender_directory)?;
        let peer = self.peer.replay(&self.original.header.peer_directory)?;
        self.original.verify(&sender, &peer)?;
        let digest = self.original.digest()?;
        let mut revision = 0;
        let mut retracted = false;
        let mut ids = BTreeSet::new();
        for operation in &self.operations {
            if retracted
                || operation.header.base != revision
                || operation.original.digest()? != digest
                || !ids.insert(&operation.header.id)
            {
                return Err(DirectError::Chain);
            }
            operation.verify_original(&sender, &peer)?;
            revision = operation.header.revision;
            retracted = operation.header.action == Action::Retract;
        }
        if retracted {
            if self.text.is_some() || self.media.is_some() {
                return Err(DirectError::Shape);
            }
        } else if self.original.header.kind == Kind::Text {
            if self.media.is_some()
                || self
                    .text
                    .as_ref()
                    .is_none_or(|s| s.is_empty() || s.len() > crate::direct_message::MAX_BODY)
            {
                return Err(DirectError::Shape);
            }
        } else {
            if self.text.is_some() {
                return Err(DirectError::Shape);
            }
            let media = self.media.as_ref().ok_or(DirectError::Shape)?;
            media
                .descriptor
                .validate(&self.original.header.id, self.original.header.kind)?;
            if let Some(ciphertext) = &media.ciphertext {
                let _plain = Plain(
                    media
                        .descriptor
                        .decrypt(self.original.header.kind, ciphertext)?,
                );
            }
        }
        Ok((sender, peer))
    }
    fn check_source_plain(&self, header: &Header, keys: &KeyPair) -> Result<()> {
        let (sender, peer) = self.checked(header)?;
        let original = Plain(
            if self.original.header.sender == header.account
                && self.original.header.sender_device == header.source.device_id
            {
                self.original.open_authored(&sender, &peer, keys)?
            } else {
                self.original.open(
                    &sender,
                    &peer,
                    &header.account,
                    &header.source.device_id,
                    keys,
                )?
            },
        );
        let own = if sender.anchor().account == header.account {
            &sender
        } else {
            &peer
        };
        let authority: [u8; 32] = own
            .anchor()
            .hash()
            .try_into()
            .map_err(|_| DirectError::Directory)?;
        let mut edited = None;
        for operation in &self.operations {
            edited = operation
                .open(
                    &sender,
                    &peer,
                    &header.account,
                    &header.source.device_id,
                    authority,
                    keys,
                )?
                .map(|text| Plain(text.into_bytes()));
        }
        if self
            .operations
            .last()
            .is_some_and(|o| o.header.action == Action::Retract)
        {
            return Ok(());
        }
        if self.original.header.kind == Kind::Text {
            let expected = edited
                .as_ref()
                .map_or(original.0.as_slice(), |s| s.0.as_slice());
            if self.text.as_ref().map(|s| s.as_bytes()) != Some(expected) {
                return Err(DirectError::Proof);
            }
        } else if self
            .media
            .as_ref()
            .ok_or(DirectError::Shape)?
            .descriptor
            .to_body(self.original.header.kind)?
            != original.0
        {
            return Err(DirectError::Proof);
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    domain: String,
    binding: [u8; 32],
    records: Vec<Record>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Offer {
    pub header: Header,
    pub size: usize,
    pub digest: [u8; 32],
    pub signature: Vec<u8>,
}
impl Offer {
    fn signing(&self) -> Result<Vec<u8>> {
        if !(40..=MAX_PLAIN + 40).contains(&self.size) || self.signature.len() != 64 {
            return Err(DirectError::Shape);
        }
        let mut bytes = DOMAIN.as_bytes().to_vec();
        bytes.push(0);
        bytes.extend_from_slice(&self.header.binding()?);
        bytes.extend_from_slice(&(self.size as u64).to_be_bytes());
        bytes.extend_from_slice(&self.digest);
        Ok(bytes)
    }
    pub fn verify(&self, current: &DeviceState) -> Result<()> {
        self.header.check(current)?;
        if !crypto::verify_with_public_key(
            &self.signing()?,
            &self.signature,
            &self.header.source.signing_key,
        )
        .map_err(|_| DirectError::Proof)?
        {
            return Err(DirectError::Proof);
        }
        if serde_json::to_vec(self)
            .map_err(|_| DirectError::Shape)?
            .len()
            > MAX_METADATA
        {
            return Err(DirectError::Shape);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<[u8; 32]> {
        let mut bytes = self.signing()?;
        bytes.extend_from_slice(&self.signature);
        Ok(hash(&bytes))
    }
    pub fn chunk_len(&self, part: usize) -> Result<usize> {
        let offset = part.checked_mul(1024 * 1024).ok_or(DirectError::Shape)?;
        if offset >= self.size {
            return Err(DirectError::Shape);
        }
        Ok((self.size - offset).min(1024 * 1024))
    }
}
#[derive(Clone)]
pub struct Envelope {
    pub header: Header,
    ciphertext: Vec<u8>,
    signature: Vec<u8>,
}
impl Header {
    fn check(&self, current: &DeviceState) -> Result<()> {
        if self.version != 1
            || !uuid(&self.id)
            || !identifier(&self.account)
            || !identifier(&self.peer)
            || self.peer == self.account
            || !time(self.created_at)
            || !time(self.expires_at)
            || self.expires_at <= self.created_at
            || self.expires_at - self.created_at > LIFETIME
            || !(1..=MAX_ITEMS).contains(&self.selection.len())
        {
            return Err(DirectError::Shape);
        }
        if current.anchor().origin != self.origin
            || current.anchor().account != self.account
            || current.anchor().root != self.source
            || Directory::from_state(current) != self.directory
            || self.source.device_id == self.target.device.device_id
            || !self.directory.members.iter().any(|m| m == &self.target)
        {
            return Err(DirectError::Directory);
        }
        let mut ids = BTreeSet::new();
        for item in &self.selection {
            if !uuid(&item.id)
                || item.digest == [0; 32]
                || item.operation_revision > crate::direct_operation::MAX_EVENTS as u64
                || !ids.insert(&item.id)
            {
                return Err(DirectError::Shape);
            }
        }
        Ok(())
    }
    fn binding(&self) -> Result<[u8; 32]> {
        Ok(hash(
            &serde_json::to_vec(&(DOMAIN, self)).map_err(|_| DirectError::Shape)?,
        ))
    }
}
impl Envelope {
    fn signing(&self) -> Result<Vec<u8>> {
        self.offer().signing()
    }
    pub fn offer(&self) -> Offer {
        Offer {
            header: self.header.clone(),
            size: self.ciphertext.len(),
            digest: hash(&self.ciphertext),
            signature: self.signature.clone(),
        }
    }
    pub fn ciphertext_chunk(&self, part: usize) -> Result<&[u8]> {
        let length = self.offer().chunk_len(part)?;
        let start = part * CHUNK;
        Ok(&self.ciphertext[start..start + length])
    }
    pub fn from_offer(offer: Offer, ciphertext: Vec<u8>) -> Result<Self> {
        offer.signing()?;
        if offer.size != ciphertext.len() || offer.digest != hash(&ciphertext) {
            return Err(DirectError::Proof);
        }
        Ok(Self {
            header: offer.header,
            ciphertext,
            signature: offer.signature,
        })
    }
    pub fn make(
        header: Header,
        current: &DeviceState,
        keys: &KeyPair,
        records: Vec<Record>,
    ) -> Result<Self> {
        header.check(current)?;
        if DeviceIdentity::from_keys(header.source.device_id.clone(), keys) != header.source
            || records.len() != header.selection.len()
        {
            return Err(DirectError::Recipient);
        }
        for (record, reference) in records.iter().zip(&header.selection) {
            if record.reference()? != *reference {
                return Err(DirectError::Shape);
            }
            record.check_source_plain(&header, keys)?;
        }
        let payload = Payload {
            domain: DOMAIN.into(),
            binding: header.binding()?,
            records,
        };
        let mut plain = Plain(Vec::new());
        serde_json::to_writer(&mut plain, &payload).map_err(|_| DirectError::Shape)?;
        let ciphertext = crypto::encrypt(
            &plain.0,
            &header.target.device.encryption_key,
            &keys.secret_key,
        )
        .map_err(|_| DirectError::Proof)?;
        let mut envelope = Self {
            header,
            ciphertext,
            signature: vec![0; 64],
        };
        envelope.signature =
            crypto::sign(&envelope.signing()?, &keys.ed25519_sk).map_err(|_| DirectError::Proof)?;
        envelope.verify(current)?;
        Ok(envelope)
    }
    pub fn verify(&self, current: &DeviceState) -> Result<()> {
        self.header.check(current)?;
        if !crypto::verify_with_public_key(
            &self.signing()?,
            &self.signature,
            &self.header.source.signing_key,
        )
        .map_err(|_| DirectError::Proof)?
        {
            return Err(DirectError::Proof);
        }
        Ok(())
    }
    /// Call only with a freshly verified current own directory for a new import.
    /// Already imported local copies use their original verified receipt instead.
    pub fn open(&self, current: &DeviceState, keys: &KeyPair, now: i64) -> Result<Vec<Record>> {
        if !time(now) || now < self.header.created_at || now >= self.header.expires_at {
            return Err(DirectError::Recipient);
        }
        self.open_received(current, keys)
    }
    /// Offline reads only: the caller must already hold a durable verified
    /// import receipt and the exact historical authorization prefix. This is
    /// never an admission check for a new import or a remote queue response.
    pub fn open_received(&self, authorized: &DeviceState, keys: &KeyPair) -> Result<Vec<Record>> {
        self.verify(authorized)?;
        if DeviceIdentity::from_keys(self.header.target.device.device_id.clone(), keys)
            != self.header.target.device
        {
            return Err(DirectError::Recipient);
        }
        let plain = Plain(
            crypto::decrypt(
                &self.ciphertext,
                &self.header.source.encryption_key,
                &keys.secret_key,
            )
            .map_err(|_| DirectError::Proof)?,
        );
        if plain.0.len() > MAX_PLAIN {
            return Err(DirectError::Shape);
        }
        let payload: Payload = serde_json::from_slice(&plain.0).map_err(|_| DirectError::Shape)?;
        if payload.domain != DOMAIN
            || payload.binding != self.header.binding()?
            || payload.records.len() != self.header.selection.len()
        {
            return Err(DirectError::Shape);
        }
        for (record, reference) in payload.records.iter().zip(&self.header.selection) {
            record.checked(&self.header)?;
            if record.reference()? != *reference {
                return Err(DirectError::Shape);
            }
        }
        Ok(payload.records)
    }
    pub fn digest(&self) -> Result<[u8; 32]> {
        let mut bytes = self.signing()?;
        bytes.extend_from_slice(&self.signature);
        Ok(hash(&bytes))
    }
    pub fn to_wire(&self) -> Result<Vec<u8>> {
        self.signing()?;
        let metadata = serde_json::to_vec(&self.offer()).map_err(|_| DirectError::Shape)?;
        if metadata.len() > MAX_METADATA {
            return Err(DirectError::Shape);
        }
        let mut wire = MAGIC.to_vec();
        wire.extend_from_slice(&(metadata.len() as u32).to_be_bytes());
        wire.extend(metadata);
        wire.extend_from_slice(&self.ciphertext);
        Ok(wire)
    }
    pub fn from_wire(wire: &[u8]) -> Result<Self> {
        if wire.len() < 12 || wire.len() > MAX_WIRE || &wire[..8] != MAGIC {
            return Err(DirectError::Shape);
        }
        let size =
            u32::from_be_bytes(wire[8..12].try_into().map_err(|_| DirectError::Shape)?) as usize;
        if size > MAX_METADATA || size > wire.len() - 12 {
            return Err(DirectError::Shape);
        }
        let metadata: Offer =
            serde_json::from_slice(&wire[12..12 + size]).map_err(|_| DirectError::Shape)?;
        let ciphertext = &wire[12 + size..];
        if metadata.size != ciphertext.len() || metadata.digest != hash(ciphertext) {
            return Err(DirectError::Proof);
        }
        let envelope = Self {
            header: metadata.header,
            ciphertext: ciphertext.to_vec(),
            signature: metadata.signature,
        };
        envelope.signing()?;
        Ok(envelope)
    }
}
