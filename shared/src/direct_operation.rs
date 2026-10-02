//! Edits/retractions form a separate immutable log. They never rewrite a batch,
//! widen its original audience, or grant another device the author's rights.
use crate::{
    crypto::{self, KeyPair},
    direct_message::{Batch, DirectError, Directory, Kind, Member, MAX_BODY},
    trusted_device::{DeviceIdentity, DeviceState},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub const MAX_WIRE: usize = 512 * 1024 - 1024;
pub const MAX_EVENTS: i64 = 10_000;
pub const MAX_PAGE: usize = 100;
pub const MAX_PAGE_BYTES: usize = 512 * 1024;
const DOMAIN: &[u8] = b"LiteSeal/direct-operation-body/v1\0";
type Result<T> = std::result::Result<T, DirectError>;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Edit,
    Retract,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub version: u8,
    pub id: String,
    pub original: [u8; 32],
    pub action: Action,
    pub base: u64,
    pub revision: u64,
    pub created_at: i64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    pub account: String,
    pub device: String,
    pub authority: [u8; 32],
    pub ciphertext: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub original: Batch,
    pub header: Header,
    pub payloads: Vec<Payload>,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub order: i64,
    pub accepted_at: i64,
    pub operation: Operation,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    pub events: Vec<Event>,
    pub through: i64,
    pub has_more: bool,
}
struct Plain(Vec<u8>);
impl Drop for Plain {
    fn drop(&mut self) {
        unsafe {
            libsodium_sys::sodium_memzero(self.0.as_mut_ptr().cast(), self.0.len());
        }
    }
}
fn identity(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 128
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}
fn source(original: &Batch) -> Result<&Member> {
    original
        .header
        .sender_directory
        .members
        .iter()
        .find(|m| m.device.device_id == original.header.sender_device)
        .ok_or(DirectError::Directory)
}
fn originals(original: &Batch) -> Vec<(String, &Member)> {
    let mut targets: Vec<_> = original
        .header
        .sender_directory
        .members
        .iter()
        .map(|m| (original.header.sender.clone(), m))
        .chain(
            original
                .header
                .peer_directory
                .members
                .iter()
                .map(|m| (original.header.peer.clone(), m)),
        )
        .collect();
    targets.sort_by(|a, b| (&a.0, &a.1.device.device_id).cmp(&(&b.0, &b.1.device.device_id)));
    targets
}
/// The exact original phases still active now, including the author's own copy.
pub fn audience(
    original: &Batch,
    sender: &DeviceState,
    peer: &DeviceState,
) -> Result<Vec<(String, Member)>> {
    if sender.anchor().origin != original.header.origin
        || peer.anchor().origin != original.header.origin
        || sender.anchor().account != original.header.sender
        || peer.anchor().account != original.header.peer
    {
        return Err(DirectError::Directory);
    }
    let s = Directory::from_state(sender);
    let p = Directory::from_state(peer);
    let result: Vec<_> = originals(original)
        .into_iter()
        .filter_map(|(a, m)| {
            let current = if a == original.header.sender { &s } else { &p };
            current
                .members
                .iter()
                .find(|n| *n == m)
                .map(|_| (a, m.clone()))
        })
        .collect();
    let author = source(original)?;
    if !result
        .iter()
        .any(|(a, m)| a == &original.header.sender && m == author)
    {
        return Err(DirectError::Directory);
    }
    Ok(result)
}
impl Operation {
    fn shape(&self) -> Result<()> {
        if self.header.version != 1
            || !identity(&self.header.id)
            || self.header.base.checked_add(1) != Some(self.header.revision)
            || self.header.revision > MAX_EVENTS as u64
            || self.header.created_at <= 0
            || self.header.created_at > 8_640_000_000_000_000
            || self.header.original != self.original.digest()?
            || self.signature.len() != 64
            || !(1..=4).contains(&self.payloads.len())
            || self.header.action == Action::Edit && self.original.header.kind != Kind::Text
        {
            return Err(DirectError::Shape);
        }
        let targets = originals(&self.original);
        let mut previous = None;
        for payload in &self.payloads {
            let key = (&payload.account, &payload.device);
            if previous.is_some_and(|p| p >= key)
                || payload.ciphertext.len() < DOMAIN.len() + 33 + 40
                || payload.ciphertext.len() > DOMAIN.len() + 33 + MAX_BODY + 40
                || !targets.iter().any(|(a, m)| {
                    a == &payload.account
                        && m.device.device_id == payload.device
                        && m.authorization_hash == payload.authority
                })
            {
                return Err(DirectError::Directory);
            }
            previous = Some(key);
        }
        Ok(())
    }
    fn binding(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(
            serde_json::to_vec(&(
                "LiteSeal/direct-operation-header/v1",
                &self.original.header,
                &self.header,
            ))
            .map_err(|_| DirectError::Shape)?,
        )
        .into())
    }
    fn signing_bytes(&self) -> Result<Vec<u8>> {
        self.shape()?;
        let mut bytes = b"LiteSeal/direct-operation/v1\0".to_vec();
        bytes.extend_from_slice(&self.binding()?);
        for p in &self.payloads {
            let target = serde_json::to_vec(&(&p.account, &p.device, p.authority))
                .map_err(|_| DirectError::Shape)?;
            bytes.extend_from_slice(&(target.len() as u32).to_be_bytes());
            bytes.extend(target);
            bytes.extend_from_slice(&(p.ciphertext.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&Sha256::digest(&p.ciphertext));
        }
        Ok(bytes)
    }
    pub fn digest(&self) -> Result<[u8; 32]> {
        let mut bytes = self.signing_bytes()?;
        bytes.extend_from_slice(&self.signature);
        Ok(Sha256::digest(bytes).into())
    }
    pub fn verify_original(&self, sender: &DeviceState, peer: &DeviceState) -> Result<()> {
        self.original.verify(sender, peer)?;
        let bytes = self.signing_bytes()?;
        if !crypto::verify_with_public_key(
            &bytes,
            &self.signature,
            &source(&self.original)?.device.signing_key,
        )
        .map_err(|_| DirectError::Proof)?
        {
            return Err(DirectError::Proof);
        }
        Ok(())
    }
    pub fn verify_current(
        &self,
        old_sender: &DeviceState,
        old_peer: &DeviceState,
        sender: &DeviceState,
        peer: &DeviceState,
    ) -> Result<()> {
        self.verify_original(old_sender, old_peer)?;
        let targets = audience(&self.original, sender, peer)?;
        if targets.len() != self.payloads.len()
            || targets.iter().zip(&self.payloads).any(|((a, m), p)| {
                a != &p.account
                    || m.device.device_id != p.device
                    || m.authorization_hash != p.authority
            })
        {
            return Err(DirectError::Directory);
        }
        Ok(())
    }
    pub fn make(
        original: Batch,
        old: (&DeviceState, &DeviceState),
        current: (&DeviceState, &DeviceState),
        keys: &KeyPair,
        header: Header,
        text: Option<&str>,
    ) -> Result<Self> {
        let (old_sender, old_peer) = old;
        let (sender, peer) = current;
        original.verify(old_sender, old_peer)?;
        let author = source(&original)?;
        if author.device != DeviceIdentity::from_keys(original.header.sender_device.clone(), keys) {
            return Err(DirectError::Recipient);
        }
        let targets = audience(&original, sender, peer)?;
        let mut operation = Self {
            original,
            header,
            payloads: vec![],
            signature: vec![0; 64],
        };
        let content = match (operation.header.action, text) {
            (Action::Edit, Some(text)) if !text.is_empty() && text.len() <= MAX_BODY => {
                text.as_bytes()
            }
            (Action::Retract, None) => b"",
            _ => return Err(DirectError::Shape),
        };
        let mut body = Plain(DOMAIN.to_vec());
        body.0.extend_from_slice(&operation.binding()?);
        body.0.push(if operation.header.action == Action::Edit {
            0
        } else {
            1
        });
        body.0.extend_from_slice(content);
        for (account, member) in targets {
            operation.payloads.push(Payload {
                account,
                device: member.device.device_id,
                authority: member.authorization_hash,
                ciphertext: crypto::encrypt(
                    &body.0,
                    &member.device.encryption_key,
                    &keys.secret_key,
                )
                .map_err(|_| DirectError::Proof)?,
            });
        }
        operation.signature = crypto::sign(&operation.signing_bytes()?, &keys.ed25519_sk)
            .map_err(|_| DirectError::Proof)?;
        operation.verify_current(old_sender, old_peer, sender, peer)?;
        Ok(operation)
    }
    pub fn open(
        &self,
        sender: &DeviceState,
        peer: &DeviceState,
        account: &str,
        device: &str,
        authority: [u8; 32],
        keys: &KeyPair,
    ) -> Result<Option<String>> {
        self.verify_original(sender, peer)?;
        let target = originals(&self.original)
            .into_iter()
            .find(|(a, m)| {
                a == account
                    && m.device == DeviceIdentity::from_keys(device.into(), keys)
                    && m.authorization_hash == authority
            })
            .ok_or(DirectError::Recipient)?;
        let payload = self
            .payloads
            .iter()
            .find(|p| p.account == target.0 && p.device == device && p.authority == authority)
            .ok_or(DirectError::Recipient)?;
        let body = Plain(
            crypto::decrypt(
                &payload.ciphertext,
                &source(&self.original)?.device.encryption_key,
                &keys.secret_key,
            )
            .map_err(|_| DirectError::Proof)?,
        );
        let prefix = DOMAIN.len() + 33;
        if body.0.len() < prefix
            || body.0.len() > prefix + MAX_BODY
            || !body.0.starts_with(DOMAIN)
            || body.0[DOMAIN.len()..DOMAIN.len() + 32] != self.binding()?
            || body.0[prefix - 1]
                != if self.header.action == Action::Edit {
                    0
                } else {
                    1
                }
        {
            return Err(DirectError::Proof);
        }
        match self.header.action {
            Action::Edit => {
                let text =
                    std::str::from_utf8(&body.0[prefix..]).map_err(|_| DirectError::Proof)?;
                if text.is_empty() {
                    return Err(DirectError::Shape);
                }
                Ok(Some(text.into()))
            }
            Action::Retract if body.0.len() == prefix => Ok(None),
            _ => Err(DirectError::Shape),
        }
    }
    pub fn to_wire(&self) -> Result<Vec<u8>> {
        self.shape()?;
        let wire = serde_json::to_vec(self).map_err(|_| DirectError::Shape)?;
        if wire.len() > MAX_WIRE {
            return Err(DirectError::Shape);
        }
        Ok(wire)
    }
    pub fn from_wire(wire: &[u8]) -> Result<Self> {
        if wire.len() > MAX_WIRE {
            return Err(DirectError::Shape);
        }
        let op: Self = serde_json::from_slice(wire).map_err(|_| DirectError::Shape)?;
        op.shape()?;
        Ok(op)
    }
}
