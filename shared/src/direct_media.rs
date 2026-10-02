//! Media descriptors stay inside the existing per-device encrypted batch.
//! A separately signed upload binding exposes only ciphertext size and digest,
//! preserving the v3 text wire and its original batch/receipt digest.
use crate::{
    crypto::{self, KeyPair},
    direct_message::{Batch, DirectError, Header, Kind},
    trusted_device::DeviceState,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub const MAX_FILE: usize = 20 * 1024 * 1024;
pub const MAX_VOICE: usize = 11 * 1024 * 1024;
pub const CHUNK: usize = 1024 * 1024;
pub const MAX_DESCRIPTOR: usize = 8192;
pub const MAX_SUBMISSION: usize = crate::direct_message::MAX_WIRE + 4096;
type Result<T> = std::result::Result<T, DirectError>;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    pub size: u64,
    pub hash: [u8; 32],
}
impl Reference {
    pub fn validate(&self, kind: Kind) -> Result<()> {
        let limit = match kind {
            Kind::Attachment => MAX_FILE,
            Kind::Voice => MAX_VOICE,
            Kind::Text => return Err(DirectError::Shape),
        };
        if !(40..=limit as u64 + 40).contains(&self.size) {
            return Err(DirectError::Shape);
        }
        Ok(())
    }
    pub fn verify_bytes(&self, bytes: &[u8]) -> Result<()> {
        if bytes.len() as u64 != self.size || Sha256::digest(bytes).as_slice() != self.hash {
            return Err(DirectError::Proof);
        }
        Ok(())
    }
    pub fn chunk_len(&self, part: i32) -> Result<usize> {
        if part < 0 {
            return Err(DirectError::Shape);
        }
        let offset = (part as u64)
            .checked_mul(CHUNK as u64)
            .ok_or(DirectError::Shape)?;
        if offset >= self.size {
            return Err(DirectError::Shape);
        }
        Ok((self.size - offset).min(CHUNK as u64) as usize)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub version: u8,
    pub id: String,
    pub name: String,
    pub size: u64,
    pub mime: String,
    pub duration_ms: Option<u32>,
    pub key: [u8; 32],
    pub hash: [u8; 32],
}
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe { libsodium_sys::sodium_memzero(self.key.as_mut_ptr().cast(), self.key.len()) }
    }
}
fn uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
            }
        })
}
pub fn detected_mime(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        "image/png"
    } else if bytes.starts_with(&[255, 216, 255]) {
        "image/jpeg"
    } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        "image/webp"
    } else {
        "application/octet-stream"
    }
}
fn voice(bytes: &[u8]) -> bool {
    let head = &bytes[..bytes.len().min(4096)];
    bytes.starts_with(&[0x1a, 0x45, 0xdf, 0xa3])
        && [b"webm".as_slice(), b"A_OPUS", b"OpusHead"]
            .iter()
            .all(|mark| head.windows(mark.len()).any(|p| p == *mark))
}
impl Descriptor {
    pub fn reference(&self) -> Result<Reference> {
        Ok(Reference {
            size: self.size.checked_add(40).ok_or(DirectError::Shape)?,
            hash: self.hash,
        })
    }
    pub fn validate(&self, id: &str, kind: Kind) -> Result<()> {
        if self.version != 1
            || !uuid(&self.id)
            || self.id != id
            || self.name.is_empty()
            || self.name.chars().count() > 160
            || self.name.trim_matches(['.', ' ']) != self.name
            || self
                .name
                .chars()
                .any(|c| c.is_control() || "<>:\"/\\|?*".contains(c))
        {
            return Err(DirectError::Shape);
        }
        self.reference()?.validate(kind)?;
        match kind {
            Kind::Attachment
                if self.duration_ms.is_none()
                    && [
                        "image/png",
                        "image/jpeg",
                        "image/webp",
                        "application/octet-stream",
                    ]
                    .contains(&self.mime.as_str()) =>
            {
                Ok(())
            }
            Kind::Voice
                if self.mime == "audio/webm"
                    && self.duration_ms.is_some_and(|d| (1..=60000).contains(&d))
                    && self.size > 0 =>
            {
                Ok(())
            }
            _ => Err(DirectError::Shape),
        }
    }
    pub fn encrypt(
        id: String,
        name: String,
        bytes: &[u8],
        kind: Kind,
        duration_ms: Option<u32>,
    ) -> Result<(Self, Vec<u8>)> {
        if bytes.len() > MAX_FILE
            || kind == Kind::Text
            || kind == Kind::Voice && (bytes.len() > MAX_VOICE || !voice(bytes))
        {
            return Err(DirectError::Shape);
        }
        // Reject metadata before allocating/encrypting a large input.
        let mut d = Self {
            version: 1,
            id,
            name,
            size: bytes.len() as u64,
            mime: if kind == Kind::Voice {
                "audio/webm"
            } else {
                detected_mime(bytes)
            }
            .into(),
            duration_ms,
            key: [0; 32],
            hash: [0; 32],
        };
        d.validate(&d.id, kind)?;
        let (cipher, mut key) =
            crypto::encrypt_attachment(bytes).map_err(|_| DirectError::Proof)?;
        let converted = key.as_slice().try_into();
        unsafe { libsodium_sys::sodium_memzero(key.as_mut_ptr().cast(), key.len()) };
        d.key = converted.map_err(|_| DirectError::Proof)?;
        d.hash = Sha256::digest(&cipher).into();
        Ok((d, cipher))
    }
    pub fn to_body(&self, kind: Kind) -> Result<Vec<u8>> {
        self.validate(&self.id, kind)?;
        let body = serde_json::to_vec(self).map_err(|_| DirectError::Shape)?;
        if body.len() > MAX_DESCRIPTOR {
            return Err(DirectError::Shape);
        }
        Ok(body)
    }
    pub fn from_body(header: &Header, body: &[u8]) -> Result<Self> {
        if body.len() > MAX_DESCRIPTOR {
            return Err(DirectError::Shape);
        }
        let d: Self = serde_json::from_slice(body).map_err(|_| DirectError::Shape)?;
        d.validate(&header.id, header.kind)?;
        Ok(d)
    }
    pub fn decrypt(&self, kind: Kind, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.validate(&self.id, kind)?;
        self.reference()?.verify_bytes(ciphertext)?;
        let mut bytes =
            crypto::decrypt_attachment(ciphertext, &self.key).map_err(|_| DirectError::Proof)?;
        if bytes.len() as u64 != self.size
            || if kind == Kind::Voice {
                !voice(&bytes)
            } else {
                detected_mime(&bytes) != self.mime
            }
        {
            unsafe { libsodium_sys::sodium_memzero(bytes.as_mut_ptr().cast(), bytes.len()) };
            return Err(DirectError::Proof);
        }
        Ok(bytes)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub version: u8,
    pub batch: Batch,
    pub object: Reference,
    pub signature: Vec<u8>,
}
impl Submission {
    fn bytes(&self) -> Result<Vec<u8>> {
        self.object.validate(self.batch.header.kind)?;
        if self.version != 1 || self.signature.len() != 64 || !uuid(&self.batch.header.id) {
            return Err(DirectError::Shape);
        }
        let mut bytes = b"LiteSeal/direct-media-binding/v1\0".to_vec();
        bytes.extend_from_slice(&self.batch.digest()?);
        bytes.extend_from_slice(&self.object.size.to_le_bytes());
        bytes.extend_from_slice(&self.object.hash);
        Ok(bytes)
    }
    pub fn verify_binding(&self) -> Result<()> {
        let source = self
            .batch
            .header
            .sender_directory
            .members
            .iter()
            .find(|m| m.device.device_id == self.batch.header.sender_device)
            .ok_or(DirectError::Directory)?;
        if !crypto::verify_with_public_key(
            &self.bytes()?,
            &self.signature,
            &source.device.signing_key,
        )
        .unwrap_or(false)
        {
            return Err(DirectError::Proof);
        }
        Ok(())
    }
    pub fn verify(&self, sender: &DeviceState, peer: &DeviceState) -> Result<()> {
        self.batch.verify(sender, peer)?;
        self.verify_binding()
    }
    pub fn make(
        header: Header,
        sender: &DeviceState,
        peer: &DeviceState,
        keys: &KeyPair,
        descriptor: &Descriptor,
    ) -> Result<Self> {
        descriptor.validate(&header.id, header.kind)?;
        let mut body = descriptor.to_body(header.kind)?;
        let made = Batch::make(header, sender, peer, keys, &body);
        unsafe { libsodium_sys::sodium_memzero(body.as_mut_ptr().cast(), body.len()) };
        let value = Self::bind(made?, descriptor, keys)?;
        value.verify(sender, peer)?;
        Ok(value)
    }
    /// Bind an already prepared immutable batch without allocating another
    /// message ID, content salt or recipient ciphertext on retry.
    pub fn bind(batch: Batch, descriptor: &Descriptor, keys: &KeyPair) -> Result<Self> {
        descriptor.validate(&batch.header.id, batch.header.kind)?;
        let source = batch
            .header
            .sender_directory
            .members
            .iter()
            .find(|m| m.device.device_id == batch.header.sender_device)
            .ok_or(DirectError::Directory)?;
        if source.device.encryption_key != keys.public_key
            || source.device.signing_key != keys.ed25519_pk
            || !crypto::verify_with_public_key(
                &batch.signing_bytes()?,
                &batch.signature,
                &source.device.signing_key,
            )
            .unwrap_or(false)
        {
            return Err(DirectError::Proof);
        }
        let mut value = Self {
            version: 1,
            batch,
            object: descriptor.reference()?,
            signature: vec![0; 64],
        };
        value.signature =
            crypto::sign(&value.bytes()?, &keys.ed25519_sk).map_err(|_| DirectError::Proof)?;
        value.verify_binding()?;
        Ok(value)
    }
    pub fn digest(&self) -> Result<[u8; 32]> {
        let mut bytes = self.bytes()?;
        bytes.extend_from_slice(&self.signature);
        Ok(Sha256::digest(bytes).into())
    }
    pub fn to_wire(&self) -> Result<Vec<u8>> {
        self.verify_binding()?;
        let bytes = serde_json::to_vec(self).map_err(|_| DirectError::Shape)?;
        if bytes.len() > MAX_SUBMISSION {
            return Err(DirectError::Shape);
        }
        Ok(bytes)
    }
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_SUBMISSION {
            return Err(DirectError::Shape);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| DirectError::Shape)?;
        value.verify_binding()?;
        Ok(value)
    }
}
