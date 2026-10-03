//! T26 opt-in wire trial. Distinct framing deliberately fails old Batch parsers.
use crate::{
    crypto::{self, KeyPair},
    direct_message::{Batch, DirectError},
    trusted_device::DeviceState,
};
use serde::{Deserialize, Serialize};
pub const MAX_LIFETIME: i64 = 7 * 24 * 60 * 60 * 1000;
const DOMAIN: &str = "LiteSeal/disappearing-message/trial/v1";
type Result<T> = std::result::Result<T, DirectError>;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Packet {
    protocol: String,
    pub original: Batch,
    pub expires_at: i64,
    pub signature: Vec<u8>,
}
impl Packet {
    fn signing_bytes(&self) -> Result<Vec<u8>> {
        let lifetime = self
            .expires_at
            .checked_sub(self.original.header.sent_at)
            .ok_or(DirectError::Shape)?;
        if self.protocol != DOMAIN || !(1000..=MAX_LIFETIME).contains(&lifetime) {
            return Err(DirectError::Shape);
        }
        serde_json::to_vec(&(
            DOMAIN,
            self.original.header.id.as_str(),
            self.original.digest()?,
            self.original.header.sent_at,
            self.expires_at,
        ))
        .map_err(|_| DirectError::Shape)
    }
    pub fn make(
        original: Batch,
        lifetime_ms: i64,
        keys: &KeyPair,
        sender: &DeviceState,
        peer: &DeviceState,
    ) -> Result<Self> {
        original.verify(sender, peer)?;
        let mut packet = Self {
            protocol: DOMAIN.into(),
            expires_at: original
                .header
                .sent_at
                .checked_add(lifetime_ms)
                .ok_or(DirectError::Shape)?,
            original,
            signature: vec![],
        };
        packet.signature = crypto::sign(&packet.signing_bytes()?, &keys.ed25519_sk)
            .map_err(|_| DirectError::Proof)?;
        packet.verify(sender, peer)?;
        Ok(packet)
    }
    pub fn verify(&self, sender: &DeviceState, peer: &DeviceState) -> Result<()> {
        self.original.verify(sender, peer)?;
        let source = self
            .original
            .header
            .sender_directory
            .members
            .iter()
            .find(|m| m.device.device_id == self.original.header.sender_device)
            .ok_or(DirectError::Directory)?;
        if !crypto::verify_with_public_key(
            &self.signing_bytes()?,
            &self.signature,
            &source.device.signing_key,
        )
        .unwrap_or(false)
        {
            return Err(DirectError::Proof);
        }
        Ok(())
    }
    pub fn to_wire(&self) -> Result<Vec<u8>> {
        self.signing_bytes()?;
        let wire = serde_json::to_vec(self).map_err(|_| DirectError::Shape)?;
        if wire.len() > crate::direct_message::MAX_WIRE + 1024 {
            return Err(DirectError::Shape);
        }
        Ok(wire)
    }
    pub fn from_wire(wire: &[u8]) -> Result<Self> {
        if wire.len() > crate::direct_message::MAX_WIRE + 1024 {
            return Err(DirectError::Shape);
        }
        let packet: Self = serde_json::from_slice(wire).map_err(|_| DirectError::Shape)?;
        packet.signing_bytes()?;
        Ok(packet)
    }
    pub fn expired(&self, observed_time: i64) -> bool {
        observed_time >= self.expires_at
    }
}
