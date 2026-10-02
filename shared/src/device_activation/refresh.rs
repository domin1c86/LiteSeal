//! Refresh keeps an immutable request and fresh possession proof. The old
//! refresh capability is an HTTP bearer, never a wire field or plaintext reply.
use super::*;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Start {
    pub version: u8,
    pub id: String,
    pub origin: String,
    pub account: String,
    pub session: String,
    pub device: DeviceIdentity,
    pub authorization: [u8; 32],
    pub mode: [u8; 32],
    pub revision: u64,
    pub head: [u8; 32],
    pub refresh_hash: [u8; 32],
    pub issued_at: i64,
    pub expires_at: i64,
    pub signature: Vec<u8>,
}
impl Start {
    pub fn verify_keys(&self, keys: &KeyPair) -> Result<()> {
        key_check(keys, &self.device)
    }
    fn signing(&self) -> Result<Vec<u8>> {
        if self.version != 1
            || !id(&self.id)
            || !id(&self.session)
            || !id(&self.account)
            || canonical_origin(&self.origin).map_err(|_| bad())? != self.origin
            || self.device.encryption_key == [0; 32]
            || self.device.signing_key == [0; 32]
            || !id(&self.device.device_id)
            || self.authorization == [0; 32]
            || self.mode == [0; 32]
            || self.refresh_hash == [0; 32]
            || self.signature.len() != 64
            || self.issued_at < 0
            || self.expires_at != self.issued_at.checked_add(LIFETIME).ok_or_else(bad)?
        {
            return Err(bad());
        }
        Ok(bytes(&(
            "LiteSeal/session-refresh-start/v1",
            self.version,
            &self.id,
            &self.origin,
            &self.account,
            &self.session,
            &self.device,
            self.authorization,
            self.mode,
            self.revision,
            self.head,
            self.refresh_hash,
            self.issued_at,
            self.expires_at,
        )))
    }
    pub fn make(
        state: &DeviceState,
        mode: &Enable,
        session: &Session,
        id_: &str,
        at: i64,
        keys: &KeyPair,
    ) -> Result<Self> {
        let device = DeviceIdentity {
            device_id: session.device.clone(),
            encryption_key: keys.public_key,
            signing_key: keys.ed25519_pk,
        };
        key_check(keys, &device)?;
        let mut request = Self {
            version: 1,
            id: id_.into(),
            origin: state.anchor().origin.clone(),
            account: session.account.clone(),
            session: session.id.clone(),
            device,
            authorization: session.authorization,
            mode: session.mode,
            revision: state.revision(),
            head: state.head().try_into().map_err(|_| bad())?,
            refresh_hash: hash(session.refresh_token.as_bytes()),
            issued_at: at,
            expires_at: at.checked_add(LIFETIME).ok_or_else(bad)?,
            signature: vec![0; 64],
        };
        if session.refresh_token.is_empty()
            || session.refresh_token.len() > 256
            || at >= session.refresh_expires_at
        {
            return Err(bad());
        }
        request.signature =
            crypto::sign(&request.signing()?, &keys.ed25519_sk).map_err(|_| bad())?;
        request.verify_state(state, mode, at)?;
        Ok(request)
    }
    pub fn digest(&self) -> Result<[u8; 32]> {
        let mut data = self.signing()?;
        data.extend_from_slice(&self.signature);
        Ok(hash(&data))
    }
    pub fn verify_state(&self, state: &DeviceState, mode: &Enable, at: i64) -> Result<()> {
        mode.verify_root(state.anchor())?;
        let member = Directory::from_state(state)
            .members
            .into_iter()
            .find(|m| m.device == self.device)
            .ok_or_else(bad)?;
        if self.origin != state.anchor().origin
            || self.account != state.anchor().account
            || self.authorization != member.authorization_hash
            || self.mode != mode.digest()?
            || self.revision != state.revision()
            || self.head.as_slice() != state.head()
            || at < self.issued_at
            || at >= self.expires_at
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
    pub fn bind_original(&self, session: &Session) -> Result<()> {
        self.digest()?;
        if self.session != session.id
            || self.account != session.account
            || self.device.device_id != session.device
            || self.authorization != session.authorization
            || self.mode != session.mode
            || session.refresh_token.is_empty()
            || self.refresh_hash != hash(session.refresh_token.as_bytes())
        {
            return Err(bad());
        }
        Ok(())
    }
    pub fn verify_challenge(
        &self,
        challenge: &Challenge,
        state: &DeviceState,
        mode: &Enable,
        keys: &KeyPair,
    ) -> Result<()> {
        self.verify_state(state, mode, self.issued_at)?;
        if challenge.id != self.id
            || challenge.issued_at < self.issued_at
            || challenge.issued_at >= self.expires_at
        {
            return Err(bad());
        }
        challenge.authenticate(state, mode, keys)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub request: [u8; 32],
    pub challenge: [u8; 32],
    pub server_key: [u8; 32],
    pub encrypted: Vec<u8>,
}
fn session_scope(request: &Start, challenge: &Challenge, session: &Session) -> Result<()> {
    if !id(&session.id)
        || session.id == request.session
        || session.account != request.account
        || session.device != request.device.device_id
        || session.authorization != request.authorization
        || session.mode != request.mode
        || session.expires_at <= challenge.issued_at
        || session.refresh_expires_at <= session.expires_at
        || session.refresh_expires_at > 8_640_000_000_000_000
        || session.access_token.is_empty()
        || session.refresh_token.is_empty()
        || session.access_token.len() > 256
        || session.refresh_token.len() > 256
        || !session.access_token.bytes().all(|b| b.is_ascii_graphic())
        || !session.refresh_token.bytes().all(|b| b.is_ascii_graphic())
        || hash(session.refresh_token.as_bytes()) == request.refresh_hash
    {
        return Err(bad());
    }
    Ok(())
}
impl Envelope {
    pub fn seal(request: &Start, challenge: &Challenge, session: &Session) -> Result<Self> {
        session_scope(request, challenge, session)?;
        let request_hash = request.digest()?;
        let challenge_hash = challenge.digest()?;
        if challenge.id != request.id
            || challenge.origin != request.origin
            || challenge.account != request.account
            || challenge.revision != request.revision
            || challenge.head != request.head
            || challenge.issued_at < request.issued_at
            || challenge.issued_at >= request.expires_at
            || challenge.device != request.device
            || challenge.authorization != request.authorization
            || challenge.mode != request.mode
        {
            return Err(bad());
        }
        let ephemeral = Ephemeral(crypto::generate_keypair().map_err(|_| bad())?);
        let body = Plain(bytes(&(
            "LiteSeal/refreshed-session/v1",
            request_hash,
            challenge_hash,
            session,
        )));
        let encrypted = crypto::encrypt(
            &body.0,
            &request.device.encryption_key,
            &ephemeral.0.secret_key,
        )
        .map_err(|_| bad())?;
        if encrypted.len() > 8192 {
            return Err(bad());
        }
        Ok(Self {
            request: request_hash,
            challenge: challenge_hash,
            server_key: ephemeral.0.public_key,
            encrypted,
        })
    }
    pub fn open(&self, request: &Start, challenge: &Challenge, keys: &KeyPair) -> Result<Session> {
        key_check(keys, &request.device)?;
        if challenge.id != request.id
            || challenge.device != request.device
            || challenge.authorization != request.authorization
            || challenge.mode != request.mode
            || challenge.origin != request.origin
            || challenge.account != request.account
            || challenge.revision != request.revision
            || challenge.head != request.head
        {
            return Err(bad());
        }
        if self.request != request.digest()?
            || self.challenge != challenge.digest()?
            || self.server_key == [0; 32]
            || self.encrypted.len() > 8192
        {
            return Err(bad());
        }
        let plain = Plain(
            crypto::decrypt(&self.encrypted, &self.server_key, &keys.secret_key)
                .map_err(|_| bad())?,
        );
        let (domain, request_hash, challenge_hash, session): (String, [u8; 32], [u8; 32], Session) =
            serde_json::from_slice(&plain.0).map_err(|_| bad())?;
        if domain != "LiteSeal/refreshed-session/v1"
            || request_hash != self.request
            || challenge_hash != self.challenge
        {
            return Err(bad());
        }
        session_scope(request, challenge, &session)?;
        Ok(session)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum Reply {
    Pending {
        request: [u8; 32],
        challenge: Box<Challenge>,
    },
    Accepted {
        request: [u8; 32],
        challenge: Box<Challenge>,
        envelope: Envelope,
    },
}
impl Reply {
    pub fn verify(
        &self,
        request: &Start,
        state: &DeviceState,
        mode: &Enable,
        keys: &KeyPair,
    ) -> Result<Option<Session>> {
        let (digest, challenge) = match self {
            Self::Pending { request, challenge }
            | Self::Accepted {
                request, challenge, ..
            } => (request, challenge),
        };
        if *digest != request.digest()? {
            return Err(bad());
        }
        request.verify_challenge(challenge, state, mode, keys)?;
        match self {
            Self::Pending { .. } => Ok(None),
            Self::Accepted { envelope, .. } => envelope.open(request, challenge, keys).map(Some),
        }
    }
}
