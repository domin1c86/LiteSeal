//! Typed activation transport. Private request/proof/session values stay in
//! Rust; shell-facing activation jobs must retain originals before calling it.
use liteseal_shared::{
    device_activation::{
        self as a, ActivationCancel, ActivationCancelResult, Challenge, Enable, EnableCancel,
        EnableCancelResult, Envelope, Inspection, InspectionResult, Proof, Session, Start,
    },
    trusted_device::{canonical_origin, Anchor, DeviceState},
};
use reqwest::{Method, RequestBuilder};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
pub mod jobs;
/// Bound HTTP result, not a signed server statement or local commit receipt.
pub struct Inspected {
    pub(super) request: Inspection,
    pub(super) result: InspectionResult,
}
#[derive(Debug)]
pub struct ActivationError {
    pub status: Option<u16>,
    pub message: &'static str,
}
impl std::fmt::Display for ActivationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message)
    }
}
impl std::error::Error for ActivationError {}
fn invalid() -> ActivationError {
    ActivationError {
        status: None,
        message: "设备激活范围或响应无法验证",
    }
}
fn network() -> ActivationError {
    ActivationError {
        status: None,
        message: "设备激活结果未确认，保留原申请与证明",
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Status {
    enabled: bool,
    event: Option<Enable>,
}
pub struct ActivationApi {
    origin: String,
    client: reqwest::Client,
}
impl ActivationApi {
    pub fn new(server: &str) -> Result<Self, ActivationError> {
        Ok(Self {
            origin: canonical_origin(server).map_err(|_| invalid())?,
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(20))
                .connect_timeout(std::time::Duration::from_secs(5))
                .build()
                .map_err(|_| network())?,
        })
    }
    fn request(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
    ) -> Result<RequestBuilder, ActivationError> {
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.origin));
        if let Some(token) = token {
            if token.is_empty() || token.len() > 256 || token.bytes().any(|b| !b.is_ascii_graphic())
            {
                return Err(invalid());
            }
            request = request.bearer_auth(token);
        }
        Ok(request)
    }
    fn body(
        &self,
        request: RequestBuilder,
        value: &impl Serialize,
    ) -> Result<RequestBuilder, ActivationError> {
        let body = serde_json::to_vec(value).map_err(|_| invalid())?;
        if body.len() > a::MAX_WIRE {
            return Err(invalid());
        }
        Ok(request
            .header("content-type", "application/json")
            .body(body))
    }
    async fn send<T: DeserializeOwned>(
        &self,
        request: RequestBuilder,
    ) -> Result<T, ActivationError> {
        let mut response = request.send().await.map_err(|_| network())?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(ActivationError {
                status: Some(response.status().as_u16()),
                message: "设备激活被拒绝，请查询原申请",
            });
        }
        if response
            .content_length()
            .is_some_and(|size| size > a::MAX_WIRE as u64)
        {
            return Err(invalid());
        }
        let mut bytes = vec![];
        while let Some(chunk) = response.chunk().await.map_err(|_| network())? {
            if bytes.len().saturating_add(chunk.len()) > a::MAX_WIRE {
                return Err(invalid());
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| invalid())
    }
    fn root(&self, anchor: &Anchor) -> Result<(), ActivationError> {
        if anchor.origin != self.origin || anchor.validate().is_err() {
            return Err(invalid());
        }
        Ok(())
    }
    pub async fn status(
        &self,
        token: &str,
        anchor: &Anchor,
    ) -> Result<Option<Enable>, ActivationError> {
        self.root(anchor)?;
        let status: Status = self
            .send(self.request(
                Method::GET,
                &format!("/users/{}/device_messaging", anchor.account),
                Some(token),
            )?)
            .await?;
        if status.enabled != status.event.is_some() {
            return Err(invalid());
        }
        if let Some(event) = &status.event {
            event.verify_root(anchor).map_err(|_| invalid())?;
        }
        Ok(status.event)
    }
    pub async fn enable(
        &self,
        token: &str,
        event: &Enable,
        anchor: &Anchor,
    ) -> Result<Enable, ActivationError> {
        self.root(anchor)?;
        event.verify_root(anchor).map_err(|_| invalid())?;
        let accepted: Enable = self
            .send(self.body(
                self.request(Method::POST, "/devices/messaging/enable", Some(token))?,
                event,
            )?)
            .await?;
        if accepted != *event {
            return Err(invalid());
        }
        Ok(accepted)
    }
    pub async fn begin(
        &self,
        input: &Start,
        state: &DeviceState,
        mode: &Enable,
    ) -> Result<Challenge, ActivationError> {
        self.root(state.anchor())?;
        mode.verify_root(state.anchor()).map_err(|_| invalid())?;
        if uuid::Uuid::parse_str(&input.id)
            .ok()
            .is_none_or(|id| id.to_string() != input.id)
            || input.username.trim().is_empty()
            || input.username.len() > 128
            || input.password.len() > 1024
            || input.request_token.len() < 32
            || input.request_token.len() > 256
            || !liteseal_shared::direct_message::Directory::from_state(state)
                .members
                .iter()
                .any(|m| {
                    m.device.device_id == input.device
                        && m.authorization_hash == input.authorization
                })
        {
            return Err(invalid());
        }
        let challenge: Challenge = self
            .send(self.body(self.request(Method::POST, "/auth/v3/begin", None)?, input)?)
            .await?;
        if challenge.id != input.id
            || challenge.device.device_id != input.device
            || challenge.authorization != input.authorization
        {
            return Err(invalid());
        }
        challenge
            .verify_state(state, mode, chrono::Utc::now().timestamp_millis())
            .map_err(|_| invalid())?;
        Ok(challenge)
    }
    /// Only a matching durable fence or the original accepted event is a
    /// terminal result. HTTP failures leave cancellation unconfirmed.
    pub async fn cancel_enable(
        &self,
        token: &str,
        cancel: &EnableCancel,
        anchor: &Anchor,
    ) -> Result<EnableCancelResult, ActivationError> {
        self.root(anchor)?;
        cancel.verify(anchor).map_err(|_| invalid())?;
        let result: EnableCancelResult = self
            .send(self.body(
                self.request(Method::POST, "/devices/messaging/cancel", Some(token))?,
                cancel,
            )?)
            .await?;
        match &result {
            EnableCancelResult::Cancelled { event }
                if *event == cancel.event.digest().map_err(|_| invalid())? => {}
            EnableCancelResult::Accepted { event } if *event == cancel.event => {}
            _ => return Err(invalid()),
        }
        Ok(result)
    }
    /// This method returns ciphertext for local persistence. Session credentials
    /// can only be opened with the authorized device keys inside Rust.
    pub async fn cancel(
        &self,
        token: &str,
        cancel: &ActivationCancel,
        state: &DeviceState,
        mode: &Enable,
        keys: &liteseal_shared::crypto::KeyPair,
    ) -> Result<ActivationCancelResult, ActivationError> {
        self.root(state.anchor())?;
        cancel.verify(state, mode, token).map_err(|_| invalid())?;
        if keys.public_key != cancel.device.encryption_key
            || keys.ed25519_pk != cancel.device.signing_key
        {
            return Err(invalid());
        }
        liteseal_shared::backup_crypto::validate_identity(
            &keys.public_key,
            &keys.secret_key,
            &keys.ed25519_pk,
            &keys.ed25519_sk,
        )
        .map_err(|_| invalid())?;
        let result: ActivationCancelResult = self
            .send(self.body(
                self.request(Method::POST, "/auth/v3/cancel", Some(token))?,
                cancel,
            )?)
            .await?;
        match &result {
            ActivationCancelResult::Cancelled { cancellation }
                if *cancellation == cancel.digest().map_err(|_| invalid())? => {}
            ActivationCancelResult::Accepted {
                challenge,
                envelope,
            } => {
                if challenge.id != cancel.id
                    || challenge.device != cancel.device
                    || challenge.authorization != cancel.authorization
                    || challenge.mode != cancel.mode
                {
                    return Err(invalid());
                }
                // Acceptance can be retried after the challenge expired.
                challenge
                    .verify_state(state, mode, challenge.issued_at)
                    .map_err(|_| invalid())?;
                envelope.open(challenge, keys).map_err(|_| invalid())?;
            }
            _ => return Err(invalid()),
        }
        Ok(result)
    }
    pub async fn challenge(
        &self,
        token: &str,
        id: &str,
        state: &DeviceState,
        mode: &Enable,
    ) -> Result<Challenge, ActivationError> {
        self.root(state.anchor())?;
        if uuid::Uuid::parse_str(id)
            .ok()
            .is_none_or(|id_| id_.to_string() != id)
        {
            return Err(invalid());
        }
        let challenge: Challenge = self
            .send(self.request(Method::GET, &format!("/auth/v3/{id}"), Some(token))?)
            .await?;
        if challenge.id != id {
            return Err(invalid());
        }
        challenge
            .verify_state(state, mode, chrono::Utc::now().timestamp_millis())
            .map_err(|_| invalid())?;
        Ok(challenge)
    }
    pub async fn prove(
        &self,
        token: &str,
        challenge: &Challenge,
        proof: &Proof,
        keys: &liteseal_shared::crypto::KeyPair,
    ) -> Result<Session, ActivationError> {
        self.prove_envelope(token, challenge, proof, keys)
            .await?
            .open(challenge, keys)
            .map_err(|_| invalid())
    }
    pub async fn inspect(
        &self,
        token: &str,
        request: &Inspection,
        state: &DeviceState,
        mode: &Enable,
        keys: &liteseal_shared::crypto::KeyPair,
    ) -> Result<Inspected, ActivationError> {
        self.root(state.anchor())?;
        request.verify(state, mode, token).map_err(|_| invalid())?;
        if request.intent.device.encryption_key != keys.public_key
            || request.intent.device.signing_key != keys.ed25519_pk
        {
            return Err(invalid());
        }
        liteseal_shared::backup_crypto::validate_identity(
            &keys.public_key,
            &keys.secret_key,
            &keys.ed25519_pk,
            &keys.ed25519_sk,
        )
        .map_err(|_| invalid())?;
        let result: InspectionResult = self
            .send(self.body(
                self.request(Method::POST, "/auth/v3/inspect", Some(token))?,
                request,
            )?)
            .await?;
        match &result {
            InspectionResult::Unknown { request: digest }
                if *digest == request.digest().map_err(|_| invalid())? => {}
            InspectionResult::Closed { closure } => {
                closure.verify(request).map_err(|_| invalid())?
            }
            InspectionResult::Pending {
                request: digest,
                challenge,
            }
            | InspectionResult::Accepted {
                request: digest,
                challenge,
                ..
            } => {
                let i = &request.intent;
                if *digest != request.digest().map_err(|_| invalid())?
                    || challenge.id != i.id
                    || challenge.origin != i.origin
                    || challenge.account != i.account
                    || challenge.device != i.device
                    || challenge.authorization != i.authorization
                    || challenge.mode != i.mode
                {
                    return Err(invalid());
                }
                challenge.authenticate_device(keys).map_err(|_| invalid())?;
                if let InspectionResult::Accepted { envelope, .. } = &result {
                    envelope.open(challenge, keys).map_err(|_| invalid())?;
                }
            }
            _ => return Err(invalid()),
        }
        Ok(Inspected {
            request: request.clone(),
            result,
        })
    }
    pub async fn prove_envelope(
        &self,
        token: &str,
        challenge: &Challenge,
        proof: &Proof,
        keys: &liteseal_shared::crypto::KeyPair,
    ) -> Result<Envelope, ActivationError> {
        if challenge.origin != self.origin {
            return Err(invalid());
        }
        if keys.public_key != challenge.device.encryption_key
            || keys.ed25519_pk != challenge.device.signing_key
        {
            return Err(invalid());
        }
        liteseal_shared::backup_crypto::validate_identity(
            &keys.public_key,
            &keys.secret_key,
            &keys.ed25519_pk,
            &keys.ed25519_sk,
        )
        .map_err(|_| invalid())?;
        proof.verify(challenge).map_err(|_| invalid())?;
        let envelope: Envelope = self
            .send(self.body(
                self.request(
                    Method::POST,
                    &format!("/auth/v3/{}/proof", challenge.id),
                    Some(token),
                )?,
                proof,
            )?)
            .await?;
        envelope.open(challenge, keys).map_err(|_| invalid())?;
        Ok(envelope)
    }
}
