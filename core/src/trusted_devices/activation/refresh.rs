//! Typed origin-bound refresh transport. A coordinator must persist the
//! original request/challenge/proof before invoking each network step.
use super::*;
use liteseal_shared::{crypto::KeyPair, device_activation::refresh as r};
pub struct Observation {
    pub(crate) request: r::Start,
    pub(crate) reply: r::Reply,
    session: Option<Session>,
}
impl Observation {
    pub fn reply(&self) -> &r::Reply {
        &self.reply
    }
    pub fn request(&self) -> &r::Start {
        &self.request
    }
    pub fn into_session(self) -> Result<Session, ActivationError> {
        self.session.ok_or_else(invalid)
    }
}
impl ActivationApi {
    fn refresh_scope(
        &self,
        request: &r::Start,
        session: &Session,
        state: &DeviceState,
        mode: &Enable,
        keys: &KeyPair,
    ) -> Result<(), ActivationError> {
        self.root(state.anchor())?;
        request.bind_original(session).map_err(|_| invalid())?;
        request
            .verify_state(state, mode, request.issued_at)
            .map_err(|_| invalid())?;
        request.verify_keys(keys).map_err(|_| invalid())?;
        Ok(())
    }
    fn refresh_observation(
        &self,
        request: &r::Start,
        reply: r::Reply,
        state: &DeviceState,
        mode: &Enable,
        keys: &KeyPair,
    ) -> Result<Observation, ActivationError> {
        let session = reply
            .verify(request, state, mode, keys)
            .map_err(|_| invalid())?;
        if session
            .as_ref()
            .is_some_and(|s| s.refresh_expires_at <= chrono::Utc::now().timestamp_millis())
        {
            return Err(invalid());
        }
        Ok(Observation {
            request: request.clone(),
            reply,
            session,
        })
    }
    pub async fn begin_refresh(
        &self,
        request: &r::Start,
        session: &Session,
        state: &DeviceState,
        mode: &Enable,
        keys: &KeyPair,
    ) -> Result<Observation, ActivationError> {
        self.refresh_scope(request, session, state, mode, keys)?;
        let http = self.body(
            self.request(
                Method::POST,
                "/auth/v3/refresh/begin",
                Some(&session.refresh_token),
            )?,
            request,
        )?;
        let reply = self.send(http).await?;
        self.refresh_observation(request, reply, state, mode, keys)
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn prove_refresh(
        &self,
        request: &r::Start,
        proof: &Proof,
        challenge: &Challenge,
        session: &Session,
        state: &DeviceState,
        mode: &Enable,
        keys: &KeyPair,
    ) -> Result<Observation, ActivationError> {
        self.refresh_scope(request, session, state, mode, keys)?;
        request
            .verify_challenge(challenge, state, mode, keys)
            .map_err(|_| invalid())?;
        proof.verify(challenge).map_err(|_| invalid())?;
        let http = self.body(
            self.request(
                Method::POST,
                &format!("/auth/v3/refresh/{}/proof", request.id),
                Some(&session.refresh_token),
            )?,
            proof,
        )?;
        let reply: r::Reply = self.send(http).await?;
        match &reply {
            r::Reply::Accepted {
                challenge: returned,
                ..
            } if **returned == *challenge => {}
            _ => return Err(invalid()),
        }
        self.refresh_observation(request, reply, state, mode, keys)
    }
}
