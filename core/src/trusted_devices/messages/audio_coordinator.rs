//! Native ephemeral call state. Keys, tickets and encrypted wire never cross
//! IPC; incoming SDP is released only through a one-use authenticated handle.
use super::*;
use liteseal_shared::{crypto, direct_message::{Directory, Member}, trusted_device::DeviceState, voice_call as v};
use serde::Serialize;
use std::collections::VecDeque;

#[derive(Default)]
pub(super) struct State { call: Option<Call>, retired: VecDeque<String> }
struct Call {
    admission: v::Admission,
    stop: v::Stop,
    token: Zeroizing<String>,
    ticket: Option<String>,
    sequence: u64,
    outbound: Option<(String, v::Envelope)>,
    incoming: Option<Incoming>,
    fence: v::ReplayFence,
}
struct Incoming { handle: String, signal: Option<v::Signal>, receipt: v::Receipt, acknowledged: bool, expires_at: i64 }
#[derive(Serialize)]
pub struct AudioTarget { pub device: String, pub encryption_fingerprint: String, pub signing_fingerprint: String }
#[derive(Serialize)]
pub struct AudioView { pub id: String, pub peer: String, pub target: AudioTarget }
#[derive(Serialize, Default)]
pub struct AudioPoll { pub call: Option<AudioView>, pub handle: Option<String>, pub closed: Option<String> }
fn failed() -> CoordinatorError { CoordinatorError { message: "音频呼叫范围已变化、对方不可用或信令未确认", http_status: None } }
fn stamp() -> i64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0) }
fn opaque() -> Result<String> { crypto::random_challenge().map(hex::encode).map_err(|_| failed()) }
fn target(member: &Member) -> AudioTarget {
    use sha2::{Digest, Sha256};
    AudioTarget { device: member.device.device_id.clone(),
        encryption_fingerprint: hex::encode(Sha256::digest(member.device.encryption_key)),
        signing_fingerprint: hex::encode(Sha256::digest(member.device.signing_key)) }
}
impl Call {
    fn view(&self, owner: &Owner) -> AudioView {
        let h = &self.admission.header;
        let (peer, member) = if h.sender == owner.account { (&h.peer, &h.target) } else { (&h.sender, &h.source) };
        AudioView { id: h.id.clone(), peer: peer.clone(), target: target(member) }
    }
}
impl State {
    fn retire(&mut self) -> Option<Call> {
        let call = self.call.take()?;
        self.retired.push_back(call.admission.header.id.clone());
        while self.retired.len() > 256 { self.retired.pop_front(); }
        Some(call)
    }
}
impl MessageCoordinator {
    fn audio_with<T>(&self, lease: &TaskLease, work: impl FnOnce(&mut State) -> Result<T>) -> Result<T> {
        self.gate.with_current(lease, || {
            let mut state = self.audio.lock().map_err(|_| "audio state unavailable".to_string())?;
            work(&mut state).map_err(|_| "audio call unavailable".to_string())
        }).map_err(|_| failed())
    }
    fn audio_directories(&self, lease: &TaskLease, peer: &str, keys: &KeyPair) -> Result<(DeviceState, DeviceState)> {
        self.with(lease, |store| {
            let own = store.root(&self.owner.account, keys)?;
            let other = store.root(peer, keys)?;
            Ok((store.trust().load(&own, None)?, store.trust().load(&other, None)?))
        })
    }
    pub(super) fn clear_audio(&self) {
        let call = self.audio.lock().ok().and_then(|mut state| state.retire());
        self.dispatch_audio_stop(call);
    }
    fn dispatch_audio_stop(&self, call: Option<Call>) {
        if let Some(call) = call {
            // Presigned while unlocked. This bounded best-effort cancellation
            // cannot read new keys, revive a context or return plaintext to UI.
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                let api = self.api.clone();
                runtime.spawn(async move { let _ = api.audio_stop(&call.token, &call.stop).await; });
            }
        }
    }
    pub async fn audio_targets(&self, peer: &str, keys: &KeyPair) -> Result<Vec<AudioTarget>> {
        let _network = self.audio_network.lock().await;
        let lease = self.lease(keys)?;
        if !self.sync(&lease, None, &self.owner.account, keys).await?
            || !self.sync(&lease, None, peer, keys).await? { return Err(failed()); }
        let (_, other) = self.audio_directories(&lease, peer, keys)?;
        Ok(Directory::from_state(&other).members.iter().map(target).collect())
    }
    pub async fn begin_audio(&self, peer: &str, device: &str, keys: &KeyPair) -> Result<AudioView> {
        let _network = self.audio_network.lock().await;
        let lease = self.lease(keys)?;
        self.audio_with(&lease, |state| if state.call.is_none() { Ok(()) } else { Err(failed()) })?;
        if !self.sync(&lease, None, &self.owner.account, keys).await?
            || !self.sync(&lease, None, peer, keys).await? { return Err(failed()); }
        let (own, other) = self.audio_directories(&lease, peer, keys)?;
        let header = v::Header::new(&own, &self.owner.device.device_id, &other, device,
            v::SignalSpec { id: opaque()?, sequence: 1, sent_at: stamp(), kind: v::Kind::Offer }).map_err(|_| failed())?;
        let admission = v::Admission::make(header, keys).map_err(|_| failed())?;
        let stop = v::Stop::make(admission.clone(), admission.header.source.clone(), keys).map_err(|_| failed())?;
        let token = self.token(&lease)?;
        self.audio_with(&lease, |state| {
            if state.call.is_some() { return Err(failed()); }
            state.call = Some(Call { admission: admission.clone(), stop, token: token.clone(),
                ticket: None, sequence: 0, outbound: None, incoming: None, fence: Default::default() });
            Ok(())
        })?;
        let reservation = match self.api.audio_reserve(&token, &admission).await {
            Ok(reservation) => reservation,
            Err(error) => { self.clear_audio(); return Err(remote(error)); }
        };
        self.audio_with(&lease, |state| {
            let call = state.call.as_mut().filter(|c| c.admission.header.id == reservation.id).ok_or_else(failed)?;
            call.ticket = Some(reservation.ticket);
            Ok(call.view(&self.owner))
        })
    }
    pub fn prepare_audio_signal(&self, id: &str, kind: v::Kind, sdp: Option<String>, keys: &KeyPair) -> Result<String> {
        let lease = self.lease(keys)?;
        let peer = self.audio_with(&lease, |state| {
            Ok(state.call.as_ref().filter(|c| c.admission.header.id == id).ok_or_else(failed)?.view(&self.owner).peer)
        })?;
        let (own, other) = self.audio_directories(&lease, &peer, keys)?;
        self.audio_with(&lease, |state| {
            let call = state.call.as_mut().filter(|c| c.admission.header.id == id).ok_or_else(failed)?;
            let (sender, receiver) = if call.admission.header.sender == self.owner.account { (&own, &other) } else { (&other, &own) };
            call.admission.verify(sender, receiver).map_err(|_| failed())?;
            if call.outbound.is_some() || call.ticket.is_none() { return Err(failed()); }
            let header = v::Header::new(&own, &self.owner.device.device_id, &other,
                &call.view(&self.owner).target.device, v::SignalSpec { id: id.into(), sequence: call.sequence + 1,
                    sent_at: stamp(), kind }).map_err(|_| failed())?;
            let envelope = v::Envelope::seal(header, &own, &other, keys, sdp).map_err(|_| failed())?;
            let handle = opaque()?;
            call.outbound = Some((handle.clone(), envelope));
            Ok(handle)
        })
    }
    pub async fn publish_audio_signal(&self, handle: &str, keys: &KeyPair) -> Result<()> {
        let _network = self.audio_network.lock().await;
        let lease = self.lease(keys)?;
        let input = self.audio_with(&lease, |state| {
            let call = state.call.as_ref().ok_or_else(failed)?;
            let (_, envelope) = call.outbound.as_ref().filter(|(h, _)| h == handle).ok_or_else(failed)?;
            Ok(v::Submission { ticket: call.ticket.clone().ok_or_else(failed)?, envelope: envelope.clone() })
        })?;
        self.api.audio_signal(&self.token(&lease)?, &input).await.map_err(remote)?;
        self.audio_with(&lease, |state| {
            let call = state.call.as_mut().filter(|c| c.admission.header.id == input.envelope.header.id).ok_or_else(failed)?;
            if call.outbound.as_ref().is_none_or(|(h, _)| h != handle) { return Err(failed()); }
            call.sequence = input.envelope.header.sequence;
            call.outbound = None;
            Ok(())
        })
    }
    pub fn open_audio_signal(&self, handle: &str, keys: &KeyPair) -> Result<v::Signal> {
        let lease = self.lease(keys)?;
        let peer = self.audio_with(&lease, |state| Ok(state.call.as_ref().ok_or_else(failed)?.view(&self.owner).peer))?;
        let (own, other) = self.audio_directories(&lease, &peer, keys)?;
        self.audio_with(&lease, |state| {
            let call = state.call.as_mut().ok_or_else(failed)?;
            let (sender, receiver) = if call.admission.header.sender == self.owner.account { (&own, &other) } else { (&other, &own) };
            call.admission.verify(sender, receiver).map_err(|_| failed())?;
            let incoming = call.incoming.as_mut()
                .filter(|incoming| incoming.handle == handle && incoming.acknowledged && stamp() < incoming.expires_at).ok_or_else(failed)?;
            incoming.signal.take().ok_or_else(failed)
        })
    }
    pub fn retire_audio(&self, id: &str, keys: &KeyPair) -> Result<()> {
        let lease = self.lease(keys)?;
        let call = self.audio_with(&lease, |state| {
            if state.call.as_ref().is_some_and(|call| call.admission.header.id != id) { return Err(failed()); }
            Ok(state.retire())
        })?;
        // Clear and presign never await; microphone release can happen at once.
        self.dispatch_audio_stop(call);
        Ok(())
    }
    pub async fn poll_audio(&self, keys: &KeyPair) -> Result<AudioPoll> {
        let _network = self.audio_network.lock().await;
        let lease = self.lease(keys)?;
        let active = self.audio_with(&lease, |state| Ok(state.call.as_ref().map(|c| c.admission.header.id.clone())))?;
        let token = self.token(&lease)?;
        let page = self.api.audio_pending(&token, &self.owner.device.device_id, active.as_deref()).await.map_err(remote)?;
        self.audio_with(&lease, |_| Ok(()))?;
        if let Some(closed) = page.closed {
            self.retire_audio(&closed, keys)?;
            return Ok(AudioPoll { closed: Some(closed), ..Default::default() });
        }
        if let Some(delivery) = page.delivery {
            let admission = &delivery.admission;
            let h = &delivery.envelope.header;
            let peer = if admission.header.sender == self.owner.account { &admission.header.peer } else { &admission.header.sender };
            if !self.sync(&lease, None, &self.owner.account, keys).await?
                || !self.sync(&lease, None, peer, keys).await? { return Err(failed()); }
            let (own, other) = self.audio_directories(&lease, peer, keys)?;
            let (sender, receiver) = if admission.header.sender == self.owner.account { (&own, &other) } else { (&other, &own) };
            admission.verify(sender, receiver).map_err(|_| failed())?;
            let own_member = if admission.header.sender == self.owner.account { &admission.header.source } else { &admission.header.target };
            let peer_member = if admission.header.sender == self.owner.account { &admission.header.target } else { &admission.header.source };
            if own_member.device != self.owner.device || &h.target != own_member || &h.source != peer_member || h.id != admission.header.id {
                return Err(failed());
            }
            let signal = delivery.envelope.open(&other, &own, keys, stamp()).map_err(|_| failed())?;
            let digest = delivery.envelope.digest().map_err(|_| failed())?;
            let acknowledgement = self.audio_with(&lease, |state| {
                if state.retired.contains(&h.id) { return Err(failed()); }
                if state.call.is_none() {
                    if h.kind != v::Kind::Offer || h.sequence != 1 || admission.header.sender == self.owner.account { return Err(failed()); }
                    admission.fresh(stamp()).map_err(|_| failed())?;
                    let stop = v::Stop::make(admission.clone(), own_member.clone(), keys).map_err(|_| failed())?;
                    state.call = Some(Call { admission: admission.clone(), stop, token: token.clone(),
                        ticket: Some(delivery.ticket.clone()), sequence: 0, outbound: None, incoming: None, fence: Default::default() });
                }
                let call = state.call.as_mut().filter(|c| c.admission.header.id == h.id).ok_or_else(failed)?;
                if call.admission.digest().map_err(|_| failed())? != admission.digest().map_err(|_| failed())?
                    || call.ticket.as_deref() != Some(&delivery.ticket) { return Err(failed()); }
                if call.incoming.as_ref().is_some_and(|i| i.signal.is_some() && i.receipt.digest != digest) { return Err(failed()); }
                if call.fence.admit(&delivery.envelope).map_err(|_| failed())? {
                    call.incoming = Some(Incoming { handle: opaque()?, signal: Some(signal),
                        receipt: v::Receipt { id: h.id.clone(), sequence: h.sequence, digest }, acknowledged: false, expires_at: h.expires_at });
                }
                Ok(v::Acknowledge { device: self.owner.device.device_id.clone(), ticket: delivery.ticket,
                    receipt: v::Receipt { id: h.id.clone(), sequence: h.sequence, digest } })
            })?;
            self.api.audio_ack(&token, &acknowledgement).await.map_err(remote)?;
            self.audio_with(&lease, |state| {
                let incoming = state.call.as_mut().filter(|c| c.admission.header.id == h.id)
                    .and_then(|c| c.incoming.as_mut()).filter(|i| i.receipt.digest == digest).ok_or_else(failed)?;
                incoming.acknowledged = true;
                Ok(())
            })?;
        }
        self.audio_with(&lease, |state| Ok(AudioPoll {
            call: state.call.as_ref().map(|call| call.view(&self.owner)),
            handle: state.call.as_ref().and_then(|call| call.incoming.as_ref())
                .filter(|i| i.acknowledged && i.signal.is_some()).map(|i| i.handle.clone()), closed: None,
        }))
    }
}
