use super::*;
use crate::trusted_devices::messages::history_transfer::{HistoryRecord, PrepareHistory, View};
use crate::trusted_devices::messages::{api::HistoryAction, history_transfer::State};
use liteseal_shared::{
    direct_message::{Directory, Member},
    history_transfer::Envelope,
};
#[derive(serde::Serialize)]
pub struct RelayReceiveProgress {
    pub id: Option<String>,
    pub downloaded: usize,
    pub total: usize,
    pub imported: bool,
}
impl MessageCoordinator {
    pub fn history_relay_jobs(
        &self,
        keys: &KeyPair,
    ) -> Result<Vec<super::super::history_jobs::View>> {
        let lease = self.lease(keys)?;
        self.with(&lease, |s| {
            Ok(s.history_relay_jobs(keys)?
                .iter()
                .map(|j| j.view())
                .collect())
        })
    }
    pub fn history_receives(
        &self,
        keys: &KeyPair,
    ) -> Result<Vec<super::super::history_receive::ReceiveView>> {
        let lease = self.lease(keys)?;
        self.with(&lease, |s| s.history_receives(keys))
    }
    pub fn pause_history_relay(
        &self,
        id: &str,
        revision: u64,
        paused: bool,
        keys: &KeyPair,
    ) -> Result<super::super::history_jobs::View> {
        let lease = self.lease(keys)?;
        self.with(&lease, |s| {
            s.set_history_relay_pause(id, revision, paused, keys)
        })
    }
    pub fn pause_history_receive(
        &self,
        id: &str,
        revision: u64,
        paused: bool,
        abandon: bool,
        keys: &KeyPair,
    ) -> Result<()> {
        let lease = self.lease(keys)?;
        self.with(&lease, |s| {
            s.set_history_receive_pause(id, revision, paused, abandon, keys)
        })
    }
    /// Persist the user's original send/cancel intent before the first request.
    pub async fn history_relay_step(
        &self,
        id: &str,
        revision: u64,
        keys: &KeyPair,
    ) -> Result<liteseal_shared::history_transfer::RelayStatus> {
        let lease = self.lease(keys)?;
        let job = self.with(&lease, |s| s.start_history_relay(id, revision, false, keys))?;
        if !job.active() {
            return Ok(liteseal_shared::history_transfer::RelayStatus {
                id: job.id,
                digest: job
                    .offer
                    .digest()
                    .map_err(|_| local("history digest".into()))?,
                state: job.state,
                next: job.next,
            });
        }
        self.history_relay_job_step(&job.id, job.revision, keys)
            .await
    }
    pub async fn cancel_history_relay(
        &self,
        id: &str,
        revision: u64,
        keys: &KeyPair,
    ) -> Result<liteseal_shared::history_transfer::RelayStatus> {
        let lease = self.lease(keys)?;
        let job = self.with(&lease, |s| s.start_history_relay(id, revision, true, keys))?;
        if !job.active() {
            return Ok(liteseal_shared::history_transfer::RelayStatus {
                id: job.id,
                digest: job
                    .offer
                    .digest()
                    .map_err(|_| local("history digest".into()))?,
                state: job.state,
                next: job.next,
            });
        }
        self.history_relay_job_step(&job.id, job.revision, keys)
            .await
    }
    pub(super) async fn history_relay_job_step(
        &self,
        id: &str,
        revision: u64,
        keys: &KeyPair,
    ) -> Result<liteseal_shared::history_transfer::RelayStatus> {
        use liteseal_shared::history_transfer::RelayState;
        let lease = self.lease(keys)?;
        let _network = self.history_network.lock().await;
        let job = self.with(&lease, |s| s.check_history_relay_job(id, revision, keys))?;
        if !self.sync(&lease, None, &self.owner.account, keys).await? {
            return Err(local("directory incomplete".into()));
        }
        self.with(&lease, |s| {
            s.check_history_relay_job(id, revision, keys).map(|_| ())
        })?;
        let offer = job.offer;
        let token = self.token(&lease)?;
        let mut view = match self.api.history_status(&token, &offer).await {
            Ok(view) => view,
            Err(e) if e.status == Some(404) => {
                self.with(&lease, |s| {
                    s.check_history_relay_job(id, revision, keys).map(|_| ())
                })?;
                self.api
                    .register_history(&token, &offer)
                    .await
                    .map_err(remote)?
            }
            Err(e) => return Err(remote(e)),
        };
        self.with(&lease, |s| {
            s.check_history_relay_job(id, revision, keys).map(|_| ())
        })?;
        if job.cancel_requested
            && matches!(
                view.state,
                RelayState::Staging | RelayState::Ready | RelayState::Permitted
            )
        {
            view = self
                .api
                .history_action(&token, &offer, HistoryAction::Cancel)
                .await
                .map_err(remote)?;
        } else if view.state == RelayState::Staging {
            if view.next
                < offer
                    .size
                    .div_ceil(liteseal_shared::history_transfer::CHUNK)
            {
                let envelope = self.with(&lease, |s| {
                    s.history_relay_original(id, job.source_revision, keys)
                })?;
                view = self
                    .api
                    .upload_history_chunk(
                        &token,
                        &offer,
                        view.next,
                        envelope
                            .ciphertext_chunk(view.next)
                            .map_err(|_| local("history chunk".into()))?
                            .to_vec(),
                    )
                    .await
                    .map_err(remote)?;
            } else {
                view = self
                    .api
                    .history_action(&token, &offer, HistoryAction::Publish)
                    .await
                    .map_err(remote)?;
            }
        }
        self.with(&lease, |s| {
            s.confirm_history_relay_job(id, revision, &view, keys)
                .map(|_| ())
        })?;
        Ok(view)
    }
    /// One authenticated chunk per explicit call; partial ciphertext is durable
    /// but never counted as confirmed history or included in portable backup.
    pub async fn receive_history_relay(&self, keys: &KeyPair) -> Result<RelayReceiveProgress> {
        self.receive_history_relay_id(None, keys).await
    }
    pub(super) async fn receive_history_relay_id(
        &self,
        requested: Option<&str>,
        keys: &KeyPair,
    ) -> Result<RelayReceiveProgress> {
        let lease = self.lease(keys)?;
        self.with(&lease, |s| {
            s.cleanup_history_receive(chrono::Utc::now().timestamp_millis(), keys)
        })?;
        let _network = self.history_network.lock().await;
        if !self.sync(&lease, None, &self.owner.account, keys).await? {
            return Err(local("directory incomplete".into()));
        }
        let token = self.token(&lease)?;
        let offers = self
            .api
            .pending_history(&token, &self.owner.account, &self.owner.device.device_id)
            .await
            .map_err(remote)?;
        let saved = self.with(&lease, |s| s.history_transfers(keys))?;
        let receiving = self.with(&lease, |s| s.history_receives(keys))?;
        let Some(offer) = offers.into_iter().find(|offer| {
            requested.is_none_or(|id| id == offer.header.id)
                && !receiving
                    .iter()
                    .any(|r| r.id == offer.header.id && r.paused)
        }) else {
            return Ok(RelayReceiveProgress {
                id: None,
                downloaded: 0,
                total: 0,
                imported: false,
            });
        };
        if let Some(received) = saved
            .iter()
            .find(|r| r.id == offer.header.id && r.state == State::Imported)
        {
            if received.digest != offer.digest().map_err(|_| local("history digest".into()))? {
                return Err(local("history conflict".into()));
            }
            let receipt = liteseal_shared::history_transfer::Received::make(
                &offer,
                chrono::Utc::now().timestamp_millis(),
                keys,
            )
            .map_err(|_| local("history receipt".into()))?;
            self.api
                .history_received(&token, &offer, &receipt)
                .await
                .map_err(remote)?;
            self.with(&lease, |s| {
                if let Some(intent) = receiving.iter().find(|r| r.id == offer.header.id) {
                    s.check_history_receive(&offer.header.id, intent.revision, keys)?;
                }
                s.clear_history_receive(&offer.header.id, keys)
            })?;
            return Ok(RelayReceiveProgress {
                id: Some(offer.header.id),
                downloaded: offer
                    .size
                    .div_ceil(liteseal_shared::history_transfer::CHUNK),
                total: offer
                    .size
                    .div_ceil(liteseal_shared::history_transfer::CHUNK),
                imported: true,
            });
        }
        if !self.sync(&lease, None, &offer.header.peer, keys).await? {
            return Err(local("directory incomplete".into()));
        }
        let total = offer
            .size
            .div_ceil(liteseal_shared::history_transfer::CHUNK);
        let next = self.with(&lease, |s| s.history_receive_next(&offer, keys))?;
        let receive_revision = self
            .with(&lease, |s| s.history_receives(keys))?
            .into_iter()
            .find(|r| r.id == offer.header.id)
            .ok_or_else(|| local("history receive intent".into()))?
            .revision;
        if next < total {
            let bytes = self
                .api
                .download_history_chunk(&token, &offer, next)
                .await
                .map_err(remote)?;
            self.with(&lease, |s| {
                s.check_history_receive(&offer.header.id, receive_revision, keys)?;
                s.history_receive_chunk(&offer, next, &bytes, keys)
            })?;
            return Ok(RelayReceiveProgress {
                id: Some(offer.header.id),
                downloaded: next + 1,
                total,
                imported: false,
            });
        }
        // Check every signed body/cache before requesting the atomic permit.
        let envelope = self.with(&lease, |s| s.history_receive_complete(&offer, keys))?;
        self.with(&lease, |s| {
            s.validate_history_import(&envelope, chrono::Utc::now().timestamp_millis(), keys)
        })?;
        let permit = self
            .api
            .history_action(&token, &offer, HistoryAction::Permit)
            .await
            .map_err(remote)?;
        if permit.state != liteseal_shared::history_transfer::RelayState::Permitted {
            return Err(local("history permit".into()));
        }
        self.with(&lease, |s| {
            s.check_history_receive(&offer.header.id, receive_revision, keys)?;
            s.finish_history_receive(&offer, chrono::Utc::now().timestamp_millis(), keys)
        })?;
        let receipt = liteseal_shared::history_transfer::Received::make(
            &offer,
            chrono::Utc::now().timestamp_millis(),
            keys,
        )
        .map_err(|_| local("history receipt".into()))?;
        self.api
            .history_received(&token, &offer, &receipt)
            .await
            .map_err(remote)?;
        self.with(&lease, |s| {
            s.check_history_receive(&offer.header.id, receive_revision, keys)?;
            s.clear_history_receive(&offer.header.id, keys)
        })?;
        Ok(RelayReceiveProgress {
            id: Some(offer.header.id),
            downloaded: total,
            total,
            imported: true,
        })
    }
    pub fn history_targets(&self, keys: &KeyPair) -> Result<Vec<Member>> {
        let lease = self.lease(keys)?;
        self.with(&lease, |store| {
            let owner = store.owner.clone();
            store.trust.read_checked(|conn| {
                let state =
                    crate::trusted_devices::messages::current(conn, &owner.origin, &owner.account)?;
                if state.anchor().root != owner.device {
                    return Ok(Vec::new());
                }
                Ok(Directory::from_state(&state)
                    .members
                    .into_iter()
                    .filter(|m| m.device != owner.device)
                    .collect())
            })
        })
    }
    pub fn history_transfers(&self, keys: &KeyPair) -> Result<Vec<View>> {
        let lease = self.lease(keys)?;
        self.with(&lease, |store| store.history_transfers(keys))
    }
    pub async fn prepare_history_transfer(
        &self,
        request: PrepareHistory<'_>,
        keys: &KeyPair,
    ) -> Result<View> {
        let lease = self.lease(keys)?;
        let _network = self.network.lock().await;
        let now = chrono::Utc::now().timestamp_millis();
        if request.created_at > now + 60000
            || request
                .created_at
                .checked_add(liteseal_shared::history_transfer::LIFETIME)
                .is_none_or(|end| end <= now)
        {
            return Err(local("expired history intent".into()));
        }
        if !self.sync(&lease, None, &self.owner.account, keys).await? {
            return Err(local("directory incomplete".into()));
        }
        if !self.sync(&lease, None, request.peer, keys).await? {
            return Err(local("directory incomplete".into()));
        }
        self.with(&lease, |store| store.prepare_history(request, keys))
    }
    pub async fn history_export_wire(
        &self,
        id: &str,
        revision: u64,
        keys: &KeyPair,
    ) -> Result<Vec<u8>> {
        let lease = self.lease(keys)?;
        let _network = self.network.lock().await;
        if !self.sync(&lease, None, &self.owner.account, keys).await? {
            return Err(local("directory incomplete".into()));
        }
        self.with(&lease, |store| {
            store.history_transfer_wire(id, revision, chrono::Utc::now().timestamp_millis(), keys)
        })
    }
    pub async fn import_history_transfer(&self, bytes: &[u8], keys: &KeyPair) -> Result<View> {
        let envelope = Envelope::from_wire(bytes).map_err(|_| local("history wire".into()))?;
        if envelope.header.origin != self.owner.origin
            || envelope.header.account != self.owner.account
            || envelope.header.target.device != self.owner.device
        {
            return Err(local("history scope".into()));
        }
        let lease = self.lease(keys)?;
        let _network = self.network.lock().await;
        if !self.sync(&lease, None, &self.owner.account, keys).await? {
            return Err(local("directory incomplete".into()));
        }
        if !self.sync(&lease, None, &envelope.header.peer, keys).await? {
            return Err(local("directory incomplete".into()));
        }
        self.with(&lease, |store| {
            store.import_history(bytes, chrono::Utc::now().timestamp_millis(), keys)
        })
    }
    pub fn cancel_history_transfer(&self, id: &str, revision: u64, keys: &KeyPair) -> Result<View> {
        let lease = self.lease(keys)?;
        self.with(&lease, |store| {
            store.cancel_history_transfer(id, revision, keys)
        })
    }
    pub fn transferred_history(
        &self,
        peer: Option<&str>,
        keys: &KeyPair,
    ) -> Result<Vec<HistoryRecord>> {
        let lease = self.lease(keys)?;
        self.with(&lease, |store| store.transferred_history(peer, keys))
    }
    pub fn transferred_media(&self, id: &str, keys: &KeyPair) -> Result<Zeroizing<Vec<u8>>> {
        let lease = self.lease(keys)?;
        self.with(&lease, |store| store.transferred_media(id, keys))
    }
    pub fn hide_transferred(&self, id: &str, keys: &KeyPair) -> Result<()> {
        let lease = self.lease(keys)?;
        self.with(&lease, |store| store.hide_transferred(id, keys))
    }
}
