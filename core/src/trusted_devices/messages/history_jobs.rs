//! Persisted explicit transfer intent. It carries no new history authorization.
use super::*;
use liteseal_shared::history_transfer::{Offer, RelayState, RelayStatus};
const KIND: &str = "history_relay_job";
fn scope(owner: &Owner) -> String {
    format!("history-relay:{}", owner.scope())
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Job {
    pub id: String,
    pub revision: u64,
    pub source_revision: u64,
    pub paused: bool,
    pub cancel_requested: bool,
    pub state: RelayState,
    pub next: usize,
    pub(super) offer: Offer,
    domain: String,
    scope: String,
}
#[derive(Serialize)]
pub struct View {
    pub id: String,
    pub revision: u64,
    pub source_revision: u64,
    pub paused: bool,
    pub cancel_requested: bool,
    pub state: RelayState,
    pub next: usize,
    pub total: usize,
}
impl Job {
    pub fn active(&self) -> bool {
        matches!(
            self.state,
            RelayState::Staging | RelayState::Ready | RelayState::Permitted
        )
    }
    pub fn view(&self) -> View {
        View {
            id: self.id.clone(),
            revision: self.revision,
            source_revision: self.source_revision,
            paused: self.paused,
            cancel_requested: self.cancel_requested,
            state: self.state,
            next: self.next,
            total: self
                .offer
                .size
                .div_ceil(liteseal_shared::history_transfer::CHUNK),
        }
    }
}
pub(super) fn load(
    conn: &Connection,
    owner: &Owner,
    id: &str,
    keys: &KeyPair,
) -> Result<Option<Job>, String> {
    let row: Option<(u64, Vec<u8>)> = conn
        .query_row(
            "SELECT revision,body FROM device_control_tasks WHERE scope=?1 AND id=?2 AND kind=?3",
            params![scope(owner), id, KIND],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(db)?;
    let Some((revision, bytes)) = row else {
        return Ok(None);
    };
    if bytes.len() > 65576 {
        return Err(invalid());
    }
    let plain = Zeroizing::new(
        crypto::decrypt(&bytes, &keys.public_key, &keys.secret_key).map_err(|_| invalid())?,
    );
    let job: Job = serde_json::from_slice(&plain).map_err(|_| invalid())?;
    if job.domain != "LiteSeal/history-relay-job/v1"
        || job.scope != owner.scope()
        || job.id != id
        || job.offer.header.id != id
        || job.revision != revision
        || revision == 0
        || job.source_revision == 0
        || job.offer.header.origin != owner.origin
        || job.offer.header.account != owner.account
        || job.offer.header.source != owner.device
        || job.next
            > job
                .offer
                .size
                .div_ceil(liteseal_shared::history_transfer::CHUNK)
    {
        return Err(invalid());
    }
    Ok(Some(job))
}
fn save(conn: &Connection, owner: &Owner, job: &Job, keys: &KeyPair) -> Result<(), String> {
    let plain = Zeroizing::new(serde_json::to_vec(job).map_err(|_| invalid())?);
    if plain.len() > 65536 {
        return Err(invalid());
    }
    let body =
        crypto::encrypt(&plain, &keys.public_key, &keys.secret_key).map_err(|_| invalid())?;
    conn.execute("INSERT INTO device_control_tasks(scope,id,revision,kind,terminal,body) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(scope,id) DO UPDATE SET revision=excluded.revision,terminal=excluded.terminal,body=excluded.body",params![scope(owner),job.id,job.revision,KIND,!job.active(),body]).map_err(db)?;
    Ok(())
}
pub(super) fn pause_local(
    conn: &Connection,
    owner: &Owner,
    id: &str,
    keys: &KeyPair,
) -> Result<(), String> {
    if let Some(mut job) = load(conn, owner, id, keys)? {
        job.revision = job.revision.checked_add(1).ok_or_else(invalid)?;
        job.paused = true;
        save(conn, owner, &job, keys)?;
    }
    Ok(())
}
impl Store {
    pub fn history_relay_jobs(&mut self, keys: &KeyPair) -> Result<Vec<Job>, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.read_checked(|conn|{
            let mut q=conn.prepare("SELECT id FROM device_control_tasks WHERE scope=?1 AND kind=?2 ORDER BY id LIMIT 1025").map_err(db)?;
            let ids=q.query_map(params![scope(&owner),KIND],|r|r.get::<_,String>(0)).map_err(db)?.collect::<rusqlite::Result<Vec<_>>>().map_err(db)?;
            if ids.len()>1024 {return Err(invalid())}
            ids.iter().map(|id|load(conn,&owner,id,keys)?.ok_or_else(invalid)).collect()
        })
    }
    pub fn start_history_relay(
        &mut self,
        id: &str,
        source_revision: u64,
        cancel: bool,
        keys: &KeyPair,
    ) -> Result<Job, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        // Store the immutable offer before contacting the relay. It survives
        // stopping local file export, so remote results/cancellation stay usable.
        let original = if self.history_relay_jobs(keys)?.iter().any(|j| j.id == id) {
            None
        } else {
            Some(
                self.history_relay_original(id, source_revision, keys)?
                    .offer(),
            )
        };
        self.trust.write_checked(|conn| {
            let existing = load(conn, &owner, id, keys)?;
            let mut job = if let Some(job) = existing {
                if job.source_revision != source_revision {
                    return Err(conflict());
                }
                job
            } else {
                let count: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM device_control_tasks WHERE scope=?1 AND kind=?2",
                        params![scope(&owner), KIND],
                        |r| r.get(0),
                    )
                    .map_err(db)?;
                if count >= 1024 {
                    return Err("历史中继编号达到本机上限".into());
                }
                Job {
                    id: id.into(),
                    revision: 1,
                    source_revision,
                    paused: false,
                    cancel_requested: false,
                    state: RelayState::Staging,
                    next: 0,
                    offer: original.clone().ok_or_else(invalid)?,
                    domain: "LiteSeal/history-relay-job/v1".into(),
                    scope: owner.scope(),
                }
            };
            if job.active() {
                if !cancel {
                    let receipt =
                        history_transfer::load(conn, &owner, id, keys)?.ok_or_else(invalid)?;
                    if receipt.state != history_transfer::State::Prepared
                        || receipt.revision != source_revision
                    {
                        return Err(conflict());
                    }
                }
                if job.paused || cancel && !job.cancel_requested {
                    job.revision = job.revision.checked_add(1).ok_or_else(invalid)?;
                }
                job.paused = false;
                job.cancel_requested |= cancel;
                save(conn, &owner, &job, keys)?;
            }
            Ok(job)
        })
    }
    pub fn set_history_relay_pause(
        &mut self,
        id: &str,
        revision: u64,
        paused: bool,
        keys: &KeyPair,
    ) -> Result<View, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.write_checked(|conn| {
            let mut job = load(conn, &owner, id, keys)?.ok_or_else(invalid)?;
            if job.revision != revision || !job.active() {
                return Err(conflict());
            }
            if !paused && !job.cancel_requested {
                let receipt =
                    history_transfer::load(conn, &owner, id, keys)?.ok_or_else(invalid)?;
                if receipt.state != history_transfer::State::Prepared
                    || receipt.revision != job.source_revision
                {
                    return Err(conflict());
                }
            }
            job.revision = job.revision.checked_add(1).ok_or_else(invalid)?;
            job.paused = paused;
            save(conn, &owner, &job, keys)?;
            Ok(job.view())
        })
    }
    pub fn check_history_relay_job(
        &mut self,
        id: &str,
        revision: u64,
        keys: &KeyPair,
    ) -> Result<Job, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.read_checked(|conn| {
            let job = load(conn, &owner, id, keys)?.ok_or_else(invalid)?;
            if job.revision != revision || job.paused || !job.active() {
                return Err(conflict());
            }
            Ok(job)
        })
    }
    pub fn confirm_history_relay_job(
        &mut self,
        id: &str,
        revision: u64,
        status: &RelayStatus,
        keys: &KeyPair,
    ) -> Result<View, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.write_checked(|conn| {
            let mut job = load(conn, &owner, id, keys)?.ok_or_else(invalid)?;
            if job.revision != revision
                || job.paused
                || !job.active()
                || status.id != job.id
                || status.digest != job.offer.digest().map_err(|_| invalid())?
                || status.next
                    > job
                        .offer
                        .size
                        .div_ceil(liteseal_shared::history_transfer::CHUNK)
            {
                return Err(conflict());
            }
            job.state = status.state;
            job.next = status.next;
            save(conn, &owner, &job, keys)?;
            Ok(job.view())
        })
    }
}
