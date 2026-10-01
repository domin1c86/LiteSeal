//! Verified T23 directory persistence. Only public authorization evidence is stored.
//! The caller supplies the independently pinned root and an optional trusted high-water mark.
use liteseal_shared::trusted_device::{
    Anchor, DeviceEvent, DeviceManifestPage, DeviceState, MAX_DEVICE_EVENTS,
    MAX_DEVICE_EVENT_BYTES, MAX_DEVICE_PAGE_BYTES,
};
use rusqlite::{params, Connection, TransactionBehavior};
use std::{path::Path, time::Duration};

pub mod api;
pub mod coordinator;
pub mod tasks;
const MAX_EVENT_BYTES: usize = MAX_DEVICE_EVENT_BYTES;
const MAX_BATCH: usize = 100;
const MAX_BATCH_BYTES: usize = MAX_DEVICE_PAGE_BYTES;
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS trusted_device_anchors (
 origin TEXT NOT NULL, account TEXT NOT NULL, anchor BLOB NOT NULL,
 revision INTEGER NOT NULL CHECK(revision>=0), head BLOB NOT NULL,
 PRIMARY KEY(origin,account)
);
CREATE TABLE IF NOT EXISTS trusted_device_events (
 origin TEXT NOT NULL, account TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>0),
 event_id TEXT NOT NULL, payload BLOB NOT NULL CHECK(length(payload)<=16384),
 PRIMARY KEY(origin,account,revision), UNIQUE(origin,account,event_id)
);";

/// Retain this outside untrusted directory responses. A whole-database rollback
/// requires a previously trusted checkpoint; a checkpoint in the same DB cannot prove freshness.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub revision: u64,
    pub hash: Vec<u8>,
}
impl Checkpoint {
    pub fn from_state(state: &DeviceState) -> Self {
        Self {
            revision: state.revision(),
            hash: state.head().to_vec(),
        }
    }
}
pub struct DeviceTrustStore {
    conn: Connection,
}
impl DeviceTrustStore {
    /// Verify the entire page, including the advertised terminal head, before
    /// advancing any persisted version. A server-supplied anchor is not a pin.
    pub fn import_page(
        &mut self,
        anchor: &Anchor,
        expected: &Checkpoint,
        page: &DeviceManifestPage,
    ) -> Result<DeviceState, String> {
        if page.anchor != *anchor
            || page.events.len() > MAX_BATCH
            || page.current_revision > MAX_DEVICE_EVENTS
            || page.current_hash.len() != 32
            || page.through_revision < expected.revision
            || page.through_revision > page.current_revision
            || page.more != (page.through_revision < page.current_revision)
            || serde_json::to_vec(page).map_err(|e| e.to_string())?.len() > MAX_DEVICE_PAGE_BYTES
        {
            return Err("invalid device manifest page".into());
        }
        let initial = self.load(anchor, Some(expected))?;
        if Checkpoint::from_state(&initial) != *expected {
            return Err("stale device manifest cursor".into());
        }
        let mut checked = initial.clone();
        for event in &page.events {
            if event.revision != checked.revision() + 1 {
                return Err("device manifest page has a gap or replay".into());
            }
            checked = checked.apply(event).map_err(|e| e.to_string())?;
        }
        if checked.revision() != page.through_revision
            || page.events.is_empty() && page.more
            || !page.more && checked.head() != page.current_hash
        {
            return Err("device manifest head or cursor does not match".into());
        }
        if page.events.is_empty() {
            Ok(initial)
        } else {
            self.import_verified(anchor, expected, &page.events)
        }
    }
    pub fn open(path: &Path) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(|e| e.to_string())?;
        conn.execute_batch(SCHEMA).map_err(|e| e.to_string())?;
        Ok(Self { conn })
    }
    /// A different root is never silently installed over an existing account.
    pub fn pin(&mut self, anchor: &Anchor) -> Result<DeviceState, String> {
        let initial = DeviceState::pin(anchor.clone()).map_err(|e| e.to_string())?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT OR IGNORE INTO trusted_device_anchors(origin,account,anchor,revision,head)
            VALUES(?1,?2,?3,0,?4)",
            params![
                anchor.origin,
                anchor.account,
                serde_json::to_vec(anchor).map_err(|e| e.to_string())?,
                initial.head()
            ],
        )
        .map_err(|e| e.to_string())?;
        let state = read(&tx, anchor, None)?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(state)
    }
    /// Uses a consistent SQLite read transaction, not independent snapshot queries.
    pub fn load(
        &mut self,
        anchor: &Anchor,
        minimum: Option<&Checkpoint>,
    ) -> Result<DeviceState, String> {
        let tx = self.conn.transaction().map_err(|e| e.to_string())?;
        let state = read(&tx, anchor, minimum)?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(state)
    }
    /// Live admission enforces expiry. Retries must use the original signed event.
    pub fn append_live(
        &mut self,
        anchor: &Anchor,
        expected: &Checkpoint,
        events: &[DeviceEvent],
        now: i64,
    ) -> Result<DeviceState, String> {
        self.append(anchor, expected, events, Some(now))
    }
    /// Historical feed replay checks acceptance-time validity and every signature.
    /// Never use this method to authorize a pending live request on the server.
    pub fn import_verified(
        &mut self,
        anchor: &Anchor,
        expected: &Checkpoint,
        events: &[DeviceEvent],
    ) -> Result<DeviceState, String> {
        self.append(anchor, expected, events, None)
    }
    fn append(
        &mut self,
        anchor: &Anchor,
        expected: &Checkpoint,
        events: &[DeviceEvent],
        now: Option<i64>,
    ) -> Result<DeviceState, String> {
        if events.is_empty() || events.len() > MAX_BATCH {
            return Err("invalid device event batch size".into());
        }
        let payloads: Vec<Vec<u8>> = events
            .iter()
            .map(serde_json::to_vec)
            .collect::<Result<_, _>>()
            .map_err(|e| e.to_string())?;
        if payloads.iter().any(|p| p.len() > MAX_EVENT_BYTES)
            || payloads.iter().map(Vec::len).sum::<usize>() > MAX_BATCH_BYTES
        {
            return Err("device event batch exceeds byte limit".into());
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        let mut state = read(&tx, anchor, Some(expected))?;
        if Checkpoint::from_state(&state) != *expected {
            return Err("stale device directory write".into());
        }
        for (event, payload) in events.iter().zip(payloads) {
            let next = match now {
                Some(at) => state.apply_live(event, at),
                None => state.apply(event),
            }
            .map_err(|e| e.to_string())?;
            if next.revision() != state.revision() {
                tx.execute(
                    "INSERT INTO trusted_device_events(origin,account,revision,event_id,payload)
                    VALUES(?1,?2,?3,?4,?5)",
                    params![
                        anchor.origin,
                        anchor.account,
                        event.revision,
                        event.id,
                        payload
                    ],
                )
                .map_err(|e| e.to_string())?;
            }
            state = next;
        }
        tx.execute(
            "UPDATE trusted_device_anchors SET revision=?3,head=?4 WHERE origin=?1 AND account=?2",
            params![
                anchor.origin,
                anchor.account,
                state.revision(),
                state.head()
            ],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(state)
    }
}
fn read(
    conn: &Connection,
    anchor: &Anchor,
    minimum: Option<&Checkpoint>,
) -> Result<DeviceState, String> {
    let mut state = DeviceState::pin(anchor.clone()).map_err(|e| e.to_string())?;
    if minimum.is_some_and(|c| c.hash.len() != 32 || c.revision > MAX_DEVICE_EVENTS) {
        return Err("invalid device directory checkpoint".into());
    }
    let (stored_anchor, revision, head): (Vec<u8>, u64, Vec<u8>) = conn.query_row(
        "SELECT anchor,revision,head FROM trusted_device_anchors WHERE origin=?1 AND account=?2",
        params![anchor.origin, anchor.account], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .map_err(|_| "device root is not pinned".to_string())?;
    if stored_anchor.len() > 2048
        || serde_json::from_slice::<Anchor>(&stored_anchor)
            .map_err(|_| "invalid stored device root")?
            != *anchor
    {
        return Err("stored device root does not match trusted anchor".into());
    }
    if revision > MAX_DEVICE_EVENTS || head.len() != 32 {
        return Err("invalid stored device checkpoint".into());
    }
    let mut matches_minimum = minimum.is_none_or(|c| c.revision == 0 && c.hash == state.head());
    let mut query = conn
        .prepare(
            "SELECT revision,event_id,payload FROM trusted_device_events
        WHERE origin=?1 AND account=?2 ORDER BY revision LIMIT ?3",
        )
        .map_err(|e| e.to_string())?;
    let mut rows = query
        .query(params![
            anchor.origin,
            anchor.account,
            MAX_DEVICE_EVENTS + 1
        ])
        .map_err(|e| e.to_string())?;
    while let Some(row) = rows.next().map_err(|e| e.to_string())? {
        let number: u64 = row.get(0).map_err(|e| e.to_string())?;
        let id: String = row.get(1).map_err(|e| e.to_string())?;
        let payload: Vec<u8> = row.get(2).map_err(|e| e.to_string())?;
        if payload.len() > MAX_EVENT_BYTES {
            return Err("stored device event exceeds byte limit".into());
        }
        let event: DeviceEvent =
            serde_json::from_slice(&payload).map_err(|_| "invalid stored device event")?;
        if event.revision != number || event.id != id || number != state.revision() + 1 {
            return Err("stored device event sequence is invalid".into());
        }
        state = state.apply(&event).map_err(|e| e.to_string())?;
        if minimum.is_some_and(|c| c.revision == state.revision() && c.hash == state.head()) {
            matches_minimum = true;
        }
    }
    if revision != state.revision() || head != state.head() || !matches_minimum {
        return Err("device directory is incomplete, rolled back, or divergent".into());
    }
    Ok(state)
}
