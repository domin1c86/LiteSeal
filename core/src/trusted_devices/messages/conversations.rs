//! Local read boundaries and preferences. A boundary names an authenticated
//! record returned to the caller; later arrivals and replayed ACKs cannot move it.
use super::{checked_record, current, db, invalid, record, Owner, Store};
use liteseal_shared::crypto::{self, KeyPair};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;
const KIND: &str = "direct_v3_conversation";
const DOMAIN: &str = "LiteSeal/direct-conversation/v1";
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    domain: String,
    scope: String,
    peer: String,
    revision: u64,
    pub(super) read_through: i64,
    #[serde(default)]
    notified_through: i64,
    pub(super) muted: bool,
}
#[derive(Debug, Serialize)]
pub struct View {
    pub peer: String,
    pub revision: u64,
    pub muted: bool,
    pub unread: u64,
    pub latest_id: Option<String>,
    pub latest_cursor: Option<i64>,
    pub has_draft: bool,
}
#[derive(Debug, Serialize)]
pub struct Notification {
    pub peer: String,
    pub id: String,
}
fn scope(owner: &Owner) -> String {
    format!("conversation:{}", owner.scope())
}
pub(super) fn load(
    conn: &Connection,
    owner: &Owner,
    peer: &str,
    keys: &KeyPair,
) -> Result<State, String> {
    let scope = scope(owner);
    let row = conn
        .query_row(
            "SELECT revision,kind,terminal,body FROM device_control_tasks WHERE scope=?1 AND id=?2",
            params![scope, peer],
            |r| {
                Ok((
                    r.get::<_, u64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, bool>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .optional()
        .map_err(db)?;
    let Some((revision, kind, terminal, bytes)) = row else {
        return Ok(State {
            domain: DOMAIN.into(),
            scope,
            peer: peer.into(),
            ..State::default()
        });
    };
    if kind != KIND || !terminal || bytes.len() > 4096 {
        return Err(invalid());
    }
    let plain = Zeroizing::new(
        crypto::decrypt(&bytes, &keys.public_key, &keys.secret_key).map_err(|_| invalid())?,
    );
    let state: State = serde_json::from_slice(&plain).map_err(|_| invalid())?;
    if state.domain != DOMAIN
        || state.scope != scope
        || state.peer != peer
        || state.revision != revision
        || revision == 0
        || state.read_through < 0
        || state.notified_through < 0
    {
        return Err(invalid());
    }
    Ok(state)
}
fn put(conn: &Connection, mut state: State, keys: &KeyPair) -> Result<(), String> {
    let previous = state.revision;
    state.revision = previous
        .checked_add(1)
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or_else(invalid)?;
    let plain = Zeroizing::new(serde_json::to_vec(&state).map_err(|_| invalid())?);
    let bytes =
        crypto::encrypt(&plain, &keys.public_key, &keys.secret_key).map_err(|_| invalid())?;
    let changed = if previous == 0 {
        let count: usize = conn
            .query_row(
                "SELECT COUNT(*) FROM device_control_tasks WHERE scope=?1",
                [&state.scope],
                |r| r.get(0),
            )
            .map_err(db)?;
        if count >= 128 {
            return Err("本机会话设置数量达到上限".into());
        }
        conn.execute("INSERT INTO device_control_tasks(scope,id,revision,kind,terminal,body) VALUES(?1,?2,?3,?4,1,?5)", params![state.scope,state.peer,state.revision,KIND,bytes]).map_err(db)?
    } else {
        conn.execute("UPDATE device_control_tasks SET revision=?3,body=?4 WHERE scope=?1 AND id=?2 AND revision=?5 AND kind=?6", params![state.scope,state.peer,state.revision,bytes,previous,KIND]).map_err(db)?
    };
    if changed != 1 {
        return Err(invalid());
    }
    Ok(())
}
impl Store {
    /// Claim once before handing identifiers to the shell. A lost shell reply
    /// can lose a best-effort toast; it never changes unread state or ACKs.
    pub fn claim_notifications(&mut self, keys: &KeyPair) -> Result<Vec<Notification>, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        let peers = self.roots(keys)?;
        self.trust.write_checked(|conn| {
            let mut result = Vec::new();
            super::ordering::check(conn, &owner.scope())?;
            let transfers=super::history_transfer::updates(conn,&owner,keys)?;
            for anchor in peers.iter().filter(|a| a.account != owner.account) {
                let peer = &anchor.account;
                let mut state = load(conn, &owner, peer, keys)?;
                let routing = "scope=?1 AND CASE WHEN json_extract(CAST(wire AS TEXT),'$.header.sender')=?2 THEN json_extract(CAST(wire AS TEXT),'$.header.peer') ELSE json_extract(CAST(wire AS TEXT),'$.header.sender') END=?3";
                let latest: Option<i64> = conn.query_row(&format!("SELECT MAX(rowid) FROM direct_v3_records r WHERE {routing}"), params![owner.scope(),owner.account,peer], |r| r.get(0)).map_err(db)?;
                let Some(latest) = latest.filter(|v| *v > state.notified_through) else { continue; };
                if !state.muted {
                    let id: Option<String> = conn.query_row(&format!("SELECT id FROM direct_v3_records r WHERE {routing} AND rowid>?4 AND role='incoming' AND outcome='processed' AND NOT EXISTS(SELECT 1 FROM direct_v3_hidden h WHERE h.scope=r.scope AND h.id=r.id) ORDER BY rowid DESC LIMIT 1"), params![owner.scope(),owner.account,peer,state.read_through.max(state.notified_through)], |r| r.get(0)).optional().map_err(db)?;
                    if let Some(id) = id {
                        let (batch, _) = checked_record(conn, &owner, &record(conn, &owner.scope(), &id)?.ok_or_else(invalid)?, keys)?;
                        let (revision,action,_)=super::operations::projection(conn,&owner,&batch,keys)?;
                        if action!=Some(liteseal_shared::direct_operation::Action::Retract)&&!transfers.get(&id).is_some_and(|(copy_revision,retracted)|*copy_revision>revision&&*retracted) {
                            result.push(Notification {peer: peer.clone(), id});
                        }
                    }
                }
                state.notified_through = latest;
                put(conn, state, keys)?;
            }
            Ok(result)
        })
    }
    pub fn conversations(&mut self, keys: &KeyPair) -> Result<Vec<View>, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        let peers = self.roots(keys)?;
        self.trust.read_checked(|conn| {
            let mut result = Vec::new();
            super::ordering::check(conn, &owner.scope())?;
            for anchor in peers.iter().filter(|a| a.account != owner.account) {
                let peer = &anchor.account;
                let state = load(conn, &owner, peer, keys)?;
                // Wire routing and role were verified before insertion and are
                // covered by the native witness. Verify the displayed latest
                // record again, including its encrypted local evidence.
                let predicate = "scope=?1 AND CASE WHEN json_extract(CAST(wire AS TEXT),'$.header.sender')=?2 THEN json_extract(CAST(wire AS TEXT),'$.header.peer') ELSE json_extract(CAST(wire AS TEXT),'$.header.sender') END=?3 AND NOT EXISTS(SELECT 1 FROM direct_v3_hidden h WHERE h.scope=r.scope AND h.id=r.id)";
                let latest = conn.query_row(&format!("SELECT rowid,id FROM direct_v3_records r WHERE {predicate} ORDER BY rowid DESC LIMIT 1"), params![owner.scope(),owner.account,peer], |r| Ok((r.get::<_, i64>(0)?,r.get::<_, String>(1)?))).optional().map_err(db)?;
                if let Some((_, id)) = &latest {
                    checked_record(conn, &owner, &record(conn, &owner.scope(), id)?.ok_or_else(invalid)?, keys)?;
                }
                let unread = conn.query_row(&format!("SELECT COUNT(*) FROM direct_v3_records r WHERE {predicate} AND rowid>?4 AND role='incoming' AND outcome='processed'"), params![owner.scope(),owner.account,peer,state.read_through], |r| r.get(0)).map_err(db)?;
                let draft = super::drafts::load(conn, &owner, peer, keys)?;
                result.push(View { peer: peer.clone(), revision: state.revision, muted: state.muted, unread, latest_id: latest.as_ref().map(|(_, id)| id.clone()), latest_cursor: latest.map(|(cursor, _)| cursor), has_draft: !draft.text.is_empty() });
            }
            result.sort_by(|a,b| b.latest_cursor.cmp(&a.latest_cursor).then(a.peer.cmp(&b.peer)));
            Ok(result)
        })
    }
    /// Mark this conversation through a specific visible record, including its
    /// older history. The operation is monotonic and idempotent after a lost reply.
    pub fn mark_read(
        &mut self,
        peer: &str,
        through_id: &str,
        keys: &KeyPair,
    ) -> Result<(), String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.write_checked(|conn| {
            current(conn, &owner.origin, peer)?;
            super::ordering::check(conn, &owner.scope())?;
            let row = record(conn, &owner.scope(), through_id)?.ok_or_else(invalid)?;
            let (batch, _) = checked_record(conn, &owner, &row, keys)?;
            let other = if batch.header.sender == owner.account { &batch.header.peer } else { &batch.header.sender };
            let cursor: i64 = conn.query_row("SELECT rowid FROM direct_v3_records WHERE scope=?1 AND id=?2 AND NOT EXISTS(SELECT 1 FROM direct_v3_hidden WHERE scope=?1 AND id=?2)", params![owner.scope(),through_id], |r| r.get(0)).map_err(db)?;
            if other != peer { return Err(invalid()); }
            let mut state = load(conn, &owner, peer, keys)?;
            if cursor <= state.read_through { return Ok(()); }
            state.read_through = cursor;
            put(conn, state, keys)
        })
    }
    pub fn set_muted(
        &mut self,
        peer: &str,
        revision: u64,
        muted: bool,
        keys: &KeyPair,
    ) -> Result<(), String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.write_checked(|conn| {
            current(conn, &owner.origin, peer)?;
            if peer == owner.account {
                return Err(invalid());
            }
            let mut state = load(conn, &owner, peer, keys)?;
            if state.revision != revision {
                return Err("会话设置已变化，请刷新后重试".into());
            }
            if state.muted == muted {
                return Ok(());
            }
            state.muted = muted;
            put(conn, state, keys)
        })
    }
}
