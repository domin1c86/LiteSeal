//! Encrypted per-owner/per-peer drafts. A consumed revision remembers the
//! immutable prepared task so a lost preparation response cannot create another.
use super::{db, invalid, Owner};
use liteseal_shared::crypto::{self, KeyPair};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;
const KIND: &str = "direct_v3_draft";
const MAX: usize = 512 * 1024;
#[derive(Debug, Clone, Serialize)]
pub struct View {
    pub peer: String,
    pub revision: u64,
    pub text: String,
    pub prepared: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    domain: String,
    version: u8,
    scope: String,
    peer: String,
    revision: u64,
    text: String,
    prepared: Option<String>,
}
fn scope(owner: &Owner) -> String {
    format!("draft:{}", owner.scope())
}
pub(super) fn load(
    conn: &Connection,
    owner: &Owner,
    peer: &str,
    keys: &KeyPair,
) -> Result<View, String> {
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
        return Ok(View {
            peer: peer.into(),
            revision: 0,
            text: String::new(),
            prepared: None,
        });
    };
    if kind != KIND || !terminal || bytes.len() > MAX + 128 {
        return Err(invalid());
    }
    let plain = Zeroizing::new(
        crypto::decrypt(&bytes, &keys.public_key, &keys.secret_key).map_err(|_| invalid())?,
    );
    if plain.len() > MAX {
        return Err(invalid());
    }
    let r: Record = serde_json::from_slice(&plain).map_err(|_| invalid())?;
    if r.domain != "LiteSeal/direct-draft/v1"
        || r.version != 1
        || r.scope != scope
        || r.peer != peer
        || r.revision != revision
        || revision == 0
        || r.text.len() > liteseal_shared::direct_message::MAX_BODY
        || r.prepared.is_some() && !r.text.is_empty()
    {
        return Err(invalid());
    }
    if r.prepared
        .as_ref()
        .is_some_and(|id| !uuid::Uuid::parse_str(id).is_ok_and(|v| v.to_string() == *id))
    {
        return Err(invalid());
    }
    Ok(View {
        peer: r.peer,
        revision,
        text: r.text,
        prepared: r.prepared,
    })
}
pub(super) fn put(
    conn: &Connection,
    owner: &Owner,
    peer: &str,
    expected: u64,
    text: &str,
    prepared: Option<String>,
    keys: &KeyPair,
) -> Result<View, String> {
    let previous = load(conn, owner, peer, keys)?;
    if previous.revision != expected {
        return Err("草稿已变化，请重新读取；没有覆盖新正文".into());
    }
    if text.len() > liteseal_shared::direct_message::MAX_BODY
        || prepared.is_some() && !text.is_empty()
    {
        return Err(invalid());
    }
    let revision = expected
        .checked_add(1)
        .filter(|v| *v <= i64::MAX as u64)
        .ok_or_else(invalid)?;
    let scope = scope(owner);
    let r = Record {
        domain: "LiteSeal/direct-draft/v1".into(),
        version: 1,
        scope: scope.clone(),
        peer: peer.into(),
        revision,
        text: text.into(),
        prepared: prepared.clone(),
    };
    let plain = Zeroizing::new(serde_json::to_vec(&r).map_err(|_| invalid())?);
    if plain.len() > MAX {
        return Err(invalid());
    }
    let bytes =
        crypto::encrypt(&plain, &keys.public_key, &keys.secret_key).map_err(|_| invalid())?;
    let changed = if expected == 0 {
        let count: usize = conn
            .query_row(
                "SELECT COUNT(*) FROM device_control_tasks WHERE scope=?1",
                [&scope],
                |r| r.get(0),
            )
            .map_err(db)?;
        if count >= 128 {
            return Err("本机草稿账号数量达到上限".into());
        }
        conn.execute("INSERT INTO device_control_tasks(scope,id,revision,kind,terminal,body) VALUES(?1,?2,?3,?4,1,?5)",params![scope,peer,revision,KIND,bytes]).map_err(db)?
    } else {
        conn.execute("UPDATE device_control_tasks SET revision=?3,body=?4 WHERE scope=?1 AND id=?2 AND revision=?5 AND kind=?6",params![scope,peer,revision,bytes,expected,KIND]).map_err(db)?
    };
    if changed != 1 {
        return Err(invalid());
    }
    Ok(View {
        peer: peer.into(),
        revision,
        text: text.into(),
        prepared,
    })
}
