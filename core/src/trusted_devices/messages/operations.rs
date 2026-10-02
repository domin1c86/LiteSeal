//! Immutable authenticated operation log, covered by the existing native witness.
//! Wire chunks contain only public routing and end-to-end ciphertext. Plain edit
//! bodies are decrypted on demand and never stored in SQLite.
use super::*;
use liteseal_shared::direct_operation::{self as op, Action, Event, Operation, Page};
const KIND: &str = "direct_v3_operation";
const CHUNK: usize = 32 * 1024;
const LIMIT: i64 = 32 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Meta {
    domain: String,
    scope: String,
    id: String,
    event: String,
    target: String,
    revision: u64,
    order: i64,
    accepted_at: i64,
    digest: [u8; 32],
    size: usize,
    hashes: Vec<[u8; 32]>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    domain: String,
    scope: String,
    revision: u64,
    authority: [u8; 32],
    through: i64,
}
fn scope(owner: &Owner) -> String {
    format!("operation:{}", owner.scope())
}
fn wires(owner: &Owner) -> String {
    format!("operation-wire:{}", owner.scope())
}
fn id(target: &str, revision: u64) -> String {
    format!("{target}:{revision:05}")
}
fn uuid(value: &str) -> Result<(), String> {
    if uuid::Uuid::parse_str(value).is_ok_and(|v| v.to_string() == value) {
        Ok(())
    } else {
        Err(invalid())
    }
}
fn row(conn: &Connection, scope: &str, id: &str) -> Result<Option<(u64, Vec<u8>)>, String> {
    let row = conn
        .query_row(
            "SELECT revision,kind,terminal,body FROM device_control_tasks WHERE scope=?1 AND id=?2",
            params![scope, id],
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
    row.map(|(revision, kind, terminal, body)| {
        if kind != KIND || !terminal || body.len() > 65576 {
            return Err(invalid());
        }
        Ok((revision, body))
    })
    .transpose()
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8], keys: &KeyPair) -> Result<T, String> {
    let plain = Zeroizing::new(
        crypto::decrypt(bytes, &keys.public_key, &keys.secret_key).map_err(|_| invalid())?,
    );
    serde_json::from_slice(&plain).map_err(|_| invalid())
}
fn put<T: Serialize>(
    conn: &Connection,
    scope: &str,
    id: &str,
    revision: u64,
    value: &T,
    keys: &KeyPair,
) -> Result<(), String> {
    let plain = Zeroizing::new(serde_json::to_vec(value).map_err(|_| invalid())?);
    if plain.len() > 64 * 1024 {
        return Err(invalid());
    }
    let body =
        crypto::encrypt(&plain, &keys.public_key, &keys.secret_key).map_err(|_| invalid())?;
    conn.execute("INSERT INTO device_control_tasks(scope,id,revision,kind,terminal,body) VALUES(?1,?2,?3,?4,1,?5) ON CONFLICT(scope,id) DO UPDATE SET revision=excluded.revision,body=excluded.body",params![scope,id,revision,KIND,body]).map_err(db)?;
    Ok(())
}
fn cursor(conn: &Connection, owner: &Owner, keys: &KeyPair) -> Result<Cursor, String> {
    let scope = scope(owner);
    let authority = owner.member(&current(conn, &owner.origin, &owner.account)?)?;
    let Some((revision, body)) = row(conn, &scope, "cursor")? else {
        return Ok(Cursor {
            domain: "LiteSeal/direct-operation-cursor/v1".into(),
            scope,
            revision: 0,
            authority,
            through: 0,
        });
    };
    let r: Cursor = decode(&body, keys)?;
    if r.domain != "LiteSeal/direct-operation-cursor/v1"
        || r.scope != scope
        || r.revision != revision
        || revision == 0
        || r.authority != authority
        || r.through < 0
    {
        return Err(invalid());
    }
    Ok(r)
}
fn meta(
    conn: &Connection,
    owner: &Owner,
    id: &str,
    keys: &KeyPair,
) -> Result<Option<Meta>, String> {
    let scope = scope(owner);
    let Some((revision, body)) = row(conn, &scope, id)? else {
        return Ok(None);
    };
    let m: Meta = decode(&body, keys)?;
    uuid(&m.event)?;
    uuid(&m.target)?;
    if m.domain != "LiteSeal/direct-operation-log/v1"
        || m.scope != scope
        || m.id != id
        || m.id != self::id(&m.target, m.revision)
        || m.revision != revision
        || !(1..=op::MAX_EVENTS as u64).contains(&revision)
        || m.order <= 0
        || !(1..=8_640_000_000_000_000).contains(&m.accepted_at)
        || m.size == 0
        || m.size > op::MAX_WIRE
        || m.hashes.len() != m.size.div_ceil(CHUNK)
    {
        return Err(invalid());
    }
    Ok(Some(m))
}
fn open(
    conn: &Connection,
    owner: &Owner,
    m: &Meta,
    keys: &KeyPair,
) -> Result<(Operation, Option<String>), String> {
    let mut wire = Vec::with_capacity(m.size);
    for (part, hash) in m.hashes.iter().enumerate() {
        let (revision, body) =
            row(conn, &wires(owner), &format!("{}:{part:02}", m.event))?.ok_or_else(invalid)?;
        if revision != m.revision
            || body.len() != CHUNK.min(m.size - part * CHUNK)
            || <[u8; 32]>::from(Sha256::digest(&body)) != *hash
        {
            return Err(invalid());
        }
        wire.extend(body);
    }
    let operation = Operation::from_wire(&wire).map_err(|_| invalid())?;
    if operation.header.id != m.event
        || operation.original.header.id != m.target
        || operation.header.revision != m.revision
        || operation.digest().map_err(|_| invalid())? != m.digest
    {
        return Err(invalid());
    }
    let (sender, peer) = evidence(conn, &operation.original)?;
    let original = if operation.original.header.sender == owner.account {
        &sender
    } else {
        &peer
    };
    let text = operation
        .open(
            &sender,
            &peer,
            &owner.account,
            &owner.device.device_id,
            owner.member(original)?,
            keys,
        )
        .map_err(|_| invalid())?;
    Ok((operation, text))
}
fn latest(
    conn: &Connection,
    owner: &Owner,
    target: &str,
    keys: &KeyPair,
) -> Result<Option<Meta>, String> {
    uuid(target)?;
    let prefix = format!("{target}:");
    let found=conn.query_row("SELECT id FROM device_control_tasks WHERE scope=?1 AND kind=?2 AND id>=?3 AND id<?4 ORDER BY id DESC LIMIT 1",params![scope(owner),KIND,prefix,format!("{prefix}~")],|r|r.get::<_,String>(0)).optional().map_err(db)?;
    found
        .map(|id| meta(conn, owner, &id, keys)?.ok_or_else(invalid))
        .transpose()
}
pub(super) fn projection(
    conn: &Connection,
    owner: &Owner,
    batch: &Batch,
    keys: &KeyPair,
) -> Result<(u64, Option<Action>, Option<String>), String> {
    let Some(m) = latest(conn, owner, &batch.header.id, keys)? else {
        return Ok((0, None, None));
    };
    let (operation, text) = open(conn, owner, &m, keys)?;
    if operation.original.digest().map_err(|_| invalid())?
        != batch.digest().map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    Ok((m.revision, Some(operation.header.action), text))
}
pub(super) fn retracted(
    conn: &Connection,
    owner: &Owner,
    target: &str,
    keys: &KeyPair,
) -> Result<bool, String> {
    let Some(m) = latest(conn, owner, target, keys)? else {
        return Ok(false);
    };
    Ok(open(conn, owner, &m, keys)?.0.header.action == Action::Retract)
}
impl Store {
    pub fn import_authenticated_operations(
        &mut self,
        expected: i64,
        page: &api::AuthenticatedOperations,
        keys: &KeyPair,
    ) -> Result<i64, String> {
        if page.origin != self.owner.origin
            || page.account != self.owner.account
            || page.device != self.owner.device.device_id
            || page.after != expected
        {
            return Err(invalid());
        }
        self.import_operations(expected, &page.page, keys)
    }
    pub fn operation_cursor(&mut self, keys: &KeyPair) -> Result<i64, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust
            .read_checked(|conn| cursor(conn, &owner, keys).map(|r| r.through))
    }
    /// This Rust-only API accepts a bounded transport page. Every event is
    /// checked/decrypted before the single covered transaction advances its cursor.
    pub fn import_operations(
        &mut self,
        expected: i64,
        page: &Page,
        keys: &KeyPair,
    ) -> Result<i64, String> {
        self.owner.keys(keys)?;
        if expected < 0
            || page.events.len() > op::MAX_PAGE
            || serde_json::to_vec(page).map_err(|_| invalid())?.len() > op::MAX_PAGE_BYTES
            || page.events.is_empty() && (page.has_more || page.through != expected)
            || page.events.last().is_some_and(|e| e.order != page.through)
        {
            return Err(invalid());
        }
        let owner = self.owner.clone();
        self.trust.write_checked(|conn|{
            let mut cursor=cursor(conn,&owner,keys)?;
            if cursor.through!=expected{return Err("操作补收游标已变化，请重新查询".into());}
            let authority=cursor.authority;
            let mut previous=expected;
            for event in &page.events {
                let Event{order,accepted_at,operation}=event;
                uuid(&operation.header.id)?;uuid(&operation.original.header.id)?;
                if *order<=previous||!(1..=8_640_000_000_000_000).contains(accepted_at){return Err(invalid());}
                previous= *order;
                let (sender,peer)=evidence(conn,&operation.original)?;
                let original=if operation.original.header.sender==owner.account{&sender}else{&peer};
                if owner.member(original)?!=authority{return Err(invalid());}
                let text=Zeroizing::new(operation.open(&sender,&peer,&owner.account,&owner.device.device_id,authority,keys).map_err(|_|invalid())?);
                drop(text);
                let wire=operation.to_wire().map_err(|_|invalid())?;
                let target=&operation.original.header.id;
                let row_id=id(target,operation.header.revision);
                let digest=operation.digest().map_err(|_|invalid())?;
                if let Some(m)=meta(conn,&owner,&row_id,keys)? {
                    let (saved,_)=open(conn,&owner,&m,keys)?;
                    if m.order!=*order||m.accepted_at!=*accepted_at||m.digest!=digest||saved.to_wire().map_err(|_|invalid())?!=wire{return Err(invalid());}
                    continue;
                }
                if let Some(m)=latest(conn,&owner,target,keys)? {
                    let (saved,_)=open(conn,&owner,&m,keys)?;
                    if m.revision!=operation.header.base||saved.header.action==Action::Retract||saved.original.digest().map_err(|_|invalid())?!=operation.header.original{return Err(invalid());}
                }else if operation.header.base!=0{return Err("操作历史存在缺口，游标没有推进".into());}
                let count:i64=conn.query_row("SELECT COUNT(*) FROM device_control_tasks WHERE scope=?1 AND id!='cursor'",[scope(&owner)],|r|r.get(0)).map_err(db)?;
                let bytes:i64=conn.query_row("SELECT COALESCE(SUM(length(body)),0) FROM device_control_tasks WHERE scope=?1",[wires(&owner)],|r|r.get(0)).map_err(db)?;
                if count>=op::MAX_EVENTS||bytes+wire.len() as i64>LIMIT{return Err("本机操作日志达到 10000 项或 32 MiB 上限".into());}
                let hashes=wire.chunks(CHUNK).map(|bytes|Sha256::digest(bytes).into()).collect();
                for (part,body) in wire.chunks(CHUNK).enumerate(){
                    // Plain INSERT preserves the global event-id fence as well
                    // as the target/revision fence, including moved-ID forgeries.
                    conn.execute("INSERT INTO device_control_tasks(scope,id,revision,kind,terminal,body) VALUES(?1,?2,?3,?4,1,?5)",params![wires(&owner),format!("{}:{part:02}",operation.header.id),operation.header.revision,KIND,body]).map_err(db)?;
                }
                let m=Meta{domain:"LiteSeal/direct-operation-log/v1".into(),scope:scope(&owner),id:row_id.clone(),event:operation.header.id.clone(),target:target.clone(),revision:operation.header.revision,order:*order,accepted_at:*accepted_at,digest,size:wire.len(),hashes};
                put(conn,&scope(&owner),&row_id,m.revision,&m,keys)?;
                if operation.header.action==Action::Retract{media::hidden(conn,&owner,target,keys)?;}
            }
            if !page.events.is_empty(){
                cursor.through=page.through;
                cursor.revision=cursor.revision.checked_add(1).filter(|r|*r<=i64::MAX as u64).ok_or_else(invalid)?;
                put(conn,&scope(&owner),"cursor",cursor.revision,&cursor,keys)?;
            }
            Ok(cursor.through)
        })
    }
}
