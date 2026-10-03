//! Disposable ciphertext progress, separate from confirmed portable history.
use super::history_transfer::{self as local, State, View};
use super::*;
use liteseal_shared::history_transfer::{self as h, Envelope, Offer};
const KIND: &str = "history_receive";
pub(super) const SCHEMA:&str="CREATE TABLE IF NOT EXISTS direct_v3_history_receive_chunks(scope TEXT NOT NULL,account TEXT NOT NULL,id TEXT NOT NULL,part INTEGER NOT NULL CHECK(part BETWEEN 0 AND 128),data BLOB NOT NULL CHECK(length(data) BETWEEN 1 AND 1048576),PRIMARY KEY(scope,id,part));";
fn scope(owner: &Owner) -> String {
    format!("history-receive:{}", owner.scope())
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receive {
    scope: String,
    offer: Offer,
    #[serde(default = "initial_revision")]
    revision: u64,
    #[serde(default)]
    paused: bool,
    #[serde(default)]
    abandoned: bool,
}
fn initial_revision() -> u64 {
    1
}
#[derive(Serialize)]
pub struct ReceiveView {
    pub id: String,
    pub revision: u64,
    pub paused: bool,
    pub abandoned: bool,
    pub downloaded: usize,
    pub total: usize,
    pub expires_at: i64,
}
fn receive(
    conn: &Connection,
    owner: &Owner,
    id: &str,
    keys: &KeyPair,
) -> Result<Option<Receive>, String> {
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
    let r: Receive = serde_json::from_slice(&plain).map_err(|_| invalid())?;
    if r.scope != owner.scope()
        || r.offer.header.id != id
        || r.revision != revision
        || revision == 0
        || r.offer.header.target.device != owner.device
        || r.offer.header.account != owner.account
        || r.offer.header.origin != owner.origin
        || r.abandoned && !r.paused
    {
        return Err(invalid());
    }
    Ok(Some(r))
}
fn save_receive(
    conn: &Connection,
    owner: &Owner,
    r: &Receive,
    keys: &KeyPair,
) -> Result<(), String> {
    let plain = Zeroizing::new(serde_json::to_vec(r).map_err(|_| invalid())?);
    if plain.len() > 65536 {
        return Err(invalid());
    }
    let body =
        crypto::encrypt(&plain, &keys.public_key, &keys.secret_key).map_err(|_| invalid())?;
    conn.execute("INSERT INTO device_control_tasks(scope,id,revision,kind,terminal,body) VALUES(?1,?2,?3,?4,0,?5) ON CONFLICT(scope,id) DO UPDATE SET revision=excluded.revision,body=excluded.body",params![scope(owner),r.offer.header.id,r.revision,KIND,body]).map_err(db)?;
    Ok(())
}
fn validate(conn: &Connection) -> Result<(), String> {
    let sql:Option<String>=conn.query_row("SELECT sql FROM sqlite_schema WHERE type='table' AND name='direct_v3_history_receive_chunks'",[],|r|r.get(0)).map_err(db)?;
    let extra:i64=conn.query_row("SELECT COUNT(*) FROM sqlite_schema WHERE tbl_name='direct_v3_history_receive_chunks' AND NOT(type='table' OR (type='index' AND sql IS NULL))",[],|r|r.get(0)).map_err(db)?;
    if sql.as_deref() != Some(SCHEMA.replace(" IF NOT EXISTS", "").trim_end_matches(';'))
        || extra != 0
    {
        return Err(invalid());
    }
    Ok(())
}
impl Store {
    pub fn history_receives(&mut self, keys: &KeyPair) -> Result<Vec<ReceiveView>, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.read_checked(|conn|{
            validate(conn)?;
            let mut q=conn.prepare("SELECT id FROM device_control_tasks WHERE scope=?1 AND kind=?2 ORDER BY id LIMIT 33").map_err(db)?;
            let ids=q.query_map(params![scope(&owner),KIND],|r|r.get::<_,String>(0)).map_err(db)?.collect::<rusqlite::Result<Vec<_>>>().map_err(db)?;
            if ids.len()>32 {return Err(invalid())}
            ids.iter().map(|id|{
                let r=receive(conn,&owner,id,keys)?.ok_or_else(invalid)?;
                let downloaded=conn.query_row("SELECT COUNT(*) FROM direct_v3_history_receive_chunks WHERE scope=?1 AND id=?2",params![owner.scope(),id],|r|r.get::<_,usize>(0)).map_err(db)?;
                Ok(ReceiveView{id:id.clone(),revision:r.revision,paused:r.paused,abandoned:r.abandoned,downloaded,total:r.offer.size.div_ceil(h::CHUNK),expires_at:r.offer.header.expires_at})
            }).collect()
        })
    }
    pub fn check_history_receive(
        &mut self,
        id: &str,
        revision: u64,
        keys: &KeyPair,
    ) -> Result<(), String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.read_checked(|conn| {
            let r = receive(conn, &owner, id, keys)?.ok_or_else(invalid)?;
            if r.revision != revision || r.paused {
                return Err(conflict());
            }
            Ok(())
        })
    }
    pub fn set_history_receive_pause(
        &mut self,
        id: &str,
        revision: u64,
        paused: bool,
        abandon: bool,
        keys: &KeyPair,
    ) -> Result<(), String> {
        if abandon && !paused {
            return Err(invalid());
        }
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.write_checked(|conn| {
            let mut r = receive(conn, &owner, id, keys)?.ok_or_else(invalid)?;
            if r.revision != revision {
                return Err(conflict());
            }
            r.revision = r.revision.checked_add(1).ok_or_else(invalid)?;
            r.paused = paused;
            if abandon {
                conn.execute(
                    "DELETE FROM direct_v3_history_receive_chunks WHERE scope=?1 AND id=?2",
                    params![owner.scope(), id],
                )
                .map_err(db)?;
                r.abandoned = true;
            } else if !paused {
                r.abandoned = false;
            }
            save_receive(conn, &owner, &r, keys)
        })
    }
    pub fn cleanup_history_receive(&mut self, now: i64, keys: &KeyPair) -> Result<(), String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.write_checked(|conn| {
            validate(conn)?;
            let mut q = conn
                .prepare(
                    "SELECT id,body FROM device_control_tasks WHERE scope=?1 AND kind=?2 LIMIT 33",
                )
                .map_err(db)?;
            let rows = q
                .query_map(params![scope(&owner), KIND], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
                })
                .map_err(db)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(db)?;
            if rows.len() > 32 {
                return Err(invalid());
            }
            drop(q);
            for (id, body) in rows {
                let plain = Zeroizing::new(
                    crypto::decrypt(&body, &keys.public_key, &keys.secret_key)
                        .map_err(|_| invalid())?,
                );
                let r: Receive = serde_json::from_slice(&plain).map_err(|_| invalid())?;
                if r.scope != owner.scope() || r.offer.header.id != id {
                    return Err(invalid());
                }
                if r.offer.header.expires_at <= now {
                    conn.execute(
                        "DELETE FROM direct_v3_history_receive_chunks WHERE scope=?1 AND id=?2",
                        params![owner.scope(), id],
                    )
                    .map_err(db)?;
                    conn.execute(
                        "DELETE FROM device_control_tasks WHERE scope=?1 AND id=?2 AND kind=?3",
                        params![scope(&owner), id, KIND],
                    )
                    .map_err(db)?;
                }
            }
            Ok(())
        })
    }
    pub fn history_relay_original(
        &mut self,
        id: &str,
        revision: u64,
        keys: &KeyPair,
    ) -> Result<Envelope, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.read_checked(|conn| {
            let r = local::load(conn, &owner, id, keys)?.ok_or_else(invalid)?;
            if r.state != State::Prepared || r.revision != revision {
                return Err(conflict());
            }
            local::wire(conn, &owner, &r, keys)
        })
    }
    pub fn history_receive_next(&mut self, offer: &Offer, keys: &KeyPair) -> Result<usize, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.write_checked(|conn| {
            validate(conn)?;
            let own=current(conn,&owner.origin,&owner.account)?;
            offer.verify(&own).map_err(|_|invalid())?;
            if offer.header.target.device!=owner.device || super::super::resolve(conn,&owner.origin,&offer.header.peer).is_err() {return Err(invalid());}
            if let Some(r)=receive(conn,&owner,&offer.header.id,keys)? {
                if r.offer!=*offer || r.paused {return Err(conflict());}
            } else {
                let count:i64=conn.query_row("SELECT COUNT(*) FROM device_control_tasks WHERE scope=?1 AND kind=?2",params![scope(&owner),KIND],|r|r.get(0)).map_err(db)?;
                if count>=32 {return Err("未完成历史收件达到上限，请停止或整理过期收件".into());}
                save_receive(conn,&owner,&Receive{scope:owner.scope(),offer:offer.clone(),revision:1,paused:false,abandoned:false},keys)?;
            }
            let mut q=conn.prepare("SELECT part,length(data) FROM direct_v3_history_receive_chunks WHERE scope=?1 AND id=?2 ORDER BY part LIMIT 130").map_err(db)?;
            let rows=q.query_map(params![owner.scope(),offer.header.id],|r|Ok((r.get::<_,usize>(0)?,r.get::<_,usize>(1)?))).map_err(db)?.collect::<rusqlite::Result<Vec<_>>>().map_err(db)?;
            for (index,(part,len)) in rows.iter().enumerate() {if *part!=index || offer.chunk_len(index).map_err(|_|invalid())?!=*len {return Err(invalid());}}
            Ok(rows.len())
        })
    }
    pub fn history_receive_chunk(
        &mut self,
        offer: &Offer,
        part: usize,
        bytes: &[u8],
        keys: &KeyPair,
    ) -> Result<(), String> {
        let next = self.history_receive_next(offer, keys)?;
        if part != next || bytes.len() != offer.chunk_len(part).map_err(|_| invalid())? {
            return Err(conflict());
        }
        let owner = self.owner.clone();
        self.trust.write_checked(|conn| {
            validate(conn)?;
            let actual:i64=conn.query_row("SELECT COUNT(*) FROM direct_v3_history_receive_chunks WHERE scope=?1 AND id=?2",params![owner.scope(),offer.header.id],|r|r.get(0)).map_err(db)?;
            if actual!=next as i64 {return Err(conflict());}
            let total:i64=conn.query_row("SELECT (SELECT COALESCE(SUM(length(data)),0) FROM direct_v3_history_receive_chunks WHERE account=?1)+(SELECT COALESCE(SUM(length(ciphertext)),0) FROM direct_v3_history_chunks WHERE account=?1)",[&owner.account],|r|r.get(0)).map_err(db)?;
            if total+bytes.len() as i64>256*1024*1024 {return Err("历史收件暂存超过 256 MiB 上限".into());}
            conn.execute("INSERT INTO direct_v3_history_receive_chunks VALUES(?1,?2,?3,?4,?5)",params![owner.scope(),owner.account,offer.header.id,part as i64,bytes]).map_err(db)?;Ok(())
        })
    }
    pub fn history_receive_complete(
        &mut self,
        offer: &Offer,
        keys: &KeyPair,
    ) -> Result<Envelope, String> {
        if self.history_receive_next(offer, keys)? != offer.size.div_ceil(h::CHUNK) {
            return Err(conflict());
        }
        let owner = self.owner.clone();
        self.trust.read_checked(|conn| {
            let mut bytes=Vec::with_capacity(offer.size);for part in 0..offer.size.div_ceil(h::CHUNK) {
                let chunk:Vec<u8>=conn.query_row("SELECT data FROM direct_v3_history_receive_chunks WHERE scope=?1 AND id=?2 AND part=?3 AND account=?4 AND length(data)=?5",params![owner.scope(),offer.header.id,part as i64,owner.account,offer.chunk_len(part).map_err(|_|invalid())? as i64],|r|r.get(0)).map_err(db)?;bytes.extend(chunk);
            }Envelope::from_offer(offer.clone(),bytes).map_err(|_|invalid())
        })
    }
    pub fn clear_history_receive(&mut self, id: &str, keys: &KeyPair) -> Result<(), String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.write_checked(|conn| {
            conn.execute(
                "DELETE FROM direct_v3_history_receive_chunks WHERE scope=?1 AND id=?2",
                params![owner.scope(), id],
            )
            .map_err(db)?;
            conn.execute(
                "DELETE FROM device_control_tasks WHERE scope=?1 AND id=?2 AND kind=?3",
                params![scope(&owner), id, KIND],
            )
            .map_err(db)?;
            Ok(())
        })
    }
    pub fn finish_history_receive(
        &mut self,
        offer: &Offer,
        now: i64,
        keys: &KeyPair,
    ) -> Result<View, String> {
        let envelope = self.history_receive_complete(offer, keys)?;
        // Release disposable raw chunks before duplicating the wire under the
        // target's at-rest key. The signed intent remains for exact redownload
        // if the confirmed metadata commit fails; the relay retains permitted
        // ciphertext until expiry or the later signed received result.
        let owner = self.owner.clone();
        self.trust.write_checked(|conn| {
            conn.execute(
                "DELETE FROM direct_v3_history_receive_chunks WHERE scope=?1 AND id=?2",
                params![owner.scope(), offer.header.id],
            )
            .map_err(db)?;
            Ok(())
        })?;
        let view = self.import_history(&envelope.to_wire().map_err(|_| invalid())?, now, keys)?;
        // Keep the exact receive intent until the relay acknowledges the signed
        // received result. A lost confirmation must remain background-retryable.
        Ok(view)
    }
}
