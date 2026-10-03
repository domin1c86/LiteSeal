//! T26 isolated native trial. No production transport or renderer API yet.
use super::*;
use liteseal_shared::disappearing_message::Packet;
const KIND: &str = "disappearing_message_trial";
const CLOCK: &str = "disappearing_clock_trial";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    scope: String,
    packet: Packet,
    expired: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Clock {
    scope: String,
    observed: i64,
}
pub struct Trial {
    store: Store,
}
impl Trial {
    /// Move an isolated store into the trial. Ordinary read APIs are not exposed.
    pub fn new(store: Store) -> Self {
        Self { store }
    }
    pub fn receive(
        &mut self,
        packet: &Packet,
        receipt: &Acceptance,
        keys: &KeyPair,
    ) -> Result<AckOutcome, String> {
        let owner = self.store.owner.clone();
        owner.keys(keys)?;
        let packet_wire = packet.to_wire().map_err(|_| invalid())?;
        self.store.trust.write_checked(|conn| {
            let (s,p) = evidence(conn, &packet.original)?;
            packet.verify(&s,&p).map_err(|_| invalid())?;
            receipt.matches(&packet.original)?;
            let scope = format!("expiry-trial:{}",owner.scope());
            if let Some(bytes) = load(conn,&scope,&packet.original.header.id,KIND)? {
                let old: Saved = decode(&bytes,keys)?;
                if old.scope != scope || old.packet.to_wire().map_err(|_| invalid())? != packet_wire { return Err(conflict()); }
                return Ok(());
            }
            let count:i64=conn.query_row("SELECT COUNT(*) FROM device_control_tasks WHERE scope=?1",[&scope],|r|r.get(0)).map_err(db)?;
            if count>=128{return Err("期限验证消息达到上限".into());}
            let bytes = encode(&Saved { scope: scope.clone(), packet: packet.clone(), expired:false },keys)?;
            conn.execute("INSERT INTO device_control_tasks(scope,id,revision,kind,terminal,body) VALUES(?1,?2,1,?3,1,?4)",params![scope,packet.original.header.id,KIND,bytes]).map_err(db)?;
            Ok(())
        })?;
        // If this commit fails, a saved policy cannot make missing original
        // evidence readable. Retrying keeps exactly the same signed packet.
        self.store.receive(&packet.original, receipt, keys)
    }
    fn visible(&mut self, id: &str, now: i64, keys: &KeyPair) -> Result<bool, String> {
        self.store.owner.keys(keys)?;
        if now <= 0 {
            return Err(invalid());
        }
        let owner = self.store.owner.clone();
        self.store.trust.write_checked(|conn| {
            let scope=format!("expiry-trial:{}",owner.scope());
            let mut saved:Saved=decode(&load(conn,&scope,id,KIND)?.ok_or_else(invalid)?,keys)?;
            let (s,p)=evidence(conn,&saved.packet.original)?;
            saved.packet.verify(&s,&p).map_err(|_| invalid())?;
            if saved.scope!=scope||saved.packet.original.header.id!=id{return Err(invalid());}
            let row=record(conn,&owner.scope(),id)?.ok_or_else(invalid)?;
            let (original,_)=checked_record(conn,&owner,&row,keys)?;
            if original.digest().map_err(|_|invalid())?!=saved.packet.original.digest().map_err(|_|invalid())?{return Err(invalid());}
            let mut clock=if let Some(bytes)=load(conn,&scope,"clock",CLOCK)?{decode::<Clock>(&bytes,keys)?}else{Clock{scope:scope.clone(),observed:0}};
            if clock.scope!=scope||clock.observed<0{return Err(invalid());}
            // Observed time is monotonic under the native external witness.
            // A prior expiry remains terminal after clock rollback or replay.
            if now>clock.observed {
                clock.observed=now;
                let bytes=encode(&clock,keys)?;
                conn.execute("INSERT INTO device_control_tasks(scope,id,revision,kind,terminal,body) VALUES(?1,'clock',1,?2,1,?3) ON CONFLICT(scope,id) DO UPDATE SET revision=revision+1,body=excluded.body WHERE kind=?2",params![scope,CLOCK,bytes]).map_err(db)?;
            }
            if !saved.expired&&saved.packet.expired(clock.observed){
                saved.expired=true;
                conn.execute("UPDATE device_control_tasks SET revision=revision+1,body=?3 WHERE scope=?1 AND id=?2 AND kind=?4",params![scope,id,encode(&saved,keys)?,KIND]).map_err(db)?;
            }
            Ok(!saved.expired)
        })
    }
    pub fn body(
        &mut self,
        id: &str,
        now: i64,
        keys: &KeyPair,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        if !self.visible(id, now, keys)? {
            return Ok(None);
        }
        self.store
            .body(id, keys)
            .map(|body| Some(Zeroizing::new(body)))
    }
    pub fn search(
        &mut self,
        id: &str,
        needle: &str,
        now: i64,
        keys: &KeyPair,
    ) -> Result<bool, String> {
        Ok(self
            .body(id, now, keys)?
            .is_some_and(|body| std::str::from_utf8(&body).is_ok_and(|body| body.contains(needle))))
    }
    pub fn notification(&mut self, id: &str, now: i64, keys: &KeyPair) -> Result<bool, String> {
        Ok(self.body(id, now, keys)?.is_some())
    }
    pub fn export_body(
        &mut self,
        id: &str,
        now: i64,
        keys: &KeyPair,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        self.body(id, now, keys)
    }
    pub fn attachment(
        &mut self,
        id: &str,
        ciphertext: &[u8],
        now: i64,
        keys: &KeyPair,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        let Some(body) = self.body(id, now, keys)? else {
            return Ok(None);
        };
        let packet = self.proof(id, keys)?;
        let descriptor =
            liteseal_shared::direct_media::Descriptor::from_body(&packet.original.header, &body)
                .map_err(|_| invalid())?;
        Ok(Some(Zeroizing::new(
            descriptor
                .decrypt(packet.original.header.kind, ciphertext)
                .map_err(|_| invalid())?,
        )))
    }
    pub fn proof(&mut self, id: &str, keys: &KeyPair) -> Result<Packet, String> {
        self.store.owner.keys(keys)?;
        let scope = format!("expiry-trial:{}", self.store.owner.scope());
        self.store.trust.read_checked(|conn| {
            let saved: Saved = decode(&load(conn, &scope, id, KIND)?.ok_or_else(invalid)?, keys)?;
            if saved.scope != scope || saved.packet.original.header.id != id {
                return Err(invalid());
            }
            let (s, p) = evidence(conn, &saved.packet.original)?;
            saved.packet.verify(&s, &p).map_err(|_| invalid())?;
            Ok(saved.packet)
        })
    }
    pub fn pending_acks(&mut self, keys: &KeyPair) -> Result<Vec<Ack>, String> {
        self.store.pending_acks(keys)
    }
}
fn load(conn: &Connection, scope: &str, id: &str, kind: &str) -> Result<Option<Vec<u8>>, String> {
    conn.query_row("SELECT body FROM device_control_tasks WHERE scope=?1 AND id=?2 AND kind=?3 AND terminal=1 AND length(body)<=270000",params![scope,id,kind],|r|r.get(0)).optional().map_err(db)
}
fn encode<T: Serialize>(value: &T, keys: &KeyPair) -> Result<Vec<u8>, String> {
    let plain = Zeroizing::new(serde_json::to_vec(value).map_err(|_| invalid())?);
    if plain.len() > 269960 {
        return Err(invalid());
    }
    crypto::encrypt(&plain, &keys.public_key, &keys.secret_key).map_err(|_| invalid())
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8], keys: &KeyPair) -> Result<T, String> {
    let plain = Zeroizing::new(
        crypto::decrypt(bytes, &keys.public_key, &keys.secret_key).map_err(|_| invalid())?,
    );
    serde_json::from_slice(&plain).map_err(|_| invalid())
}
