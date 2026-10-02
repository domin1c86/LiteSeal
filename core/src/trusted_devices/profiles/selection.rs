//! Explicit local profile selection, covered by the external native witness.
//! Clearing writes a tombstone: it never falls back to another saved identity.
use crate::{
    secret_store,
    trusted_devices::{witness::Witness, DeviceTrustStore},
};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::Zeroizing;
const SLOT: &str = "normal_profile_selection";
const MAX: usize = 4096;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Target {
    Root {},
    Join {
        #[serde(rename = "profileId")]
        profile_id: String,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub target: Target,
    pub fingerprint: [u8; 32],
}
impl Binding {
    fn validate(&self) -> Result<(), String> {
        if self.fingerprint == [0; 32] {
            return Err(bad());
        }
        if let Target::Join { profile_id } = &self.target {
            if !uuid::Uuid::parse_str(profile_id).is_ok_and(|id| id.to_string() == *profile_id) {
                return Err(bad());
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selection {
    pub generation: u64,
    pub selected: Option<Binding>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    domain: String,
    version: u8,
    generation: u64,
    selected: Option<Binding>,
}
fn bad() -> String {
    "选中档案记录无法验证，请保留原数据，不会自动切换身份".into()
}
fn db(_: rusqlite::Error) -> String {
    "选中档案存储不可用".into()
}
fn load(conn: &rusqlite::Connection) -> Result<Selection, String> {
    let row = conn
        .query_row(
            "SELECT revision,kind,terminal,body FROM device_control_tasks WHERE scope=?1 AND id=?1",
            [SLOT],
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
        return Ok(Selection {
            generation: 0,
            selected: None,
        });
    };
    if bytes.len() > MAX + 16384 || kind != SLOT || !terminal {
        return Err(bad());
    }
    let plain = Zeroizing::new(secret_store::unprotect_local(&bytes).map_err(|_| bad())?);
    if plain.len() > MAX {
        return Err(bad());
    }
    let record: Record = serde_json::from_slice(&plain).map_err(|_| bad())?;
    if record.domain != "LiteSeal/normal-profile-selection/v1"
        || record.version != 1
        || record.generation == 0
        || record.generation != revision
    {
        return Err(bad());
    }
    if let Some(binding) = &record.selected {
        binding.validate()?;
    }
    Ok(Selection {
        generation: revision,
        selected: record.selected,
    })
}
pub struct Store {
    trust: DeviceTrustStore,
}
impl Store {
    pub fn open(path: &Path, witness: Witness) -> Result<Self, String> {
        let mut trust = DeviceTrustStore::open(path)?;
        trust.protect(witness)?;
        Ok(Self { trust })
    }
    pub fn current(&mut self) -> Result<Selection, String> {
        self.trust.read_checked(load)
    }
    pub fn replace(
        &mut self,
        expected: u64,
        selected: Option<Binding>,
    ) -> Result<Selection, String> {
        if let Some(binding) = &selected {
            binding.validate()?;
        }
        self.trust.write_checked(|conn|{
            let previous=load(conn)?;
            if previous.generation!=expected {return Err("选中范围已变化，请重新查询后确认".into());}
            let generation=expected.checked_add(1).filter(|n|*n<=i64::MAX as u64).ok_or_else(bad)?;
            let record=Record{domain:"LiteSeal/normal-profile-selection/v1".into(),version:1,generation,selected:selected.clone()};
            let plain=Zeroizing::new(serde_json::to_vec(&record).map_err(|_|bad())?);
            let bytes=secret_store::protect_local(&plain).map_err(|_|bad())?;
            let changed=if expected==0 {conn.execute("INSERT INTO device_control_tasks(scope,id,revision,kind,terminal,body) VALUES(?1,?1,?2,?1,1,?3)",params![SLOT,generation,bytes]).map_err(db)?}else{conn.execute("UPDATE device_control_tasks SET revision=?2,body=?3 WHERE scope=?1 AND id=?1 AND revision=?4",params![SLOT,generation,bytes,expected]).map_err(db)?};
            if changed!=1 {return Err(bad());}
            Ok(Selection{generation,selected})
        })
    }
}
