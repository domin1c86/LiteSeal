//! Authenticated task classification, scoped cleanup and physical SQLite accounting.
use super::*;
use std::collections::BTreeMap;
#[derive(Default, Debug, Serialize)]
pub struct PeerStorage {
    pub peer: String,
    pub bytes: u64,
    pub clearable_bytes: u64,
    pub protected_tasks: u64,
    pub clearable_tasks: u64,
}
#[derive(Debug, Serialize)]
pub struct StorageStats {
    pub cache_bytes: u64,
    pub shared_cache_bytes: u64,
    pub limit: u64,
    pub orphan_bytes: u64,
    pub database_allocated: u64,
    pub database_reusable: u64,
    pub disk_bytes: u64,
    pub peers: Vec<PeerStorage>,
}
#[derive(Default, Debug, Serialize)]
pub struct ClearResult {
    pub removed_bytes: u64,
    pub cleared_tasks: u64,
    pub protected_tasks: u64,
}
pub(super) fn job_bytes(conn: &Connection, owner: &Owner, id: &str) -> Result<u64, String> {
    conn.query_row("SELECT COALESCE(SUM(length(ciphertext)),0) FROM direct_v3_media_chunks WHERE scope=?1 AND id=?2",params![owner.scope(),id],|r|r.get(0)).map_err(db)
}
fn jobs(conn: &Connection, owner: &Owner, keys: &KeyPair) -> Result<Vec<Job>, String> {
    let mut query = conn
        .prepare(
            "SELECT id FROM device_control_tasks WHERE scope=?1 AND kind=?2 ORDER BY id LIMIT 129",
        )
        .map_err(db)?;
    let ids = query
        .query_map(params![scope(owner), KIND], |r| r.get::<_, String>(0))
        .map_err(db)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(db)?;
    if ids.len() > 128 {
        return Err(invalid());
    }
    ids.into_iter()
        .map(|id| load(conn, owner, &id, keys))
        .collect()
}
fn orphan_bytes(conn: &Connection, owner: &Owner) -> Result<u64, String> {
    conn.query_row("SELECT COALESCE(SUM(length(ciphertext)),0) FROM direct_v3_media_chunks c WHERE c.scope=?1 AND NOT EXISTS(SELECT 1 FROM device_control_tasks t WHERE t.scope=?2 AND t.id=c.id AND t.kind=?3)",params![owner.scope(),scope(owner),KIND],|r|r.get(0)).map_err(db)
}
impl Store {
    pub fn media_storage_stats(&mut self, keys: &KeyPair) -> Result<StorageStats, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.read_checked(|conn| {
            validate_cache(conn)?;
            let mut peers = BTreeMap::<String, PeerStorage>::new();
            for job in jobs(conn, &owner, keys)? {
                let bytes = job_bytes(conn, &owner, &job.id)?;
                let entry = peers
                    .entry(job.peer.clone())
                    .or_insert_with(|| PeerStorage {
                        peer: job.peer.clone(),
                        ..Default::default()
                    });
                entry.bytes += bytes;
                if clearable(conn, &owner, &job, keys)? {
                    entry.clearable_bytes += bytes;
                    entry.clearable_tasks += 1;
                } else {
                    entry.protected_tasks += 1;
                }
            }
            let orphan_bytes = orphan_bytes(conn, &owner)?;
            let cache_bytes = peers.values().map(|p| p.bytes).sum::<u64>() + orphan_bytes;
            let page_size: u64 = conn
                .query_row("PRAGMA page_size", [], |r| r.get(0))
                .map_err(db)?;
            let pages: u64 = conn
                .query_row("PRAGMA page_count", [], |r| r.get(0))
                .map_err(db)?;
            let free: u64 = conn
                .query_row("PRAGMA freelist_count", [], |r| r.get(0))
                .map_err(db)?;
            let mut disk_bytes = 0;
            if let Some(path) = conn.path() {
                for file in [
                    path.to_string(),
                    format!("{path}-wal"),
                    format!("{path}-shm"),
                ] {
                    match std::fs::metadata(file) {
                        Ok(m) => disk_bytes += m.len(),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(_) => return Err("档案磁盘占用无法读取".into()),
                    }
                }
            }
            Ok(StorageStats {
                cache_bytes,
                shared_cache_bytes: crate::attachment_cache::bytes(conn, &owner.account)
                    .map_err(db)? as u64,
                limit: LIMIT as u64,
                orphan_bytes,
                database_allocated: pages * page_size,
                database_reusable: free * page_size,
                disk_bytes,
                peers: peers.into_values().collect(),
            })
        })
    }
    /// Classify every selected task before deleting any cache. Unknown publication
    /// and active upload/download jobs remain protected, including hidden jobs.
    pub fn clear_media_cache(
        &mut self,
        peer: Option<&str>,
        keys: &KeyPair,
    ) -> Result<ClearResult, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.write_checked(|conn|{
            validate_cache(conn)?;
            let mut result=ClearResult::default();let mut eligible=Vec::new();
            for job in jobs(conn,&owner,keys)? {
                if peer.is_some_and(|p|p!=job.peer){continue;}
                if clearable(conn,&owner,&job,keys)? {eligible.push(job.id);}else{result.protected_tasks+=1;}
            }
            for id in eligible{result.removed_bytes+=clear_job(conn,&owner,&id,keys)?;result.cleared_tasks+=1;}
            if peer.is_none(){
                result.removed_bytes+=orphan_bytes(conn,&owner)?;
                conn.execute("DELETE FROM direct_v3_media_chunks WHERE scope=?1 AND NOT EXISTS(SELECT 1 FROM device_control_tasks t WHERE t.scope=?2 AND t.id=direct_v3_media_chunks.id AND t.kind=?3)",params![owner.scope(),scope(&owner),KIND]).map_err(db)?;
            }
            Ok(result)
        })
    }
}
