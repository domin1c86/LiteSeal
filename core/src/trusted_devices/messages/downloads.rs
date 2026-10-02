//! Downloaded ciphertext is never readable until the original visible signed
//! descriptor authenticates the complete object. Prefix hashes only protect
//! local persistence; they do not authenticate remote media on their own.
use super::*;
use rusqlite::OptionalExtension;
#[cfg(test)]
#[path = "downloads_tests.rs"]
mod tests;

#[derive(Debug, Serialize)]
pub struct Info {
    pub id: String,
    pub peer: String,
    pub kind: Kind,
    pub name: String,
    pub mime: String,
    pub size: u64,
    pub duration_ms: Option<u32>,
    pub cache: Option<Phase>,
}
fn visible(
    conn: &Connection,
    owner: &Owner,
    id: &str,
    keys: &KeyPair,
) -> Result<(Batch, Descriptor), String> {
    let hidden: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM direct_v3_hidden WHERE scope=?1 AND id=?2)",
            params![owner.scope(), id],
            |r| r.get(0),
        )
        .map_err(db)?;
    if hidden {
        return Err("原媒体消息已在本机隐藏".into());
    }
    if super::super::operations::retracted(conn, owner, id, keys)? {
        return Err("原媒体消息已撤回".into());
    }
    let row = super::super::record(conn, &owner.scope(), id)?.ok_or_else(invalid)?;
    let (batch, local) = super::super::checked_record(conn, owner, &row, keys)?;
    if row.outcome != "processed" {
        return Err("原媒体消息未认证，不能读取附件".into());
    }
    let descriptor = Descriptor::from_body(&batch.header, &local.body).map_err(|_| invalid())?;
    Ok((batch, descriptor))
}
fn same_descriptor(job: &Job, batch: &Batch, descriptor: &Descriptor) -> Result<(), String> {
    let expected = Zeroizing::new(
        descriptor
            .to_body(batch.header.kind)
            .map_err(|_| invalid())?,
    );
    let actual = Zeroizing::new(job.descriptor.to_body(job.kind).map_err(|_| invalid())?);
    if job.kind != batch.header.kind || *actual != *expected {
        return Err("媒体缓存与原消息不匹配".into());
    }
    Ok(())
}
fn original_authority(conn: &Connection, owner: &Owner, batch: &Batch) -> Result<[u8; 32], String> {
    let (sender, peer) = super::super::evidence(conn, batch)?;
    owner.member(if batch.header.sender == owner.account {
        &sender
    } else {
        &peer
    })
}
fn admitted(conn: &Connection, owner: &Owner, job: &Job, keys: &KeyPair) -> Result<(), String> {
    let (batch, descriptor) = visible(conn, owner, &job.id, keys)?;
    same_descriptor(job, &batch, &descriptor)?;
    if job.authority != original_authority(conn, owner, &batch)?
        || job.authority != owner.member(&current(conn, &owner.origin, &owner.account)?)?
    {
        return Err("原媒体设备授权已变化，不能继续远端下载".into());
    }
    Ok(())
}
pub(in crate::trusted_devices::messages) fn hidden(
    conn: &Connection,
    owner: &Owner,
    id: &str,
    keys: &KeyPair,
) -> Result<(), String> {
    let exists:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM device_control_tasks WHERE scope=?1 AND id=?2 AND kind=?3)",params![scope(owner),id,KIND],|r|r.get(0)).map_err(db)?;
    if !exists {
        return Ok(());
    }
    let mut job = load(conn, owner, id, keys)?;
    if job.phase == Phase::Downloading {
        let revision = job.revision;
        job.phase = Phase::Cancelled;
        save(conn, owner, &mut job, revision, keys)?;
    }
    Ok(())
}
impl Store {
    pub fn media_info(&mut self, id: &str, keys: &KeyPair) -> Result<Info, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.read_checked(|conn| {
            let (batch, descriptor) = visible(conn, &owner, id, keys)?;
            let kind: Option<String> = conn
                .query_row(
                    "SELECT kind FROM device_control_tasks WHERE scope=?1 AND id=?2",
                    params![scope(&owner), id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(db)?;
            let cache = if kind.as_deref() == Some(KIND) {
                let job = load(conn, &owner, id, keys)?;
                same_descriptor(&job, &batch, &descriptor)?;
                Some(job.phase)
            } else {
                None
            };
            let peer = if batch.header.sender == owner.account {
                batch.header.peer
            } else {
                batch.header.sender
            };
            Ok(Info {
                id: id.into(),
                peer,
                kind: batch.header.kind,
                name: descriptor.name.clone(),
                mime: descriptor.mime.clone(),
                size: descriptor.size,
                duration_ms: descriptor.duration_ms,
                cache,
            })
        })
    }
    /// Explicit business action. It never creates a message or downloads by
    /// itself, and cannot use a stale/hidden row as an attachment key source.
    pub fn start_media_download(&mut self, id: &str, keys: &KeyPair) -> Result<View, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        let mut job = self.trust.read_checked(|conn| {
            let (batch, descriptor) = visible(conn, &owner, id, keys)?;
            let existing: Option<(u64, String)> = conn
                .query_row(
                    "SELECT revision,kind FROM device_control_tasks WHERE scope=?1 AND id=?2",
                    params![scope(&owner), id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(db)?;
            if let Some((_, kind)) = &existing {
                if kind == KIND {
                    let job = load(conn, &owner, id, keys)?;
                    same_descriptor(&job, &batch, &descriptor)?;
                    if matches!(
                        job.phase,
                        Phase::Cached | Phase::Downloading | Phase::Prepared
                    ) {
                        return Ok(job);
                    }
                    if !job.download {
                        return Err("原媒体暂存/发送任务不能改为下载".into());
                    }
                } else if kind != "direct_v3_media_done" {
                    return Err(invalid());
                }
            }
            let authority = original_authority(conn, &owner, &batch)?;
            if authority != owner.member(&current(conn, &owner.origin, &owner.account)?)? {
                return Err("原设备授权不能用于本次远端下载".into());
            }
            let peer = if batch.header.sender == owner.account {
                batch.header.peer
            } else {
                batch.header.sender
            };
            Ok(Job {
                domain: "LiteSeal/direct-media-job/v1".into(),
                scope: owner.scope(),
                id: id.into(),
                peer,
                revision: existing.map_or(0, |r| r.0),
                phase: Phase::Downloading,
                kind: batch.header.kind,
                authority,
                descriptor,
                hashes: vec![],
                next: 0,
                download: true,
                reupload: None,
                paused: false,
                requested: true,
            })
        })?;
        if job.phase != Phase::Downloading || !job.hashes.is_empty() {
            return Ok(job.view());
        }
        // Existing revision with an empty prefix may already be downloading.
        let existing = self.trust.read_checked(|conn| {
            conn.query_row(
                "SELECT kind FROM device_control_tasks WHERE scope=?1 AND id=?2",
                params![scope(&owner), id],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .map_err(db)
        })?;
        if existing.as_deref() == Some(KIND) {
            let old = self.media_job(id, keys)?;
            if old.phase == Phase::Downloading {
                return Ok(old.view());
            }
        }
        let revision = job.revision;
        self.trust.write_checked(|conn| {
            validate_cache(conn)?;
            admitted(conn, &owner, &job, keys)?;
            let row: Option<(u64, String)> = conn
                .query_row(
                    "SELECT revision,kind FROM device_control_tasks WHERE scope=?1 AND id=?2",
                    params![scope(&owner), id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(db)?;
            if row.as_ref().map_or(0, |r| r.0) != revision {
                return Err("原下载任务已变化".into());
            }
            if row.is_none() {
                let count: u64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM device_control_tasks WHERE scope=?1 AND kind=?2",
                        params![scope(&owner), KIND],
                        |r| r.get(0),
                    )
                    .map_err(db)?;
                if count >= 128 {
                    return Err("本机媒体任务达到上限".into());
                }
            }
            conn.execute(
                "DELETE FROM direct_v3_media_chunks WHERE scope=?1 AND id=?2",
                params![owner.scope(), id],
            )
            .map_err(db)?;
            save(conn, &owner, &mut job, revision, keys)?;
            Ok(job.view())
        })
    }
    pub(in crate::trusted_devices::messages) fn download_job(
        &mut self,
        id: &str,
        keys: &KeyPair,
    ) -> Result<Job, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.read_checked(|conn| {
            let job = load(conn, &owner, id, keys)?;
            if !job.download || job.phase != Phase::Downloading || job.paused {
                return Err(invalid());
            }
            admitted(conn, &owner, &job, keys)?;
            for part in 0..job.next {
                chunk(conn, &owner, &job, part)?;
            }
            Ok(job)
        })
    }
    /// Cache first, covered prefix second. Full verification failure persists
    /// Failed and exposes no plaintext, even if all chunks arrived successfully.
    pub(in crate::trusted_devices::messages) fn downloaded_chunk(
        &mut self,
        id: &str,
        revision: u64,
        bytes: &[u8],
        keys: &KeyPair,
    ) -> Result<View, String> {
        let mut job = self.download_job(id, keys)?;
        if job.revision != revision {
            return Err(invalid());
        }
        let part = job.next;
        let len = job
            .descriptor
            .reference()
            .map_err(|_| invalid())?
            .chunk_len(part as i32)
            .map_err(|_| invalid())?;
        if bytes.len() != len {
            return Err("下载分块长度不符".into());
        }
        let owner = self.owner.clone();
        self.trust.write_checked(|conn|{
            validate_cache(conn)?;let current=load(conn,&owner,id,keys)?;
            if current.revision!=revision || current.phase!=Phase::Downloading{return Err("下载原任务已变化，拒绝迟到分块".into());}admitted(conn,&owner,&current,keys)?;
            let old:i64=conn.query_row("SELECT COALESCE((SELECT length(ciphertext) FROM direct_v3_media_chunks WHERE scope=?1 AND id=?2 AND part=?3 AND account=?4),0)",params![owner.scope(),id,part as i32,owner.account],|r|r.get(0)).map_err(db)?;
            if crate::attachment_cache::bytes(conn,&owner.account).map_err(db)?-old+bytes.len() as i64>LIMIT{return Err("本机附件缓存达到 256 MiB，下载没有推进".into());}
            conn.execute("INSERT INTO direct_v3_media_chunks(scope,account,id,part,ciphertext) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(scope,id,part) DO UPDATE SET ciphertext=excluded.ciphertext,account=excluded.account",params![owner.scope(),owner.account,id,part as i32,bytes]).map_err(db)?;Ok(())
        })?;
        self.trust.write_checked(|conn| {
            let current = load(conn, &owner, id, keys)?;
            if current.revision != revision || current.phase != Phase::Downloading {
                return Err("下载原任务已变化，拒绝迟到进度".into());
            }
            admitted(conn, &owner, &current, keys)?;
            job.hashes.push(Sha256::digest(bytes).into());
            job.next += 1;
            if job.next == (job.descriptor.size as usize + 40).div_ceil(CHUNK) {
                match ciphertext(conn, &owner, &job).and_then(|cipher| {
                    job.descriptor
                        .decrypt(job.kind, &cipher)
                        .map_err(|_| "附件完整认证失败".into())
                }) {
                    Ok(plain) => {
                        drop(Zeroizing::new(plain));
                        job.phase = Phase::Cached;
                    }
                    Err(_) => {
                        job.phase = Phase::Failed;
                        job.next = 0;
                        job.hashes.clear();
                    }
                }
            }
            save(conn, &owner, &mut job, revision, keys)?;
            Ok(job.view())
        })
    }
    pub(in crate::trusted_devices::messages) fn download_unavailable(
        &mut self,
        id: &str,
        revision: u64,
        keys: &KeyPair,
    ) -> Result<View, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.write_checked(|conn| {
            let mut job = load(conn, &owner, id, keys)?;
            if job.revision != revision || job.phase != Phase::Downloading {
                return Err(invalid());
            }
            visible(conn, &owner, id, keys)?;
            job.phase = Phase::Unavailable;
            save(conn, &owner, &mut job, revision, keys)?;
            Ok(job.view())
        })
    }
    /// Rust-only authenticated bytes; file keys are neither returned nor logged.
    /// Each read repeats visibility, original descriptor, full hash and MAC.
    pub fn media_plain(&mut self, id: &str, keys: &KeyPair) -> Result<Zeroizing<Vec<u8>>, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.read_checked(|conn| {
            let (batch, descriptor) = visible(conn, &owner, id, keys)?;
            let job = load(conn, &owner, id, keys)?;
            same_descriptor(&job, &batch, &descriptor)?;
            if job.phase != Phase::Cached
                && !(job.phase == Phase::Prepared
                    && message_state(conn, &owner, id, keys)? == TaskState::Accepted)
            {
                return Err("附件尚未完整认证或已取消".into());
            }
            let bytes = descriptor
                .decrypt(batch.header.kind, &ciphertext(conn, &owner, &job)?)
                .map_err(|_| "附件缓存认证失败".to_string())?;
            Ok(Zeroizing::new(bytes))
        })
    }
}
