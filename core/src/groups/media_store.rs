use super::super::media::{Cache, GroupAttachmentTask};
use super::*;
use liteseal_shared::group_extension as e;
impl GroupStore {
    #[allow(clippy::too_many_arguments)]
    pub fn media_cache_verify_row(
        &self,
        id: &str,
        root: &str,
        blob: &str,
        metadata: &[u8],
        ciphertext: &[u8],
        offset: usize,
        keys: &crypto::KeyPair,
    ) -> Result<(), String> {
        let (domain, scope, group, stored, d): (String, String, String, String, e::Attachment) =
            serde_json::from_slice(&opened(keys, metadata)?).map_err(|_| invalid())?;
        if domain != "group-attachment-local/v1"
            || scope != self.scope
            || group != id
            || stored != blob
            || offset != ciphertext.len()
            || d != self.extension_attachment_unchecked(id, root, keys)?
            || ciphertext.len() != d.size as usize + 40
            || liteseal_shared::collaboration::digest(ciphertext) != d.hash
        {
            return Err(invalid());
        }
        let plain = crypto::decrypt_attachment(ciphertext, &d.key).map_err(|_| invalid())?;
        if plain.len() != d.size as usize {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn media_archive_verify(
        &self,
        id: &str,
        blob: &str,
        keys: &crypto::KeyPair,
    ) -> Result<e::Attachment, String> {
        let item = self.media_load(blob, keys)?;
        if item.group != id || item.direction != "download" || item.offset != item.ciphertext.len()
        {
            return Err("群缓存未完成".into());
        }
        let d = self.extension_attachment_unchecked(id, &item.root, keys)?;
        if item.descriptor.as_ref() != Some(&d) {
            return Err(invalid());
        }
        item.plain()?;
        Ok(d)
    }
    pub fn media_archive_read(
        &self,
        id: &str,
        object: &str,
        keys: &crypto::KeyPair,
    ) -> Result<(e::Attachment, Vec<u8>), String> {
        let d = self.extension_attachment(id, object, keys)?;
        self.media_archive_verify(id, &d.blob, keys)?;
        let item = self.media_load(&d.blob, keys)?;
        Ok((d, item.plain()?))
    }
    pub(in crate::groups) fn media_load(
        &self,
        blob: &str,
        keys: &crypto::KeyPair,
    ) -> Result<Cache, String> {
        let mut item=self.conn.query_row("SELECT group_id,id,joined,metadata,ciphertext,offset,direction,root FROM group_attachment_cache WHERE scope=?1 AND id=?2",params![self.scope,blob],|r|Ok(Cache{group:r.get(0)?,id:r.get(1)?,joined:r.get(2)?,metadata:r.get(3)?,ciphertext:r.get(4)?,offset:r.get(5)?,direction:r.get(6)?,root:r.get(7)?,descriptor:None})).map_err(db)?;
        let (domain, scope, group, id, d): (String, String, String, String, e::Attachment) =
            serde_json::from_slice(&opened(keys, &item.metadata)?).map_err(|_| invalid())?;
        if domain != "group-attachment-local/v1"
            || scope != self.scope
            || group != item.group
            || id != item.id
            || d.blob != item.id
            || d.size > e::MAX_FILE as u64
            || d.key.len() != 32
            || item.offset > d.size as usize + 40
            || item.ciphertext.len() > d.size as usize + 40
        {
            return Err(invalid());
        }
        item.descriptor = Some(d);
        Ok(item)
    }
    pub(in crate::groups) fn media_save(&mut self, item: &Cache) -> Result<(), String> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db)?;
        let previous:i64=tx.query_row("SELECT COALESCE((SELECT length(ciphertext) FROM group_attachment_cache WHERE scope=?1 AND id=?2),0)",params![self.scope,item.id],|r|r.get(0)).map_err(db)?;
        if crate::attachment_cache::bytes(&tx, &self.identity.user_id).map_err(db)? - previous
            + item.ciphertext.len() as i64
            > 256 * 1024 * 1024
        {
            return Err("附件共享缓存上限 256 MiB".into());
        }
        tx.execute("INSERT INTO group_attachment_cache VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) ON CONFLICT(scope,id) DO UPDATE SET ciphertext=excluded.ciphertext,offset=excluded.offset,direction=excluded.direction,root=excluded.root",params![self.scope,self.identity.user_id,item.group,item.id,item.joined,item.metadata,item.ciphertext,item.offset,item.direction,item.root]).map_err(db)?;
        tx.commit().map_err(db)
    }
    pub(in crate::groups) fn media_stage(
        &mut self,
        id: &str,
        bytes: &[u8],
        name: String,
        mime: String,
        duration_ms: Option<u32>,
        keys: &crypto::KeyPair,
    ) -> Result<GroupAttachmentTask, String> {
        let g = self.state(id)?;
        let me = g
            .member(&self.identity.user_id)
            .filter(|m| m.identity == self.identity && !g.closed())
            .ok_or("本机不在此群中")?;
        if bytes.len() > e::MAX_FILE
            || name.is_empty()
            || name.chars().count() > 160
            || name.chars().any(char::is_control)
            || duration_ms.is_some_and(|d| !(1..=60000).contains(&d) || mime != "audio/webm")
        {
            return Err("群附件格式、大小或时长无效".into());
        }
        let (ciphertext, key) = crypto::encrypt_attachment(bytes).map_err(|_| invalid())?;
        let blob = uuid::Uuid::new_v4().to_string();
        let d = e::Attachment {
            version: 1,
            blob: blob.clone(),
            name,
            size: bytes.len() as u64,
            mime,
            duration_ms,
            key,
            hash: liteseal_shared::collaboration::digest(&ciphertext),
        };
        let metadata = sealed(
            keys,
            &serde_json::to_vec(&("group-attachment-local/v1", &self.scope, id, &blob, &d))
                .map_err(|_| invalid())?,
        )?;
        let item = Cache {
            group: id.into(),
            id: blob,
            joined: me.joined_epoch,
            metadata,
            ciphertext,
            offset: 0,
            direction: "upload".into(),
            root: "".into(),
            descriptor: Some(d),
        };
        self.media_save(&item)?;
        Ok(item.view())
    }
    pub(in crate::groups) fn media_tasks(
        &self,
        id: &str,
        keys: &crypto::KeyPair,
    ) -> Result<Vec<GroupAttachmentTask>, String> {
        let mut q=self.conn.prepare("SELECT id FROM group_attachment_cache WHERE scope=?1 AND group_id=?2 AND direction='upload'").map_err(db)?;
        let result = q
            .query_map(params![self.scope, id], |r| r.get::<_, String>(0))
            .map_err(db)?
            .map(|r| Ok(self.media_load(&r.map_err(db)?, keys)?.view()))
            .collect();
        result
    }
    pub(in crate::groups) fn media_remove(&mut self, blob: &str) -> Result<(), String> {
        self.conn
            .execute(
                "DELETE FROM group_attachment_cache WHERE scope=?1 AND id=?2",
                params![self.scope, blob],
            )
            .map_err(db)?;
        Ok(())
    }
    pub fn media_clear(&mut self, id: Option<&str>) -> Result<usize, String> {
        self.conn.execute("DELETE FROM group_attachment_cache WHERE scope=?1 AND direction='download' AND (?2 IS NULL OR group_id=?2)",params![self.scope,id]).map_err(db)
    }
    pub(in crate::groups) fn media_original(
        &self,
        id: &str,
        blob: &str,
    ) -> Result<Option<(e::Submission, String)>, String> {
        let mut q=self.conn.prepare("SELECT body,status FROM local_extension_outbox WHERE scope=?1 AND group_id=?2 ORDER BY rowid DESC").map_err(db)?;
        let rows = q
            .query_map(params![self.scope, id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })
            .map_err(db)?;
        for row in rows {
            let (body, status) = row.map_err(db)?;
            let sub: e::Submission = parse(&body)?;
            if matches!(&sub.event.action,e::Action::Attachment{blob:existing,..} if existing==blob)
            {
                return Ok(Some((sub, status)));
            }
        }
        Ok(None)
    }
    pub(in crate::groups) fn media_download(
        &mut self,
        id: &str,
        object: &str,
        keys: &crypto::KeyPair,
    ) -> Result<GroupAttachmentTask, String> {
        let d = self.extension_attachment(id, object, keys)?;
        if let Ok(item) = self.media_load(&d.blob, keys) {
            if item.group != id || item.descriptor.as_ref() != Some(&d) {
                return Err(invalid());
            }
            return Ok(item.view());
        }
        let metadata = sealed(
            keys,
            &serde_json::to_vec(&("group-attachment-local/v1", &self.scope, id, &d.blob, &d))
                .map_err(|_| invalid())?,
        )?;
        let item = Cache {
            group: id.into(),
            id: d.blob.clone(),
            joined: 0,
            metadata,
            ciphertext: vec![],
            offset: 0,
            direction: "download".into(),
            root: object.into(),
            descriptor: Some(d),
        };
        self.media_save(&item)?;
        Ok(item.view())
    }
}
