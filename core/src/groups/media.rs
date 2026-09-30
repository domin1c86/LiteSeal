use super::*;
use liteseal_shared::group_extension as e;
const CHUNK: usize = 1024 * 1024;
pub(super) struct Cache {
    pub group: String,
    pub id: String,
    pub joined: u64,
    pub metadata: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub offset: usize,
    pub direction: String,
    pub root: String,
    pub descriptor: Option<e::Attachment>,
}
#[derive(Serialize)]
pub struct GroupAttachmentTask {
    pub id: String,
    pub peer_id: String,
    pub message_id: String,
    pub name: String,
    pub size: u64,
    pub mime: String,
    pub duration_ms: Option<u32>,
    pub offset: usize,
    pub total: usize,
    pub direction: String,
}
impl Cache {
    pub fn view(&self) -> GroupAttachmentTask {
        let d = self.descriptor.as_ref().expect("loaded descriptor");
        GroupAttachmentTask {
            id: self.id.clone(),
            peer_id: self.group.clone(),
            message_id: self.root.clone(),
            name: d.name.clone(),
            size: d.size,
            mime: d.mime.clone(),
            duration_ms: d.duration_ms,
            offset: self.offset,
            total: d.size as usize + 40,
            direction: self.direction.clone(),
        }
    }
    pub fn plain(&self) -> Result<Vec<u8>, String> {
        let d = self.descriptor.as_ref().ok_or("缺少群附件描述")?;
        if self.ciphertext.len() != d.size as usize + 40
            || liteseal_shared::collaboration::digest(&self.ciphertext) != d.hash
        {
            return Err("群附件密文不完整或被篡改".into());
        }
        let bytes =
            crypto::decrypt_attachment(&self.ciphertext, &d.key).map_err(|_| "群附件认证失败")?;
        if bytes.len() != d.size as usize {
            return Err("群附件长度无效".into());
        }
        Ok(bytes)
    }
}
impl GroupClient {
    pub fn media_stage(
        &self,
        id: &str,
        bytes: &[u8],
        name: String,
        mime: String,
        duration: Option<u32>,
        keys: &crypto::KeyPair,
    ) -> Result<GroupAttachmentTask, String> {
        check_keys(&self.identity, keys)?;
        self.store()?
            .media_stage(id, bytes, name, mime, duration, keys)
    }
    pub fn media_tasks(
        &self,
        id: &str,
        keys: &crypto::KeyPair,
    ) -> Result<Vec<GroupAttachmentTask>, String> {
        self.store()?.media_tasks(id, keys)
    }
    pub fn media_download(
        &self,
        id: &str,
        object: &str,
        keys: &crypto::KeyPair,
    ) -> Result<GroupAttachmentTask, String> {
        self.store()?.media_download(id, object, keys)
    }
    pub fn media_plain(
        &self,
        id: &str,
        blob: &str,
        keys: &crypto::KeyPair,
    ) -> Result<Vec<u8>, String> {
        let item = self.store()?.media_load(blob, keys)?;
        if item.group != id {
            return Err("群附件任务范围不符".into());
        }
        if item.direction == "download" {
            let descriptor = self.extension_attachment(id, &item.root, keys)?;
            if item.descriptor.as_ref() != Some(&descriptor) {
                return Err("群附件原消息不可见".into());
            }
        }
        item.plain()
    }
    pub fn media_clear(&self, id: Option<&str>) -> Result<usize, String> {
        self.store()?.media_clear(id)
    }
    pub async fn media_step(
        &self,
        id: &str,
        blob: &str,
        keys: &crypto::KeyPair,
    ) -> Result<GroupAttachmentTask, String> {
        let _guard = self.media_gate.lock().await;
        let mut item = self.store()?.media_load(blob, keys)?;
        if item.group != id {
            return Err("群附件任务范围不符".into());
        }
        let d = item.descriptor.as_ref().ok_or("群附件描述无效")?;
        if item.direction == "upload" {
            if item.offset == 0 {
                self.api
                    .media_create(id, blob, item.ciphertext.len())
                    .await
                    .map_err(|e| e.to_string())?;
            }
            if item.offset < item.ciphertext.len() {
                let end = (item.offset + CHUNK).min(item.ciphertext.len());
                let uploaded = self
                    .api
                    .media_upload(
                        id,
                        blob,
                        item.offset / CHUNK,
                        item.ciphertext[item.offset..end].to_vec(),
                    )
                    .await;
                if let Err(error) = uploaded {
                    if error.status == Some(404) {
                        item.offset = 0;
                        self.store()?.media_save(&item)?;
                    }
                    return Err(error.to_string());
                }
                item.offset = end;
                self.store()?.media_save(&item)?;
            }
        } else if item.offset < d.size as usize + 40 {
            let bytes = self
                .api
                .media_download(id, blob, item.offset / CHUNK)
                .await
                .map_err(|e| e.to_string())?;
            if bytes.len() != (d.size as usize + 40 - item.offset).min(CHUNK) {
                return Err("群附件分块长度不符".into());
            }
            item.ciphertext.extend_from_slice(&bytes);
            item.offset += bytes.len();
            if item.offset == d.size as usize + 40 {
                item.plain()?;
            }
            self.store()?.media_save(&item)?;
        }
        Ok(item.view())
    }
    pub async fn media_publish(
        &self,
        id: &str,
        blob: &str,
        keys: &crypto::KeyPair,
    ) -> Result<String, String> {
        let _guard = self.media_gate.lock().await;
        let mut item = self.store()?.media_load(blob, keys)?;
        if item.group != id || item.direction != "upload" || item.offset != item.ciphertext.len() {
            return Err("请先完成此群附件上传".into());
        }
        item.plain()?;
        let original = self.store()?.media_original(id, blob)?;
        let root = if let Some((task, status)) = original {
            if status == "cancelled" {
                return Err("原群附件发送已取消".into());
            }
            if status != "accepted" {
                self.extension_retry(id, keys).await?;
            }
            task.event.object
        } else {
            self.sync(id).await?;
            let g = self.state(id)?;
            if g.member(&self.identity.user_id)
                .is_none_or(|m| m.joined_epoch != item.joined)
            {
                return Err("加入阶段已变化，请取消原附件任务".into());
            }
            self.send_extension_content(
                id,
                &e::Content::Attachment(item.descriptor.clone().ok_or("群附件描述无效")?),
                keys,
            )
            .await?
        };
        item.root = root.clone();
        item.direction = "download".into();
        self.store()?.media_save(&item)?;
        Ok(root)
    }
    pub async fn media_cancel(
        &self,
        id: &str,
        blob: &str,
        keys: &crypto::KeyPair,
    ) -> Result<(), String> {
        let _guard = self.media_gate.lock().await;
        let item = self.store()?.media_load(blob, keys)?;
        if item.group != id {
            return Err("群附件任务范围不符".into());
        }
        let original = self.store()?.media_original(id, blob)?;
        if let Some((_, status)) = original {
            if status == "accepted" {
                return Err("群附件已发送，请清理缓存".into());
            }
            if status != "cancelled" {
                self.extension_cancel_task(id, keys).await?;
            }
        }
        self.store()?.media_remove(blob)
    }
}
