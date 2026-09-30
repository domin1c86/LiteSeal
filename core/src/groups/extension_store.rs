use super::*;
use liteseal_shared::{
    collaboration::{self as c, Member},
    group_extension as e,
};
use std::collections::BTreeMap;
pub(super) const SCHEMA:&str="
CREATE TABLE IF NOT EXISTS local_extension_log(scope TEXT NOT NULL,group_id TEXT NOT NULL,id TEXT NOT NULL,seq INTEGER NOT NULL,object_id TEXT NOT NULL,header TEXT NOT NULL,content BLOB,PRIMARY KEY(scope,group_id,id));
CREATE INDEX IF NOT EXISTS local_extension_object ON local_extension_log(scope,group_id,object_id,seq);
CREATE TABLE IF NOT EXISTS local_extension_cursor(scope TEXT NOT NULL,group_id TEXT NOT NULL,joined INTEGER NOT NULL,position INTEGER NOT NULL,PRIMARY KEY(scope,group_id,joined));
CREATE TABLE IF NOT EXISTS local_extension_outbox(scope TEXT NOT NULL,group_id TEXT NOT NULL,id TEXT NOT NULL,body TEXT NOT NULL,status TEXT NOT NULL,PRIMARY KEY(scope,group_id,id));
CREATE UNIQUE INDEX IF NOT EXISTS local_extension_one_queued ON local_extension_outbox(scope,group_id) WHERE status='queued';
";
#[derive(Clone, Serialize)]
pub struct ExtensionAttachmentView {
    pub id: String,
    pub blob: String,
    pub name: String,
    pub size: u64,
    pub mime: String,
    pub duration_ms: Option<u32>,
}
#[derive(Serialize)]
pub struct ActivityView {
    pub id: String,
    pub creator: String,
    pub title: String,
    pub start_at: i64,
    pub timezone: String,
    pub location: String,
    pub description: String,
    pub responses: BTreeMap<String, e::Answer>,
    pub participants: Vec<String>,
    pub departed: Vec<String>,
    pub closed: bool,
    pub cancelled: bool,
    pub eligible: bool,
    pub can_manage: bool,
    pub revision: u64,
}
#[derive(Serialize)]
pub struct ExtensionView {
    pub attachments: Vec<ExtensionAttachmentView>,
    pub activities: Vec<ActivityView>,
    pub pending: bool,
    pub conflict: bool,
    pub pending_root: Option<String>,
}
pub(super) fn replay(
    conn: &Connection,
    scope: &str,
    id: &str,
    object: &str,
) -> Result<Option<e::Object>, String> {
    let mut q=conn.prepare("SELECT header FROM local_extension_log WHERE scope=?1 AND group_id=?2 AND object_id=?3 ORDER BY seq").map_err(db)?;
    let rows = q
        .query_map(params![scope, id, object], |r| r.get::<_, String>(0))
        .map_err(db)?;
    let mut previous = None;
    for row in rows {
        let event: e::Event = parse(&row.map_err(db)?)?;
        let historical = state(conn, scope, id, Some(event.epoch))?;
        previous =
            Some(e::transition(previous.as_ref(), &historical, &event).map_err(|_| invalid())?);
    }
    Ok(previous)
}
fn content(
    conn: &Connection,
    scope: &str,
    id: &str,
    event: &str,
    keys: &crypto::KeyPair,
) -> Result<Option<e::Content>, String> {
    let body: Option<Option<Vec<u8>>> = conn
        .query_row(
            "SELECT content FROM local_extension_log WHERE scope=?1 AND group_id=?2 AND id=?3",
            params![scope, id, event],
            |r| r.get(0),
        )
        .optional()
        .map_err(db)?;
    body.flatten()
        .map(|b| {
            let (domain, s, g, ev, content): (String, String, String, String, e::Content) =
                parse(&String::from_utf8(opened(keys, &b)?).map_err(|_| invalid())?)?;
            if domain != "group-extension-local/v1" || s != scope || g != id || ev != event {
                return Err(invalid());
            }
            Ok(content)
        })
        .transpose()
}
fn visible(conn: &Connection, scope: &str, id: &str, object: &str) -> Result<bool, String> {
    conn.query_row("SELECT EXISTS(SELECT 1 FROM local_group_messages m WHERE m.scope=?1 AND m.group_id=?2 AND m.message_id=?3 AND m.status IN ('accepted','received','seen') AND NOT EXISTS(SELECT 1 FROM local_group_hidden h WHERE h.scope=m.scope AND h.group_id=m.group_id AND h.message_id=m.message_id))",params![scope,id,object],|r|r.get(0)).map_err(db)
}
fn verify_root(
    conn: &Connection,
    scope: &str,
    id: &str,
    event: &e::Event,
    identity: &GroupIdentity,
) -> Result<(), String> {
    if !event.action.creates() {
        return Ok(());
    }
    let root:Option<Option<String>>=conn.query_row("SELECT envelope FROM local_group_messages WHERE scope=?1 AND group_id=?2 AND message_id=?3",params![scope,id,event.object],|r|r.get(0)).optional().map_err(db)?;
    if let Some(Some(body)) = root {
        let root: GroupEnvelope = parse(&body)?;
        if root.sender_user_id != event.actor.user
            || root.sender_device_id != event.actor.device
            || !event.roots.iter().any(|r| {
                r.member.user == identity.user_id
                    && r.member.device == identity.device_id
                    && r.hash == e::root_hash(&root)
            })
        {
            return Err(invalid());
        }
    }
    Ok(())
}
fn apply_into(
    tx: &Transaction<'_>,
    scope: &str,
    id: &str,
    identity: &GroupIdentity,
    delivery: &e::Delivery,
    keys: &crypto::KeyPair,
) -> Result<(), String> {
    let event = &delivery.event;
    if event.group != id || delivery.seq < 1 {
        return Err(invalid());
    }
    let stored: Option<String> = tx
        .query_row(
            "SELECT header FROM local_extension_log WHERE scope=?1 AND group_id=?2 AND id=?3",
            params![scope, id, event.id],
            |r| r.get(0),
        )
        .optional()
        .map_err(db)?;
    if let Some(stored) = stored {
        if stored != json(event)? {
            return Err(invalid());
        }
        return Ok(());
    }
    let historical = state(tx, scope, id, Some(event.epoch))?;
    let previous = replay(tx, scope, id, &event.object)?;
    e::transition(previous.as_ref(), &historical, event).map_err(|_| invalid())?;
    verify_root(tx, scope, id, event, identity)?;
    let me = Member {
        user: identity.user_id.clone(),
        device: identity.device_id.clone(),
        joined: historical
            .member(&identity.user_id)
            .filter(|m| m.identity == *identity)
            .map_or(0, |m| m.joined_epoch),
    };
    let plain = if let Some(cipher) = &delivery.ciphertext {
        let slot = event
            .slots
            .iter()
            .find(|s| s.member == me)
            .ok_or_else(invalid)?;
        if !(40..=8192).contains(&cipher.len()) || slot.hash != c::digest(cipher) {
            return Err(invalid());
        }
        let actor = historical.member(&event.actor.user).ok_or_else(invalid)?;
        let pk = actor
            .identity
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| invalid())?;
        let plain: e::Content = serde_json::from_slice(
            &crypto::decrypt(cipher, &pk, &keys.secret_key).map_err(|_| invalid())?,
        )
        .map_err(|_| invalid())?;
        e::validate_content(event, &plain).map_err(|_| invalid())?;
        Some(sealed(
            keys,
            json(&("group-extension-local/v1", scope, id, &event.id, &plain))?.as_bytes(),
        )?)
    } else {
        None
    };
    tx.execute(
        "INSERT INTO local_extension_log VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![
            scope,
            id,
            event.id,
            delivery.seq,
            event.object,
            json(event)?,
            plain
        ],
    )
    .map_err(db)?;
    Ok(())
}
impl GroupStore {
    fn checked_extension_task(&self, id: &str, body: &str) -> Result<e::Submission, String> {
        let task: e::Submission = parse(body)?;
        if task.event.group != id
            || task.event.actor.user != self.identity.user_id
            || task.event.actor.device != self.identity.device_id
        {
            return Err(invalid());
        }
        let group = state(&self.conn, &self.scope, id, Some(task.event.epoch))?;
        e::validate_submission(&group, &task).map_err(|_| invalid())?;
        Ok(task)
    }
    pub fn extension_object(&self, id: &str, object: &str) -> Result<Option<e::Object>, String> {
        replay(&self.conn, &self.scope, id, object)
    }
    pub fn extension_pending(&self, id: &str) -> Result<Option<e::Submission>, String> {
        let body:Option<String>=self.conn.query_row("SELECT body FROM local_extension_outbox WHERE scope=?1 AND group_id=?2 AND status='queued'",params![self.scope,id],|r|r.get(0)).optional().map_err(db)?;
        body.map(|body| self.checked_extension_task(id, &body))
            .transpose()
    }
    pub fn extension_conflicted(&self, id: &str) -> Result<bool, String> {
        self.conn.query_row("SELECT EXISTS(SELECT 1 FROM local_extension_outbox WHERE scope=?1 AND group_id=?2 AND status='conflict')",params![self.scope,id],|r|r.get(0)).map_err(db)
    }
    pub fn extension_conflict(&mut self, id: &str, event: &str) -> Result<(), String> {
        self.conn.execute("UPDATE local_extension_outbox SET status='conflict' WHERE scope=?1 AND group_id=?2 AND id=?3",params![self.scope,id,event]).map_err(db)?;
        Ok(())
    }
    pub fn extension_task(&self, id: &str) -> Result<Option<e::Submission>, String> {
        let body:Option<String>=self.conn.query_row("SELECT body FROM local_extension_outbox WHERE scope=?1 AND group_id=?2 AND status IN ('queued','conflict') ORDER BY rowid LIMIT 1",params![self.scope,id],|r|r.get(0)).optional().map_err(db)?;
        body.map(|body| self.checked_extension_task(id, &body))
            .transpose()
    }
    pub fn extension_queue(&mut self, submission: &e::Submission) -> Result<(), String> {
        let id = &submission.event.group;
        if self.extension_task(id)?.is_some() {
            return Err("请先处理原群扩展任务".into());
        }
        let group = self.state(id)?;
        e::validate_submission(&group, submission).map_err(|_| invalid())?;
        e::transition(
            self.extension_object(id, &submission.event.object)?
                .as_ref(),
            &group,
            &submission.event,
        )
        .map_err(|_| invalid())?;
        self.conn
            .execute(
                "INSERT INTO local_extension_outbox VALUES(?1,?2,?3,?4,'queued')",
                params![self.scope, id, submission.event.id, json(submission)?],
            )
            .map_err(db)?;
        Ok(())
    }
    pub fn extension_accepted(
        &mut self,
        id: &str,
        submission: &e::Submission,
        receipt: &e::Receipt,
        keys: &crypto::KeyPair,
    ) -> Result<(), String> {
        if receipt.event_id != submission.event.id
            || receipt.hash != submission.event.hash()
            || receipt.seq < 1
            || receipt.root.is_some() != submission.event.action.creates()
        {
            return Err(invalid());
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db)?;
        if let Some(root) = &receipt.root {
            accepted_into(&tx, &self.scope, id, &self.identity, root)?;
        }
        let cipher = submission
            .boxes
            .iter()
            .find(|b| {
                b.member.user == self.identity.user_id && b.member.device == self.identity.device_id
            })
            .map(|b| b.ciphertext.clone());
        apply_into(
            &tx,
            &self.scope,
            id,
            &self.identity,
            &e::Delivery {
                seq: receipt.seq,
                event: submission.event.clone(),
                ciphertext: cipher,
            },
            keys,
        )?;
        tx.execute("UPDATE local_extension_outbox SET status='accepted' WHERE scope=?1 AND group_id=?2 AND id=?3",params![self.scope,id,submission.event.id]).map_err(db)?;
        tx.commit().map_err(db)
    }
    pub fn extension_cancelled(
        &mut self,
        id: &str,
        submission: &e::Submission,
    ) -> Result<(), String> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db)?;
        if submission.event.action.creates() {
            tx.execute("UPDATE local_group_outbox SET status='cancelled' WHERE scope=?1 AND group_id=?2 AND message_id=?3 AND status='queued'",params![self.scope,id,submission.event.object]).map_err(db)?;
            tx.execute("UPDATE local_group_messages SET status='cancelled' WHERE scope=?1 AND group_id=?2 AND message_id=?3 AND status='queued'",params![self.scope,id,submission.event.object]).map_err(db)?;
        }
        tx.execute("UPDATE local_extension_outbox SET status='cancelled' WHERE scope=?1 AND group_id=?2 AND id=?3",params![self.scope,id,submission.event.id]).map_err(db)?;
        tx.commit().map_err(db)
    }
    pub fn extension_cursor(&self, id: &str) -> Result<i64, String> {
        let group = self.state(id)?;
        let joined = group
            .member(&self.identity.user_id)
            .ok_or_else(invalid)?
            .joined_epoch;
        Ok(self.conn.query_row("SELECT position FROM local_extension_cursor WHERE scope=?1 AND group_id=?2 AND joined=?3",params![self.scope,id,joined],|r|r.get(0)).optional().map_err(db)?.unwrap_or(0))
    }
    pub fn extension_apply(
        &mut self,
        id: &str,
        page: &e::Page,
        keys: &crypto::KeyPair,
    ) -> Result<usize, String> {
        let old = self.extension_cursor(id)?;
        if page.items.len() > 100
            || page.cursor < old
            || page.items.last().map_or(old, |item| item.seq) != page.cursor
            || page.more && page.items.is_empty()
        {
            return Err(invalid());
        }
        let current = self.state(id)?;
        let joined = current
            .member(&self.identity.user_id)
            .filter(|m| m.identity == self.identity && !current.closed())
            .ok_or_else(invalid)?
            .joined_epoch;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db)?;
        let mut last = old;
        for delivery in &page.items {
            if delivery.seq <= last {
                return Err(invalid());
            }
            apply_into(&tx, &self.scope, id, &self.identity, delivery, keys)?;
            last = delivery.seq;
        }
        tx.execute("INSERT INTO local_extension_cursor VALUES(?1,?2,?3,?4) ON CONFLICT(scope,group_id,joined) DO UPDATE SET position=excluded.position",params![self.scope,id,joined,page.cursor]).map_err(db)?;
        tx.commit().map_err(db)?;
        Ok(page.items.len())
    }
    pub fn extension_root_check(&self, root: &GroupEnvelope) -> Result<(), String> {
        let mut q=self.conn.prepare("SELECT header FROM local_extension_log WHERE scope=?1 AND group_id=?2 AND object_id=?3 AND content IS NOT NULL ORDER BY seq LIMIT 1").map_err(db)?;
        let header: Option<String> = q
            .query_row(params![self.scope, root.group_id, root.message_id], |r| {
                r.get(0)
            })
            .optional()
            .map_err(db)?;
        if let Some(header) = header {
            let event: e::Event = parse(&header)?;
            if event.action.creates()
                && !event.roots.iter().any(|h| {
                    h.member.user == root.recipient_user_id
                        && h.member.device == root.recipient_device_id
                        && h.member.joined == root.recipient_join_epoch
                        && h.hash == e::root_hash(root)
                })
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
    pub fn extension_attachment(
        &self,
        id: &str,
        object: &str,
        keys: &crypto::KeyPair,
    ) -> Result<e::Attachment, String> {
        if !visible(&self.conn, &self.scope, id, object)? {
            return Err("群附件原消息不可用".into());
        }
        self.extension_attachment_unchecked(id, object, keys)
    }
    pub(in crate::groups) fn extension_attachment_unchecked(
        &self,
        id: &str,
        object: &str,
        keys: &crypto::KeyPair,
    ) -> Result<e::Attachment, String> {
        let event:Option<String>=self.conn.query_row("SELECT id FROM local_extension_log WHERE scope=?1 AND group_id=?2 AND object_id=?3 AND content IS NOT NULL ORDER BY seq LIMIT 1",params![self.scope,id,object],|r|r.get(0)).optional().map_err(db)?;
        match event
            .map(|ev| content(&self.conn, &self.scope, id, &ev, keys))
            .transpose()?
            .flatten()
        {
            Some(e::Content::Attachment(a)) => Ok(a),
            _ => Err("群附件详情尚未取得".into()),
        }
    }
    pub fn extension_view(
        &self,
        id: &str,
        ids: &[String],
        keys: &crypto::KeyPair,
    ) -> Result<ExtensionView, String> {
        if ids.len() > 100 {
            return Err("群扩展详情每次最多 100 条".into());
        }
        let current = self.state(id)?;
        let members = c::members(&current);
        let me = current.member(&self.identity.user_id).map(Member::from);
        let mut result = ExtensionView {
            attachments: vec![],
            activities: vec![],
            pending: self.extension_pending(id)?.is_some(),
            conflict: self.extension_conflicted(id)?,
            pending_root: self
                .extension_task(id)?
                .filter(|s| s.event.action.creates())
                .map(|s| s.event.object),
        };
        for object in ids {
            if !visible(&self.conn, &self.scope, id, object)? {
                continue;
            }
            let event:Option<String>=self.conn.query_row("SELECT id FROM local_extension_log WHERE scope=?1 AND group_id=?2 AND object_id=?3 AND content IS NOT NULL ORDER BY seq LIMIT 1",params![self.scope,id,object],|r|r.get(0)).optional().map_err(db)?;
            let Some(event) = event else {
                continue;
            };
            let Some(content) = content(&self.conn, &self.scope, id, &event, keys)? else {
                continue;
            };
            let state = self.extension_object(id, object)?.ok_or_else(invalid)?;
            match content {
                e::Content::Attachment(a) => result.attachments.push(ExtensionAttachmentView {
                    id: object.clone(),
                    blob: a.blob,
                    name: a.name,
                    size: a.size,
                    mime: a.mime,
                    duration_ms: a.duration_ms,
                }),
                e::Content::Activity(a) => {
                    let eligible = !current.closed()
                        && me.as_ref().is_some_and(|m| state.audience.contains(m));
                    let can_manage = !current.closed()
                        && me
                            .as_ref()
                            .is_some_and(|m| *m == state.creator || m.user == current.owner());
                    let departed = state
                        .audience
                        .iter()
                        .filter(|m| !members.contains(m))
                        .map(|m| m.user.clone())
                        .collect();
                    result.activities.push(ActivityView {
                        id: object.clone(),
                        creator: state.creator.user,
                        title: a.title,
                        start_at: a.start_at,
                        timezone: a.timezone,
                        location: a.location,
                        description: a.description,
                        responses: state.responses,
                        participants: state.audience.iter().map(|m| m.user.clone()).collect(),
                        departed,
                        closed: state.closed,
                        cancelled: state.cancelled,
                        eligible,
                        can_manage,
                        revision: state.revision,
                    });
                }
            }
        }
        Ok(result)
    }
    pub fn extension_validate(&self, id: &str, keys: &crypto::KeyPair) -> Result<(), String> {
        let mut q=self.conn.prepare("SELECT id,header FROM local_extension_log WHERE scope=?1 AND group_id=?2 ORDER BY seq").map_err(db)?;
        let rows = q
            .query_map(params![self.scope, id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })
            .map_err(db)?;
        for row in rows {
            let (ev, header) = row.map_err(db)?;
            let event: e::Event = parse(&header)?;
            if event.id != ev || event.group != id {
                return Err(invalid());
            }
            let state = state(&self.conn, &self.scope, id, Some(event.epoch))?;
            event.verify(&state).map_err(|_| invalid())?;
            self.extension_object(id, &event.object)?
                .ok_or_else(invalid)?;
            verify_root(&self.conn, &self.scope, id, &event, &self.identity)?;
            if let Some(content) = content(&self.conn, &self.scope, id, &ev, keys)? {
                e::validate_content(&event, &content).map_err(|_| invalid())?;
            }
        }
        Ok(())
    }
}
