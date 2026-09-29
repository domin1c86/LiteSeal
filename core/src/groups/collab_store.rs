use super::*;
use liteseal_shared::collaboration as c;
use std::collections::BTreeMap;

pub(super) const SCHEMA:&str="
CREATE TABLE IF NOT EXISTS local_collab_log(scope TEXT NOT NULL,group_id TEXT NOT NULL,id TEXT NOT NULL,seq INTEGER NOT NULL,object_id TEXT NOT NULL,header TEXT NOT NULL,content BLOB,PRIMARY KEY(scope,group_id,id));
CREATE TABLE IF NOT EXISTS local_collab_cursor(scope TEXT NOT NULL,group_id TEXT NOT NULL,joined INTEGER NOT NULL,position INTEGER NOT NULL,PRIMARY KEY(scope,group_id,joined));
CREATE TABLE IF NOT EXISTS local_collab_outbox(scope TEXT NOT NULL,group_id TEXT NOT NULL,id TEXT NOT NULL,body TEXT NOT NULL,status TEXT NOT NULL,PRIMARY KEY(scope,group_id,id));
CREATE UNIQUE INDEX IF NOT EXISTS local_collab_one_queued ON local_collab_outbox(scope,group_id) WHERE status='queued';
CREATE TABLE IF NOT EXISTS local_collab_ack(scope TEXT NOT NULL,group_id TEXT NOT NULL,id TEXT NOT NULL,PRIMARY KEY(scope,group_id,id));
";
#[derive(Serialize)]
pub struct PollView {
    pub id: String,
    pub creator: String,
    pub question: String,
    pub options: Vec<c::OptionText>,
    pub votes: BTreeMap<String, String>,
    pub departed: Vec<String>,
    pub closed: bool,
    pub eligible: bool,
    pub revision: u64,
}
#[derive(Serialize)]
pub struct CollaborationView {
    pub polls: Vec<PollView>,
    pub pin: Option<String>,
    pub pin_unavailable: bool,
    pub pin_revision: u64,
    pub pending: bool,
    pub conflict: bool,
}
fn replay(
    conn: &Connection,
    scope: &str,
    id: &str,
    object: &str,
) -> Result<Option<c::Object>, String> {
    let mut query=conn.prepare("SELECT header FROM local_collab_log WHERE scope=?1 AND group_id=?2 AND object_id=?3 ORDER BY seq").map_err(db)?;
    let rows = query
        .query_map(params![scope, id, object], |r| r.get::<_, String>(0))
        .map_err(db)?;
    let mut current = None;
    for row in rows {
        let e: c::Event = parse(&row.map_err(db)?)?;
        let group = state(conn, scope, id, Some(e.epoch))?;
        current = Some(c::transition(current.as_ref(), &group, &e).map_err(|_| invalid())?);
    }
    Ok(current)
}
fn content(
    conn: &Connection,
    scope: &str,
    id: &str,
    event: &str,
    keys: &crypto::KeyPair,
) -> Result<Option<c::Content>, String> {
    let bytes: Option<Vec<u8>> = conn
        .query_row(
            "SELECT content FROM local_collab_log WHERE scope=?1 AND group_id=?2 AND id=?3",
            params![scope, id, event],
            |r| r.get(0),
        )
        .optional()
        .map_err(db)?
        .flatten();
    bytes
        .map(|bytes| {
            let (domain, s, g, e, c): (String, String, String, String, c::Content) =
                serde_json::from_slice(&opened(keys, &bytes)?).map_err(|_| invalid())?;
            if domain != "collab-local-v1" || s != scope || g != id || e != event {
                return Err(invalid());
            }
            Ok(c)
        })
        .transpose()
}
fn hidden(conn: &Connection, scope: &str, id: &str, message: &str) -> Result<bool, String> {
    conn.query_row("SELECT EXISTS(SELECT 1 FROM local_group_hidden WHERE scope=?1 AND group_id=?2 AND message_id=?3)",params![scope,id,message],|r|r.get(0)).map_err(db)
}
impl GroupStore {
    pub fn collaboration_object(
        &self,
        id: &str,
        object: &str,
    ) -> Result<Option<c::Object>, String> {
        replay(&self.conn, &self.scope, id, object)
    }
    pub fn collaboration_cursor(&self, id: &str) -> Result<i64, String> {
        let state = self.state(id)?;
        let joined = state
            .member(&self.identity.user_id)
            .ok_or_else(invalid)?
            .joined_epoch;
        Ok(self.conn.query_row("SELECT position FROM local_collab_cursor WHERE scope=?1 AND group_id=?2 AND joined=?3",params![self.scope,id,joined],|r|r.get(0)).optional().map_err(db)?.unwrap_or(0))
    }
    pub fn collaboration_pending(&self, id: &str) -> Result<Option<c::Submission>, String> {
        let body:Option<String>=self.conn.query_row("SELECT body FROM local_collab_outbox WHERE scope=?1 AND group_id=?2 AND status='queued'",params![self.scope,id],|r|r.get(0)).optional().map_err(db)?;
        body.map(|s| parse(&s)).transpose()
    }
    pub fn collaboration_conflicted(&self, id: &str) -> Result<bool, String> {
        self.conn.query_row("SELECT EXISTS(SELECT 1 FROM local_collab_outbox WHERE scope=?1 AND group_id=?2 AND status='conflict')",params![self.scope,id],|r|r.get(0)).map_err(db)
    }
    pub fn collaboration_conflict(&mut self, id: &str, event: &str) -> Result<(), String> {
        self.conn.execute("UPDATE local_collab_outbox SET status='conflict' WHERE scope=?1 AND group_id=?2 AND id=?3 AND status='queued'",params![self.scope,id,event]).map_err(db)?;
        Ok(())
    }
    pub fn collaboration_discard_conflict(&mut self, id: &str) -> Result<(), String> {
        let tx = self.conn.transaction().map_err(db)?;
        tx.execute("UPDATE local_group_messages SET status='cancelled' WHERE scope=?1 AND group_id=?2 AND message_id IN (SELECT id FROM local_collab_outbox WHERE scope=?1 AND group_id=?2 AND status='conflict')",params![self.scope,id]).map_err(db)?;
        tx.execute("UPDATE local_collab_outbox SET status='cancelled' WHERE scope=?1 AND group_id=?2 AND status='conflict'",params![self.scope,id]).map_err(db)?;
        tx.commit().map_err(db)
    }
    pub fn collaboration_queue(
        &mut self,
        submission: &c::Submission,
        plain: Option<&c::Content>,
        keys: &crypto::KeyPair,
    ) -> Result<(), String> {
        check_keys(&self.identity, keys)?;
        let e = &submission.event;
        c::validate_boxes(submission).map_err(|_| invalid())?;
        let group = self.state(&e.group)?;
        let previous = self.collaboration_object(&e.group, &e.object)?;
        c::transition(previous.as_ref(), &group, e).map_err(|_| invalid())?;
        if self.collaboration_pending(&e.group)?.is_some()
            || self.collaboration_conflicted(&e.group)?
        {
            return Err("请先重试或处理已有协作任务".into());
        }
        let tx = self.conn.transaction().map_err(db)?;
        tx.execute("INSERT INTO local_collab_outbox(scope,group_id,id,body,status) VALUES(?1,?2,?3,?4,'queued')",params![self.scope,e.group,e.id,json(submission)?]).map_err(db)?;
        if let Some(plain) = plain {
            c::validate_content(e, plain).map_err(|_| invalid())?;
            save_message(&tx, &self.scope, e, plain, "queued", keys)?;
        }
        tx.commit().map_err(db)
    }
    pub fn collaboration_accepted(&mut self, id: &str, event: &str) -> Result<(), String> {
        let tx = self.conn.transaction().map_err(db)?;
        tx.execute("UPDATE local_collab_outbox SET status='accepted' WHERE scope=?1 AND group_id=?2 AND id=?3",params![self.scope,id,event]).map_err(db)?;
        tx.execute("UPDATE local_group_messages SET status='accepted' WHERE scope=?1 AND group_id=?2 AND message_id=?3 AND status='queued'",params![self.scope,id,event]).map_err(db)?;
        tx.commit().map_err(db)
    }
    pub fn collaboration_acks(&self, id: &str) -> Result<Vec<String>, String> {
        let mut q = self
            .conn
            .prepare("SELECT id FROM local_collab_ack WHERE scope=?1 AND group_id=?2 LIMIT 100")
            .map_err(db)?;
        let rows = q
            .query_map(params![self.scope, id], |r| r.get(0))
            .map_err(db)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db)?;
        Ok(rows)
    }
    pub fn collaboration_acked(&mut self, id: &str, ids: &[String]) -> Result<(), String> {
        let tx = self.conn.transaction().map_err(db)?;
        for item in ids {
            tx.execute(
                "DELETE FROM local_collab_ack WHERE scope=?1 AND group_id=?2 AND id=?3",
                params![self.scope, id, item],
            )
            .map_err(db)?;
        }
        tx.commit().map_err(db)
    }
    pub fn collaboration_apply(
        &mut self,
        id: &str,
        page: &c::Page,
        keys: &crypto::KeyPair,
    ) -> Result<usize, String> {
        check_keys(&self.identity, keys)?;
        if page.items.len() > 100 {
            return Err(invalid());
        }
        let current = self.state(id)?;
        let me = c::Member::from(current.member(&self.identity.user_id).ok_or_else(invalid)?);
        let old_cursor = self.collaboration_cursor(id)?;
        if page.cursor < old_cursor
            || page
                .items
                .last()
                .is_some_and(|last| last.seq != page.cursor)
            || page.items.is_empty() && page.cursor != old_cursor
        {
            return Err(invalid());
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db)?;
        let mut previous_seq = old_cursor;
        let mut candidates = vec![];
        let mut fresh = 0;
        for delivery in &page.items {
            let e = &delivery.event;
            if e.group != id || delivery.seq <= previous_seq {
                return Err(invalid());
            }
            previous_seq = delivery.seq;
            if !matches!(e.action, c::Action::Pin { .. }) && !e.audience.contains(&me) {
                return Err(invalid());
            }
            let group = state(&tx, &self.scope, id, Some(e.epoch))?;
            e.verify(&group).map_err(|_| invalid())?;
            let existing: Option<String> = tx
                .query_row(
                    "SELECT header FROM local_collab_log WHERE scope=?1 AND group_id=?2 AND id=?3",
                    params![self.scope, id, e.id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(db)?;
            if let Some(old) = existing {
                if old != json(e)? {
                    return Err(invalid());
                }
            } else {
                let prior = replay(&tx, &self.scope, id, &e.object)?;
                c::transition(prior.as_ref(), &group, e).map_err(|_| invalid())?;
                let plain = if let Some(cipher) = &delivery.ciphertext {
                    let slot = e
                        .slots
                        .iter()
                        .find(|slot| slot.member == me)
                        .ok_or_else(invalid)?;
                    if c::digest(cipher) != slot.hash {
                        return Err(invalid());
                    }
                    let pk: [u8; 32] = group
                        .member(&e.actor.user)
                        .ok_or_else(invalid)?
                        .identity
                        .public_key
                        .as_slice()
                        .try_into()
                        .map_err(|_| invalid())?;
                    let bytes =
                        crypto::decrypt(cipher, &pk, &keys.secret_key).map_err(|_| invalid())?;
                    let (domain, event_id, plain): (String, String, c::Content) =
                        serde_json::from_slice(&bytes).map_err(|_| invalid())?;
                    if domain != "collab-content-v1" || event_id != e.id {
                        return Err(invalid());
                    }
                    c::validate_content(e, &plain).map_err(|_| invalid())?;
                    Some(plain)
                } else {
                    if e.slots.iter().any(|s| s.member == me) {
                        return Err(invalid());
                    }
                    None
                };
                let local = plain
                    .as_ref()
                    .map(|c| {
                        sealed(
                            keys,
                            json(&("collab-local-v1", &self.scope, id, &e.id, c))?.as_bytes(),
                        )
                    })
                    .transpose()?;
                tx.execute("INSERT INTO local_collab_log(scope,group_id,id,seq,object_id,header,content) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![self.scope,id,e.id,delivery.seq,e.object,json(e)?,local]).map_err(db)?;
                if let Some(plain) = &plain {
                    let own = e.actor.user == self.identity.user_id;
                    save_message(
                        &tx,
                        &self.scope,
                        e,
                        plain,
                        if own { "accepted" } else { "received" },
                        keys,
                    )?;
                    if !own
                        && matches!(e.action, c::Action::Mention | c::Action::Poll { .. })
                        && !hidden(&tx, &self.scope, id, &e.id)?
                    {
                        candidates.push(GroupNotification {
                            group_id: id.into(),
                            message_id: e.id.clone(),
                        });
                    }
                }
                fresh += 1;
            }
            if e.audience.contains(&me) {
                tx.execute(
                    "INSERT OR IGNORE INTO local_collab_ack(scope,group_id,id) VALUES(?1,?2,?3)",
                    params![self.scope, id, e.id],
                )
                .map_err(db)?;
            }
        }
        tx.execute("INSERT INTO local_collab_cursor(scope,group_id,joined,position) VALUES(?1,?2,?3,?4) ON CONFLICT(scope,group_id,joined) DO UPDATE SET position=excluded.position",params![self.scope,id,me.joined,page.cursor]).map_err(db)?;
        tx.commit().map_err(db)?;
        if !self.muted(id)? {
            self.notifications.extend(candidates);
            self.notifications.truncate(20000);
        }
        Ok(fresh)
    }
    pub fn collaboration_view(
        &self,
        id: &str,
        keys: &crypto::KeyPair,
    ) -> Result<CollaborationView, String> {
        check_keys(&self.identity, keys)?;
        let group = self.state(id)?;
        let me = group.member(&self.identity.user_id).map(c::Member::from);
        let mut q=self.conn.prepare("SELECT id,header FROM local_collab_log WHERE scope=?1 AND group_id=?2 ORDER BY seq").map_err(db)?;
        let rows = q
            .query_map(params![self.scope, id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })
            .map_err(db)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db)?;
        let mut polls = vec![];
        let mut pin = None;
        let mut pin_unavailable = false;
        for (event_id, header) in rows {
            let e: c::Event = parse(&header)?;
            if matches!(e.action, c::Action::Poll { .. })
                && !hidden(&self.conn, &self.scope, id, &event_id)?
            {
                let Some(c::Content::Poll { question, options }) =
                    content(&self.conn, &self.scope, id, &event_id, keys)?
                else {
                    continue;
                };
                let p = self
                    .collaboration_object(id, &event_id)?
                    .ok_or_else(invalid)?;
                let departed = p
                    .audience
                    .iter()
                    .filter(|m| {
                        group
                            .member(&m.user)
                            .is_none_or(|current| c::Member::from(current) != **m)
                    })
                    .map(|m| m.user.clone())
                    .collect();
                polls.push(PollView {
                    id: event_id.clone(),
                    creator: p.creator.user,
                    question,
                    options,
                    votes: p.votes,
                    departed,
                    closed: p.closed || group.closed(),
                    eligible: !group.closed()
                        && me.as_ref().is_some_and(|m| p.audience.contains(m)),
                    revision: p.revision,
                });
            }
            if let c::Action::Pin { target_hash } = &e.action {
                pin = None;
                pin_unavailable = target_hash.is_some();
                if let Some(c::Content::Pin {
                    message_id: Some(message),
                }) = content(&self.conn, &self.scope, id, &event_id, keys)?
                {
                    let exists:bool=self.conn.query_row("SELECT EXISTS(SELECT 1 FROM local_group_messages WHERE scope=?1 AND group_id=?2 AND message_id=?3 AND status NOT IN ('queued','cancelled'))",params![self.scope,id,message],|r|r.get(0)).map_err(db)?;
                    if exists && !hidden(&self.conn, &self.scope, id, &message)? {
                        pin = Some(message);
                        pin_unavailable = false;
                    }
                }
            }
        }
        Ok(CollaborationView {
            polls,
            pin,
            pin_unavailable,
            pin_revision: self.collaboration_object(id, id)?.map_or(0, |p| p.revision),
            pending: self.collaboration_pending(id)?.is_some(),
            conflict: self.collaboration_conflicted(id)?,
        })
    }
    pub fn collaboration_pin_audience(
        &self,
        id: &str,
        message: &str,
    ) -> Result<Vec<c::Member>, String> {
        let group = self.state(id)?;
        if let Some(object) = self.collaboration_object(id, message)? {
            if matches!(object.action, c::Action::Mention | c::Action::Poll { .. }) {
                return Ok(object
                    .audience
                    .into_iter()
                    .filter(|m| c::members(&group).contains(m))
                    .collect());
            }
        }
        let envelope:Option<String>=self.conn.query_row("SELECT envelope FROM local_group_messages WHERE scope=?1 AND group_id=?2 AND message_id=?3 AND status NOT IN ('queued','cancelled')",params![self.scope,id,message],|r|r.get(0)).optional().map_err(db)?.flatten();
        let envelope: GroupEnvelope = if let Some(body) = envelope {
            parse(&body)?
        } else {
            let batch:String=self.conn.query_row("SELECT batch FROM local_group_outbox WHERE scope=?1 AND group_id=?2 AND message_id=?3 AND status='accepted'",params![self.scope,id,message],|r|r.get(0)).map_err(db)?;
            let batch: Vec<GroupEnvelope> = parse(&batch)?;
            batch.into_iter().next().ok_or_else(invalid)?
        };
        let origin = state(&self.conn, &self.scope, id, Some(envelope.epoch))?;
        Ok(c::members(&origin)
            .into_iter()
            .filter(|m| c::members(&group).contains(m))
            .collect())
    }
}
fn save_message(
    tx: &Transaction<'_>,
    scope: &str,
    e: &c::Event,
    plain: &c::Content,
    status: &str,
    keys: &crypto::KeyPair,
) -> Result<(), String> {
    let text = match plain {
        c::Content::Mention { text, .. } => text.clone(),
        c::Content::Poll { question, .. } => format!("投票：{question}"),
        c::Content::Pin { .. } => return Ok(()),
    };
    let message = GroupLocalMessage {
        id: e.id.clone(),
        sender_user_id: e.actor.user.clone(),
        sender_device_id: e.actor.device.clone(),
        sent_at: e.at,
        text,
        status: status.into(),
    };
    tx.execute("INSERT INTO local_group_messages(scope,group_id,message_id,body,status,sent_at,envelope) VALUES(?1,?2,?3,?4,?5,?6,NULL) ON CONFLICT(scope,group_id,message_id) DO UPDATE SET status=CASE WHEN local_group_messages.status='queued' THEN excluded.status ELSE local_group_messages.status END",params![scope,e.group,e.id,seal_local(scope,&e.group,&message,keys)?,status,e.at]).map_err(db)?;
    Ok(())
}
