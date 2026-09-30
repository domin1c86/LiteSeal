//! Additive group extensions. Legacy roots contain only the fixed placeholder;
//! attachment secrets and activity details never enter the legacy text stream.
use crate::{
    collaboration::{self as c, Boxed, Member, Slot},
    crypto,
    group::{self, GroupEnvelope, GroupError, GroupState},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
pub const PLACEHOLDER: &str = "[群附件或活动，请升级客户端查看]";
pub const MAX_FILE: usize = 20 * 1024 * 1024;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Answer {
    Yes,
    No,
    Maybe,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Attachment {
        blob: String,
        size: u64,
        hash: Vec<u8>,
    },
    Activity,
    Respond {
        answer: Answer,
    },
    Close,
    Cancel,
}
impl Action {
    pub fn creates(&self) -> bool {
        matches!(self, Self::Attachment { .. } | Self::Activity)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Attachment {
    pub version: u8,
    pub blob: String,
    pub name: String,
    pub size: u64,
    pub mime: String,
    pub duration_ms: Option<u32>,
    pub key: Vec<u8>,
    pub hash: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Activity {
    pub title: String,
    pub start_at: i64,
    pub timezone: String,
    pub location: String,
    pub description: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Content {
    Attachment(Attachment),
    Activity(Activity),
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RootHash {
    pub member: Member,
    pub hash: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub version: u8,
    pub id: String,
    pub group: String,
    pub epoch: u64,
    pub membership_hash: Vec<u8>,
    pub actor: Member,
    pub object: String,
    pub revision: u64,
    pub previous: Vec<u8>,
    pub at: i64,
    pub action: Action,
    pub audience: Vec<Member>,
    pub slots: Vec<Slot>,
    pub roots: Vec<RootHash>,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub event: Event,
    pub boxes: Vec<Boxed>,
    pub roots: Vec<GroupEnvelope>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Delivery {
    pub seq: i64,
    pub event: Event,
    pub ciphertext: Option<Vec<u8>>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Page {
    pub items: Vec<Delivery>,
    pub cursor: i64,
    pub more: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Receipt {
    pub event_id: String,
    pub hash: Vec<u8>,
    pub seq: i64,
    pub root: Option<group::GroupMessageReceipt>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CancelResult {
    pub cancelled: bool,
    pub receipt: Option<Receipt>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Object {
    pub group: String,
    pub id: String,
    pub revision: u64,
    pub head: Vec<u8>,
    pub creator: Member,
    pub audience: Vec<Member>,
    pub action: Action,
    pub responses: BTreeMap<String, Answer>,
    pub closed: bool,
    pub cancelled: bool,
}
fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}
pub fn root_hash(root: &GroupEnvelope) -> Vec<u8> {
    c::digest(&serde_json::to_vec(root).expect("group envelope serialization"))
}
impl Event {
    pub fn signing_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&(
            "LiteSeal/group-extension/v1",
            self.version,
            &self.id,
            &self.group,
            self.epoch,
            &self.membership_hash,
            &self.actor,
            &self.object,
            self.revision,
            &self.previous,
            self.at,
            &self.action,
            &self.audience,
            &self.slots,
            &self.roots,
        ))
        .expect("extension serialization")
    }
    pub fn hash(&self) -> Vec<u8> {
        c::digest(
            &serde_json::to_vec(&(self.signing_bytes(), &self.signature)).expect("extension hash"),
        )
    }
    pub fn verify(&self, state: &GroupState) -> Result<(), GroupError> {
        if self.version != 1
            || !valid_id(&self.id)
            || !valid_id(&self.object)
            || self.id == self.object
            || self.id == self.group
            || self.object == self.group
            || self.group != state.group_id()
            || self.epoch != state.epoch()
            || self.membership_hash != state.revision_hash()
            || state.closed()
            || self.at < 0
            || self.revision == 0
            || self.revision > 10000
        {
            return Err(GroupError::InvalidShape);
        }
        let actor = state
            .member(&self.actor.user)
            .ok_or(GroupError::Unauthorized)?;
        if Member::from(actor) != self.actor {
            return Err(GroupError::Unauthorized);
        }
        let pk: [u8; 32] = actor
            .identity
            .signing_key
            .as_slice()
            .try_into()
            .map_err(|_| GroupError::InvalidShape)?;
        if !crypto::verify_with_public_key(&self.signing_bytes(), &self.signature, &pk)
            .unwrap_or(false)
        {
            return Err(GroupError::InvalidSignature);
        }
        let current = c::members(state);
        if self.audience.is_empty()
            || self.audience.len() > 10
            || self.audience.windows(2).any(|p| p[0] >= p[1])
            || self.audience.iter().any(|m| !current.contains(m))
        {
            return Err(GroupError::InvalidRecipients);
        }
        if self.action.creates() {
            if self.audience != current
                || self.slots.len() != self.audience.len()
                || self
                    .slots
                    .iter()
                    .zip(&self.audience)
                    .any(|(s, m)| &s.member != m || s.hash.len() != 32)
                || self.roots.len() != current.len().saturating_sub(1)
            {
                return Err(GroupError::InvalidRecipients);
            }
            let expected: Vec<_> = current.into_iter().filter(|m| m != &self.actor).collect();
            if self
                .roots
                .iter()
                .zip(expected)
                .any(|(h, m)| h.member != m || h.hash.len() != 32)
            {
                return Err(GroupError::InvalidRecipients);
            }
        } else if !self.slots.is_empty() || !self.roots.is_empty() {
            return Err(GroupError::InvalidShape);
        }
        Ok(())
    }
}
pub fn transition(
    previous: Option<&Object>,
    state: &GroupState,
    event: &Event,
) -> Result<Object, GroupError> {
    event.verify(state)?;
    if let Some(old) = previous {
        if old.group != event.group
            || old.id != event.object
            || event.revision != old.revision + 1
            || event.previous != old.head
        {
            return Err(GroupError::StaleRevision);
        }
    } else if event.revision != 1 || !event.previous.is_empty() {
        return Err(GroupError::StaleRevision);
    }
    let mut object = previous.cloned().unwrap_or(Object {
        group: event.group.clone(),
        id: event.object.clone(),
        revision: 0,
        head: vec![],
        creator: event.actor.clone(),
        audience: event.audience.clone(),
        action: event.action.clone(),
        responses: BTreeMap::new(),
        closed: false,
        cancelled: false,
    });
    match &event.action {
        Action::Attachment { blob, size, hash } => {
            if previous.is_some() || !valid_id(blob) || *size > MAX_FILE as u64 || hash.len() != 32
            {
                return Err(GroupError::InvalidShape);
            }
        }
        Action::Activity => {
            if previous.is_some() {
                return Err(GroupError::InvalidShape);
            }
        }
        Action::Respond { .. } | Action::Close | Action::Cancel => {
            let old = previous.ok_or(GroupError::StaleRevision)?;
            if !matches!(old.action, Action::Activity) || old.cancelled {
                return Err(GroupError::Unauthorized);
            }
            let current = c::members(state);
            let expected: Vec<_> = old
                .audience
                .iter()
                .filter(|m| current.contains(m))
                .cloned()
                .collect();
            if expected != event.audience {
                return Err(GroupError::InvalidRecipients);
            }
            match &event.action {
                Action::Respond { answer } => {
                    if old.closed || !old.audience.contains(&event.actor) {
                        return Err(GroupError::Unauthorized);
                    }
                    object
                        .responses
                        .insert(event.actor.user.clone(), answer.clone());
                }
                Action::Close => {
                    if old.closed || event.actor != old.creator && event.actor.user != state.owner()
                    {
                        return Err(GroupError::Unauthorized);
                    }
                    object.closed = true;
                }
                Action::Cancel => {
                    if event.actor != old.creator && event.actor.user != state.owner() {
                        return Err(GroupError::Unauthorized);
                    }
                    object.closed = true;
                    object.cancelled = true;
                }
                _ => unreachable!(),
            }
        }
    }
    object.revision = event.revision;
    object.head = event.hash();
    Ok(object)
}
pub fn validate_content(event: &Event, content: &Content) -> Result<(), GroupError> {
    let good = match (&event.action, content) {
        (Action::Attachment { blob, size, hash }, Content::Attachment(a)) => {
            a.version == 1
                && &a.blob == blob
                && a.size == *size
                && a.hash == *hash
                && a.key.len() == 32
                && !a.name.is_empty()
                && a.name.chars().count() <= 160
                && !a.name.chars().any(char::is_control)
                && a.mime.len() <= 128
                && a.duration_ms
                    .is_none_or(|t| (1..=60000).contains(&t) && a.mime == "audio/webm")
        }
        (Action::Activity, Content::Activity(a)) => {
            !a.title.trim().is_empty()
                && a.title.chars().count() <= 100
                && a.start_at >= 0
                && a.start_at <= 8_640_000_000_000_000
                && !a.timezone.is_empty()
                && a.timezone.len() <= 64
                && a.location.chars().count() <= 200
                && a.description.chars().count() <= 1000
        }
        _ => false,
    };
    if !good || serde_json::to_vec(content).map_or(true, |v| v.len() > 8152) {
        return Err(GroupError::InvalidShape);
    }
    Ok(())
}
pub fn validate_submission(state: &GroupState, submission: &Submission) -> Result<(), GroupError> {
    let event = &submission.event;
    event.verify(state)?;
    if submission.boxes.len() != event.slots.len()
        || submission.boxes.iter().zip(&event.slots).any(|(b, s)| {
            b.member != s.member
                || !(40..=8192).contains(&b.ciphertext.len())
                || c::digest(&b.ciphertext) != s.hash
        })
    {
        return Err(GroupError::InvalidRecipients);
    }
    if event.action.creates() {
        group::validate_batch(state, &submission.roots)?;
        let mut roots: Vec<_> = submission.roots.iter().collect();
        roots.sort_by(|a, b| {
            (&a.recipient_user_id, &a.recipient_device_id)
                .cmp(&(&b.recipient_user_id, &b.recipient_device_id))
        });
        for (root, commitment) in roots.iter().zip(&event.roots) {
            if root.message_id != event.object
                || root.sender_user_id != event.actor.user
                || root.sender_device_id != event.actor.device
                || root.sender_join_epoch != event.actor.joined
                || root.sent_at != event.at
                || root_hash(root) != commitment.hash
                || root.recipient_user_id != commitment.member.user
                || root.recipient_device_id != commitment.member.device
                || root.recipient_join_epoch != commitment.member.joined
            {
                return Err(GroupError::InvalidRecipients);
            }
        }
    } else if !submission.roots.is_empty() {
        return Err(GroupError::InvalidShape);
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub fn make(
    state: &GroupState,
    actor: &Member,
    object: String,
    id: String,
    previous: Option<&Object>,
    action: Action,
    content: Option<&Content>,
    roots: Vec<GroupEnvelope>,
    keys: &crypto::KeyPair,
    at: i64,
) -> Result<Submission, GroupError> {
    let current = c::members(state);
    let audience = previous
        .map(|o| {
            o.audience
                .iter()
                .filter(|m| current.contains(m))
                .cloned()
                .collect()
        })
        .unwrap_or(current);
    let mut commitments: Vec<_> = roots
        .iter()
        .map(|r| RootHash {
            member: Member {
                user: r.recipient_user_id.clone(),
                device: r.recipient_device_id.clone(),
                joined: r.recipient_join_epoch,
            },
            hash: root_hash(r),
        })
        .collect();
    commitments.sort_by(|a, b| a.member.cmp(&b.member));
    let mut event = Event {
        version: 1,
        id,
        group: state.group_id().into(),
        epoch: state.epoch(),
        membership_hash: state.revision_hash().to_vec(),
        actor: actor.clone(),
        object,
        revision: previous.map_or(1, |o| o.revision + 1),
        previous: previous.map_or(vec![], |o| o.head.clone()),
        at,
        action,
        audience,
        slots: vec![],
        roots: commitments,
        signature: vec![],
    };
    let mut boxes = vec![];
    if let Some(content) = content {
        validate_content(&event, content)?;
        let bytes = serde_json::to_vec(content).map_err(|_| GroupError::InvalidShape)?;
        for member in &event.audience {
            let pk: [u8; 32] = state
                .member(&member.user)
                .ok_or(GroupError::Unauthorized)?
                .identity
                .public_key
                .as_slice()
                .try_into()
                .map_err(|_| GroupError::InvalidShape)?;
            let ciphertext = crypto::encrypt(&bytes, &pk, &keys.secret_key)
                .map_err(|_| GroupError::InvalidShape)?;
            event.slots.push(Slot {
                member: member.clone(),
                hash: c::digest(&ciphertext),
            });
            boxes.push(Boxed {
                member: member.clone(),
                ciphertext,
            });
        }
    }
    event.signature = crypto::sign(&event.signing_bytes(), &keys.ed25519_sk)
        .map_err(|_| GroupError::InvalidSignature)?;
    transition(previous, state, &event)?;
    let submission = Submission {
        event,
        boxes,
        roots,
    };
    validate_submission(state, &submission)?;
    Ok(submission)
}
