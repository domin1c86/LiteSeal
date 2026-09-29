//! Signed group collaboration metadata. Private text is carried in recipient boxes.
use crate::{
    crypto,
    group::{GroupError, GroupMember, GroupState},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(deny_unknown_fields)]
pub struct Member {
    pub user: String,
    pub device: String,
    pub joined: u64,
}
impl From<&GroupMember> for Member {
    fn from(m: &GroupMember) -> Self {
        Self {
            user: m.identity.user_id.clone(),
            device: m.identity.device_id.clone(),
            joined: m.joined_epoch,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Mention,
    Poll { options: Vec<String> },
    Vote { option: String },
    Close,
    Pin { target_hash: Option<Vec<u8>> },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Slot {
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
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Boxed {
    pub member: Member,
    pub ciphertext: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub event: Event,
    pub boxes: Vec<Boxed>,
    pub pin_target: Option<String>,
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
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OptionText {
    pub id: String,
    pub text: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Content {
    Mention {
        text: String,
        mentions: Vec<Member>,
    },
    Poll {
        question: String,
        options: Vec<OptionText>,
    },
    Pin {
        message_id: Option<String>,
    },
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
    pub votes: BTreeMap<String, String>,
    pub closed: bool,
}
pub fn digest(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}
fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}
pub fn members(group: &GroupState) -> Vec<Member> {
    let mut result: Vec<_> = group.members().iter().map(Member::from).collect();
    result.sort();
    result
}
impl Event {
    pub fn signing_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&(
            "LiteSeal/collaboration/v1",
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
        ))
        .expect("event serialization")
    }
    pub fn hash(&self) -> Vec<u8> {
        digest(
            &serde_json::to_vec(&(self.signing_bytes(), &self.signature))
                .expect("signature serialization"),
        )
    }
    pub fn verify(&self, group: &GroupState) -> Result<(), GroupError> {
        let bad = GroupError::InvalidShape;
        if self.version != 1
            || !valid_id(&self.id)
            || !valid_id(&self.object)
            || self.group != group.group_id()
            || self.epoch != group.epoch()
            || self.membership_hash != group.revision_hash()
            || group.closed()
            || self.at < 0
            || self.revision == 0
            || self.revision > 10000
        {
            return Err(bad);
        }
        let actor = group
            .member(&self.actor.user)
            .ok_or(GroupError::Unauthorized)?;
        if Member::from(actor) != self.actor {
            return Err(GroupError::Unauthorized);
        }
        let key: [u8; 32] = actor
            .identity
            .signing_key
            .as_slice()
            .try_into()
            .map_err(|_| GroupError::InvalidShape)?;
        if !crypto::verify_with_public_key(&self.signing_bytes(), &self.signature, &key)
            .unwrap_or(false)
        {
            return Err(GroupError::InvalidSignature);
        }
        let current = members(group);
        if self.audience.len() > 10
            || self.audience.windows(2).any(|p| p[0] >= p[1])
            || self.audience.iter().any(|m| !current.contains(m))
        {
            return Err(GroupError::InvalidRecipients);
        }
        let boxed = matches!(
            self.action,
            Action::Mention | Action::Poll { .. } | Action::Pin { .. }
        );
        if boxed
            && (self.slots.len() != self.audience.len()
                || self
                    .slots
                    .iter()
                    .zip(&self.audience)
                    .any(|(s, m)| &s.member != m || s.hash.len() != 32))
            || !boxed && !self.slots.is_empty()
        {
            return Err(GroupError::InvalidRecipients);
        }
        Ok(())
    }
}
pub fn transition(
    previous: Option<&Object>,
    group: &GroupState,
    event: &Event,
) -> Result<Object, GroupError> {
    event.verify(group)?;
    let current = members(group);
    if let Some(old) = previous {
        if old.group != event.group
            || old.id != event.object
            || old.revision + 1 != event.revision
            || old.head != event.previous
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
        votes: BTreeMap::new(),
        closed: false,
    });
    match &event.action {
        Action::Mention => {
            if previous.is_some() || event.object != event.id || event.audience != current {
                return Err(GroupError::InvalidShape);
            }
        }
        Action::Poll { options } => {
            if previous.is_some()
                || event.object != event.id
                || event.audience != current
                || !(2..=10).contains(&options.len())
                || options.iter().any(|s| !valid_id(s))
                || options.iter().collect::<HashSet<_>>().len() != options.len()
            {
                return Err(GroupError::InvalidShape);
            }
        }
        Action::Vote { .. } | Action::Close => {
            let old = previous.ok_or(GroupError::StaleRevision)?;
            let Action::Poll { options } = &old.action else {
                return Err(GroupError::InvalidShape);
            };
            let audience: Vec<_> = old
                .audience
                .iter()
                .filter(|m| current.contains(m))
                .cloned()
                .collect();
            if old.closed || event.audience != audience {
                return Err(GroupError::Unauthorized);
            }
            match &event.action {
                Action::Vote { option } => {
                    if !old.audience.contains(&event.actor) || !options.contains(option) {
                        return Err(GroupError::Unauthorized);
                    }
                    object
                        .votes
                        .insert(event.actor.user.clone(), option.clone());
                }
                Action::Close => {
                    if event.actor != old.creator && event.actor.user != group.owner() {
                        return Err(GroupError::Unauthorized);
                    }
                    object.closed = true;
                }
                _ => unreachable!(),
            }
        }
        Action::Pin { target_hash } => {
            if event.object != event.group
                || event.actor.user != group.owner()
                || previous.is_some_and(|p| !matches!(p.action, Action::Pin { .. }))
                || target_hash.as_ref().is_some_and(|h| h.len() != 32)
            {
                return Err(GroupError::Unauthorized);
            }
            object.action = event.action.clone();
            object.audience = event.audience.clone();
        }
    }
    object.revision = event.revision;
    object.head = event.hash();
    Ok(object)
}
pub fn validate_content(event: &Event, content: &Content) -> Result<(), GroupError> {
    let text_ok = |s: &str, max: usize| {
        !s.trim().is_empty()
            && s.chars().count() <= max
            && !s.chars().any(|c| c.is_control() && c != '\n')
    };
    let valid = match (&event.action, content) {
        (Action::Mention, Content::Mention { text, mentions }) => {
            !text.trim().is_empty()
                && text.len() <= 4096
                && !mentions.is_empty()
                && mentions.len() <= 10
                && mentions.iter().all(|m| event.audience.contains(m))
                && mentions.iter().collect::<HashSet<_>>().len() == mentions.len()
        }
        (Action::Poll { options: ids }, Content::Poll { question, options }) => {
            text_ok(question, 200)
                && options.iter().map(|o| &o.id).eq(ids.iter())
                && options.iter().all(|o| text_ok(&o.text, 100))
                && options
                    .iter()
                    .map(|o| o.text.trim())
                    .collect::<HashSet<_>>()
                    .len()
                    == options.len()
        }
        (Action::Pin { target_hash }, Content::Pin { message_id }) => {
            message_id.as_ref().map(|id| digest(id.as_bytes())) == *target_hash
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(GroupError::InvalidShape)
    }
}
pub fn validate_boxes(submission: &Submission) -> Result<(), GroupError> {
    let event = &submission.event;
    if submission.boxes.len() != event.slots.len()
        || submission.boxes.iter().zip(&event.slots).any(|(b, s)| {
            b.member != s.member
                || !(40..=8192).contains(&b.ciphertext.len())
                || digest(&b.ciphertext) != s.hash
        })
    {
        return Err(GroupError::InvalidRecipients);
    }
    if let Action::Pin { target_hash } = &event.action {
        if submission
            .pin_target
            .as_ref()
            .map(|id| digest(id.as_bytes()))
            != *target_hash
        {
            return Err(GroupError::InvalidShape);
        }
    } else if submission.pin_target.is_some() {
        return Err(GroupError::InvalidShape);
    }
    Ok(())
}
