//! Small private group trial primitives. Not yet a deployed relay protocol.
use crate::crypto;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use thiserror::Error;

pub const MAX_GROUP_MEMBERS: usize = 10;
pub const MAX_GROUP_TEXT_BYTES: usize = 4096;
const MAX_INVITE_MS: i64 = 7 * 24 * 60 * 60 * 1000;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GroupError {
    #[error("invalid group identity or metadata")]
    InvalidShape,
    #[error("invalid group signature")]
    InvalidSignature,
    #[error("group membership revision is stale or not linked")]
    StaleRevision,
    #[error("group action is not authorized")]
    Unauthorized,
    #[error("group invitation is invalid or expired")]
    InvalidInvitation,
    #[error("group recipient set does not match current membership")]
    InvalidRecipients,
    #[error("group message chain does not match the recipient incarnation")]
    InvalidChain,
}
fn id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
}
fn name(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 160 && !value.chars().any(char::is_control)
}
fn signature(bytes: &[u8], signed: &[u8], key: &[u8]) -> Result<(), GroupError> {
    let key: [u8; 32] = key.try_into().map_err(|_| GroupError::InvalidShape)?;
    if crypto::verify_with_public_key(bytes, signed, &key).unwrap_or(false) {
        Ok(())
    } else {
        Err(GroupError::InvalidSignature)
    }
}
fn hash(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GroupIdentity {
    pub user_id: String,
    pub device_id: String,
    pub public_key: Vec<u8>,
    pub signing_key: Vec<u8>,
}
impl GroupIdentity {
    pub fn validate(&self) -> Result<(), GroupError> {
        if !id(&self.user_id)
            || !id(&self.device_id)
            || self.public_key.len() != 32
            || self.signing_key.len() != 32
            || self.public_key.iter().all(|byte| *byte == 0)
            || self.signing_key.iter().all(|byte| *byte == 0)
        {
            return Err(GroupError::InvalidShape);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct GroupMember {
    pub identity: GroupIdentity,
    pub joined_epoch: u64,
}

/// Constructed only by verifying and replaying signed changes. No untrusted snapshot import.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct GroupState {
    group_id: String,
    name: String,
    owner: String,
    epoch: u64,
    members: Vec<GroupMember>,
    revision_hash: Vec<u8>,
    closed: bool,
}
impl GroupState {
    pub fn group_id(&self) -> &str {
        &self.group_id
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn owner(&self) -> &str {
        &self.owner
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn members(&self) -> &[GroupMember] {
        &self.members
    }
    pub fn revision_hash(&self) -> &[u8] {
        &self.revision_hash
    }
    pub fn closed(&self) -> bool {
        self.closed
    }
    pub fn member(&self, user: &str) -> Option<&GroupMember> {
        self.members
            .iter()
            .find(|member| member.identity.user_id == user)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GroupInvite {
    pub id: String,
    pub group_id: String,
    pub epoch: u64,
    pub previous_hash: Vec<u8>,
    pub member: GroupIdentity,
    pub issued_at: i64,
    pub expires_at: i64,
    pub signature: Vec<u8>,
}
impl GroupInvite {
    pub fn signing_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&(
            "LiteSeal/group-invite/v1",
            &self.id,
            &self.group_id,
            self.epoch,
            &self.previous_hash,
            &self.member,
            self.issued_at,
            self.expires_at,
        ))
        .expect("serializable invite")
    }
    pub fn digest(&self) -> Vec<u8> {
        hash(
            &serde_json::to_vec(&(self.signing_bytes(), &self.signature))
                .expect("serializable invite digest"),
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GroupAcceptance {
    pub invite_id: String,
    pub invite_hash: Vec<u8>,
    pub signature: Vec<u8>,
}
impl GroupAcceptance {
    pub fn signing_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&(
            "LiteSeal/group-acceptance/v1",
            &self.invite_id,
            &self.invite_hash,
        ))
        .expect("serializable acceptance")
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GroupAction {
    Create {
        name: String,
        owner: GroupIdentity,
    },
    Rename {
        name: String,
    },
    Join {
        invite: GroupInvite,
        acceptance: GroupAcceptance,
    },
    Leave,
    Remove {
        user_id: String,
    },
    Close,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GroupChange {
    pub group_id: String,
    pub epoch: u64,
    pub previous_hash: Vec<u8>,
    pub actor: String,
    pub created_at: i64,
    pub action: GroupAction,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupChangeRequest {
    pub device_id: String,
    pub change: GroupChange,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupInviteRequest {
    pub device_id: String,
    pub invite: GroupInvite,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupEventPage {
    pub changes: Vec<GroupChange>,
    pub through_epoch: u64,
    pub has_more: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupListEntry {
    pub group_id: String,
    pub joined_epoch: u64,
    pub visible_epoch: u64,
    pub active: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupListPage {
    pub groups: Vec<GroupListEntry>,
    pub next_cursor: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupInviteStatus {
    pub invite: GroupInvite,
    pub status: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupInvitePage {
    pub invites: Vec<GroupInvite>,
    pub next_cursor: Option<String>,
}
impl GroupChange {
    pub fn signing_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&(
            "LiteSeal/group-change/v1",
            &self.group_id,
            self.epoch,
            &self.previous_hash,
            &self.actor,
            self.created_at,
            &self.action,
        ))
        .expect("serializable group change")
    }
    pub fn digest(&self) -> Vec<u8> {
        hash(
            &serde_json::to_vec(&(self.signing_bytes(), &self.signature))
                .expect("serializable change digest"),
        )
    }
}
pub fn validate_invite(
    state: &GroupState,
    invite: &GroupInvite,
    timestamp: i64,
) -> Result<(), GroupError> {
    invite.member.validate()?;
    if state.closed
        || !id(&invite.id)
        || invite.group_id != state.group_id
        || invite.epoch != state.epoch
        || invite.previous_hash != state.revision_hash
        || state.members.len() >= MAX_GROUP_MEMBERS
        || timestamp < invite.issued_at
        || timestamp >= invite.expires_at
        || invite.issued_at < 0
        || i128::from(invite.expires_at) - i128::from(invite.issued_at) > i128::from(MAX_INVITE_MS)
        || state.members.iter().any(|member| {
            member.identity.user_id == invite.member.user_id
                || member.identity.device_id == invite.member.device_id
                || member.identity.public_key == invite.member.public_key
                || member.identity.signing_key == invite.member.signing_key
        })
    {
        return Err(GroupError::InvalidInvitation);
    }
    let owner = state.member(&state.owner).ok_or(GroupError::Unauthorized)?;
    signature(
        &invite.signing_bytes(),
        &invite.signature,
        &owner.identity.signing_key,
    )
}
/// Historical replay checks the signed join time, not today's clock. The relay must
/// additionally call validate_submission with its current clock when appending an event.
pub fn apply_change(
    previous: Option<&GroupState>,
    change: &GroupChange,
) -> Result<GroupState, GroupError> {
    if !id(&change.group_id) || !id(&change.actor) || change.created_at < 0 {
        return Err(GroupError::InvalidShape);
    }
    let Some(previous) = previous else {
        let GroupAction::Create {
            name: group_name,
            owner,
        } = &change.action
        else {
            return Err(GroupError::Unauthorized);
        };
        owner.validate()?;
        if change.epoch != 1
            || !change.previous_hash.is_empty()
            || change.actor != owner.user_id
            || !name(group_name)
        {
            return Err(GroupError::InvalidShape);
        }
        signature(
            &change.signing_bytes(),
            &change.signature,
            &owner.signing_key,
        )?;
        return Ok(GroupState {
            group_id: change.group_id.clone(),
            name: group_name.clone(),
            owner: owner.user_id.clone(),
            epoch: 1,
            members: vec![GroupMember {
                identity: owner.clone(),
                joined_epoch: 1,
            }],
            revision_hash: change.digest(),
            closed: false,
        });
    };
    if change.group_id != previous.group_id
        || Some(change.epoch) != previous.epoch.checked_add(1)
        || change.previous_hash != previous.revision_hash
    {
        return Err(GroupError::StaleRevision);
    }
    if previous.closed {
        return Err(GroupError::Unauthorized);
    }
    let mut state = previous.clone();
    let signing_key = match &change.action {
        GroupAction::Create { .. } => return Err(GroupError::Unauthorized),
        GroupAction::Join { invite, acceptance } => {
            validate_invite(previous, invite, change.created_at)?;
            if change.actor != invite.member.user_id
                || acceptance.invite_id != invite.id
                || acceptance.invite_hash != invite.digest()
            {
                return Err(GroupError::InvalidInvitation);
            }
            signature(
                &acceptance.signing_bytes(),
                &acceptance.signature,
                &invite.member.signing_key,
            )?;
            state.members.push(GroupMember {
                identity: invite.member.clone(),
                joined_epoch: change.epoch,
            });
            invite.member.signing_key.clone()
        }
        action => {
            let actor = previous
                .member(&change.actor)
                .ok_or(GroupError::Unauthorized)?;
            match action {
                GroupAction::Rename { name: group_name } => {
                    if change.actor != previous.owner || !name(group_name) {
                        return Err(GroupError::Unauthorized);
                    }
                    state.name = group_name.clone();
                }
                GroupAction::Remove { user_id } => {
                    if change.actor != previous.owner
                        || *user_id == previous.owner
                        || previous.member(user_id).is_none()
                    {
                        return Err(GroupError::Unauthorized);
                    }
                    state
                        .members
                        .retain(|member| member.identity.user_id != *user_id);
                }
                GroupAction::Leave => {
                    if change.actor == previous.owner {
                        return Err(GroupError::Unauthorized);
                    }
                    state
                        .members
                        .retain(|member| member.identity.user_id != change.actor);
                }
                GroupAction::Close => {
                    if change.actor != previous.owner {
                        return Err(GroupError::Unauthorized);
                    }
                    state.closed = true;
                }
                _ => return Err(GroupError::Unauthorized),
            }
            actor.identity.signing_key.clone()
        }
    };
    signature(&change.signing_bytes(), &change.signature, &signing_key)?;
    state
        .members
        .sort_by(|left, right| left.identity.user_id.cmp(&right.identity.user_id));
    state.epoch = change.epoch;
    state.revision_hash = change.digest();
    Ok(state)
}
pub fn validate_submission(
    previous: Option<&GroupState>,
    change: &GroupChange,
    timestamp: i64,
) -> Result<GroupState, GroupError> {
    if timestamp < 0 || (i128::from(timestamp) - i128::from(change.created_at)).abs() > 60_000 {
        return Err(GroupError::StaleRevision);
    }
    if let (Some(state), GroupAction::Join { invite, .. }) = (previous, &change.action) {
        validate_invite(state, invite, timestamp)?;
    }
    apply_change(previous, change)
}

/// Pin the creation identity to an independently verified account/device record.
/// A self-signed owner in a server-provided snapshot is not a trust anchor by itself.
pub fn pin_creation(
    change: &GroupChange,
    expected_owner: &GroupIdentity,
) -> Result<GroupState, GroupError> {
    expected_owner.validate()?;
    if !matches!(&change.action,GroupAction::Create {owner,..} if owner==expected_owner) {
        return Err(GroupError::Unauthorized);
    }
    apply_change(None, change)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GroupEnvelope {
    pub version: u8,
    pub message_id: String,
    pub group_id: String,
    pub epoch: u64,
    pub membership_hash: Vec<u8>,
    pub sender_user_id: String,
    pub sender_device_id: String,
    pub sender_join_epoch: u64,
    pub recipient_user_id: String,
    pub recipient_device_id: String,
    pub recipient_join_epoch: u64,
    pub sender_seq: i64,
    pub prev_hash: Vec<u8>,
    pub sent_at: i64,
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
}
impl GroupEnvelope {
    pub fn signing_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&(
            "LiteSeal/group-envelope/v1",
            self.version,
            &self.message_id,
            &self.group_id,
            self.epoch,
            &self.membership_hash,
            (
                &self.sender_user_id,
                &self.sender_device_id,
                self.sender_join_epoch,
            ),
            (
                &self.recipient_user_id,
                &self.recipient_device_id,
                self.recipient_join_epoch,
            ),
            self.sender_seq,
            &self.prev_hash,
            self.sent_at,
            &self.ciphertext,
        ))
        .expect("serializable group envelope")
    }
    pub fn chain_hash(&self) -> Vec<u8> {
        hash(
            &serde_json::to_vec(&(self.signing_bytes(), &self.signature))
                .expect("serializable group message hash"),
        )
    }
}
pub fn validate_envelope(state: &GroupState, envelope: &GroupEnvelope) -> Result<(), GroupError> {
    if state.closed
        || envelope.version != 1
        || !id(&envelope.message_id)
        || envelope.group_id != state.group_id
        || envelope.epoch != state.epoch
        || envelope.membership_hash != state.revision_hash
        || envelope.sent_at < 0
        || envelope.sender_seq < 1
        || !(40..=MAX_GROUP_TEXT_BYTES + 40).contains(&envelope.ciphertext.len())
        || (envelope.sender_seq == 1 && !envelope.prev_hash.is_empty())
        || (envelope.sender_seq > 1 && envelope.prev_hash.len() != 32)
    {
        return Err(GroupError::InvalidShape);
    }
    let sender = state
        .member(&envelope.sender_user_id)
        .ok_or(GroupError::Unauthorized)?;
    let recipient = state
        .member(&envelope.recipient_user_id)
        .ok_or(GroupError::Unauthorized)?;
    if sender.identity.user_id == recipient.identity.user_id
        || envelope.sender_device_id != sender.identity.device_id
        || envelope.recipient_device_id != recipient.identity.device_id
        || envelope.sender_join_epoch != sender.joined_epoch
        || envelope.recipient_join_epoch != recipient.joined_epoch
    {
        return Err(GroupError::Unauthorized);
    }
    signature(
        &envelope.signing_bytes(),
        &envelope.signature,
        &sender.identity.signing_key,
    )
}
pub fn validate_batch(state: &GroupState, envelopes: &[GroupEnvelope]) -> Result<(), GroupError> {
    let first = envelopes.first().ok_or(GroupError::InvalidRecipients)?;
    if envelopes.len() != state.members.len().saturating_sub(1) {
        return Err(GroupError::InvalidRecipients);
    }
    let mut recipients = HashSet::new();
    for envelope in envelopes {
        validate_envelope(state, envelope)?;
        if envelope.message_id != first.message_id
            || envelope.sender_user_id != first.sender_user_id
            || envelope.sent_at != first.sent_at
            || !recipients.insert(&envelope.recipient_user_id)
        {
            return Err(GroupError::InvalidRecipients);
        }
    }
    if state.members.iter().any(|member| {
        member.identity.user_id != first.sender_user_id
            && !recipients.contains(&member.identity.user_id)
    }) {
        return Err(GroupError::InvalidRecipients);
    }
    Ok(())
}
/// New envelopes must first pass validate_envelope; previous must be a verified stored envelope.
pub fn validate_chain(
    envelope: &GroupEnvelope,
    previous: Option<&GroupEnvelope>,
) -> Result<(), GroupError> {
    match previous {
        None if envelope.sender_seq == 1 && envelope.prev_hash.is_empty() => Ok(()),
        Some(previous)
            if previous.group_id == envelope.group_id
                && previous.sender_user_id == envelope.sender_user_id
                && previous.epoch <= envelope.epoch
                && previous.sender_device_id == envelope.sender_device_id
                && previous.sender_join_epoch == envelope.sender_join_epoch
                && previous.recipient_user_id == envelope.recipient_user_id
                && previous.recipient_device_id == envelope.recipient_device_id
                && previous.recipient_join_epoch == envelope.recipient_join_epoch
                && previous.message_id != envelope.message_id
                && previous.sender_seq.checked_add(1) == Some(envelope.sender_seq)
                && previous.chain_hash() == envelope.prev_hash =>
        {
            Ok(())
        }
        _ => Err(GroupError::InvalidChain),
    }
}
