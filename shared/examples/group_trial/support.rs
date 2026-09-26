use liteseal_shared::{crypto, group::*};

pub struct Participant {
    pub user: String,
    pub keys: crypto::KeyPair,
}
impl Participant {
    pub fn new(user: &str) -> Self {
        Self {
            user: user.into(),
            keys: crypto::generate_keypair().unwrap(),
        }
    }
    pub fn identity(&self) -> GroupIdentity {
        GroupIdentity {
            user_id: self.user.clone(),
            device_id: format!("{}-device", self.user),
            public_key: self.keys.public_key.to_vec(),
            signing_key: self.keys.ed25519_pk.to_vec(),
        }
    }
}
pub fn change(
    state: Option<&GroupState>,
    actor: &Participant,
    action: GroupAction,
    timestamp: i64,
) -> GroupChange {
    let mut event = GroupChange {
        group_id: state
            .map(|state| state.group_id())
            .unwrap_or("trial-group")
            .into(),
        epoch: state.map(|state| state.epoch() + 1).unwrap_or(1),
        previous_hash: state
            .map(|state| state.revision_hash().to_vec())
            .unwrap_or_default(),
        actor: actor.user.clone(),
        created_at: timestamp,
        action,
        signature: Vec::new(),
    };
    event.signature = crypto::sign(&event.signing_bytes(), &actor.keys.ed25519_sk).unwrap();
    event
}
pub fn join(
    state: &GroupState,
    owner: &Participant,
    member: &Participant,
    timestamp: i64,
) -> GroupChange {
    let mut invitation = GroupInvite {
        id: format!("invite-{}-{}", member.user, state.epoch()),
        group_id: state.group_id().into(),
        epoch: state.epoch(),
        previous_hash: state.revision_hash().to_vec(),
        member: member.identity(),
        issued_at: timestamp,
        expires_at: timestamp + 60_000,
        signature: Vec::new(),
    };
    invitation.signature =
        crypto::sign(&invitation.signing_bytes(), &owner.keys.ed25519_sk).unwrap();
    let mut acceptance = GroupAcceptance {
        invite_id: invitation.id.clone(),
        invite_hash: invitation.digest(),
        signature: Vec::new(),
    };
    acceptance.signature =
        crypto::sign(&acceptance.signing_bytes(), &member.keys.ed25519_sk).unwrap();
    change(
        Some(state),
        member,
        GroupAction::Join {
            invite: invitation,
            acceptance,
        },
        timestamp,
    )
}
pub fn envelope(
    state: &GroupState,
    sender: &Participant,
    recipient: &Participant,
    message_id: &str,
    text: &str,
    previous: Option<&GroupEnvelope>,
) -> GroupEnvelope {
    let mut envelope = GroupEnvelope {
        version: 1,
        message_id: message_id.into(),
        group_id: state.group_id().into(),
        epoch: state.epoch(),
        membership_hash: state.revision_hash().to_vec(),
        sender_user_id: sender.user.clone(),
        sender_device_id: sender.identity().device_id,
        sender_join_epoch: state.member(&sender.user).unwrap().joined_epoch,
        recipient_user_id: recipient.user.clone(),
        recipient_device_id: recipient.identity().device_id,
        recipient_join_epoch: state.member(&recipient.user).unwrap().joined_epoch,
        sender_seq: previous
            .map(|previous| previous.sender_seq + 1)
            .unwrap_or(1),
        prev_hash: previous
            .map(|previous| previous.chain_hash())
            .unwrap_or_default(),
        sent_at: 1000,
        ciphertext: crypto::encrypt(
            text.as_bytes(),
            &recipient.keys.public_key,
            &sender.keys.secret_key,
        )
        .unwrap(),
        signature: Vec::new(),
    };
    envelope.signature = crypto::sign(&envelope.signing_bytes(), &sender.keys.ed25519_sk).unwrap();
    envelope
}
