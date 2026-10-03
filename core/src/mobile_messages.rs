//! Mobile plaintext projection. Identity secrets and attachment keys stay native.
use crate::{chat, db::repository::MessageRepository, keystore::KeystoreData};
use liteseal_shared::{
    crypto,
    message_operation::{self as op, OperationDelivery},
    protocol::{EncryptedPayload, SignedEnvelopeV2, PROTOCOL_V2},
};
use zeroize::Zeroizing;
fn bad() -> String {
    "消息证据或可见性无法验证；正文未展示".into()
}
pub(crate) fn read(
    db: &MessageRepository,
    saved: &KeystoreData,
    id: &str,
) -> Result<String, String> {
    let message = db.get_message(id).map_err(|_| bad())?.ok_or_else(bad)?;
    if message.local_state == "integrity_failed"
        || message
            .expire_at
            .is_some_and(|at| at <= chrono::Utc::now().timestamp())
        || db
            .locally_deleted_ids(&saved.user_id, &message.conversation_id)
            .map_err(|_| bad())?
            .contains(&message.id)
    {
        return Err(bad());
    }
    let contact = db
        .get_contacts()
        .map_err(|_| bad())?
        .into_iter()
        .find(|c| {
            message.conversation_id == chat::canonical_conversation_id(&saved.user_id, &c.user_id)
        })
        .ok_or_else(bad)?;
    if contact.key_changed
        || contact.trust_state == "key_changed"
        || (message.sender_id != saved.user_id && message.sender_id != contact.user_id)
    {
        return Err(bad());
    }
    let signing_pk: [u8; 32] = if message.sender_id == saved.user_id {
        saved.ed25519_pk.as_slice()
    } else {
        contact.ed25519_pk.as_deref().ok_or_else(bad)?
    }
    .try_into()
    .map_err(|_| bad())?;
    let own_secret =
        Zeroizing::new(<[u8; 32]>::try_from(saved.secret_key.as_slice()).map_err(|_| bad())?);
    let peer_key: [u8; 32] = contact
        .public_key
        .as_slice()
        .try_into()
        .map_err(|_| bad())?;
    let mut plain = Zeroizing::new(
        crypto::decrypt(&message.ciphertext, &peer_key, &own_secret).map_err(|_| bad())?,
    );
    let (recipient, device, ciphertext, signature, sequence, previous) = if message.sender_id
        == saved.user_id
    {
        if message.sender_device_id != saved.device_id {
            return Err(bad());
        }
        let payloads: Vec<EncryptedPayload> =
            serde_json::from_str(&db.outgoing_payloads(id).map_err(|_| bad())?)
                .map_err(|_| bad())?;
        if payloads.len() != 1 || payloads[0].recipient_user_id != contact.user_id {
            return Err(bad());
        }
        let payload = payloads.into_iter().next().ok_or_else(bad)?;
        let (sequence, previous) = db
            .outgoing_chains(id)
            .map_err(|_| bad())?
            .remove(&payload.recipient_device_id)
            .ok_or_else(bad)?;
        let wire_plain = Zeroizing::new(
            crypto::decrypt(&payload.ciphertext, &peer_key, &own_secret).map_err(|_| bad())?,
        );
        if *wire_plain != *plain || sequence != message.sender_seq || previous != message.prev_hash
        {
            return Err(bad());
        }
        (
            contact.user_id.clone(),
            payload.recipient_device_id,
            payload.ciphertext,
            payload.signature,
            sequence,
            previous,
        )
    } else {
        if db.incoming_chain_version(id).map_err(|_| bad())? != 2 {
            return Err(bad());
        }
        (
            saved.user_id.clone(),
            saved.device_id.clone(),
            message.ciphertext.clone(),
            message.signature.clone(),
            message.sender_seq,
            message.prev_hash.clone(),
        )
    };
    let envelope = SignedEnvelopeV2 {
        protocol_version: PROTOCOL_V2,
        message_id: message.id.clone(),
        conversation_id: message.conversation_id.clone(),
        sender_user_id: message.sender_id.clone(),
        sender_device_id: message.sender_device_id.clone(),
        recipient_user_id: recipient,
        recipient_device_id: device,
        sender_seq: sequence,
        prev_hash: previous,
        sent_at: message.timestamp,
        message_type: message.message_type.clone(),
        ciphertext,
        signature,
    };
    if !crypto::verify_with_public_key(
        &envelope.signing_bytes().map_err(|_| bad())?,
        &envelope.signature,
        &signing_pk,
    )
    .map_err(|_| bad())?
    {
        return Err(bad());
    }
    let rows = db
        .operations(
            &saved.user_id,
            &saved.device_id,
            Some(&message.conversation_id),
        )
        .map_err(|_| bad())?;
    let mut deliveries = Vec::new();
    for row in rows
        .into_iter()
        .filter(|row| row.target_id == id && row.status == "accepted")
    {
        if row.body.len() > 512 * 1024 || deliveries.len() >= 256 {
            return Err(bad());
        }
        let delivery: OperationDelivery = serde_json::from_str(&row.body).map_err(|_| bad())?;
        if row.id != delivery.header.id
            || row.target_id != delivery.header.target_id
            || row.conversation_id != delivery.header.conversation_id
        {
            return Err(bad());
        }
        deliveries.push(delivery);
    }
    deliveries.sort_by_key(|delivery| delivery.revision);
    let mut revision = 0;
    let mut terminal = false;
    for delivery in deliveries {
        let h = &delivery.header;
        if terminal
            || h.sender_id != message.sender_id
            || h.sender_device_id != message.sender_device_id
            || h.target_id != id
            || h.conversation_id != message.conversation_id
            || h.base_revision != revision
            || delivery.revision != revision + 1
            || delivery.payload.device_id != saved.device_id
            || !matches!(h.kind.as_str(), "edit" | "revoke")
            || !crypto::verify_with_public_key(
                &op::signing_bytes(h, &delivery.payload.device_id, &delivery.payload.ciphertext),
                &delivery.payload.signature,
                &signing_pk,
            )
            .map_err(|_| bad())?
        {
            return Err(bad());
        }
        plain = Zeroizing::new(
            crypto::decrypt(
                &delivery.payload.ciphertext,
                &if message.sender_id == saved.user_id {
                    saved.public_key.as_slice().try_into().map_err(|_| bad())?
                } else {
                    peer_key
                },
                &own_secret,
            )
            .map_err(|_| bad())?,
        );
        if plain.len() > 64 * 1024 {
            return Err(bad());
        }
        revision = delivery.revision;
        terminal = h.kind == "revoke";
    }
    if terminal {
        return Err("消息已撤回".into());
    }
    public_body(std::str::from_utf8(&plain).map_err(|_| bad())?)
}
pub(crate) fn public_body(text: &str) -> Result<String, String> {
    const PREFIX: &str = "\u{1e}LiteSeal:2:";
    if let Some(raw) = text.strip_prefix(PREFIX) {
        #[derive(serde::Deserialize, serde::Serialize)]
        struct Media {
            version: u8,
            id: String,
            name: String,
            size: u64,
            mime: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            duration_ms: Option<u32>,
        }
        // Ignore private descriptor fields while parsing, then serialize only
        // this explicit public allowlist, including on unknown future input.
        let media: Media = serde_json::from_str(raw).map_err(|_| bad())?;
        if media.version != 1
            || media.id.len() > 128
            || media.name.len() > 512
            || media.mime.len() > 128
            || media.size > 20 * 1024 * 1024
            || media.duration_ms.is_some_and(|v| v == 0 || v > 60_000)
        {
            return Err(bad());
        }
        return Ok(format!(
            "{PREFIX}{}",
            serde_json::to_string(&media).map_err(|_| bad())?
        ));
    }
    Ok(text.into())
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::db::{
        models::{ContactModel, MessageModel},
        repository::LocalOperation,
    };
    use liteseal_shared::message_operation::{OperationHeader, OperationPayload};

    pub(crate) fn fixture(
        outgoing: bool,
    ) -> (
        MessageRepository,
        KeystoreData,
        crypto::KeyPair,
        MessageModel,
    ) {
        let own = crypto::generate_keypair().unwrap();
        let peer = crypto::generate_keypair().unwrap();
        let saved = KeystoreData {
            user_id: "alice".into(),
            device_id: "alice-phone".into(),
            server_url: "http://localhost".into(),
            token: "synthetic".into(),
            refresh_token: String::new(),
            public_key: own.public_key.to_vec(),
            secret_key: own.secret_key.to_vec(),
            ed25519_pk: own.ed25519_pk.to_vec(),
            ed25519_sk: own.ed25519_sk.to_vec(),
        };
        let db = MessageRepository::new(":memory:").unwrap();
        db.insert_contact(&ContactModel {
            user_id: "bob".into(),
            username: "Bob".into(),
            public_key: peer.public_key.to_vec(),
            ed25519_pk: Some(peer.ed25519_pk.to_vec()),
            trust_state: "verified".into(),
            key_changed: false,
            fingerprint: "test".into(),
            added_at: 1,
        })
        .unwrap();
        let (
            sender,
            sender_device,
            recipient,
            recipient_device,
            encrypt_pk,
            encrypt_sk,
            signing_sk,
        ) = if outgoing {
            (
                "alice",
                "alice-phone",
                "bob",
                "bob-pc",
                &peer.public_key,
                &own.secret_key,
                &own.ed25519_sk,
            )
        } else {
            (
                "bob",
                "bob-pc",
                "alice",
                "alice-phone",
                &own.public_key,
                &peer.secret_key,
                &peer.ed25519_sk,
            )
        };
        let ciphertext = crypto::encrypt("原始正文 🦭".as_bytes(), encrypt_pk, encrypt_sk).unwrap();
        let mut wire = SignedEnvelopeV2 {
            protocol_version: 2,
            message_id: "original".into(),
            conversation_id: chat::canonical_conversation_id("alice", "bob"),
            sender_user_id: sender.into(),
            sender_device_id: sender_device.into(),
            recipient_user_id: recipient.into(),
            recipient_device_id: recipient_device.into(),
            sender_seq: 1,
            prev_hash: vec![],
            sent_at: 1234,
            message_type: "text".into(),
            ciphertext: ciphertext.clone(),
            signature: vec![],
        };
        wire.signature = crypto::sign(&wire.signing_bytes().unwrap(), signing_sk).unwrap();
        let message = MessageModel {
            id: wire.message_id.clone(),
            conversation_id: wire.conversation_id.clone(),
            sender_id: sender.into(),
            sender_device_id: sender_device.into(),
            sender_seq: 1,
            timestamp: 1234,
            message_type: "text".into(),
            local_state: "received".into(),
            expire_at: None,
            ciphertext,
            signature: wire.signature.clone(),
            prev_hash: vec![],
        };
        if outgoing {
            db.prepare_outgoing(
                &message,
                vec![EncryptedPayload {
                    recipient_user_id: recipient.into(),
                    recipient_device_id: recipient_device.into(),
                    ciphertext: wire.ciphertext.clone(),
                    signature: wire.signature.clone(),
                }],
                |_, _, _| Ok(wire.signature.clone()),
            )
            .unwrap();
        } else {
            db.insert_received(&message, 2).unwrap();
        }
        (db, saved, peer, message)
    }
    fn change(
        db: &MessageRepository,
        saved: &KeystoreData,
        peer: &crypto::KeyPair,
        message: &MessageModel,
        revision: i64,
        kind: &str,
    ) {
        let header = OperationHeader {
            id: format!("op-{revision}"),
            target_id: message.id.clone(),
            conversation_id: message.conversation_id.clone(),
            sender_id: "bob".into(),
            sender_device_id: "bob-pc".into(),
            kind: kind.into(),
            base_revision: revision - 1,
        };
        let pk: [u8; 32] = saved.public_key.as_slice().try_into().unwrap();
        let ciphertext = crypto::encrypt("编辑后的正文".as_bytes(), &pk, &peer.secret_key).unwrap();
        let signature = crypto::sign(
            &op::signing_bytes(&header, &saved.device_id, &ciphertext),
            &peer.ed25519_sk,
        )
        .unwrap();
        let delivery = OperationDelivery {
            header: header.clone(),
            payload: OperationPayload {
                device_id: saved.device_id.clone(),
                ciphertext,
                signature,
            },
            revision,
            accepted_at: 1235,
        };
        db.save_operation(
            &saved.user_id,
            &saved.device_id,
            &LocalOperation {
                id: header.id,
                target_id: message.id.clone(),
                conversation_id: message.conversation_id.clone(),
                body: serde_json::to_string(&delivery).unwrap(),
                status: "accepted".into(),
                error: None,
            },
        )
        .unwrap();
    }
    #[test]
    fn incoming_original_edit_retract_and_hidden_never_fall_back_to_stale_body() {
        let (db, saved, peer, message) = fixture(false);
        assert_eq!(read(&db, &saved, &message.id).unwrap(), "原始正文 🦭");
        change(&db, &saved, &peer, &message, 1, "edit");
        assert_eq!(read(&db, &saved, &message.id).unwrap(), "编辑后的正文");
        change(&db, &saved, &peer, &message, 2, "revoke");
        assert!(read(&db, &saved, &message.id).is_err());
        let (db, saved, _, message) = fixture(false);
        db.delete_message_locally(&saved.user_id, &message.conversation_id, &message.id)
            .unwrap();
        assert!(read(&db, &saved, &message.id).is_err());
    }
    #[test]
    fn missing_revision_and_tampered_original_evidence_fail_closed() {
        let (db, saved, peer, message) = fixture(false);
        change(&db, &saved, &peer, &message, 2, "edit");
        assert!(read(&db, &saved, &message.id).is_err());
        let (db, saved, _, mut message) = fixture(false);
        message.timestamp += 1;
        let corrupted = MessageRepository::new(":memory:").unwrap();
        corrupted
            .insert_contact(&db.get_contact("bob").unwrap().unwrap())
            .unwrap();
        corrupted.insert_received(&message, 2).unwrap();
        assert!(read(&corrupted, &saved, &message.id).is_err());
    }
    #[test]
    fn outgoing_projection_requires_original_saved_wire_and_current_contact() {
        let (db, saved, _, message) = fixture(true);
        assert_eq!(read(&db, &saved, &message.id).unwrap(), "原始正文 🦭");
        let mut changed = db.get_contact("bob").unwrap().unwrap();
        changed.public_key = crypto::generate_keypair().unwrap().public_key.to_vec();
        db.insert_contact(&changed).unwrap();
        assert!(read(&db, &saved, &message.id).is_err());
    }
    #[test]
    fn attachment_projection_strips_all_private_and_unknown_fields() {
        let input="\u{1e}LiteSeal:2:{\"version\":1,\"id\":\"synthetic\",\"name\":\"voice.webm\",\"size\":100,\"mime\":\"audio/webm\",\"duration_ms\":1200,\"key\":[42,43],\"secret_future_field\":\"synthetic secret\"}";
        let result = public_body(input).unwrap();
        assert!(result.contains("duration_ms"));
        assert!(!result.contains("key"));
        assert!(!result.contains("secret"));
        assert!(public_body("\u{1e}LiteSeal:2:broken").is_err());
        assert_eq!(public_body("普通正文 🦭").unwrap(), "普通正文 🦭");
    }
}
