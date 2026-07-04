use liteseal_app_lib::db::models::{
    AttachmentModel, ContactModel, ConversationModel, DeviceModel, MessageModel,
};
use liteseal_app_lib::db::repository::MessageRepository;

#[test]
fn test_insert_and_get_message() {
    let repo = MessageRepository::new(":memory:").unwrap();

    let msg = MessageModel {
        id: "msg-1".to_string(),
        conversation_id: "conv-1".to_string(),
        sender_id: "user-1".to_string(),
        sender_device_id: "device-1".to_string(),
        sender_seq: 1,
        timestamp: 1234567890,
        message_type: "text".to_string(),
        local_state: "sent".to_string(),
        expire_at: None,
        ciphertext: vec![1, 2, 3],
        signature: vec![4, 5, 6],
        prev_hash: vec![7, 8, 9],
    };

    repo.insert_message(&msg).unwrap();
    let retrieved = repo.get_message("msg-1").unwrap().unwrap();

    assert_eq!(retrieved.id, "msg-1");
    assert_eq!(retrieved.conversation_id, "conv-1");
    assert_eq!(retrieved.ciphertext, vec![1, 2, 3]);
}

#[test]
fn test_get_messages_by_conversation() {
    let repo = MessageRepository::new(":memory:").unwrap();

    for i in 0..5 {
        let msg = MessageModel {
            id: format!("msg-{}", i),
            conversation_id: "conv-1".to_string(),
            sender_id: "user-1".to_string(),
            sender_device_id: "device-1".to_string(),
            sender_seq: i,
            timestamp: 1234567890 + i,
            message_type: "text".to_string(),
            local_state: "sent".to_string(),
            expire_at: None,
            ciphertext: vec![i as u8],
            signature: vec![],
            prev_hash: vec![],
        };
        repo.insert_message(&msg).unwrap();
    }

    let messages = repo.get_messages_by_conversation("conv-1", 10, 0).unwrap();
    assert_eq!(messages.len(), 5);
    assert_eq!(messages[0].id, "msg-0");
    assert_eq!(messages[4].id, "msg-4");
}

#[test]
fn test_update_message_state() {
    let repo = MessageRepository::new(":memory:").unwrap();

    let msg = MessageModel {
        id: "msg-state".to_string(),
        conversation_id: "conv-1".to_string(),
        sender_id: "user-1".to_string(),
        sender_device_id: "device-1".to_string(),
        sender_seq: 1,
        timestamp: 1234567890,
        message_type: "text".to_string(),
        local_state: "pending".to_string(),
        expire_at: None,
        ciphertext: vec![1, 2, 3],
        signature: vec![],
        prev_hash: vec![],
    };

    repo.insert_message(&msg).unwrap();
    repo.update_message_state("msg-state", "delivered").unwrap();

    let updated = repo.get_message("msg-state").unwrap().unwrap();
    assert_eq!(updated.local_state, "delivered");
    assert!(repo.update_message_state("missing", "offline").is_err());
}

#[test]
fn test_insert_message_is_idempotent_for_duplicate_ids() {
    let repo = MessageRepository::new(":memory:").unwrap();

    let msg = MessageModel {
        id: "msg-dupe".to_string(),
        conversation_id: "conv-1".to_string(),
        sender_id: "user-1".to_string(),
        sender_device_id: "device-1".to_string(),
        sender_seq: 1,
        timestamp: 1000,
        message_type: "text".to_string(),
        local_state: "received".to_string(),
        expire_at: None,
        ciphertext: vec![1],
        signature: vec![],
        prev_hash: vec![],
    };

    repo.insert_message(&msg).unwrap();
    repo.insert_message(&msg).unwrap();

    let messages = repo.get_messages_by_conversation("conv-1", 10, 0).unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].id, "msg-dupe");
}

#[test]
fn test_delete_message() {
    let repo = MessageRepository::new(":memory:").unwrap();

    let msg = MessageModel {
        id: "msg-del".to_string(),
        conversation_id: "conv-1".to_string(),
        sender_id: "user-1".to_string(),
        sender_device_id: "device-1".to_string(),
        sender_seq: 1,
        timestamp: 1234567890,
        message_type: "text".to_string(),
        local_state: "sent".to_string(),
        expire_at: None,
        ciphertext: vec![1, 2, 3],
        signature: vec![],
        prev_hash: vec![],
    };

    repo.insert_message(&msg).unwrap();
    assert!(repo.get_message("msg-del").unwrap().is_some());

    repo.delete_message("msg-del").unwrap();
    assert!(repo.get_message("msg-del").unwrap().is_none());
}

#[test]
fn test_conversation_operations() {
    let repo = MessageRepository::new(":memory:").unwrap();

    let conv = ConversationModel {
        id: "conv-1".to_string(),
        conversation_type: "direct".to_string(),
        created_at: 1000,
        updated_at: 1000,
        storage_policy: Some("standard".to_string()),
        privacy_mode: Some("normal".to_string()),
    };

    repo.insert_conversation(&conv).unwrap();
    let retrieved = repo.get_conversation("conv-1").unwrap().unwrap();

    assert_eq!(retrieved.id, "conv-1");
    assert_eq!(retrieved.conversation_type, "direct");
    assert_eq!(retrieved.storage_policy, Some("standard".to_string()));

    repo.update_conversation_timestamp("conv-1", 2000).unwrap();
    let updated = repo.get_conversation("conv-1").unwrap().unwrap();
    assert_eq!(updated.updated_at, 2000);
}

#[test]
fn test_attachment_operations() {
    let repo = MessageRepository::new(":memory:").unwrap();

    let att = AttachmentModel {
        id: "att-1".to_string(),
        message_id: "msg-1".to_string(),
        blob_id: "blob-1".to_string(),
        encrypted_name: vec![10, 20, 30],
        encrypted_mime: vec![40, 50, 60],
        size: 1024,
        downloaded: false,
        pinned: false,
        expire_at: Some(9999),
        last_accessed_at: None,
    };

    repo.insert_attachment(&att).unwrap();
    let retrieved = repo.get_attachment("att-1").unwrap().unwrap();

    assert_eq!(retrieved.id, "att-1");
    assert_eq!(retrieved.message_id, "msg-1");
    assert_eq!(retrieved.encrypted_name, vec![10, 20, 30]);
    assert_eq!(retrieved.size, 1024);
    assert!(!retrieved.downloaded);

    repo.update_attachment_downloaded("att-1", true).unwrap();
    let updated = repo.get_attachment("att-1").unwrap().unwrap();
    assert!(updated.downloaded);
}

#[test]
fn test_get_attachments_by_message() {
    let repo = MessageRepository::new(":memory:").unwrap();

    for i in 0..3 {
        let att = AttachmentModel {
            id: format!("att-{}", i),
            message_id: "msg-1".to_string(),
            blob_id: format!("blob-{}", i),
            encrypted_name: vec![i as u8],
            encrypted_mime: vec![],
            size: 100 * i,
            downloaded: false,
            pinned: false,
            expire_at: None,
            last_accessed_at: None,
        };
        repo.insert_attachment(&att).unwrap();
    }

    let attachments = repo.get_attachments_by_message("msg-1").unwrap();
    assert_eq!(attachments.len(), 3);
}

#[test]
fn test_delete_attachment() {
    let repo = MessageRepository::new(":memory:").unwrap();

    let att = AttachmentModel {
        id: "att-del".to_string(),
        message_id: "msg-1".to_string(),
        blob_id: "blob-1".to_string(),
        encrypted_name: vec![],
        encrypted_mime: vec![],
        size: 500,
        downloaded: false,
        pinned: false,
        expire_at: None,
        last_accessed_at: None,
    };

    repo.insert_attachment(&att).unwrap();
    assert!(repo.get_attachment("att-del").unwrap().is_some());

    repo.delete_attachment("att-del").unwrap();
    assert!(repo.get_attachment("att-del").unwrap().is_none());
}

#[test]
fn test_device_operations() {
    let repo = MessageRepository::new(":memory:").unwrap();

    let device = DeviceModel {
        id: "device-1".to_string(),
        user_id: "user-1".to_string(),
        public_key: vec![1, 2, 3, 4],
        created_at: 1000,
        last_seen: 2000,
    };

    repo.insert_device(&device).unwrap();
    let retrieved = repo.get_device("device-1").unwrap().unwrap();

    assert_eq!(retrieved.id, "device-1");
    assert_eq!(retrieved.user_id, "user-1");
    assert_eq!(retrieved.public_key, vec![1, 2, 3, 4]);
}

#[test]
fn test_message_not_found() {
    let repo = MessageRepository::new(":memory:").unwrap();
    let result = repo.get_message("nonexistent").unwrap();
    assert!(result.is_none());
}

#[test]
fn test_conversation_not_found() {
    let repo = MessageRepository::new(":memory:").unwrap();
    let result = repo.get_conversation("nonexistent").unwrap();
    assert!(result.is_none());
}

#[test]
fn test_contact_operations() {
    let repo = MessageRepository::new(":memory:").unwrap();

    let contact = ContactModel {
        user_id: "user-1".to_string(),
        username: "alice".to_string(),
        public_key: vec![1, 2, 3],
        ed25519_pk: None,
        trust_state: "unverified".to_string(),
        fingerprint: "fingerprint-1".to_string(),
        key_changed: false,
        added_at: 1000,
    };

    repo.insert_contact(&contact).unwrap();

    let retrieved = repo.get_contact("user-1").unwrap().unwrap();
    assert_eq!(retrieved.user_id, "user-1");
    assert_eq!(retrieved.username, "alice");
    assert_eq!(retrieved.public_key, vec![1, 2, 3]);
    assert_eq!(retrieved.trust_state, "unverified");
    assert_eq!(retrieved.fingerprint, "fingerprint-1");

    repo.update_contact_trust("user-1", "verified").unwrap();
    let verified = repo.get_contact("user-1").unwrap().unwrap();
    assert_eq!(verified.trust_state, "verified");

    let contact2 = ContactModel {
        user_id: "user-2".to_string(),
        username: "bob".to_string(),
        public_key: vec![4, 5, 6],
        ed25519_pk: None,
        trust_state: "unverified".to_string(),
        fingerprint: "fingerprint-2".to_string(),
        key_changed: false,
        added_at: 2000,
    };
    repo.insert_contact(&contact2).unwrap();

    let all = repo.get_contacts().unwrap();
    assert_eq!(all.len(), 2);

    repo.delete_contact("user-1").unwrap();
    assert!(repo.get_contact("user-1").unwrap().is_none());
    assert_eq!(repo.get_contacts().unwrap().len(), 1);
}

#[test]
fn test_storage_stats() {
    let repo = MessageRepository::new(":memory:").unwrap();

    let conv = ConversationModel {
        id: "conv-1".to_string(),
        conversation_type: "direct".to_string(),
        created_at: 1000,
        updated_at: 1000,
        storage_policy: None,
        privacy_mode: None,
    };
    repo.insert_conversation(&conv).unwrap();

    for i in 0..3 {
        let msg = MessageModel {
            id: format!("msg-{}", i),
            conversation_id: "conv-1".to_string(),
            sender_id: "user-1".to_string(),
            sender_device_id: "device-1".to_string(),
            sender_seq: i,
            timestamp: 1000 + i,
            message_type: "text".to_string(),
            local_state: "sent".to_string(),
            expire_at: None,
            ciphertext: vec![0u8; 10],
            signature: vec![],
            prev_hash: vec![],
        };
        repo.insert_message(&msg).unwrap();
    }

    let contact = ContactModel {
        user_id: "user-2".to_string(),
        username: "bob".to_string(),
        public_key: vec![],
        ed25519_pk: None,
        trust_state: "unverified".to_string(),
        fingerprint: "".to_string(),
        key_changed: false,
        added_at: 1000,
    };
    repo.insert_contact(&contact).unwrap();

    let stats = repo.get_storage_stats().unwrap();
    assert_eq!(stats.conversation_count, 1);
    assert_eq!(stats.message_count, 3);
    assert_eq!(stats.contact_count, 1);
    assert_eq!(stats.ciphertext_bytes, 30);
}

#[test]
fn test_clear_expired_messages() {
    let repo = MessageRepository::new(":memory:").unwrap();

    let msg_expired = MessageModel {
        id: "msg-exp".to_string(),
        conversation_id: "conv-1".to_string(),
        sender_id: "user-1".to_string(),
        sender_device_id: "device-1".to_string(),
        sender_seq: 1,
        timestamp: 1000,
        message_type: "text".to_string(),
        local_state: "sent".to_string(),
        expire_at: Some(5000),
        ciphertext: vec![1],
        signature: vec![],
        prev_hash: vec![],
    };
    repo.insert_message(&msg_expired).unwrap();

    let msg_fresh = MessageModel {
        id: "msg-fresh".to_string(),
        conversation_id: "conv-1".to_string(),
        sender_id: "user-1".to_string(),
        sender_device_id: "device-1".to_string(),
        sender_seq: 2,
        timestamp: 1000,
        message_type: "text".to_string(),
        local_state: "sent".to_string(),
        expire_at: Some(99999),
        ciphertext: vec![2],
        signature: vec![],
        prev_hash: vec![],
    };
    repo.insert_message(&msg_fresh).unwrap();

    let msg_no_expire = MessageModel {
        id: "msg-keep".to_string(),
        conversation_id: "conv-1".to_string(),
        sender_id: "user-1".to_string(),
        sender_device_id: "device-1".to_string(),
        sender_seq: 3,
        timestamp: 1000,
        message_type: "text".to_string(),
        local_state: "sent".to_string(),
        expire_at: None,
        ciphertext: vec![3],
        signature: vec![],
        prev_hash: vec![],
    };
    repo.insert_message(&msg_no_expire).unwrap();

    let deleted = repo.clear_expired_messages(6000).unwrap();
    assert_eq!(deleted, 1);
    assert!(repo.get_message("msg-exp").unwrap().is_none());
    assert!(repo.get_message("msg-fresh").unwrap().is_some());
    assert!(repo.get_message("msg-keep").unwrap().is_some());
}

#[test]
fn test_clear_unpinned_attachments() {
    let repo = MessageRepository::new(":memory:").unwrap();

    let att_unpinned = AttachmentModel {
        id: "att-unpinned".to_string(),
        message_id: "msg-1".to_string(),
        blob_id: "blob-1".to_string(),
        encrypted_name: vec![],
        encrypted_mime: vec![],
        size: 100,
        downloaded: false,
        pinned: false,
        expire_at: None,
        last_accessed_at: None,
    };
    repo.insert_attachment(&att_unpinned).unwrap();

    let att_pinned = AttachmentModel {
        id: "att-pinned".to_string(),
        message_id: "msg-1".to_string(),
        blob_id: "blob-2".to_string(),
        encrypted_name: vec![],
        encrypted_mime: vec![],
        size: 200,
        downloaded: false,
        pinned: true,
        expire_at: None,
        last_accessed_at: None,
    };
    repo.insert_attachment(&att_pinned).unwrap();

    let deleted = repo.clear_unpinned_attachments().unwrap();
    assert_eq!(deleted, 1);
    assert!(repo.get_attachment("att-unpinned").unwrap().is_none());
    assert!(repo.get_attachment("att-pinned").unwrap().is_some());
}
