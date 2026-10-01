#![cfg(windows)]
use liteseal_core::{
    backup::WorkDirectory,
    keystore::{self, KeystoreData},
    secret_store,
    trusted_devices::{coordinator::DeviceCoordinator, profiles::JoinProfileStore},
};
use liteseal_shared::crypto;
use std::fs;

#[test]
fn dpapi_join_profile_and_original_task_reopen_without_changing_normal_identity() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let original = work.0.join("normal.bin");
    let original_keys = crypto::generate_keypair().unwrap();
    keystore::save_keypair_to(
        &original,
        KeystoreData {
            user_id: "synthetic-original".into(),
            token: "isolated-access".into(),
            refresh_token: "isolated-refresh".into(),
            device_id: "original".into(),
            server_url: "http://127.0.0.1:9".into(),
            public_key: original_keys.public_key.to_vec(),
            secret_key: original_keys.secret_key.to_vec(),
            ed25519_pk: original_keys.ed25519_pk.to_vec(),
            ed25519_sk: original_keys.ed25519_sk.to_vec(),
        },
    )
    .unwrap();
    let original_bytes = fs::read(&original).unwrap();
    let root = work.0.join("joining");
    let store = JoinProfileStore::new(root.clone());
    let profile = store
        .create("http://127.0.0.1:9/", " Alice ", "加入 Windows 中文 🦭")
        .unwrap();
    let view = profile.view();
    let keys = profile.keys().unwrap();
    assert_eq!(view.origin, "http://127.0.0.1:9");
    assert_eq!(view.username, "Alice");
    assert!(
        keys.public_key != original_keys.public_key && keys.ed25519_pk != original_keys.ed25519_pk
    );
    let public = serde_json::to_string(&view).unwrap();
    for field in ["secret_key", "ed25519_sk", "token", "password"] {
        assert!(!public.contains(field));
    }
    let protected = fs::read(root.join(&view.id).join("identity.bin")).unwrap();
    assert!(!protected.windows(32).any(|bytes| bytes == keys.secret_key));
    let client = DeviceCoordinator::open(
        &store.database(&view.id).unwrap(),
        profile.owner().unwrap(),
        &keys,
    )
    .unwrap();
    let task = client.tasks(&keys).unwrap().remove(0);
    drop(client);
    drop(profile);
    let profile = store.load(&view.id).unwrap();
    let restored = profile.keys().unwrap();
    assert!(restored.secret_key == keys.secret_key && restored.ed25519_sk == keys.ed25519_sk);
    let reopened = DeviceCoordinator::open(
        &store.database(&view.id).unwrap(),
        profile.owner().unwrap(),
        &restored,
    )
    .unwrap();
    let info = reopened.join_info(&task.id, &restored).unwrap();
    assert_eq!(info.task.id, task.id);
    assert!(info.root_account.is_none());
    assert_eq!(fs::read(original).unwrap(), original_bytes);
    assert_eq!(store.list().unwrap().len(), 1);
}

#[test]
fn profile_binding_corruption_bad_keys_versions_tokens_and_oversize_fail_closed() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let root = work.0.join("joining");
    let store = JoinProfileStore::new(root.clone());
    let first = store
        .create("http://127.0.0.1:9", "Alice", "one")
        .unwrap()
        .view();
    let second = store
        .create("http://127.0.0.1:9", "Bob", "two")
        .unwrap()
        .view();
    let first_path = root.join(&first.id).join("identity.bin");
    let second_path = root.join(&second.id).join("identity.bin");
    let first_bytes = fs::read(&first_path).unwrap();
    let second_bytes = fs::read(&second_path).unwrap();
    fs::write(&second_path, &first_bytes).unwrap();
    assert!(store.load(&second.id).is_err());
    fs::write(&second_path, second_bytes).unwrap();
    let original = secret_store::unprotect_local(&first_bytes).unwrap();
    let record: serde_json::Value = serde_json::from_slice(&original).unwrap();
    for change in 0..5 {
        let mut bad = record.clone();
        match change {
            0 => bad["version"] = serde_json::json!(2),
            1 => bad["id"] = serde_json::json!(second.id),
            2 => bad["identity"]["token"] = serde_json::json!("forbidden-synthetic"),
            3 => {
                bad["identity"]["secret_key"] =
                    serde_json::json!(crypto::generate_keypair().unwrap().secret_key)
            }
            _ => bad["identity"]["server_url"] = serde_json::json!("http://127.0.0.1:9/path"),
        }
        secret_store::secret_store(first_path.clone())
            .save(&serde_json::to_vec(&bad).unwrap())
            .unwrap();
        assert!(store.load(&first.id).is_err());
    }
    fs::write(&first_path, vec![0; 32769]).unwrap();
    assert!(store.load(&first.id).is_err());
    let listed = store.list().unwrap();
    assert_eq!(listed.iter().filter(|row| row.error.is_some()).count(), 1);
    assert!(store.load(&second.id).is_ok());
    fs::write(&first_path, first_bytes).unwrap();
    fs::copy(
        store.database(&first.id).unwrap(),
        root.join(&second.id).join("tasks.db"),
    )
    .unwrap();
    assert!(store.database(&second.id).is_err());
    assert!(store.load(&first.id).is_ok());
    fs::remove_file(root.join(&first.id).join("tasks.db")).unwrap();
    assert!(store.database(&first.id).is_err());
    assert!(!root.join(&first.id).join("tasks.db").exists());
}

#[test]
fn concurrent_allocations_share_eight_profile_limit_without_replacing_keys() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let root = work.0.join("joining");
    let jobs = (0..10)
        .map(|n| {
            let path = root.clone();
            std::thread::spawn(move || {
                JoinProfileStore::new(path).create(
                    "http://127.0.0.1:9",
                    "Alice",
                    &format!("device {n}"),
                )
            })
        })
        .collect::<Vec<_>>();
    let results = jobs
        .into_iter()
        .map(|job| job.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|v| v.is_ok()).count(), 8);
    assert!(results
        .iter()
        .filter_map(|v| v.as_ref().err())
        .all(|error| error.contains("八个")));
    let store = JoinProfileStore::new(root);
    let listed = store.list().unwrap();
    assert_eq!(listed.len(), 8);
    assert!(listed
        .iter()
        .all(|item| item.profile.is_some() && item.error.is_none()));
}

#[test]
fn cleanup_checks_explicit_files_and_preserves_unknown_content_and_invalid_paths() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let root = work.0.join("joining");
    let store = JoinProfileStore::new(root.clone());
    assert!(store
        .create("http://127.0.0.1:9/path", "Alice", "one")
        .is_err());
    assert!(!root.exists());
    let view = store
        .create("http://127.0.0.1:9", "Alice", "one")
        .unwrap()
        .view();
    for id in ["..", "../outside", "not-a-uuid"] {
        assert!(store.load(id).is_err());
        assert!(store.remove(id).is_err());
    }
    let directory = root.join(&view.id);
    fs::write(directory.join("preserve.txt"), "synthetic unknown file").unwrap();
    assert!(store.remove(&view.id).is_err());
    assert!(store.load(&view.id).is_ok());
    assert!(store.remove_empty(&view.id).is_err());
    fs::remove_file(directory.join("preserve.txt")).unwrap();
    store.remove(&view.id).unwrap();
    assert!(!directory.exists());
    let empty = uuid::Uuid::new_v4().to_string();
    fs::create_dir(root.join(&empty)).unwrap();
    assert!(store.list().unwrap()[0].error.is_some());
    store.remove_empty(&empty).unwrap();
    assert!(store.list().unwrap().is_empty());
}
