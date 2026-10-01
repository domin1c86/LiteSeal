#![cfg(windows)]
use liteseal_core::{
    backup::WorkDirectory,
    trusted_devices::{
        tasks::*,
        witness::{windows::WindowsStore, *},
    },
};
use liteseal_shared::crypto;
use std::{fs, path::PathBuf, sync::Arc};
struct Native(Arc<WindowsStore>);
impl Drop for Native {
    fn drop(&mut self) {
        self.0.clear_isolated().unwrap();
    }
}
fn native(path: &std::path::Path) -> Native {
    Native(Arc::new(
        WindowsStore::isolated(path, uuid::Uuid::new_v4()).unwrap(),
    ))
}
#[test]
fn actual_windows_credential_survives_database_restore_and_detects_missing_state() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let path = work.0.join("tasks.db");
    let keys = crypto::generate_keypair().unwrap();
    let owner = TaskOwner::for_join(
        "http://127.0.0.1:9",
        "synthetic",
        &uuid::Uuid::new_v4().to_string(),
        &keys,
    )
    .unwrap();
    let mut tasks = DeviceTaskStore::open(&path, owner.clone(), &keys).unwrap();
    let native = native(&path);
    tasks
        .protect(Witness::new(&path, native.0.clone()))
        .unwrap();
    let task = tasks.prepare_join("synthetic Windows", &keys).unwrap();
    drop(tasks);
    let old = work.0.join("old.db");
    fs::copy(&path, &old).unwrap();
    let mut tasks = DeviceTaskStore::open(&path, owner.clone(), &keys).unwrap();
    tasks
        .protect(Witness::new(&path, native.0.clone()))
        .unwrap();
    let current = tasks.get(&task.view().id, &keys).unwrap();
    tasks.request_cancel(&current, &keys).unwrap();
    drop(tasks);
    fs::copy(&old, &path).unwrap();
    let mut tasks = DeviceTaskStore::open(&path, owner.clone(), &keys).unwrap();
    assert!(tasks
        .protect(Witness::new(&path, native.0.clone()))
        .is_err());
    drop(tasks);
    native.0.clear_isolated().unwrap();
    let mut tasks = DeviceTaskStore::open(&path, owner, &keys).unwrap();
    assert!(tasks
        .protect(Witness::new(&path, native.0.clone()))
        .is_err());
}
#[test]
fn full_record_size_path_binding_and_production_reset_refusal() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let one = work.0.join("one.db");
    let two = work.0.join("two.db");
    fs::write(&one, []).unwrap();
    fs::write(&two, []).unwrap();
    let id = uuid::Uuid::new_v4();
    let a = Native(Arc::new(WindowsStore::isolated(&one, id).unwrap()));
    let b = Native(Arc::new(WindowsStore::isolated(&two, id).unwrap()));
    assert_ne!(a.0.binding(), b.0.binding());
    let record = vec![7u8; 2048];
    {
        let mut cell = a.0.lock().unwrap();
        cell.write(&record).unwrap();
        assert!(cell.write(&vec![0; 2049]).is_err());
    }
    assert_eq!(
        WindowsStore::isolated(&one, id)
            .unwrap()
            .lock()
            .unwrap()
            .read()
            .unwrap(),
        Some(record)
    );
    assert!(b.0.lock().unwrap().read().unwrap().is_none());
    let production = WindowsStore::open(&one).unwrap();
    assert_ne!(production.binding(), a.0.binding());
    // No production read, write, or deletion occurs in this test.
    assert!(production.clear_isolated().is_err());
}
fn increment(store: &WindowsStore) {
    for _ in 0..30 {
        let mut cell = store.lock().unwrap();
        let n: u32 = serde_json::from_slice(&cell.read().unwrap().unwrap()).unwrap();
        cell.write(&serde_json::to_vec(&(n + 1)).unwrap()).unwrap();
    }
}
#[test]
fn native_child_worker() {
    let Ok(path) = std::env::var("LITESEAL_WITNESS_CHILD_DB") else {
        return;
    };
    let namespace =
        uuid::Uuid::parse_str(&std::env::var("LITESEAL_WITNESS_CHILD_ID").unwrap()).unwrap();
    let store = WindowsStore::isolated(&PathBuf::from(path), namespace).unwrap();
    if let Ok(keyfile) = std::env::var("LITESEAL_WITNESS_CHILD_KEYFILE") {
        let saved =
            liteseal_core::keystore::load_keypair_from(std::path::Path::new(&keyfile)).unwrap();
        let keys = liteseal_core::backup::identity_keys(&saved).unwrap();
        let owner = TaskOwner::for_join(&saved.server_url, &saved.user_id, &saved.device_id, &keys)
            .unwrap();
        let database = PathBuf::from(std::env::var("LITESEAL_WITNESS_CHILD_DB").unwrap());
        let mut tasks = DeviceTaskStore::open(&database, owner, &keys).unwrap();
        tasks
            .protect(Witness::new(&database, Arc::new(CrashAfterPending(store))))
            .unwrap();
        let id = std::env::var("LITESEAL_WITNESS_CHILD_TASK").unwrap();
        let task = tasks.get(&id, &keys).unwrap();
        tasks.request_cancel(&task, &keys).unwrap();
        panic!("child must exit while first external pending write owns the SQLite transaction");
    }
    increment(&store);
}
struct CrashAfterPending(WindowsStore);
struct CrashSlot<'a>(Box<dyn SecureCell + 'a>);
impl SecureCell for CrashSlot<'_> {
    fn read(&mut self) -> Result<Option<Vec<u8>>, String> {
        self.0.read()
    }
    fn write(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.0.write(bytes)?;
        // Test-only termination after native pending persisted, before SQLite
        // commit. No destructor runs; private keys are loaded only from DPAPI.
        std::process::exit(23)
    }
}
impl SecureStore for CrashAfterPending {
    fn binding(&self) -> [u8; 32] {
        self.0.binding()
    }
    fn lock(&self) -> Result<Box<dyn SecureCell + '_>, String> {
        Ok(Box::new(CrashSlot(self.0.lock()?)))
    }
}

#[test]
fn real_process_termination_after_native_pending_recovers_exact_original_patch() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let database = work.0.join("crash.db");
    let keyfile = work.0.join("synthetic.bin");
    let keys = crypto::generate_keypair().unwrap();
    let device = uuid::Uuid::new_v4().to_string();
    let namespace = uuid::Uuid::new_v4();
    let owner = TaskOwner::for_join("http://127.0.0.1:9", "synthetic", &device, &keys).unwrap();
    liteseal_core::keystore::save_keypair_to(
        &keyfile,
        liteseal_core::keystore::KeystoreData {
            user_id: "synthetic".into(),
            device_id: device,
            server_url: "http://127.0.0.1:9".into(),
            token: String::new(),
            refresh_token: String::new(),
            public_key: keys.public_key.to_vec(),
            secret_key: keys.secret_key.to_vec(),
            ed25519_pk: keys.ed25519_pk.to_vec(),
            ed25519_sk: keys.ed25519_sk.to_vec(),
        },
    )
    .unwrap();
    let mut tasks = DeviceTaskStore::open(&database, owner.clone(), &keys).unwrap();
    let native = Native(Arc::new(
        WindowsStore::isolated(&database, namespace).unwrap(),
    ));
    tasks
        .protect(Witness::new(&database, native.0.clone()))
        .unwrap();
    let task = tasks.prepare_join("second", &keys).unwrap();
    let original_credential = task.join_credential().unwrap().to_string();
    drop(tasks);
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "native_child_worker", "--nocapture"])
        .env("LITESEAL_WITNESS_CHILD_DB", &database)
        .env("LITESEAL_WITNESS_CHILD_ID", namespace.to_string())
        .env("LITESEAL_WITNESS_CHILD_KEYFILE", &keyfile)
        .env("LITESEAL_WITNESS_CHILD_TASK", &task.view().id)
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(23));
    let witness = Witness::new(&database, native.0.clone());
    assert!(witness.journal_path().is_file());
    let mut recovered = DeviceTaskStore::open(&database, owner, &keys).unwrap();
    recovered.protect(witness.clone()).unwrap();
    let next = recovered.get(&task.view().id, &keys).unwrap();
    assert_eq!(next.view().phase, TaskPhase::Cancelling);
    assert_eq!(next.view().revision, 1);
    assert!(next.join_credential().unwrap() == original_credential);
    assert!(!witness.journal_path().exists());
}
#[test]
fn named_mutex_serializes_real_parent_and_child_process_updates() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let path = work.0.join("parallel.db");
    fs::write(&path, []).unwrap();
    let id = uuid::Uuid::new_v4();
    let native = Native(Arc::new(WindowsStore::isolated(&path, id).unwrap()));
    native.0.lock().unwrap().write(b"0").unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "native_child_worker", "--nocapture"])
        .env("LITESEAL_WITNESS_CHILD_DB", &path)
        .env("LITESEAL_WITNESS_CHILD_ID", id.to_string())
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    increment(&native.0);
    assert!(child.wait().unwrap().success());
    assert_eq!(
        native.0.lock().unwrap().read().unwrap(),
        Some(b"60".to_vec())
    );
}

#[test]
fn concurrent_distinct_targets_keep_each_original_record() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let mut natives = vec![];
    for n in 0..8 {
        let path = work.0.join(format!("distinct-{n}.db"));
        fs::write(&path, []).unwrap();
        natives.push(native(&path));
    }
    let gate = Arc::new(std::sync::Barrier::new(8));
    let threads = natives
        .iter()
        .enumerate()
        .map(|(n, native)| {
            let store = native.0.clone();
            let gate = gate.clone();
            std::thread::spawn(move || {
                gate.wait();
                let bytes = vec![n as u8; 2048];
                for _ in 0..20 {
                    let mut cell = store.lock().unwrap();
                    cell.write(&bytes).unwrap();
                    assert!(
                        cell.read().unwrap().as_deref() == Some(bytes.as_slice()),
                        "original synthetic target missing or replaced"
                    );
                }
            })
        })
        .collect::<Vec<_>>();
    let results = threads
        .into_iter()
        .map(|thread| thread.join())
        .collect::<Vec<_>>();
    assert!(results.into_iter().all(|result| result.is_ok()));
}
