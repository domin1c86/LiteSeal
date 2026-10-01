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
    increment(&store);
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
