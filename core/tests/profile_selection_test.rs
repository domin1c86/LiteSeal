#![cfg(windows)]
use liteseal_core::{
    backup::WorkDirectory,
    trusted_devices::{
        profiles::selection::{Binding, Store, Target},
        witness::platform::Protection,
    },
};
#[test]
fn explicit_selection_reopens_cas_protects_changes_and_clear_never_falls_back() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let path = work.0.join("selected.db");
    drop(rusqlite::Connection::open(&path).unwrap());
    let p = Protection::isolated_test();
    let open = || Store::open(&path, p.witness(&path).unwrap()).unwrap();
    let mut store = open();
    assert_eq!(store.current().unwrap().generation, 0);
    let root = Binding {
        target: Target::Root {},
        fingerprint: [1; 32],
    };
    let first = store.replace(0, Some(root.clone())).unwrap();
    assert_eq!(first.generation, 1);
    assert_eq!(open().current().unwrap(), first);
    let join = Binding {
        target: Target::Join {
            profile_id: uuid::Uuid::new_v4().to_string(),
        },
        fingerprint: [2; 32],
    };
    assert!(store.replace(0, Some(join.clone())).is_err());
    assert_eq!(store.current().unwrap(), first);
    let second = store.replace(1, Some(join)).unwrap();
    assert_eq!(second.generation, 2);
    let cleared = store.replace(2, None).unwrap();
    assert_eq!(cleared.generation, 3);
    assert_eq!(open().current().unwrap(), cleared);
    assert!(store.replace(2, Some(root)).is_err());
}
#[test]
fn rollback_and_invalid_target_never_change_selection() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let path = work.0.join("selected.db");
    drop(rusqlite::Connection::open(&path).unwrap());
    let p = Protection::isolated_test();
    let mut s = Store::open(&path, p.witness(&path).unwrap()).unwrap();
    assert!(s
        .replace(
            0,
            Some(Binding {
                target: Target::Join {
                    profile_id: "../wrong".into()
                },
                fingerprint: [1; 32]
            })
        )
        .is_err());
    assert_eq!(s.current().unwrap().generation, 0);
    s.replace(
        0,
        Some(Binding {
            target: Target::Root {},
            fingerprint: [1; 32],
        }),
    )
    .unwrap();
    drop(s);
    let before = std::fs::read(&path).unwrap();
    let mut s = Store::open(&path, p.witness(&path).unwrap()).unwrap();
    s.replace(1, None).unwrap();
    drop(s);
    std::fs::write(&path, before).unwrap();
    assert!(Store::open(&path, p.witness(&path).unwrap()).is_err());
}
