//! Native-owned mobile identity. Neither this store nor its private snapshots
//! are exported through UniFFI. The shell receives public metadata only.
use crate::{api, keystore::KeystoreData, secret_store::SecretStore};
use liteseal_shared::{backup_crypto, crypto};
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::Mutex};
use zeroize::{Zeroize, Zeroizing};

const MAX_STORE: usize = 64 * 1024;
fn bad() -> String {
    "移动身份存储或范围无法验证；原数据已保留".into()
}
#[derive(Serialize, Deserialize, Zeroize)]
#[serde(deny_unknown_fields)]
struct Stored {
    version: u8,
    username: String,
    data: KeystoreData,
    #[serde(default, skip_serializing_if = "is_false")]
    legacy_cleanup: bool,
}
fn is_false(value: &bool) -> bool {
    !*value
}
#[derive(Clone, Serialize)]
pub struct PublicIdentity {
    pub user_id: String,
    pub device_id: String,
    pub server_url: String,
    pub public_key: Vec<u8>,
    pub ed25519_pk: Vec<u8>,
    pub has_session: bool,
}
pub(crate) struct Snapshot {
    pub epoch: u64,
    pub platform_epoch: u64,
    pub username: String,
    pub data: Zeroizing<KeystoreData>,
}
struct State {
    epoch: u64,
    saved: Option<Zeroizing<Stored>>,
}
pub struct MobileIdentity {
    store: Box<dyn SecretStore + Send + Sync>,
    state: Mutex<State>,
}
impl MobileIdentity {
    pub fn open(path: &Path) -> Result<Self, String> {
        Self::load(
            crate::secret_store::secret_store(path.into()),
            path.exists(),
        )
    }
    fn load(store: Box<dyn SecretStore + Send + Sync>, exists: bool) -> Result<Self, String> {
        let saved = if exists {
            let plain = Zeroizing::new(store.load().map_err(|_| bad())?);
            if plain.len() > MAX_STORE {
                return Err(bad());
            }
            let value =
                Zeroizing::new(serde_json::from_slice::<Stored>(&plain).map_err(|_| bad())?);
            validate(&value)?;
            Some(value)
        } else {
            None
        };
        Ok(Self {
            store,
            state: Mutex::new(State { epoch: 1, saved }),
        })
    }
    fn save(&self, value: &Stored) -> Result<(), String> {
        validate(value)?;
        let bytes = Zeroizing::new(serde_json::to_vec(value).map_err(|_| bad())?);
        if bytes.len() > MAX_STORE {
            return Err(bad());
        }
        self.store.save(&bytes).map_err(|_| bad())
    }
    pub fn public(&self) -> Result<Option<PublicIdentity>, String> {
        let state = self.state.lock().map_err(|_| bad())?;
        Ok(state
            .saved
            .as_ref()
            .filter(|s| !s.data.user_id.is_empty())
            .map(|s| public(&s.data)))
    }
    pub fn restore_legacy(&self) -> Result<Option<PublicIdentity>, String> {
        #[cfg(target_os = "android")]
        return self.restore_legacy_using(
            || crate::android_secret_store::native(3, &[]),
            || crate::android_secret_store::native(4, &[]).map(|_| ()),
        );
        #[cfg(not(target_os = "android"))]
        self.public()
    }
    #[cfg(any(target_os = "android", test))]
    fn restore_legacy_using(
        &self,
        read: impl FnOnce() -> Result<Vec<u8>, String>,
        clear: impl FnOnce() -> Result<(), String>,
    ) -> Result<Option<PublicIdentity>, String> {
        {
            let mut state = self.state.lock().map_err(|_| bad())?;
            if state.saved.is_none() {
                let plain = Zeroizing::new(read()?);
                if !plain.is_empty() {
                    let data = serde_json::from_slice::<KeystoreData>(&plain).map_err(|_| bad())?;
                    let saved = Zeroizing::new(Stored {
                        version: 1,
                        username: String::new(),
                        data,
                        legacy_cleanup: true,
                    });
                    if saved.data.user_id.is_empty() || saved.data.device_id.is_empty() {
                        return Err(bad());
                    }
                    self.save(&saved)?;
                    let read = Zeroizing::new(self.store.load().map_err(|_| bad())?);
                    let checked =
                        Zeroizing::new(serde_json::from_slice::<Stored>(&read).map_err(|_| bad())?);
                    validate(&checked)?;
                    let expected = Zeroizing::new(serde_json::to_vec(&*saved).map_err(|_| bad())?);
                    let actual = Zeroizing::new(serde_json::to_vec(&*checked).map_err(|_| bad())?);
                    if *expected != *actual {
                        return Err(bad());
                    }
                    state.saved = Some(saved);
                }
            }
            if let Some(saved) = state.saved.as_mut().filter(|saved| saved.legacy_cleanup) {
                // This marker survives a failed clear or process restart. No
                // second legacy read can replace the confirmed new identity.
                clear()?;
                saved.legacy_cleanup = false;
                if self.save(saved).is_err() {
                    saved.legacy_cleanup = true;
                    return Err(bad());
                }
            }
        }
        self.public()
    }
    /// Persist the original keys before registration. Failed or unknown results
    /// cannot silently generate a replacement identity on retry.
    pub(crate) fn begin_auth(
        &self,
        username: &str,
        origin: &str,
        registering: bool,
    ) -> Result<Snapshot, String> {
        let username = username.trim();
        let origin =
            liteseal_shared::trusted_device::canonical_origin(origin).map_err(|_| bad())?;
        if username.is_empty() || username.len() > 128 {
            return Err(bad());
        }
        let mut state = self.state.lock().map_err(|_| bad())?;
        if let Some(saved) = &state.saved {
            if (!saved.username.is_empty() && saved.username != username)
                || saved.data.server_url != origin
            {
                return Err("当前原生身份属于另一账号或服务器；不能覆盖".into());
            }
            if registering && !saved.data.user_id.is_empty() {
                return Err("本机已经保存身份；请登录原账号".into());
            }
            if !registering && (saved.data.user_id.is_empty() || saved.data.device_id.is_empty()) {
                return Err("原注册结果尚未确认；保留原密钥，不能创建替换设备".into());
            }
        } else {
            if !registering {
                return Err("此设备没有原身份；须使用原设备授权，不能仅凭密码替换密钥".into());
            }
            let mut keys = crypto::generate_keypair().map_err(|_| bad())?;
            let value = Zeroizing::new(Stored {
                version: 1,
                username: username.into(),
                legacy_cleanup: false,
                data: KeystoreData {
                    user_id: String::new(),
                    token: String::new(),
                    refresh_token: String::new(),
                    device_id: String::new(),
                    server_url: origin,
                    public_key: keys.public_key.to_vec(),
                    secret_key: keys.secret_key.to_vec(),
                    ed25519_pk: keys.ed25519_pk.to_vec(),
                    ed25519_sk: keys.ed25519_sk.to_vec(),
                },
            });
            keys.secret_key.zeroize();
            keys.ed25519_sk.zeroize();
            self.save(&value)?;
            state.saved = Some(value);
        }
        let saved = state.saved.as_ref().ok_or_else(bad)?;
        Ok(Snapshot {
            epoch: state.epoch,
            platform_epoch: crate::mobile_runtime::epoch(),
            username: username.into(),
            data: Zeroizing::new(saved.data.clone()),
        })
    }
    pub(crate) fn snapshot(&self, require_session: bool) -> Result<Snapshot, String> {
        let state = self.state.lock().map_err(|_| bad())?;
        let saved = state
            .saved
            .as_ref()
            .filter(|s| !s.data.user_id.is_empty())
            .ok_or_else(bad)?;
        if require_session && saved.data.token.is_empty() {
            return Err("原生身份已退出会话".into());
        }
        Ok(Snapshot {
            epoch: state.epoch,
            platform_epoch: crate::mobile_runtime::epoch(),
            username: saved.username.clone(),
            data: Zeroizing::new(saved.data.clone()),
        })
    }
    pub(crate) fn check(&self, snapshot: &Snapshot) -> Result<(), String> {
        crate::mobile_runtime::check(snapshot.platform_epoch)?;
        let state = self.state.lock().map_err(|_| bad())?;
        if state.epoch != snapshot.epoch
            || state.saved.as_ref().is_none_or(|s| {
                s.data.public_key != snapshot.data.public_key
                    || s.data.device_id != snapshot.data.device_id
                    || s.data.user_id != snapshot.data.user_id
            })
        {
            return Err("移动身份已切换或退出，拒绝迟到结果".into());
        }
        Ok(())
    }
    pub(crate) fn commit_auth(
        &self,
        snapshot: &Snapshot,
        result: api::RegisterResult,
    ) -> Result<PublicIdentity, String> {
        let _commit = crate::mobile_runtime::COMMIT.lock().map_err(|_| bad())?;
        crate::mobile_runtime::check(snapshot.platform_epoch)?;
        let mut state = self.state.lock().map_err(|_| bad())?;
        if state.epoch != snapshot.epoch {
            return Err("移动身份已切换或退出，拒绝迟到会话".into());
        }
        let saved = state.saved.as_ref().ok_or_else(bad)?;
        if saved.data.public_key != snapshot.data.public_key
            || saved.data.server_url != snapshot.data.server_url
        {
            return Err(bad());
        }
        let token = result.access_token.unwrap_or(result.token);
        let device = result
            .device_id
            .unwrap_or_else(|| snapshot.data.device_id.clone());
        if result.user_id.is_empty()
            || device.is_empty()
            || token.is_empty()
            || (!saved.data.user_id.is_empty() && saved.data.user_id != result.user_id)
            || (!saved.data.device_id.is_empty() && saved.data.device_id != device)
        {
            return Err(bad());
        }
        let mut next = Zeroizing::new(Stored {
            version: 1,
            username: snapshot.username.clone(),
            data: saved.data.clone(),
            legacy_cleanup: saved.legacy_cleanup,
        });
        next.data.user_id = result.user_id;
        next.data.device_id = device;
        next.data.token = token;
        next.data.refresh_token = result.refresh_token.unwrap_or_default();
        self.save(&next)?;
        state.epoch = state.epoch.checked_add(1).ok_or_else(bad)?;
        let visible = public(&next.data);
        state.saved = Some(next);
        Ok(visible)
    }
    /// Sign-out retires all outstanding leases and retains the identity needed
    /// for offline history. A failed disk write is reported, never swallowed.
    pub fn clear_session(&self) -> Result<(), String> {
        #[cfg(target_os = "android")]
        crate::mobile_runtime::retire();
        let mut state = self.state.lock().map_err(|_| bad())?;
        state.epoch = state.epoch.checked_add(1).ok_or_else(bad)?;
        if let Some(saved) = &mut state.saved {
            saved.data.token.zeroize();
            saved.data.token.clear();
            saved.data.refresh_token.zeroize();
            saved.data.refresh_token.clear();
            self.save(saved)?;
        }
        Ok(())
    }
}
fn public(data: &KeystoreData) -> PublicIdentity {
    PublicIdentity {
        user_id: data.user_id.clone(),
        device_id: data.device_id.clone(),
        server_url: data.server_url.clone(),
        public_key: data.public_key.clone(),
        ed25519_pk: data.ed25519_pk.clone(),
        has_session: !data.token.is_empty(),
    }
}
fn validate(saved: &Stored) -> Result<(), String> {
    if saved.version != 1
        || (saved.username.is_empty() && saved.data.user_id.is_empty())
        || saved.username.len() > 128
        || liteseal_shared::trusted_device::canonical_origin(&saved.data.server_url)
            .map_err(|_| bad())?
            != saved.data.server_url
        || saved.data.user_id.is_empty() != saved.data.device_id.is_empty()
        || (saved.data.user_id.is_empty()
            && (!saved.data.token.is_empty() || !saved.data.refresh_token.is_empty()))
    {
        return Err(bad());
    }
    backup_crypto::validate_identity(
        &saved.data.public_key,
        &saved.data.secret_key,
        &saved.data.ed25519_pk,
        &saved.data.ed25519_sk,
    )
    .map_err(|_| bad())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    #[derive(Clone, Default)]
    struct Memory {
        bytes: Arc<Mutex<Vec<u8>>>,
        fail: Arc<AtomicBool>,
    }
    pub(crate) fn saved(data: KeystoreData) -> MobileIdentity {
        let value = Zeroizing::new(Stored {
            version: 1,
            username: "synthetic".into(),
            data,
            legacy_cleanup: false,
        });
        validate(&value).unwrap();
        let identity = MobileIdentity {
            store: Box::<Memory>::default(),
            state: Mutex::new(State {
                epoch: 1,
                saved: Some(value),
            }),
        };
        let state = identity.state.lock().unwrap();
        identity.save(state.saved.as_ref().unwrap()).unwrap();
        drop(state);
        identity
    }
    impl SecretStore for Memory {
        fn save(&self, value: &[u8]) -> Result<(), String> {
            if self.fail.load(Ordering::SeqCst) {
                return Err("synthetic failure".into());
            }
            *self.bytes.lock().unwrap() = value.to_vec();
            Ok(())
        }
        fn load(&self) -> Result<Vec<u8>, String> {
            Ok(self.bytes.lock().unwrap().clone())
        }
        fn clear(&self) -> Result<(), String> {
            self.bytes.lock().unwrap().clear();
            Ok(())
        }
    }
    fn accepted() -> api::RegisterResult {
        api::RegisterResult {
            user_id: "synthetic-user".into(),
            device_id: Some("synthetic-device".into()),
            token: "synthetic-token".into(),
            access_token: None,
            refresh_token: Some("synthetic-refresh".into()),
        }
    }
    #[test]
    fn legacy_clear_failure_reopens_confirmed_keys_and_retries_only_cleanup() {
        let original = Memory::default();
        let identity = MobileIdentity::load(Box::new(original), false).unwrap();
        let pending = identity
            .begin_auth("alice", "https://synthetic.example", true)
            .unwrap();
        identity.commit_auth(&pending, accepted()).unwrap();
        let private = identity.snapshot(true).unwrap();
        let legacy = serde_json::to_vec(&*private.data).unwrap();
        let target = Memory::default();
        let migrating = MobileIdentity::load(Box::new(target.clone()), false).unwrap();
        assert!(migrating
            .restore_legacy_using(
                || Ok(legacy),
                || Err("synthetic unavailable legacy clear".into())
            )
            .is_err());
        drop(migrating);
        let reopened = MobileIdentity::load(Box::new(target.clone()), true).unwrap();
        assert_eq!(
            reopened.public().unwrap().unwrap().public_key,
            private.data.public_key
        );
        reopened
            .restore_legacy_using(
                || panic!("confirmed identity must not read legacy again"),
                || Ok(()),
            )
            .unwrap();
        let closed = MobileIdentity::load(Box::new(target), true).unwrap();
        closed
            .restore_legacy_using(
                || panic!("must not reread"),
                || panic!("completed migration must not clear again"),
            )
            .unwrap();
        assert!(closed.snapshot(true).unwrap().data.ed25519_sk == private.data.ed25519_sk);
    }
    #[test]
    fn original_pending_registration_keys_survive_retry_and_store_failure() {
        let store = Memory::default();
        let identity = MobileIdentity::load(Box::new(store.clone()), false).unwrap();
        assert!(identity
            .begin_auth("alice", "https://synthetic.example", false)
            .is_err());
        store.fail.store(true, Ordering::SeqCst);
        assert!(identity
            .begin_auth("alice", "https://synthetic.example", true)
            .is_err());
        assert!(store.bytes.lock().unwrap().is_empty());
        store.fail.store(false, Ordering::SeqCst);
        let first = identity
            .begin_auth("alice", "https://synthetic.example", true)
            .unwrap();
        let reopened = MobileIdentity::load(Box::new(store.clone()), true).unwrap();
        let repeated = reopened
            .begin_auth("alice", "https://synthetic.example", true)
            .unwrap();
        assert_eq!(first.data.public_key, repeated.data.public_key);
        assert_eq!(first.data.ed25519_pk, repeated.data.ed25519_pk);
        assert!(reopened
            .begin_auth("bob", "https://synthetic.example", true)
            .is_err());
        assert!(reopened
            .begin_auth("alice", "https://another.example", true)
            .is_err());
        assert!(reopened.public().unwrap().is_none());
        assert!(reopened
            .begin_auth("alice", "https://synthetic.example", false)
            .is_err());
    }
    #[test]
    fn signout_retires_auth_and_network_leases_and_preserves_public_identity() {
        let store = Memory::default();
        let identity = MobileIdentity::load(Box::new(store.clone()), false).unwrap();
        let pending = identity
            .begin_auth("alice", "https://synthetic.example", true)
            .unwrap();
        identity.clear_session().unwrap();
        assert!(identity.commit_auth(&pending, accepted()).is_err());
        let current = identity
            .begin_auth("alice", "https://synthetic.example", true)
            .unwrap();
        let visible = identity.commit_auth(&current, accepted()).unwrap();
        let json = serde_json::to_string(&visible).unwrap();
        assert!(!json.contains("secret_key"));
        assert!(!json.contains("ed25519_sk"));
        assert!(!json.contains("token"));
        let online = identity.snapshot(true).unwrap();
        identity.clear_session().unwrap();
        assert!(identity.check(&online).is_err());
        assert!(identity.snapshot(true).is_err());
        let reopened = MobileIdentity::load(Box::new(store), true).unwrap();
        let offline = reopened.public().unwrap().unwrap();
        assert!(!offline.has_session);
        assert_eq!(offline.public_key, visible.public_key);
        assert!(reopened.snapshot(false).is_ok());
    }
    #[test]
    fn failed_session_commit_and_identity_substitution_do_not_replace_keys() {
        let store = Memory::default();
        let identity = MobileIdentity::load(Box::new(store.clone()), false).unwrap();
        let pending = identity
            .begin_auth("alice", "https://synthetic.example", true)
            .unwrap();
        store.fail.store(true, Ordering::SeqCst);
        assert!(identity.commit_auth(&pending, accepted()).is_err());
        assert!(identity.public().unwrap().is_none());
        store.fail.store(false, Ordering::SeqCst);
        identity.commit_auth(&pending, accepted()).unwrap();
        let login = identity
            .begin_auth("alice", "https://synthetic.example", false)
            .unwrap();
        let mut wrong = accepted();
        wrong.user_id = "wrong-account".into();
        assert!(identity.commit_auth(&login, wrong).is_err());
        assert_eq!(
            identity.public().unwrap().unwrap().public_key,
            pending.data.public_key
        );
        let mut bytes = store.bytes.lock().unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let mut changed = value;
        changed["data"]["public_key"][0] = json_number(0);
        *bytes = serde_json::to_vec(&changed).unwrap();
        drop(bytes);
        // Corrupt a private/public pair deterministically, even if the original
        // generated first public byte happened to be zero.
        let mut bytes = store.bytes.lock().unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["data"]["public_key"][1] = json_number((pending.data.public_key[1] ^ 1) as u64);
        *bytes = serde_json::to_vec(&value).unwrap();
        drop(bytes);
        assert!(MobileIdentity::load(Box::new(store), true).is_err());
    }
    fn json_number(value: u64) -> serde_json::Value {
        serde_json::Value::Number(value.into())
    }
}
