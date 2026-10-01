//! An external, current-Windows-user witness. No credential enumeration and no
//! production deletion/reset operation. A named mutex serializes synchronous
//! SQLite/journal/credential work across processes and logon sessions.
use super::{SecureCell, SecureStore};
use sha2::{Digest, Sha256};
use std::{marker::PhantomData, path::Path, ptr, rc::Rc};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, GetLastError, ERROR_NOT_FOUND, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0,
    },
    Security::{
        Credentials::{
            CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE,
            CRED_TYPE_GENERIC,
        },
        GetLengthSid, GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER,
    },
    System::Threading::{
        CreateMutexW, GetCurrentProcess, OpenProcessToken, ReleaseMutex, WaitForSingleObject,
    },
};

pub struct WindowsStore {
    binding: [u8; 32],
    target: Vec<u16>,
    mutex: Vec<u16>,
    isolated: bool,
}
fn unavailable() -> String {
    "Windows 设备安全存储不可用，未重置高水位".into()
}
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}
struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}
fn user_sid() -> Result<Vec<u8>, String> {
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(unavailable());
    }
    let token = Handle(token);
    let mut needed = 0;
    unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut needed) };
    if needed == 0 || needed > 16384 {
        return Err(unavailable());
    }
    // TOKEN_USER contains a pointer: retain pointer alignment, not Vec<u8> alignment.
    let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(unavailable());
    }
    let sid = unsafe { (*(buffer.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    let length = unsafe { GetLengthSid(sid) } as usize;
    if length == 0 || length > 256 {
        return Err(unavailable());
    }
    Ok(unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), length).to_vec() })
}
impl WindowsStore {
    pub fn open(database: &Path) -> Result<Self, String> {
        Self::create(database, None)
    }
    /// Explicit synthetic-test namespace. It never addresses production targets.
    pub fn isolated(database: &Path, namespace: uuid::Uuid) -> Result<Self, String> {
        Self::create(database, Some(namespace))
    }
    fn create(database: &Path, namespace: Option<uuid::Uuid>) -> Result<Self, String> {
        let path = std::fs::canonicalize(database).map_err(|_| unavailable())?;
        if !path.is_file() {
            return Err(unavailable());
        }
        let path = path.to_str().ok_or_else(unavailable)?.to_lowercase();
        let sid = user_sid()?;
        // This Windows environment can lose distinct target writes when the
        // credential set is updated concurrently. Serialize all our targets for
        // this user, including profile deletion, across threads/processes.
        let user_mutex = hex::encode(Sha256::digest(&sid));
        let mut hash = Sha256::new();
        hash.update(b"LiteSeal/Windows-device-witness/v1");
        hash.update((sid.len() as u64).to_le_bytes());
        hash.update(sid);
        hash.update((path.len() as u64).to_le_bytes());
        hash.update(path.as_bytes());
        hash.update(
            namespace
                .map_or_else(|| "production".into(), |id| id.to_string())
                .as_bytes(),
        );
        let binding: [u8; 32] = hash.finalize().into();
        let suffix = hex::encode(binding);
        let prefix = if namespace.is_some() {
            "LiteSeal.Test.DeviceState.v1"
        } else {
            "LiteSeal.DeviceState.v1"
        };
        Ok(Self {
            binding,
            target: wide(&format!("{prefix}/{suffix}")),
            mutex: wide(&format!(
                "Global\\LiteSeal.DeviceState.v1.User.{user_mutex}"
            )),
            isolated: namespace.is_some(),
        })
    }
    /// Only the exact isolated test target can be removed, never user credentials.
    pub fn clear_isolated(&self) -> Result<(), String> {
        if !self.isolated {
            return Err("生产设备高水位不能删除或重置".into());
        }
        let _guard = self.lock()?;
        if unsafe { CredDeleteW(self.target.as_ptr(), CRED_TYPE_GENERIC, 0) } == 0
            && unsafe { GetLastError() } != ERROR_NOT_FOUND
        {
            return Err(unavailable());
        }
        Ok(())
    }
}
struct Slot<'a> {
    store: &'a WindowsStore,
    handle: Handle,
    // Mutex ownership is thread-affine. The cell cannot be sent across await/thread.
    _thread: PhantomData<Rc<()>>,
}
impl Drop for Slot<'_> {
    fn drop(&mut self) {
        unsafe { ReleaseMutex(self.handle.0) };
    }
}
impl SecureStore for WindowsStore {
    fn binding(&self) -> [u8; 32] {
        self.binding
    }
    fn lock(&self) -> Result<Box<dyn SecureCell + '_>, String> {
        let handle = unsafe { CreateMutexW(ptr::null(), 0, self.mutex.as_ptr()) };
        if handle.is_null() {
            return Err(unavailable());
        }
        let handle = Handle(handle);
        let status = unsafe { WaitForSingleObject(handle.0, 5000) };
        // Abandonment grants ownership; the engine must revalidate/reconcile before use.
        if status != WAIT_OBJECT_0 && status != WAIT_ABANDONED {
            return Err(unavailable());
        }
        Ok(Box::new(Slot {
            store: self,
            handle,
            _thread: PhantomData,
        }))
    }
}
impl SecureCell for Slot<'_> {
    fn read(&mut self) -> Result<Option<Vec<u8>>, String> {
        let mut credential = ptr::null_mut();
        if unsafe {
            CredReadW(
                self.store.target.as_ptr(),
                CRED_TYPE_GENERIC,
                0,
                &mut credential,
            )
        } == 0
        {
            return if unsafe { GetLastError() } == ERROR_NOT_FOUND {
                Ok(None)
            } else {
                Err(unavailable())
            };
        }
        if credential.is_null() {
            return Err(unavailable());
        }
        let record = unsafe { &*credential };
        let valid = record.Type == CRED_TYPE_GENERIC
            && record.Persist == CRED_PERSIST_LOCAL_MACHINE
            && record.CredentialBlobSize > 0
            && record.CredentialBlobSize <= 2560
            && !record.CredentialBlob.is_null();
        let result = if valid {
            let blob = unsafe {
                std::slice::from_raw_parts(
                    record.CredentialBlob,
                    record.CredentialBlobSize as usize,
                )
            };
            crate::secret_store::unprotect_local(blob).and_then(|bytes| {
                if bytes.len() > 2048 {
                    Err(unavailable())
                } else {
                    Ok(Some(bytes))
                }
            })
        } else {
            Err(unavailable())
        };
        unsafe { CredFree(credential.cast()) };
        result.map_err(|_| unavailable())
    }
    fn write(&mut self, value: &[u8]) -> Result<(), String> {
        if value.len() > 2048 {
            return Err(unavailable());
        }
        let mut blob = crate::secret_store::protect_local(value).map_err(|_| unavailable())?;
        if blob.len() > 2560 {
            return Err(unavailable());
        }
        let mut record: CREDENTIALW = unsafe { std::mem::zeroed() };
        record.Type = CRED_TYPE_GENERIC;
        record.TargetName = self.store.target.as_ptr() as *mut u16;
        record.CredentialBlobSize = blob.len() as u32;
        record.CredentialBlob = blob.as_mut_ptr();
        record.Persist = CRED_PERSIST_LOCAL_MACHINE;
        if unsafe { CredWriteW(&record, 0) } == 0 {
            return Err(unavailable());
        }
        Ok(())
    }
}
