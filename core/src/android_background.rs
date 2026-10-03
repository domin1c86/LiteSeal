//! Private JNI worker entry points. No UniFFI/JS export or credential parameter.
use crate::{ffi::LitesealCore, mobile_runtime};
#[no_mangle]
pub extern "C" fn liteseal_android_foreground(value: bool) {
    mobile_runtime::set_foreground(value);
}
/// # Safety
/// JNI supplies a valid, bounded UTF-8 app-private DB path for this call only.
#[no_mangle]
pub unsafe extern "C" fn liteseal_android_sync(path: *const u8, length: usize) -> i32 {
    if path.is_null() || length == 0 || length > 4096 {
        return -1;
    }
    // A panic must never unwind across JNI. Return only a public outcome code.
    std::panic::catch_unwind(|| {
        let bytes = unsafe { std::slice::from_raw_parts(path, length) };
        let path = std::str::from_utf8(bytes).map_err(|_| ())?;
        let identity = std::path::Path::new(path).with_file_name("mobile-identity.bin");
        if !identity.is_file() {
            return Ok(0);
        } // Never create credentials.
        let core = LitesealCore::new(path.into()).map_err(|_| ())?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| ())?;
        let outcome = runtime.block_on(async {
            let outcome =
                tokio::time::timeout(std::time::Duration::from_secs(20), core.background_round())
                    .await;
            // Timeout releases the worker's network gate. Reacquire it before
            // cleanup, and never disconnect a resumed foreground connection.
            let cleanup = async {
                let _network = mobile_runtime::NETWORK.lock().await;
                if !mobile_runtime::foreground() {
                    core.disconnect().await;
                }
            };
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), cleanup).await;
            outcome
        });
        match outcome {
            Ok(Ok(_)) => Ok(0),
            _ => Err(()),
        }
    })
    .ok()
    .and_then(Result::<i32, ()>::ok)
    .unwrap_or(-1)
}
