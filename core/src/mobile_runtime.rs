//! Native process lifecycle, shared by foreground FFI and the private worker.
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
static EPOCH: AtomicU64 = AtomicU64::new(1);
static FOREGROUND: AtomicBool = AtomicBool::new(!cfg!(target_os = "android"));
pub(crate) static NETWORK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
pub(crate) static COMMIT: std::sync::Mutex<()> = std::sync::Mutex::new(());
pub(crate) fn epoch() -> u64 {
    EPOCH.load(Ordering::SeqCst)
}
#[cfg(target_os = "android")]
pub(crate) fn retire() {
    let _guard = COMMIT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    EPOCH.fetch_add(1, Ordering::SeqCst);
}
pub(crate) fn foreground() -> bool {
    FOREGROUND.load(Ordering::SeqCst)
}
#[cfg(target_os = "android")]
pub(crate) fn set_foreground(value: bool) {
    let _guard = COMMIT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if FOREGROUND.swap(value, Ordering::SeqCst) != value {
        EPOCH.fetch_add(1, Ordering::SeqCst);
    }
}
pub(crate) fn check(value: u64) -> Result<(), String> {
    if epoch() == value {
        Ok(())
    } else {
        Err("移动生命周期已变化；拒绝迟到结果".into())
    }
}
pub(crate) fn require_foreground() -> Result<(), String> {
    if foreground() {
        Ok(())
    } else {
        Err("应用未在前台；正文与发送入口已暂停".into())
    }
}
