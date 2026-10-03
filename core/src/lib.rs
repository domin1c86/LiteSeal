//! Platform-independent client core shared by the Electron desktop app and the
//! React Native Android app. All business logic (local store, integrity
//! chain, relay connection, server REST calls, keystore model) lives here;
//! platform shells only adapt it to their IPC mechanism.

#[cfg(all(target_os = "android", feature = "ffi"))]
mod android_background;
#[cfg(target_os = "android")]
pub mod android_secret_store;
pub mod api;
pub mod attachment_cache;
pub mod backup;
pub mod beta;
pub mod chat;
pub mod client;
pub mod contacts;
pub mod db;
#[cfg(feature = "ffi")]
pub mod ffi;
pub mod groups;
pub mod integrity;
pub mod keystore;
#[cfg(feature = "ffi")]
pub mod mobile_identity;
#[cfg(feature = "ffi")]
pub(crate) mod mobile_messages;
#[cfg(feature = "ffi")]
pub(crate) mod mobile_operations;
#[cfg(feature = "ffi")]
pub(crate) mod mobile_runtime;
pub mod network;
pub mod secret_store;
pub mod trusted_devices;

pub use client::LitesealClient;

#[cfg(feature = "ffi")]
uniffi::setup_scaffolding!();
