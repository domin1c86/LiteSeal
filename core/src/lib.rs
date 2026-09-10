//! Platform-independent client core shared by the Tauri desktop app and the
//! React Native Android app. All business logic (local store, integrity
//! chain, relay connection, server REST calls, keystore model) lives here;
//! platform shells only adapt it to their IPC mechanism.

pub mod api;
pub mod beta;
pub mod chat;
pub mod client;
pub mod contacts;
pub mod db;
#[cfg(feature = "ffi")]
pub mod ffi;
pub mod integrity;
pub mod keystore;
pub mod network;
pub mod secret_store;

pub use client::LitesealClient;

#[cfg(feature = "ffi")]
uniffi::setup_scaffolding!();
