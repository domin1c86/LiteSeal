#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use liteseal_app_lib::{commands, AppState};

fn main() {
    tracing_subscriber::fmt::init();

    let base_dir = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("liteseal");
    let legacy_secret_dir = dirs::data_local_dir()
        .map(|directory| directory.join("liteseal"))
        .unwrap_or_else(|| base_dir.clone());
    let state =
        AppState::new(base_dir, legacy_secret_dir).expect("Failed to initialize application state");

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            commands::auth::bootstrap,
            commands::auth::register,
            commands::auth::login,
            commands::auth::logout,
            commands::auth::logout_all,
            commands::chat::send_text,
            commands::chat::poll_events,
            commands::chat::get_messages,
            commands::contacts::add_contact,
            commands::contacts::get_contacts,
            commands::contacts::remove_contact,
            commands::contacts::set_contact_trust,
            commands::contacts::search_users,
            commands::storage::get_storage_stats,
            commands::storage::clear_expired_messages,
            commands::storage::clear_downloaded_attachments,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
