#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use liteseal_app::{commands, AppState};

fn main() {
    tracing_subscriber::fmt::init();

    let db_path = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("liteseal")
        .join("data.db");

    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let state = AppState::new(db_path.to_str().unwrap_or("liteseal.db"))
        .expect("Failed to initialize application state");

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            commands::auth::register,
            commands::auth::connect_relay,
            commands::auth::disconnect,
            commands::chat::send_message,
            commands::chat::poll_messages,
            commands::chat::get_local_messages,
            commands::chat::encrypt_message,
            commands::chat::decrypt_message,
            commands::chat::sign_message,
            commands::chat::generate_keypair_cmd,
            commands::contacts::add_contact,
            commands::contacts::get_contacts,
            commands::contacts::remove_contact,
            commands::contacts::search_users,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
