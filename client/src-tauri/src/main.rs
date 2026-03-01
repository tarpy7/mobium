// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::Manager;
use tracing::info;

mod commands;
mod db;
mod db_crypto;
mod crypto;
mod websocket;
mod state;
mod tor;

use state::AppState;

/// Get the Mobium base data directory.
///
/// Checks the `MOBIUM_DATA_DIR` environment variable first, then falls back
/// to the OS data directory (`%APPDATA%/Mobium` on Windows).
///
/// This returns the **base** directory. Profile-specific data lives in
/// subdirectories (e.g., `base/Alice/`, `base/Bob/`).
pub fn mobium_data_dir() -> anyhow::Result<std::path::PathBuf> {
    if let Ok(custom) = std::env::var("MOBIUM_DATA_DIR") {
        Ok(std::path::PathBuf::from(custom))
    } else {
        dirs::data_dir()
            .map(|d| d.join("Mobium"))
            .ok_or_else(|| anyhow::anyhow!("Could not find data directory"))
    }
}

/// Get the active profile's data directory.
///
/// Returns `base_data_dir / profile_name`. Panics if no profile is selected
/// (callers must ensure `select_profile` was called first).
pub async fn mobium_profile_dir(state: &AppState) -> anyhow::Result<std::path::PathBuf> {
    let base = mobium_data_dir()?;
    let profile_guard = state.active_profile.read().await;
    match profile_guard.as_ref() {
        Some(name) => Ok(base.join(name)),
        None => {
            // Backwards compatibility: if no profile is selected, check if there's
            // legacy data directly in the base dir (identity.enc). If so, use base dir.
            let legacy_path = base.join("identity.enc");
            if legacy_path.exists() {
                Ok(base)
            } else {
                Err(anyhow::anyhow!("No profile selected"))
            }
        }
    }
}

fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();
    
    info!("Starting Mobium client v{}", env!("CARGO_PKG_VERSION"));
    
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            // Profile management
            commands::list_profiles,
            commands::select_profile,
            commands::create_profile,
            commands::get_active_profile,
            
            // Key management
            commands::generate_identity,
            commands::export_mnemonic,
            commands::import_mnemonic,
            commands::has_identity,
            commands::unlock_identity,
            
            // Identity
            commands::get_pubkey,
            commands::reset_identity,
            
            // Connection
            commands::connect_server,
            commands::disconnect_server,
            commands::get_connection_status,
            
            // Messaging
            commands::send_message,
            commands::get_conversations,
            commands::get_messages,
            
            // Channel messaging
            commands::create_channel,
            commands::join_channel,
            commands::leave_channel,
            commands::send_channel_message,
            commands::fetch_channel_history,
            
            // Channel members
            commands::get_channel_members,
            commands::get_all_known_users,
            
            // Voice calling (DM)
            commands::send_voice_signal,
            commands::poll_voice_signals,
            commands::clear_voice_signals,
            
            // Voice chat (channels)
            commands::join_voice_channel,
            commands::leave_voice_channel,
            commands::send_voice_data,
            commands::poll_voice_data,
            commands::poll_voice_events,
            commands::get_current_voice_channel,
            
            // Screen share (channels)
            commands::send_screen_data,
            commands::poll_screen_data,
            
            // Nicknames & settings
            commands::set_nickname,
            commands::get_nicknames,
            commands::get_last_server,
            
            // DM / X3DH
            commands::publish_prekeys,
            commands::has_dm_session,
            commands::init_dm_session,
            
            // ICE config
            commands::get_ice_config,
            
            // Profile lock
            commands::lock_profile,
            
            // Social recovery
            commands::setup_social_recovery,
            commands::reconstruct_from_shards,

            // Tor
            commands::set_tor_enabled,
            commands::get_tor_status,
            commands::bootstrap_tor,
        ])
        .setup(|app| {
            let window = app.get_webview_window("main");
            
            #[cfg(debug_assertions)]
            if let Some(ref w) = window {
                w.open_devtools();
            }

            // On Windows, WebView2 blocks getUserMedia by default.
            // We need to grant permission via the WebView2 environment.
            // Tauri v2 handles this through initialization scripts.
            #[cfg(target_os = "windows")]
            if let Some(ref w) = window {
                use tauri::WebviewWindow;
                // WebView2 on Windows requires the page to be served from
                // https:// origin (tauri.localhost) for getUserMedia to work.
                // The CSP media-src directive handles the rest.
                info!("Windows: WebView2 media permissions configured via CSP");
            }

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}