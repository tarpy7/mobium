//! Input validation for Tauri command parameters.
//!
//! All user-provided inputs from the frontend are untrusted.
//! This module validates and sanitizes them before they reach
//! any crypto or database operations.

/// Maximum length for text message content (bytes).
pub const MAX_MESSAGE_LEN: usize = 64 * 1024; // 64 KB

/// Maximum length for channel/group names.
pub const MAX_NAME_LEN: usize = 128;

/// Maximum length for nicknames.
pub const MAX_NICKNAME_LEN: usize = 64;

/// Maximum length for a password.
pub const MAX_PASSWORD_LEN: usize = 1024;

/// Maximum length for a mnemonic phrase.
pub const MAX_MNEMONIC_LEN: usize = 512;

/// Maximum length for a profile name.
pub const MAX_PROFILE_NAME_LEN: usize = 64;

/// Expected length of an Ed25519 public key in hex.
pub const PUBKEY_HEX_LEN: usize = 64; // 32 bytes = 64 hex chars

/// Expected length of a channel ID in hex.
pub const CHANNEL_ID_HEX_LEN: usize = 64;

/// Validate a hex-encoded Ed25519 public key.
pub fn validate_pubkey_hex(pubkey: &str) -> Result<Vec<u8>, String> {
    if pubkey.len() != PUBKEY_HEX_LEN {
        return Err(format!(
            "Invalid pubkey: expected {} hex chars, got {}",
            PUBKEY_HEX_LEN,
            pubkey.len()
        ));
    }
    if !pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Invalid pubkey: contains non-hex characters".to_string());
    }
    hex::decode(pubkey).map_err(|_| "Invalid pubkey hex encoding".to_string())
}

/// Validate a hex-encoded channel ID.
pub fn validate_channel_id_hex(channel_id: &str) -> Result<Vec<u8>, String> {
    let trimmed = channel_id.trim();
    if trimmed.is_empty() {
        return Err("Channel ID cannot be empty".to_string());
    }
    if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Invalid channel ID: contains non-hex characters".to_string());
    }
    hex::decode(trimmed).map_err(|_| "Invalid channel ID hex encoding".to_string())
}

/// Validate message content.
pub fn validate_message_content(content: &str) -> Result<(), String> {
    if content.is_empty() {
        return Err("Message cannot be empty".to_string());
    }
    if content.len() > MAX_MESSAGE_LEN {
        return Err(format!(
            "Message too long: {} bytes (max {})",
            content.len(),
            MAX_MESSAGE_LEN
        ));
    }
    Ok(())
}

/// Validate a channel or group name.
pub fn validate_name(name: &str, kind: &str) -> Result<(), String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(format!("{} name cannot be empty", kind));
    }
    if trimmed.len() > MAX_NAME_LEN {
        return Err(format!(
            "{} name too long: {} chars (max {})",
            kind,
            trimmed.len(),
            MAX_NAME_LEN
        ));
    }
    // Reject control characters
    if trimmed.chars().any(|c| c.is_control() && c != '\n') {
        return Err(format!("{} name contains invalid characters", kind));
    }
    Ok(())
}

/// Validate a nickname.
pub fn validate_nickname(nick: &str) -> Result<(), String> {
    if nick.is_empty() {
        return Err("Nickname cannot be empty".to_string());
    }
    if nick.len() > MAX_NICKNAME_LEN {
        return Err(format!("Nickname too long: {} chars (max {})", nick.len(), MAX_NICKNAME_LEN));
    }
    if nick.chars().any(|c| c.is_control()) {
        return Err("Nickname contains invalid characters".to_string());
    }
    Ok(())
}

/// Validate a password.
pub fn validate_password(password: &str) -> Result<(), String> {
    if password.len() < 12 {
        return Err("Password must be at least 12 characters".to_string());
    }
    if password.len() > MAX_PASSWORD_LEN {
        return Err(format!("Password too long (max {} chars)", MAX_PASSWORD_LEN));
    }
    Ok(())
}

/// Validate a mnemonic phrase.
pub fn validate_mnemonic(mnemonic: &str) -> Result<(), String> {
    let trimmed = mnemonic.trim();
    if trimmed.is_empty() {
        return Err("Mnemonic cannot be empty".to_string());
    }
    if trimmed.len() > MAX_MNEMONIC_LEN {
        return Err("Mnemonic too long".to_string());
    }
    let word_count = trimmed.split_whitespace().count();
    if word_count != 24 {
        return Err(format!("Expected 24-word mnemonic, got {} words", word_count));
    }
    Ok(())
}

/// Validate a profile name.
pub fn validate_profile_name(name: &str) -> Result<(), String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("Profile name cannot be empty".to_string());
    }
    if trimmed.len() > MAX_PROFILE_NAME_LEN {
        return Err(format!("Profile name too long (max {} chars)", MAX_PROFILE_NAME_LEN));
    }
    // Only allow alphanumeric, spaces, hyphens, underscores
    if !trimmed.chars().all(|c| c.is_alphanumeric() || c == ' ' || c == '-' || c == '_') {
        return Err("Profile name can only contain letters, numbers, spaces, hyphens, and underscores".to_string());
    }
    Ok(())
}

/// Validate a server URL.
pub fn validate_server_url(url: &str) -> Result<(), String> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err("Server URL cannot be empty".to_string());
    }
    if trimmed.len() > 2048 {
        return Err("Server URL too long".to_string());
    }
    // Must start with ws:// wss:// or be a hostname/IP
    if !trimmed.starts_with("ws://") && !trimmed.starts_with("wss://") {
        // Try adding ws:// prefix
        return Err("Server URL must start with ws:// or wss://".to_string());
    }
    Ok(())
}
