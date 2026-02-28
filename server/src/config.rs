//! Server configuration

use anyhow::{Context, Result};
use serde::Deserialize;
use std::env;

/// Server configuration
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Host to bind to
    pub host: String,
    /// Port to listen on
    pub port: u16,
    /// Database URL
    pub database_url: String,
    /// TLS certificate path
    pub tls_cert_path: Option<String>,
    /// TLS key path
    pub tls_key_path: Option<String>,
    /// mTLS CA certificate path (optional)
    pub mtls_ca_path: Option<String>,
    /// Maximum message size in bytes
    pub max_message_size: usize,
    /// WebSocket ping interval in seconds (also used as keepalive timeout base)
    pub ws_ping_interval: u64,
    /// Maximum number of offline messages per user
    pub max_offline_messages: usize,
    /// Require TLS (disable HTTP fallback)
    pub require_tls: bool,
    /// Message TTL in seconds (default: 7 days = 604800)
    pub message_ttl_seconds: i64,
    /// Maximum total WebSocket connections (0 = unlimited)
    pub max_connections: usize,
    /// Maximum WebSocket connections per IP address (0 = unlimited)
    pub max_connections_per_ip: usize,
    /// Comma-separated list of allowed CORS origins (empty = permissive)
    pub cors_origins: Option<String>,
    /// Bearer token for /admin/* endpoints (None = endpoints hidden)
    pub admin_token: Option<String>,
    /// Seconds to wait for authentication before dropping connection
    pub auth_timeout_seconds: u64,
}

impl ServerConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();

        let config = ServerConfig {
            host: env::var("SC_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: env::var("SC_PORT")
                .unwrap_or_else(|_| "8443".to_string())
                .parse()
                .context("Invalid SC_PORT")?,
            database_url: env::var("SC_DATABASE_URL")
                .unwrap_or_else(|_| "sqlite://./data/mobium.db".to_string()),
            tls_cert_path: env::var("SC_TLS_CERT").ok(),
            tls_key_path: env::var("SC_TLS_KEY").ok(),
            mtls_ca_path: env::var("SC_MTLS_CA").ok(),
            max_message_size: env::var("SC_MAX_MESSAGE_SIZE")
                .unwrap_or_else(|_| "1048576".to_string()) // 1MB
                .parse()
                .context("Invalid SC_MAX_MESSAGE_SIZE")?,
            ws_ping_interval: env::var("SC_WS_PING_INTERVAL")
                .unwrap_or_else(|_| "30".to_string())
                .parse()
                .context("Invalid SC_WS_PING_INTERVAL")?,
            max_offline_messages: env::var("SC_MAX_OFFLINE_MESSAGES")
                .unwrap_or_else(|_| "1000".to_string())
                .parse()
                .context("Invalid SC_MAX_OFFLINE_MESSAGES")?,
            require_tls: env::var("SC_REQUIRE_TLS")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .context("Invalid SC_REQUIRE_TLS")?,
            message_ttl_seconds: env::var("SC_MESSAGE_TTL")
                .unwrap_or_else(|_| "604800".to_string()) // 7 days
                .parse()
                .context("Invalid SC_MESSAGE_TTL")?,
            max_connections: env::var("SC_MAX_CONNECTIONS")
                .unwrap_or_else(|_| "2000".to_string())
                .parse()
                .context("Invalid SC_MAX_CONNECTIONS")?,
            max_connections_per_ip: env::var("SC_MAX_CONNECTIONS_PER_IP")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .context("Invalid SC_MAX_CONNECTIONS_PER_IP")?,
            cors_origins: env::var("SC_CORS_ORIGINS").ok(),
            admin_token: env::var("SC_ADMIN_TOKEN").ok(),
            auth_timeout_seconds: env::var("SC_AUTH_TIMEOUT")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .context("Invalid SC_AUTH_TIMEOUT")?,
        };

        Ok(config)
    }
}
