//! Tor (Arti) integration for anonymous WebSocket connections.
//!
//! When enabled, WebSocket connections are routed through Tor circuits
//! via the Arti library (Tor's official Rust implementation). This hides
//! the client's IP address from the Mobium server and network observers.
//!
//! # Architecture
//!
//! Instead of calling `tokio_tungstenite::connect_async()` directly (which
//! opens a plain TCP connection), we:
//!
//! 1. Bootstrap an Arti `TorClient` (one-time, cached across connections)
//! 2. Open an anonymous TCP stream through a Tor circuit to the server
//! 3. Upgrade that stream to a WebSocket using `tokio_tungstenite`
//!
//! The Arti client manages its own directory cache, circuit pool, and
//! guard selection. Bootstrap typically takes 5-15 seconds on first run,
//! <1 second on subsequent runs (cached consensus).

#[cfg(feature = "tor")]
use arti_client::{TorClient, TorClientConfig};
#[cfg(feature = "tor")]
use tor_rtcompat::PreferredRuntime;

use anyhow::Result;
use tokio::sync::RwLock;
use tracing::info;

/// Global Tor client state.
///
/// Lazily bootstrapped on first use. The TorClient is internally
/// reference-counted and thread-safe.
pub struct TorState {
    #[cfg(feature = "tor")]
    client: RwLock<Option<TorClient<PreferredRuntime>>>,
    #[cfg(not(feature = "tor"))]
    client: RwLock<Option<()>>,
    /// Whether the user has enabled Tor mode
    enabled: RwLock<bool>,
}

impl Default for TorState {
    fn default() -> Self {
        Self {
            client: RwLock::new(None),
            enabled: RwLock::new(false),
        }
    }
}

impl TorState {
    /// Check if Tor mode is enabled
    pub async fn is_enabled(&self) -> bool {
        *self.enabled.read().await
    }

    /// Enable or disable Tor mode
    pub async fn set_enabled(&self, enabled: bool) {
        *self.enabled.write().await = enabled;
        if !enabled {
            info!("Tor mode disabled");
        } else {
            info!("Tor mode enabled — connections will be routed through Tor");
        }
    }

    /// Get or bootstrap the Tor client.
    /// Returns an error if Tor feature is not compiled in.
    #[cfg(feature = "tor")]
    pub async fn get_client(&self) -> Result<TorClient<PreferredRuntime>> {
        // Fast path: already bootstrapped
        {
            let guard = self.client.read().await;
            if let Some(ref client) = *guard {
                return Ok(client.clone());
            }
        }

        // Slow path: bootstrap
        let mut guard = self.client.write().await;
        // Double-check after acquiring write lock
        if let Some(ref client) = *guard {
            return Ok(client.clone());
        }

        info!("Bootstrapping Arti Tor client...");
        let config = TorClientConfig::default();
        let client = TorClient::create_bootstrapped(config).await
            .map_err(|e| anyhow::anyhow!("Failed to bootstrap Tor: {}", e))?;
        info!("Arti Tor client bootstrapped successfully");

        *guard = Some(client.clone());
        Ok(client)
    }

    #[cfg(not(feature = "tor"))]
    pub async fn get_client(&self) -> Result<()> {
        Err(anyhow::anyhow!("Tor support not compiled in. Rebuild with --features tor"))
    }

    /// Connect a TCP stream through Tor to the given host:port.
    /// Returns a stream that can be upgraded to WebSocket.
    #[cfg(feature = "tor")]
    pub async fn connect_tcp(&self, host: &str, port: u16) -> Result<arti_client::DataStream> {
        let client = self.get_client().await?;
        info!("Opening Tor circuit to {}:{}", host, port);
        let stream = client.connect((host, port)).await
            .map_err(|e| anyhow::anyhow!("Tor connection to {}:{} failed: {}", host, port, e))?;
        info!("Tor circuit established to {}:{}", host, port);
        Ok(stream)
    }

    /// Shut down the Tor client (e.g. when disabling Tor or app exit)
    pub async fn shutdown(&self) {
        let mut guard = self.client.write().await;
        if guard.is_some() {
            *guard = None;
            info!("Tor client shut down");
        }
    }

    /// Get bootstrap status info
    #[cfg(feature = "tor")]
    pub async fn status(&self) -> TorStatus {
        let guard = self.client.read().await;
        let bootstrapped = guard.is_some();
        let enabled = *self.enabled.read().await;
        TorStatus { enabled, bootstrapped }
    }

    #[cfg(not(feature = "tor"))]
    pub async fn status(&self) -> TorStatus {
        TorStatus {
            enabled: false,
            bootstrapped: false,
        }
    }
}

#[derive(Clone, serde::Serialize)]
pub struct TorStatus {
    pub enabled: bool,
    pub bootstrapped: bool,
}
