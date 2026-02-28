use anyhow::Result;
use tracing::{info, warn, error};
use std::net::SocketAddr;

// Use jemalloc on Linux for reduced fragmentation and better throughput
// on long-running server processes (especially helpful on RPi / ARM64).
// On Windows/macOS the default system allocator is used instead.
#[cfg(target_os = "linux")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

mod config;
mod websocket;
mod routing;
mod database;
mod tls;
mod auth;

use config::ServerConfig;
use websocket::ServerState;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("securecomm_server=debug".parse()?)
                .add_directive("axum=info".parse()?),
        )
        .init();

    info!("Starting SecureComm server");

    let config = ServerConfig::from_env()?;
    info!("Configuration loaded");

    let db_pool = database::init(&config.database_url).await?;
    info!("Database initialized");

    let state = std::sync::Arc::new(ServerState::new(db_pool.clone(), config.clone()));

    // Periodic message TTL cleanup
    {
        let pool = db_pool.clone();
        let ttl = config.message_ttl_seconds;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                match database::purge_expired_messages(&pool, ttl).await {
                    Ok(0) => {}
                    Ok(n) => info!("TTL cleanup: purged {} expired channel messages", n),
                    Err(e) => warn!("TTL cleanup error (channel messages): {}", e),
                }
                match database::purge_expired_offline_messages(&pool, ttl).await {
                    Ok(0) => {}
                    Ok(n) => info!("TTL cleanup: purged {} expired offline messages", n),
                    Err(e) => warn!("TTL cleanup error (offline messages): {}", e),
                }
            }
        });
        info!("Message TTL cleanup task started (TTL={}s)", ttl);
    }

    let app = routing::create_router(state);
    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;

    // B3: Graceful shutdown signal (cross-platform)
    let shutdown_signal = async {
        let _ = tokio::signal::ctrl_c().await;
        info!("Shutdown signal received, draining connections...");
    };

    // Check TLS configuration
    let tls_acceptor = tls::configure_tls(&config).await?;

    if let Some(acceptor) = tls_acceptor {
        info!("Server listening on https://{}", addr);
        info!("WebSocket endpoint: wss://{}/ws", addr);
        let _tls_acceptor = tokio_rustls::TlsAcceptor::from(acceptor);

        // TODO: Implement proper TLS termination
        error!("TLS configured but HTTP fallback active until TLS termination is implemented.");
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal)
        .await?;
    } else {
        if config.require_tls {
            anyhow::bail!("TLS is required but not configured. Set SC_TLS_CERT and SC_TLS_KEY.");
        }

        warn!("Running without TLS — development mode only");
        info!("Server listening on http://{}", addr);
        info!("WebSocket endpoint: ws://{}/ws", addr);

        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal)
        .await?;
    }

    // B3: Checkpoint SQLite WAL before exit
    info!("Checkpointing SQLite WAL...");
    if let Err(e) = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&db_pool)
        .await
    {
        warn!("WAL checkpoint failed: {}", e);
    }

    info!("Server stopped cleanly");
    Ok(())
}
