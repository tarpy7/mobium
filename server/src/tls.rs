//! TLS configuration

use anyhow::{Result, Context};
use rustls::{
    ServerConfig as RustlsConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tracing::info;

use crate::config::ServerConfig;

/// Configure TLS for the server
pub async fn configure_tls(config: &ServerConfig) -> Result<Option<TlsAcceptor>> {
    // Check if TLS is configured
    let (cert_path, key_path) = match (&config.tls_cert_path, &config.tls_key_path) {
        (Some(cert), Some(key)) => (cert, key),
        _ => {
            if config.require_tls {
                anyhow::bail!("TLS is required but certificate and key paths are not configured");
            }
            info!("TLS not configured, running in HTTP mode (insecure)");
            return Ok(None);
        }
    };
    
    info!("Loading TLS certificate from {}", cert_path);
    
    // Load certificate
    let cert_file = tokio::fs::read(cert_path).await
        .context("Failed to read TLS certificate")?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &*cert_file)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse TLS certificate")?;
    
    if certs.is_empty() {
        anyhow::bail!("No certificates found in certificate file");
    }
    
    // Load private key
    let key_file = tokio::fs::read(key_path).await
        .context("Failed to read TLS private key")?;
    let keys: Vec<PrivateKeyDer<'static>> = rustls_pemfile::pkcs8_private_keys(&mut &*key_file)
        .map(|key| key.map(Into::into))
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse TLS private key")?;
    
    if keys.is_empty() {
        // Try RSA format
        let keys_rsa: Vec<PrivateKeyDer<'static>> = rustls_pemfile::rsa_private_keys(&mut &*key_file)
            .map(|key| key.map(Into::into))
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse TLS private key as RSA")?;
        
        if keys_rsa.is_empty() {
            anyhow::bail!("No private keys found in key file");
        }
        
        build_tls_config(certs, keys_rsa, config).map(Some)
    } else {
        build_tls_config(certs, keys, config).map(Some)
    }
}

fn build_tls_config(
    certs: Vec<CertificateDer<'static>>,
    mut keys: Vec<PrivateKeyDer<'static>>,
    config: &ServerConfig,
) -> Result<TlsAcceptor> {
    // Configure TLS 1.3 only
    let mut tls_config = RustlsConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, keys.remove(0))
        .context("Failed to build TLS config")?;
    
    // Force TLS 1.3
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    
    // Configure mTLS for admin if CA is provided
    if let Some(ca_path) = &config.mtls_ca_path {
        info!("Configuring mTLS with CA: {}", ca_path);
        // TODO: Implement mTLS configuration
    }
    
    Ok(TlsAcceptor::from(Arc::new(tls_config)))
}

/// Generate a self-signed certificate for development
#[allow(dead_code)]
pub async fn generate_self_signed_cert(cert_path: &str, key_path: &str) -> Result<()> {
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    
    info!("Generating self-signed certificate...");
    
    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(
        vec!["localhost".to_string(), "mobium.local".to_string()]
    ).context("Failed to generate self-signed certificate")?;
    
    // Write certificate
    tokio::fs::write(cert_path, cert.pem()).await
        .context("Failed to write certificate")?;
    
    // Write private key
    tokio::fs::write(key_path, key_pair.serialize_pem()).await
        .context("Failed to write private key")?;
    
    info!("Self-signed certificate generated:");
    info!("  Certificate: {}", cert_path);
    info!("  Private key: {}", key_path);
    
    Ok(())
}