//! TLS connection utilities for remote certificate inspection.

#![allow(dead_code)]

use std::io::Write;
use std::net::TcpStream;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use x509::CertificateChain;

use super::verifier::NoVerifier;
use crate::error::{Error, Result};

fn build_config() -> ClientConfig {
    ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth()
}

fn connect_tls(
    host: &str,
    port: u16,
    config: ClientConfig,
) -> Result<StreamOwned<ClientConnection, TcpStream>> {
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| Error::InvalidHostname(host.to_string()))?;

    let addr = format!("{}:{}", host, port);
    let tcp_stream = TcpStream::connect(&addr).map_err(|e| Error::ConnectionFailed {
        host: host.to_string(),
        port,
        reason: e.to_string(),
    })?;

    let conn = ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| Error::TlsConnectionFailed(e.to_string()))?;

    Ok(StreamOwned::new(conn, tcp_stream))
}

fn extract_certificate_chain(
    tls_stream: &StreamOwned<ClientConnection, TcpStream>,
) -> Result<CertificateChain> {
    let certs = tls_stream
        .conn
        .peer_certificates()
        .ok_or(Error::NoCertificatesReceived)?;

    CertificateChain::try_from(certs).map_err(|e| Error::CertificateChainParseFailed(e.to_string()))
}

/// Fetches the certificate chain from a remote TLS server.
///
/// # Arguments
/// * `host` - The hostname to connect to
/// * `port` - The port to connect to (default: 443)
///
/// # Returns
/// The certificate chain presented by the server.
pub fn fetch_certificate_chain(host: &str, port: u16) -> Result<CertificateChain> {
    let config = build_config();
    let mut tls_stream = connect_tls(host, port, config)?;

    tls_stream
        .flush()
        .map_err(|e| Error::TlsHandshakeFailed(e.to_string()))?;

    extract_certificate_chain(&tls_stream)
}
