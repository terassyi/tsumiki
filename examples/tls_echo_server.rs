//! mTLS Echo Server Example
//!
//! This example demonstrates how to use tsumiki with rustls to create an mTLS server
//! that requires client certificate authentication.
//!
//! Usage:
//!   cargo run --bin tls-echo-server
//!
//! Then connect with:
//!   cargo run --bin tls-echo-client
//!
//! Or test with openssl:
//!   echo "hello" | openssl s_client -connect localhost:8443 -cert examples/certs/client.crt -key examples/certs/client.key -CAfile examples/certs/ca.crt -quiet

use std::fs;
use std::io;
use std::net::ToSocketAddrs;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DistinguishedName, Error, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tsumiki::decoder::Decoder;
use tsumiki_pkcs::PrivateKey;
use tsumiki_x509::Certificate;

const CA_CERT_PATH: &str = "examples/certs/ca.crt";
const CERT_PATH: &str = "examples/certs/server.crt";
const KEY_PATH: &str = "examples/certs/server.key";
const LISTEN_ADDR: &str = "127.0.0.1:8443";

/// Custom client certificate verifier that uses tsumiki to inspect client certificates
#[derive(Debug)]
struct TsumikiClientCertVerifier {
    /// CA certificate for verification
    ca_cert: Certificate,
}

impl TsumikiClientCertVerifier {
    fn new(ca_cert: Certificate) -> Self {
        Self { ca_cert }
    }
}

impl ClientCertVerifier for TsumikiClientCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        // Convert rustls CertificateDer to tsumiki Certificate
        let cert = Certificate::try_from(end_entity.clone())
            .map_err(|e| Error::General(format!("Failed to parse client certificate: {}", e)))?;

        println!("\n=== Client Certificate (parsed by tsumiki) ===");
        println!("Subject: {}", cert.tbs_certificate().subject());
        println!("Issuer: {}", cert.tbs_certificate().issuer());
        println!("Version: {:?}", cert.tbs_certificate().version());
        println!("Serial: {}", cert.tbs_certificate().serial_number());
        println!(
            "Not Before: {}",
            cert.tbs_certificate().validity().not_before()
        );
        println!(
            "Not After: {}",
            cert.tbs_certificate().validity().not_after()
        );
        println!(
            "Signature Algorithm: {}",
            cert.signature_algorithm().algorithm
        );

        // Verify issuer matches CA subject
        let ca_subject = self.ca_cert.tbs_certificate().subject();
        let cert_issuer = cert.tbs_certificate().issuer();

        if ca_subject == cert_issuer {
            println!("\nClient certificate issuer matches CA subject");
            println!("=== End Client Certificate Info ===\n");
            Ok(ClientCertVerified::assertion())
        } else {
            println!("\nWARNING: Client certificate issuer does not match CA!");
            println!("Expected: {}", ca_subject);
            println!("Got: {}", cert_issuer);
            Err(Error::General(
                "Client certificate not signed by trusted CA".to_string(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

/// Load certificate as tsumiki Certificate
fn load_certificate_as_tsumiki(path: &Path) -> io::Result<Certificate> {
    let pem_data = fs::read_to_string(path)?;
    let pem = pem_data.parse::<tsumiki_pem::Pem>().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("PEM parse error: {}", e),
        )
    })?;

    pem.decode().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Certificate decode error: {}", e),
        )
    })
}

/// Load certificate from PEM file using tsumiki
fn load_certificate(path: &Path) -> io::Result<CertificateDer<'static>> {
    let pem_data = fs::read_to_string(path)?;
    let pem = pem_data.parse::<tsumiki_pem::Pem>().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("PEM parse error: {}", e),
        )
    })?;

    let cert: Certificate = pem.decode().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Certificate decode error: {}", e),
        )
    })?;

    // Display certificate information
    println!("Loaded certificate:");
    println!("  Subject: {}", cert.tbs_certificate().subject());
    println!("  Issuer: {}", cert.tbs_certificate().issuer());
    println!(
        "  Valid from: {}",
        cert.tbs_certificate().validity().not_before()
    );
    println!(
        "  Valid until: {}",
        cert.tbs_certificate().validity().not_after()
    );

    // Convert to rustls CertificateDer
    CertificateDer::try_from(&cert).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Certificate conversion error: {}", e),
        )
    })
}

/// Load private key from PEM file using tsumiki
///
/// This function uses `PrivateKey` which automatically detects the key format
/// (PKCS#1 RSA, SEC1 EC, or PKCS#8).
fn load_private_key(path: &Path) -> io::Result<PrivateKeyDer<'static>> {
    let pem_data = fs::read_to_string(path)?;
    let pem = pem_data.parse::<tsumiki_pem::Pem>().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("PEM parse error: {}", e),
        )
    })?;

    // PrivateKey automatically detects the format (PKCS#1, SEC1, or PKCS#8)
    let key: PrivateKey = pem.decode().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Private key decode error: {}", e),
        )
    })?;

    let format = if key.is_pkcs1() {
        "PKCS#1 RSA"
    } else if key.is_sec1() {
        "SEC1 EC"
    } else {
        "PKCS#8"
    };
    println!("Loaded private key ({} format)", format);

    // Convert to rustls PrivateKeyDer
    PrivateKeyDer::try_from(key).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Private key conversion error: {}", e),
        )
    })
}

#[tokio::main]
async fn main() -> io::Result<()> {
    println!("mTLS Echo Server Example");
    println!("========================\n");

    // Load CA certificate for client verification
    let ca_cert = load_certificate_as_tsumiki(Path::new(CA_CERT_PATH))?;
    println!("Loaded CA certificate:");
    println!("  Subject: {}", ca_cert.tbs_certificate().subject());

    // Load server certificate and private key using tsumiki
    let cert = load_certificate(Path::new(CERT_PATH))?;
    let key = load_private_key(Path::new(KEY_PATH))?;

    println!();

    // Create custom client certificate verifier
    let client_verifier = Arc::new(TsumikiClientCertVerifier::new(ca_cert));

    // Build rustls ServerConfig with client authentication
    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(vec![cert], key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let acceptor = TlsAcceptor::from(Arc::new(config));

    // Start listening
    let addr = LISTEN_ADDR
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid address"))?;

    let listener = TcpListener::bind(&addr).await?;
    println!("Listening on {}", addr);
    println!("Connect with: cargo run --bin tls-echo-client");
    println!("Or: echo 'hello' | openssl s_client -connect localhost:8443 -quiet\n");

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();

        tokio::spawn(async move {
            println!("New connection from {}", peer_addr);

            match acceptor.accept(stream).await {
                Ok(mut tls_stream) => {
                    let mut buf = vec![0u8; 1024];

                    loop {
                        match tls_stream.read(&mut buf).await {
                            Ok(0) => {
                                println!("Connection closed by {}", peer_addr);
                                break;
                            }
                            Ok(n) => {
                                let received = String::from_utf8_lossy(&buf[..n]);
                                println!("Received from {}: {}", peer_addr, received.trim());

                                // Echo back
                                if let Err(e) = tls_stream.write_all(&buf[..n]).await {
                                    eprintln!("Write error: {}", e);
                                    break;
                                }
                            }
                            Err(e) => {
                                eprintln!("Read error from {}: {}", peer_addr, e);
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("TLS handshake error with {}: {}", peer_addr, e);
                }
            }
        });
    }
}
