//! mTLS Echo Client Example
//!
//! This example demonstrates how to use tsumiki with rustls to create an mTLS client
//! that sends a client certificate and inspects the server's certificate.
//!
//! Usage:
//!   First start the server:
//!     cargo run --bin tls-echo-server
//!
//!   Then run the client:
//!     cargo run --bin tls-echo-client

use std::fs;
use std::io::{self, BufRead, Write};
use std::net::ToSocketAddrs;
use std::path::Path;
use std::sync::Arc;

use pkcs::PrivateKey;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tsumiki::decoder::Decoder;
use x509::Certificate;

const SERVER_ADDR: &str = "127.0.0.1:8443";
const CA_CERT_PATH: &str = "examples/certs/ca.crt";
const CLIENT_CERT_PATH: &str = "examples/certs/client.crt";
const CLIENT_KEY_PATH: &str = "examples/certs/client.key";

/// Custom certificate verifier that uses tsumiki to inspect certificates
#[derive(Debug)]
struct TsumikiCertVerifier {
    /// Root certificate for verification (self-signed in this example)
    root_cert: Certificate,
}

impl TsumikiCertVerifier {
    fn new(root_cert: Certificate) -> Self {
        Self { root_cert }
    }
}

impl ServerCertVerifier for TsumikiCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // Convert rustls CertificateDer to tsumiki Certificate
        let cert = Certificate::try_from(end_entity.clone())
            .map_err(|e| Error::General(format!("Failed to parse certificate: {}", e)))?;

        println!("\n=== Server Certificate (parsed by tsumiki) ===");
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

        // Check signature algorithm
        println!(
            "Signature Algorithm: {}",
            cert.signature_algorithm().algorithm
        );

        // List extensions if present
        if let Some(oids) = cert.extension_oids() {
            println!("Extensions:");
            for oid in oids {
                println!("  - {}", oid);
            }
        }

        // In a real application, you would verify:
        // 1. The certificate chain
        // 2. The certificate signature
        // 3. The validity period
        // 4. The server name matches

        // For this example, we just check if issuer matches our root cert's subject
        let root_subject = self.root_cert.tbs_certificate().subject();
        let cert_issuer = cert.tbs_certificate().issuer();

        if root_subject == cert_issuer {
            println!("\nCertificate issuer matches root certificate subject");
            println!("=== End Certificate Info ===\n");
            Ok(ServerCertVerified::assertion())
        } else {
            println!("\nWARNING: Certificate issuer does not match!");
            println!("Expected: {}", root_subject);
            println!("Got: {}", cert_issuer);
            // For demo purposes, we still accept it
            println!("(Accepting anyway for demo purposes)");
            println!("=== End Certificate Info ===\n");
            Ok(ServerCertVerified::assertion())
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // For demo purposes, accept all signatures
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // For demo purposes, accept all signatures
        Ok(HandshakeSignatureValid::assertion())
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
    let pem = pem_data.parse::<pem::Pem>().map_err(|e| {
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

/// Load certificate from PEM file and convert to rustls CertificateDer
fn load_certificate(path: &Path) -> io::Result<CertificateDer<'static>> {
    let cert = load_certificate_as_tsumiki(path)?;
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
    let pem = pem_data.parse::<pem::Pem>().map_err(|e| {
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
    println!("mTLS Echo Client Example");
    println!("========================\n");

    // Load CA certificate for server verification
    let ca_cert = load_certificate_as_tsumiki(Path::new(CA_CERT_PATH))?;
    println!("Loaded CA certificate:");
    println!("  Subject: {}", ca_cert.tbs_certificate().subject());

    // Load client certificate and key
    let client_cert = load_certificate(Path::new(CLIENT_CERT_PATH))?;
    let client_key = load_private_key(Path::new(CLIENT_KEY_PATH))?;

    let client_cert_tsumiki = load_certificate_as_tsumiki(Path::new(CLIENT_CERT_PATH))?;
    println!("Loaded client certificate:");
    println!(
        "  Subject: {}",
        client_cert_tsumiki.tbs_certificate().subject()
    );

    // Create custom server certificate verifier
    let verifier = Arc::new(TsumikiCertVerifier::new(ca_cert));

    // Build rustls ClientConfig with custom verifier and client auth
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![client_cert], client_key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let connector = TlsConnector::from(Arc::new(config));

    // Connect to server
    let addr = SERVER_ADDR
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid address"))?;

    println!("\nConnecting to {}...", addr);

    let stream = TcpStream::connect(&addr).await?;
    let domain = ServerName::try_from("localhost").unwrap();

    let mut tls_stream = connector.connect(domain, stream).await.map_err(|e| {
        io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("TLS error: {}", e),
        )
    })?;

    println!("Connected! TLS handshake successful.");
    println!("\nType messages to send (Ctrl+D to quit):\n");

    // Read from stdin and send to server
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }

        // Send message
        let msg = format!("{}\n", line);
        tls_stream.write_all(msg.as_bytes()).await?;

        // Read response
        let mut buf = vec![0u8; 1024];
        let n = tls_stream.read(&mut buf).await?;
        if n == 0 {
            println!("Server closed connection");
            break;
        }

        let response = String::from_utf8_lossy(&buf[..n]);
        print!("Server echoed: {}", response);
        io::stdout().flush()?;
    }

    println!("\nGoodbye!");
    Ok(())
}
