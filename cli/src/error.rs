use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("PEM decode error: {0}")]
    Pem(#[from] pem::error::Error),

    #[error("DER decode error: {0}")]
    Der(#[from] der::error::Error),

    #[error("ASN.1 decode error: {0}")]
    Asn1(#[from] asn1::error::Error),

    #[error("X.509 parse error: {0}")]
    X509(#[from] x509::error::Error),

    #[error("PKCS#1 decode error: {0}")]
    Pkcs1(#[from] pkcs::pkcs1::Error),

    #[error("PKCS#8 decode error: {0}")]
    Pkcs8(#[from] pkcs::pkcs8::Error),

    #[error("SEC1 decode error: {0}")]
    Sec1(#[from] pkcs::sec1::Error),

    #[error("PKCS error: {0}")]
    Pkcs(#[from] pkcs::Error),

    #[error("PKIX types error: {0}")]
    PkixTypes(#[from] pkix_types::Error),

    #[error("algorithm parameter error: {0}")]
    AlgorithmParameter(#[from] pkix_types::algorithm::parameters::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("YAML serialization error: {0}")]
    Yaml(#[from] serde_yml::Error),

    #[error("UTF-8 conversion error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("Formatting error: {0}")]
    Fmt(#[from] std::fmt::Error),

    // Input validation errors
    #[error("invalid hostname: {0}")]
    InvalidHostname(String),
    #[error("--remote cannot be used with file input")]
    RemoteWithFileInput,
    #[error("unsupported PEM label: {0}")]
    UnsupportedPemLabel(String),

    // Connection errors
    #[error("failed to connect to {host}:{port}: {reason}")]
    ConnectionFailed {
        host: String,
        port: u16,
        reason: String,
    },

    // TLS errors
    #[error("failed to create TLS connection: {0}")]
    TlsConnectionFailed(String),
    #[error("TLS handshake failed: {0}")]
    TlsHandshakeFailed(String),
    #[error("no certificates received from server")]
    NoCertificatesReceived,

    // Certificate errors
    #[error("no certificates found")]
    NoCertificatesFound,
    #[error("certificate index {index} out of range (chain has {total} certificates)")]
    CertificateIndexOutOfRange { index: usize, total: usize },
    #[error("failed to parse certificate chain: {0}")]
    CertificateChainParseFailed(String),

    // Key extraction errors
    #[error("cannot extract public key: unsupported key format (only RSA-PKCS#1, PKCS#8, or SEC1)")]
    UnsupportedKeyFormat,
    #[error("cannot extract public key from {0} key")]
    PublicKeyExtractionFailed(String),

    // Decode errors
    #[error("failed to decode private key: {0}")]
    PrivateKeyDecodeFailed(String),
    #[error("failed to decode public key: {0}")]
    PublicKeyDecodeFailed(String),
    #[error("cannot determine key size for: {0}")]
    CannotDetermineKeySize(String),
}

pub type Result<T> = std::result::Result<T, Error>;
