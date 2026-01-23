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

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("YAML serialization error: {0}")]
    Yaml(#[from] serde_yml::Error),

    #[error("UTF-8 conversion error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("Formatting error: {0}")]
    Fmt(#[from] std::fmt::Error),

    #[error("cannot extract public key from {0}")]
    PublicKeyExtraction(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Certificate error: {0}")]
    Certificate(String),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("{0}")]
    Message(String),
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::Message(s.to_string())
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Message(s)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
