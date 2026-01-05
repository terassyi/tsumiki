use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
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

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("YAML serialization error: {0}")]
    Yaml(#[from] serde_yml::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
