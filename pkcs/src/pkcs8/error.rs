use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid version: {0}")]
    InvalidVersion(i64),

    #[error("Invalid structure: {0}")]
    InvalidStructure(String),

    #[error("ASN.1 error: {0}")]
    Asn1(#[from] asn1::error::Error),

    #[error("DER error: {0}")]
    Der(#[from] der::error::Error),

    #[error("PKIX types error: {0}")]
    PkixTypes(#[from] pkix_types::Error),

    #[error("Invalid algorithm identifier")]
    InvalidAlgorithmIdentifier,

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("PKCS#9 attribute error: {0}")]
    Pkcs9(#[from] crate::pkcs9::error::Error),
}
