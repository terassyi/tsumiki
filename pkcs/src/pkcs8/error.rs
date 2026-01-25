use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid version: {0}")]
    InvalidVersion(i64),

    #[error("expected SEQUENCE")]
    ExpectedSequence,

    #[error("expected {expected} elements, got {actual}")]
    InvalidElementCount {
        expected: &'static str,
        actual: usize,
    },

    #[error("expected OCTET STRING for {field}")]
    ExpectedOctetString { field: &'static str },

    #[error("expected INTEGER for version")]
    ExpectedVersionInteger,

    #[error("empty ASN1Object")]
    EmptyAsn1Object,

    #[error("failed to encode SubjectPublicKeyInfo")]
    SubjectPublicKeyInfoEncodingFailed,

    #[error("unexpected key format: expected {expected}")]
    UnexpectedKeyFormat { expected: &'static str },

    #[error("ASN.1 error: {0}")]
    Asn1(#[from] tsumiki_asn1::error::Error),

    #[error("DER error: {0}")]
    Der(#[from] tsumiki_der::error::Error),

    #[error("PKIX types error: {0}")]
    PkixTypes(#[from] tsumiki_pkix_types::Error),

    #[error("Invalid algorithm identifier")]
    InvalidAlgorithmIdentifier,

    #[error("PKCS#9 attribute error: {0}")]
    Pkcs9(#[from] crate::pkcs9::error::Error),
}
