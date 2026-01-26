use thiserror::Error;

/// Unified error type for the pkcs crate.
///
/// This error type aggregates errors from all PKCS standards and related crates.
#[derive(Debug, Error)]
pub enum Error {
    #[error("ASN.1 error: {0}")]
    Asn1(#[from] tsumiki_asn1::error::Error),

    #[error("PKCS#1 error: {0}")]
    Pkcs1(#[from] crate::pkcs1::Error),

    #[error("PKCS#8 error: {0}")]
    Pkcs8(#[from] crate::pkcs8::Error),

    #[error("SEC1 error: {0}")]
    Sec1(#[from] crate::sec1::Error),

    #[error(transparent)]
    PKIXTypes(#[from] tsumiki_pkix_types::Error),

    #[error("DER error: {0}")]
    Der(#[from] tsumiki_der::error::Error),

    #[error("unrecognized private key format: pkcs8={pkcs8}, sec1={sec1}, pkcs1={pkcs1}")]
    UnrecognizedPrivateKeyFormat {
        pkcs8: Box<crate::pkcs8::Error>,
        sec1: Box<crate::sec1::Error>,
        pkcs1: Box<crate::pkcs1::Error>,
    },

    #[error("unrecognized public key format: spki={spki}, pkcs1={pkcs1}")]
    UnrecognizedPublicKeyFormat {
        spki: Box<crate::pkcs8::Error>,
        pkcs1: Box<crate::pkcs1::Error>,
    },

    #[error("empty ASN.1 object")]
    EmptyAsn1Object,
}

/// Result type alias using the pkcs crate's Error type.
pub type Result<T> = std::result::Result<T, Error>;
