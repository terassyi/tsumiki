use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("ASN.1 error: {0}")]
    Asn1(#[from] asn1::error::Error),

    #[error("PKCS#1 error: {0}")]
    Pkcs1(#[from] crate::pkcs1::Error),

    #[error("PKCS#8 error: {0}")]
    Pkcs8(#[from] crate::pkcs8::Error),

    #[error("SEC1 error: {0}")]
    Sec1(#[from] crate::sec1::Error),

    #[error(transparent)]
    PKIXTypes(#[from] pkix_types::Error),

    #[error("DER error: {0}")]
    Der(#[from] der::error::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
