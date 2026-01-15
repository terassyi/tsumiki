use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("ASN.1 error: {0}")]
    Asn1(#[from] asn1::error::Error),

    #[error("PKCS#1 error: {0}")]
    Pkcs1(#[from] crate::pkcs1::Error),
    // PKCS#8 and SEC1 will be added later
}

pub type Result<T> = std::result::Result<T, Error>;
