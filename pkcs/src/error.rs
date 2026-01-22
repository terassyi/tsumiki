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

    #[error("unrecognized private key format: pkcs8={pkcs8}, sec1={sec1}, pkcs1={pkcs1}")]
    UnrecognizedPrivateKeyFormat {
        pkcs8: Box<crate::pkcs8::Error>,
        sec1: Box<crate::sec1::Error>,
        pkcs1: Box<crate::pkcs1::Error>,
    },

    #[error("empty ASN.1 object")]
    EmptyAsn1Object,
}

pub type Result<T> = std::result::Result<T, Error>;
