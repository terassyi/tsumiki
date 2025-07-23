use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid validity: {0}")]
    InvalidValidity(String),
    #[error("invalid attribute type and value: {0}")]
    InvalidAttributeTypeAndValue(String),
    #[error("invalid attribute type: {0}")]
    InvalidAttributeType(String),
    #[error("invalid attribute value: {0}")]
    InvalidAttributeValue(String),
    #[error("invalid name: {0}")]
    InvalidName(String),
    #[error("invalid relative distinguished name: {0}")]
    InvalidRelativeDistinguishedName(String),
    #[error("invalid algorithm identifier: {0}")]
    InvalidAlgorithmIdentifier(String),
    #[error("invalid certificate serial number: {0}")]
    InvalidCertificateSerialNumber(String),
    #[error("invalid version: {0}")]
    InvalidVersion(String),
}
