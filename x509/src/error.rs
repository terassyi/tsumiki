use thiserror::Error;

#[derive(Debug, Error)]
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
    #[error("invalid unique identifier: {0}")]
    InvalidUniqueIdentifier(String),
    #[error("invalid extension: {0}")]
    InvalidExtension(String),
    #[error("invalid extensions: {0}")]
    InvalidExtensions(String),
    #[error("invalid BasicConstraints: {0}")]
    InvalidBasicConstraints(String),
    #[error("invalid KeyUsage: {0}")]
    InvalidKeyUsage(String),
    #[error("invalid SubjectKeyIdentifier: {0}")]
    InvalidSubjectKeyIdentifier(String),
    #[error("invalid AuthorityKeyIdentifier: {0}")]
    InvalidAuthorityKeyIdentifier(String),
    #[error("invalid SubjectAltName: {0}")]
    InvalidSubjectAltName(String),
    #[error("invalid IssuerAltName: {0}")]
    InvalidIssuerAltName(String),
    #[error("invalid GeneralName: {0}")]
    InvalidGeneralName(String),
    #[error("invalid ExtendedKeyUsage: {0}")]
    InvalidExtendedKeyUsage(String),
    #[error("invalid AuthorityInfoAccess: {0}")]
    InvalidAuthorityInfoAccess(String),
    #[error("invalid NameConstraints: {0}")]
    InvalidNameConstraints(String),
    #[error("invalid CRLDistributionPoints: {0}")]
    InvalidCRLDistributionPoints(String),
    #[error("invalid CertificatePolicies: {0}")]
    InvalidCertificatePolicies(String),
    #[error("invalid InhibitAnyPolicy: {0}")]
    InvalidInhibitAnyPolicy(String),
    #[error("invalid PolicyConstraints: {0}")]
    InvalidPolicyConstraints(String),
    #[error("invalid PolicyMappings: {0}")]
    InvalidPolicyMappings(String),
    #[error("invalid certificate: {0}")]
    InvalidCertificate(String),
    #[error("invalid TBS certificate: {0}")]
    InvalidTBSCertificate(String),
    #[error("invalid ASN.1: {0}")]
    InvalidASN1(#[source] asn1::error::Error),
    #[error("PKIX types error: {0}")]
    PKIXTypesError(#[from] pkix_types::Error),
    #[error("serialization error: {0}")]
    SerializationError(String),
}
