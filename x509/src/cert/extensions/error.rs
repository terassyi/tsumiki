//! Error types for the certificate-specific extensions.

use thiserror::Error;

/// Context for where a certificate extension error occurred
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    BasicConstraints,
    KeyUsage,
    SubjectKeyIdentifier,
    ExtendedKeyUsage,
    AuthorityInfoAccess,
    NameConstraints,
    CertificatePolicies,
    InhibitAnyPolicy,
    PolicyConstraints,
    PolicyMappings,
    SubjectAltName,
    SubjectInfoAccess,
    SubjectDirectoryAttributes,
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BasicConstraints => write!(f, "BasicConstraints"),
            Self::KeyUsage => write!(f, "KeyUsage"),
            Self::SubjectKeyIdentifier => write!(f, "SubjectKeyIdentifier"),
            Self::ExtendedKeyUsage => write!(f, "ExtendedKeyUsage"),
            Self::AuthorityInfoAccess => write!(f, "AuthorityInfoAccess"),
            Self::NameConstraints => write!(f, "NameConstraints"),
            Self::CertificatePolicies => write!(f, "CertificatePolicies"),
            Self::InhibitAnyPolicy => write!(f, "InhibitAnyPolicy"),
            Self::PolicyConstraints => write!(f, "PolicyConstraints"),
            Self::PolicyMappings => write!(f, "PolicyMappings"),
            Self::SubjectAltName => write!(f, "SubjectAltName"),
            Self::SubjectInfoAccess => write!(f, "SubjectInfoAccess"),
            Self::SubjectDirectoryAttributes => write!(f, "SubjectDirectoryAttributes"),
        }
    }
}

/// Certificate extension parsing errors
#[derive(Debug, Error)]
pub enum Error {
    // Common structural errors
    #[error("{0}: empty sequence")]
    EmptySequence(Kind),

    #[error("{0}: expected SEQUENCE")]
    ExpectedSequence(Kind),

    #[error("{0}: expected BIT STRING")]
    ExpectedBitString(Kind),

    #[error("{0}: expected OCTET STRING")]
    ExpectedOctetString(Kind),

    #[error("{0}: expected INTEGER")]
    ExpectedInteger(Kind),

    #[error("{0}: expected OBJECT IDENTIFIER")]
    ExpectedOid(Kind),

    #[error("{kind}: expected context-specific tag [{expected}]")]
    ExpectedContextTag { kind: Kind, expected: u8 },

    #[error("{kind}: expected {expected} elements, got {actual}")]
    InvalidElementCount {
        kind: Kind,
        expected: &'static str,
        actual: usize,
    },

    #[error("{0}: unexpected element type")]
    UnexpectedElementType(Kind),

    // BasicConstraints specific errors
    #[error("BasicConstraints: pathLenConstraint out of range for u32")]
    PathLenConstraintOutOfRange,

    // ExtendedKeyUsage specific errors
    #[error("ExtendedKeyUsage: at least one KeyPurposeId required")]
    ExtendedKeyUsageEmpty,

    #[error("ExtendedKeyUsage: all elements must be OBJECT IDENTIFIER")]
    ExtendedKeyUsageExpectedOid,

    // InhibitAnyPolicy / PolicyConstraints specific errors
    #[error("{0}: empty content")]
    EmptyContent(Kind),

    #[error("{0}: value out of range for u32")]
    ValueOutOfRangeU32(Kind),

    // NameConstraints specific errors
    #[error(
        "NameConstraints: at least one of permittedSubtrees or excludedSubtrees must be present"
    )]
    NameConstraintsEmptyContent,

    #[error("NameConstraints: invalid element in sequence")]
    NameConstraintsInvalidElement,

    // CRLDistributionPoints specific errors
    #[error("CRLDistributionPoints: at least one DistributionPoint required")]
    CrlDistributionPointsEmpty,

    #[error("CRLDistributionPoints: unknown context tag [{0}]")]
    CrlDistributionPointsUnknownTag(u8),

    // CertificatePolicies specific errors
    #[error("CertificatePolicies: at least one PolicyInformation required")]
    CertificatePoliciesEmpty,

    #[error("CertificatePolicies: PolicyInformation must be SEQUENCE")]
    PolicyInformationExpectedSequence,

    #[error(
        "CertificatePolicies: PolicyInformation requires at least 1 element (policyIdentifier)"
    )]
    PolicyInformationMissingIdentifier,

    #[error("CertificatePolicies: policyIdentifier must be OBJECT IDENTIFIER")]
    PolicyInformationExpectedOid,

    #[error("CertificatePolicies: policyQualifiers must be SEQUENCE")]
    PolicyQualifiersExpectedSequence,

    #[error("CertificatePolicies: PolicyQualifierInfo must be SEQUENCE")]
    PolicyQualifierInfoExpectedSequence,

    #[error("CertificatePolicies: PolicyQualifierInfo requires 2 elements")]
    PolicyQualifierInfoInvalidElementCount,

    #[error("CertificatePolicies: policyQualifierId must be OBJECT IDENTIFIER")]
    PolicyQualifierIdExpectedOid,

    #[error("CertificatePolicies: UserNotice must be SEQUENCE")]
    UserNoticeExpectedSequence,

    #[error("CertificatePolicies: NoticeReference must be SEQUENCE with 2 elements")]
    NoticeReferenceInvalidStructure,

    #[error("CertificatePolicies: noticeNumbers must be SEQUENCE")]
    NoticeNumbersExpectedSequence,

    #[error("CertificatePolicies: noticeNumbers must contain INTEGER values")]
    NoticeNumbersExpectedIntegers,

    // PolicyMappings specific errors
    #[error("PolicyMappings: at least one mapping required")]
    PolicyMappingsEmpty,

    #[error("PolicyMappings: PolicyMapping must be SEQUENCE with 2 elements")]
    PolicyMappingInvalidStructure,

    #[error("PolicyMappings: issuerDomainPolicy must be OBJECT IDENTIFIER")]
    PolicyMappingIssuerExpectedOid,

    #[error("PolicyMappings: subjectDomainPolicy must be OBJECT IDENTIFIER")]
    PolicyMappingSubjectExpectedOid,

    // AuthorityInfoAccess specific errors
    #[error("AuthorityInfoAccess: at least one AccessDescription required")]
    AuthorityInfoAccessEmpty,

    #[error("AuthorityInfoAccess: AccessDescription must be SEQUENCE with 2 elements")]
    AccessDescriptionInvalidStructure,

    #[error("AuthorityInfoAccess: accessMethod must be OBJECT IDENTIFIER")]
    AccessDescriptionExpectedOid,

    // SubjectInfoAccess specific errors
    #[error("SubjectInfoAccess: at least one AccessDescription required")]
    SubjectInfoAccessEmpty,

    #[error("SubjectInfoAccess: AccessDescription must be SEQUENCE with 2 elements")]
    SubjectInfoAccessInvalidStructure,

    #[error("SubjectInfoAccess: accessMethod must be OBJECT IDENTIFIER")]
    SubjectInfoAccessExpectedOid,

    // SubjectAltName specific errors
    #[error("{0}: at least one GeneralName required")]
    AtLeastOneGeneralNameRequired(Kind),

    // SubjectDirectoryAttributes specific errors
    #[error("SubjectDirectoryAttributes: at least one Attribute required")]
    SubjectDirectoryAttributesEmpty,

    #[error("SubjectDirectoryAttributes: Attribute must be SEQUENCE with 2 elements")]
    SubjectDirectoryAttributeInvalidStructure,

    #[error("SubjectDirectoryAttributes: type must be OBJECT IDENTIFIER")]
    SubjectDirectoryAttributeExpectedOid,

    #[error("SubjectDirectoryAttributes: values must be SET")]
    SubjectDirectoryAttributeExpectedSet,

    #[error("SubjectDirectoryAttributes: at least one AttributeValue required")]
    SubjectDirectoryAttributeEmptyValues,

    /// Invalid ASN.1 structure
    #[error("invalid ASN.1: {0}")]
    InvalidAsn1(#[source] tsumiki_asn1::error::Error),
}

/// Result type for certificate extension operations
pub type Result<T> = std::result::Result<T, Error>;
