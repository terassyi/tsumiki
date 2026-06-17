//! Error types for the shared extension machinery and types.
//!
//! These cover the extensions and types that live in the shared `extensions`
//! module (reused by both certificates and CRLs): `GeneralName`,
//! `AuthorityKeyIdentifier`, `IssuerAltName`, `FreshestCRL`, and the shared
//! `DistributionPoint`/`DistributionPointName`/`ReasonFlags` types.

use thiserror::Error;

/// Context for where a shared extension error occurred
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    AuthorityKeyIdentifier,
    IssuerAltName,
    GeneralName,
    CRLDistributionPoints,
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthorityKeyIdentifier => write!(f, "AuthorityKeyIdentifier"),
            Self::IssuerAltName => write!(f, "IssuerAltName"),
            Self::GeneralName => write!(f, "GeneralName"),
            Self::CRLDistributionPoints => write!(f, "CRLDistributionPoints"),
        }
    }
}

/// Shared extension parsing errors
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

    #[error("{0}: expected OBJECT IDENTIFIER")]
    ExpectedOid(Kind),

    #[error("{0}: unexpected element type")]
    UnexpectedElementType(Kind),

    // GeneralName specific errors
    #[error("GeneralName: unknown context-specific tag [{0}]")]
    UnknownGeneralNameTag(u8),

    #[error("GeneralName: IA5String must be valid ASCII")]
    GeneralNameInvalidAscii,

    #[error("GeneralName: iPAddress must be 4, 8, 16, or 32 bytes, got {0}")]
    InvalidIpAddressLength(usize),

    #[error("GeneralName: invalid IPv4 network: {0}")]
    InvalidIpv4Network(String),

    #[error("GeneralName: invalid IPv6 network: {0}")]
    InvalidIpv6Network(String),

    #[error("GeneralName: invalid OID encoding")]
    InvalidOidEncoding,

    #[error("GeneralName: otherName requires at least 2 elements")]
    OtherNameInvalidElementCount,

    #[error("GeneralName: otherName type-id must be OBJECT IDENTIFIER")]
    OtherNameExpectedOid,

    #[error("GeneralName: otherName value must be [0] EXPLICIT")]
    OtherNameExpectedExplicitTag,

    #[error("GeneralName: ediPartyName missing required partyName [1]")]
    EdiPartyNameMissingPartyName,

    #[error("GeneralName: invalid nameAssigner in ediPartyName")]
    EdiPartyNameInvalidNameAssigner,

    #[error("GeneralName: invalid partyName in ediPartyName")]
    EdiPartyNameInvalidPartyName,

    // SubjectAltName / IssuerAltName specific errors
    #[error("{0}: at least one GeneralName required")]
    AtLeastOneGeneralNameRequired(Kind),

    // AuthorityKeyIdentifier specific errors
    #[error("AuthorityKeyIdentifier: keyIdentifier must be OCTET STRING")]
    AkiKeyIdentifierNotOctetString,

    #[error("AuthorityKeyIdentifier: authorityCertIssuer must be SEQUENCE (GeneralNames)")]
    AkiAuthorityCertIssuerNotSequence,

    #[error("AuthorityKeyIdentifier: serialNumber must be OCTET STRING or INTEGER")]
    AkiSerialNumberInvalidType,

    // CRLDistributionPoints / DistributionPoint shared type errors
    #[error("CRLDistributionPoints: at least one DistributionPoint required")]
    CrlDistributionPointsEmpty,

    #[error("CRLDistributionPoints: unknown context tag [{0}]")]
    CrlDistributionPointsUnknownTag(u8),

    /// Invalid ASN.1 structure
    #[error("invalid ASN.1: {0}")]
    InvalidAsn1(#[source] tsumiki_asn1::error::Error),
}

/// Result type for shared extension operations
pub type Result<T> = std::result::Result<T, Error>;
