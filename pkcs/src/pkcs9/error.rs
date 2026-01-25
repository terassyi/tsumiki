//! Error types for PKCS#9

use thiserror::Error;

/// Result type for PKCS#9 operations
pub type Result<T> = std::result::Result<T, Error>;

/// PKCS#9 error types
#[derive(Debug, Error)]
pub enum Error {
    // Attribute general errors
    /// Attribute: expected SEQUENCE
    #[error("Attribute: expected SEQUENCE")]
    AttributeExpectedSequence,

    /// Attribute: expected 2 elements (attributeType, attributeValues)
    #[error("Attribute: expected 2 elements, got {0}")]
    AttributeInvalidElementCount(usize),

    /// Attribute: expected OBJECT IDENTIFIER for attributeType
    #[error("Attribute: expected OBJECT IDENTIFIER for attributeType")]
    AttributeExpectedOid,

    /// Attribute: expected SET for attributeValues
    #[error("Attribute: expected SET for attributeValues")]
    AttributeExpectedSet,

    /// Attribute: empty ASN1Object
    #[error("{0}: empty ASN1Object")]
    AttributeEmptyAsn1Object(&'static str),

    /// Attribute: values SET is empty
    #[error("{0}: values SET is empty")]
    AttributeEmptyValuesSet(&'static str),

    /// Attribute: expected exactly one value, got {actual}
    #[error("{attr}: expected exactly one value, got {actual}")]
    AttributeInvalidValueCount { attr: &'static str, actual: usize },

    /// Attribute: expected element type
    #[error("{attr}: expected {expected}")]
    AttributeExpectedElementType {
        attr: &'static str,
        expected: &'static str,
    },

    /// Attributes: expected SET
    #[error("Attributes: must be a SET")]
    AttributesExpectedSet,

    /// Invalid contentType attribute - expected OBJECT IDENTIFIER
    #[error("invalid contentType: expected OBJECT IDENTIFIER")]
    InvalidContentTypeExpectedOid,

    /// Invalid messageDigest attribute - expected OCTET STRING
    #[error("invalid messageDigest: expected OCTET STRING")]
    InvalidMessageDigestExpectedOctetString,

    // signingTime errors
    /// signingTime: invalid RFC3339 format
    #[error("signingTime: invalid RFC3339 format: {0}")]
    SigningTimeInvalidRfc3339(String),

    /// signingTime: invalid date/time from UTCTime
    #[error("signingTime: invalid date/time from UTCTime")]
    SigningTimeInvalidDateTime,

    /// signingTime: expected UTCTime or GeneralizedTime
    #[error("signingTime: expected UTCTime or GeneralizedTime")]
    SigningTimeExpectedTime,

    // challengePassword errors
    /// challengePassword: invalid encoding
    #[error("challengePassword: invalid encoding: {0}")]
    ChallengePasswordInvalidEncoding(String),

    // unstructuredName errors
    /// unstructuredName: expected IA5String or DirectoryString
    #[error("unstructuredName: expected IA5String or DirectoryString, got {0}")]
    UnstructuredNameInvalidType(String),

    // unstructuredAddress errors
    /// unstructuredAddress: expected DirectoryString
    #[error("unstructuredAddress: expected DirectoryString, got {0}")]
    UnstructuredAddressInvalidType(String),

    // smimeCapabilities errors
    /// smimeCapabilities: expected SEQUENCE for SMIMECapability
    #[error("smimeCapabilities: expected SEQUENCE for SMIMECapability")]
    SmimeCapabilitiesExpectedSequence,

    /// smimeCapabilities: expected OBJECT IDENTIFIER for capabilityID
    #[error("smimeCapabilities: expected OBJECT IDENTIFIER for capabilityID")]
    SmimeCapabilitiesExpectedOid,

    /// smimeCapabilities: expected 1 or 2 elements in SMIMECapability
    #[error("smimeCapabilities: expected 1 or 2 elements, got {0}")]
    SmimeCapabilitiesInvalidElementCount(usize),

    // countersignature errors
    /// countersignature: expected SEQUENCE for SignerInfo
    #[error("countersignature: expected SEQUENCE for SignerInfo, got {0}")]
    CountersignatureExpectedSequence(String),

    /// countersignature: invalid version value
    #[error("countersignature: invalid version value")]
    CountersignatureInvalidVersion,

    /// countersignature: missing required field
    #[error("countersignature: missing {0}")]
    CountersignatureMissingField(&'static str),

    /// countersignature: expected element type
    #[error("countersignature: expected {expected}, got {actual}")]
    CountersignatureExpectedType {
        expected: &'static str,
        actual: String,
    },

    /// countersignature: invalid element count
    #[error("countersignature: expected {expected} elements, got {actual}")]
    CountersignatureInvalidElementCount { expected: usize, actual: usize },

    // extensionRequest errors
    /// extensionRequest: expected SEQUENCE for Extensions
    #[error("extensionRequest: expected SEQUENCE for Extensions")]
    ExtensionRequestExpectedSequence,

    /// extensionRequest: expected exactly one value
    #[error("extensionRequest: expected exactly one value, got {0}")]
    ExtensionRequestInvalidValueCount(usize),

    /// Invalid friendlyName attribute - expected BMPString
    #[error("invalid friendlyName: expected BMPString")]
    InvalidFriendlyNameExpectedBmpString,

    /// Invalid friendlyName attribute - BMPString conversion failed
    #[error("invalid friendlyName: BMPString conversion failed: {0}")]
    InvalidFriendlyNameBmpStringConversion(String),

    /// Invalid localKeyId attribute - expected OCTET STRING
    #[error("invalid localKeyId: expected OCTET STRING")]
    InvalidLocalKeyIdExpectedOctetString,

    /// Empty attribute name or value
    #[error("{0} cannot be empty")]
    EmptyValue(String),

    /// Value exceeds maximum length
    #[error("value too long: {actual} characters (max: {max})")]
    ValueTooLong { max: usize, actual: usize },

    /// OID mismatch between expected and actual
    #[error("OID mismatch: expected {expected}, got {actual}")]
    OidMismatch { expected: String, actual: String },

    /// Failed to parse ASN.1 structure
    #[error("ASN.1 error: {0}")]
    ASN1Error(#[from] tsumiki_asn1::error::Error),

    /// Failed to encode/decode DER
    #[error("DER encoding/decoding error: {0}")]
    DerError(#[from] tsumiki_der::error::Error),

    /// PKIX types error
    #[error("PKIX types error: {0}")]
    PkixTypesError(#[from] tsumiki_pkix_types::Error),

    /// Unsupported attribute type
    #[error("unsupported attribute type: {0}")]
    UnsupportedAttribute(String),
}
