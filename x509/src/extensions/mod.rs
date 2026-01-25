use std::str::FromStr;

use asn1::Element;
use asn1::ObjectIdentifier;
use asn1::OctetString;
use serde::Deserialize;
use serde::Serialize;
use tsumiki::decoder::DecodableFrom;
use tsumiki::decoder::Decoder;
use tsumiki::encoder::EncodableTo;
use tsumiki::encoder::Encoder;

use crate::error::Error;

// Submodules
mod authority_info_access;
mod authority_key_identifier;
mod basic_constraints;
mod certificate_policies;
mod crl_distribution_points;
pub mod error;
mod extended_key_usage;
mod freshest_crl;
mod general_name;
mod inhibit_any_policy;
mod issuer_alt_name;
mod key_usage;
mod name_constraints;
mod policy_constraints;
mod policy_mappings;
mod subject_alt_name;
mod subject_key_identifier;

// Re-export public types
use asn1::AsOid;
pub use authority_info_access::{AccessDescription, AuthorityInfoAccess};
pub use authority_key_identifier::AuthorityKeyIdentifier;
pub use basic_constraints::BasicConstraints;
pub use certificate_policies::{
    CertPolicyId, CertificatePolicies, NoticeReference, PolicyInformation, PolicyQualifierInfo,
    Qualifier, UserNotice,
};
pub use crl_distribution_points::{
    CRLDistributionPoints, DistributionPoint, DistributionPointName, ReasonFlags,
};
pub use extended_key_usage::ExtendedKeyUsage;
pub use freshest_crl::FreshestCRL;
pub use general_name::{EdiPartyName, GeneralName, IpAddressOrRange, OtherName};
pub use inhibit_any_policy::InhibitAnyPolicy;
pub use issuer_alt_name::IssuerAltName;
pub use key_usage::KeyUsage;
pub use name_constraints::{GeneralSubtree, NameConstraints};
pub use policy_constraints::{PolicyConstraints, SkipCerts};
pub use policy_mappings::{PolicyMapping, PolicyMappings};
pub use subject_alt_name::SubjectAltName;
pub use subject_key_identifier::SubjectKeyIdentifier;

/// RawExtension wraps pkix_types::Extension for X.509-specific operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RawExtension(pkix_types::Extension);

impl RawExtension {
    /// Create a new RawExtension
    pub fn new(oid: ObjectIdentifier, critical: bool, value: OctetString) -> Self {
        Self(pkix_types::Extension::new(oid, critical, value))
    }

    /// Get the extension OID
    pub fn oid(&self) -> &ObjectIdentifier {
        self.0.oid()
    }

    /// Get the critical flag
    pub fn critical(&self) -> bool {
        self.0.is_critical()
    }

    /// Get the extension value
    pub fn value(&self) -> &OctetString {
        self.0.value()
    }

    /// Parse the extension value as a specific extension type
    pub fn parse<T: Extension>(&self) -> Result<T, Error> {
        // Verify OID matches
        let expected_oid = T::oid()?;
        if self.oid() != &expected_oid {
            return Err(Error::OidMismatch {
                expected: expected_oid.to_string(),
                actual: self.oid().to_string(),
            });
        }
        T::parse(self.value())
    }

    /// Get a reference to the inner pkix_types::Extension
    pub fn inner(&self) -> &pkix_types::Extension {
        &self.0
    }

    /// Convert into the inner pkix_types::Extension
    pub fn into_inner(self) -> pkix_types::Extension {
        self.0
    }
}

// Implement OidName for RawExtension
impl pkix_types::OidName for RawExtension {
    fn oid_name(&self) -> Option<&'static str> {
        // Map OID to standard extension names using constants from each extension type
        match self.oid().to_string().as_str() {
            SubjectKeyIdentifier::OID => Some("subjectKeyIdentifier"),
            KeyUsage::OID => Some("keyUsage"),
            SubjectAltName::OID => Some("subjectAltName"),
            IssuerAltName::OID => Some("issuerAltName"),
            BasicConstraints::OID => Some("basicConstraints"),
            NameConstraints::OID => Some("nameConstraints"),
            CRLDistributionPoints::OID => Some("cRLDistributionPoints"),
            CertificatePolicies::OID => Some("certificatePolicies"),
            PolicyMappings::OID => Some("policyMappings"),
            AuthorityKeyIdentifier::OID => Some("authorityKeyIdentifier"),
            PolicyConstraints::OID => Some("policyConstraints"),
            ExtendedKeyUsage::OID => Some("extKeyUsage"),
            FreshestCRL::OID => Some("freshestCRL"),
            InhibitAnyPolicy::OID => Some("inhibitAnyPolicy"),
            AuthorityInfoAccess::OID => Some("authorityInfoAccess"),
            // Additional common extensions not yet implemented
            "2.5.29.9" => Some("subjectDirectoryAttributes"),
            "2.5.29.16" => Some("privateKeyUsagePeriod"),
            "1.3.6.1.5.5.7.1.11" => Some("subjectInfoAccess"),
            _ => None,
        }
    }
}

impl From<pkix_types::Extension> for RawExtension {
    fn from(ext: pkix_types::Extension) -> Self {
        Self(ext)
    }
}

impl From<RawExtension> for pkix_types::Extension {
    fn from(ext: RawExtension) -> Self {
        ext.0
    }
}

impl AsRef<pkix_types::Extension> for RawExtension {
    fn as_ref(&self) -> &pkix_types::Extension {
        &self.0
    }
}

impl std::ops::Deref for RawExtension {
    type Target = pkix_types::Extension;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// Implement marker traits
impl DecodableFrom<Element> for RawExtension {}
impl EncodableTo<RawExtension> for Element {}

// Implement Decoder for Element -> RawExtension
impl Decoder<Element, RawExtension> for Element {
    type Error = pkix_types::Error;

    fn decode(&self) -> Result<RawExtension, Self::Error> {
        let ext: pkix_types::Extension = self.decode()?;
        Ok(RawExtension(ext))
    }
}

// Implement Encoder for RawExtension -> Element
impl Encoder<RawExtension, Element> for RawExtension {
    type Error = pkix_types::Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        self.0.encode()
    }
}

/*
RFC 5280 Section 4.1.2.9

Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension

Extension  ::=  SEQUENCE  {
    extnID      OBJECT IDENTIFIER,
    critical    BOOLEAN DEFAULT FALSE,
    extnValue   OCTET STRING
                -- contains the DER encoding of an ASN.1 value
                -- corresponding to the extension type identified
                -- by extnID
}
*/

/// Extensions is a sequence of RawExtension
/// RFC 5280: Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
///
/// Note: In TBSCertificate, this appears as:
/// - extensions [3] EXPLICIT Extensions OPTIONAL
/// - Element::ContextSpecific { slot: 3, element: Box<Element::Sequence> }
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Extensions {
    pub(crate) extensions: Vec<RawExtension>,
}

impl Extensions {
    pub fn extensions(&self) -> &Vec<RawExtension> {
        &self.extensions
    }

    /// Get a specific extension by OID
    pub fn get_by_oid<O: AsOid>(&self, oid: O) -> Result<Option<&RawExtension>, Error> {
        let oid_obj = oid.as_oid().map_err(Error::InvalidASN1)?;
        Ok(self.extensions.iter().find(|ext| ext.oid() == &oid_obj))
    }

    /// Get and parse a specific extension by type
    pub fn extension<T: Extension>(&self) -> Result<Option<T>, Error> {
        let oid = T::oid()?;
        if let Some(ext) = self.get_by_oid(&oid)? {
            Ok(Some(ext.parse::<T>()?))
        } else {
            Ok(None)
        }
    }
}

impl DecodableFrom<Element> for Extensions {}

impl Decoder<Element, Extensions> for Element {
    type Error = Error;

    fn decode(&self) -> Result<Extensions, Self::Error> {
        match self {
            Element::ContextSpecific { slot, element, .. } => {
                if *slot != 3 {
                    return Err(Error::UnexpectedContextTag {
                        expected: 3,
                        actual: *slot,
                    });
                }
                // EXPLICIT tagging: element contains the full SEQUENCE
                match element.as_ref() {
                    Element::Sequence(seq_elements) => {
                        if seq_elements.is_empty() {
                            return Err(Error::ExtensionsEmpty);
                        }
                        let extensions = seq_elements
                            .iter()
                            .map(|elem| elem.decode().map_err(Error::from))
                            .collect::<Result<Vec<RawExtension>, Error>>()?;
                        Ok(Extensions { extensions })
                    }
                    _ => Err(Error::ExpectedSequenceInExtensions),
                }
            }
            Element::Sequence(seq_elements) => {
                // Allow direct Sequence for testing
                if seq_elements.is_empty() {
                    return Err(Error::ExtensionsEmpty);
                }
                let extensions = seq_elements
                    .iter()
                    .map(|elem| elem.decode().map_err(Error::from))
                    .collect::<Result<Vec<RawExtension>, Error>>()?;
                Ok(Extensions { extensions })
            }
            _ => Err(Error::InvalidExtensionsStructure),
        }
    }
}

impl EncodableTo<Extensions> for Element {}

impl Encoder<Extensions, Element> for Extensions {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        if self.extensions.is_empty() {
            return Err(Error::ExtensionsEmpty);
        }

        let extension_elements: Result<Vec<Element>, Error> = self
            .extensions
            .iter()
            .map(|ext| ext.encode().map_err(Error::from))
            .collect();

        // Wrap in [3] EXPLICIT tag for TBSCertificate
        Ok(Element::ContextSpecific {
            constructed: true,
            slot: 3,
            element: Box::new(Element::Sequence(extension_elements?)),
        })
    }
}

/// Trait for X.509 extensions that can be parsed from RawExtension.value
pub trait Extension: Sized {
    const OID: &'static str;

    fn oid() -> Result<ObjectIdentifier, Error> {
        ObjectIdentifier::from_str(Self::OID).map_err(|e| Error::InvalidOidString {
            oid: Self::OID.to_string(),
            message: e.to_string(),
        })
    }
    /// Parse the extension value (DER-encoded ASN.1 in OctetString)
    fn parse(value: &OctetString) -> Result<Self, Error>;
}

/// ParsedExtensions holds all parsed extension types for JSON serialization
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ParsedExtensions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) basic_constraints: Option<BasicConstraints>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) key_usage: Option<KeyUsage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) extended_key_usage: Option<ExtendedKeyUsage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) subject_key_identifier: Option<SubjectKeyIdentifier>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) authority_key_identifier: Option<AuthorityKeyIdentifier>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) subject_alt_name: Option<SubjectAltName>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) issuer_alt_name: Option<IssuerAltName>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) crl_distribution_points: Option<CRLDistributionPoints>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) certificate_policies: Option<CertificatePolicies>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) policy_mappings: Option<PolicyMappings>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) authority_info_access: Option<AuthorityInfoAccess>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) name_constraints: Option<NameConstraints>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) policy_constraints: Option<PolicyConstraints>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) inhibit_any_policy: Option<InhibitAnyPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) freshest_crl: Option<FreshestCRL>,
}

impl ParsedExtensions {
    pub(crate) fn from_extensions(extensions: &Extensions) -> Result<Self, Error> {
        let mut raw = ParsedExtensions {
            basic_constraints: None,
            key_usage: None,
            extended_key_usage: None,
            subject_key_identifier: None,
            authority_key_identifier: None,
            subject_alt_name: None,
            issuer_alt_name: None,
            crl_distribution_points: None,
            certificate_policies: None,
            policy_mappings: None,
            authority_info_access: None,
            name_constraints: None,
            policy_constraints: None,
            inhibit_any_policy: None,
            freshest_crl: None,
        };

        for ext in extensions.extensions() {
            match ext.oid().to_string().as_str() {
                BasicConstraints::OID => {
                    raw.basic_constraints = Some(ext.parse::<BasicConstraints>()?);
                }
                KeyUsage::OID => {
                    raw.key_usage = Some(ext.parse::<KeyUsage>()?);
                }
                ExtendedKeyUsage::OID => {
                    raw.extended_key_usage = Some(ext.parse::<ExtendedKeyUsage>()?);
                }
                SubjectKeyIdentifier::OID => {
                    raw.subject_key_identifier = Some(ext.parse::<SubjectKeyIdentifier>()?);
                }
                AuthorityKeyIdentifier::OID => {
                    raw.authority_key_identifier = Some(ext.parse::<AuthorityKeyIdentifier>()?);
                }
                SubjectAltName::OID => {
                    raw.subject_alt_name = Some(ext.parse::<SubjectAltName>()?);
                }
                IssuerAltName::OID => {
                    raw.issuer_alt_name = Some(ext.parse::<IssuerAltName>()?);
                }
                CRLDistributionPoints::OID => {
                    raw.crl_distribution_points = Some(ext.parse::<CRLDistributionPoints>()?);
                }
                CertificatePolicies::OID => {
                    raw.certificate_policies = Some(ext.parse::<CertificatePolicies>()?);
                }
                PolicyMappings::OID => {
                    raw.policy_mappings = Some(ext.parse::<PolicyMappings>()?);
                }
                AuthorityInfoAccess::OID => {
                    raw.authority_info_access = Some(ext.parse::<AuthorityInfoAccess>()?);
                }
                NameConstraints::OID => {
                    raw.name_constraints = Some(ext.parse::<NameConstraints>()?);
                }
                PolicyConstraints::OID => {
                    raw.policy_constraints = Some(ext.parse::<PolicyConstraints>()?);
                }
                InhibitAnyPolicy::OID => {
                    raw.inhibit_any_policy = Some(ext.parse::<InhibitAnyPolicy>()?);
                }
                FreshestCRL::OID => {
                    raw.freshest_crl = Some(ext.parse::<FreshestCRL>()?);
                }
                _ => {
                    // Unknown extension, skip
                }
            }
        }

        Ok(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::str::FromStr;

    // Extensions tests
    #[rstest(
        input,
        // Test case: Extensions with context-specific [3] tag
        case(
            Element::ContextSpecific {
                constructed: true,
            slot: 3,
                element: Box::new(Element::Sequence(vec![
                    Element::Sequence(vec![
                        Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.19").unwrap()),
                        Element::Boolean(true),
                        Element::OctetString(OctetString::from(vec![0x30, 0x00])),
                    ]),
                ])),
            }
        ),
        // Test case: Extensions with direct Sequence (for testing)
        case(
            Element::Sequence(vec![
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.19").unwrap()),
                    Element::OctetString(OctetString::from(vec![0x30, 0x00])),
                ]),
            ])
        ),
        // Test case: Extensions with multiple extensions
        case(
            Element::Sequence(vec![
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.19").unwrap()),
                    Element::Boolean(true),
                    Element::OctetString(OctetString::from(vec![0x30, 0x00])),
                ]),
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.15").unwrap()),
                    Element::OctetString(OctetString::from(vec![0x03, 0x02, 0x05, 0xA0])),
                ]),
            ])
        ),
    )]
    fn test_extensions_decode_success(input: Element) {
        let result: Result<Extensions, _> = input.decode();
        assert!(result.is_ok());
        let extensions = result.unwrap();
        assert!(!extensions.extensions.is_empty());
    }

    #[rstest(
        input,
        expected_error_msg,
        // Test case: Empty Extensions
        case(
            Element::Sequence(vec![]),
            "at least one extension required"
        ),
        // Test case: Wrong context-specific tag
        case(
            Element::ContextSpecific {
                constructed: true,
            slot: 2,
                element: Box::new(Element::Sequence(vec![
                    Element::Sequence(vec![
                        Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.19").unwrap()),
                        Element::OctetString(OctetString::from(vec![0x30, 0x00])),
                    ]),
                ])),
            },
            "expected context-specific tag [3], got [2]"
        ),
        // Test case: Context-specific tag without Sequence
        case(
            Element::ContextSpecific {
                constructed: true,
            slot: 3,
                element: Box::new(Element::Integer(asn1::Integer::from(vec![0x01]))),
            },
            "expected SEQUENCE inside context-specific tag [3]"
        ),
        // Test case: Not a Sequence or ContextSpecific
        case(
            Element::Integer(asn1::Integer::from(vec![0x01])),
            "invalid structure - expected context-specific tag [3] or SEQUENCE"
        ),
    )]
    fn test_extensions_decode_failure(input: Element, expected_error_msg: &str) {
        let result: Result<Extensions, _> = input.decode();
        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_str = format!("{}", err);
        assert!(
            err_str.contains(expected_error_msg),
            "Expected error message containing '{}', but got '{}'",
            expected_error_msg,
            err_str
        );
    }

    // Extension tests
    #[rstest(
        input,
        expected,
        // Test case: Extension with critical=false (default, omitted)
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.19").unwrap()), // basicConstraints
                Element::OctetString(OctetString::from(vec![0x30, 0x00])), // SEQUENCE {}
            ]),
            RawExtension::new(
                ObjectIdentifier::from_str("2.5.29.19").unwrap(),
                false,
                OctetString::from(vec![0x30, 0x00]),
            )
        ),
        // Test case: Extension with critical=true
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.19").unwrap()),
                Element::Boolean(true),
                Element::OctetString(OctetString::from(vec![0x30, 0x03, 0x01, 0x01, 0xFF])),
            ]),
            RawExtension::new(
                ObjectIdentifier::from_str("2.5.29.19").unwrap(),
                true,
                OctetString::from(vec![0x30, 0x03, 0x01, 0x01, 0xFF]),
            )
        ),
        // Test case: Extension with critical=false (explicit)
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.15").unwrap()), // keyUsage
                Element::Boolean(false),
                Element::OctetString(OctetString::from(vec![0x03, 0x02, 0x05, 0xA0])),
            ]),
            RawExtension::new(
                ObjectIdentifier::from_str("2.5.29.15").unwrap(),
                false,
                OctetString::from(vec![0x03, 0x02, 0x05, 0xA0]),
            )
        ),
    )]
    fn test_extension_decode_success(input: Element, expected: RawExtension) {
        let result: Result<RawExtension, Error> = input.decode().map_err(Error::from);
        assert!(result.is_ok());
        let extension = result.unwrap();
        assert_eq!(extension, expected);
    }

    #[rstest(
        input,
        expected_error_msg,
        // Test case: Not a Sequence
        case(
            Element::Integer(asn1::Integer::from(vec![0x01])),
            "Extension: expected SEQUENCE"
        ),
        // Test case: Empty sequence
        case(
            Element::Sequence(vec![]),
            "expected 2 or 3 elements, got 0"
        ),
        // Test case: Only one element
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.19").unwrap()),
            ]),
            "expected 2 or 3 elements, got 1"
        ),
        // Test case: Too many elements
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.19").unwrap()),
                Element::Boolean(true),
                Element::OctetString(OctetString::from(vec![0x30, 0x00])),
                Element::Null,
            ]),
            "expected 2 or 3 elements, got 4"
        ),
        // Test case: First element is not OID
        case(
            Element::Sequence(vec![
                Element::Integer(asn1::Integer::from(vec![0x01])),
                Element::OctetString(OctetString::from(vec![0x30, 0x00])),
            ]),
            "expected OBJECT IDENTIFIER for extnID"
        ),
        // Test case: Second element (critical) is not Boolean when 3 elements
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.19").unwrap()),
                Element::Integer(asn1::Integer::from(vec![0x01])),
                Element::OctetString(OctetString::from(vec![0x30, 0x00])),
            ]),
            "expected BOOLEAN for critical or OCTET STRING for extnValue"
        ),
        // Test case: extnValue is not OctetString (2 elements)
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.19").unwrap()),
                Element::Integer(asn1::Integer::from(vec![0x01])),
            ]),
            "expected BOOLEAN for critical or OCTET STRING for extnValue"
        ),
    )]
    fn test_extension_decode_failure(input: Element, expected_error_msg: &str) {
        let result: Result<RawExtension, Error> = input.decode().map_err(Error::from);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_str = format!("{}", err);
        assert!(
            err_str.contains(expected_error_msg),
            "Expected error message containing '{}', but got '{}'",
            expected_error_msg,
            err_str
        );
    }
}
