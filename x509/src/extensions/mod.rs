use std::str::FromStr;

use asn1::{Element, ObjectIdentifier, OctetString};
use serde::{Deserialize, Serialize};
use tsumiki::decoder::{DecodableFrom, Decoder};

use crate::error::Error;

// Submodules
mod authority_info_access;
mod authority_key_identifier;
mod basic_constraints;
mod certificate_policies;
mod crl_distribution_points;
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

/// Extensions is a sequence of Extension
/// RFC 5280: Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
///
/// Note: In TBSCertificate, this appears as:
/// - extensions [3] EXPLICIT Extensions OPTIONAL
/// - Element::ContextSpecific { slot: 3, element: Box<Element::Sequence> }
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Extensions {
    extensions: Vec<Extension>,
}

impl Extensions {
    pub fn extensions(&self) -> &Vec<Extension> {
        &self.extensions
    }
}

impl DecodableFrom<Element> for Extensions {}

impl Decoder<Element, Extensions> for Element {
    type Error = Error;

    fn decode(&self) -> Result<Extensions, Self::Error> {
        match self {
            Element::ContextSpecific { slot, element } => {
                if *slot != 3 {
                    return Err(Error::InvalidExtensions(format!(
                        "expected context-specific tag [3], got [{}]",
                        slot
                    )));
                }
                // EXPLICIT tagging: element contains the full SEQUENCE
                match element.as_ref() {
                    Element::Sequence(seq_elements) => {
                        if seq_elements.is_empty() {
                            return Err(Error::InvalidExtensions(
                                "Extensions must contain at least one Extension".to_string(),
                            ));
                        }
                        let mut extensions = Vec::new();
                        for elem in seq_elements {
                            let extension: Extension = elem.decode()?;
                            extensions.push(extension);
                        }
                        Ok(Extensions { extensions })
                    }
                    _ => Err(Error::InvalidExtensions(
                        "expected Sequence inside context-specific tag [3]".to_string(),
                    )),
                }
            }
            Element::Sequence(seq_elements) => {
                // Allow direct Sequence for testing
                if seq_elements.is_empty() {
                    return Err(Error::InvalidExtensions(
                        "Extensions must contain at least one Extension".to_string(),
                    ));
                }
                let mut extensions = Vec::new();
                for elem in seq_elements {
                    let extension: Extension = elem.decode()?;
                    extensions.push(extension);
                }
                Ok(Extensions { extensions })
            }
            _ => Err(Error::InvalidExtensions(
                "expected context-specific tag [3] or Sequence for Extensions".to_string(),
            )),
        }
    }
}

/// Extension represents a single X.509 extension
/// RFC 5280: Extension ::= SEQUENCE { extnID, critical, extnValue }
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Extension {
    id: ObjectIdentifier,
    critical: bool,
    value: OctetString,
}

impl Extension {
    /// Get the extension ID (OID)
    pub fn id(&self) -> &ObjectIdentifier {
        &self.id
    }

    /// Check if the extension is critical
    pub fn is_critical(&self) -> bool {
        self.critical
    }

    /// Get the raw extension value (DER-encoded ASN.1)
    pub fn value(&self) -> &OctetString {
        &self.value
    }

    /// Parse the extension value as a specific standard extension type
    pub fn parse<T: StandardExtension>(&self) -> Result<T, Error> {
        // Verify OID matches
        if self.id.to_string() != T::OID {
            return Err(Error::InvalidExtension(format!(
                "OID mismatch: expected {}, got {}",
                T::OID,
                self.id.to_string()
            )));
        }
        T::parse(&self.value)
    }
}

impl DecodableFrom<Element> for Extension {}

impl Decoder<Element, Extension> for Element {
    type Error = Error;

    fn decode(&self) -> Result<Extension, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                if elements.len() < 2 || elements.len() > 3 {
                    return Err(Error::InvalidExtension(format!(
                        "expected 2 or 3 elements in Extension sequence, got {}",
                        elements.len()
                    )));
                }

                // First element: extnID (OBJECT IDENTIFIER)
                let id = if let Element::ObjectIdentifier(oid) = &elements[0] {
                    oid.clone()
                } else {
                    return Err(Error::InvalidExtension(
                        "expected ObjectIdentifier for extnID".to_string(),
                    ));
                };

                // Second and third elements: critical (BOOLEAN) and extnValue (OCTET STRING)
                // critical has DEFAULT FALSE, so it may be omitted
                let (critical, extn_value_element) = if elements.len() == 3 {
                    // critical is present
                    let crit = if let Element::Boolean(b) = &elements[1] {
                        *b
                    } else {
                        return Err(Error::InvalidExtension(
                            "expected Boolean for critical".to_string(),
                        ));
                    };
                    (crit, &elements[2])
                } else {
                    // critical is omitted, defaults to FALSE
                    (false, &elements[1])
                };

                // extnValue (OCTET STRING)
                let value = if let Element::OctetString(octets) = extn_value_element {
                    octets.clone()
                } else {
                    return Err(Error::InvalidExtension(
                        "expected OctetString for extnValue".to_string(),
                    ));
                };

                Ok(Extension {
                    id,
                    critical,
                    value,
                })
            }
            _ => Err(Error::InvalidExtension(
                "expected Sequence for Extension".to_string(),
            )),
        }
    }
}

/// Trait for standard X.509 extensions that can be parsed from Extension.value
pub trait StandardExtension: Sized {
    const OID: &'static str;

    fn oid() -> Result<ObjectIdentifier, Error> {
        ObjectIdentifier::from_str(Self::OID).map_err(|e| {
            Error::InvalidExtension(format!("failed to parse OID {}: {}", Self::OID, e))
        })
    }
    /// Parse the extension value (DER-encoded ASN.1 in OctetString)
    fn parse(value: &OctetString) -> Result<Self, Error>;
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
        let result: Result<Extensions, Error> = input.decode();
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
            "Extensions must contain at least one Extension"
        ),
        // Test case: Wrong context-specific tag
        case(
            Element::ContextSpecific {
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
                slot: 3,
                element: Box::new(Element::Integer(asn1::Integer::from(vec![0x01]))),
            },
            "expected Sequence inside context-specific tag [3]"
        ),
        // Test case: Not a Sequence or ContextSpecific
        case(
            Element::Integer(asn1::Integer::from(vec![0x01])),
            "expected context-specific tag [3] or Sequence for Extensions"
        ),
    )]
    fn test_extensions_decode_failure(input: Element, expected_error_msg: &str) {
        let result: Result<Extensions, Error> = input.decode();
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
            Extension {
                id: ObjectIdentifier::from_str("2.5.29.19").unwrap(),
                critical: false,
                value: OctetString::from(vec![0x30, 0x00]),
            }
        ),
        // Test case: Extension with critical=true
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.19").unwrap()),
                Element::Boolean(true),
                Element::OctetString(OctetString::from(vec![0x30, 0x03, 0x01, 0x01, 0xFF])),
            ]),
            Extension {
                id: ObjectIdentifier::from_str("2.5.29.19").unwrap(),
                critical: true,
                value: OctetString::from(vec![0x30, 0x03, 0x01, 0x01, 0xFF]),
            }
        ),
        // Test case: Extension with critical=false (explicit)
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.15").unwrap()), // keyUsage
                Element::Boolean(false),
                Element::OctetString(OctetString::from(vec![0x03, 0x02, 0x05, 0xA0])),
            ]),
            Extension {
                id: ObjectIdentifier::from_str("2.5.29.15").unwrap(),
                critical: false,
                value: OctetString::from(vec![0x03, 0x02, 0x05, 0xA0]),
            }
        ),
    )]
    fn test_extension_decode_success(input: Element, expected: Extension) {
        let result: Result<Extension, Error> = input.decode();
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
            "expected Sequence for Extension"
        ),
        // Test case: Empty sequence
        case(
            Element::Sequence(vec![]),
            "expected 2 or 3 elements in Extension sequence, got 0"
        ),
        // Test case: Only one element
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.19").unwrap()),
            ]),
            "expected 2 or 3 elements in Extension sequence, got 1"
        ),
        // Test case: Too many elements
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.19").unwrap()),
                Element::Boolean(true),
                Element::OctetString(OctetString::from(vec![0x30, 0x00])),
                Element::Null,
            ]),
            "expected 2 or 3 elements in Extension sequence, got 4"
        ),
        // Test case: First element is not OID
        case(
            Element::Sequence(vec![
                Element::Integer(asn1::Integer::from(vec![0x01])),
                Element::OctetString(OctetString::from(vec![0x30, 0x00])),
            ]),
            "expected ObjectIdentifier for extnID"
        ),
        // Test case: Second element (critical) is not Boolean when 3 elements
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.19").unwrap()),
                Element::Integer(asn1::Integer::from(vec![0x01])),
                Element::OctetString(OctetString::from(vec![0x30, 0x00])),
            ]),
            "expected Boolean for critical"
        ),
        // Test case: extnValue is not OctetString
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.19").unwrap()),
                Element::Integer(asn1::Integer::from(vec![0x01])),
            ]),
            "expected OctetString for extnValue"
        ),
    )]
    fn test_extension_decode_failure(input: Element, expected_error_msg: &str) {
        let result: Result<Extension, Error> = input.decode();
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
