use std::str::FromStr;

use serde::Deserialize;
use serde::Serialize;
use tsumiki::decoder::DecodableFrom;
use tsumiki::decoder::Decoder;
use tsumiki::encoder::EncodableTo;
use tsumiki::encoder::Encoder;
use tsumiki_asn1::Element;
use tsumiki_asn1::ObjectIdentifier;
use tsumiki_asn1::OctetString;

use crate::error::Error;

// Shared submodules: the extension machinery plus types/extensions reused by
// both certificates and CRLs.
mod authority_key_identifier;
mod crl_distribution_points;
pub mod error;
mod freshest_crl;
pub(crate) mod general_name;
mod issuer_alt_name;

// Re-export public types
pub use authority_key_identifier::AuthorityKeyIdentifier;
pub use crl_distribution_points::{
    CRLDistributionPoints, DistributionPoint, DistributionPointName, ReasonFlags,
};
pub use freshest_crl::FreshestCRL;
pub use general_name::{EdiPartyName, GeneralName, IpAddressOrRange, OtherName};
pub use issuer_alt_name::IssuerAltName;
use tsumiki_asn1::AsOid;

/// Raw X.509 extension before type-specific parsing.
///
/// Wraps a generic extension (OID, critical flag, and DER-encoded value)
/// and provides methods to parse it into specific extension types.
///
/// This is an intermediate representation used internally by the certificate
/// parser. Most users should use the typed extension structs directly via
/// `Certificate::extension::<T>()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RawExtension(tsumiki_pkix_types::Extension);

impl RawExtension {
    /// Create a new RawExtension (for testing purposes)
    #[cfg(test)]
    pub(crate) fn new(oid: ObjectIdentifier, critical: bool, value: OctetString) -> Self {
        Self(tsumiki_pkix_types::Extension::new(oid, critical, value))
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
}

impl From<tsumiki_pkix_types::Extension> for RawExtension {
    fn from(ext: tsumiki_pkix_types::Extension) -> Self {
        Self(ext)
    }
}

impl From<RawExtension> for tsumiki_pkix_types::Extension {
    fn from(ext: RawExtension) -> Self {
        ext.0
    }
}

impl AsRef<tsumiki_pkix_types::Extension> for RawExtension {
    fn as_ref(&self) -> &tsumiki_pkix_types::Extension {
        &self.0
    }
}

impl std::ops::Deref for RawExtension {
    type Target = tsumiki_pkix_types::Extension;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// Implement marker traits
impl DecodableFrom<Element> for RawExtension {}
impl EncodableTo<RawExtension> for Element {}

// Implement Decoder for Element -> RawExtension
impl Decoder<Element, RawExtension> for Element {
    type Error = tsumiki_pkix_types::Error;

    fn decode(&self) -> Result<RawExtension, Self::Error> {
        let ext: tsumiki_pkix_types::Extension = self.decode()?;
        Ok(RawExtension(ext))
    }
}

// Implement Encoder for RawExtension -> Element
impl Encoder<RawExtension, Element> for RawExtension {
    type Error = tsumiki_pkix_types::Error;

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

/// Collection of X.509 v3 extensions ([RFC 5280 Section 4.1.2.9](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.9)).
///
/// Extensions provide additional information and constraints for certificate
/// usage, validation, and processing. Each extension has an OID, a critical flag,
/// and a DER-encoded value.
///
/// # Critical vs Non-Critical
/// - Critical extensions MUST be processed and understood by the certificate user
/// - Non-critical extensions MAY be ignored if not understood
///
/// # ASN.1 Structure
/// ```text
/// Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
/// ```
///
/// In TBSCertificate, this appears as \[3\] EXPLICIT Extensions OPTIONAL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Extensions {
    pub(crate) extensions: Vec<RawExtension>,
    pub(crate) tag: Option<u8>,
}

impl Extensions {
    /// Get the raw extensions
    pub fn extensions(&self) -> &Vec<RawExtension> {
        &self.extensions
    }

    /// Get a specific extension by OID
    fn get_by_oid<O: AsOid>(&self, oid: O) -> Result<Option<&RawExtension>, Error> {
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
                        Ok(Extensions {
                            extensions,
                            tag: Some(*slot),
                        })
                    }
                    _ => Err(Error::ExpectedSequenceInExtensions),
                }
            }
            Element::Sequence(seq_elements) => {
                // Bare SEQUENCE (e.g., CRL RevokedCertificate.crlEntryExtensions, RFC 5280 §5.3)
                if seq_elements.is_empty() {
                    return Err(Error::ExtensionsEmpty);
                }
                let extensions = seq_elements
                    .iter()
                    .map(|elem| elem.decode().map_err(Error::from))
                    .collect::<Result<Vec<RawExtension>, Error>>()?;
                Ok(Extensions {
                    extensions,
                    tag: None,
                })
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

        match self.tag {
            Some(slot) => Ok(Element::ContextSpecific {
                constructed: true,
                slot,
                element: Box::new(Element::Sequence(extension_elements?)),
            }),
            None => extension_elements.map(Element::Sequence),
        }
    }
}

/// Trait for typed X.509 extensions.
///
/// Implementors of this trait represent specific X.509 extensions
/// and can be parsed from the raw extension value (DER-encoded ASN.1).
///
/// # Example
/// ```no_run
/// use std::str::FromStr;
/// use tsumiki_x509::Certificate;
/// use tsumiki_x509::extensions::{Extension, BasicConstraints};
///
/// let cert = Certificate::from_str("-----BEGIN CERTIFICATE-----...").unwrap();
/// // Parse extension from certificate
/// if let Some(bc) = cert.extension::<BasicConstraints>().unwrap() {
///     println!("CA: {}, PathLen: {:?}", bc.ca, bc.path_len_constraint);
/// }
/// ```
pub trait Extension: Sized {
    /// The OID of this extension type as a string (e.g., "2.5.29.19" for BasicConstraints)
    const OID: &'static str;

    /// Get the OID as an ObjectIdentifier.
    ///
    /// # Errors
    /// Returns an error if the OID string is invalid.
    fn oid() -> Result<ObjectIdentifier, Error> {
        ObjectIdentifier::from_str(Self::OID).map_err(|e| Error::InvalidOidString {
            oid: Self::OID.to_string(),
            message: e.to_string(),
        })
    }

    /// Parse the extension from its DER-encoded value.
    ///
    /// The value is the content of the extension's OCTET STRING,
    /// which itself contains DER-encoded ASN.1 data specific to
    /// the extension type.
    ///
    /// # Errors
    /// Returns an error if the extension value is malformed or
    /// cannot be parsed according to the extension's schema.
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
        // Test case: Extensions with context-specific [0] tag
        // (CRL TBSCertList.crlExtensions, RFC 5280 §5.1.2.7)
        case(
            Element::ContextSpecific {
                constructed: true,
                slot: 0,
                element: Box::new(Element::Sequence(vec![
                    Element::Sequence(vec![
                        Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.20").unwrap()), // cRLNumber
                        Element::OctetString(OctetString::from(vec![0x02, 0x01, 0x01])),
                    ]),
                ])),
            }
        ),
        // Test case: Extensions with context-specific [1] tag
        // (slot-agnostic decoder accepts any slot; caller asserts the expected slot)
        case(
            Element::ContextSpecific {
                constructed: true,
                slot: 1,
                element: Box::new(Element::Sequence(vec![
                    Element::Sequence(vec![
                        Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.19").unwrap()),
                        Element::OctetString(OctetString::from(vec![0x30, 0x00])),
                    ]),
                ])),
            }
        ),
        // Test case: Extensions with context-specific [2] tag
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
            }
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
        // Test case: Context-specific tag without Sequence inside
        // (slot does not matter; the inner element must be SEQUENCE)
        case(
            Element::ContextSpecific {
                constructed: true,
            slot: 3,
                element: Box::new(Element::Integer(tsumiki_asn1::Integer::from(vec![0x01]))),
            },
            "expected SEQUENCE"
        ),
        // Test case: Not a Sequence or ContextSpecific
        case(
            Element::Integer(tsumiki_asn1::Integer::from(vec![0x01])),
            "invalid structure"
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
            Element::Integer(tsumiki_asn1::Integer::from(vec![0x01])),
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
                Element::Integer(tsumiki_asn1::Integer::from(vec![0x01])),
                Element::OctetString(OctetString::from(vec![0x30, 0x00])),
            ]),
            "expected OBJECT IDENTIFIER for extnID"
        ),
        // Test case: Second element (critical) is not Boolean when 3 elements
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.19").unwrap()),
                Element::Integer(tsumiki_asn1::Integer::from(vec![0x01])),
                Element::OctetString(OctetString::from(vec![0x30, 0x00])),
            ]),
            "expected BOOLEAN for critical or OCTET STRING for extnValue"
        ),
        // Test case: extnValue is not OctetString (2 elements)
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.19").unwrap()),
                Element::Integer(tsumiki_asn1::Integer::from(vec![0x01])),
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
