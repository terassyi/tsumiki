//! PKIX Extension type
//!
//! RFC 5280 Section 4.1.2.9
//!
//! ```asn1
//! Extension  ::=  SEQUENCE  {
//!     extnID      OBJECT IDENTIFIER,
//!     critical    BOOLEAN DEFAULT FALSE,
//!     extnValue   OCTET STRING
//!                 -- contains the DER encoding of an ASN.1 value
//!                 -- corresponding to the extension type identified
//!                 -- by extnID
//! }
//! ```
//!
//! This module provides the Extension struct definition and basic Decoder/Encoder
//! implementations. Each crate (x509 and pkcs) may use these implementations
//! or provide their own specific encoding/decoding logic.

use serde::{Deserialize, Serialize};
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};
use tsumiki_asn1::{Element, ObjectIdentifier, OctetString};

use crate::error::{Error, Result};

/// Extension represents a single X.509 extension
///
/// RFC 5280: Extension ::= SEQUENCE { extnID, critical, extnValue }
///
/// Note: This is just the data structure. Decoder/Encoder implementations
/// are provided by each crate (x509, pkcs) according to their needs:
/// - x509: May need special handling for certificate extensions
/// - pkcs: Used in extensionRequest attribute with plain SEQUENCE encoding
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Extension {
    pub(crate) id: ObjectIdentifier,
    pub(crate) critical: bool,
    pub(crate) value: OctetString,
}

impl Extension {
    /// Create a new Extension
    pub fn new(id: ObjectIdentifier, critical: bool, value: OctetString) -> Self {
        Self {
            id,
            critical,
            value,
        }
    }

    /// Get the extension ID (OID)
    pub fn oid(&self) -> &ObjectIdentifier {
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
}

// Decoder implementation for Extension
impl DecodableFrom<Element> for Extension {}

impl Decoder<Element, Extension> for Element {
    type Error = Error;

    fn decode(&self) -> Result<Extension> {
        let Element::Sequence(elements) = self else {
            return Err(Error::ExtensionExpectedSequence);
        };

        // Extension ::= SEQUENCE {
        //     extnID      OBJECT IDENTIFIER,
        //     critical    BOOLEAN DEFAULT FALSE,
        //     extnValue   OCTET STRING
        // }
        // Validate element count first
        if elements.len() < 2 || elements.len() > 3 {
            return Err(Error::ExtensionInvalidElementCount(elements.len()));
        }

        let (id, critical, value) = match elements.as_slice() {
            // With critical flag
            [
                Element::ObjectIdentifier(oid),
                Element::Boolean(crit),
                Element::OctetString(octets),
            ] => (oid.clone(), *crit, octets.clone()),
            // Without critical flag (defaults to FALSE)
            [Element::ObjectIdentifier(oid), Element::OctetString(octets)] => {
                (oid.clone(), false, octets.clone())
            }
            // Wrong type for extnValue
            [Element::ObjectIdentifier(_), Element::Boolean(_), _] => {
                return Err(Error::ExtensionExpectedOctetString);
            }
            // Wrong type for critical or extnValue
            [Element::ObjectIdentifier(_), _] | [Element::ObjectIdentifier(_), _, _] => {
                return Err(Error::ExtensionInvalidCriticalOrValue);
            }
            // Wrong type for extnID
            _ => {
                return Err(Error::ExtensionExpectedOidForExtnId);
            }
        };

        Ok(Extension::new(id, critical, value))
    }
}

// Encoder implementation for Extension
impl EncodableTo<Extension> for Element {}

impl Encoder<Extension, Element> for Extension {
    type Error = Error;

    fn encode(&self) -> Result<Element> {
        // Only include critical field if it's true (since DEFAULT FALSE)
        let critical_elem = self.is_critical().then_some(Element::Boolean(true));

        let elements: Vec<_> = std::iter::once(Element::ObjectIdentifier(self.oid().clone()))
            .chain(critical_elem)
            .chain(std::iter::once(Element::OctetString(self.value().clone())))
            .collect();

        Ok(Element::Sequence(elements))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use tsumiki::decoder::Decoder;
    use tsumiki::encoder::Encoder;
    use tsumiki_asn1::ObjectIdentifier;

    #[test]
    fn test_extension_new() {
        let oid = ObjectIdentifier::from_str("2.5.29.15").unwrap();
        let value = OctetString::from(vec![0x03, 0x02, 0x05, 0x20]);
        let ext = Extension::new(oid.clone(), true, value.clone());

        assert_eq!(ext.oid(), &oid);
        assert!(ext.is_critical());
        assert_eq!(ext.value(), &value);
    }

    #[test]
    fn test_extension_non_critical() {
        let oid = ObjectIdentifier::from_str("2.5.29.17").unwrap();
        let value = OctetString::from(vec![0x30, 0x00]);
        let ext = Extension::new(oid, false, value);

        assert!(!ext.is_critical());
    }

    #[test]
    fn test_extension_encode_critical() {
        let oid = ObjectIdentifier::from_str("2.5.29.15").unwrap();
        let value = OctetString::from(vec![0x03, 0x02, 0x05, 0x20]);
        let ext = Extension::new(oid.clone(), true, value.clone());

        let element = ext.encode().unwrap();
        let Element::Sequence(elements) = &element else {
            panic!("expected Sequence");
        };
        let [oid_elem, critical_elem, value_elem] = elements.as_slice() else {
            panic!("expected 3 elements, got {}", elements.len());
        };
        assert!(matches!(oid_elem, Element::ObjectIdentifier(_)));
        assert_eq!(critical_elem, &Element::Boolean(true));
        assert!(matches!(value_elem, Element::OctetString(_)));
    }

    #[test]
    fn test_extension_encode_non_critical() {
        let oid = ObjectIdentifier::from_str("2.5.29.17").unwrap();
        let value = OctetString::from(vec![0x30, 0x00]);
        let ext = Extension::new(oid, false, value);

        let element = ext.encode().unwrap();
        // critical field should be omitted when false (DEFAULT FALSE)
        let Element::Sequence(elements) = &element else {
            panic!("expected Sequence");
        };
        let [oid_elem, value_elem] = elements.as_slice() else {
            panic!("expected 2 elements, got {}", elements.len());
        };
        assert!(matches!(oid_elem, Element::ObjectIdentifier(_)));
        assert!(matches!(value_elem, Element::OctetString(_)));
    }

    #[test]
    fn test_extension_decode_critical() {
        let oid = ObjectIdentifier::from_str("2.5.29.15").unwrap();
        let value = OctetString::from(vec![0x03, 0x02, 0x05, 0x20]);

        let element = Element::Sequence(vec![
            Element::ObjectIdentifier(oid.clone()),
            Element::Boolean(true),
            Element::OctetString(value.clone()),
        ]);

        let ext: Extension = element.decode().unwrap();
        assert_eq!(ext.oid(), &oid);
        assert!(ext.is_critical());
        assert_eq!(ext.value(), &value);
    }

    #[test]
    fn test_extension_decode_non_critical() {
        let oid = ObjectIdentifier::from_str("2.5.29.17").unwrap();
        let value = OctetString::from(vec![0x30, 0x00]);

        let element = Element::Sequence(vec![
            Element::ObjectIdentifier(oid.clone()),
            Element::OctetString(value.clone()),
        ]);

        let ext: Extension = element.decode().unwrap();
        assert_eq!(ext.oid(), &oid);
        assert!(!ext.is_critical()); // DEFAULT FALSE
        assert_eq!(ext.value(), &value);
    }

    #[test]
    fn test_extension_roundtrip() {
        let oid = ObjectIdentifier::from_str("2.5.29.19").unwrap();
        let value = OctetString::from(vec![0x30, 0x03, 0x01, 0x01, 0xff]);
        let ext = Extension::new(oid, true, value);

        let element = ext.encode().unwrap();
        let decoded: Extension = element.decode().unwrap();

        assert_eq!(ext, decoded);
    }
}
