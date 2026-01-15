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

use asn1::{Element, ObjectIdentifier, OctetString};
use serde::{Deserialize, Serialize};
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};

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

                Ok(Extension::new(id, critical, value))
            }
            _ => Err(Error::InvalidExtension(
                "expected Sequence for Extension".to_string(),
            )),
        }
    }
}

// Encoder implementation for Extension
impl EncodableTo<Extension> for Element {}

impl Encoder<Extension, Element> for Extension {
    type Error = Error;

    fn encode(&self) -> Result<Element> {
        let mut elements = vec![Element::ObjectIdentifier(self.oid().clone())];

        // Only include critical field if it's true (since DEFAULT FALSE)
        if self.is_critical() {
            elements.push(Element::Boolean(true));
        }

        elements.push(Element::OctetString(self.value().clone()));

        Ok(Element::Sequence(elements))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asn1::ObjectIdentifier;
    use std::str::FromStr;
    use tsumiki::decoder::Decoder;
    use tsumiki::encoder::Encoder;

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
        match &element {
            Element::Sequence(elements) => {
                assert_eq!(elements.len(), 3);
                assert!(matches!(&elements[0], Element::ObjectIdentifier(_)));
                assert_eq!(&elements[1], &Element::Boolean(true));
                assert!(matches!(&elements[2], Element::OctetString(_)));
            }
            _ => panic!("expected Sequence"),
        }
    }

    #[test]
    fn test_extension_encode_non_critical() {
        let oid = ObjectIdentifier::from_str("2.5.29.17").unwrap();
        let value = OctetString::from(vec![0x30, 0x00]);
        let ext = Extension::new(oid, false, value);

        let element = ext.encode().unwrap();
        match &element {
            Element::Sequence(elements) => {
                // critical field should be omitted when false (DEFAULT FALSE)
                assert_eq!(elements.len(), 2);
                assert!(matches!(&elements[0], Element::ObjectIdentifier(_)));
                assert!(matches!(&elements[1], Element::OctetString(_)));
            }
            _ => panic!("expected Sequence"),
        }
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
