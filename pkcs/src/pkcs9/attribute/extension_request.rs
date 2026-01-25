//! PKCS#9 extensionRequest attribute (OID: 1.2.840.113549.1.9.14)
//!
//! Defined in RFC 2985 Section 5.4.2
//!
//! ```asn1
//! extensionRequest ATTRIBUTE ::= {
//!     WITH SYNTAX ExtensionRequest
//!     SINGLE VALUE TRUE
//!     ID pkcs-9-at-extensionRequest
//! }
//!
//! ExtensionRequest ::= Extensions
//! Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
//! ```
//!
//! The extensionRequest attribute is used in PKCS#10 certification requests
//! to request X.509 v3 extensions that should be included in the certificate.
//! This allows the certificate requester to specify which extensions they want,
//! such as Subject Alternative Names, Key Usage, Extended Key Usage, etc.

use asn1::{ASN1Object, Element, OctetString};
use pkix_types::Extension;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};

use crate::pkcs9::error::{Error, Result};

use super::Attribute;

/// extensionRequest attribute
///
/// Contains a sequence of X.509 v3 extensions that the certificate
/// requester wishes to be included in the certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionRequest {
    /// X.509 v3 extensions
    extensions: Vec<Extension>,
}

impl ExtensionRequest {
    /// Create a new ExtensionRequest from a vector of extensions
    pub fn new(extensions: Vec<Extension>) -> Result<Self> {
        if extensions.is_empty() {
            return Err(Error::EmptyValue("extensionRequest".into()));
        }
        Ok(Self { extensions })
    }

    /// Get the extensions
    pub fn extensions(&self) -> &[Extension] {
        &self.extensions
    }
}

// Decoder implementation for ExtensionRequest
// ExtensionRequest is encoded as a plain SEQUENCE OF Extension (no [3] EXPLICIT wrapper)
impl DecodableFrom<Element> for ExtensionRequest {}

impl Decoder<Element, ExtensionRequest> for Element {
    type Error = Error;

    fn decode(&self) -> Result<ExtensionRequest> {
        match self {
            Element::Sequence(seq_elements) => {
                if seq_elements.is_empty() {
                    return Err(Error::ExtensionRequestInvalidValueCount(0));
                }

                let extensions = seq_elements
                    .iter()
                    .map(|elem| elem.decode())
                    .collect::<std::result::Result<Vec<_>, _>>()?;

                Ok(ExtensionRequest { extensions })
            }
            _ => Err(Error::ExtensionRequestExpectedSequence),
        }
    }
}

// Encoder implementation for ExtensionRequest
impl EncodableTo<ExtensionRequest> for Element {}

impl Encoder<ExtensionRequest, Element> for ExtensionRequest {
    type Error = Error;

    fn encode(&self) -> Result<Element> {
        if self.extensions.is_empty() {
            return Err(Error::EmptyValue("ExtensionRequest".to_string()));
        }

        let extension_elements: std::result::Result<Vec<Element>, _> =
            self.extensions.iter().map(|ext| ext.encode()).collect();

        Ok(Element::Sequence(extension_elements?))
    }
}

impl Serialize for ExtensionRequest {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(self.extensions.len()))?;
        for ext in &self.extensions {
            seq.serialize_element(ext)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for ExtensionRequest {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ExtensionRequestVisitor;

        impl<'de> de::Visitor<'de> for ExtensionRequestVisitor {
            type Value = ExtensionRequest;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a sequence of Extension")
            }

            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<ExtensionRequest, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut extensions = Vec::new();
                while let Some(ext) = seq.next_element()? {
                    extensions.push(ext);
                }
                ExtensionRequest::new(extensions).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_seq(ExtensionRequestVisitor)
    }
}

impl Attribute for ExtensionRequest {
    const OID: &'static str = "1.2.840.113549.1.9.14";

    fn parse(data: &OctetString) -> Result<Self> {
        // Parse the SET OF values
        let asn1_obj = ASN1Object::try_from(data).map_err(Error::from)?;
        let elements = asn1_obj.elements();

        if elements.is_empty() {
            return Err(Error::AttributeEmptyAsn1Object("extensionRequest"));
        }

        // The first element should be a SET
        let Element::Set(set) = &elements[0] else {
            return Err(Error::AttributeExpectedElementType {
                attr: "extensionRequest",
                expected: "SET",
            });
        };

        if set.len() != 1 {
            return Err(Error::ExtensionRequestInvalidValueCount(set.len()));
        }

        // The value should be a SEQUENCE (Extensions)
        let Element::Sequence(_) = &set[0] else {
            return Err(Error::ExtensionRequestExpectedSequence);
        };

        // Decode the Extensions SEQUENCE into ExtensionRequest
        set[0].decode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asn1::ObjectIdentifier;
    use rstest::rstest;
    use std::str::FromStr;
    use tsumiki::decoder::Decoder;
    use tsumiki::encoder::Encoder;

    fn create_basic_extension() -> Extension {
        // Create a simple Extension: basicConstraints with CA:TRUE
        let bc_oid = ObjectIdentifier::from_str("2.5.29.19").unwrap(); // basicConstraints

        // BasicConstraints ::= SEQUENCE { cA BOOLEAN }
        let bc_value_seq = Element::Sequence(vec![Element::Boolean(true)]);
        let bc_value_asn1 = ASN1Object::new(vec![bc_value_seq]);
        let bc_value_der = bc_value_asn1.encode().unwrap();
        let bc_value_bytes = bc_value_der.encode().unwrap();
        let bc_value = OctetString::from(bc_value_bytes);

        Extension::new(bc_oid, true, bc_value)
    }

    fn create_key_usage_extension() -> Extension {
        // Create KeyUsage extension
        let ku_oid = ObjectIdentifier::from_str("2.5.29.15").unwrap();
        // KeyUsage ::= BIT STRING { digitalSignature, keyEncipherment }
        let ku_value = OctetString::from(vec![0x03, 0x02, 0x05, 0xA0]);
        Extension::new(ku_oid, false, ku_value)
    }

    #[test]
    fn test_extension_request_new() {
        let extension = create_basic_extension();
        let ext_req = ExtensionRequest::new(vec![extension.clone()]).unwrap();
        assert_eq!(ext_req.extensions().len(), 1);
        assert_eq!(&ext_req.extensions()[0], &extension);
    }

    #[test]
    fn test_extension_request_empty() {
        let result = ExtensionRequest::new(vec![]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::EmptyValue(_)));
    }

    #[test]
    fn test_extension_request_encode() {
        let extension = create_basic_extension();
        let ext_req = ExtensionRequest::new(vec![extension]).unwrap();

        let elem = ext_req.encode().unwrap();
        assert!(matches!(elem, Element::Sequence(_)));
    }

    #[test]
    fn test_extension_request_decode() {
        // Create Extensions SEQUENCE
        let extension1 = create_basic_extension();
        let extension2 = create_key_usage_extension();

        let ext1_elem = extension1.encode().unwrap();
        let ext2_elem = extension2.encode().unwrap();

        let extensions_elem = Element::Sequence(vec![ext1_elem, ext2_elem]);

        let ext_req: ExtensionRequest = extensions_elem.decode().unwrap();
        assert_eq!(ext_req.extensions().len(), 2);
    }

    #[test]
    fn test_extension_request_roundtrip() {
        let extension1 = create_basic_extension();
        let extension2 = create_key_usage_extension();
        let ext_req = ExtensionRequest::new(vec![extension1, extension2]).unwrap();

        let elem = ext_req.encode().unwrap();
        let decoded: ExtensionRequest = elem.decode().unwrap();

        assert_eq!(ext_req, decoded);
    }

    #[test]
    fn test_extension_request_parse() {
        // Create Extensions SEQUENCE with one extension
        let extension = create_basic_extension();
        let ext_elem = extension.encode().unwrap();
        let extensions_elem = Element::Sequence(vec![ext_elem]);

        // Wrap in SET
        let set = Element::Set(vec![extensions_elem]);
        let asn1_obj = ASN1Object::new(vec![set]);
        let set_der = asn1_obj.encode().unwrap();
        let set_der_bytes = set_der.encode().unwrap();
        let octet_string = OctetString::from(set_der_bytes);

        // Parse as ExtensionRequest
        let ext_req = ExtensionRequest::parse(&octet_string).unwrap();
        assert_eq!(ext_req.extensions().len(), 1);
    }

    #[test]
    fn test_extension_request_serde() {
        let extension = create_basic_extension();
        let ext_req = ExtensionRequest::new(vec![extension]).unwrap();

        // Serialize to JSON
        let json = serde_json::to_string(&ext_req).unwrap();

        // Deserialize from JSON
        let deserialized: ExtensionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(ext_req, deserialized);
    }

    #[rstest]
    #[case(1)] // Single extension
    #[case(2)] // Two extensions
    #[case(3)] // Three extensions
    fn test_extension_request_multiple_extensions(#[case] count: usize) {
        let extensions: Vec<_> = (0..count)
            .map(|i| {
                let oid = ObjectIdentifier::from_str(&format!("2.5.29.{}", 14 + i)).unwrap();
                let value_seq = Element::Sequence(vec![Element::Boolean(true)]);
                let value_asn1 = ASN1Object::new(vec![value_seq]);
                let value_der = value_asn1.encode().unwrap();
                let value_bytes = value_der.encode().unwrap();
                let value = OctetString::from(value_bytes);
                Extension::new(oid, false, value)
            })
            .collect();

        let ext_req = ExtensionRequest::new(extensions).unwrap();
        assert_eq!(ext_req.extensions().len(), count);
    }
}
