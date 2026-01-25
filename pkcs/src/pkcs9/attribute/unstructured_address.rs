//! PKCS#9 unstructuredAddress attribute (OID: 1.2.840.113549.1.9.9)
//!
//! Defined in RFC 2985 Section 5.4.3
//!
//! ```asn1
//! unstructuredAddress ATTRIBUTE ::= {
//!     WITH SYNTAX PKCS9String {pkcs-9-ub-unstructuredAddress}
//!     EQUALITY MATCHING RULE caseIgnoreMatch
//!     ID pkcs-9-at-unstructuredAddress
//! }
//!
//! PKCS9String ::= CHOICE {
//!     ia5String        IA5String (SIZE(1..pkcs-9-ub-pkcs9String)),
//!     directoryString  DirectoryString (SIZE(1..pkcs-9-ub-pkcs9String))
//! }
//!
//! DirectoryString ::= CHOICE {
//!     teletexString     TeletexString   (SIZE(1..MAX)),
//!     printableString   PrintableString (SIZE(1..MAX)),
//!     bmpString         BMPString        (SIZE(1..MAX)),
//!     universalString   UniversalString  (SIZE(1..MAX)),
//!     utf8String        UTF8String       (SIZE(1..MAX))
//! }
//! ```
//!
//! The unstructuredAddress attribute type specifies the unstructured postal
//! address or addresses for the subject. It is commonly used in PKCS#10
//! certificate signing requests (CSR) to provide address information about
//! the certificate requester.
//!
//! Unlike structured addresses, unstructured addresses can be arbitrary text
//! and don't follow a specific format.

use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeStruct};
use std::fmt;
use tsumiki_asn1::{ASN1Object, Element, OctetString};
use tsumiki_pkix_types::DirectoryString;

use crate::pkcs9::error::{Error, Result};

use super::{Attribute, PKCS9String};

/// unstructuredAddress attribute
///
/// Contains a human-readable unstructured postal address as a string.
/// Can be encoded as either IA5String (ASCII) or DirectoryString
/// (which supports international characters).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnstructuredAddress {
    /// The unstructured address value
    address: PKCS9String,
}

impl UnstructuredAddress {
    /// Create a new UnstructuredAddress with the given address
    pub fn new(address: impl Into<PKCS9String>) -> Self {
        Self {
            address: address.into(),
        }
    }

    /// Get the address as a string reference
    pub fn address(&self) -> &PKCS9String {
        &self.address
    }
}

impl fmt::Display for UnstructuredAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

impl Serialize for UnstructuredAddress {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("UnstructuredAddress", 1)?;
        state.serialize_field("unstructuredAddress", &self.address)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for UnstructuredAddress {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct UnstructuredAddressHelper {
            #[serde(rename = "unstructuredAddress")]
            address: String,
        }

        let helper = UnstructuredAddressHelper::deserialize(deserializer)?;
        Ok(UnstructuredAddress {
            address: helper.address,
        })
    }
}

impl Attribute for UnstructuredAddress {
    /// OID for unstructuredAddress: 1.2.840.113549.1.9.9
    const OID: &'static str = "1.2.840.113549.1.9.9";

    fn parse(values: &OctetString) -> Result<Self> {
        // Parse the SET OF PKCS9String
        let asn1_obj = ASN1Object::try_from(values).map_err(Error::from)?;

        // The values should be a SET
        let elements = asn1_obj.elements();
        if elements.is_empty() {
            return Err(Error::AttributeEmptyAsn1Object("unstructuredAddress"));
        }

        // The first element should be a SET
        let Element::Set(set) = &elements[0] else {
            return Err(Error::AttributeExpectedElementType {
                attr: "unstructuredAddress",
                expected: "SET",
            });
        };

        if set.is_empty() {
            return Err(Error::AttributeEmptyValuesSet("unstructuredAddress"));
        }

        // Get the first value from the SET
        // PKCS9String can be either IA5String or DirectoryString
        let address = match &set[0] {
            Element::IA5String(ia5) => ia5.clone(),
            Element::UTF8String(_) | Element::PrintableString(_) | Element::BMPString(_) => {
                // Use DirectoryString to handle all string types
                DirectoryString::try_from(&set[0])
                    .map_err(|e| Error::ChallengePasswordInvalidEncoding(e.to_string()))?
                    .as_str()
                    .to_string()
            }
            _ => {
                return Err(Error::UnstructuredAddressInvalidType(format!(
                    "{:?}",
                    set[0]
                )));
            }
        };

        Ok(Self { address })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use tsumiki::encoder::Encoder;
    use tsumiki_asn1::Element;
    use tsumiki_der::Der;

    #[test]
    fn test_unstructured_address_oid() {
        assert_eq!(UnstructuredAddress::OID, "1.2.840.113549.1.9.9");
    }

    #[rstest]
    #[case("123 Main St", "123 Main St")]
    #[case("Tokyo, Japan", "Tokyo, Japan")]
    #[case("1-2-3 Shibuya, Tokyo 150-0002", "1-2-3 Shibuya, Tokyo 150-0002")]
    fn test_unstructured_address_new(#[case] input: &str, #[case] expected: &str) {
        let address = UnstructuredAddress::new(input);
        assert_eq!(address.address(), expected);
    }

    #[rstest]
    #[case("123 Main St")]
    #[case("Tokyo, Japan")]
    #[case("1-2-3 Shibuya, Tokyo")]
    #[case("東京都渋谷区1-2-3")] // Japanese address
    fn test_unstructured_address_encode_decode(#[case] address_str: &str) {
        // Manually create a SET containing UTF8String
        let utf8_element = Element::UTF8String(address_str.to_string());
        let set = Element::Set(vec![utf8_element]);
        let asn1_obj = ASN1Object::new(vec![set]);
        let der: Der = asn1_obj.encode().expect("Failed to encode");
        let der_bytes = der.encode().expect("Failed to encode to bytes");
        let values = OctetString::from(der_bytes);

        // Parse back
        let decoded = UnstructuredAddress::parse(&values).expect("Failed to parse values");

        assert_eq!(decoded.address(), address_str);
    }

    #[rstest]
    #[case(Element::IA5String("123 Main Street".to_string()), "123 Main Street")]
    #[case(Element::UTF8String("Tokyo Tower".to_string()), "Tokyo Tower")]
    #[case(Element::PrintableString("PO Box 123".to_string()), "PO Box 123")]
    #[case(Element::UTF8String("東京タワー".to_string()), "東京タワー")]
    fn test_unstructured_address_parse_string_types(
        #[case] element: Element,
        #[case] expected: &str,
    ) {
        // Create a SET containing the element
        let set = Element::Set(vec![element]);
        let asn1_obj = ASN1Object::new(vec![set]);
        let der: Der = asn1_obj.encode().expect("Failed to encode");
        let der_bytes = der.encode().expect("Failed to encode to bytes");
        let values = OctetString::from(der_bytes);

        let parsed = UnstructuredAddress::parse(&values).expect("Failed to parse");
        assert_eq!(parsed.address(), expected);
    }

    #[rstest]
    #[case(vec![], "AttributeEmptyValuesSet")]
    #[case(vec![Element::Integer(vec![1, 2, 3].into())], "UnstructuredAddressInvalidType")]
    #[case(vec![Element::Null], "UnstructuredAddressInvalidType")]
    fn test_unstructured_address_parse_errors(
        #[case] elements: Vec<Element>,
        #[case] error_msg: &str,
    ) {
        let set = Element::Set(elements);
        let asn1_obj = ASN1Object::new(vec![set]);
        let der: Der = asn1_obj.encode().expect("Failed to encode");
        let der_bytes = der.encode().expect("Failed to encode to bytes");
        let values = OctetString::from(der_bytes);

        let result = UnstructuredAddress::parse(&values);
        assert!(result.is_err());
        let err_str = format!("{:?}", result.unwrap_err());
        assert!(err_str.contains(error_msg));
    }

    #[test]
    fn test_unstructured_address_serde_json() {
        let address = UnstructuredAddress::new("100 Market Street, San Francisco, CA");

        // Serialize to JSON
        let json = serde_json::to_string(&address).expect("Failed to serialize to JSON");
        assert!(json.contains("unstructuredAddress"));
        assert!(json.contains("100 Market Street"));

        // Deserialize from JSON
        let deserialized: UnstructuredAddress =
            serde_json::from_str(&json).expect("Failed to deserialize from JSON");
        assert_eq!(
            deserialized.address(),
            "100 Market Street, San Francisco, CA"
        );
    }
}
