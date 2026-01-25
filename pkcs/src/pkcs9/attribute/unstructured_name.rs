//! PKCS#9 unstructuredName attribute (OID: 1.2.840.113549.1.9.8)
//!
//! Defined in RFC 2985 Section 5.4.2
//!
//! ```asn1
//! unstructuredName ATTRIBUTE ::= {
//!     WITH SYNTAX PKCS9String {pkcs-9-ub-unstructuredName}
//!     EQUALITY MATCHING RULE caseIgnoreMatch
//!     ID pkcs-9-at-unstructuredName
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
//! The unstructuredName attribute type specifies the unstructured name
//! for the subject. It is commonly used in PKCS#10 certificate signing
//! requests (CSR) to provide additional human-readable information about
//! the certificate requester.
//!
//! Unlike structured names (Distinguished Names), unstructured names can
//! be arbitrary text and don't follow the X.500 naming hierarchy.

use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeStruct};
use std::fmt;
use tsumiki_asn1::{ASN1Object, Element, OctetString};
use tsumiki_pkix_types::DirectoryString;

use crate::pkcs9::error::{Error, Result};

use super::{Attribute, PKCS9String};

/// unstructuredName attribute
///
/// Contains a human-readable unstructured name as a string.
/// Can be encoded as either IA5String (ASCII) or DirectoryString
/// (which supports international characters).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnstructuredName {
    /// The unstructured name value
    name: PKCS9String,
}

impl UnstructuredName {
    /// Create a new UnstructuredName with the given name
    pub fn new(name: impl Into<PKCS9String>) -> Self {
        Self { name: name.into() }
    }

    /// Get the name as a string reference
    pub fn name(&self) -> &PKCS9String {
        &self.name
    }
}

impl fmt::Display for UnstructuredName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl Serialize for UnstructuredName {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("UnstructuredName", 1)?;
        state.serialize_field("unstructuredName", &self.name)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for UnstructuredName {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct UnstructuredNameHelper {
            #[serde(rename = "unstructuredName")]
            unstructured_name: String,
        }

        let helper = UnstructuredNameHelper::deserialize(deserializer)?;
        Ok(Self {
            name: helper.unstructured_name,
        })
    }
}

impl Attribute for UnstructuredName {
    /// OID for unstructuredName: 1.2.840.113549.1.9.8
    const OID: &'static str = "1.2.840.113549.1.9.8";

    fn parse(values: &OctetString) -> Result<Self> {
        // Parse the SET OF PKCS9String
        let asn1_obj = ASN1Object::try_from(values).map_err(Error::from)?;

        // The values should be a SET
        let elements = asn1_obj.elements();
        if elements.is_empty() {
            return Err(Error::AttributeEmptyAsn1Object("unstructuredName"));
        }

        // The first element should be a SET
        let Element::Set(set) = &elements[0] else {
            return Err(Error::AttributeExpectedElementType {
                attr: "unstructuredName",
                expected: "SET",
            });
        };

        if set.is_empty() {
            return Err(Error::AttributeEmptyValuesSet("unstructuredName"));
        }

        // Get the first value from the SET
        // PKCS9String can be either IA5String or DirectoryString
        let name = match &set[0] {
            Element::IA5String(ia5) => ia5.clone(),
            Element::UTF8String(_) | Element::PrintableString(_) | Element::BMPString(_) => {
                // Use DirectoryString to handle all string types
                DirectoryString::try_from(&set[0])
                    .map_err(|e| Error::ChallengePasswordInvalidEncoding(e.to_string()))?
                    .as_str()
                    .to_string()
            }
            _ => {
                return Err(Error::UnstructuredNameInvalidType(format!("{:?}", set[0])));
            }
        };

        Ok(Self { name })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use tsumiki::encoder::Encoder;
    use tsumiki_der::Der;

    #[test]
    fn test_unstructured_name_oid() {
        assert_eq!(UnstructuredName::OID, "1.2.840.113549.1.9.8");
    }

    #[rstest]
    #[case("John Doe", "John Doe")]
    #[case("Test User", "Test User")]
    #[case("Alice Smith", "Alice Smith")]
    fn test_unstructured_name_new(#[case] input: &str, #[case] expected: &str) {
        let name = UnstructuredName::new(input);
        assert_eq!(name.name(), expected);
    }

    #[rstest]
    #[case("John Doe")]
    #[case("Test User")]
    #[case("Alice Smith")]
    #[case("日本語名前")] // Japanese characters
    fn test_unstructured_name_encode_decode(#[case] name_str: &str) {
        // Manually create a SET containing UTF8String
        let utf8_element = Element::UTF8String(name_str.to_string());
        let set = Element::Set(vec![utf8_element]);
        let asn1_obj = ASN1Object::new(vec![set]);
        let der: Der = asn1_obj.encode().expect("Failed to encode");
        let der_bytes = der.encode().expect("Failed to encode to bytes");
        let values = OctetString::from(der_bytes);

        // Parse back
        let decoded = UnstructuredName::parse(&values).expect("Failed to parse values");

        assert_eq!(decoded.name(), name_str);
    }

    #[rstest]
    #[case(Element::IA5String("Test Name".to_string()), "Test Name")]
    #[case(Element::UTF8String("UTF8 Name".to_string()), "UTF8 Name")]
    #[case(Element::PrintableString("Printable Name".to_string()), "Printable Name")]
    #[case(Element::UTF8String("日本語名前".to_string()), "日本語名前")]
    fn test_unstructured_name_parse_string_types(#[case] element: Element, #[case] expected: &str) {
        // Create a SET containing the element
        let set = Element::Set(vec![element]);
        let asn1_obj = ASN1Object::new(vec![set]);
        let der: Der = asn1_obj.encode().expect("Failed to encode");
        let der_bytes = der.encode().expect("Failed to encode to bytes");
        let values = OctetString::from(der_bytes);

        let parsed = UnstructuredName::parse(&values).expect("Failed to parse");
        assert_eq!(parsed.name(), expected);
    }

    #[rstest]
    #[case(vec![], "AttributeEmptyValuesSet")]
    #[case(vec![Element::Integer(vec![1, 2, 3].into())], "UnstructuredNameInvalidType")]
    #[case(vec![Element::Null], "UnstructuredNameInvalidType")]
    fn test_unstructured_name_parse_errors(
        #[case] elements: Vec<Element>,
        #[case] error_msg: &str,
    ) {
        let set = Element::Set(elements);
        let asn1_obj = ASN1Object::new(vec![set]);
        let der: Der = asn1_obj.encode().expect("Failed to encode");
        let der_bytes = der.encode().expect("Failed to encode to bytes");
        let values = OctetString::from(der_bytes);

        let result = UnstructuredName::parse(&values);
        assert!(result.is_err());
        let err_str = format!("{:?}", result.unwrap_err());
        assert!(err_str.contains(error_msg));
    }

    #[test]
    fn test_unstructured_name_serde_json() {
        let name = UnstructuredName::new("Test User");

        // Serialize to JSON
        let json = serde_json::to_string(&name).expect("Failed to serialize to JSON");
        assert!(json.contains("unstructuredName"));
        assert!(json.contains("Test User"));

        // Deserialize from JSON
        let deserialized: UnstructuredName =
            serde_json::from_str(&json).expect("Failed to deserialize from JSON");
        assert_eq!(deserialized.name(), "Test User");
    }
}
