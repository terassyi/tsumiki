//! DirectoryString type as defined in RFC 5280 Section 4.1.2.4
//!
//! DirectoryString is used throughout X.509 certificates and PKCS standards
//! to represent textual information in various character encodings.

use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

use asn1::Element;
use serde::{Deserialize, Serialize};
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};

use crate::error::{Error, Result};

/// DirectoryString as defined in RFC 5280 Section 4.1.2.4
///
/// ```asn1
/// DirectoryString ::= CHOICE {
///   teletexString     TeletexString (SIZE (1..MAX)),
///   printableString   PrintableString (SIZE (1..MAX)),
///   universalString   UniversalString (SIZE (1..MAX)),
///   utf8String        UTF8String (SIZE (1..MAX)),
///   bmpString         BMPString (SIZE (1..MAX))
/// }
/// ```
///
/// This is a wrapper around a String that can be decoded from various ASN.1 string types.
/// It is commonly used in X.509 certificate Distinguished Names and PKCS#9 attributes.
///
/// Note: TeletexString and UniversalString are not currently supported in decoding
/// as they are deprecated and rarely used in modern PKI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryString {
    inner: String,
}

impl DirectoryString {
    /// Create a new DirectoryString
    pub fn new(value: String) -> Self {
        Self { inner: value }
    }

    /// Get the inner string value
    pub fn as_str(&self) -> &str {
        &self.inner
    }
}

impl Serialize for DirectoryString {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.inner.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DirectoryString {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let inner = String::deserialize(deserializer)?;
        Ok(DirectoryString { inner })
    }
}

impl AsRef<str> for DirectoryString {
    fn as_ref(&self) -> &str {
        &self.inner
    }
}

impl Deref for DirectoryString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl From<DirectoryString> for String {
    fn from(ds: DirectoryString) -> Self {
        ds.inner
    }
}

impl From<String> for DirectoryString {
    fn from(value: String) -> Self {
        Self { inner: value }
    }
}

impl From<&str> for DirectoryString {
    fn from(value: &str) -> Self {
        Self {
            inner: value.to_string(),
        }
    }
}

impl TryFrom<&Element> for DirectoryString {
    type Error = Error;

    fn try_from(element: &Element) -> Result<Self> {
        let value = match element {
            Element::PrintableString(s) => s.clone(),
            Element::UTF8String(s) => s.clone(),
            Element::BMPString(bmp) => bmp.to_string(),
            Element::IA5String(s) => s.clone(),
            Element::OctetString(os) => {
                // May come as OctetString due to IMPLICIT tagging
                String::from_utf8(os.as_bytes().to_vec()).map_err(|e| {
                    Error::InvalidDirectoryString(format!("invalid UTF-8 in OctetString: {}", e))
                })?
            }
            other => {
                return Err(Error::InvalidDirectoryString(format!(
                    "DirectoryString must be a string type, got {:?}",
                    other
                )))
            }
        };
        Ok(Self { inner: value })
    }
}

impl FromStr for DirectoryString {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self {
            inner: s.to_string(),
        })
    }
}

impl From<&DirectoryString> for Element {
    fn from(ds: &DirectoryString) -> Self {
        if is_printable_string(&ds.inner) {
            Element::PrintableString(ds.inner.clone())
        } else {
            Element::UTF8String(ds.inner.clone())
        }
    }
}

impl From<DirectoryString> for Element {
    fn from(ds: DirectoryString) -> Self {
        if is_printable_string(&ds.inner) {
            Element::PrintableString(ds.inner)
        } else {
            Element::UTF8String(ds.inner)
        }
    }
}

impl fmt::Display for DirectoryString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

// Implement Decoder/Encoder traits for integration with tsumiki ecosystem
impl DecodableFrom<Element> for DirectoryString {}

impl Decoder<Element, DirectoryString> for Element {
    type Error = Error;

    fn decode(&self) -> Result<DirectoryString> {
        DirectoryString::try_from(self)
    }
}

impl EncodableTo<DirectoryString> for Element {}

impl Encoder<DirectoryString, Element> for DirectoryString {
    type Error = Error;

    fn encode(&self) -> Result<Element> {
        Ok(self.into())
    }
}

/// Check if a string contains only PrintableString characters
///
/// PrintableString allows: A-Z, a-z, 0-9, space, and ' ( ) + , - . / : = ?
fn is_printable_string(s: &str) -> bool {
    const PRINTABLE_CHARS: &str =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?";
    s.chars().all(|c| PRINTABLE_CHARS.contains(c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use asn1::BMPString;
    use rstest::rstest;

    #[test]
    fn test_directory_string_new() {
        let ds = DirectoryString::new("test".to_string());
        assert_eq!(ds.as_str(), "test");
    }

    #[rstest]
    #[case(Element::PrintableString("Hello123".to_string()), "Hello123")]
    #[case(Element::UTF8String("こんにちは".to_string()), "こんにちは")]
    #[case(Element::IA5String("test@example.com".to_string()), "test@example.com")]
    fn test_directory_string_from_element_success(
        #[case] element: Element,
        #[case] expected: &str,
    ) {
        let ds = DirectoryString::try_from(&element).unwrap();
        assert_eq!(ds.as_str(), expected);
    }

    #[test]
    fn test_directory_string_from_bmp_string() {
        let bmp = BMPString::new("テスト").unwrap();
        let element = Element::BMPString(bmp);
        let ds = DirectoryString::try_from(&element).unwrap();
        assert_eq!(ds.as_str(), "テスト");
    }

    #[test]
    fn test_directory_string_from_octet_string() {
        let bytes = "hello".as_bytes().to_vec();
        let element = Element::OctetString(asn1::OctetString::from(bytes));
        let ds = DirectoryString::try_from(&element).unwrap();
        assert_eq!(ds.as_str(), "hello");
    }

    #[test]
    fn test_directory_string_from_invalid_type() {
        let element = Element::Null;
        let result = DirectoryString::try_from(&element);
        assert!(result.is_err());
    }

    #[rstest]
    #[case("ABC123", Element::PrintableString("ABC123".to_string()))]
    #[case("CN=Test", Element::PrintableString("CN=Test".to_string()))]
    fn test_directory_string_to_element_printable(#[case] input: &str, #[case] expected: Element) {
        let ds = DirectoryString::new(input.to_string());
        let element: Element = (&ds).into();
        assert_eq!(element, expected);
    }

    #[rstest]
    #[case("こんにちは", "こんにちは")]
    #[case("test@example.com", "test@example.com")]
    #[case("test!", "test!")]
    fn test_directory_string_to_element_utf8(#[case] input: &str, #[case] expected: &str) {
        let ds = DirectoryString::new(input.to_string());
        let element: Element = (&ds).into();
        assert!(matches!(element, Element::UTF8String(_)));
        if let Element::UTF8String(s) = element {
            assert_eq!(s, expected);
        }
    }

    #[test]
    fn test_directory_string_deref() {
        let ds = DirectoryString::new("test".to_string());
        assert_eq!(&*ds, "test");
        assert_eq!(ds.len(), 4);
    }

    #[test]
    fn test_directory_string_as_ref() {
        let ds = DirectoryString::new("test".to_string());
        let s: &str = ds.as_ref();
        assert_eq!(s, "test");
    }

    #[rstest]
    #[case("test".to_string())]
    #[case("hello".to_string())]
    fn test_directory_string_from_string(#[case] input: String) {
        let expected = input.clone();
        let ds: DirectoryString = input.into();
        assert_eq!(ds.as_str(), expected);
    }

    #[rstest]
    #[case("test")]
    #[case("hello")]
    fn test_directory_string_from_str(#[case] input: &str) {
        let ds: DirectoryString = input.into();
        assert_eq!(ds.as_str(), input);
    }

    #[test]
    fn test_directory_string_from_str_trait() {
        let ds = DirectoryString::from_str("test").unwrap();
        assert_eq!(ds.as_str(), "test");
    }

    #[test]
    fn test_directory_string_to_string() {
        let ds = DirectoryString::new("test".to_string());
        let s: String = ds.into();
        assert_eq!(s, "test");
    }

    #[test]
    fn test_directory_string_display() {
        let ds = DirectoryString::new("test".to_string());
        assert_eq!(format!("{}", ds), "test");
    }

    #[test]
    fn test_directory_string_serde() {
        let ds = DirectoryString::new("serialize_test".to_string());
        let json = serde_json::to_string(&ds).unwrap();
        assert_eq!(json, "\"serialize_test\"");

        let deserialized: DirectoryString = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.as_str(), "serialize_test");
    }

    #[rstest]
    #[case("ABC123", true)]
    #[case("Hello World", true)]
    #[case("test(1)", true)]
    #[case("CN=Test", true)]
    #[case("test@example.com", false)] // @ not in printable
    #[case("こんにちは", false)]
    #[case("test!", false)]
    fn test_is_printable_string(#[case] input: &str, #[case] expected: bool) {
        assert_eq!(is_printable_string(input), expected);
    }

    #[test]
    fn test_directory_string_clone() {
        let ds1 = DirectoryString::new("test".to_string());
        let ds2 = ds1.clone();
        assert_eq!(ds1, ds2);
    }

    #[test]
    fn test_directory_string_debug() {
        let ds = DirectoryString::new("test".to_string());
        let debug_str = format!("{:?}", ds);
        assert!(debug_str.contains("test"));
    }
}
