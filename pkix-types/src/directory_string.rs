//! DirectoryString type as defined in RFC 5280 Section 4.1.2.4
//!
//! DirectoryString is used throughout X.509 certificates and PKCS standards
//! to represent textual information in various character encodings.

use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};
use tsumiki_asn1::{BMPString, Element};

use crate::error::{Error, Result};

/// The encoding type used for a DirectoryString.
///
/// This preserves the original ASN.1 encoding type so that re-encoding
/// produces byte-identical output.
///
/// Default is UTF8String as recommended by RFC 5280 Section 4.1.2.4.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum StringEncoding {
    /// PrintableString (tag 0x13)
    PrintableString,
    /// UTF8String (tag 0x0C) - default as recommended by RFC 5280
    #[default]
    UTF8String,
    /// BMPString (tag 0x1E)
    BMPString,
    /// IA5String (tag 0x16)
    IA5String,
}

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
/// This type preserves the original encoding type so that re-encoding
/// produces byte-identical output. It is commonly used in X.509 certificate
/// Distinguished Names and PKCS#9 attributes.
///
/// Note: TeletexString and UniversalString are not currently supported in decoding
/// as they are deprecated and rarely used in modern PKI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryString {
    value: String,
    encoding: StringEncoding,
}

impl DirectoryString {
    /// Create a new DirectoryString with default encoding (UTF8String)
    pub fn new(value: String) -> Self {
        Self {
            value,
            encoding: StringEncoding::default(),
        }
    }

    /// Create a new DirectoryString with a specific encoding
    pub fn with_encoding(value: String, encoding: StringEncoding) -> Self {
        Self { value, encoding }
    }

    /// Get the string value
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Get the encoding type
    pub fn encoding(&self) -> StringEncoding {
        self.encoding
    }
}

impl Serialize for DirectoryString {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.value.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DirectoryString {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(DirectoryString {
            value,
            encoding: StringEncoding::default(),
        })
    }
}

impl AsRef<str> for DirectoryString {
    fn as_ref(&self) -> &str {
        &self.value
    }
}

impl Deref for DirectoryString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl From<DirectoryString> for String {
    fn from(ds: DirectoryString) -> Self {
        ds.value
    }
}

impl From<String> for DirectoryString {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for DirectoryString {
    fn from(value: &str) -> Self {
        Self::new(value.to_string())
    }
}

impl TryFrom<&Element> for DirectoryString {
    type Error = Error;

    fn try_from(element: &Element) -> Result<Self> {
        let (value, encoding) = match element {
            Element::PrintableString(s) => (s.clone(), StringEncoding::PrintableString),
            Element::UTF8String(s) => (s.clone(), StringEncoding::UTF8String),
            Element::BMPString(bmp) => (bmp.to_string(), StringEncoding::BMPString),
            Element::IA5String(s) => (s.clone(), StringEncoding::IA5String),
            Element::OctetString(os) => {
                // May come as OctetString due to IMPLICIT tagging
                // Default to UTF8String encoding for OctetString
                let s = String::from_utf8(os.as_bytes().to_vec())
                    .map_err(|_| Error::DirectoryStringInvalidUtf8)?;
                (s, StringEncoding::UTF8String)
            }
            _ => {
                return Err(Error::DirectoryStringExpectedStringType);
            }
        };
        Ok(Self { value, encoding })
    }
}

impl FromStr for DirectoryString {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self::new(s.to_string()))
    }
}

impl From<&DirectoryString> for Element {
    fn from(ds: &DirectoryString) -> Self {
        match ds.encoding {
            StringEncoding::PrintableString => Element::PrintableString(ds.value.clone()),
            StringEncoding::UTF8String => Element::UTF8String(ds.value.clone()),
            StringEncoding::BMPString => {
                // BMPString::new can fail for characters outside BMP
                // Fall back to UTF8String if conversion fails
                BMPString::new(&ds.value)
                    .map(Element::BMPString)
                    .unwrap_or_else(|_| Element::UTF8String(ds.value.clone()))
            }
            StringEncoding::IA5String => Element::IA5String(ds.value.clone()),
        }
    }
}

impl From<DirectoryString> for Element {
    fn from(ds: DirectoryString) -> Self {
        match ds.encoding {
            StringEncoding::PrintableString => Element::PrintableString(ds.value),
            StringEncoding::UTF8String => Element::UTF8String(ds.value),
            StringEncoding::BMPString => {
                // BMPString::new can fail for characters outside BMP
                // Fall back to UTF8String if conversion fails
                BMPString::new(&ds.value)
                    .map(Element::BMPString)
                    .unwrap_or_else(|_| Element::UTF8String(ds.value))
            }
            StringEncoding::IA5String => Element::IA5String(ds.value),
        }
    }
}

impl fmt::Display for DirectoryString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
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

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use tsumiki_asn1::BMPString;

    #[test]
    fn test_directory_string_new() {
        let ds = DirectoryString::new("test".to_string());
        assert_eq!(ds.as_str(), "test");
        assert_eq!(ds.encoding(), StringEncoding::UTF8String);
    }

    #[test]
    fn test_directory_string_with_encoding() {
        let ds =
            DirectoryString::with_encoding("test".to_string(), StringEncoding::PrintableString);
        assert_eq!(ds.as_str(), "test");
        assert_eq!(ds.encoding(), StringEncoding::PrintableString);
    }

    #[rstest]
    #[case(Element::PrintableString("Hello123".to_string()), "Hello123", StringEncoding::PrintableString)]
    #[case(Element::UTF8String("こんにちは".to_string()), "こんにちは", StringEncoding::UTF8String)]
    #[case(Element::IA5String("test@example.com".to_string()), "test@example.com", StringEncoding::IA5String)]
    fn test_directory_string_from_element_preserves_encoding(
        #[case] element: Element,
        #[case] expected_value: &str,
        #[case] expected_encoding: StringEncoding,
    ) {
        let ds = DirectoryString::try_from(&element).unwrap();
        assert_eq!(ds.as_str(), expected_value);
        assert_eq!(ds.encoding(), expected_encoding);
    }

    #[test]
    fn test_directory_string_from_bmp_string() {
        let bmp = BMPString::new("テスト").unwrap();
        let element = Element::BMPString(bmp);
        let ds = DirectoryString::try_from(&element).unwrap();
        assert_eq!(ds.as_str(), "テスト");
        assert_eq!(ds.encoding(), StringEncoding::BMPString);
    }

    #[test]
    fn test_directory_string_from_octet_string() {
        let bytes = "hello".as_bytes().to_vec();
        let element = Element::OctetString(tsumiki_asn1::OctetString::from(bytes));
        let ds = DirectoryString::try_from(&element).unwrap();
        assert_eq!(ds.as_str(), "hello");
        // OctetString defaults to UTF8String encoding
        assert_eq!(ds.encoding(), StringEncoding::UTF8String);
    }

    #[test]
    fn test_directory_string_from_invalid_type() {
        let element = Element::Null;
        let result = DirectoryString::try_from(&element);
        assert!(result.is_err());
    }

    #[rstest]
    #[case(StringEncoding::PrintableString, "ABC123", Element::PrintableString("ABC123".to_string()))]
    #[case(StringEncoding::UTF8String, "ABC123", Element::UTF8String("ABC123".to_string()))]
    #[case(StringEncoding::IA5String, "test@example.com", Element::IA5String("test@example.com".to_string()))]
    fn test_directory_string_to_element_preserves_encoding(
        #[case] encoding: StringEncoding,
        #[case] value: &str,
        #[case] expected: Element,
    ) {
        let ds = DirectoryString::with_encoding(value.to_string(), encoding);
        let element: Element = (&ds).into();
        assert_eq!(element, expected);
    }

    #[test]
    fn test_directory_string_roundtrip_printable() {
        let original = Element::PrintableString("Hello World".to_string());
        let ds = DirectoryString::try_from(&original).unwrap();
        let encoded: Element = ds.into();
        assert_eq!(original, encoded);
    }

    #[test]
    fn test_directory_string_roundtrip_utf8() {
        let original = Element::UTF8String("Hello World".to_string());
        let ds = DirectoryString::try_from(&original).unwrap();
        let encoded: Element = ds.into();
        assert_eq!(original, encoded);
    }

    #[test]
    fn test_directory_string_roundtrip_bmp() {
        let bmp = BMPString::new("Test").unwrap();
        let original = Element::BMPString(bmp);
        let ds = DirectoryString::try_from(&original).unwrap();
        let encoded: Element = ds.into();
        assert_eq!(original, encoded);
    }

    #[test]
    fn test_directory_string_roundtrip_ia5() {
        let original = Element::IA5String("test@example.com".to_string());
        let ds = DirectoryString::try_from(&original).unwrap();
        let encoded: Element = ds.into();
        assert_eq!(original, encoded);
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
        assert_eq!(ds.encoding(), StringEncoding::UTF8String);
    }

    #[rstest]
    #[case("test")]
    #[case("hello")]
    fn test_directory_string_from_str(#[case] input: &str) {
        let ds: DirectoryString = input.into();
        assert_eq!(ds.as_str(), input);
        assert_eq!(ds.encoding(), StringEncoding::UTF8String);
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

    #[test]
    fn test_directory_string_clone() {
        let ds1 =
            DirectoryString::with_encoding("test".to_string(), StringEncoding::PrintableString);
        let ds2 = ds1.clone();
        assert_eq!(ds1, ds2);
        assert_eq!(ds2.encoding(), StringEncoding::PrintableString);
    }

    #[test]
    fn test_directory_string_debug() {
        let ds = DirectoryString::new("test".to_string());
        let debug_str = format!("{:?}", ds);
        assert!(debug_str.contains("test"));
        assert!(debug_str.contains("UTF8String"));
    }

    #[test]
    fn test_string_encoding_default() {
        assert_eq!(StringEncoding::default(), StringEncoding::UTF8String);
    }

    #[test]
    fn test_string_encoding_copy() {
        let encoding = StringEncoding::PrintableString;
        let copied = encoding;
        assert_eq!(encoding, copied);
    }
}
