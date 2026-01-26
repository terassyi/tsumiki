//! Certificate Serial Number
//!
//! Defined in RFC 5280 Section 4.1.2.2
//!
//! ```asn1
//! CertificateSerialNumber ::= INTEGER
//! ```
//!
//! The serial number MUST be a positive integer assigned by the CA to
//! each certificate. It MUST be unique for each certificate issued by
//! a given CA.

use std::ops::Deref;

use serde::{Deserialize, Serialize};
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};
use tsumiki_asn1::{Element, Integer};

use crate::error::{Error, Result};

/// Certificate Serial Number
///
/// An INTEGER that uniquely identifies a certificate issued by a given CA.
/// Typically displayed in hexadecimal format with colon separators.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
pub struct CertificateSerialNumber {
    inner: Integer,
}

impl Serialize for CertificateSerialNumber {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Convert to hex string with colon separators (like OpenSSL format)
        let bytes = self.inner.as_ref().to_signed_bytes_be();
        let hex_string = bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":");
        serializer.serialize_str(&hex_string)
    }
}

impl CertificateSerialNumber {
    /// Create from raw bytes (IMPLICIT INTEGER encoding).
    ///
    /// The bytes are interpreted as a big-endian signed integer.
    ///
    /// # Example
    ///
    /// ```
    /// use tsumiki_pkix_types::CertificateSerialNumber;
    ///
    /// let serial = CertificateSerialNumber::from_bytes(vec![0x01, 0x02, 0x03]);
    /// assert_eq!(serial.format_hex(), "01:02:03");
    /// ```
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Integer::from(bytes).into()
    }

    /// Format as hex string with colon separators.
    ///
    /// Returns a lowercase hexadecimal representation with colon separators
    /// between each byte (e.g., "00:f7:e9:eb"), similar to OpenSSL's format.
    ///
    /// # Example
    ///
    /// ```
    /// use tsumiki_pkix_types::CertificateSerialNumber;
    ///
    /// let serial = CertificateSerialNumber::from_bytes(vec![0x48, 0xc3, 0x54, 0x8e]);
    /// assert_eq!(serial.format_hex(), "48:c3:54:8e");
    /// ```
    pub fn format_hex(&self) -> String {
        let bytes = self.inner.as_ref().to_signed_bytes_be();
        bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":")
    }
}

impl From<Integer> for CertificateSerialNumber {
    fn from(inner: Integer) -> Self {
        Self { inner }
    }
}

impl AsRef<Integer> for CertificateSerialNumber {
    fn as_ref(&self) -> &Integer {
        &self.inner
    }
}

impl std::fmt::Display for CertificateSerialNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.format_hex())
    }
}

impl Deref for CertificateSerialNumber {
    type Target = Integer;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DecodableFrom<Element> for CertificateSerialNumber {}

impl Decoder<Element, CertificateSerialNumber> for Element {
    type Error = Error;

    fn decode(&self) -> Result<CertificateSerialNumber> {
        match self {
            Element::Integer(i) => Ok(CertificateSerialNumber { inner: i.clone() }),
            _ => Err(Error::CertificateSerialNumberExpectedInteger),
        }
    }
}

impl EncodableTo<CertificateSerialNumber> for Element {}

impl Encoder<CertificateSerialNumber, Element> for CertificateSerialNumber {
    type Error = Error;

    fn encode(&self) -> Result<Element> {
        Ok(Element::Integer(self.inner.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_serial_number_from_bytes() {
        let serial = CertificateSerialNumber::from_bytes(vec![0x01, 0x02, 0x03]);
        assert_eq!(serial.format_hex(), "01:02:03");
    }

    #[test]
    fn test_certificate_serial_number_encode_decode() {
        let serial = CertificateSerialNumber::from_bytes(vec![0xAA, 0xBB, 0xCC]);
        let encoded = serial.encode().unwrap();
        let decoded: CertificateSerialNumber = encoded.decode().unwrap();
        assert_eq!(decoded, serial);
    }

    #[test]
    fn test_certificate_serial_number_format() {
        let serial = CertificateSerialNumber::from_bytes(vec![
            0x48, 0xc3, 0x54, 0x8e, 0x4a, 0x5e, 0xe7, 0x64,
        ]);
        let hex = serial.format_hex();
        assert!(hex.contains("48:c3:54:8e"));
    }
}
