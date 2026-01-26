use serde::{Deserialize, Serialize};
use std::fmt;
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};
use tsumiki_asn1::{ASN1Object, BitString, Element, OctetString};
use tsumiki_pkix_types::OidName;

use super::error;
use crate::error::Error;
use crate::extensions::Extension;

/*
RFC 5280 Section 4.2.1.3
KeyUsage ::= BIT STRING {
    digitalSignature        (0),
    nonRepudiation          (1), -- renamed to contentCommitment
    keyEncipherment         (2),
    dataEncipherment        (3),
    keyAgreement            (4),
    keyCertSign             (5),
    cRLSign                 (6),
    encipherOnly            (7),
    decipherOnly            (8)
}
*/

/// Key Usage extension ([RFC 5280 Section 4.2.1.3](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3)).
///
/// Defines the purpose of the key contained in the certificate.
/// This extension is typically marked as critical.
///
/// # Key Usage Bits
/// - `digital_signature`: Verify digital signatures (other than certificates and CRLs)
/// - `content_commitment`: Non-repudiation, proof of origin (formerly nonRepudiation)
/// - `key_encipherment`: Encrypt keys (e.g., for key transport)
/// - `data_encipherment`: Directly encrypt user data (rarely used)
/// - `key_agreement`: Key agreement (e.g., Diffie-Hellman)
/// - `key_cert_sign`: Verify signatures on certificates
/// - `crl_sign`: Verify signatures on CRLs
/// - `encipher_only`: Only for encryption with key agreement
/// - `decipher_only`: Only for decryption with key agreement
///
/// # Example
/// ```no_run
/// use std::str::FromStr;
/// use tsumiki_x509::Certificate;
/// use tsumiki_x509::extensions::KeyUsage;
///
/// let cert = Certificate::from_str("-----BEGIN CERTIFICATE-----...").unwrap();
/// if let Some(ku) = cert.extension::<KeyUsage>().unwrap() {
///     if ku.digital_signature {
///         println!("Can be used for digital signatures");
///     }
///     if ku.key_cert_sign {
///         println!("This is a CA certificate");
///     }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyUsage {
    /// Verify digital signatures on data
    pub digital_signature: bool,
    /// Non-repudiation (content commitment)
    pub content_commitment: bool,
    /// Encrypt keys for key transport
    pub key_encipherment: bool,
    /// Directly encrypt user data
    pub data_encipherment: bool,
    /// Key agreement protocol
    pub key_agreement: bool,
    /// Verify certificate signatures (CA certificates)
    pub key_cert_sign: bool,
    /// Verify CRL signatures
    pub crl_sign: bool,
    /// Encryption only (with key agreement)
    pub encipher_only: bool,
    /// Decryption only (with key agreement)
    pub decipher_only: bool,
}

impl Extension for KeyUsage {
    const OID: &'static str = "2.5.29.15";

    fn parse(value: &OctetString) -> Result<Self, Error> {
        // OctetString -> ASN1Object -> Element (BitString) -> KeyUsage
        let asn1_obj = ASN1Object::try_from(value).map_err(Error::InvalidASN1)?;
        // The first element should be a BitString
        match asn1_obj.elements() {
            [elem, ..] => elem.decode(),
            [] => Err(error::Error::EmptySequence(error::Kind::KeyUsage).into()),
        }
    }
}

impl DecodableFrom<Element> for KeyUsage {}

impl Decoder<Element, KeyUsage> for Element {
    type Error = Error;

    fn decode(&self) -> Result<KeyUsage, Self::Error> {
        match self {
            Element::BitString(bs) => {
                let bytes = bs.as_ref();
                let total_bits = bs.bit_len();

                // Helper to get bit at position (MSB first in each byte)
                let get_bit = |index: usize| -> bool {
                    if index >= total_bits {
                        return false;
                    }
                    let byte_index = index / 8;
                    let bit_index = 7 - (index % 8); // MSB first
                    if byte_index < bytes.len() {
                        (bytes[byte_index] & (1 << bit_index)) != 0
                    } else {
                        false
                    }
                };

                Ok(KeyUsage {
                    digital_signature: get_bit(0),
                    content_commitment: get_bit(1),
                    key_encipherment: get_bit(2),
                    data_encipherment: get_bit(3),
                    key_agreement: get_bit(4),
                    key_cert_sign: get_bit(5),
                    crl_sign: get_bit(6),
                    encipher_only: get_bit(7),
                    decipher_only: get_bit(8),
                })
            }
            _ => Err(error::Error::ExpectedBitString(error::Kind::KeyUsage).into()),
        }
    }
}

impl OidName for KeyUsage {
    fn oid_name(&self) -> Option<&'static str> {
        Some("keyUsage")
    }
}

impl fmt::Display for KeyUsage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ext_name = self.oid_name().unwrap_or("keyUsage");
        writeln!(f, "            X509v3 {}: critical", ext_name)?;
        let usages: Vec<_> = [
            (self.digital_signature, "Digital Signature"),
            (self.content_commitment, "Content Commitment"),
            (self.key_encipherment, "Key Encipherment"),
            (self.data_encipherment, "Data Encipherment"),
            (self.key_agreement, "Key Agreement"),
            (self.key_cert_sign, "Certificate Sign"),
            (self.crl_sign, "CRL Sign"),
            (self.encipher_only, "Encipher Only"),
            (self.decipher_only, "Decipher Only"),
        ]
        .into_iter()
        .filter_map(|(enabled, name)| enabled.then_some(name))
        .collect();
        writeln!(f, "                {}", usages.join(", "))?;
        Ok(())
    }
}

impl EncodableTo<KeyUsage> for Element {}

impl Encoder<KeyUsage, Element> for KeyUsage {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        let bits = [
            self.digital_signature,
            self.content_commitment,
            self.key_encipherment,
            self.data_encipherment,
            self.key_agreement,
            self.key_cert_sign,
            self.crl_sign,
            self.encipher_only,
            self.decipher_only,
        ];

        let last_bit = bits.iter().rposition(|&b| b).map_or(0, |p| p + 1);
        let num_bytes = last_bit.div_ceil(8);

        let bytes = (0..num_bytes)
            .map(|byte_idx| {
                (0..8)
                    .filter_map(|bit_idx| {
                        let bit_pos = byte_idx * 8 + bit_idx;
                        (bit_pos < last_bit && bits.get(bit_pos) == Some(&true))
                            .then_some(1u8 << (7 - bit_idx))
                    })
                    .sum()
            })
            .collect::<Vec<_>>();

        let unused_bits = if last_bit == 0 {
            0
        } else {
            (num_bytes * 8 - last_bit) as u8
        };
        Ok(Element::BitString(BitString::new(unused_bits, bytes)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    // KeyUsage tests
    #[rstest(
        input,
        expected,
        // Test case: digitalSignature only (bit 0)
        // BitString: 0x80 (10000000 in binary, bit 0 set)
        case(
            Element::BitString(tsumiki_asn1::BitString::try_from(vec![0x07, 0x80]).unwrap()),
            KeyUsage {
                digital_signature: true,
                content_commitment: false,
                key_encipherment: false,
                data_encipherment: false,
                key_agreement: false,
                key_cert_sign: false,
                crl_sign: false,
                encipher_only: false,
                decipher_only: false,
            }
        ),
        // Test case: keyCertSign and cRLSign (bits 5 and 6)
        // BitString: 0x06 (00000110 in binary)
        // unused=1, so bits 0-6 are valid, bits 5 and 6 are set
        case(
            Element::BitString(tsumiki_asn1::BitString::try_from(vec![0x01, 0x06]).unwrap()),
            KeyUsage {
                digital_signature: false,
                content_commitment: false,
                key_encipherment: false,
                data_encipherment: false,
                key_agreement: false,
                key_cert_sign: true,  // bit 5
                crl_sign: true,       // bit 6
                encipher_only: false,
                decipher_only: false,
            }
        ),
        // Test case: digitalSignature, keyEncipherment, dataEncipherment (bits 0, 2, 3)
        // Bit 0 = 0x80, Bit 2 = 0x20, Bit 3 = 0x10, together = 0xB0
        // unused=4, so bits 0-3 are valid
        case(
            Element::BitString(tsumiki_asn1::BitString::try_from(vec![0x04, 0xB0]).unwrap()),
            KeyUsage {
                digital_signature: true,
                content_commitment: false,
                key_encipherment: true,
                data_encipherment: true,
                key_agreement: false,
                key_cert_sign: false,
                crl_sign: false,
                encipher_only: false,
                decipher_only: false,
            }
        ),
        // Test case: All bits set
        // BitString: 0xFF 0x80 (11111111 10000000)
        case(
            Element::BitString(tsumiki_asn1::BitString::try_from(vec![0x07, 0xFF, 0x80]).unwrap()),
            KeyUsage {
                digital_signature: true,
                content_commitment: true,
                key_encipherment: true,
                data_encipherment: true,
                key_agreement: true,
                key_cert_sign: true,
                crl_sign: true,
                encipher_only: true,
                decipher_only: true,
            }
        ),
    )]
    fn test_key_usage_decode_success(input: Element, expected: KeyUsage) {
        let result: Result<KeyUsage, Error> = input.decode();
        assert!(result.is_ok(), "Failed to decode: {:?}", result);
        let actual = result.unwrap();
        assert_eq!(expected, actual);
    }

    #[rstest(
        input,
        expected_error_msg,
        // Test case: Not a BitString
        case(
            Element::Boolean(true),
            "expected BIT STRING"
        ),
        // Test case: Sequence instead of BitString
        case(
            Element::Sequence(vec![]),
            "expected BIT STRING"
        ),
    )]
    fn test_key_usage_decode_failure(input: Element, expected_error_msg: &str) {
        let result: Result<KeyUsage, _> = input.decode();
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

    #[rstest]
    #[case(KeyUsage {
        digital_signature: true,
        content_commitment: false,
        key_encipherment: false,
        data_encipherment: false,
        key_agreement: false,
        key_cert_sign: false,
        crl_sign: false,
        encipher_only: false,
        decipher_only: false,
    })]
    #[case(KeyUsage {
        digital_signature: true,
        content_commitment: true,
        key_encipherment: true,
        data_encipherment: false,
        key_agreement: false,
        key_cert_sign: false,
        crl_sign: false,
        encipher_only: false,
        decipher_only: false,
    })]
    #[case(KeyUsage {
        digital_signature: false,
        content_commitment: false,
        key_encipherment: false,
        data_encipherment: false,
        key_agreement: false,
        key_cert_sign: true,
        crl_sign: true,
        encipher_only: false,
        decipher_only: false,
    })]
    fn test_key_usage_encode_decode(#[case] original: KeyUsage) {
        let encoded = original.encode();
        assert!(encoded.is_ok(), "Failed to encode: {:?}", encoded);

        let element = encoded.unwrap();
        let decoded: Result<KeyUsage, _> = element.decode();
        assert!(decoded.is_ok(), "Failed to decode: {:?}", decoded);

        let roundtrip = decoded.unwrap();
        assert_eq!(original, roundtrip);
    }
}
