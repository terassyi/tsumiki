//! Subject Public Key Info
//!
//! RFC 5280 Section 4.1.2.7
//!
//! ```asn1
//! SubjectPublicKeyInfo  ::=  SEQUENCE  {
//!     algorithm            AlgorithmIdentifier,
//!     subjectPublicKey     BIT STRING
//! }
//! ```
//!
//! Used in:
//! - X.509 certificates (RFC 5280)
//! - PKCS#8 private key format (RFC 5958)
//! - PKCS#10 certificate signing requests (RFC 2986)

use serde::{Deserialize, Serialize};
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};
use tsumiki_asn1::{BitString, Element};

use crate::OidName;
use crate::algorithm::AlgorithmIdentifier;
use crate::error::{Error, Result};

/// Subject Public Key Info
///
/// Contains the algorithm identifier and the public key itself.
///
/// Defined in [RFC 5280 Section 4.1.2.7](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.7).
/// Algorithm-specific formats:
/// - [RFC 3279](https://datatracker.ietf.org/doc/html/rfc3279) - RSA, DSA, and Diffie-Hellman
/// - [RFC 5480](https://datatracker.ietf.org/doc/html/rfc5480) - Elliptic Curve Cryptography
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectPublicKeyInfo {
    algorithm: AlgorithmIdentifier,
    subject_public_key: BitString,
}

impl SubjectPublicKeyInfo {
    /// Create a new SubjectPublicKeyInfo.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The algorithm identifier specifying the public key algorithm
    /// * `subject_public_key` - The public key as a BIT STRING
    ///
    /// # Example
    ///
    /// ```
    /// use std::str::FromStr;
    /// use tsumiki_asn1::{BitString, ObjectIdentifier};
    /// use tsumiki_pkix_types::{AlgorithmIdentifier, AlgorithmParameters, SubjectPublicKeyInfo};
    ///
    /// // RSA public key
    /// let oid = ObjectIdentifier::from_str("1.2.840.113549.1.1.1")?; // rsaEncryption
    /// let algorithm = AlgorithmIdentifier::new_with_params(oid, AlgorithmParameters::Null);
    /// let public_key = BitString::new(0, vec![0x30, 0x0d, 0x06, 0x09]);
    ///
    /// let spki = SubjectPublicKeyInfo::new(algorithm, public_key);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn new(algorithm: AlgorithmIdentifier, subject_public_key: BitString) -> Self {
        Self {
            algorithm,
            subject_public_key,
        }
    }

    /// Get the algorithm identifier.
    ///
    /// Returns a reference to the `AlgorithmIdentifier` that specifies
    /// the public key algorithm and any associated parameters.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use tsumiki_pkix_types::SubjectPublicKeyInfo;
    ///
    /// # fn example(spki: &SubjectPublicKeyInfo) {
    /// let algorithm = spki.algorithm();
    /// println!("Algorithm: {:?}", algorithm.algorithm());
    /// # }
    /// ```
    pub fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.algorithm
    }

    /// Get the subject public key.
    ///
    /// Returns a reference to the `BitString` containing the public key bytes.
    /// The interpretation of these bytes depends on the algorithm.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use tsumiki_pkix_types::SubjectPublicKeyInfo;
    ///
    /// # fn example(spki: &SubjectPublicKeyInfo) {
    /// let public_key = spki.subject_public_key();
    /// println!("Public key length: {} bits", public_key.bit_len());
    /// # }
    /// ```
    pub fn subject_public_key(&self) -> &BitString {
        &self.subject_public_key
    }
}

impl DecodableFrom<Element> for SubjectPublicKeyInfo {}

impl Decoder<Element, SubjectPublicKeyInfo> for Element {
    type Error = Error;

    fn decode(&self) -> Result<SubjectPublicKeyInfo> {
        let Element::Sequence(elements) = self else {
            return Err(Error::SubjectPublicKeyInfoExpectedSequence);
        };

        let (algorithm, subject_public_key) = match elements.as_slice() {
            [algorithm_elm, Element::BitString(subject_public_key)] => {
                (algorithm_elm.decode()?, subject_public_key.clone())
            }
            [_, _] => {
                return Err(Error::SubjectPublicKeyInfoExpectedBitString);
            }
            _ => {
                return Err(Error::SubjectPublicKeyInfoInvalidElementCount(
                    elements.len(),
                ));
            }
        };

        Ok(SubjectPublicKeyInfo {
            algorithm,
            subject_public_key,
        })
    }
}

impl EncodableTo<SubjectPublicKeyInfo> for Element {}

impl Encoder<SubjectPublicKeyInfo, Element> for SubjectPublicKeyInfo {
    type Error = Error;

    fn encode(&self) -> Result<Element> {
        let algorithm_elm = self.algorithm.encode()?;
        let public_key_elm = Element::BitString(self.subject_public_key.clone());
        Ok(Element::Sequence(vec![algorithm_elm, public_key_elm]))
    }
}

impl OidName for SubjectPublicKeyInfo {
    fn oid_name(&self) -> Option<&'static str> {
        self.algorithm.oid_name()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::AlgorithmParameters;
    use tsumiki_asn1::ObjectIdentifier;

    #[test]
    fn test_subject_public_key_info_round_trip() {
        // RSA public key
        let oid: ObjectIdentifier = "1.2.840.113549.1.1.1".parse().unwrap();
        let algorithm = AlgorithmIdentifier::new_with_params(oid, AlgorithmParameters::Null);
        let public_key = BitString::new(0, vec![0x30, 0x0d, 0x06, 0x09]);

        let spki = SubjectPublicKeyInfo::new(algorithm.clone(), public_key.clone());

        // Encode
        let encoded = spki.encode().unwrap();

        // Decode
        let decoded: SubjectPublicKeyInfo = encoded.decode().unwrap();

        assert_eq!(decoded.algorithm(), &algorithm);
        assert_eq!(decoded.subject_public_key(), &public_key);
    }

    #[test]
    fn test_subject_public_key_info_invalid_sequence_length() {
        // Sequence with only 1 element (should be 2)
        let oid: ObjectIdentifier = "1.2.840.113549.1.1.1".parse().unwrap();
        let element = Element::Sequence(vec![Element::ObjectIdentifier(oid)]);

        let result: Result<SubjectPublicKeyInfo> = element.decode();
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(Error::SubjectPublicKeyInfoInvalidElementCount(_))
        ));
    }

    #[test]
    fn test_subject_public_key_info_invalid_public_key_type() {
        // Second element is not BitString
        let oid: ObjectIdentifier = "1.2.840.113549.1.1.1".parse().unwrap();
        let algorithm = AlgorithmIdentifier::new(oid);
        let algorithm_elm = algorithm.encode().unwrap();
        let element = Element::Sequence(vec![
            algorithm_elm,
            Element::OctetString(tsumiki_asn1::OctetString::from(vec![1, 2, 3])),
        ]);

        let result: Result<SubjectPublicKeyInfo> = element.decode();
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(Error::SubjectPublicKeyInfoExpectedBitString)
        ));
    }
}
