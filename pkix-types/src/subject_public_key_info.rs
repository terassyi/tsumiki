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

use asn1::{BitString, Element};
use serde::{Deserialize, Serialize};
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};

use crate::algorithm::AlgorithmIdentifier;
use crate::error::{Error, Result};
use crate::OidName;

/// Subject Public Key Info
///
/// Contains the algorithm identifier and the public key itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectPublicKeyInfo {
    algorithm: AlgorithmIdentifier,
    subject_public_key: BitString,
}

impl SubjectPublicKeyInfo {
    /// Create a new SubjectPublicKeyInfo
    pub fn new(algorithm: AlgorithmIdentifier, subject_public_key: BitString) -> Self {
        Self {
            algorithm,
            subject_public_key,
        }
    }

    /// Get the algorithm identifier
    pub fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.algorithm
    }

    /// Get the subject public key
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
    use asn1::ObjectIdentifier;

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
            Element::OctetString(asn1::OctetString::from(vec![1, 2, 3])),
        ]);

        let result: Result<SubjectPublicKeyInfo> = element.decode();
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(Error::SubjectPublicKeyInfoExpectedBitString)
        ));
    }
}
