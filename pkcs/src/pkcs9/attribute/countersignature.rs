//! PKCS#9 countersignature attribute (OID: 1.2.840.113549.1.9.6)
//!
//! Defined in RFC 2985 Section 5.3.6 and RFC 5652 Section 11.4
//!
//! ```asn1
//! countersignature ATTRIBUTE ::= {
//!     WITH SYNTAX SignerInfo
//!     ID pkcs-9-at-counterSignature
//! }
//!
//! SignerInfo ::= SEQUENCE {
//!     version CMSVersion,
//!     sid SignerIdentifier,
//!     digestAlgorithm DigestAlgorithmIdentifier,
//!     signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
//!     signatureAlgorithm SignatureAlgorithmIdentifier,
//!     signature SignatureValue,
//!     unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL
//! }
//!
//! CMSVersion ::= INTEGER { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }
//!
//! SignerIdentifier ::= CHOICE {
//!     issuerAndSerialNumber IssuerAndSerialNumber,
//!     subjectKeyIdentifier [0] SubjectKeyIdentifier
//! }
//!
//! IssuerAndSerialNumber ::= SEQUENCE {
//!     issuer Name,
//!     serialNumber CertificateSerialNumber
//! }
//!
//! DigestAlgorithmIdentifier ::= AlgorithmIdentifier
//! SignatureAlgorithmIdentifier ::= AlgorithmIdentifier
//! SignatureValue ::= OCTET STRING
//! ```
//!
//! The countersignature attribute type is used to countersign (i.e., sign
//! the signature of) a message. This provides a timestamp or additional
//! authentication to an existing signature.

use num_bigint::BigInt;
use serde::{Deserialize, Serialize};
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};
use tsumiki_asn1::{ASN1Object, Element, Integer, OctetString};
use tsumiki_pkix_types::{AlgorithmIdentifier, CertificateSerialNumber, KeyIdentifier, Name};

use crate::pkcs9::RawAttribute;
use crate::pkcs9::error::{Error, Result};

use super::Attribute;

/// DigestAlgorithmIdentifier is an alias for AlgorithmIdentifier
/// used to identify digest (hash) algorithms in CMS/PKCS#7
pub type DigestAlgorithmIdentifier = AlgorithmIdentifier;

/// SignatureAlgorithmIdentifier is an alias for AlgorithmIdentifier
/// used to identify signature algorithms in CMS/PKCS#7
pub type SignatureAlgorithmIdentifier = AlgorithmIdentifier;

/// SignedAttributes is a SET of attributes that are signed
/// Defined in RFC 5652 Section 5.3
pub type SignedAttributes = Vec<RawAttribute>;

/// UnsignedAttributes is a SET of attributes that are not signed
/// Defined in RFC 5652 Section 5.3
pub type UnsignedAttributes = Vec<RawAttribute>;

/// CMS/PKCS#7 Version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CMSVersion {
    V0 = 0,
    V1 = 1,
    V2 = 2,
    V3 = 3,
    V4 = 4,
    V5 = 5,
}

impl From<CMSVersion> for i64 {
    fn from(v: CMSVersion) -> Self {
        v as i64
    }
}

impl TryFrom<i64> for CMSVersion {
    type Error = Error;

    fn try_from(value: i64) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(CMSVersion::V0),
            1 => Ok(CMSVersion::V1),
            2 => Ok(CMSVersion::V2),
            3 => Ok(CMSVersion::V3),
            4 => Ok(CMSVersion::V4),
            5 => Ok(CMSVersion::V5),
            _ => Err(Error::CountersignatureInvalidVersion),
        }
    }
}

impl TryFrom<&Integer> for CMSVersion {
    type Error = Error;

    fn try_from(value: &Integer) -> std::result::Result<Self, Self::Error> {
        let i64_val = value
            .to_i64()
            .ok_or(Error::CountersignatureInvalidVersion)?;
        CMSVersion::try_from(i64_val)
    }
}

/// SignerIdentifier
///
/// A CHOICE between IssuerAndSerialNumber and SubjectKeyIdentifier
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignerIdentifier {
    /// IssuerAndSerialNumber
    IssuerAndSerialNumber(IssuerAndSerialNumber),
    /// SubjectKeyIdentifier \[0\] IMPLICIT
    SubjectKeyIdentifier(KeyIdentifier),
}

/// IssuerAndSerialNumber
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerAndSerialNumber {
    issuer: Name,
    serial_number: CertificateSerialNumber,
}

impl IssuerAndSerialNumber {
    pub fn new(issuer: Name, serial_number: CertificateSerialNumber) -> Self {
        Self {
            issuer,
            serial_number,
        }
    }

    pub fn issuer(&self) -> &Name {
        &self.issuer
    }

    pub fn serial_number(&self) -> &CertificateSerialNumber {
        &self.serial_number
    }
}

impl DecodableFrom<Element> for IssuerAndSerialNumber {}

impl Decoder<Element, IssuerAndSerialNumber> for Element {
    type Error = Error;

    fn decode(&self) -> Result<IssuerAndSerialNumber> {
        let Element::Sequence(elements) = self else {
            return Err(Error::CountersignatureExpectedSequence(format!(
                "IssuerAndSerialNumber: got {:?}",
                self
            )));
        };

        let (issuer, serial_number) = match elements.as_slice() {
            [issuer_elm, Element::Integer(int)] => {
                let issuer: Name = issuer_elm.decode().map_err(Error::from)?;
                let serial_number = CertificateSerialNumber::from(int.clone());
                (issuer, serial_number)
            }
            [_, _] => {
                return Err(Error::CountersignatureExpectedType {
                    expected: "INTEGER for serial number",
                    actual: format!("{:?}", elements[1]),
                });
            }
            _ => {
                return Err(Error::CountersignatureInvalidElementCount {
                    expected: 2,
                    actual: elements.len(),
                });
            }
        };

        Ok(IssuerAndSerialNumber {
            issuer,
            serial_number,
        })
    }
}

impl EncodableTo<IssuerAndSerialNumber> for Element {}

impl Encoder<IssuerAndSerialNumber, Element> for IssuerAndSerialNumber {
    type Error = Error;

    fn encode(&self) -> Result<Element> {
        let issuer_elm = self.issuer.encode().map_err(Error::from)?;
        let serial_elm = Element::Integer(self.serial_number.as_ref().clone());
        Ok(Element::Sequence(vec![issuer_elm, serial_elm]))
    }
}

impl DecodableFrom<Element> for SignerIdentifier {}

impl Decoder<Element, SignerIdentifier> for Element {
    type Error = Error;

    fn decode(&self) -> Result<SignerIdentifier> {
        match self {
            Element::Sequence(_) => {
                let issuer_and_serial: IssuerAndSerialNumber = self.decode()?;
                Ok(SignerIdentifier::IssuerAndSerialNumber(issuer_and_serial))
            }
            Element::ContextSpecific {
                slot: 0, element, ..
            } => {
                // SubjectKeyIdentifier [0] IMPLICIT
                let Element::OctetString(octet_string) = element.as_ref() else {
                    return Err(Error::CountersignatureExpectedType {
                        expected: "OCTET STRING for SubjectKeyIdentifier",
                        actual: format!("{:?}", element),
                    });
                };
                Ok(SignerIdentifier::SubjectKeyIdentifier(octet_string.clone()))
            }
            _ => Err(Error::CountersignatureExpectedType {
                expected: "SEQUENCE or [0] IMPLICIT for SignerIdentifier",
                actual: format!("{:?}", self),
            }),
        }
    }
}

impl EncodableTo<SignerIdentifier> for Element {}

impl Encoder<SignerIdentifier, Element> for SignerIdentifier {
    type Error = Error;

    fn encode(&self) -> Result<Element> {
        match self {
            SignerIdentifier::IssuerAndSerialNumber(issuer_and_serial) => {
                issuer_and_serial.encode()
            }
            SignerIdentifier::SubjectKeyIdentifier(key_id) => Ok(Element::ContextSpecific {
                slot: 0,
                constructed: false,
                element: Box::new(Element::OctetString(key_id.clone())),
            }),
        }
    }
}

/// SignerInfo
///
/// Contains information about a signature
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerInfo {
    version: CMSVersion,
    sid: SignerIdentifier,
    digest_algorithm: DigestAlgorithmIdentifier,
    signed_attrs: Option<SignedAttributes>,
    signature_algorithm: SignatureAlgorithmIdentifier,
    signature: OctetString,
    unsigned_attrs: Option<UnsignedAttributes>,
}

impl SignerInfo {
    pub fn new(
        version: CMSVersion,
        sid: SignerIdentifier,
        digest_algorithm: DigestAlgorithmIdentifier,
        signature_algorithm: SignatureAlgorithmIdentifier,
        signature: OctetString,
    ) -> Self {
        Self {
            version,
            sid,
            digest_algorithm,
            signed_attrs: None,
            signature_algorithm,
            signature,
            unsigned_attrs: None,
        }
    }

    pub fn with_signed_attrs(mut self, signed_attrs: SignedAttributes) -> Self {
        self.signed_attrs = Some(signed_attrs);
        self
    }

    pub fn with_unsigned_attrs(mut self, unsigned_attrs: UnsignedAttributes) -> Self {
        self.unsigned_attrs = Some(unsigned_attrs);
        self
    }

    pub fn version(&self) -> CMSVersion {
        self.version
    }

    pub fn sid(&self) -> &SignerIdentifier {
        &self.sid
    }

    pub fn digest_algorithm(&self) -> &DigestAlgorithmIdentifier {
        &self.digest_algorithm
    }

    pub fn signed_attrs(&self) -> Option<&[RawAttribute]> {
        self.signed_attrs.as_deref()
    }

    pub fn signature_algorithm(&self) -> &SignatureAlgorithmIdentifier {
        &self.signature_algorithm
    }

    pub fn signature(&self) -> &OctetString {
        &self.signature
    }

    pub fn unsigned_attrs(&self) -> Option<&[RawAttribute]> {
        self.unsigned_attrs.as_deref()
    }
}

impl DecodableFrom<Element> for SignerInfo {}

impl Decoder<Element, SignerInfo> for Element {
    type Error = Error;

    fn decode(&self) -> Result<SignerInfo> {
        let Element::Sequence(elements) = self else {
            return Err(Error::CountersignatureExpectedSequence(format!(
                "SignerInfo: got {:?}",
                self
            )));
        };

        if elements.len() < 5 {
            return Err(Error::CountersignatureInvalidElementCount {
                expected: 5,
                actual: elements.len(),
            });
        }

        let mut iter = elements.iter();

        // version
        let version_elm = iter
            .next()
            .ok_or(Error::CountersignatureMissingField("version"))?;
        let Element::Integer(version_int) = version_elm else {
            return Err(Error::CountersignatureExpectedType {
                expected: "INTEGER for version",
                actual: format!("{:?}", version_elm),
            });
        };
        let version = CMSVersion::try_from(version_int)?;

        // sid
        let sid_elm = iter
            .next()
            .ok_or(Error::CountersignatureMissingField("sid"))?;
        let sid: SignerIdentifier = sid_elm.decode()?;

        // digestAlgorithm
        let digest_alg_elm = iter
            .next()
            .ok_or(Error::CountersignatureMissingField("digestAlgorithm"))?;
        let digest_algorithm: AlgorithmIdentifier = digest_alg_elm.decode().map_err(Error::from)?;

        // Parse optional signed attributes, signature algorithm, signature, and optional unsigned attributes
        let mut signed_attrs = None;

        // Peek at next element to check for signed attributes [0] IMPLICIT
        let next_elm = iter.next().ok_or(Error::CountersignatureMissingField(
            "signatureAlgorithm or signature",
        ))?;

        let (signature_algorithm, mut remaining_iter);
        if let Element::ContextSpecific {
            slot: 0, element, ..
        } = next_elm
        {
            let Element::Set(attrs_set) = element.as_ref() else {
                return Err(Error::CountersignatureExpectedType {
                    expected: "SET for signed attributes",
                    actual: format!("{:?}", element),
                });
            };
            let attrs = attrs_set
                .iter()
                .map(|e| e.decode())
                .collect::<Result<Vec<_>>>()?;
            signed_attrs = Some(attrs);

            // Next element is signatureAlgorithm
            let sig_alg_elm = iter
                .next()
                .ok_or(Error::CountersignatureMissingField("signatureAlgorithm"))?;
            signature_algorithm = sig_alg_elm.decode().map_err(Error::from)?;
            remaining_iter = iter;
        } else {
            // next_elm is signatureAlgorithm
            signature_algorithm = next_elm.decode().map_err(Error::from)?;
            remaining_iter = iter;
        }

        // signature
        let sig_elm = remaining_iter
            .next()
            .ok_or(Error::CountersignatureMissingField("signature"))?;
        let Element::OctetString(signature) = sig_elm else {
            return Err(Error::CountersignatureExpectedType {
                expected: "OCTET STRING for signature",
                actual: format!("{:?}", sig_elm),
            });
        };

        // Optional unsigned attributes [1] IMPLICIT
        let mut unsigned_attrs = None;
        if let Some(Element::ContextSpecific {
            slot: 1, element, ..
        }) = remaining_iter.next()
        {
            let Element::Set(attrs_set) = element.as_ref() else {
                return Err(Error::CountersignatureExpectedType {
                    expected: "SET for unsigned attributes",
                    actual: format!("{:?}", element),
                });
            };
            let attrs = attrs_set
                .iter()
                .map(|e| e.decode())
                .collect::<Result<Vec<_>>>()?;
            unsigned_attrs = Some(attrs);
        }

        Ok(SignerInfo {
            version,
            sid,
            digest_algorithm,
            signed_attrs,
            signature_algorithm,
            signature: signature.to_owned(),
            unsigned_attrs,
        })
    }
}

impl EncodableTo<SignerInfo> for Element {}

impl Encoder<SignerInfo, Element> for SignerInfo {
    type Error = Error;

    fn encode(&self) -> Result<Element> {
        let mut elements = vec![
            Element::Integer(Integer::from(BigInt::from(self.version as i64))),
            self.sid.encode()?,
            self.digest_algorithm.encode().map_err(Error::from)?,
        ];

        // Add signed attributes if present
        if let Some(signed_attrs) = &self.signed_attrs {
            let attrs_elements = signed_attrs
                .iter()
                .map(|attr| attr.encode())
                .collect::<Result<Vec<_>>>()?;
            elements.push(Element::ContextSpecific {
                slot: 0,
                constructed: true,
                element: Box::new(Element::Set(attrs_elements)),
            });
        }

        // Add signature algorithm and signature
        elements.push(self.signature_algorithm.encode().map_err(Error::from)?);
        elements.push(Element::OctetString(self.signature.clone()));

        // Add unsigned attributes if present
        if let Some(unsigned_attrs) = &self.unsigned_attrs {
            let attrs_elements = unsigned_attrs
                .iter()
                .map(|attr| attr.encode())
                .collect::<Result<Vec<_>>>()?;
            elements.push(Element::ContextSpecific {
                slot: 1,
                constructed: true,
                element: Box::new(Element::Set(attrs_elements)),
            });
        }

        Ok(Element::Sequence(elements))
    }
}

/// Countersignature attribute
///
/// Contains a SignerInfo structure that countersigns an existing signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Countersignature {
    signer_info: SignerInfo,
}

impl Countersignature {
    /// Create a new Countersignature with a SignerInfo
    pub fn new(signer_info: SignerInfo) -> Self {
        Self { signer_info }
    }

    /// Get the SignerInfo
    pub fn signer_info(&self) -> &SignerInfo {
        &self.signer_info
    }
}

impl Attribute for Countersignature {
    /// OID for countersignature: 1.2.840.113549.1.9.6
    const OID: &'static str = "1.2.840.113549.1.9.6";

    fn parse(values: &OctetString) -> Result<Self> {
        // Parse the SET OF SignerInfo
        let asn1_obj = ASN1Object::try_from(values).map_err(Error::from)?;

        let elements = asn1_obj.elements();
        let first_element = elements
            .first()
            .ok_or(Error::AttributeEmptyAsn1Object("countersignature"))?;

        // The first element should be a SET
        let Element::Set(set) = first_element else {
            return Err(Error::CountersignatureExpectedType {
                expected: "SET for countersignature values",
                actual: format!("{:?}", first_element),
            });
        };

        // Get the first SignerInfo from the SET
        let signer_info_elm = set
            .first()
            .ok_or(Error::AttributeEmptyValuesSet("countersignature"))?;

        // SignerInfo must be a SEQUENCE
        if !matches!(signer_info_elm, Element::Sequence(_)) {
            return Err(Error::CountersignatureExpectedSequence(format!(
                "SignerInfo: got {:?}",
                signer_info_elm
            )));
        }

        Ok(Self {
            signer_info: signer_info_elm.decode()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::str::FromStr;
    use tsumiki::encoder::Encoder;
    use tsumiki_asn1::ObjectIdentifier;
    use tsumiki_der::Der;

    #[rstest]
    #[case(Integer::from(vec![0u8]), CMSVersion::V0)]
    #[case(Integer::from(vec![1u8]), CMSVersion::V1)]
    #[case(Integer::from(vec![5u8]), CMSVersion::V5)]
    fn test_cms_version_from_integer(#[case] input: Integer, #[case] expected: CMSVersion) {
        assert_eq!(CMSVersion::try_from(&input).unwrap(), expected);
    }

    #[rstest]
    #[case(CertificateSerialNumber::from(Integer::from(vec![42])))]
    #[case(CertificateSerialNumber::from(Integer::from(vec![1, 2, 3])))]
    #[case(CertificateSerialNumber::from(Integer::from(vec![255, 255])))]
    fn test_issuer_and_serial_number_round_trip(#[case] input: CertificateSerialNumber) {
        let issuer = Name::new(vec![]);

        let ian = IssuerAndSerialNumber::new(issuer, input);
        let encoded = ian.encode().unwrap();
        let decoded: IssuerAndSerialNumber = encoded.decode().unwrap();

        assert_eq!(decoded, ian);
    }

    #[rstest]
    #[case(IssuerAndSerialNumber::new(
        Name::new(vec![]),
        CertificateSerialNumber::from(Integer::from(vec![1]))
    ))]
    #[case(IssuerAndSerialNumber::new(
        Name::new(vec![]),
        CertificateSerialNumber::from(Integer::from(vec![42]))
    ))]
    #[case(IssuerAndSerialNumber::new(
        Name::new(vec![]),
        CertificateSerialNumber::from(Integer::from(vec![1, 2, 3, 4, 5]))
    ))]
    fn test_signer_identifier_issuer_and_serial(#[case] input: IssuerAndSerialNumber) {
        let sid = SignerIdentifier::IssuerAndSerialNumber(input.clone());
        let encoded = sid.encode().unwrap();
        let decoded: SignerIdentifier = encoded.decode().unwrap();

        match decoded {
            SignerIdentifier::IssuerAndSerialNumber(decoded_ian) => {
                assert_eq!(decoded_ian, input);
            }
            _ => panic!("Expected IssuerAndSerialNumber"),
        }
    }

    #[rstest]
    #[case(KeyIdentifier::from(OctetString::from(vec![0xAA, 0xBB, 0xCC])))]
    #[case(KeyIdentifier::from(OctetString::from(vec![0x01, 0x02, 0x03])))]
    #[case(KeyIdentifier::from(OctetString::from(vec![0xFF; 20])))]
    fn test_signer_identifier_subject_key_identifier(#[case] input: KeyIdentifier) {
        let sid = SignerIdentifier::SubjectKeyIdentifier(input.clone());
        let encoded = sid.encode().unwrap();
        let decoded: SignerIdentifier = encoded.decode().unwrap();

        match decoded {
            SignerIdentifier::SubjectKeyIdentifier(decoded_kid) => {
                assert_eq!(decoded_kid, input);
            }
            _ => panic!("Expected SubjectKeyIdentifier"),
        }
    }

    #[rstest]
    #[case(CMSVersion::V0, "2.16.840.1.101.3.4.2.1", "1.2.840.113549.1.1.1")]
    #[case(CMSVersion::V1, "2.16.840.1.101.3.4.2.1", "1.2.840.113549.1.1.1")]
    #[case(CMSVersion::V3, "2.16.840.1.101.3.4.2.2", "1.2.840.113549.1.1.11")]
    fn test_signer_info_round_trip(
        #[case] input_version: CMSVersion,
        #[case] input_digest_oid: &str,
        #[case] input_sig_oid: &str,
    ) {
        let sid = SignerIdentifier::SubjectKeyIdentifier(OctetString::from(vec![1, 2, 3]));
        let digest_alg =
            AlgorithmIdentifier::new(ObjectIdentifier::from_str(input_digest_oid).unwrap());
        let sig_alg = AlgorithmIdentifier::new(ObjectIdentifier::from_str(input_sig_oid).unwrap());
        let signature = OctetString::from(vec![0xAB; 32]);

        let signer_info = SignerInfo::new(input_version, sid, digest_alg, sig_alg, signature);

        let encoded = signer_info.encode().unwrap();
        let decoded: SignerInfo = encoded.decode().unwrap();

        assert_eq!(decoded.version(), input_version);
        assert_eq!(decoded.signature(), signer_info.signature());
    }

    #[rstest]
    #[case(
        SignerInfo::new(
            CMSVersion::V1,
            SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber::new(
                Name::new(vec![]),
                CertificateSerialNumber::from(Integer::from(vec![42]))
            )),
            AlgorithmIdentifier::new(ObjectIdentifier::from_str("2.16.840.1.101.3.4.2.1").unwrap()),
            AlgorithmIdentifier::new(ObjectIdentifier::from_str("1.2.840.113549.1.1.1").unwrap()),
            OctetString::from(vec![0x99; 32])
        ),
        CMSVersion::V1
    )]
    #[case(
        SignerInfo::new(
            CMSVersion::V3,
            SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber::new(
                Name::new(vec![]),
                CertificateSerialNumber::from(Integer::from(vec![1, 2, 3]))
            )),
            AlgorithmIdentifier::new(ObjectIdentifier::from_str("2.16.840.1.101.3.4.2.1").unwrap()),
            AlgorithmIdentifier::new(ObjectIdentifier::from_str("1.2.840.113549.1.1.1").unwrap()),
            OctetString::from(vec![0x99; 32])
        ),
        CMSVersion::V3
    )]
    fn test_countersignature_parse(
        #[case] input: SignerInfo,
        #[case] expected_version: CMSVersion,
    ) {
        let signer_info_elm = input.encode().unwrap();

        let set = Element::Set(vec![signer_info_elm]);
        let asn1_obj = ASN1Object::new(vec![set]);

        let der: Der = asn1_obj.encode().expect("Failed to encode");
        let der_bytes = der.encode().expect("Failed to encode to bytes");
        let values = OctetString::from(der_bytes);

        let parsed = Countersignature::parse(&values).expect("Failed to parse");
        assert_eq!(parsed.signer_info().version(), expected_version);
    }
}
