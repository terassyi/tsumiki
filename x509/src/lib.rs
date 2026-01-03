use asn1::{ASN1Object, BitString, Element, Integer, ObjectIdentifier};
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use tsumiki::decoder::{DecodableFrom, Decoder};

use crate::{
    error::Error,
    extensions::{Extensions, RawExtensions},
};

pub(crate) mod error;
pub mod extensions;
mod types;

// Re-export public types
pub use types::{DirectoryString, Name};

/*
https://datatracker.ietf.org/doc/html/rfc5280#section-4.1

Certificate  ::=  SEQUENCE  {
    tbsCertificate       TBSCertificate,
    signatureAlgorithm   AlgorithmIdentifier,
    signatureValue       BIT STRING
}
 */

#[derive(Debug, Deserialize)]
pub(crate) struct Certificate {
    tbs_certificate: TBSCertificate,
    signature_algorithm: AlgorithmIdentifier,
    signature_value: BitString, // BIT STRING
}

impl Serialize for Certificate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("Certificate", 3)?;

        // Serialize TBSCertificate with RawExtensions
        let tbs = SerializableTBSCertificate::try_from(&self.tbs_certificate)
            .map_err(serde::ser::Error::custom)?;
        state.serialize_field("tbs_certificate", &tbs)?;

        state.serialize_field("signature_algorithm", &self.signature_algorithm)?;
        state.serialize_field("signature_value", &self.signature_value)?;
        state.end()
    }
}

impl Certificate {
    /// Get a specific extension by type
    ///
    /// # Example
    /// ```ignore
    /// let basic_constraints = cert.extension::<BasicConstraints>()?;
    /// ```
    pub fn extension<T: extensions::StandardExtension>(&self) -> Result<Option<T>, Error> {
        if let Some(ref exts) = self.tbs_certificate.extensions {
            exts.extension::<T>()
        } else {
            Ok(None)
        }
    }

    /// Get the TBS (To Be Signed) certificate
    pub fn tbs_certificate(&self) -> &TBSCertificate {
        &self.tbs_certificate
    }

    /// Get the signature algorithm
    pub fn signature_algorithm(&self) -> &AlgorithmIdentifier {
        &self.signature_algorithm
    }

    /// Get the signature value
    pub fn signature_value(&self) -> &BitString {
        &self.signature_value
    }

    /// Get a list of OIDs for all extensions present in the certificate
    ///
    /// Returns None if the certificate has no extensions (e.g., V1 certificates).
    /// This is useful to check which extensions are present without parsing them.
    ///
    /// # Example
    /// ```ignore
    /// if let Some(oids) = cert.extension_oids() {
    ///     for oid in oids {
    ///         println!("Extension present: {}", oid);
    ///     }
    /// }
    /// ```
    pub fn extension_oids(&self) -> Option<Vec<ObjectIdentifier>> {
        self.tbs_certificate.extensions.as_ref().map(|exts| {
            exts.extensions()
                .iter()
                .map(|ext| ext.oid().clone())
                .collect()
        })
    }
}

impl DecodableFrom<ASN1Object> for Certificate {}

impl Decoder<ASN1Object, Certificate> for ASN1Object {
    type Error = Error;

    fn decode(&self) -> Result<Certificate, Self::Error> {
        let elements = self.elements();
        if elements.len() != 1 {
            return Err(Error::InvalidCertificate(format!(
                "expected 1 top-level element in ASN1Object, got {}",
                elements.len()
            )));
        }

        elements[0].decode()
    }
}

impl DecodableFrom<Element> for Certificate {}

impl Decoder<Element, Certificate> for Element {
    type Error = Error;

    fn decode(&self) -> Result<Certificate, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                if elements.len() != 3 {
                    return Err(Error::InvalidCertificate(format!(
                        "expected 3 elements in Certificate sequence, got {}",
                        elements.len()
                    )));
                }

                // TBSCertificate
                let tbs_certificate: TBSCertificate = elements[0].decode()?;

                // signatureAlgorithm
                let signature_algorithm: AlgorithmIdentifier = elements[1].decode()?;

                // signatureValue (BIT STRING)
                let signature_value = if let Element::BitString(bs) = &elements[2] {
                    bs.clone()
                } else {
                    return Err(Error::InvalidCertificate(
                        "expected BitString for signature value".to_string(),
                    ));
                };

                Ok(Certificate {
                    tbs_certificate,
                    signature_algorithm,
                    signature_value,
                })
            }
            _ => Err(Error::InvalidCertificate(
                "expected Sequence for Certificate".to_string(),
            )),
        }
    }
}

/*
TBSCertificate  ::=  SEQUENCE  {
     version         [0]  EXPLICIT Version DEFAULT v1,
     serialNumber         CertificateSerialNumber,
     signature            AlgorithmIdentifier,
     issuer               Name,
     validity             Validity,
     subject              Name,
     subjectPublicKeyInfo SubjectPublicKeyInfo,
     issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                          -- If present, version MUST be v2 or v3
     subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                              -- If present, version MUST be v2 or v3
     extensions      [3]  EXPLICIT Extensions OPTIONAL
                              -- If present, version MUST be v3
}
 */

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct TBSCertificate {
    version: Version,
    serial_number: CertificateSerialNumber,
    signature: AlgorithmIdentifier,
    issuer: Name,
    validity: Validity,
    subject: Name,
    subject_public_key_info: SubjectPublicKeyInfo,
    issuer_unique_id: Option<UniqueIdentifier>,
    subject_unique_id: Option<UniqueIdentifier>,
    extensions: Option<Extensions>,
}

impl TBSCertificate {
    /// Get the extensions
    pub fn extensions(&self) -> Option<&Extensions> {
        self.extensions.as_ref()
    }
}

impl DecodableFrom<Element> for TBSCertificate {}

impl Decoder<Element, TBSCertificate> for Element {
    type Error = Error;

    fn decode(&self) -> Result<TBSCertificate, Self::Error> {
        let Element::Sequence(elements) = self else {
            return Err(Error::InvalidTBSCertificate(
                "expected Sequence for TBSCertificate".to_string(),
            ));
        };

        // V1 certificates have 6 required fields (no version field)
        // V2/V3 certificates can have up to 10 fields (version + 6 required + 3 optional)
        if elements.len() < 6 || elements.len() > 10 {
            return Err(Error::InvalidTBSCertificate(format!(
                "expected 6-10 elements in TBSCertificate sequence, got {}",
                elements.len()
            )));
        }

        let mut iter = elements.iter();

        // version [0] EXPLICIT Version DEFAULT v1
        let version =
            if let Some(Element::ContextSpecific { slot: 0, .. }) = iter.as_slice().first() {
                if let Some(elem) = iter.next() {
                    elem.decode()?
                } else {
                    return Err(Error::InvalidTBSCertificate("missing version".to_string()));
                }
            } else {
                Version::V1 // DEFAULT v1
            };

        // serialNumber
        let serial_number = if let Some(elem) = iter.next() {
            elem.decode()?
        } else {
            return Err(Error::InvalidTBSCertificate(
                "missing serialNumber".to_string(),
            ));
        };

        // signature
        let signature = if let Some(elem) = iter.next() {
            elem.decode()?
        } else {
            return Err(Error::InvalidTBSCertificate(
                "missing signature".to_string(),
            ));
        };

        // issuer
        let issuer = if let Some(elem) = iter.next() {
            elem.decode()?
        } else {
            return Err(Error::InvalidTBSCertificate("missing issuer".to_string()));
        };

        // validity
        let validity = if let Some(elem) = iter.next() {
            elem.decode()?
        } else {
            return Err(Error::InvalidTBSCertificate("missing validity".to_string()));
        };

        // subject
        let subject = if let Some(elem) = iter.next() {
            elem.decode()?
        } else {
            return Err(Error::InvalidTBSCertificate("missing subject".to_string()));
        };

        // subjectPublicKeyInfo
        let subject_public_key_info = if let Some(elem) = iter.next() {
            elem.decode()?
        } else {
            return Err(Error::InvalidTBSCertificate(
                "missing subjectPublicKeyInfo".to_string(),
            ));
        };

        // Optional fields: issuerUniqueID [1], subjectUniqueID [2], extensions [3]
        let mut issuer_unique_id = None;
        let mut subject_unique_id = None;
        let mut extensions = None;

        while let Some(elem) = iter.next() {
            match elem {
                Element::ContextSpecific { slot: 1, .. } if issuer_unique_id.is_none() => {
                    issuer_unique_id = Some(elem.decode()?);
                }
                Element::ContextSpecific { slot: 2, .. } if subject_unique_id.is_none() => {
                    subject_unique_id = Some(elem.decode()?);
                }
                Element::ContextSpecific { slot: 3, .. } if extensions.is_none() => {
                    extensions = Some(elem.decode()?);
                }
                _ => {
                    return Err(Error::InvalidTBSCertificate(format!(
                        "unexpected element in TBSCertificate: {:?}",
                        elem
                    )));
                }
            }
        }

        Ok(TBSCertificate {
            version,
            serial_number,
            signature,
            issuer,
            validity,
            subject,
            subject_public_key_info,
            issuer_unique_id,
            subject_unique_id,
            extensions,
        })
    }
}

// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.1.2
/*
AlgorithmIdentifier  ::=  SEQUENCE  {
    algorithm               OBJECT IDENTIFIER,
    parameters              ANY DEFINED BY algorithm OPTIONAL
}
 */

/// Parameters field in AlgorithmIdentifier
///
/// Wrapped in Option:
/// - None: Field not present (OPTIONAL field omitted, 0 bytes) - Absent
/// - Some(Data(Element::Null)): Explicit NULL value - Common for RSA
/// - Some(Data(Element::ObjectIdentifier)): OID - Used for ECDSA curve parameters
/// - Some(Data(Element::Sequence)): Complex SEQUENCE structure - Used for DSA, RSASSA-PSS
/// - Some(Data(Element::OctetString)): Arbitrary octet string data
/// - Some(Elm(other)): Any other ASN.1 element
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AlgorithmParameters {
    Null,         // Explicit NULL (05 00)
    Elm(Element), // Any other ASN.1 element
}

impl Serialize for AlgorithmParameters {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            AlgorithmParameters::Null => serializer.serialize_str("NULL"),
            AlgorithmParameters::Elm(elm) => {
                // TODO: Serialize based on the actual element type
                let type_name = match elm {
                    Element::Boolean(_) => "Boolean",
                    Element::Integer(_) => "Integer",
                    Element::BitString(_) => "BitString",
                    Element::OctetString(_) => "OctetString",
                    Element::Null => "Null",
                    Element::ObjectIdentifier(_) => "ObjectIdentifier",
                    Element::UTF8String(_) => "UTF8String",
                    Element::Sequence(_) => "Sequence",
                    Element::Set(_) => "Set",
                    Element::PrintableString(_) => "PrintableString",
                    Element::IA5String(_) => "IA5String",
                    Element::UTCTime(_) => "UTCTime",
                    Element::GeneralizedTime(_) => "GeneralizedTime",
                    Element::ContextSpecific { .. } => "ContextSpecific",
                    Element::Unimplemented(_) => "Unimplemented",
                };
                serializer.serialize_str(type_name)
            }
        }
    }
}

impl<'de> Deserialize<'de> for AlgorithmParameters {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Err(serde::de::Error::custom(
            "AlgorithmParameters deserialization not supported",
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AlgorithmIdentifier {
    algorithm: ObjectIdentifier, // OBJECT IDENTIFIER
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<AlgorithmParameters>,
}

impl DecodableFrom<Element> for AlgorithmIdentifier {}

impl Decoder<Element, AlgorithmIdentifier> for Element {
    type Error = Error;

    fn decode(&self) -> Result<AlgorithmIdentifier, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                if elements.is_empty() || elements.len() > 2 {
                    return Err(Error::InvalidAlgorithmIdentifier(
                        "expected 1 or 2 elements in sequence".to_string(),
                    ));
                }

                let algorithm = if let Element::ObjectIdentifier(oid) = &elements[0] {
                    oid.clone()
                } else {
                    return Err(Error::InvalidAlgorithmIdentifier(
                        "expected ObjectIdentifier for algorithm".to_string(),
                    ));
                };

                let parameters = if elements.len() == 2 {
                    Some(match &elements[1] {
                        Element::Null => AlgorithmParameters::Null,
                        other => AlgorithmParameters::Elm(other.clone()),
                    })
                } else {
                    None
                };

                Ok(AlgorithmIdentifier {
                    algorithm,
                    parameters,
                })
            }
            _ => Err(Error::InvalidAlgorithmIdentifier(
                "expected Sequence for AlgorithmIdentifier".to_string(),
            )),
        }
    }
}

/*
Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }

CertificateSerialNumber  ::=  INTEGER


Time ::= CHOICE {
    utcTime        UTCTime,
    generalTime    GeneralizedTime
}

UniqueIdentifier  ::=  BIT STRING

SubjectPublicKeyInfo  ::=  SEQUENCE  {
    algorithm            AlgorithmIdentifier,
    subjectPublicKey     BIT STRING
}

Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
*/

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectPublicKeyInfo {
    algorithm: AlgorithmIdentifier,
    subject_public_key: BitString,
}

impl DecodableFrom<Element> for SubjectPublicKeyInfo {}

impl Decoder<Element, SubjectPublicKeyInfo> for Element {
    type Error = Error;

    fn decode(&self) -> Result<SubjectPublicKeyInfo, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                if elements.len() != 2 {
                    return Err(Error::InvalidSubjectPublicKeyInfo(format!(
                        "expected 2 elements in sequence, got {}",
                        elements.len()
                    )));
                }

                let algorithm = elements[0].decode().map_err(|e| {
                    Error::InvalidSubjectPublicKeyInfo(format!("failed to decode algorithm: {}", e))
                })?;

                let subject_public_key = if let Element::BitString(bit_string) = &elements[1] {
                    bit_string.clone()
                } else {
                    return Err(Error::InvalidSubjectPublicKeyInfo(
                        "expected BitString for subject public key".to_string(),
                    ));
                };

                Ok(SubjectPublicKeyInfo {
                    algorithm,
                    subject_public_key,
                })
            }
            _ => Err(Error::InvalidSubjectPublicKeyInfo(
                "expected Sequence".to_string(),
            )),
        }
    }
}

// UniqueIdentifier is a BIT STRING used in X.509 v2 certificates
// RFC 5280 Section 4.1.2.8: CAs conforming to this profile MUST NOT generate
// certificates with unique identifiers. This field is deprecated.
//
// Note: In TBSCertificate, these appear as context-specific tagged fields:
// - issuerUniqueID [1] IMPLICIT UniqueIdentifier OPTIONAL
// - subjectUniqueID [2] IMPLICIT UniqueIdentifier OPTIONAL
// The decoder must handle Element::ContextSpecific { slot: 1 or 2, element: BitString }
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UniqueIdentifier(BitString);

impl UniqueIdentifier {
    pub fn new(bit_string: BitString) -> Self {
        UniqueIdentifier(bit_string)
    }

    pub fn as_bit_string(&self) -> &BitString {
        &self.0
    }

    pub fn into_bit_string(self) -> BitString {
        self.0
    }
}

impl DecodableFrom<Element> for UniqueIdentifier {}

impl Decoder<Element, UniqueIdentifier> for Element {
    type Error = Error;

    fn decode(&self) -> Result<UniqueIdentifier, Self::Error> {
        // UniqueIdentifier appears as [1] IMPLICIT or [2] IMPLICIT UniqueIdentifier
        // IMPLICIT tagging means the element directly contains the BitString data
        match self {
            Element::ContextSpecific { slot, element } => {
                if *slot != 1 && *slot != 2 {
                    return Err(Error::InvalidUniqueIdentifier(format!(
                        "expected context-specific tag [1] or [2], got [{}]",
                        slot
                    )));
                }
                // IMPLICIT tagging: element is directly the BitString
                match element.as_ref() {
                    Element::BitString(bit_string) => Ok(UniqueIdentifier(bit_string.clone())),
                    _ => Err(Error::InvalidUniqueIdentifier(
                        "expected BitString inside context-specific tag".to_string(),
                    )),
                }
            }
            Element::BitString(bit_string) => Ok(UniqueIdentifier(bit_string.clone())), // Allow direct BitString for testing
            _ => Err(Error::InvalidUniqueIdentifier(
                "expected context-specific tag [1] or [2] or BitString for UniqueIdentifier"
                    .to_string(),
            )),
        }
    }
}

/*
Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension

Extension  ::=  SEQUENCE  {
    extnID      OBJECT IDENTIFIER,
    critical    BOOLEAN DEFAULT FALSE,
    extnValue   OCTET STRING
                -- contains the DER encoding of an ASN.1 value
                -- corresponding to the extension type identified
                -- by extnID
}
*/

// Version field in TBSCertificate
// RFC 5280: version [0] EXPLICIT Version DEFAULT v1
//
// Note: In TBSCertificate, this appears as a context-specific tagged field:
// - Element::ContextSpecific { slot: 0, element: Box<Element::Integer> }
// - If slot 0 is absent, defaults to V1
// - EXPLICIT tagging means the element is wrapped: [0] contains a full INTEGER
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) enum Version {
    V1 = 0,
    V2 = 1,
    V3 = 2,
}

impl DecodableFrom<Element> for Version {}

impl Decoder<Element, Version> for Element {
    type Error = Error;

    fn decode(&self) -> Result<Version, Self::Error> {
        // Version appears as [0] EXPLICIT Version in TBSCertificate
        // This means Element::ContextSpecific { slot: 0, element: Box<Element::Integer> }
        let integer = match self {
            Element::ContextSpecific { slot, element } => {
                if *slot != 0 {
                    return Err(Error::InvalidVersion(format!(
                        "expected context-specific tag [0], got [{}]",
                        slot
                    )));
                }
                // EXPLICIT tagging: element contains the full INTEGER
                match element.as_ref() {
                    Element::Integer(i) => i,
                    _ => {
                        return Err(Error::InvalidVersion(
                            "expected Integer inside context-specific tag [0]".to_string(),
                        ));
                    }
                }
            }
            _ => {
                return Err(Error::InvalidVersion(
                    "expected context-specific tag [0] for Version".to_string(),
                ));
            }
        };

        match u64::try_from(integer).map_err(Error::InvalidASN1)? {
            0 => Ok(Version::V1),
            1 => Ok(Version::V2),
            2 => Ok(Version::V3),
            v => Err(Error::InvalidVersion(format!(
                "unknown version value: {}",
                v
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CertificateSerialNumber {
    inner: Integer,
}

impl CertificateSerialNumber {
    /// Create from raw bytes (IMPLICIT INTEGER encoding)
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            inner: Integer::from(bytes),
        }
    }
}

impl From<Integer> for CertificateSerialNumber {
    fn from(inner: Integer) -> Self {
        Self { inner }
    }
}

impl DecodableFrom<Element> for CertificateSerialNumber {}

impl Decoder<Element, CertificateSerialNumber> for Element {
    type Error = Error;

    fn decode(&self) -> Result<CertificateSerialNumber, Self::Error> {
        match self {
            Element::Integer(i) => Ok(CertificateSerialNumber { inner: i.clone() }),
            _ => Err(Error::InvalidCertificateSerialNumber(
                "expected Integer for CertificateSerialNumber".to_string(),
            )),
        }
    }
}

// https://datatracker.ietf.org/doc/html/rfc5280#sectioで-4.1.2.5
/*
Validity ::= SEQUENCE {
    notBefore      Time,
    notAfter       Time
}
*/

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Validity {
    not_before: NaiveDateTime,
    not_after: NaiveDateTime,
}

impl DecodableFrom<Element> for Validity {}

impl Decoder<Element, Validity> for Element {
    type Error = Error;

    fn decode(&self) -> Result<Validity, Self::Error> {
        if let Element::Sequence(elements) = self {
            if elements.len() != 2 {
                return Err(Error::InvalidValidity(
                    "expected 2 elements in sequence".to_string(),
                ));
            }
            let not_before = match &elements[0] {
                Element::UTCTime(dt) => *dt,
                Element::GeneralizedTime(dt) => *dt,
                _ => return Err(Error::InvalidValidity("invalid notBefore time".to_string())),
            };
            let not_after = match &elements[1] {
                Element::UTCTime(dt) => *dt,
                Element::GeneralizedTime(dt) => *dt,
                _ => return Err(Error::InvalidValidity("invalid notAfter time".to_string())),
            };
            Ok(Validity {
                not_before,
                not_after,
            })
        } else {
            Err(Error::InvalidValidity(
                "expected sequence for Validity".to_string(),
            ))
        }
    }
}

// Serialization helper for TBSCertificate with parsed extensions

#[derive(Debug, Clone, Serialize)]
struct SerializableTBSCertificate {
    version: Version,
    serial_number: CertificateSerialNumber,
    signature: AlgorithmIdentifier,
    issuer: Name,
    validity: Validity,
    subject: Name,
    subject_public_key_info: SubjectPublicKeyInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer_unique_id: Option<UniqueIdentifier>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject_unique_id: Option<UniqueIdentifier>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extensions: Option<RawExtensions>,
}

impl TryFrom<&TBSCertificate> for SerializableTBSCertificate {
    type Error = Error;

    fn try_from(tbs: &TBSCertificate) -> Result<Self, Self::Error> {
        let extensions = if let Some(ref exts) = tbs.extensions {
            Some(RawExtensions::from_extensions(exts)?)
        } else {
            None
        };

        Ok(SerializableTBSCertificate {
            version: tbs.version,
            serial_number: tbs.serial_number.clone(),
            signature: tbs.signature.clone(),
            issuer: tbs.issuer.clone(),
            validity: tbs.validity.clone(),
            subject: tbs.subject.clone(),
            subject_public_key_info: tbs.subject_public_key_info.clone(),
            issuer_unique_id: tbs.issuer_unique_id.clone(),
            subject_unique_id: tbs.subject_unique_id.clone(),
            extensions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asn1::OctetString;
    use chrono::NaiveDateTime;
    use rstest::rstest;
    use std::str::FromStr;

    // AlgorithmIdentifier tests
    #[rstest(
        input,
        expected,
        // Test case: Algorithm without parameters (None = Absent)
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.840.113549.1.1.11").unwrap()), // sha256WithRSAEncryption
            ]),
            AlgorithmIdentifier {
                algorithm: ObjectIdentifier::from_str("1.2.840.113549.1.1.11").unwrap(),
                parameters: None,
            }
        ),
        // Test case: Algorithm with NULL parameters
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.840.113549.1.1.11").unwrap()),
                Element::Null,
            ]),
            AlgorithmIdentifier {
                algorithm: ObjectIdentifier::from_str("1.2.840.113549.1.1.11").unwrap(),
                parameters: Some(AlgorithmParameters::Null),
            }
        ),
        // Test case: Algorithm with OctetString parameters
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.840.10045.4.3.2").unwrap()), // ecdsa-with-SHA256
                Element::OctetString(asn1::OctetString::from(vec![0x01, 0x02, 0x03])),
            ]),
            AlgorithmIdentifier {
                algorithm: ObjectIdentifier::from_str("1.2.840.10045.4.3.2").unwrap(),
                parameters: Some(AlgorithmParameters::Elm(
                    Element::OctetString(asn1::OctetString::from(vec![0x01, 0x02, 0x03]))
                )),
            }
        ),
        // Test case: Algorithm with OID parameters - ECDSA curve
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.840.10045.2.1").unwrap()), // ecPublicKey
                Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.840.10045.3.1.7").unwrap()), // secp256r1 (prime256v1)
            ]),
            AlgorithmIdentifier {
                algorithm: ObjectIdentifier::from_str("1.2.840.10045.2.1").unwrap(),
                parameters: Some(AlgorithmParameters::Elm(
                    Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.840.10045.3.1.7").unwrap())
                )),
            }
        )
    )]
    fn test_algorithm_identifier_decode_success(input: Element, expected: AlgorithmIdentifier) {
        let result: AlgorithmIdentifier = input.decode().unwrap();
        assert_eq!(result, expected);
    }

    #[rstest(
        input,
        expected_error_variant,
        // Test case: Not a Sequence
        case(
            Element::Integer(Integer::from(vec![0x01])),
            "InvalidAlgorithmIdentifier"
        ),
        // Test case: Empty sequence
        case(
            Element::Sequence(vec![]),
            "InvalidAlgorithmIdentifier"
        ),
        // Test case: Too many elements
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.840.113549.1.1.11").unwrap()),
                Element::Null,
                Element::Integer(Integer::from(vec![0x01])),
            ]),
            "InvalidAlgorithmIdentifier"
        ),
        // Test case: First element is not ObjectIdentifier
        case(
            Element::Sequence(vec![
                Element::Integer(Integer::from(vec![0x01])),
            ]),
            "InvalidAlgorithmIdentifier"
        )
    )]
    fn test_algorithm_identifier_decode_failure(input: Element, expected_error_variant: &str) {
        let result: Result<AlgorithmIdentifier, Error> = input.decode();
        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_str = format!("{:?}", err);
        assert!(
            err_str.contains(expected_error_variant),
            "Expected error '{}', but got '{}'",
            expected_error_variant,
            err_str
        );
    }

    // Version tests
    #[rstest]
    #[case::v1(
        Element::ContextSpecific {
            slot: 0,
            element: Box::new(Element::Integer(Integer::from(vec![0x00])))
        },
        Version::V1
    )]
    #[case::v2(
        Element::ContextSpecific {
            slot: 0,
            element: Box::new(Element::Integer(Integer::from(vec![0x01])))
        },
        Version::V2
    )]
    #[case::v3(
        Element::ContextSpecific {
            slot: 0,
            element: Box::new(Element::Integer(Integer::from(vec![0x02])))
        },
        Version::V3
    )]
    fn test_version_decode_success(#[case] input: Element, #[case] expected: Version) {
        let result: Result<Version, Error> = input.decode();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected);
    }

    #[rstest]
    #[case::null(Element::Null, "InvalidVersion")]
    #[case::direct_integer(Element::Integer(Integer::from(vec![0x00])), "InvalidVersion")]
    #[case::invalid_version_value(
        Element::ContextSpecific {
            slot: 0,
            element: Box::new(Element::Integer(Integer::from(vec![0x03])))
        },
        "InvalidVersion"
    )]
    #[case::wrong_slot(
        Element::ContextSpecific {
            slot: 1,
            element: Box::new(Element::Integer(Integer::from(vec![0x00])))
        },
        "InvalidVersion"
    )]
    #[case::not_integer_inside(
        Element::ContextSpecific {
            slot: 0,
            element: Box::new(Element::Null)
        },
        "InvalidVersion"
    )]
    #[case::octet_string(Element::OctetString(asn1::OctetString::from(vec![0x00])), "InvalidVersion")]
    #[case::utf8_string(Element::UTF8String("v1".to_string()), "InvalidVersion")]
    fn test_version_decode_failure(#[case] input: Element, #[case] expected_error_variant: &str) {
        let result: Result<Version, Error> = input.decode();
        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_str = format!("{:?}", err);
        assert!(
            err_str.contains(expected_error_variant),
            "Expected error '{}', but got '{}'",
            expected_error_variant,
            err_str
        );
    }

    // CertificateSerialNumber tests
    #[rstest]
    #[case::simple_serial(
        Element::Integer(Integer::from(vec![0x01])),
        CertificateSerialNumber { inner: Integer::from(vec![0x01]) }
    )]
    #[case::medium_serial(
        Element::Integer(Integer::from(vec![0x01, 0x02, 0x03, 0x04])),
        CertificateSerialNumber { inner: Integer::from(vec![0x01, 0x02, 0x03, 0x04]) }
    )]
    #[case::long_serial(
        Element::Integer(Integer::from(vec![
            0x48, 0xc3, 0x54, 0x8e, 0x4a, 0x5e, 0xe7, 0x64,
            0x74, 0x7b, 0xb0, 0x50, 0xc9, 0x16, 0xea, 0xae,
            0x99, 0xd6, 0x8f, 0x82
        ])),
        CertificateSerialNumber { inner: Integer::from(vec![
            0x48, 0xc3, 0x54, 0x8e, 0x4a, 0x5e, 0xe7, 0x64,
            0x74, 0x7b, 0xb0, 0x50, 0xc9, 0x16, 0xea, 0xae,
            0x99, 0xd6, 0x8f, 0x82
        ]) }
    )]
    fn test_certificate_serial_number_decode_success(
        #[case] input: Element,
        #[case] expected: CertificateSerialNumber,
    ) {
        let result: Result<CertificateSerialNumber, Error> = input.decode();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected);
    }

    #[rstest]
    #[case::null(Element::Null, "InvalidCertificateSerialNumber")]
    #[case::octet_string(Element::OctetString(asn1::OctetString::from(vec![0x01])), "InvalidCertificateSerialNumber")]
    #[case::object_identifier(Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.3.4").unwrap()), "InvalidCertificateSerialNumber")]
    #[case::utf8_string(Element::UTF8String("test".to_string()), "InvalidCertificateSerialNumber")]
    fn test_certificate_serial_number_decode_failure(
        #[case] input: Element,
        #[case] expected_error_variant: &str,
    ) {
        let result: Result<CertificateSerialNumber, Error> = input.decode();
        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_str = format!("{:?}", err);
        assert!(
            err_str.contains(expected_error_variant),
            "Expected error '{}', but got '{}'",
            expected_error_variant,
            err_str
        );
    }

    // Validity tests
    #[rstest(
        not_before_element,
        not_after_element,
        expected_not_before,
        expected_not_after,
        // Test case: Both UTCTime
        case(
            Element::UTCTime(NaiveDateTime::parse_from_str("2019-12-16 03:02:10", "%Y-%m-%d %H:%M:%S").unwrap()),
            Element::UTCTime(NaiveDateTime::parse_from_str("2024-12-16 03:02:10", "%Y-%m-%d %H:%M:%S").unwrap()),
            NaiveDateTime::parse_from_str("2019-12-16 03:02:10", "%Y-%m-%d %H:%M:%S").unwrap(),
            NaiveDateTime::parse_from_str("2024-12-16 03:02:10", "%Y-%m-%d %H:%M:%S").unwrap()
        ),
        // Test case: Both GeneralizedTime
        case(
            Element::GeneralizedTime(NaiveDateTime::parse_from_str("2025-01-01 00:00:00", "%Y-%m-%d %H:%M:%S").unwrap()),
            Element::GeneralizedTime(NaiveDateTime::parse_from_str("2026-01-01 00:00:00", "%Y-%m-%d %H:%M:%S").unwrap()),
            NaiveDateTime::parse_from_str("2025-01-01 00:00:00", "%Y-%m-%d %H:%M:%S").unwrap(),
            NaiveDateTime::parse_from_str("2026-01-01 00:00:00", "%Y-%m-%d %H:%M:%S").unwrap()
        ),
        // Test case: Mixed UTCTime and GeneralizedTime
        case(
            Element::UTCTime(NaiveDateTime::parse_from_str("2020-06-15 12:30:45", "%Y-%m-%d %H:%M:%S").unwrap()),
            Element::GeneralizedTime(NaiveDateTime::parse_from_str("2030-06-15 12:30:45", "%Y-%m-%d %H:%M:%S").unwrap()),
            NaiveDateTime::parse_from_str("2020-06-15 12:30:45", "%Y-%m-%d %H:%M:%S").unwrap(),
            NaiveDateTime::parse_from_str("2030-06-15 12:30:45", "%Y-%m-%d %H:%M:%S").unwrap()
        )
    )]
    fn test_validity_decode_success(
        not_before_element: Element,
        not_after_element: Element,
        expected_not_before: NaiveDateTime,
        expected_not_after: NaiveDateTime,
    ) {
        let sequence = Element::Sequence(vec![not_before_element, not_after_element]);
        let validity: Validity = sequence.decode().unwrap();

        assert_eq!(validity.not_before, expected_not_before);
        assert_eq!(validity.not_after, expected_not_after);
    }

    #[rstest(
        input,
        expected_error_msg,
        // Test case: Empty sequence
        case(
            Element::Sequence(vec![]),
            "expected 2 elements in sequence"
        ),
        // Test case: Only one element
        case(
            Element::Sequence(vec![
                Element::UTCTime(NaiveDateTime::parse_from_str("2019-12-16 03:02:10", "%Y-%m-%d %H:%M:%S").unwrap())
            ]),
            "expected 2 elements in sequence"
        ),
        // Test case: Too many elements
        case(
            Element::Sequence(vec![
                Element::UTCTime(NaiveDateTime::parse_from_str("2019-12-16 03:02:10", "%Y-%m-%d %H:%M:%S").unwrap()),
                Element::UTCTime(NaiveDateTime::parse_from_str("2024-12-16 03:02:10", "%Y-%m-%d %H:%M:%S").unwrap()),
                Element::UTCTime(NaiveDateTime::parse_from_str("2025-12-16 03:02:10", "%Y-%m-%d %H:%M:%S").unwrap())
            ]),
            "expected 2 elements in sequence"
        ),
        // Test case: Not a sequence
        case(
            Element::Integer(Integer::from(vec![0x01])),
            "expected sequence for Validity"
        ),
        // Test case: Invalid notBefore (not a time element)
        case(
            Element::Sequence(vec![
                Element::Integer(Integer::from(vec![0x01])),
                Element::UTCTime(NaiveDateTime::parse_from_str("2024-12-16 03:02:10", "%Y-%m-%d %H:%M:%S").unwrap())
            ]),
            "invalid notBefore time"
        ),
        // Test case: Invalid notAfter (not a time element)
        case(
            Element::Sequence(vec![
                Element::UTCTime(NaiveDateTime::parse_from_str("2019-12-16 03:02:10", "%Y-%m-%d %H:%M:%S").unwrap()),
                Element::Integer(Integer::from(vec![0x01]))
            ]),
            "invalid notAfter time"
        )
    )]
    fn test_validity_decode_failure(input: Element, expected_error_msg: &str) {
        let result: Result<Validity, Error> = input.decode();
        assert!(result.is_err());
        let err = result.unwrap_err();
        #[allow(irrefutable_let_patterns)]
        if let Error::InvalidValidity(msg) = err {
            assert!(
                msg.contains(expected_error_msg),
                "Expected error message to contain '{}', but got '{}'",
                expected_error_msg,
                msg
            );
        } else {
            panic!("Expected InvalidValidity error, but got {:?}", err);
        }
    }

    #[test]
    fn test_validity_roundtrip_serialization() {
        let validity = Validity {
            not_before: NaiveDateTime::parse_from_str("2019-12-16 03:02:10", "%Y-%m-%d %H:%M:%S")
                .unwrap(),
            not_after: NaiveDateTime::parse_from_str("2024-12-16 03:02:10", "%Y-%m-%d %H:%M:%S")
                .unwrap(),
        };

        let json = serde_json::to_string(&validity).unwrap();
        let deserialized: Validity = serde_json::from_str(&json).unwrap();

        assert_eq!(validity, deserialized);
    }

    // SubjectPublicKeyInfo tests
    #[rstest(
        input,
        expected,
        // Test case: RSA public key (2048-bit)
        case(
            Element::Sequence(vec![
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.840.113549.1.1.1").unwrap()), // rsaEncryption
                    Element::Null,
                ]),
                Element::BitString(BitString::new(0, vec![
                    0x30, 0x82, 0x01, 0x0a, // SEQUENCE header
                    0x02, 0x82, 0x01, 0x01, // INTEGER (modulus)
                    0x00, 0xb4, 0x6c, 0x8f, // First few bytes of modulus
                ])),
            ]),
            SubjectPublicKeyInfo {
                algorithm: AlgorithmIdentifier {
                    algorithm: ObjectIdentifier::from_str("1.2.840.113549.1.1.1").unwrap(),
                    parameters: Some(AlgorithmParameters::Null),
                },
                subject_public_key: BitString::new(0, vec![
                    0x30, 0x82, 0x01, 0x0a,
                    0x02, 0x82, 0x01, 0x01,
                    0x00, 0xb4, 0x6c, 0x8f,
                ]),
            }
        ),
        // Test case: ECDSA public key (P-256)
        case(
            Element::Sequence(vec![
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.840.10045.2.1").unwrap()), // ecPublicKey
                    Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.840.10045.3.1.7").unwrap()), // secp256r1
                ]),
                Element::BitString(BitString::new(0, vec![
                    0x04, // Uncompressed point
                    0x8d, 0x61, 0x7e, 0x65, // X coordinate (first 4 bytes)
                    0x3b, 0x6b, 0x80, 0x69, // Y coordinate (first 4 bytes)
                ])),
            ]),
            SubjectPublicKeyInfo {
                algorithm: AlgorithmIdentifier {
                    algorithm: ObjectIdentifier::from_str("1.2.840.10045.2.1").unwrap(),
                    parameters: Some(AlgorithmParameters::Elm(
                        Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.840.10045.3.1.7").unwrap())
                    )),
                },
                subject_public_key: BitString::new(0, vec![
                    0x04,
                    0x8d, 0x61, 0x7e, 0x65,
                    0x3b, 0x6b, 0x80, 0x69,
                ]),
            }
        ),
        // Test case: Ed25519 public key
        case(
            Element::Sequence(vec![
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str("1.3.101.112").unwrap()), // Ed25519
                ]),
                Element::BitString(BitString::new(0, vec![
                    0x8d, 0x61, 0x7e, 0x65, 0x3b, 0x6b, 0x80, 0x69, // 32 bytes of public key
                    0x1b, 0x21, 0x4c, 0x28, 0xf8, 0x3a, 0x8b, 0x27,
                    0x3f, 0x49, 0x40, 0xea, 0xc0, 0x8e, 0x73, 0x6d,
                    0x9f, 0x3f, 0x31, 0x21, 0x91, 0x3b, 0xa2, 0x16,
                ])),
            ]),
            SubjectPublicKeyInfo {
                algorithm: AlgorithmIdentifier {
                    algorithm: ObjectIdentifier::from_str("1.3.101.112").unwrap(),
                    parameters: None,
                },
                subject_public_key: BitString::new(0, vec![
                    0x8d, 0x61, 0x7e, 0x65, 0x3b, 0x6b, 0x80, 0x69,
                    0x1b, 0x21, 0x4c, 0x28, 0xf8, 0x3a, 0x8b, 0x27,
                    0x3f, 0x49, 0x40, 0xea, 0xc0, 0x8e, 0x73, 0x6d,
                    0x9f, 0x3f, 0x31, 0x21, 0x91, 0x3b, 0xa2, 0x16,
                ]),
            }
        ),
        // Test case: BitString with unused bits
        case(
            Element::Sequence(vec![
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.840.113549.1.1.1").unwrap()),
                    Element::Null,
                ]),
                Element::BitString(BitString::new(3, vec![0xFF, 0xE0])), // 13 bits (3 unused in last byte)
            ]),
            SubjectPublicKeyInfo {
                algorithm: AlgorithmIdentifier {
                    algorithm: ObjectIdentifier::from_str("1.2.840.113549.1.1.1").unwrap(),
                    parameters: Some(AlgorithmParameters::Null),
                },
                subject_public_key: BitString::new(3, vec![0xFF, 0xE0]),
            }
        ),
    )]
    fn test_subject_public_key_info_decode_success(input: Element, expected: SubjectPublicKeyInfo) {
        let result: Result<SubjectPublicKeyInfo, Error> = input.decode();
        assert!(result.is_ok());
        let spki = result.unwrap();
        assert_eq!(spki, expected);
    }

    #[rstest(
        input,
        expected_error_msg,
        // Test case: Not a Sequence
        case(
            Element::Integer(Integer::from(vec![0x01])),
            "expected Sequence"
        ),
        // Test case: Empty sequence
        case(
            Element::Sequence(vec![]),
            "expected 2 elements in sequence, got 0"
        ),
        // Test case: Only one element
        case(
            Element::Sequence(vec![
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.840.113549.1.1.1").unwrap()),
                ]),
            ]),
            "expected 2 elements in sequence, got 1"
        ),
        // Test case: Too many elements
        case(
            Element::Sequence(vec![
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.840.113549.1.1.1").unwrap()),
                ]),
                Element::BitString(BitString::new(0, vec![0x00])),
                Element::Null,
            ]),
            "expected 2 elements in sequence, got 3"
        ),
        // Test case: First element is not AlgorithmIdentifier (not a sequence)
        case(
            Element::Sequence(vec![
                Element::Integer(Integer::from(vec![0x01])),
                Element::BitString(BitString::new(0, vec![0x00])),
            ]),
            "failed to decode algorithm"
        ),
        // Test case: Second element is not BitString
        case(
            Element::Sequence(vec![
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.840.113549.1.1.1").unwrap()),
                ]),
                Element::OctetString(OctetString::from(vec![0x00])),
            ]),
            "expected BitString for subject public key"
        ),
        // Test case: Invalid AlgorithmIdentifier (empty sequence)
        case(
            Element::Sequence(vec![
                Element::Sequence(vec![]),
                Element::BitString(BitString::new(0, vec![0x00])),
            ]),
            "failed to decode algorithm"
        ),
    )]
    fn test_subject_public_key_info_decode_failure(input: Element, expected_error_msg: &str) {
        let result: Result<SubjectPublicKeyInfo, Error> = input.decode();
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

    // Test certificate V1 (RSA 2048-bit, no extensions)
    // Generated with: openssl req -x509 -newkey rsa:2048 -nodes \
    //   -keyout x509/test_v1_key.pem -out x509/test_v1_cert.pem -days 3650 \
    //   -subj "/C=JP/O=Tsumiki/CN=test-v1"
    const TEST_CERT_V1: &str = r"-----BEGIN CERTIFICATE-----
MIIC3jCCAcYCCQD36esrlVEnfTANBgkqhkiG9w0BAQsFADAxMQswCQYDVQQGEwJK
UDEQMA4GA1UECgwHVHN1bWlraTEQMA4GA1UEAwwHdGVzdC12MTAeFw0yNTEyMjgw
OTU0MDlaFw0zNTEyMjYwOTU0MDlaMDExCzAJBgNVBAYTAkpQMRAwDgYDVQQKDAdU
c3VtaWtpMRAwDgYDVQQDDAd0ZXN0LXYxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEA4wIzS7OSAX5BGtOggT2npL7j07MK7tp8LdLQtVv4STTTldq5nB21
msh7WjrJ/DVzBljyoDOS+rRCe/33SakVCWtsvgXmlbr6/HYiHEFIeMj1U5qFHBPI
/yccZdwW0FdaKNoMDyaa6ii/uZ0mdm9Rh2BTmM6jbsKghGOPZNtt7cfPDOQEkbuX
tdTS8YNRxULsIVrKi3GEsITZylvpzaS2k8atsQyayE2I/wVCBuwnP8JKE7ZjXBCu
D1+RpXdeVIJFwG9oe7X1ejurwb+VRTZzLFr+p9f6D/1PXzjWGxxohG9ACKaMlWqO
+Ge0mODKwo7D+Z+2uR1t0W8eZp/Mg7PjHQIDAQABMA0GCSqGSIb3DQEBCwUAA4IB
AQAWbVDRrPKoZ+kAOKdl5rZ9DOtzTnAkYTIXKiI5kKsZQ05Rz0N3zjtv6WieHu4f
STa6A1EjsESx78VhqiWD451lfJTAPvofzY7f32ZrMhGPI5GIGQJXm3ykFNC57z/g
hZS04cvj1lqaWdp5DQ9ZrIS9PaBVcY+RtuRmIpbSuZukjGvG/W76fqajZWRwG6yW
lbz1C5n4m8n+m8zTLy28nxX7Fm/8h0c3/jjrJnkYQ98JIQuj9vyhH0SHloP/uoTI
arWjLcCEZ6DqqXiKc4ojkQvARkufeKpztUlgi7lrTfk6hG0RWp0jmY/OyV3OeTeP
ZyI1Mobuf6I2De0X96VkC+JV
-----END CERTIFICATE-----";

    // Test certificate V3 CA (RSA 4096-bit, with CA extensions)
    // Generated with: openssl req -x509 -newkey rsa:4096 -nodes \
    //   -keyout x509/test_key.pem -out x509/test_cert.pem -days 3650 \
    //   -config x509/cert_config.cnf \
    //   -subj "/C=JP/ST=Tokyo/L=Shibuya/O=Tsumiki Project/OU=Test/CN=tsumiki.test"
    const TEST_CERT_V3_CA: &str = r"-----BEGIN CERTIFICATE-----
MIIFxDCCA6ygAwIBAgIJAJOR1eonIkS9MA0GCSqGSIb3DQEBCwUAMG8xCzAJBgNV
BAYTAkpQMQ4wDAYDVQQIDAVUb2t5bzEQMA4GA1UEBwwHU2hpYnV5YTEYMBYGA1UE
CgwPVHN1bWlraSBQcm9qZWN0MQ0wCwYDVQQLDARUZXN0MRUwEwYDVQQDDAx0c3Vt
aWtpLnRlc3QwHhcNMjUxMjI4MDg0OTA3WhcNMzUxMjI2MDg0OTA3WjBvMQswCQYD
VQQGEwJKUDEOMAwGA1UECAwFVG9reW8xEDAOBgNVBAcMB1NoaWJ1eWExGDAWBgNV
BAoMD1RzdW1pa2kgUHJvamVjdDENMAsGA1UECwwEVGVzdDEVMBMGA1UEAwwMdHN1
bWlraS50ZXN0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA4Ey4xmrV
Oju/hD/gGWzIG7PHAIKrCIyZdGNuESZxZCTISFYDLBif9SpIh1Ss1p5L37KCe7P8
6T2Ab/NPCpCUuHI51XOLBfvyAYPlkbF3bgtrtG4+4cCqpBTsQpE23tLjq3Yiw1Tp
uw8ny+83omq7sJJ3fYaDun/JDwK+sDhOxAfF7B0g8n6crg4cONXwBEVXcPNIr+SG
enwUAZwcCGG50tGiDGf92Mj/GuwbHrcaRsGbSClK/YismkO/dROCVhp+4tSCmGLM
eoKa7z+bkCyVNfCNJYXfJp1Iqpu65ElT0DzHq/KTvkbfFnkqSXb0e61CW/tSfFCK
vA0Ih6tlEa275rv86hEH5NZvM5kS66LUzZwgA2Cc527Xnf41zEPQZZhBe9VtReqR
sbBd02vScg4rsGy8j01T8mK/1yTD8euXJN7fuiuChhFMw/LWcGfwMsd3vG7ty4hh
Yuv7kYAcasZpABbT/2SvdJ8VX9pZLQiFJvUJ/tQGX0Mm3FZaExj/vttsO2/Q9/OP
hIAyPUWqgqw14SqjrBa9eUULKENiWpbf5EtXNeDWOGTUz8xLXL4AKYvbkLi0ciPp
GiN5U9/P05PgzakwsniCMuG+RtgYX0jJJNwzAsDMqk8C7ATWWj1UOCowADqOsTXS
oDnrwNkBv0AKN4oL1wh+Lyqc+8Idin2sA6sCAwEAAaNjMGEwHQYDVR0OBBYEFAHB
rLF5p+pxNqZDYFTpIpgzkOkIMB8GA1UdIwQYMBaAFAHBrLF5p+pxNqZDYFTpIpgz
kOkIMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEB
CwUAA4ICAQBc9G5hR7REaXkwnUs6gxGAqsrs2FLskDWUmQ7CqZChvmIcYDYaWBkN
dORbNnt5IayJaeGRtGVobLzKa5gkd7H8S2nYEf3ZB53Ao7axc6+qkXsyqw53GrkL
y9gRNtcmE2S1DAHLvNP2ITr+Q5xeilGrN5LX6cgvPLq7W9oUrejilCUdaxMD9JxU
H4UPitrCoenz6kmATYjFccgucpDrII6TKnAMBNa1MsRfyMxrK9eKWDVrCVaU8qG/
cc/lW+81HF9a58jLvLVNzkBU1akyuEkIySpjUAB17MqZED/E1vjnuz2uZ1ZdqvXn
v5IknYv37rFFa9umzLrPBg+bdAq6kSYO6fuZ1ALLXnXwS/o6aB6er3IhQ+BG3T2l
csJ9HHkSzd9+OQBxmvzQzqzPnrRUPPsVWFpY5U/HgiapQY7ap2WvH5PYqTTVJxuX
nRY+7m26TseaQUoGtvmGQroWExHXnfMPegXFMLMQNZ6sLd3196b7xXbsDLPWHI+W
iVmR86a6BiAiLoWky6r4X7hzOvEKEpP+U0AmzCy/M5QIJrQ8WUAUMYwUvwA/PUwD
UbUqI1x5HAbH95tvCou+2CI27rSINgsQjFdx13Xc3+4xjHGvncqWQXCyQvcC4a33
dlxmWgRWrD79sttWdIihj33fPv+OezjPjVNXU5tSJsDpKudwXhcPzQ==
-----END CERTIFICATE-----";

    // Test certificate V3 End Entity (RSA 2048-bit, with SAN extension)
    // Generated with: openssl req -x509 -newkey rsa:2048 -nodes \
    //   -keyout x509/test_ee_key.pem -out x509/test_ee_cert.pem -days 3650 \
    //   -config x509/end_entity_config.cnf \
    //   -subj "/C=JP/ST=Tokyo/O=Tsumiki Project/CN=server.tsumiki.test"
    const TEST_CERT_V3_EE: &str = r"-----BEGIN CERTIFICATE-----
MIIDrDCCApSgAwIBAgIJAJe8Uwe3KSplMA0GCSqGSIb3DQEBCwUAMFUxCzAJBgNV
BAYTAkpQMQ4wDAYDVQQIDAVUb2t5bzEYMBYGA1UECgwPVHN1bWlraSBQcm9qZWN0
MRwwGgYDVQQDDBNzZXJ2ZXIudHN1bWlraS50ZXN0MB4XDTI1MTIyODA5NTQyNloX
DTM1MTIyNjA5NTQyNlowVTELMAkGA1UEBhMCSlAxDjAMBgNVBAgMBVRva3lvMRgw
FgYDVQQKDA9Uc3VtaWtpIFByb2plY3QxHDAaBgNVBAMME3NlcnZlci50c3VtaWtp
LnRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDtc3gArhY+2ZPa
EEodwZSdV64JfI6LP/VJdCrJkrWw+cAjIoPd5IWYYM4quJjyS0sKJdOcG1ox+Vyk
V2Mx3Tu7a9HfkL94UVC6wkuqxn6ss1nF3WDwRpMKdk2osAkfC2DEy+gUTbSUP7nF
xLfzWnHsiKf7OQdnvqi1+ky77c2oYCsR4Gmc45/pmma8laHtD15nLrNw6QPNFXgi
tqVRsJAd887FP35vsxlKLSt1KtDplXPwVdTKIEoAfC3rbfS2RtHoLz2iScS4m97R
H2yd71R04UaBluloV6eVn+SYx6toglm2TigxQG/v0i/b4J5+tTLRFWSbSw6IXfPv
IpeO5QybAgMBAAGjfzB9MB0GA1UdDgQWBBQ3BSW6F/y0r7M6za10RFuSkEjWADAO
BgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMC0G
A1UdEQQmMCSCDHRzdW1pa2kudGVzdIIOKi50c3VtaWtpLnRlc3SHBH8AAAEwDQYJ
KoZIhvcNAQELBQADggEBAK+YTpe3eg622ATN9mXMUxyD+qHLdsjqaoe1XHyjZyZ7
uEERNtSw2FBxzg1YDh2dEZtWc8ybwPwJwpySo/7dq53BWZW6aBW0kMp3GLC/Od6C
k+8EFoao7SFr16XsGQJD4DNoKVvHKAE2FworjXdRUFswwtkoD8gdsK2sf2vgnBv8
HAVm7HukOAHpl5Cv4uoD57p1kfMH4T7q1yKz5e9kQi3Ta5vJzydMluZzgJQUxif1
3nAQuaKAyIZfiF4QTlaA8i8nodjhZeM6A0ZomnZeCVjigqkr706tbakcyyrbsjM4
I36SjnCvZLfTAZy2PzjD+JS43m/+2ydsdhU7+aUoR+w=
-----END CERTIFICATE-----";

    // Test certificate V3 ECDSA P-256 CA (with CA extensions)
    // Generated with: openssl ecparam -name prime256v1 -genkey -noout | \
    //   openssl req -new -x509 -key /dev/stdin -out x509/test_ec_cert.pem -days 3650 \
    //   -config x509/cert_config.cnf \
    //   -subj "/C=JP/ST=Tokyo/O=Tsumiki Project/CN=ec-ca.tsumiki.test"
    const TEST_CERT_V3_ECDSA_P256: &str = r"-----BEGIN CERTIFICATE-----
MIICAjCCAaigAwIBAgIJAKtsTdFGb77kMAoGCCqGSM49BAMCMFQxCzAJBgNVBAYT
AkpQMQ4wDAYDVQQIDAVUb2t5bzEYMBYGA1UECgwPVHN1bWlraSBQcm9qZWN0MRsw
GQYDVQQDDBJlYy1jYS50c3VtaWtpLnRlc3QwHhcNMjUxMjI4MTAyOTI0WhcNMzUx
MjI2MTAyOTI0WjBUMQswCQYDVQQGEwJKUDEOMAwGA1UECAwFVG9reW8xGDAWBgNV
BAoMD1RzdW1pa2kgUHJvamVjdDEbMBkGA1UEAwwSZWMtY2EudHN1bWlraS50ZXN0
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7sCe86byM+Pj8cbpthxg1eMhQ/MN
xgsLmedraZo9OXStkYhMFFqcFccwiIXLiWJgiIsVVpGn02uLpB4SOlu4FKNjMGEw
HQYDVR0OBBYEFDWBtOp+1zCPl3dUA52ZjY7C2F1tMB8GA1UdIwQYMBaAFDWBtOp+
1zCPl3dUA52ZjY7C2F1tMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGG
MAoGCCqGSM49BAMCA0gAMEUCIEtUSow92vKt7bYbjRszN8Db2UR6BSaz+q7kxo+X
Z1s+AiEAsj0FnruwSPLI6M1KzOjeNKTmFeDyYIw3zF1DVdCFOmc=
-----END CERTIFICATE-----";

    // Test certificate V3 ECDSA P-384 (with SAN extension)
    // Generated with: openssl ecparam -name secp384r1 -genkey -noout | \
    //   openssl req -new -x509 -key /dev/stdin -out x509/test_ec384_cert.pem -days 3650 \
    //   -config x509/end_entity_config.cnf \
    //   -subj "/C=JP/O=Tsumiki Project/CN=ec384.tsumiki.test"
    const TEST_CERT_V3_ECDSA_P384: &str = r"-----BEGIN CERTIFICATE-----
MIICOjCCAcGgAwIBAgIJAPSkPOMqZro8MAoGCCqGSM49BAMCMEQxCzAJBgNVBAYT
AkpQMRgwFgYDVQQKDA9Uc3VtaWtpIFByb2plY3QxGzAZBgNVBAMMEmVjMzg0LnRz
dW1pa2kudGVzdDAeFw0yNTEyMjgxMDI5NDhaFw0zNTEyMjYxMDI5NDhaMEQxCzAJ
BgNVBAYTAkpQMRgwFgYDVQQKDA9Uc3VtaWtpIFByb2plY3QxGzAZBgNVBAMMEmVj
Mzg0LnRzdW1pa2kudGVzdDB2MBAGByqGSM49AgEGBSuBBAAiA2IABMZzYCpsCn/q
OkGGfxphk+24hS47tW849Z2xjzh2XJqLlKrcPcO+5zpWri7WNuo/DrsPXIgJdTxx
/b97Rq25TgtRLem5rux4uN0gMxf5qcRotqSXrN5eL7i8xPGrWBxw9aN/MH0wHQYD
VR0OBBYEFGVQxde1MT37ma9vjNCp9WVdUXsCMA4GA1UdDwEB/wQEAwIFoDAdBgNV
HSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwLQYDVR0RBCYwJIIMdHN1bWlraS50
ZXN0gg4qLnRzdW1pa2kudGVzdIcEfwAAATAKBggqhkjOPQQDAgNnADBkAjAVRQuq
66V6ZQQoCFGNDUbki4yWd4pKp2x2igVxJ+8yAJj0hSERlRP1cpnq5CWhOXgCMExy
sDuylxpp9szuj0bvfcO9JcS+V/5gPK0+5QxawidqE/ERQgBD9yj8ouw4F6BmKg==
-----END CERTIFICATE-----";

    #[test]
    fn test_decode_v1_certificate() {
        use der::Der;
        use pem::Pem;

        let pem = Pem::from_str(TEST_CERT_V1).unwrap();
        let der: Der = pem.decode().unwrap();
        let asn1_obj: ASN1Object = der.decode().unwrap();

        let cert: Certificate = asn1_obj.decode().unwrap();
        let json_output = serde_json::to_string_pretty(&cert).unwrap();
        println!("=== V1 Certificate ===");
        println!("{}", json_output);

        // V1 certificate assertions
        assert_eq!(cert.tbs_certificate.version, Version::V1);
        assert!(cert.tbs_certificate.extensions.is_none());
        assert_eq!(cert.tbs_certificate.issuer.rdn_sequence.len(), 3); // C, O, CN
        assert_eq!(cert.tbs_certificate.subject.rdn_sequence.len(), 3);
    }

    #[test]
    fn test_decode_v3_ca_certificate() {
        use der::Der;
        use pem::Pem;

        let pem = Pem::from_str(TEST_CERT_V3_CA).unwrap();
        let der: Der = pem.decode().unwrap();
        let asn1_obj: ASN1Object = der.decode().unwrap();

        let cert: Certificate = asn1_obj.decode().unwrap();
        let json_output = serde_json::to_string_pretty(&cert).unwrap();
        println!("=== V3 CA Certificate ===");
        println!("{}", json_output);

        // V3 CA certificate assertions
        assert_eq!(cert.tbs_certificate.version, Version::V3);
        assert!(cert.tbs_certificate.extensions.is_some());
        let extensions = cert.tbs_certificate.extensions.as_ref().unwrap();
        assert_eq!(extensions.extensions().len(), 4); // SKI, AKI, BasicConstraints, KeyUsage
        assert_eq!(cert.tbs_certificate.issuer.rdn_sequence.len(), 6); // C, ST, L, O, OU, CN
    }

    #[test]
    fn test_decode_v3_ee_certificate() {
        use der::Der;
        use pem::Pem;

        let pem = Pem::from_str(TEST_CERT_V3_EE).unwrap();
        let der: Der = pem.decode().unwrap();
        let asn1_obj: ASN1Object = der.decode().unwrap();

        let cert: Certificate = asn1_obj.decode().unwrap();
        let json_output = serde_json::to_string_pretty(&cert).unwrap();
        println!("=== V3 End Entity Certificate ===");
        println!("{}", json_output);

        // V3 End Entity certificate assertions
        assert_eq!(cert.tbs_certificate.version, Version::V3);
        assert!(cert.tbs_certificate.extensions.is_some());
        let extensions = cert.tbs_certificate.extensions.as_ref().unwrap();
        assert_eq!(extensions.extensions().len(), 4); // SKI, KeyUsage, ExtKeyUsage, SAN
        assert_eq!(cert.tbs_certificate.issuer.rdn_sequence.len(), 4); // C, ST, O, CN
    }

    #[test]
    fn test_decode_v3_ecdsa_p256_certificate() {
        use der::Der;
        use pem::Pem;

        let pem = Pem::from_str(TEST_CERT_V3_ECDSA_P256).unwrap();
        let der: Der = pem.decode().unwrap();
        let asn1_obj: ASN1Object = der.decode().unwrap();

        let cert: Certificate = asn1_obj.decode().unwrap();
        let json_output = serde_json::to_string_pretty(&cert).unwrap();
        println!("=== V3 ECDSA P-256 CA Certificate ===");
        println!("{}", json_output);

        // V3 ECDSA P-256 CA certificate assertions
        assert_eq!(cert.tbs_certificate.version, Version::V3);
        assert!(cert.tbs_certificate.extensions.is_some());
        let extensions = cert.tbs_certificate.extensions.as_ref().unwrap();
        assert_eq!(extensions.extensions().len(), 4); // SKI, AKI, BasicConstraints, KeyUsage

        // Verify it's ECDSA (OID: 1.2.840.10045.2.1)
        assert_eq!(
            cert.tbs_certificate
                .subject_public_key_info
                .algorithm
                .algorithm
                .to_string(),
            "1.2.840.10045.2.1"
        );
        // Verify signature algorithm is ECDSA-SHA256 (OID: 1.2.840.10045.4.3.2)
        assert_eq!(
            cert.signature_algorithm.algorithm.to_string(),
            "1.2.840.10045.4.3.2"
        );
    }

    #[test]
    fn test_decode_v3_ecdsa_p384_certificate() {
        use der::Der;
        use pem::Pem;

        let pem = Pem::from_str(TEST_CERT_V3_ECDSA_P384).unwrap();
        let der: Der = pem.decode().unwrap();
        let asn1_obj: ASN1Object = der.decode().unwrap();

        let cert: Certificate = asn1_obj.decode().unwrap();
        let json_output = serde_json::to_string_pretty(&cert).unwrap();
        println!("=== V3 ECDSA P-384 Certificate ===");
        println!("{}", json_output);

        // V3 ECDSA P-384 certificate assertions
        assert_eq!(cert.tbs_certificate.version, Version::V3);
        assert!(cert.tbs_certificate.extensions.is_some());
        let extensions = cert.tbs_certificate.extensions.as_ref().unwrap();
        assert_eq!(extensions.extensions().len(), 4); // SKI, KeyUsage, ExtKeyUsage, SAN

        // Verify it's ECDSA (OID: 1.2.840.10045.2.1)
        assert_eq!(
            cert.tbs_certificate
                .subject_public_key_info
                .algorithm
                .algorithm
                .to_string(),
            "1.2.840.10045.2.1"
        );
        // Verify signature algorithm is ECDSA-SHA256 (OID: 1.2.840.10045.4.3.2)
        assert_eq!(
            cert.signature_algorithm.algorithm.to_string(),
            "1.2.840.10045.4.3.2"
        );
    }

    #[test]
    fn test_decode_full_certificate() {
        use der::Der;
        use pem::Pem;

        // Parse PEM -> DER -> ASN1Object -> Certificate
        let pem = Pem::from_str(TEST_CERT_V1).unwrap();
        let der: Der = pem.decode().unwrap();
        let asn1_obj: ASN1Object = der.decode().unwrap();

        // Decode to Certificate from ASN1Object directly
        let certificate: Result<Certificate, Error> = asn1_obj.decode();
        assert!(
            certificate.is_ok(),
            "Failed to decode certificate: {:?}",
            certificate.err()
        );

        let cert = certificate.unwrap();

        // Output as JSON
        let json_output = serde_json::to_string_pretty(&cert).unwrap();
        println!("{}", json_output);

        // Verify basic properties
        // This is a v1 certificate (no explicit version field in the encoding)
        assert_eq!(cert.tbs_certificate.version, Version::V1);
        // v1 certificates don't have extensions
        assert!(cert.tbs_certificate.extensions.is_none());
        // Verify subject/issuer
        assert_eq!(
            cert.tbs_certificate.issuer.rdn_sequence.len(),
            3 // C, O, CN
        );
        assert_eq!(
            cert.tbs_certificate.subject.rdn_sequence.len(),
            3 // C, O, CN
        );
    }
}
