use asn1::{ASN1Object, BitString, Element, Integer, ObjectIdentifier};
use chrono::{Datelike, NaiveDateTime};
use pkix_types::OidName;
use serde::{Deserialize, Serialize, ser::SerializeStruct};
use std::fmt;
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};

use crate::error::Error;
use crate::extensions::{Extensions, ParsedExtensions};

pub mod error;
pub mod extensions;
mod types;

// Re-export public types from pkix-types
pub use pkix_types::{
    AlgorithmIdentifier, AlgorithmParameters, CertificateSerialNumber, DirectoryString, Name,
    RawAlgorithmParameter, SubjectPublicKeyInfo,
};

/*
https://datatracker.ietf.org/doc/html/rfc5280#section-4.1

Certificate  ::=  SEQUENCE  {
    tbsCertificate       TBSCertificate,
    signatureAlgorithm   AlgorithmIdentifier,
    signatureValue       BIT STRING
}
 */

#[derive(Debug, Deserialize)]
pub struct Certificate {
    tbs_certificate: TBSCertificate,
    signature_algorithm: AlgorithmIdentifier,
    signature_value: BitString, // BIT STRING
}

impl Serialize for Certificate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
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
    pub fn extension<T: extensions::Extension>(&self) -> Result<Option<T>, Error> {
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

impl fmt::Display for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Certificate:")?;
        writeln!(f, "    Data:")?;

        // Version
        let version_num = match self.tbs_certificate.version {
            Version::V1 => 1,
            Version::V2 => 2,
            Version::V3 => 3,
        };
        writeln!(
            f,
            "        Version: {} (0x{})",
            version_num,
            version_num - 1
        )?;

        // Serial Number
        let serial_bytes = self
            .tbs_certificate
            .serial_number
            .as_ref()
            .to_signed_bytes_be();
        let serial_hex: Vec<String> = serial_bytes.iter().map(|b| format!("{:02x}", b)).collect();
        writeln!(f, "        Serial Number: {}", serial_hex.join(":"))?;

        // Signature Algorithm
        let sig_alg = self
            .tbs_certificate
            .signature
            .oid_name()
            .map(|s| s.to_string())
            .unwrap_or_else(|| self.tbs_certificate.signature.algorithm.to_string());
        writeln!(f, "        Signature Algorithm: {}", sig_alg)?;

        // Issuer
        writeln!(f, "        Issuer: {}", self.tbs_certificate.issuer)?;

        // Validity
        writeln!(f, "        Validity")?;
        writeln!(
            f,
            "            Not Before: {}",
            self.tbs_certificate
                .validity
                .not_before
                .format("%b %d %H:%M:%S %Y GMT")
        )?;
        writeln!(
            f,
            "            Not After : {}",
            self.tbs_certificate
                .validity
                .not_after
                .format("%b %d %H:%M:%S %Y GMT")
        )?;

        // Subject
        writeln!(f, "        Subject: {}", self.tbs_certificate.subject)?;

        // Subject Public Key Info
        writeln!(f, "        Subject Public Key Info:")?;
        let pubkey_alg = self
            .tbs_certificate
            .subject_public_key_info
            .algorithm()
            .oid_name()
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                self.tbs_certificate
                    .subject_public_key_info
                    .algorithm()
                    .algorithm
                    .to_string()
            });
        writeln!(f, "            Public Key Algorithm: {}", pubkey_alg)?;

        // Public Key (hex dump)
        let pubkey_bytes = self
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key()
            .as_bytes();
        writeln!(
            f,
            "                Public-Key: ({} bit)",
            pubkey_bytes.len() * 8
        )?;
        for chunk in pubkey_bytes.chunks(15) {
            let hex_str: Vec<String> = chunk.iter().map(|b| format!("{:02x}", b)).collect();
            writeln!(f, "                {}", hex_str.join(":"))?;
        }

        // Extensions
        if let Some(ref _exts) = self.tbs_certificate.extensions {
            writeln!(f, "        X509v3 extensions:")?;

            // Subject Key Identifier
            if let Ok(Some(ski)) = self.extension::<extensions::SubjectKeyIdentifier>() {
                write!(f, "{}", ski)?;
            }

            // Authority Key Identifier
            if let Ok(Some(aki)) = self.extension::<extensions::AuthorityKeyIdentifier>() {
                write!(f, "{}", aki)?;
            }

            // Basic Constraints
            if let Ok(Some(bc)) = self.extension::<extensions::BasicConstraints>() {
                write!(f, "{}", bc)?;
            }

            // Key Usage
            if let Ok(Some(ku)) = self.extension::<extensions::KeyUsage>() {
                write!(f, "{}", ku)?;
            }

            // Extended Key Usage
            if let Ok(Some(eku)) = self.extension::<extensions::ExtendedKeyUsage>() {
                write!(f, "{}", eku)?;
            }

            // Subject Alternative Name
            if let Ok(Some(san)) = self.extension::<extensions::SubjectAltName>() {
                write!(f, "{}", san)?;
            }

            // Issuer Alternative Name
            if let Ok(Some(ian)) = self.extension::<extensions::IssuerAltName>() {
                write!(f, "{}", ian)?;
            }

            // Name Constraints
            if let Ok(Some(nc)) = self.extension::<extensions::NameConstraints>() {
                write!(f, "{}", nc)?;
            }

            // CRL Distribution Points
            if let Ok(Some(cdp)) = self.extension::<extensions::CRLDistributionPoints>() {
                write!(f, "{}", cdp)?;
            }

            // Certificate Policies
            if let Ok(Some(cp)) = self.extension::<extensions::CertificatePolicies>() {
                write!(f, "{}", cp)?;
            }

            // Policy Mappings
            if let Ok(Some(pm)) = self.extension::<extensions::PolicyMappings>() {
                write!(f, "{}", pm)?;
            }

            // Policy Constraints
            if let Ok(Some(pc)) = self.extension::<extensions::PolicyConstraints>() {
                write!(f, "{}", pc)?;
            }

            // Freshest CRL
            if let Ok(Some(fcrl)) = self.extension::<extensions::FreshestCRL>() {
                write!(f, "{}", fcrl)?;
            }

            // Inhibit Any Policy
            if let Ok(Some(iap)) = self.extension::<extensions::InhibitAnyPolicy>() {
                write!(f, "{}", iap)?;
            }

            // Authority Info Access
            if let Ok(Some(aia)) = self.extension::<extensions::AuthorityInfoAccess>() {
                write!(f, "{}", aia)?;
            }

            // Display any other extensions not explicitly handled above
            let handled_oids = vec![
                "2.5.29.14",         // SubjectKeyIdentifier
                "2.5.29.35",         // AuthorityKeyIdentifier
                "2.5.29.19",         // BasicConstraints
                "2.5.29.15",         // KeyUsage
                "2.5.29.37",         // ExtendedKeyUsage
                "2.5.29.17",         // SubjectAltName
                "2.5.29.18",         // IssuerAltName
                "2.5.29.30",         // NameConstraints
                "2.5.29.31",         // CRLDistributionPoints
                "2.5.29.32",         // CertificatePolicies
                "2.5.29.33",         // PolicyMappings
                "2.5.29.36",         // PolicyConstraints
                "2.5.29.46",         // FreshestCRL
                "2.5.29.54",         // InhibitAnyPolicy
                "1.3.6.1.5.5.7.1.1", // AuthorityInfoAccess
            ];

            if let Some(ref exts) = self.tbs_certificate.extensions {
                for raw_ext in exts.extensions() {
                    let oid_str = raw_ext.oid().to_string();
                    if !handled_oids.contains(&oid_str.as_str()) {
                        let ext_name = raw_ext.oid_name().unwrap_or(&oid_str);
                        let critical = if raw_ext.critical() { " critical" } else { "" };
                        writeln!(f, "            X509v3 {}:{}", ext_name, critical)?;
                        // Display raw value as hex
                        let value_bytes = raw_ext.value().as_bytes();
                        if value_bytes.len() <= 32 {
                            let hex_str: Vec<String> =
                                value_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                            writeln!(f, "                {}", hex_str.join(":"))?;
                        } else {
                            writeln!(f, "                <{} bytes>", value_bytes.len())?;
                        }
                    }
                }
            }
        }

        // Signature Algorithm (outer)
        let sig_alg_outer = self
            .signature_algorithm
            .oid_name()
            .map(|s| s.to_string())
            .unwrap_or_else(|| self.signature_algorithm.algorithm.to_string());
        writeln!(f, "    Signature Algorithm: {}", sig_alg_outer)?;

        // Signature Value
        let sig_bytes = self.signature_value.as_bytes();
        for chunk in sig_bytes.chunks(18) {
            let hex_str: Vec<String> = chunk.iter().map(|b| format!("{:02x}", b)).collect();
            writeln!(f, "         {}", hex_str.join(":"))?;
        }

        Ok(())
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

impl EncodableTo<Certificate> for Element {}

impl Encoder<Certificate, Element> for Certificate {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        Ok(Element::Sequence(vec![
            self.tbs_certificate.encode()?,
            self.signature_algorithm.encode()?,
            Element::BitString(self.signature_value.clone()),
        ]))
    }
}

impl EncodableTo<Certificate> for ASN1Object {}

impl Encoder<Certificate, ASN1Object> for Certificate {
    type Error = Error;

    fn encode(&self) -> Result<ASN1Object, Self::Error> {
        Ok(ASN1Object::new(vec![self.encode()?]))
    }
}

// Pem -> Certificate decoder
impl DecodableFrom<pem::Pem> for Certificate {}

impl Decoder<pem::Pem, Certificate> for pem::Pem {
    type Error = Error;

    fn decode(&self) -> Result<Certificate, Self::Error> {
        // Decode PEM to DER
        let der: der::Der = self.decode().map_err(|e| {
            Error::InvalidCertificate(format!("Failed to decode PEM to DER: {}", e))
        })?;

        // Decode DER to ASN1Object
        let asn1_obj: asn1::ASN1Object = der.decode().map_err(|e| {
            Error::InvalidCertificate(format!("Failed to decode DER to ASN1Object: {}", e))
        })?;

        // Get first element
        if asn1_obj.elements().is_empty() {
            return Err(Error::InvalidCertificate(
                "No elements in ASN1Object".to_string(),
            ));
        }
        let element = &asn1_obj.elements()[0];

        // Decode to Certificate
        element.decode()
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

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct TBSCertificate {
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

    /// Get the certificate version
    pub fn version(&self) -> &Version {
        &self.version
    }

    /// Get the serial number
    pub fn serial_number(&self) -> &CertificateSerialNumber {
        &self.serial_number
    }

    /// Get the signature algorithm
    pub fn signature(&self) -> &AlgorithmIdentifier {
        &self.signature
    }

    /// Get the issuer name
    pub fn issuer(&self) -> &Name {
        &self.issuer
    }

    /// Get the validity period
    pub fn validity(&self) -> &Validity {
        &self.validity
    }

    /// Get the subject name
    pub fn subject(&self) -> &Name {
        &self.subject
    }

    /// Get the subject public key info
    pub fn subject_public_key_info(&self) -> &SubjectPublicKeyInfo {
        &self.subject_public_key_info
    }
}

impl EncodableTo<TBSCertificate> for Element {}

impl Encoder<TBSCertificate, Element> for TBSCertificate {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        let mut elements = Vec::new();

        // version [0] EXPLICIT Version DEFAULT v1
        // Only include version if not V1
        if self.version != Version::V1 {
            elements.push(self.version.encode()?);
        }

        // serialNumber
        elements.push(self.serial_number.encode()?);

        // signature
        elements.push(self.signature.encode()?);

        // issuer
        elements.push(self.issuer.encode()?);

        // validity
        elements.push(self.validity.encode()?);

        // subject
        elements.push(self.subject.encode()?);

        // subjectPublicKeyInfo
        elements.push(self.subject_public_key_info.encode()?);

        // issuerUniqueID [1] IMPLICIT UniqueIdentifier OPTIONAL
        if let Some(ref issuer_uid) = self.issuer_unique_id {
            let bit_string = issuer_uid.encode()?;
            elements.push(Element::ContextSpecific {
                slot: 1,
                constructed: false,
                element: Box::new(bit_string),
            });
        }

        // subjectUniqueID [2] IMPLICIT UniqueIdentifier OPTIONAL
        if let Some(ref subject_uid) = self.subject_unique_id {
            let bit_string = subject_uid.encode()?;
            elements.push(Element::ContextSpecific {
                slot: 2,
                constructed: false,
                element: Box::new(bit_string),
            });
        }

        // extensions [3] EXPLICIT Extensions OPTIONAL
        if let Some(ref exts) = self.extensions {
            elements.push(exts.encode()?);
        }

        Ok(Element::Sequence(elements))
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

        for elem in iter {
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

/*
Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }

CertificateSerialNumber  ::=  INTEGER


Time ::= CHOICE {
    utcTime        UTCTime,
    generalTime    GeneralizedTime
}

UniqueIdentifier  ::=  BIT STRING

SubjectPublicKeyInfo is now provided by pkix-types

Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
*/

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
}

impl AsRef<BitString> for UniqueIdentifier {
    fn as_ref(&self) -> &BitString {
        &self.0
    }
}

impl From<UniqueIdentifier> for BitString {
    fn from(uid: UniqueIdentifier) -> Self {
        uid.0
    }
}

impl EncodableTo<UniqueIdentifier> for Element {}

impl Encoder<UniqueIdentifier, Element> for UniqueIdentifier {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        // UniqueIdentifier needs context-specific tagging [1] or [2] IMPLICIT
        // This is handled by the caller (TBSCertificate encoder)
        // Here we just return the BitString element
        Ok(Element::BitString(self.0.clone()))
    }
}

impl DecodableFrom<Element> for UniqueIdentifier {}

impl Decoder<Element, UniqueIdentifier> for Element {
    type Error = Error;

    fn decode(&self) -> Result<UniqueIdentifier, Self::Error> {
        // UniqueIdentifier appears as [1] IMPLICIT or [2] IMPLICIT UniqueIdentifier
        // IMPLICIT tagging means the element directly contains the BitString data
        match self {
            Element::ContextSpecific { slot, element, .. } => {
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
pub enum Version {
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
            Element::ContextSpecific { slot, element, .. } => {
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

impl EncodableTo<Version> for Element {}

impl Encoder<Version, Element> for Version {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        let version_value = *self as i64;
        let version_int = Integer::from(version_value.to_be_bytes().to_vec());
        Ok(Element::ContextSpecific {
            slot: 0,
            constructed: true,
            element: Box::new(Element::Integer(version_int)),
        })
    }
}

// CertificateSerialNumber is now in pkix-types crate
// No need for adapter implementations - pkix-types provides the Encoder/Decoder traits

// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5
/*
Validity ::= SEQUENCE {
    notBefore      Time,
    notAfter       Time
}
*/

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validity {
    not_before: NaiveDateTime,
    not_after: NaiveDateTime,
}

impl Validity {
    /// Get the not before date
    pub fn not_before(&self) -> &NaiveDateTime {
        &self.not_before
    }

    /// Get the not after date
    pub fn not_after(&self) -> &NaiveDateTime {
        &self.not_after
    }
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

impl EncodableTo<Validity> for Element {}

impl Encoder<Validity, Element> for Validity {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        // RFC 5280: Use UTCTime for years 1950-2049, GeneralizedTime otherwise
        let not_before_elm = if self.not_before.year() >= 1950 && self.not_before.year() < 2050 {
            Element::UTCTime(self.not_before)
        } else {
            Element::GeneralizedTime(self.not_before)
        };

        let not_after_elm = if self.not_after.year() >= 1950 && self.not_after.year() < 2050 {
            Element::UTCTime(self.not_after)
        } else {
            Element::GeneralizedTime(self.not_after)
        };

        Ok(Element::Sequence(vec![not_before_elm, not_after_elm]))
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
    extensions: Option<ParsedExtensions>,
}

impl TryFrom<&TBSCertificate> for SerializableTBSCertificate {
    type Error = Error;

    fn try_from(tbs: &TBSCertificate) -> Result<Self, Self::Error> {
        let extensions = if let Some(ref exts) = tbs.extensions {
            Some(ParsedExtensions::from_extensions(exts)?)
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

// Helper functions for Display implementation

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::{Extension, Extensions, RawExtension};
    use crate::types::{AttributeTypeAndValue, Name, RelativeDistinguishedName};
    use asn1::{BitString, OctetString};
    use chrono::NaiveDate;
    use der::Der;
    use pem::Pem;
    use rstest::rstest;
    use std::str::FromStr;

    // AlgorithmIdentifier tests
    #[rstest(
        input,
        expected,
        // Test case: Algorithm without parameters (None = Absent)
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str(pkix_types::AlgorithmIdentifier::OID_SHA256_WITH_RSA_ENCRYPTION).unwrap()), // sha256WithRSAEncryption
            ]),
            AlgorithmIdentifier {
                algorithm: ObjectIdentifier::from_str(pkix_types::AlgorithmIdentifier::OID_SHA256_WITH_RSA_ENCRYPTION).unwrap(),
                parameters: None,
            }
        ),
        // Test case: Algorithm with NULL parameters
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str(pkix_types::AlgorithmIdentifier::OID_SHA256_WITH_RSA_ENCRYPTION).unwrap()),
                Element::Null,
            ]),
            AlgorithmIdentifier {
                algorithm: ObjectIdentifier::from_str(pkix_types::AlgorithmIdentifier::OID_SHA256_WITH_RSA_ENCRYPTION).unwrap(),
                parameters: Some(AlgorithmParameters::Null),
            }
        ),
        // Test case: Algorithm with OctetString parameters
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str(pkix_types::AlgorithmIdentifier::OID_ECDSA_WITH_SHA256).unwrap()), // ecdsa-with-SHA256
                Element::OctetString(asn1::OctetString::from(vec![0x01, 0x02, 0x03])),
            ]),
            AlgorithmIdentifier {
                algorithm: ObjectIdentifier::from_str(pkix_types::AlgorithmIdentifier::OID_ECDSA_WITH_SHA256).unwrap(),
                parameters: Some(AlgorithmParameters::Other(
                    RawAlgorithmParameter::new(Element::OctetString(asn1::OctetString::from(vec![0x01, 0x02, 0x03])))
                )),
            }
        ),
        // Test case: Algorithm with OID parameters - ECDSA curve
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str(pkix_types::AlgorithmIdentifier::OID_EC_PUBLIC_KEY).unwrap()), // ecPublicKey
                Element::ObjectIdentifier(ObjectIdentifier::from_str(pkix_types::algorithm::parameters::ec::NamedCurve::OID_SECP256R1).unwrap()), // secp256r1 (prime256v1)
            ]),
            AlgorithmIdentifier {
                algorithm: ObjectIdentifier::from_str(pkix_types::AlgorithmIdentifier::OID_EC_PUBLIC_KEY).unwrap(),
                parameters: Some(AlgorithmParameters::Other(
                    RawAlgorithmParameter::new(Element::ObjectIdentifier(ObjectIdentifier::from_str(pkix_types::algorithm::parameters::ec::NamedCurve::OID_SECP256R1).unwrap()))
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
        let result: Result<AlgorithmIdentifier, _> = input.decode();
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
            constructed: true,
            slot: 0,
            element: Box::new(Element::Integer(Integer::from(vec![0x00])))
        },
        Version::V1
    )]
    #[case::v2(
        Element::ContextSpecific {
            constructed: true,
            slot: 0,
            element: Box::new(Element::Integer(Integer::from(vec![0x01])))
        },
        Version::V2
    )]
    #[case::v3(
        Element::ContextSpecific {
            constructed: true,
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
            constructed: true,
            slot: 0,
            element: Box::new(Element::Integer(Integer::from(vec![0x03])))
        },
        "InvalidVersion"
    )]
    #[case::wrong_slot(
        Element::ContextSpecific {
            constructed: true,
            slot: 1,
            element: Box::new(Element::Integer(Integer::from(vec![0x00])))
        },
        "InvalidVersion"
    )]
    #[case::not_integer_inside(
        Element::ContextSpecific {
            constructed: true,
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
        CertificateSerialNumber::from(Integer::from(vec![0x01]))
    )]
    #[case::medium_serial(
        Element::Integer(Integer::from(vec![0x01, 0x02, 0x03, 0x04])),
        CertificateSerialNumber::from(Integer::from(vec![0x01, 0x02, 0x03, 0x04]))
    )]
    #[case::long_serial(
        Element::Integer(Integer::from(vec![
            0x48, 0xc3, 0x54, 0x8e, 0x4a, 0x5e, 0xe7, 0x64,
            0x74, 0x7b, 0xb0, 0x50, 0xc9, 0x16, 0xea, 0xae,
            0x99, 0xd6, 0x8f, 0x82
        ])),
        CertificateSerialNumber::from(Integer::from(vec![
            0x48, 0xc3, 0x54, 0x8e, 0x4a, 0x5e, 0xe7, 0x64,
            0x74, 0x7b, 0xb0, 0x50, 0xc9, 0x16, 0xea, 0xae,
            0x99, 0xd6, 0x8f, 0x82
        ]))
    )]
    fn test_certificate_serial_number_decode_success(
        #[case] input: Element,
        #[case] expected: CertificateSerialNumber,
    ) {
        let result: Result<CertificateSerialNumber, pkix_types::Error> = input.decode();
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
        let result: Result<CertificateSerialNumber, pkix_types::Error> = input.decode();
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
                    Element::ObjectIdentifier(ObjectIdentifier::from_str(pkix_types::AlgorithmIdentifier::OID_RSA_ENCRYPTION).unwrap()), // rsaEncryption
                    Element::Null,
                ]),
                Element::BitString(BitString::new(0, vec![
                    0x30, 0x82, 0x01, 0x0a, // SEQUENCE header
                    0x02, 0x82, 0x01, 0x01, // INTEGER (modulus)
                    0x00, 0xb4, 0x6c, 0x8f, // First few bytes of modulus
                ])),
            ]),
            SubjectPublicKeyInfo::new(
                AlgorithmIdentifier::new_with_params(
                    ObjectIdentifier::from_str(pkix_types::AlgorithmIdentifier::OID_RSA_ENCRYPTION).unwrap(),
                    AlgorithmParameters::Null,
                ),
                BitString::new(0, vec![
                    0x30, 0x82, 0x01, 0x0a,
                    0x02, 0x82, 0x01, 0x01,
                    0x00, 0xb4, 0x6c, 0x8f,
                ]),
            )
        ),
        // Test case: ECDSA public key (P-256)
        case(
            Element::Sequence(vec![
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str(pkix_types::AlgorithmIdentifier::OID_EC_PUBLIC_KEY).unwrap()), // ecPublicKey
                    Element::ObjectIdentifier(ObjectIdentifier::from_str(pkix_types::algorithm::parameters::ec::NamedCurve::OID_SECP256R1).unwrap()), // secp256r1
                ]),
                Element::BitString(BitString::new(0, vec![
                    0x04, // Uncompressed point
                    0x8d, 0x61, 0x7e, 0x65, // X coordinate (first 4 bytes)
                    0x3b, 0x6b, 0x80, 0x69, // Y coordinate (first 4 bytes)
                ])),
            ]),
            SubjectPublicKeyInfo::new(
                AlgorithmIdentifier::new_with_params(
                    ObjectIdentifier::from_str(pkix_types::AlgorithmIdentifier::OID_EC_PUBLIC_KEY).unwrap(),
                    AlgorithmParameters::Other(
                        RawAlgorithmParameter::new(Element::ObjectIdentifier(ObjectIdentifier::from_str(pkix_types::algorithm::parameters::ec::NamedCurve::OID_SECP256R1).unwrap()))
                    ),
                ),
                BitString::new(0, vec![
                    0x04,
                    0x8d, 0x61, 0x7e, 0x65,
                    0x3b, 0x6b, 0x80, 0x69,
                ]),
            )
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
            SubjectPublicKeyInfo::new(
                AlgorithmIdentifier::new(
                    ObjectIdentifier::from_str("1.3.101.112").unwrap(),
                ),
                BitString::new(0, vec![
                    0x8d, 0x61, 0x7e, 0x65, 0x3b, 0x6b, 0x80, 0x69,
                    0x1b, 0x21, 0x4c, 0x28, 0xf8, 0x3a, 0x8b, 0x27,
                    0x3f, 0x49, 0x40, 0xea, 0xc0, 0x8e, 0x73, 0x6d,
                    0x9f, 0x3f, 0x31, 0x21, 0x91, 0x3b, 0xa2, 0x16,
                ]),
            )
        ),
        // Test case: BitString with unused bits
        case(
            Element::Sequence(vec![
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str(pkix_types::AlgorithmIdentifier::OID_RSA_ENCRYPTION).unwrap()),
                    Element::Null,
                ]),
                Element::BitString(BitString::new(3, vec![0xFF, 0xE0])), // 13 bits (3 unused in last byte)
            ]),
            SubjectPublicKeyInfo::new(
                AlgorithmIdentifier::new_with_params(
                    ObjectIdentifier::from_str(pkix_types::AlgorithmIdentifier::OID_RSA_ENCRYPTION).unwrap(),
                    AlgorithmParameters::Null,
                ),
                BitString::new(3, vec![0xFF, 0xE0]),
            )
        ),
    )]
    fn test_subject_public_key_info_decode_success(input: Element, expected: SubjectPublicKeyInfo) {
        let result: Result<SubjectPublicKeyInfo, pkix_types::Error> = input.decode();
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
                    Element::ObjectIdentifier(ObjectIdentifier::from_str(pkix_types::AlgorithmIdentifier::OID_RSA_ENCRYPTION).unwrap()),
                ]),
            ]),
            "expected 2 elements in sequence, got 1"
        ),
        // Test case: Too many elements
        case(
            Element::Sequence(vec![
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str(pkix_types::AlgorithmIdentifier::OID_RSA_ENCRYPTION).unwrap()),
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
            "Invalid algorithm identifier"
        ),
        // Test case: Second element is not BitString
        case(
            Element::Sequence(vec![
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str(pkix_types::AlgorithmIdentifier::OID_RSA_ENCRYPTION).unwrap()),
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
            "Invalid algorithm identifier"
        ),
    )]
    fn test_subject_public_key_info_decode_failure(input: Element, expected_error_msg: &str) {
        let result: Result<SubjectPublicKeyInfo, pkix_types::Error> = input.decode();
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
        assert_eq!(cert.tbs_certificate.issuer.rdn_sequence().len(), 3); // C, O, CN
        assert_eq!(cert.tbs_certificate.subject.rdn_sequence().len(), 3);
    }

    #[test]
    fn test_decode_v3_ca_certificate() {
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
        assert_eq!(cert.tbs_certificate.issuer.rdn_sequence().len(), 6); // C, ST, L, O, OU, CN
    }

    #[test]
    fn test_decode_v3_ee_certificate() {
        let pem = Pem::from_str(TEST_CERT_V3_EE).unwrap();
        let der: Der = pem.decode().unwrap();
        let asn1_obj: ASN1Object = der.decode().unwrap();

        let cert: Certificate = asn1_obj.decode().unwrap();

        // Print Display output (OpenSSL-like format)
        println!("\n=== V3 End Entity Certificate (Display) ===");
        println!("{}", cert);

        // Print JSON output
        let json_output = serde_json::to_string_pretty(&cert).unwrap();
        println!("\n=== V3 End Entity Certificate (JSON) ===");
        println!("{}", json_output);

        // V3 End Entity certificate assertions
        assert_eq!(cert.tbs_certificate.version, Version::V3);
        assert!(cert.tbs_certificate.extensions.is_some());
        let extensions = cert.tbs_certificate.extensions.as_ref().unwrap();
        assert_eq!(extensions.extensions().len(), 4); // SKI, KeyUsage, ExtKeyUsage, SAN
        assert_eq!(cert.tbs_certificate.issuer.rdn_sequence().len(), 4); // C, ST, O, CN
    }

    #[test]
    fn test_decode_v3_ecdsa_p256_certificate() {
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
                .algorithm()
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
                .algorithm()
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
            cert.tbs_certificate.issuer.rdn_sequence().len(),
            3 // C, O, CN
        );
        assert_eq!(
            cert.tbs_certificate.subject.rdn_sequence().len(),
            3 // C, O, CN
        );
    }

    // Encoder tests
    #[rstest(
        alg_id,
        expected_len,
        case(
            AlgorithmIdentifier {
                algorithm: ObjectIdentifier::from_str(pkix_types::AlgorithmIdentifier::OID_SHA256_WITH_RSA_ENCRYPTION).unwrap(),
                parameters: None,
            },
            1
        ),
        case(
            AlgorithmIdentifier {
                algorithm: ObjectIdentifier::from_str(pkix_types::AlgorithmIdentifier::OID_SHA256_WITH_RSA_ENCRYPTION).unwrap(),
                parameters: Some(AlgorithmParameters::Null),
            },
            2
        ),
        case(
            AlgorithmIdentifier {
                algorithm: ObjectIdentifier::from_str(pkix_types::AlgorithmIdentifier::OID_ECDSA_WITH_SHA256).unwrap(),
                parameters: Some(AlgorithmParameters::Other(
                    RawAlgorithmParameter::new(Element::OctetString(OctetString::from(vec![0x01, 0x02, 0x03])))
                )),
            },
            2
        )
    )]
    fn test_algorithm_identifier_encode(alg_id: AlgorithmIdentifier, expected_len: usize) {
        let encoded = alg_id.encode().unwrap();

        match &encoded {
            Element::Sequence(elems) => {
                assert_eq!(elems.len(), expected_len);
                assert!(matches!(elems[0], Element::ObjectIdentifier(_)));
                if expected_len == 2 {
                    // Parameters exist
                    assert!(alg_id.parameters.is_some());
                }
            }
            _ => panic!("Expected Sequence"),
        }

        // Round-trip test
        let decoded: AlgorithmIdentifier = encoded.decode().unwrap();
        assert_eq!(decoded, alg_id);
    }

    #[rstest(
        version,
        expected_value,
        case(Version::V1, 0),
        case(Version::V2, 1),
        case(Version::V3, 2)
    )]
    fn test_version_encode(version: Version, expected_value: u64) {
        let encoded = version.encode().unwrap();
        match encoded {
            Element::ContextSpecific {
                slot, ref element, ..
            } => {
                assert_eq!(slot, 0);
                match element.as_ref() {
                    Element::Integer(i) => {
                        let value = u64::try_from(i).unwrap();
                        assert_eq!(value, expected_value);
                    }
                    _ => panic!("Expected Integer inside context-specific tag"),
                }
            }
            _ => panic!("Expected ContextSpecific"),
        }

        // Round-trip test
        let decoded: Version = encoded.decode().unwrap();
        assert_eq!(decoded, version);
    }

    #[rstest(
        serial_bytes,
        case(vec![0x01]),
        case(vec![0x01, 0x23, 0x45, 0x67, 0x89]),
        case(vec![0x7f, 0xee, 0xdd, 0xcc, 0xbb, 0xaa]) // Use 0x7f to avoid sign bit issues
    )]
    fn test_certificate_serial_number_encode(serial_bytes: Vec<u8>) {
        let serial = CertificateSerialNumber::from_bytes(serial_bytes.clone());

        let encoded = serial.encode().unwrap();

        match &encoded {
            Element::Integer(_) => {
                // Just verify it's an Integer
            }
            _ => panic!("Expected Integer"),
        }

        // Round-trip test is the most important
        let decoded: CertificateSerialNumber = encoded.decode().unwrap();
        assert_eq!(decoded, serial);
    }

    #[rstest(
        not_before,
        not_after,
        case(
            NaiveDate::from_ymd_opt(2024, 1, 1).unwrap().and_hms_opt(0, 0, 0).unwrap(),
            NaiveDate::from_ymd_opt(2025, 1, 1).unwrap().and_hms_opt(0, 0, 0).unwrap()
        ),
        case(
            NaiveDate::from_ymd_opt(1950, 1, 1).unwrap().and_hms_opt(0, 0, 0).unwrap(),
            NaiveDate::from_ymd_opt(2049, 12, 31).unwrap().and_hms_opt(23, 59, 59).unwrap()
        ),
        case(
            NaiveDate::from_ymd_opt(1949, 12, 31).unwrap().and_hms_opt(23, 59, 59).unwrap(),
            NaiveDate::from_ymd_opt(2050, 1, 1).unwrap().and_hms_opt(0, 0, 0).unwrap()
        )
    )]
    fn test_validity_encode(not_before: NaiveDateTime, not_after: NaiveDateTime) {
        let validity = Validity {
            not_before,
            not_after,
        };

        let encoded = validity.encode().unwrap();

        match &encoded {
            Element::Sequence(elements) => {
                assert_eq!(elements.len(), 2);

                // Check that dates in range 1950-2049 use UTCTime
                match &elements[0] {
                    Element::UTCTime(_) => {
                        assert!(not_before.year() >= 1950 && not_before.year() < 2050);
                    }
                    Element::GeneralizedTime(_) => {
                        assert!(not_before.year() < 1950 || not_before.year() >= 2050);
                    }
                    _ => panic!("Expected UTCTime or GeneralizedTime for notBefore"),
                }

                match &elements[1] {
                    Element::UTCTime(_) => {
                        assert!(not_after.year() >= 1950 && not_after.year() < 2050);
                    }
                    Element::GeneralizedTime(_) => {
                        assert!(not_after.year() < 1950 || not_after.year() >= 2050);
                    }
                    _ => panic!("Expected UTCTime or GeneralizedTime for notAfter"),
                }
            }
            _ => panic!("Expected Sequence"),
        }

        // Round-trip test
        let decoded: Validity = encoded.decode().unwrap();
        assert_eq!(decoded, validity);
    }

    #[rstest(
        algorithm,
        public_key_bytes,
        case(
            AlgorithmIdentifier {
                algorithm: ObjectIdentifier::from_str(pkix_types::AlgorithmIdentifier::OID_RSA_ENCRYPTION).unwrap(), // RSA
                parameters: None,
            },
            vec![0x30, 0x0d, 0x06, 0x09] // Sample RSA public key bytes
        ),
        case(
            AlgorithmIdentifier {
                algorithm: ObjectIdentifier::from_str(pkix_types::AlgorithmIdentifier::OID_EC_PUBLIC_KEY).unwrap(), // EC public key
                parameters: Some(AlgorithmParameters::Other(
                    RawAlgorithmParameter::new(Element::ObjectIdentifier(ObjectIdentifier::from_str(pkix_types::algorithm::parameters::ec::NamedCurve::OID_SECP256R1).unwrap())) // prime256v1
                )),
            },
            vec![0x04, 0x41] // Sample EC public key bytes
        ),
        case(
            AlgorithmIdentifier {
                algorithm: ObjectIdentifier::from_str(pkix_types::AlgorithmIdentifier::OID_EC_PUBLIC_KEY).unwrap(), // EC public key
                parameters: Some(AlgorithmParameters::Null),
            },
            vec![0xff, 0xee, 0xdd] // Different key bytes
        )
    )]
    fn test_subject_public_key_info_encode(
        algorithm: AlgorithmIdentifier,
        public_key_bytes: Vec<u8>,
    ) {
        let subject_public_key_info = SubjectPublicKeyInfo::new(
            algorithm.clone(),
            BitString::new(0, public_key_bytes.clone()),
        );

        let encoded = subject_public_key_info.encode().unwrap();

        match &encoded {
            Element::Sequence(elements) => {
                assert_eq!(elements.len(), 2);

                // First element should be the algorithm identifier
                let decoded_algorithm: AlgorithmIdentifier = elements[0].decode().unwrap();
                assert_eq!(decoded_algorithm, algorithm);

                // Second element should be a BitString
                match &elements[1] {
                    Element::BitString(bs) => {
                        assert_eq!(bs.as_bytes(), public_key_bytes.as_slice());
                    }
                    _ => panic!("Expected BitString for subject public key"),
                }
            }
            _ => panic!("Expected Sequence"),
        }

        // Round-trip test
        let decoded: SubjectPublicKeyInfo = encoded.decode().unwrap();
        assert_eq!(decoded, subject_public_key_info);
    }

    #[rstest(
        name,
        case(Name {
            rdn_sequence: vec![
                RelativeDistinguishedName {
                    attributes: vec![AttributeTypeAndValue {
                        attribute_type: ObjectIdentifier::from_str(pkix_types::AttributeTypeAndValue::OID_COMMON_NAME).unwrap(),
                        attribute_value: "Example CA".to_string(),
                    }],
                },
            ],
        }),
        case(Name {
            rdn_sequence: vec![
                RelativeDistinguishedName {
                    attributes: vec![AttributeTypeAndValue {
                        attribute_type: ObjectIdentifier::from_str(pkix_types::AttributeTypeAndValue::OID_COUNTRY_NAME).unwrap(),
                        attribute_value: "US".to_string(),
                    }],
                },
                RelativeDistinguishedName {
                    attributes: vec![AttributeTypeAndValue {
                        attribute_type: ObjectIdentifier::from_str(pkix_types::AttributeTypeAndValue::OID_STATE_OR_PROVINCE_NAME).unwrap(),
                        attribute_value: "California".to_string(),
                    }],
                },
                RelativeDistinguishedName {
                    attributes: vec![AttributeTypeAndValue {
                        attribute_type: ObjectIdentifier::from_str(pkix_types::AttributeTypeAndValue::OID_ORGANIZATION_NAME).unwrap(),
                        attribute_value: "Example Corp".to_string(),
                    }],
                },
            ],
        }),
        case(Name {
            rdn_sequence: vec![
                RelativeDistinguishedName {
                    attributes: vec![AttributeTypeAndValue {
                        attribute_type: ObjectIdentifier::from_str(pkix_types::AttributeTypeAndValue::OID_COUNTRY_NAME).unwrap(),
                        attribute_value: "JP".to_string(),
                    }],
                },
                RelativeDistinguishedName {
                    attributes: vec![AttributeTypeAndValue {
                        attribute_type: ObjectIdentifier::from_str(pkix_types::AttributeTypeAndValue::OID_STATE_OR_PROVINCE_NAME).unwrap(),
                        attribute_value: "Tokyo".to_string(),
                    }],
                },
                RelativeDistinguishedName {
                    attributes: vec![
                        AttributeTypeAndValue {
                            attribute_type: ObjectIdentifier::from_str(pkix_types::AttributeTypeAndValue::OID_ORGANIZATION_NAME).unwrap(),
                            attribute_value: "ACME Inc".to_string(),
                        },
                        AttributeTypeAndValue {
                            attribute_type: ObjectIdentifier::from_str(pkix_types::AttributeTypeAndValue::OID_ORGANIZATIONAL_UNIT_NAME).unwrap(),
                            attribute_value: "Engineering".to_string(),
                        },
                    ],
                },
                RelativeDistinguishedName {
                    attributes: vec![AttributeTypeAndValue {
                        attribute_type: ObjectIdentifier::from_str(pkix_types::AttributeTypeAndValue::OID_COMMON_NAME).unwrap(),
                        attribute_value: "www.example.com".to_string(),
                    }],
                },
            ],
        }),
        case(Name {
            rdn_sequence: vec![
                RelativeDistinguishedName {
                    attributes: vec![AttributeTypeAndValue {
                        attribute_type: ObjectIdentifier::from_str(pkix_types::AttributeTypeAndValue::OID_COMMON_NAME).unwrap(),
                        attribute_value: "日本語ドメイン.jp".to_string(),
                    }],
                },
            ],
        })
    )]
    fn test_name_encode(name: Name) {
        let encoded = name.encode().unwrap();

        match &encoded {
            Element::Sequence(rdn_elements) => {
                assert_eq!(rdn_elements.len(), name.rdn_sequence().len());
                for (i, rdn_elm) in rdn_elements.iter().enumerate() {
                    match rdn_elm {
                        Element::Set(attr_elements) => {
                            assert_eq!(
                                attr_elements.len(),
                                name.rdn_sequence()[i].attributes.len()
                            );
                            for (j, attr_elm) in attr_elements.iter().enumerate() {
                                match attr_elm {
                                    Element::Sequence(seq) => {
                                        assert_eq!(seq.len(), 2);
                                        match &seq[0] {
                                            Element::ObjectIdentifier(oid) => {
                                                assert_eq!(
                                                    oid,
                                                    &name.rdn_sequence()[i].attributes[j]
                                                        .attribute_type
                                                );
                                            }
                                            _ => panic!("Expected ObjectIdentifier"),
                                        }
                                        // Check that appropriate string type is used
                                        match &seq[1] {
                                            Element::PrintableString(s) => {
                                                assert_eq!(
                                                    s,
                                                    &name.rdn_sequence()[i].attributes[j]
                                                        .attribute_value
                                                );
                                            }
                                            Element::UTF8String(s) => {
                                                assert_eq!(
                                                    s,
                                                    &name.rdn_sequence()[i].attributes[j]
                                                        .attribute_value
                                                );
                                            }
                                            _ => panic!("Expected PrintableString or UTF8String"),
                                        }
                                    }
                                    _ => panic!("Expected Sequence for AttributeTypeAndValue"),
                                }
                            }
                        }
                        _ => panic!("Expected Set for RDN"),
                    }
                }
            }
            _ => panic!("Expected Sequence"),
        }

        // Round-trip test
        let decoded: Name = encoded.decode().unwrap();
        assert_eq!(decoded, name);
    }

    #[rstest(
        exts,
        case(Extensions {
            extensions: vec![
                RawExtension::new(
                    ObjectIdentifier::from_str(crate::extensions::BasicConstraints::OID).unwrap(),
                    false,
                    OctetString::from(vec![0x30, 0x00]),
                ),
            ],
        }),
        case(Extensions {
            extensions: vec![
                RawExtension::new(
                    ObjectIdentifier::from_str(crate::extensions::KeyUsage::OID).unwrap(),
                    true,
                    OctetString::from(vec![0x03, 0x02, 0x05, 0xa0]),
                ),
            ],
        }),
        case(Extensions {
            extensions: vec![
                RawExtension::new(
                    ObjectIdentifier::from_str(crate::extensions::BasicConstraints::OID).unwrap(),
                    true,
                    OctetString::from(vec![0x30, 0x03, 0x01, 0x01, 0xff]),
                ),
                RawExtension::new(
                    ObjectIdentifier::from_str(crate::extensions::SubjectKeyIdentifier::OID).unwrap(),
                    false,
                    OctetString::from(vec![0x04, 0x14, 0x01, 0x02, 0x03]),
                ),
            ],
        })
    )]
    fn test_extensions_encode(exts: Extensions) {
        let encoded = exts.encode().unwrap();

        // Should be wrapped in [3] EXPLICIT
        match &encoded {
            Element::ContextSpecific { slot, element, .. } => {
                assert_eq!(slot, &3);
                match element.as_ref() {
                    Element::Sequence(ext_elements) => {
                        assert_eq!(ext_elements.len(), exts.extensions.len());

                        for (i, ext_elm) in ext_elements.iter().enumerate() {
                            match ext_elm {
                                Element::Sequence(fields) => {
                                    // Check OID
                                    match &fields[0] {
                                        Element::ObjectIdentifier(oid) => {
                                            assert_eq!(oid, exts.extensions[i].oid());
                                        }
                                        _ => panic!("Expected ObjectIdentifier"),
                                    }

                                    // Check critical field (only present if true)
                                    let value_index = if exts.extensions[i].is_critical() {
                                        assert_eq!(fields.len(), 3);
                                        match &fields[1] {
                                            Element::Boolean(b) => assert!(b),
                                            _ => panic!("Expected Boolean"),
                                        }
                                        2
                                    } else {
                                        assert_eq!(fields.len(), 2);
                                        1
                                    };

                                    // Check value
                                    match &fields[value_index] {
                                        Element::OctetString(octets) => {
                                            assert_eq!(
                                                octets.as_bytes(),
                                                exts.extensions[i].value().as_bytes()
                                            );
                                        }
                                        _ => panic!("Expected OctetString"),
                                    }
                                }
                                _ => panic!("Expected Sequence for Extension"),
                            }
                        }
                    }
                    _ => panic!("Expected Sequence inside [3]"),
                }
            }
            _ => panic!("Expected ContextSpecific [3]"),
        }

        // Round-trip test
        let decoded: Extensions = encoded.decode().unwrap();
        assert_eq!(decoded, exts);
    }

    fn create_tbs_v3_with_extensions() -> TBSCertificate {
        TBSCertificate {
            version: Version::V3,
            serial_number: CertificateSerialNumber::from_bytes(vec![0x01, 0x02, 0x03]),
            signature: AlgorithmIdentifier {
                algorithm: ObjectIdentifier::from_str(
                    pkix_types::AlgorithmIdentifier::OID_SHA256_WITH_RSA_ENCRYPTION,
                )
                .unwrap(),
                parameters: Some(AlgorithmParameters::Null),
            },
            issuer: Name {
                rdn_sequence: vec![RelativeDistinguishedName {
                    attributes: vec![AttributeTypeAndValue {
                        attribute_type: ObjectIdentifier::from_str(
                            pkix_types::AttributeTypeAndValue::OID_COMMON_NAME,
                        )
                        .unwrap(),
                        attribute_value: "Test CA".to_string(),
                    }],
                }],
            },
            validity: Validity {
                not_before: NaiveDate::from_ymd_opt(2024, 1, 1)
                    .unwrap()
                    .and_hms_opt(0, 0, 0)
                    .unwrap(),
                not_after: NaiveDate::from_ymd_opt(2025, 1, 1)
                    .unwrap()
                    .and_hms_opt(0, 0, 0)
                    .unwrap(),
            },
            subject: Name {
                rdn_sequence: vec![RelativeDistinguishedName {
                    attributes: vec![AttributeTypeAndValue {
                        attribute_type: ObjectIdentifier::from_str(
                            pkix_types::AttributeTypeAndValue::OID_COMMON_NAME,
                        )
                        .unwrap(),
                        attribute_value: "Test Subject".to_string(),
                    }],
                }],
            },
            subject_public_key_info: SubjectPublicKeyInfo::new(
                AlgorithmIdentifier::new_with_params(
                    ObjectIdentifier::from_str("1.2.840.113549.1.1.1").unwrap(),
                    AlgorithmParameters::Null,
                ),
                BitString::new(0, vec![0x30, 0x0d]),
            ),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(Extensions {
                extensions: vec![RawExtension::new(
                    ObjectIdentifier::from_str(crate::extensions::BasicConstraints::OID).unwrap(),
                    true,
                    OctetString::from(vec![0x30, 0x03, 0x01, 0x01, 0xff]),
                )],
            }),
        }
    }

    fn create_tbs_v1_minimal() -> TBSCertificate {
        TBSCertificate {
            version: Version::V1,
            serial_number: CertificateSerialNumber::from_bytes(vec![0x01]),
            signature: AlgorithmIdentifier {
                algorithm: ObjectIdentifier::from_str("1.2.840.113549.1.1.5").unwrap(),
                parameters: Some(AlgorithmParameters::Null),
            },
            issuer: Name {
                rdn_sequence: vec![RelativeDistinguishedName {
                    attributes: vec![AttributeTypeAndValue {
                        attribute_type: ObjectIdentifier::from_str(
                            pkix_types::AttributeTypeAndValue::OID_COMMON_NAME,
                        )
                        .unwrap(),
                        attribute_value: "CA".to_string(),
                    }],
                }],
            },
            validity: Validity {
                not_before: NaiveDate::from_ymd_opt(2000, 1, 1)
                    .unwrap()
                    .and_hms_opt(0, 0, 0)
                    .unwrap(),
                not_after: NaiveDate::from_ymd_opt(2001, 1, 1)
                    .unwrap()
                    .and_hms_opt(0, 0, 0)
                    .unwrap(),
            },
            subject: Name {
                rdn_sequence: vec![RelativeDistinguishedName {
                    attributes: vec![AttributeTypeAndValue {
                        attribute_type: ObjectIdentifier::from_str(
                            pkix_types::AttributeTypeAndValue::OID_COMMON_NAME,
                        )
                        .unwrap(),
                        attribute_value: "Subject".to_string(),
                    }],
                }],
            },
            subject_public_key_info: SubjectPublicKeyInfo::new(
                AlgorithmIdentifier::new_with_params(
                    ObjectIdentifier::from_str("1.2.840.113549.1.1.1").unwrap(),
                    AlgorithmParameters::Null,
                ),
                BitString::new(0, vec![0x30, 0x0d]),
            ),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: None,
        }
    }

    #[rstest(
        tbs,
        case(create_tbs_v3_with_extensions()),
        case(create_tbs_v1_minimal())
    )]
    fn test_tbs_certificate_encode(tbs: TBSCertificate) {
        let encoded = tbs.encode().unwrap();

        // Should be a Sequence
        match &encoded {
            Element::Sequence(elements) => {
                // V1 certificates have 6 fields (no version field)
                // V3 certificates with extensions have 8 fields (version + 6 required + extensions)
                if tbs.version == Version::V1 {
                    assert_eq!(elements.len(), 6);
                } else {
                    assert!(elements.len() >= 7);
                }
            }
            _ => panic!("Expected Sequence for TBSCertificate"),
        }

        // Round-trip test
        let decoded: TBSCertificate = encoded.decode().unwrap();
        assert_eq!(decoded.version, tbs.version);
        assert_eq!(decoded.serial_number, tbs.serial_number);
        assert_eq!(decoded.signature, tbs.signature);
        assert_eq!(decoded.issuer, tbs.issuer);
        assert_eq!(decoded.validity, tbs.validity);
        assert_eq!(decoded.subject, tbs.subject);
        assert_eq!(decoded.subject_public_key_info, tbs.subject_public_key_info);
        assert_eq!(decoded.issuer_unique_id, tbs.issuer_unique_id);
        assert_eq!(decoded.subject_unique_id, tbs.subject_unique_id);
        assert_eq!(decoded.extensions, tbs.extensions);
    }

    #[test]
    fn test_certificate_encode_decode_roundtrip() {
        // Test with a real V3 certificate
        let pem = Pem::from_str(TEST_CERT_V3_EE).unwrap();
        let der: Der = pem.decode().unwrap();
        let asn1_obj: ASN1Object = der.decode().unwrap();

        // Decode certificate
        let cert: Certificate = asn1_obj.decode().unwrap();

        // Encode certificate
        let encoded_element: Element = cert.encode().unwrap();

        // Decode back
        let decoded_cert: Certificate = encoded_element.decode().unwrap();

        // Verify all fields match
        assert_eq!(decoded_cert.tbs_certificate, cert.tbs_certificate);
        assert_eq!(decoded_cert.signature_algorithm, cert.signature_algorithm);
        assert_eq!(decoded_cert.signature_value, cert.signature_value);
    }

    #[test]
    fn test_certificate_encode_decode_v1() {
        // Test with V1 certificate (no extensions)
        let pem = Pem::from_str(TEST_CERT_V1).unwrap();
        let der: Der = pem.decode().unwrap();
        let asn1_obj: ASN1Object = der.decode().unwrap();

        let cert: Certificate = asn1_obj.decode().unwrap();
        let encoded_element: Element = cert.encode().unwrap();
        let decoded_cert: Certificate = encoded_element.decode().unwrap();

        assert_eq!(decoded_cert.tbs_certificate.version, Version::V1);
        assert_eq!(decoded_cert.tbs_certificate, cert.tbs_certificate);
        assert_eq!(decoded_cert.signature_algorithm, cert.signature_algorithm);
        assert_eq!(decoded_cert.signature_value, cert.signature_value);
    }

    #[test]
    fn test_certificate_encode_decode_v3_ca() {
        // Test with V3 CA certificate
        let pem = Pem::from_str(TEST_CERT_V3_CA).unwrap();
        let der: Der = pem.decode().unwrap();
        let asn1_obj: ASN1Object = der.decode().unwrap();

        let cert: Certificate = asn1_obj.decode().unwrap();
        let encoded_element: Element = cert.encode().unwrap();
        let decoded_cert: Certificate = encoded_element.decode().unwrap();

        assert_eq!(decoded_cert.tbs_certificate.version, Version::V3);
        assert!(decoded_cert.tbs_certificate.extensions.is_some());
        assert_eq!(decoded_cert.tbs_certificate, cert.tbs_certificate);
        assert_eq!(decoded_cert.signature_algorithm, cert.signature_algorithm);
        assert_eq!(decoded_cert.signature_value, cert.signature_value);
    }

    #[test]
    fn test_certificate_encode_to_asn1object() {
        // Test with V3 EE certificate
        let pem = Pem::from_str(TEST_CERT_V3_EE).unwrap();
        let der: Der = pem.decode().unwrap();
        let original_asn1_obj: ASN1Object = der.decode().unwrap();

        // Decode certificate
        let cert: Certificate = original_asn1_obj.decode().unwrap();

        // Encode to ASN1Object
        let encoded_asn1_obj: ASN1Object = cert.encode().unwrap();

        // Decode back from ASN1Object
        let decoded_cert: Certificate = encoded_asn1_obj.decode().unwrap();

        // Verify all fields match
        assert_eq!(decoded_cert.tbs_certificate, cert.tbs_certificate);
        assert_eq!(decoded_cert.signature_algorithm, cert.signature_algorithm);
        assert_eq!(decoded_cert.signature_value, cert.signature_value);

        // Verify ASN1Object structure
        assert_eq!(encoded_asn1_obj.elements().len(), 1);
        assert!(matches!(
            encoded_asn1_obj.elements()[0],
            Element::Sequence(_)
        ));
    }

    #[test]
    fn test_certificate_encode_to_asn1object_v1() {
        // Test with V1 certificate
        let pem = Pem::from_str(TEST_CERT_V1).unwrap();
        let der: Der = pem.decode().unwrap();
        let original_asn1_obj: ASN1Object = der.decode().unwrap();

        let cert: Certificate = original_asn1_obj.decode().unwrap();
        let encoded_asn1_obj: ASN1Object = cert.encode().unwrap();
        let decoded_cert: Certificate = encoded_asn1_obj.decode().unwrap();

        assert_eq!(decoded_cert.tbs_certificate.version, Version::V1);
        assert_eq!(decoded_cert.tbs_certificate, cert.tbs_certificate);
        assert_eq!(decoded_cert.signature_algorithm, cert.signature_algorithm);
        assert_eq!(decoded_cert.signature_value, cert.signature_value);
    }

    #[test]
    fn test_version_constructed_flag() {
        // Version is [0] EXPLICIT, so constructed should be true
        let version = Version::V3;
        let encoded = version.encode().unwrap();

        match encoded {
            Element::ContextSpecific {
                slot, constructed, ..
            } => {
                assert_eq!(slot, 0);
                assert!(
                    constructed,
                    "Version [0] EXPLICIT should have constructed=true"
                );
            }
            _ => panic!("Version should encode to ContextSpecific"),
        }
    }

    #[test]
    fn test_unique_identifier_constructed_flag() {
        // UniqueIdentifier is [1]/[2] IMPLICIT BitString, so constructed should be false
        let unique_id = UniqueIdentifier(BitString::new(0, vec![0x01, 0x02, 0x03]));

        // Create TBSCertificate with issuerUniqueID to test encoding
        let tbs = TBSCertificate {
            version: Version::V3,
            serial_number: CertificateSerialNumber::from_bytes(vec![0x01]),
            signature: AlgorithmIdentifier {
                algorithm: ObjectIdentifier::from_str("1.2.840.113549.1.1.11").unwrap(),
                parameters: None,
            },
            issuer: Name {
                rdn_sequence: vec![],
            },
            validity: Validity {
                not_before: NaiveDate::from_ymd_opt(1970, 1, 1)
                    .unwrap()
                    .and_hms_opt(0, 0, 0)
                    .unwrap(),
                not_after: NaiveDate::from_ymd_opt(1970, 1, 1)
                    .unwrap()
                    .and_hms_opt(0, 0, 1)
                    .unwrap(),
            },
            subject: Name {
                rdn_sequence: vec![],
            },
            subject_public_key_info: SubjectPublicKeyInfo::new(
                AlgorithmIdentifier::new(
                    ObjectIdentifier::from_str("1.2.840.113549.1.1.1").unwrap(),
                ),
                BitString::new(0, vec![0x00]),
            ),
            issuer_unique_id: Some(unique_id),
            subject_unique_id: None,
            extensions: None,
        };

        let encoded = tbs.encode().unwrap();

        if let Element::Sequence(elements) = encoded {
            // Find the issuerUniqueID element (slot 1)
            let issuer_uid = elements
                .iter()
                .find(|e| matches!(e, Element::ContextSpecific { slot: 1, .. }))
                .expect("issuerUniqueID should be present");

            if let Element::ContextSpecific {
                slot, constructed, ..
            } = issuer_uid
            {
                assert_eq!(*slot, 1);
                assert!(
                    !(*constructed),
                    "issuerUniqueID [1] IMPLICIT should have constructed=false"
                );
            }
        } else {
            panic!("TBSCertificate should encode to Sequence");
        }
    }
}
