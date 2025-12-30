use std::net::IpAddr;
use std::str::FromStr;

use asn1::{ASN1Object, Element, ObjectIdentifier, OctetString};
use serde::{Deserialize, Serialize};
use tsumiki::decoder::{DecodableFrom, Decoder};

use crate::error::Error;
use crate::{CertificateSerialNumber, DirectoryString, Name};

/*
RFC 5280 Section 4.1.2.9

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

/// Extensions is a sequence of Extension
/// RFC 5280: Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
///
/// Note: In TBSCertificate, this appears as:
/// - extensions [3] EXPLICIT Extensions OPTIONAL
/// - Element::ContextSpecific { slot: 3, element: Box<Element::Sequence> }
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Extensions {
    extensions: Vec<Extension>,
}

impl Extensions {
    pub fn extensions(&self) -> &Vec<Extension> {
        &self.extensions
    }
}

impl DecodableFrom<Element> for Extensions {}

impl Decoder<Element, Extensions> for Element {
    type Error = Error;

    fn decode(&self) -> Result<Extensions, Self::Error> {
        match self {
            Element::ContextSpecific { slot, element } => {
                if *slot != 3 {
                    return Err(Error::InvalidExtensions(format!(
                        "expected context-specific tag [3], got [{}]",
                        slot
                    )));
                }
                // EXPLICIT tagging: element contains the full SEQUENCE
                match element.as_ref() {
                    Element::Sequence(seq_elements) => {
                        if seq_elements.is_empty() {
                            return Err(Error::InvalidExtensions(
                                "Extensions must contain at least one Extension".to_string(),
                            ));
                        }
                        let mut extensions = Vec::new();
                        for elem in seq_elements {
                            let extension: Extension = elem.decode()?;
                            extensions.push(extension);
                        }
                        Ok(Extensions { extensions })
                    }
                    _ => Err(Error::InvalidExtensions(
                        "expected Sequence inside context-specific tag [3]".to_string(),
                    )),
                }
            }
            Element::Sequence(seq_elements) => {
                // Allow direct Sequence for testing
                if seq_elements.is_empty() {
                    return Err(Error::InvalidExtensions(
                        "Extensions must contain at least one Extension".to_string(),
                    ));
                }
                let mut extensions = Vec::new();
                for elem in seq_elements {
                    let extension: Extension = elem.decode()?;
                    extensions.push(extension);
                }
                Ok(Extensions { extensions })
            }
            _ => Err(Error::InvalidExtensions(
                "expected context-specific tag [3] or Sequence for Extensions".to_string(),
            )),
        }
    }
}

/// Extension represents a single X.509 extension
/// RFC 5280: Extension ::= SEQUENCE { extnID, critical, extnValue }
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Extension {
    id: ObjectIdentifier,
    critical: bool,
    value: OctetString,
}

impl Extension {
    /// Get the extension ID (OID)
    pub fn id(&self) -> &ObjectIdentifier {
        &self.id
    }

    /// Check if the extension is critical
    pub fn is_critical(&self) -> bool {
        self.critical
    }

    /// Get the raw extension value (DER-encoded ASN.1)
    pub fn value(&self) -> &OctetString {
        &self.value
    }

    /// Parse the extension value as a specific standard extension type
    pub fn parse<T: StandardExtension>(&self) -> Result<T, Error> {
        // Verify OID matches
        if self.id.to_string() != T::OID {
            return Err(Error::InvalidExtension(format!(
                "OID mismatch: expected {}, got {}",
                T::OID,
                self.id.to_string()
            )));
        }
        T::parse(&self.value)
    }
}

impl DecodableFrom<Element> for Extension {}

impl Decoder<Element, Extension> for Element {
    type Error = Error;

    fn decode(&self) -> Result<Extension, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                if elements.len() < 2 || elements.len() > 3 {
                    return Err(Error::InvalidExtension(format!(
                        "expected 2 or 3 elements in Extension sequence, got {}",
                        elements.len()
                    )));
                }

                // First element: extnID (OBJECT IDENTIFIER)
                let id = if let Element::ObjectIdentifier(oid) = &elements[0] {
                    oid.clone()
                } else {
                    return Err(Error::InvalidExtension(
                        "expected ObjectIdentifier for extnID".to_string(),
                    ));
                };

                // Second and third elements: critical (BOOLEAN) and extnValue (OCTET STRING)
                // critical has DEFAULT FALSE, so it may be omitted
                let (critical, extn_value_element) = if elements.len() == 3 {
                    // critical is present
                    let crit = if let Element::Boolean(b) = &elements[1] {
                        *b
                    } else {
                        return Err(Error::InvalidExtension(
                            "expected Boolean for critical".to_string(),
                        ));
                    };
                    (crit, &elements[2])
                } else {
                    // critical is omitted, defaults to FALSE
                    (false, &elements[1])
                };

                // extnValue (OCTET STRING)
                let value = if let Element::OctetString(octets) = extn_value_element {
                    octets.clone()
                } else {
                    return Err(Error::InvalidExtension(
                        "expected OctetString for extnValue".to_string(),
                    ));
                };

                Ok(Extension {
                    id,
                    critical,
                    value,
                })
            }
            _ => Err(Error::InvalidExtension(
                "expected Sequence for Extension".to_string(),
            )),
        }
    }
}

/// Trait for standard X.509 extensions that can be parsed from Extension.value
pub trait StandardExtension: Sized {
    const OID: &'static str;

    fn oid() -> Result<ObjectIdentifier, Error> {
        ObjectIdentifier::from_str(Self::OID).map_err(|e| {
            Error::InvalidExtension(format!("failed to parse OID {}: {}", Self::OID, e))
        })
    }
    /// Parse the extension value (DER-encoded ASN.1 in OctetString)
    fn parse(value: &OctetString) -> Result<Self, Error>;
}

/*
RFC 5280 Section 4.2.1.9
BasicConstraints ::= SEQUENCE {
    cA                      BOOLEAN DEFAULT FALSE,
    pathLenConstraint       INTEGER (0..MAX) OPTIONAL
}
*/
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasicConstraints {
    pub ca: bool,
    pub path_len_constraint: Option<u32>,
}

impl BasicConstraints {
    /// OID for BasicConstraints extension (2.5.29.19)
    pub const OID: &'static str = "2.5.29.19";
}

impl StandardExtension for BasicConstraints {
    const OID: &'static str = Self::OID;

    fn parse(value: &OctetString) -> Result<Self, Error> {
        // OctetString -> ASN1Object -> Element (Sequence) -> BasicConstraints
        let asn1_obj = ASN1Object::try_from(value).map_err(Error::InvalidASN1)?;
        let elements = asn1_obj.elements();

        if elements.is_empty() {
            return Err(Error::InvalidBasicConstraints("empty sequence".to_string()));
        }

        // The first element should be a Sequence
        if let Element::Sequence(_) = &elements[0] {
            // Decode the Sequence into BasicConstraints
            elements[0].decode()
        } else {
            return Err(Error::InvalidBasicConstraints(
                "expected Sequence".to_string(),
            ));
        }
    }
}

impl DecodableFrom<Element> for BasicConstraints {}

impl Decoder<Element, BasicConstraints> for Element {
    type Error = Error;

    fn decode(&self) -> Result<BasicConstraints, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                let mut ca = false;
                let mut path_len_constraint = None;

                for elem in elements {
                    match elem {
                        Element::Boolean(b) => {
                            ca = *b;
                        }
                        Element::Integer(i) => {
                            // Convert Integer to u32
                            let value: u64 = i.try_into().map_err(|_| {
                                Error::InvalidBasicConstraints(
                                    "pathLenConstraint: value out of range".to_string(),
                                )
                            })?;
                            if value > u32::MAX as u64 {
                                return Err(Error::InvalidBasicConstraints(
                                    "pathLenConstraint: value too large for u32".to_string(),
                                ));
                            }
                            path_len_constraint = Some(value as u32);
                        }
                        _ => {
                            return Err(Error::InvalidBasicConstraints(format!(
                                "unexpected element: {:?}",
                                elem
                            )));
                        }
                    }
                }

                Ok(BasicConstraints {
                    ca,
                    path_len_constraint,
                })
            }
            _ => Err(Error::InvalidBasicConstraints(
                "expected Sequence".to_string(),
            )),
        }
    }
}

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyUsage {
    pub digital_signature: bool,
    pub content_commitment: bool,
    pub key_encipherment: bool,
    pub data_encipherment: bool,
    pub key_agreement: bool,
    pub key_cert_sign: bool,
    pub crl_sign: bool,
    pub encipher_only: bool,
    pub decipher_only: bool,
}

impl StandardExtension for KeyUsage {
    const OID: &'static str = "2.5.29.15";

    fn parse(value: &OctetString) -> Result<Self, Error> {
        // OctetString -> ASN1Object -> Element (BitString) -> KeyUsage
        let asn1_obj = ASN1Object::try_from(value).map_err(Error::InvalidASN1)?;
        let elements = asn1_obj.elements();

        if elements.is_empty() {
            return Err(Error::InvalidKeyUsage("empty sequence".to_string()));
        }

        // The first element should be a BitString
        let element = &elements[0];
        element.decode()
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
            _ => Err(Error::InvalidKeyUsage("expected BitString".to_string())),
        }
    }
}

/*
RFC 5280 Section 4.2.1.1
AuthorityKeyIdentifier ::= SEQUENCE {
    keyIdentifier             [0] KeyIdentifier           OPTIONAL,
    authorityCertIssuer       [1] GeneralNames            OPTIONAL,
    authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL
}

KeyIdentifier ::= OCTET STRING
CertificateSerialNumber ::= INTEGER
*/

/// KeyIdentifier is an OCTET STRING used to identify a public key
/// Typically a SHA-1 hash of the SubjectPublicKeyInfo (20 bytes)
pub type KeyIdentifier = Vec<u8>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityKeyIdentifier {
    /// KeyIdentifier: typically a SHA-1 hash of the CA's public key
    pub key_identifier: Option<KeyIdentifier>,
    /// GeneralNames: issuer name(s) of the CA certificate
    /// Note: Currently simplified - full GeneralNames parsing pending
    pub authority_cert_issuer: Option<Vec<GeneralName>>,
    /// CertificateSerialNumber: serial number of the CA certificate
    pub authority_cert_serial_number: Option<CertificateSerialNumber>,
}

impl AuthorityKeyIdentifier {
    /// OID for AuthorityKeyIdentifier extension (2.5.29.35)
    pub const OID: &'static str = "2.5.29.35";
}

impl StandardExtension for AuthorityKeyIdentifier {
    const OID: &'static str = Self::OID;

    fn parse(value: &OctetString) -> Result<Self, Error> {
        // OctetString -> ASN1Object -> Element (Sequence) -> AuthorityKeyIdentifier
        let asn1_obj = ASN1Object::try_from(value).map_err(Error::InvalidASN1)?;
        let elements = asn1_obj.elements();

        if elements.is_empty() {
            return Err(Error::InvalidAuthorityKeyIdentifier(
                "empty sequence".to_string(),
            ));
        }

        // The first element should be a Sequence
        (&elements[0]).decode()
    }
}

impl DecodableFrom<Element> for AuthorityKeyIdentifier {}

impl Decoder<Element, AuthorityKeyIdentifier> for Element {
    type Error = Error;

    fn decode(&self) -> Result<AuthorityKeyIdentifier, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                let mut key_identifier = None;
                let mut authority_cert_issuer = None;
                let mut authority_cert_serial_number = None;

                for elem in elements {
                    match elem {
                        // [0] IMPLICIT KeyIdentifier (OCTET STRING)
                        Element::ContextSpecific { slot: 0, element } => {
                            if let Element::OctetString(os) = element.as_ref() {
                                key_identifier = Some(os.as_bytes().to_vec());
                            } else {
                                return Err(Error::InvalidAuthorityKeyIdentifier(
                                    "keyIdentifier must be OctetString".to_string(),
                                ));
                            }
                        }
                        // [1] IMPLICIT GeneralNames (SEQUENCE OF GeneralName)
                        Element::ContextSpecific { slot: 1, element } => {
                            // GeneralNames is a SEQUENCE OF GeneralName
                            match element.as_ref() {
                                Element::Sequence(names) => {
                                    let mut parsed_names = Vec::new();
                                    for name_elem in names {
                                        // Each GeneralName is a context-specific tagged element
                                        let general_name: GeneralName = name_elem.decode()?;
                                        parsed_names.push(general_name);
                                    }
                                    authority_cert_issuer = Some(parsed_names);
                                }
                                _ => {
                                    return Err(Error::InvalidAuthorityKeyIdentifier(
                                        "authorityCertIssuer must be Sequence (GeneralNames)"
                                            .to_string(),
                                    ));
                                }
                            }
                        }
                        // [2] IMPLICIT CertificateSerialNumber (INTEGER)
                        Element::ContextSpecific { slot: 2, element } => {
                            // IMPLICIT tagging: OctetString wrapper around raw INTEGER bytes
                            if let Element::OctetString(os) = element.as_ref() {
                                authority_cert_serial_number = Some(
                                    CertificateSerialNumber::from_bytes(os.as_bytes().to_vec()),
                                );
                            } else if let Element::Integer(i) = element.as_ref() {
                                // EXPLICIT tagging (less common but valid)
                                authority_cert_serial_number =
                                    Some(CertificateSerialNumber::from(i.clone()));
                            } else {
                                return Err(Error::InvalidAuthorityKeyIdentifier(
                                    "serialNumber must be OctetString (IMPLICIT) or Integer (EXPLICIT)".to_string(),
                                ));
                            }
                        }
                        _ => {
                            return Err(Error::InvalidAuthorityKeyIdentifier(format!(
                                "unexpected element: {:?}",
                                elem
                            )));
                        }
                    }
                }

                Ok(AuthorityKeyIdentifier {
                    key_identifier,
                    authority_cert_issuer,
                    authority_cert_serial_number,
                })
            }
            _ => Err(Error::InvalidAuthorityKeyIdentifier(
                "expected Sequence".to_string(),
            )),
        }
    }
}

/*
RFC 5280 Section 4.2.1.2
SubjectKeyIdentifier ::= KeyIdentifier
KeyIdentifier ::= OCTET STRING

The SubjectKeyIdentifier extension provides a means of identifying certificates
that contain a particular public key. Typically, this is a SHA-1 hash of the
subjectPublicKey (excluding the tag, length, and number of unused bits).
*/
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectKeyIdentifier {
    /// KeyIdentifier: typically a SHA-1 hash of the subject's public key (20 bytes)
    pub key_identifier: KeyIdentifier,
}

impl SubjectKeyIdentifier {
    /// OID for SubjectKeyIdentifier extension (2.5.29.14)
    pub const OID: &'static str = "2.5.29.14";
}

impl DecodableFrom<OctetString> for SubjectKeyIdentifier {}

impl Decoder<OctetString, SubjectKeyIdentifier> for OctetString {
    type Error = Error;

    fn decode(&self) -> Result<SubjectKeyIdentifier, Self::Error> {
        // SubjectKeyIdentifier is an OCTET STRING containing another OCTET STRING
        // The outer OCTET STRING is the extension value wrapper (handled by Extension)
        // Parse the inner DER structure
        let asn1_obj = ASN1Object::try_from(self).map_err(Error::InvalidASN1)?;
        let elements = asn1_obj.elements();

        if elements.is_empty() {
            return Err(Error::InvalidSubjectKeyIdentifier(
                "empty content".to_string(),
            ));
        }

        // The first element should be an OctetString
        elements[0].decode()
    }
}

impl DecodableFrom<Element> for SubjectKeyIdentifier {}

impl Decoder<Element, SubjectKeyIdentifier> for Element {
    type Error = Error;

    fn decode(&self) -> Result<SubjectKeyIdentifier, Self::Error> {
        match self {
            Element::OctetString(os) => Ok(SubjectKeyIdentifier {
                key_identifier: os.as_bytes().to_vec(),
            }),
            _ => Err(Error::InvalidSubjectKeyIdentifier(
                "expected OctetString".to_string(),
            )),
        }
    }
}

impl StandardExtension for SubjectKeyIdentifier {
    const OID: &'static str = Self::OID;

    fn parse(value: &OctetString) -> Result<Self, Error> {
        value.decode()
    }
}

/*
RFC 5280 Section 4.2.1.6
SubjectAltName ::= GeneralNames
GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
*/
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectAltName {
    pub names: Vec<GeneralName>,
}

impl SubjectAltName {
    /// OID for SubjectAltName extension (2.5.29.17)
    pub const OID: &'static str = "2.5.29.17";
}

/*
RFC 5280 Section 4.2.1.6
GeneralName ::= CHOICE {
    otherName                 [0] OtherName,
    rfc822Name                [1] IA5String,
    dNSName                   [2] IA5String,
    x400Address               [3] ORAddress,
    directoryName             [4] Name,
    ediPartyName              [5] EDIPartyName,
    uniformResourceIdentifier [6] IA5String,
    iPAddress                 [7] OCTET STRING,
    registeredID              [8] OBJECT IDENTIFIER
}

OtherName ::= SEQUENCE {
    type-id    OBJECT IDENTIFIER,
    value      [0] EXPLICIT ANY DEFINED BY type-id
}

EDIPartyName ::= SEQUENCE {
    nameAssigner [0] DirectoryString OPTIONAL,
    partyName    [1] DirectoryString
}
*/

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GeneralName {
    /// otherName [0] - structured OtherName
    OtherName(OtherName),
    /// rfc822Name [1] - Email address (IA5String)
    Rfc822Name(String),
    /// dNSName [2] - DNS hostname (IA5String)
    DnsName(String),
    /// x400Address [3] - X.400 address (ORAddress, rarely used)
    X400Address(Vec<u8>),
    /// directoryName [4] - X.500 Name
    DirectoryName(Name),
    /// ediPartyName [5] - EDI party name
    EdiPartyName(EdiPartyName),
    /// uniformResourceIdentifier [6] - URI (IA5String)
    Uri(String),
    /// iPAddress [7] - IP address (IPv4 or IPv6)
    IpAddress(IpAddr),
    /// registeredID [8] - Registered OBJECT IDENTIFIER
    RegisteredId(ObjectIdentifier),
}

impl GeneralName {
    /// Parse a GeneralName based on its context-specific tag slot
    fn parse_from_context_specific(slot: u8, element: &Box<Element>) -> Result<GeneralName, Error> {
        match slot {
            0 => {
                // otherName [0] IMPLICIT OtherName (SEQUENCE)
                match element.as_ref() {
                    Element::Sequence(seq) => {
                        if seq.len() < 2 {
                            return Err(Error::InvalidGeneralName(
                                "otherName requires at least 2 elements".to_string(),
                            ));
                        }
                        // First: type-id (OBJECT IDENTIFIER)
                        let type_id = match &seq[0] {
                            Element::ObjectIdentifier(oid) => oid.clone(),
                            _ => {
                                return Err(Error::InvalidGeneralName(
                                    "otherName type-id must be ObjectIdentifier".to_string(),
                                ));
                            }
                        };
                        // Second: [0] EXPLICIT value
                        let value = match &seq[1] {
                            Element::ContextSpecific {
                                slot: 0,
                                element: val,
                            } => {
                                // EXPLICIT tag: The value is encoded within the context-specific tag
                                // TODO: Properly encode the Element back to DER bytes
                                // For now, we use a simplified representation
                                // In a complete implementation, we would re-encode the Element to DER
                                match val.as_ref() {
                                    Element::OctetString(os) => os.as_bytes().to_vec(),
                                    Element::UTF8String(s)
                                    | Element::IA5String(s)
                                    | Element::PrintableString(s) => s.as_bytes().to_vec(),
                                    // For other types, use Debug representation as placeholder
                                    _ => format!("{:?}", val).into_bytes(),
                                }
                            }
                            _ => {
                                return Err(Error::InvalidGeneralName(
                                    "otherName value must be [0] EXPLICIT".to_string(),
                                ));
                            }
                        };
                        Ok(GeneralName::OtherName(OtherName { type_id, value }))
                    }
                    _ => Err(Error::InvalidGeneralName(
                        "otherName must be Sequence".to_string(),
                    )),
                }
            }
            1 => {
                // rfc822Name [1] IMPLICIT IA5String
                Self::parse_ia5_string(element).map(GeneralName::Rfc822Name)
            }
            2 => {
                // dNSName [2] IMPLICIT IA5String
                Self::parse_ia5_string(element).map(GeneralName::DnsName)
            }
            3 => {
                // x400Address [3] IMPLICIT ORAddress
                // ORAddress is complex and rarely used, store as raw bytes
                match element.as_ref() {
                    Element::OctetString(os) => {
                        Ok(GeneralName::X400Address(os.as_bytes().to_vec()))
                    }
                    Element::Sequence(_) => {
                        // May come as Sequence if parsed recursively
                        Ok(GeneralName::X400Address(
                            format!("{:?}", element).into_bytes(),
                        ))
                    }
                    _ => Err(Error::InvalidGeneralName(
                        "x400Address must be ORAddress".to_string(),
                    )),
                }
            }
            4 => {
                // directoryName [4] IMPLICIT Name (SEQUENCE)
                match element.as_ref() {
                    Element::Sequence(_) => {
                        // Decode as Name
                        let name: Name = element.as_ref().decode()?;
                        Ok(GeneralName::DirectoryName(name))
                    }
                    _ => Err(Error::InvalidGeneralName(
                        "directoryName must be Sequence (Name)".to_string(),
                    )),
                }
            }
            5 => {
                // ediPartyName [5] IMPLICIT EDIPartyName (SEQUENCE)
                match element.as_ref() {
                    Element::Sequence(seq) => {
                        let mut name_assigner = None;
                        let mut party_name = None;

                        for elem in seq {
                            match elem {
                                Element::ContextSpecific { slot: 0, element } => {
                                    // nameAssigner [0]
                                    let dir_string: DirectoryString =
                                        element.as_ref().decode().map_err(|_| {
                                            Error::InvalidGeneralName(
                                                "invalid nameAssigner".to_string(),
                                            )
                                        })?;
                                    name_assigner = Some(dir_string.into_string());
                                }
                                Element::ContextSpecific { slot: 1, element } => {
                                    // partyName [1]
                                    let dir_string: DirectoryString =
                                        element.as_ref().decode().map_err(|_| {
                                            Error::InvalidGeneralName(
                                                "invalid partyName".to_string(),
                                            )
                                        })?;
                                    party_name = Some(dir_string.into_string());
                                }
                                _ => {
                                    return Err(Error::InvalidGeneralName(
                                        "ediPartyName has invalid element".to_string(),
                                    ));
                                }
                            }
                        }

                        let party_name = party_name.ok_or_else(|| {
                            Error::InvalidGeneralName(
                                "ediPartyName requires partyName [1]".to_string(),
                            )
                        })?;
                        Ok(GeneralName::EdiPartyName(EdiPartyName {
                            name_assigner,
                            party_name,
                        }))
                    }
                    _ => Err(Error::InvalidGeneralName(
                        "ediPartyName must be Sequence".to_string(),
                    )),
                }
            }
            6 => {
                // uniformResourceIdentifier [6] IMPLICIT IA5String
                Self::parse_ia5_string(element).map(GeneralName::Uri)
            }
            7 => {
                // iPAddress [7] IMPLICIT OCTET STRING
                match element.as_ref() {
                    Element::OctetString(os) => {
                        let bytes = os.as_bytes();
                        let ip_addr = match bytes.len() {
                            4 => {
                                // IPv4: 4 bytes
                                let octets: [u8; 4] = bytes.try_into().unwrap();
                                IpAddr::from(octets)
                            }
                            16 => {
                                // IPv6: 16 bytes
                                let octets: [u8; 16] = bytes.try_into().unwrap();
                                IpAddr::from(octets)
                            }
                            _ => {
                                return Err(Error::InvalidGeneralName(format!(
                                    "iPAddress must be 4 or 16 bytes, got {}",
                                    bytes.len()
                                )));
                            }
                        };
                        Ok(GeneralName::IpAddress(ip_addr))
                    }
                    _ => Err(Error::InvalidGeneralName(
                        "iPAddress must be OctetString".to_string(),
                    )),
                }
            }
            8 => {
                // registeredID [8] IMPLICIT OBJECT IDENTIFIER
                match element.as_ref() {
                    Element::OctetString(os) => {
                        // IMPLICIT OID comes as OctetString, need to parse
                        let oid = ObjectIdentifier::try_from(os.as_bytes())
                            .map_err(|_| Error::InvalidGeneralName("invalid OID".to_string()))?;
                        Ok(GeneralName::RegisteredId(oid))
                    }
                    Element::ObjectIdentifier(oid) => {
                        // EXPLICIT OID (less common)
                        Ok(GeneralName::RegisteredId(oid.clone()))
                    }
                    _ => Err(Error::InvalidGeneralName(
                        "registeredID must be ObjectIdentifier".to_string(),
                    )),
                }
            }
            _ => Err(Error::InvalidGeneralName(format!(
                "unknown GeneralName tag [{}]",
                slot
            ))),
        }
    }

    /// Parse IA5String from IMPLICIT context-specific element
    fn parse_ia5_string(element: &Box<Element>) -> Result<String, Error> {
        match element.as_ref() {
            Element::OctetString(os) => {
                // IMPLICIT IA5String comes as OctetString
                String::from_utf8(os.as_bytes().to_vec()).map_err(|_| {
                    Error::InvalidGeneralName("IA5String must be valid ASCII".to_string())
                })
            }
            Element::IA5String(s) => Ok(s.clone()),
            _ => Err(Error::InvalidGeneralName("expected IA5String".to_string())),
        }
    }
}

impl DecodableFrom<Element> for GeneralName {}

impl Decoder<Element, GeneralName> for Element {
    type Error = Error;

    fn decode(&self) -> Result<GeneralName, Self::Error> {
        match self {
            Element::ContextSpecific { slot, element } => {
                GeneralName::parse_from_context_specific(*slot, element)
            }
            _ => Err(Error::InvalidGeneralName(
                "GeneralName must be context-specific element".to_string(),
            )),
        }
    }
}

/// OtherName structure for [0] IMPLICIT OtherName
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtherName {
    /// type-id: OBJECT IDENTIFIER identifying the type
    pub type_id: ObjectIdentifier,
    /// value: [0] EXPLICIT - The actual value as raw DER-encoded bytes
    /// Type interpretation depends on type-id
    /// Note: This is the DER-encoded content of the EXPLICIT [0] tag
    pub value: Vec<u8>,
}

/// EDIPartyName structure for [5] IMPLICIT EDIPartyName
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdiPartyName {
    /// nameAssigner [0] OPTIONAL
    pub name_assigner: Option<String>,
    /// partyName [1]
    pub party_name: String,
}

impl DecodableFrom<OctetString> for SubjectAltName {}

impl Decoder<OctetString, SubjectAltName> for OctetString {
    type Error = Error;

    fn decode(&self) -> Result<SubjectAltName, Self::Error> {
        // SubjectAltName -> ASN1Object -> Element (Sequence) -> SubjectAltName
        let asn1_obj = ASN1Object::try_from(self).map_err(Error::InvalidASN1)?;
        let elements = asn1_obj.elements();

        if elements.is_empty() {
            return Err(Error::InvalidSubjectAltName("empty sequence".to_string()));
        }

        // The first element should be a Sequence (GeneralNames)
        elements[0].decode()
    }
}

impl DecodableFrom<Element> for SubjectAltName {}

impl Decoder<Element, SubjectAltName> for Element {
    type Error = Error;

    fn decode(&self) -> Result<SubjectAltName, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                if elements.is_empty() {
                    return Err(Error::InvalidSubjectAltName(
                        "empty sequence - at least one GeneralName required".to_string(),
                    ));
                }

                let mut names = Vec::new();
                for elem in elements {
                    // Each element should be a context-specific tagged GeneralName
                    let general_name: GeneralName = elem.decode()?;
                    names.push(general_name);
                }

                Ok(SubjectAltName { names })
            }
            _ => Err(Error::InvalidSubjectAltName(
                "expected Sequence".to_string(),
            )),
        }
    }
}

impl StandardExtension for SubjectAltName {
    const OID: &'static str = Self::OID;

    fn parse(value: &OctetString) -> Result<Self, Error> {
        value.decode()
    }
}

/*
RFC 5280 Section 4.2.1.12
ExtendedKeyUsage ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
KeyPurposeId ::= OBJECT IDENTIFIER
*/
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtendedKeyUsage {
    pub purposes: Vec<ObjectIdentifier>,
}

impl ExtendedKeyUsage {
    /// OID for ExtendedKeyUsage extension (2.5.29.37)
    pub const OID: &'static str = "2.5.29.37";

    // Common KeyPurposeId OIDs (RFC 5280)
    /// TLS WWW server authentication (1.3.6.1.5.5.7.3.1)
    pub const SERVER_AUTH: &'static str = "1.3.6.1.5.5.7.3.1";
    /// TLS WWW client authentication (1.3.6.1.5.5.7.3.2)
    pub const CLIENT_AUTH: &'static str = "1.3.6.1.5.5.7.3.2";
    /// Code signing (1.3.6.1.5.5.7.3.3)
    pub const CODE_SIGNING: &'static str = "1.3.6.1.5.5.7.3.3";
    /// Email protection (1.3.6.1.5.5.7.3.4)
    pub const EMAIL_PROTECTION: &'static str = "1.3.6.1.5.5.7.3.4";
    /// Time stamping (1.3.6.1.5.5.7.3.8)
    pub const TIME_STAMPING: &'static str = "1.3.6.1.5.5.7.3.8";
    /// OCSP signing (1.3.6.1.5.5.7.3.9)
    pub const OCSP_SIGNING: &'static str = "1.3.6.1.5.5.7.3.9";
}

impl DecodableFrom<OctetString> for ExtendedKeyUsage {}

impl Decoder<OctetString, ExtendedKeyUsage> for OctetString {
    type Error = Error;

    fn decode(&self) -> Result<ExtendedKeyUsage, Self::Error> {
        let asn1_obj = ASN1Object::try_from(self).map_err(Error::InvalidASN1)?;
        let elements = asn1_obj.elements();

        if elements.is_empty() {
            return Err(Error::InvalidExtendedKeyUsage("empty sequence".to_string()));
        }

        // The first element should be a Sequence
        elements[0].decode()
    }
}

impl DecodableFrom<Element> for ExtendedKeyUsage {}

impl Decoder<Element, ExtendedKeyUsage> for Element {
    type Error = Error;

    fn decode(&self) -> Result<ExtendedKeyUsage, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                if elements.is_empty() {
                    return Err(Error::InvalidExtendedKeyUsage(
                        "empty sequence - at least one KeyPurposeId required".to_string(),
                    ));
                }

                let mut purposes = Vec::new();
                for elem in elements {
                    match elem {
                        Element::ObjectIdentifier(oid) => {
                            purposes.push(oid.clone());
                        }
                        _ => {
                            return Err(Error::InvalidExtendedKeyUsage(format!(
                                "expected ObjectIdentifier, got {:?}",
                                elem
                            )));
                        }
                    }
                }

                Ok(ExtendedKeyUsage { purposes })
            }
            _ => Err(Error::InvalidExtendedKeyUsage(
                "expected Sequence".to_string(),
            )),
        }
    }
}

impl StandardExtension for ExtendedKeyUsage {
    const OID: &'static str = Self::OID;

    fn parse(value: &OctetString) -> Result<Self, Error> {
        value.decode()
    }
}

/*
RFC 5280 Section 4.2.2.1

id-pe-authorityInfoAccess OBJECT IDENTIFIER ::= { id-pe 1 }
AuthorityInfoAccessSyntax  ::= SEQUENCE SIZE (1..MAX) OF AccessDescription

AccessDescription  ::=  SEQUENCE {
    accessMethod          OBJECT IDENTIFIER,
    accessLocation        GeneralName
}

id-ad OBJECT IDENTIFIER ::= { id-pkix 48 }
id-ad-caIssuers OBJECT IDENTIFIER ::= { id-ad 2 }
id-ad-ocsp OBJECT IDENTIFIER ::= { id-ad 1 }
*/

/// AccessDescription represents a single access method and location
/// RFC 5280: AccessDescription ::= SEQUENCE { accessMethod, accessLocation }
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessDescription {
    pub access_method: ObjectIdentifier,
    pub access_location: GeneralName,
}

impl DecodableFrom<Element> for AccessDescription {}

impl Decoder<Element, AccessDescription> for Element {
    type Error = Error;

    fn decode(&self) -> Result<AccessDescription, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                if elements.len() != 2 {
                    return Err(Error::InvalidAuthorityInfoAccess(format!(
                        "AccessDescription must have exactly 2 elements, got {}",
                        elements.len()
                    )));
                }

                let access_method = match &elements[0] {
                    Element::ObjectIdentifier(oid) => oid.clone(),
                    _ => {
                        return Err(Error::InvalidAuthorityInfoAccess(
                            "accessMethod must be ObjectIdentifier".to_string(),
                        ));
                    }
                };

                let access_location: GeneralName = elements[1].decode()?;

                Ok(AccessDescription {
                    access_method,
                    access_location,
                })
            }
            _ => Err(Error::InvalidAuthorityInfoAccess(
                "AccessDescription must be a Sequence".to_string(),
            )),
        }
    }
}

/// AuthorityInfoAccess extension (RFC 5280 Section 4.2.2.1)
/// Contains information about OCSP responders and CA certificate issuers
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityInfoAccess {
    pub descriptors: Vec<AccessDescription>,
}

impl AuthorityInfoAccess {
    /// OID for AuthorityInfoAccess extension (1.3.6.1.5.5.7.1.1)
    pub const OID: &'static str = "1.3.6.1.5.5.7.1.1";

    // Access method OIDs
    /// OCSP responder access method (1.3.6.1.5.5.7.48.1)
    pub const OCSP: &'static str = "1.3.6.1.5.5.7.48.1";
    /// CA Issuers access method (1.3.6.1.5.5.7.48.2)
    pub const CA_ISSUERS: &'static str = "1.3.6.1.5.5.7.48.2";
}

impl DecodableFrom<OctetString> for AuthorityInfoAccess {}

impl Decoder<OctetString, AuthorityInfoAccess> for OctetString {
    type Error = Error;

    fn decode(&self) -> Result<AuthorityInfoAccess, Self::Error> {
        let asn1_obj = ASN1Object::try_from(self).map_err(Error::InvalidASN1)?;
        let elements = asn1_obj.elements();

        if elements.is_empty() {
            return Err(Error::InvalidAuthorityInfoAccess(
                "empty sequence".to_string(),
            ));
        }

        // The first element should be a Sequence
        elements[0].decode()
    }
}

impl DecodableFrom<Element> for AuthorityInfoAccess {}

impl Decoder<Element, AuthorityInfoAccess> for Element {
    type Error = Error;

    fn decode(&self) -> Result<AuthorityInfoAccess, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                if elements.is_empty() {
                    return Err(Error::InvalidAuthorityInfoAccess(
                        "at least one AccessDescription required".to_string(),
                    ));
                }

                let mut descriptors = Vec::new();
                for elem in elements {
                    let desc: AccessDescription = elem.decode()?;
                    descriptors.push(desc);
                }

                Ok(AuthorityInfoAccess { descriptors })
            }
            _ => Err(Error::InvalidAuthorityInfoAccess(
                "expected Sequence".to_string(),
            )),
        }
    }
}

impl StandardExtension for AuthorityInfoAccess {
    const OID: &'static str = Self::OID;

    fn parse(value: &OctetString) -> Result<Self, Error> {
        value.decode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::str::FromStr;

    // Extensions tests
    #[rstest(
        input,
        // Test case: Extensions with context-specific [3] tag
        case(
            Element::ContextSpecific {
                slot: 3,
                element: Box::new(Element::Sequence(vec![
                    Element::Sequence(vec![
                        Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.19").unwrap()),
                        Element::Boolean(true),
                        Element::OctetString(OctetString::from(vec![0x30, 0x00])),
                    ]),
                ])),
            }
        ),
        // Test case: Extensions with direct Sequence (for testing)
        case(
            Element::Sequence(vec![
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.19").unwrap()),
                    Element::OctetString(OctetString::from(vec![0x30, 0x00])),
                ]),
            ])
        ),
        // Test case: Extensions with multiple extensions
        case(
            Element::Sequence(vec![
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.19").unwrap()),
                    Element::Boolean(true),
                    Element::OctetString(OctetString::from(vec![0x30, 0x00])),
                ]),
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.15").unwrap()),
                    Element::OctetString(OctetString::from(vec![0x03, 0x02, 0x05, 0xA0])),
                ]),
            ])
        ),
    )]
    fn test_extensions_decode_success(input: Element) {
        let result: Result<Extensions, Error> = input.decode();
        assert!(result.is_ok());
        let extensions = result.unwrap();
        assert!(!extensions.extensions.is_empty());
    }

    #[rstest(
        input,
        expected_error_msg,
        // Test case: Empty Extensions
        case(
            Element::Sequence(vec![]),
            "Extensions must contain at least one Extension"
        ),
        // Test case: Wrong context-specific tag
        case(
            Element::ContextSpecific {
                slot: 2,
                element: Box::new(Element::Sequence(vec![
                    Element::Sequence(vec![
                        Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.19").unwrap()),
                        Element::OctetString(OctetString::from(vec![0x30, 0x00])),
                    ]),
                ])),
            },
            "expected context-specific tag [3], got [2]"
        ),
        // Test case: Context-specific tag without Sequence
        case(
            Element::ContextSpecific {
                slot: 3,
                element: Box::new(Element::Integer(asn1::Integer::from(vec![0x01]))),
            },
            "expected Sequence inside context-specific tag [3]"
        ),
        // Test case: Not a Sequence or ContextSpecific
        case(
            Element::Integer(asn1::Integer::from(vec![0x01])),
            "expected context-specific tag [3] or Sequence for Extensions"
        ),
    )]
    fn test_extensions_decode_failure(input: Element, expected_error_msg: &str) {
        let result: Result<Extensions, Error> = input.decode();
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

    // Extension tests
    #[rstest(
        input,
        expected,
        // Test case: Extension with critical=false (default, omitted)
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.19").unwrap()), // basicConstraints
                Element::OctetString(OctetString::from(vec![0x30, 0x00])), // SEQUENCE {}
            ]),
            Extension {
                id: ObjectIdentifier::from_str("2.5.29.19").unwrap(),
                critical: false,
                value: OctetString::from(vec![0x30, 0x00]),
            }
        ),
        // Test case: Extension with critical=true
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.19").unwrap()),
                Element::Boolean(true),
                Element::OctetString(OctetString::from(vec![0x30, 0x03, 0x01, 0x01, 0xFF])),
            ]),
            Extension {
                id: ObjectIdentifier::from_str("2.5.29.19").unwrap(),
                critical: true,
                value: OctetString::from(vec![0x30, 0x03, 0x01, 0x01, 0xFF]),
            }
        ),
        // Test case: Extension with critical=false (explicit)
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.15").unwrap()), // keyUsage
                Element::Boolean(false),
                Element::OctetString(OctetString::from(vec![0x03, 0x02, 0x05, 0xA0])),
            ]),
            Extension {
                id: ObjectIdentifier::from_str("2.5.29.15").unwrap(),
                critical: false,
                value: OctetString::from(vec![0x03, 0x02, 0x05, 0xA0]),
            }
        ),
    )]
    fn test_extension_decode_success(input: Element, expected: Extension) {
        let result: Result<Extension, Error> = input.decode();
        assert!(result.is_ok());
        let extension = result.unwrap();
        assert_eq!(extension, expected);
    }

    #[rstest(
        input,
        expected_error_msg,
        // Test case: Not a Sequence
        case(
            Element::Integer(asn1::Integer::from(vec![0x01])),
            "expected Sequence for Extension"
        ),
        // Test case: Empty sequence
        case(
            Element::Sequence(vec![]),
            "expected 2 or 3 elements in Extension sequence, got 0"
        ),
        // Test case: Only one element
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.19").unwrap()),
            ]),
            "expected 2 or 3 elements in Extension sequence, got 1"
        ),
        // Test case: Too many elements
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.19").unwrap()),
                Element::Boolean(true),
                Element::OctetString(OctetString::from(vec![0x30, 0x00])),
                Element::Null,
            ]),
            "expected 2 or 3 elements in Extension sequence, got 4"
        ),
        // Test case: First element is not OID
        case(
            Element::Sequence(vec![
                Element::Integer(asn1::Integer::from(vec![0x01])),
                Element::OctetString(OctetString::from(vec![0x30, 0x00])),
            ]),
            "expected ObjectIdentifier for extnID"
        ),
        // Test case: Second element (critical) is not Boolean when 3 elements
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.19").unwrap()),
                Element::Integer(asn1::Integer::from(vec![0x01])),
                Element::OctetString(OctetString::from(vec![0x30, 0x00])),
            ]),
            "expected Boolean for critical"
        ),
        // Test case: extnValue is not OctetString
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.19").unwrap()),
                Element::Integer(asn1::Integer::from(vec![0x01])),
            ]),
            "expected OctetString for extnValue"
        ),
    )]
    fn test_extension_decode_failure(input: Element, expected_error_msg: &str) {
        let result: Result<Extension, Error> = input.decode();
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

    // BasicConstraints tests
    #[rstest(
        input,
        expected,
        // Test case: CA=true, no pathLenConstraint
        case(
            Element::Sequence(vec![Element::Boolean(true)]),
            BasicConstraints {
                ca: true,
                path_len_constraint: None,
            }
        ),
        // Test case: CA=false (default), no pathLenConstraint
        case(
            Element::Sequence(vec![]),
            BasicConstraints {
                ca: false,
                path_len_constraint: None,
            }
        ),
        // Test case: CA=true with pathLenConstraint=0
        case(
            Element::Sequence(vec![
                Element::Boolean(true),
                Element::Integer(asn1::Integer::from(vec![0x00])),
            ]),
            BasicConstraints {
                ca: true,
                path_len_constraint: Some(0),
            }
        ),
        // Test case: CA=true with pathLenConstraint=1
        case(
            Element::Sequence(vec![
                Element::Boolean(true),
                Element::Integer(asn1::Integer::from(vec![0x01])),
            ]),
            BasicConstraints {
                ca: true,
                path_len_constraint: Some(1),
            }
        ),
        // Test case: CA=false with pathLenConstraint (unusual but valid)
        case(
            Element::Sequence(vec![
                Element::Boolean(false),
                Element::Integer(asn1::Integer::from(vec![0x0a])),
            ]),
            BasicConstraints {
                ca: false,
                path_len_constraint: Some(10),
            }
        ),
    )]
    fn test_basic_constraints_decode_success(input: Element, expected: BasicConstraints) {
        let result: Result<BasicConstraints, Error> = input.decode();
        assert!(result.is_ok(), "Failed to decode: {:?}", result);
        let actual = result.unwrap();
        assert_eq!(expected, actual);
    }

    #[rstest(
        input,
        expected_error_msg,
        // Test case: Not a Sequence
        case(
            Element::Boolean(true),
            "expected Sequence"
        ),
        // Test case: Invalid element type in Sequence
        case(
            Element::Sequence(vec![Element::OctetString(OctetString::from(vec![0x01]))]),
            "unexpected element"
        ),
    )]
    fn test_basic_constraints_decode_failure(input: Element, expected_error_msg: &str) {
        let result: Result<BasicConstraints, Error> = input.decode();
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

    // KeyUsage tests
    #[rstest(
        input,
        expected,
        // Test case: digitalSignature only (bit 0)
        // BitString: 0x80 (10000000 in binary, bit 0 set)
        case(
            Element::BitString(asn1::BitString::try_from(vec![0x07, 0x80]).unwrap()),
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
            Element::BitString(asn1::BitString::try_from(vec![0x01, 0x06]).unwrap()),
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
            Element::BitString(asn1::BitString::try_from(vec![0x04, 0xB0]).unwrap()),
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
            Element::BitString(asn1::BitString::try_from(vec![0x07, 0xFF, 0x80]).unwrap()),
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
            "expected BitString"
        ),
        // Test case: Sequence instead of BitString
        case(
            Element::Sequence(vec![]),
            "expected BitString"
        ),
    )]
    fn test_key_usage_decode_failure(input: Element, expected_error_msg: &str) {
        let result: Result<KeyUsage, Error> = input.decode();
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

    // AuthorityKeyIdentifier tests
    #[rstest(
        input,
        expected,
        // Test case: Only keyIdentifier [0]
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    slot: 0,
                    element: Box::new(Element::OctetString(OctetString::from(vec![0x01, 0x02, 0x03, 0x04]))),
                },
            ]),
            AuthorityKeyIdentifier {
                key_identifier: Some(vec![0x01, 0x02, 0x03, 0x04]),
                authority_cert_issuer: None,
                authority_cert_serial_number: None,
            }
        ),
        // Test case: Only serialNumber [2]
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    slot: 2,
                    element: Box::new(Element::Integer(asn1::Integer::from(vec![0x01, 0x23, 0x45]))),
                },
            ]),
            AuthorityKeyIdentifier {
                key_identifier: None,
                authority_cert_issuer: None,
                authority_cert_serial_number: Some(CertificateSerialNumber::from_bytes(vec![0x01, 0x23, 0x45])),
            }
        ),
        // Test case: keyIdentifier and serialNumber
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    slot: 0,
                    element: Box::new(Element::OctetString(OctetString::from(vec![0xAA, 0xBB, 0xCC]))),
                },
                Element::ContextSpecific {
                    slot: 2,
                    element: Box::new(Element::Integer(asn1::Integer::from(vec![0xFF]))),
                },
            ]),
            AuthorityKeyIdentifier {
                key_identifier: Some(vec![0xAA, 0xBB, 0xCC]),
                authority_cert_issuer: None,
                authority_cert_serial_number: Some(CertificateSerialNumber::from_bytes(vec![0xFF])),
            }
        ),
        // Test case: Empty sequence (all fields OPTIONAL)
        case(
            Element::Sequence(vec![]),
            AuthorityKeyIdentifier {
                key_identifier: None,
                authority_cert_issuer: None,
                authority_cert_serial_number: None,
            }
        ),
    )]
    fn test_authority_key_identifier_decode_success(
        input: Element,
        expected: AuthorityKeyIdentifier,
    ) {
        let result: Result<AuthorityKeyIdentifier, Error> = input.decode();
        assert!(result.is_ok(), "Failed to decode: {:?}", result);
        let actual = result.unwrap();
        assert_eq!(expected, actual);
    }

    #[rstest(
        input,
        expected_error_msg,
        // Test case: Not a Sequence
        case(
            Element::Boolean(true),
            "expected Sequence"
        ),
        // Test case: keyIdentifier [0] is not OctetString
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    slot: 0,
                    element: Box::new(Element::Integer(asn1::Integer::from(vec![0x01]))),
                },
            ]),
            "keyIdentifier must be OctetString"
        ),
        // Test case: serialNumber [2] is invalid type (BitString)
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    slot: 2,
                    element: Box::new(Element::BitString(asn1::BitString::try_from(vec![0x00, 0x01]).unwrap())),
                },
            ]),
            "serialNumber must be OctetString (IMPLICIT) or Integer (EXPLICIT)"
        ),
    )]
    fn test_authority_key_identifier_decode_failure(input: Element, expected_error_msg: &str) {
        let result: Result<AuthorityKeyIdentifier, Error> = input.decode();
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

    #[test]
    fn test_authority_key_identifier_parse_with_real_values() {
        // Test with actual values from OpenSSL-generated certificate
        // keyid:78:D4:81:76:CD:F7:8D:59:6D:D4:C4:86:A4:1D:23:0A:53:CE:CD:D7
        let key_id = vec![
            0x78, 0xD4, 0x81, 0x76, 0xCD, 0xF7, 0x8D, 0x59, 0x6D, 0xD4, 0xC4, 0x86, 0xA4, 0x1D,
            0x23, 0x0A, 0x53, 0xCE, 0xCD, 0xD7,
        ];

        // Create Element structure directly (simulating parsed DER)
        let element = Element::Sequence(vec![Element::ContextSpecific {
            slot: 0,
            element: Box::new(Element::OctetString(OctetString::from(key_id.clone()))),
        }]);

        let result: Result<AuthorityKeyIdentifier, Error> = element.decode();
        assert!(result.is_ok(), "Failed to decode: {:?}", result);
        let aki = result.unwrap();
        assert_eq!(aki.key_identifier, Some(key_id));
        assert_eq!(aki.authority_cert_issuer, None);
        assert_eq!(aki.authority_cert_serial_number, None);
    }

    #[test]
    fn test_authority_key_identifier_parse_from_real_der() {
        // Real DER-encoded AuthorityKeyIdentifier from OpenSSL-generated certificate
        // 30 16: SEQUENCE, length 22
        // 80 14: [0] IMPLICIT (context-specific primitive 0), length 20
        // 78D4...CDD7: keyIdentifier value (20 bytes SHA-1 hash)
        let der_bytes = vec![
            0x30, 0x16, 0x80, 0x14, 0x78, 0xD4, 0x81, 0x76, 0xCD, 0xF7, 0x8D, 0x59, 0x6D, 0xD4,
            0xC4, 0x86, 0xA4, 0x1D, 0x23, 0x0A, 0x53, 0xCE, 0xCD, 0xD7,
        ];
        let octet_string = OctetString::from(der_bytes);

        let extension = Extension {
            id: ObjectIdentifier::from_str(AuthorityKeyIdentifier::OID).unwrap(),
            critical: false,
            value: octet_string,
        };

        let result = extension.parse::<AuthorityKeyIdentifier>();
        assert!(result.is_ok(), "Failed to parse: {:?}", result);
        let aki = result.unwrap();

        let expected_key_id = vec![
            0x78, 0xD4, 0x81, 0x76, 0xCD, 0xF7, 0x8D, 0x59, 0x6D, 0xD4, 0xC4, 0x86, 0xA4, 0x1D,
            0x23, 0x0A, 0x53, 0xCE, 0xCD, 0xD7,
        ];
        assert_eq!(aki.key_identifier, Some(expected_key_id));
        assert_eq!(aki.authority_cert_issuer, None);
        assert_eq!(aki.authority_cert_serial_number, None);
    }

    // ========== SubjectKeyIdentifier Tests ==========

    #[rstest(
        input,
        expected,
        // Test case: Typical 20-byte SHA-1 hash
        case(
            Element::OctetString(OctetString::from(vec![
                0x78, 0xD4, 0x81, 0x76, 0xCD, 0xF7, 0x8D, 0x59, 0x6D, 0xD4,
                0xC4, 0x86, 0xA4, 0x1D, 0x23, 0x0A, 0x53, 0xCE, 0xCD, 0xD7,
            ])),
            SubjectKeyIdentifier {
                key_identifier: vec![
                    0x78, 0xD4, 0x81, 0x76, 0xCD, 0xF7, 0x8D, 0x59, 0x6D, 0xD4,
                    0xC4, 0x86, 0xA4, 0x1D, 0x23, 0x0A, 0x53, 0xCE, 0xCD, 0xD7,
                ],
            }
        ),
        // Test case: Shorter identifier (4 bytes)
        case(
            Element::OctetString(OctetString::from(vec![0xAA, 0xBB, 0xCC, 0xDD])),
            SubjectKeyIdentifier {
                key_identifier: vec![0xAA, 0xBB, 0xCC, 0xDD],
            }
        ),
        // Test case: Single byte identifier
        case(
            Element::OctetString(OctetString::from(vec![0x42])),
            SubjectKeyIdentifier {
                key_identifier: vec![0x42],
            }
        ),
    )]
    fn test_subject_key_identifier_decode_success(input: Element, expected: SubjectKeyIdentifier) {
        let result: Result<SubjectKeyIdentifier, Error> = input.decode();
        assert!(result.is_ok(), "Failed to decode: {:?}", result);
        let actual = result.unwrap();
        assert_eq!(expected, actual);
    }

    #[rstest(
        input,
        expected_error_msg,
        // Test case: Not an OctetString (Integer)
        case(
            Element::Integer(asn1::Integer::from(vec![0x01, 0x02])),
            "expected OctetString"
        ),
        // Test case: Not an OctetString (Sequence)
        case(
            Element::Sequence(vec![
                Element::OctetString(OctetString::from(vec![0x01]))
            ]),
            "expected OctetString"
        ),
    )]
    fn test_subject_key_identifier_decode_failure(input: Element, expected_error_msg: &str) {
        let result: Result<SubjectKeyIdentifier, Error> = input.decode();
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

    #[test]
    fn test_subject_key_identifier_parse_from_real_der() {
        // Real DER-encoded SubjectKeyIdentifier from OpenSSL-generated certificate
        // 04 14: OCTET STRING, length 20
        // 78D4...CDD7: keyIdentifier value (20 bytes SHA-1 hash)
        let der_bytes = vec![
            0x04, 0x14, 0x78, 0xD4, 0x81, 0x76, 0xCD, 0xF7, 0x8D, 0x59, 0x6D, 0xD4, 0xC4, 0x86,
            0xA4, 0x1D, 0x23, 0x0A, 0x53, 0xCE, 0xCD, 0xD7,
        ];
        let octet_string = OctetString::from(der_bytes);

        let extension = Extension {
            id: ObjectIdentifier::from_str(SubjectKeyIdentifier::OID).unwrap(),
            critical: false,
            value: octet_string,
        };

        let result = extension.parse::<SubjectKeyIdentifier>();
        assert!(result.is_ok(), "Failed to parse: {:?}", result);
        let ski = result.unwrap();

        let expected_key_id = vec![
            0x78, 0xD4, 0x81, 0x76, 0xCD, 0xF7, 0x8D, 0x59, 0x6D, 0xD4, 0xC4, 0x86, 0xA4, 0x1D,
            0x23, 0x0A, 0x53, 0xCE, 0xCD, 0xD7,
        ];
        assert_eq!(ski.key_identifier, expected_key_id);
    }

    // ========== ExtendedKeyUsage Tests ==========

    #[rstest(
        input,
        expected,
        // Test case: Single purpose - serverAuth
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str(ExtendedKeyUsage::SERVER_AUTH).unwrap()),
            ]),
            ExtendedKeyUsage {
                purposes: vec![
                    ObjectIdentifier::from_str(ExtendedKeyUsage::SERVER_AUTH).unwrap(),
                ],
            }
        ),
        // Test case: Multiple purposes - serverAuth and clientAuth
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str(ExtendedKeyUsage::SERVER_AUTH).unwrap()),
                Element::ObjectIdentifier(ObjectIdentifier::from_str(ExtendedKeyUsage::CLIENT_AUTH).unwrap()),
            ]),
            ExtendedKeyUsage {
                purposes: vec![
                    ObjectIdentifier::from_str(ExtendedKeyUsage::SERVER_AUTH).unwrap(),
                    ObjectIdentifier::from_str(ExtendedKeyUsage::CLIENT_AUTH).unwrap(),
                ],
            }
        ),
        // Test case: Multiple purposes - serverAuth, clientAuth, codeSigning
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str(ExtendedKeyUsage::SERVER_AUTH).unwrap()),
                Element::ObjectIdentifier(ObjectIdentifier::from_str(ExtendedKeyUsage::CLIENT_AUTH).unwrap()),
                Element::ObjectIdentifier(ObjectIdentifier::from_str(ExtendedKeyUsage::CODE_SIGNING).unwrap()),
            ]),
            ExtendedKeyUsage {
                purposes: vec![
                    ObjectIdentifier::from_str(ExtendedKeyUsage::SERVER_AUTH).unwrap(),
                    ObjectIdentifier::from_str(ExtendedKeyUsage::CLIENT_AUTH).unwrap(),
                    ObjectIdentifier::from_str(ExtendedKeyUsage::CODE_SIGNING).unwrap(),
                ],
            }
        ),
        // Test case: emailProtection
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str(ExtendedKeyUsage::EMAIL_PROTECTION).unwrap()),
            ]),
            ExtendedKeyUsage {
                purposes: vec![
                    ObjectIdentifier::from_str(ExtendedKeyUsage::EMAIL_PROTECTION).unwrap(),
                ],
            }
        ),
    )]
    fn test_extended_key_usage_decode_success(input: Element, expected: ExtendedKeyUsage) {
        let result: Result<ExtendedKeyUsage, Error> = input.decode();
        assert!(result.is_ok(), "Failed to decode: {:?}", result);
        let actual = result.unwrap();
        assert_eq!(expected, actual);
    }

    #[rstest(
        input,
        expected_error_msg,
        // Test case: Empty sequence (at least one required)
        case(
            Element::Sequence(vec![]),
            "empty sequence - at least one KeyPurposeId required"
        ),
        // Test case: Not a Sequence
        case(
            Element::OctetString(OctetString::from(vec![0x01, 0x02])),
            "expected Sequence"
        ),
        // Test case: Sequence with non-OID element
        case(
            Element::Sequence(vec![
                Element::Integer(asn1::Integer::from(vec![0x01])),
            ]),
            "expected ObjectIdentifier"
        ),
        // Test case: Mixed OID and non-OID
        case(
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str(ExtendedKeyUsage::SERVER_AUTH).unwrap()),
                Element::OctetString(OctetString::from(vec![0x01])),
            ]),
            "expected ObjectIdentifier"
        ),
    )]
    fn test_extended_key_usage_decode_failure(input: Element, expected_error_msg: &str) {
        let result: Result<ExtendedKeyUsage, Error> = input.decode();
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

    #[test]
    fn test_extended_key_usage_parse_from_real_der() {
        // Real DER-encoded ExtendedKeyUsage with serverAuth and clientAuth
        // 30 14: SEQUENCE, length 20
        // 06 08 2B 06 01 05 05 07 03 01: OID 1.3.6.1.5.5.7.3.1 (serverAuth)
        // 06 08 2B 06 01 05 05 07 03 02: OID 1.3.6.1.5.5.7.3.2 (clientAuth)
        let der_bytes = vec![
            0x30, 0x14, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x06, 0x08,
            0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02,
        ];
        let octet_string = OctetString::from(der_bytes);

        let extension = Extension {
            id: ObjectIdentifier::from_str(ExtendedKeyUsage::OID).unwrap(),
            critical: false,
            value: octet_string,
        };

        let result = extension.parse::<ExtendedKeyUsage>();
        assert!(result.is_ok(), "Failed to parse: {:?}", result);
        let eku = result.unwrap();

        assert_eq!(eku.purposes.len(), 2);
        assert_eq!(eku.purposes[0].to_string(), ExtendedKeyUsage::SERVER_AUTH);
        assert_eq!(eku.purposes[1].to_string(), ExtendedKeyUsage::CLIENT_AUTH);
    }

    // ========== SubjectAltName Tests ==========

    #[rstest(
        input,
        expected,
        // Test case: Single dNSName
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    slot: 2,
                    element: Box::new(Element::OctetString(OctetString::from(b"example.com".to_vec()))),
                },
            ]),
            SubjectAltName {
                names: vec![GeneralName::DnsName("example.com".to_string())],
            }
        ),
        // Test case: Multiple dNSNames
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    slot: 2,
                    element: Box::new(Element::OctetString(OctetString::from(b"example.com".to_vec()))),
                },
                Element::ContextSpecific {
                    slot: 2,
                    element: Box::new(Element::OctetString(OctetString::from(b"www.example.com".to_vec()))),
                },
            ]),
            SubjectAltName {
                names: vec![
                    GeneralName::DnsName("example.com".to_string()),
                    GeneralName::DnsName("www.example.com".to_string()),
                ],
            }
        ),
        // Test case: IPv4 address
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    slot: 7,
                    element: Box::new(Element::OctetString(OctetString::from(vec![192, 0, 2, 1]))),
                },
            ]),
            SubjectAltName {
                names: vec![GeneralName::IpAddress(IpAddr::from([192, 0, 2, 1]))],
            }
        ),
        // Test case: IPv6 address
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    slot: 7,
                    element: Box::new(Element::OctetString(OctetString::from(vec![
                        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                    ]))),
                },
            ]),
            SubjectAltName {
                names: vec![GeneralName::IpAddress(IpAddr::from([
                    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                ]))],
            }
        ),
        // Test case: URI
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    slot: 6,
                    element: Box::new(Element::OctetString(OctetString::from(b"https://example.com".to_vec()))),
                },
            ]),
            SubjectAltName {
                names: vec![GeneralName::Uri("https://example.com".to_string())],
            }
        ),
        // Test case: rfc822Name (email)
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    slot: 1,
                    element: Box::new(Element::OctetString(OctetString::from(b"user@example.com".to_vec()))),
                },
            ]),
            SubjectAltName {
                names: vec![GeneralName::Rfc822Name("user@example.com".to_string())],
            }
        ),
        // Test case: Mixed types
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    slot: 2,
                    element: Box::new(Element::OctetString(OctetString::from(b"example.com".to_vec()))),
                },
                Element::ContextSpecific {
                    slot: 7,
                    element: Box::new(Element::OctetString(OctetString::from(vec![192, 0, 2, 1]))),
                },
                Element::ContextSpecific {
                    slot: 6,
                    element: Box::new(Element::OctetString(OctetString::from(b"https://example.com".to_vec()))),
                },
            ]),
            SubjectAltName {
                names: vec![
                    GeneralName::DnsName("example.com".to_string()),
                    GeneralName::IpAddress(IpAddr::from([192, 0, 2, 1])),
                    GeneralName::Uri("https://example.com".to_string()),
                ],
            }
        ),
    )]
    fn test_subject_alt_name_decode_success(input: Element, expected: SubjectAltName) {
        let result: Result<SubjectAltName, Error> = input.decode();
        assert!(result.is_ok(), "Failed to decode: {:?}", result);
        let actual = result.unwrap();
        assert_eq!(expected, actual);
    }

    #[rstest(
        input,
        expected_error_msg,
        // Test case: Empty sequence
        case(
            Element::Sequence(vec![]),
            "empty sequence - at least one GeneralName required"
        ),
        // Test case: Not a Sequence
        case(
            Element::OctetString(OctetString::from(vec![0x01, 0x02])),
            "expected Sequence"
        ),
        // Test case: Invalid IP address length (3 bytes)
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    slot: 7,
                    element: Box::new(Element::OctetString(OctetString::from(vec![192, 0, 2]))),
                },
            ]),
            "iPAddress must be 4 or 16 bytes"
        ),
        // Test case: Non-context-specific element
        case(
            Element::Sequence(vec![
                Element::OctetString(OctetString::from(b"example.com".to_vec())),
            ]),
            "GeneralName must be context-specific element"
        ),
    )]
    fn test_subject_alt_name_decode_failure(input: Element, expected_error_msg: &str) {
        let result: Result<SubjectAltName, Error> = input.decode();
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

    #[test]
    fn test_subject_alt_name_parse_from_real_der() {
        // Real DER-encoded SubjectAltName with dNSName
        // 30 0D: SEQUENCE, length 13 (0x0D)
        // 82 0B: [2] IMPLICIT (dNSName), length 11 (0x0B)
        // "example.com" (11 bytes: 0x65 0x78 0x61 0x6d 0x70 0x6c 0x65 0x2e 0x63 0x6f 0x6d)
        let der_bytes = vec![
            0x30, 0x0D, // SEQUENCE, length 13
            0x82, 0x0B, // [2] IMPLICIT, length 11
            0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, // "example.com"
        ];
        let octet_string = OctetString::from(der_bytes);

        let extension = Extension {
            id: ObjectIdentifier::from_str(SubjectAltName::OID).unwrap(),
            critical: false,
            value: octet_string,
        };

        let result = extension.parse::<SubjectAltName>();
        assert!(result.is_ok(), "Failed to parse: {:?}", result);
        let san = result.unwrap();

        assert_eq!(san.names.len(), 1);
        match &san.names[0] {
            GeneralName::DnsName(name) => assert_eq!(name, "example.com"),
            _ => panic!("Expected DnsName"),
        }
    }

    #[test]
    fn test_general_name_other_name() {
        // Test OtherName with a simple structure
        // SEQUENCE {
        //   type-id: OID 1.2.3.4
        //   value: [0] EXPLICIT UTF8String "test"
        // }
        let other_name_elem = Element::Sequence(vec![
            Element::ObjectIdentifier(ObjectIdentifier::from_str("1.2.3.4").unwrap()),
            Element::ContextSpecific {
                slot: 0,
                element: Box::new(Element::UTF8String("test".to_string())),
            },
        ]);

        let gn = GeneralName::parse_from_context_specific(0, &Box::new(other_name_elem));
        assert!(gn.is_ok(), "Failed to parse OtherName: {:?}", gn);

        match gn.unwrap() {
            GeneralName::OtherName(on) => {
                assert_eq!(on.type_id, ObjectIdentifier::from_str("1.2.3.4").unwrap());
                // value should contain some representation of "test"
                assert!(!on.value.is_empty());
            }
            _ => panic!("Expected OtherName"),
        }
    }

    #[test]
    fn test_general_name_edi_party_name() {
        // Test EDIPartyName with nameAssigner and partyName
        // SEQUENCE {
        //   [0] nameAssigner (DirectoryString)
        //   [1] partyName (DirectoryString)
        // }
        let edi_elem = Element::Sequence(vec![
            Element::ContextSpecific {
                slot: 0,
                element: Box::new(Element::UTF8String("Assigner".to_string())),
            },
            Element::ContextSpecific {
                slot: 1,
                element: Box::new(Element::UTF8String("Party".to_string())),
            },
        ]);

        let gn = GeneralName::parse_from_context_specific(5, &Box::new(edi_elem));
        assert!(gn.is_ok(), "Failed to parse EDIPartyName: {:?}", gn);

        match gn.unwrap() {
            GeneralName::EdiPartyName(epn) => {
                assert_eq!(epn.name_assigner, Some("Assigner".to_string()));
                assert_eq!(epn.party_name, "Party".to_string());
            }
            _ => panic!("Expected EdiPartyName"),
        }
    }

    #[test]
    fn test_general_name_edi_party_name_no_assigner() {
        // Test EDIPartyName with only partyName (nameAssigner is OPTIONAL)
        let edi_elem = Element::Sequence(vec![Element::ContextSpecific {
            slot: 1,
            element: Box::new(Element::PrintableString("Party Only".to_string())),
        }]);

        let gn = GeneralName::parse_from_context_specific(5, &Box::new(edi_elem));
        assert!(gn.is_ok(), "Failed to parse EDIPartyName: {:?}", gn);

        match gn.unwrap() {
            GeneralName::EdiPartyName(epn) => {
                assert_eq!(epn.name_assigner, None);
                assert_eq!(epn.party_name, "Party Only".to_string());
            }
            _ => panic!("Expected EdiPartyName"),
        }
    }

    #[test]
    fn test_general_name_x400_address() {
        // Test x400Address (stored as raw bytes)
        let x400_elem = Element::OctetString(asn1::OctetString::from(vec![0x01, 0x02, 0x03]));

        let gn = GeneralName::parse_from_context_specific(3, &Box::new(x400_elem));
        assert!(gn.is_ok(), "Failed to parse x400Address: {:?}", gn);

        match gn.unwrap() {
            GeneralName::X400Address(bytes) => {
                assert_eq!(bytes, vec![0x01, 0x02, 0x03]);
            }
            _ => panic!("Expected X400Address"),
        }
    }

    #[test]
    fn test_general_name_registered_id() {
        // Test registeredID [8] - IMPLICIT OID
        let oid_bytes = vec![0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D]; // 1.2.840.113549
        let reg_id_elem = Element::OctetString(asn1::OctetString::from(oid_bytes));

        let gn = GeneralName::parse_from_context_specific(8, &Box::new(reg_id_elem));
        assert!(gn.is_ok(), "Failed to parse registeredID: {:?}", gn);

        match gn.unwrap() {
            GeneralName::RegisteredId(oid) => {
                assert_eq!(oid, ObjectIdentifier::from_str("1.2.840.113549").unwrap());
            }
            _ => panic!("Expected RegisteredId"),
        }
    }

    #[rstest(
        input,
        expected,
        // Test case: Single OCSP descriptor
        case(
            Element::Sequence(vec![
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str(AuthorityInfoAccess::OCSP).unwrap()),
                    Element::ContextSpecific {
                        slot: 6,
                        element: Box::new(Element::OctetString(OctetString::from(b"http://ocsp.example.com".to_vec()))),
                    },
                ]),
            ]),
            AuthorityInfoAccess {
                descriptors: vec![AccessDescription {
                    access_method: ObjectIdentifier::from_str(AuthorityInfoAccess::OCSP).unwrap(),
                    access_location: GeneralName::Uri("http://ocsp.example.com".to_string()),
                }],
            }
        ),
        // Test case: Single CA Issuers descriptor
        case(
            Element::Sequence(vec![
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str(AuthorityInfoAccess::CA_ISSUERS).unwrap()),
                    Element::ContextSpecific {
                        slot: 6,
                        element: Box::new(Element::OctetString(OctetString::from(b"http://ca.example.com/cert.crt".to_vec()))),
                    },
                ]),
            ]),
            AuthorityInfoAccess {
                descriptors: vec![AccessDescription {
                    access_method: ObjectIdentifier::from_str(AuthorityInfoAccess::CA_ISSUERS).unwrap(),
                    access_location: GeneralName::Uri("http://ca.example.com/cert.crt".to_string()),
                }],
            }
        ),
        // Test case: Multiple descriptors (OCSP + CA Issuers)
        case(
            Element::Sequence(vec![
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str(AuthorityInfoAccess::OCSP).unwrap()),
                    Element::ContextSpecific {
                        slot: 6,
                        element: Box::new(Element::OctetString(OctetString::from(b"http://ocsp.example.com".to_vec()))),
                    },
                ]),
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str(AuthorityInfoAccess::CA_ISSUERS).unwrap()),
                    Element::ContextSpecific {
                        slot: 6,
                        element: Box::new(Element::OctetString(OctetString::from(b"http://ca.example.com/cert.crt".to_vec()))),
                    },
                ]),
            ]),
            AuthorityInfoAccess {
                descriptors: vec![
                    AccessDescription {
                        access_method: ObjectIdentifier::from_str(AuthorityInfoAccess::OCSP).unwrap(),
                        access_location: GeneralName::Uri("http://ocsp.example.com".to_string()),
                    },
                    AccessDescription {
                        access_method: ObjectIdentifier::from_str(AuthorityInfoAccess::CA_ISSUERS).unwrap(),
                        access_location: GeneralName::Uri("http://ca.example.com/cert.crt".to_string()),
                    },
                ],
            }
        ),
        // Test case: Multiple OCSP descriptors
        case(
            Element::Sequence(vec![
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str(AuthorityInfoAccess::OCSP).unwrap()),
                    Element::ContextSpecific {
                        slot: 6,
                        element: Box::new(Element::OctetString(OctetString::from(b"http://ocsp1.example.com".to_vec()))),
                    },
                ]),
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str(AuthorityInfoAccess::OCSP).unwrap()),
                    Element::ContextSpecific {
                        slot: 6,
                        element: Box::new(Element::OctetString(OctetString::from(b"http://ocsp2.example.com".to_vec()))),
                    },
                ]),
            ]),
            AuthorityInfoAccess {
                descriptors: vec![
                    AccessDescription {
                        access_method: ObjectIdentifier::from_str(AuthorityInfoAccess::OCSP).unwrap(),
                        access_location: GeneralName::Uri("http://ocsp1.example.com".to_string()),
                    },
                    AccessDescription {
                        access_method: ObjectIdentifier::from_str(AuthorityInfoAccess::OCSP).unwrap(),
                        access_location: GeneralName::Uri("http://ocsp2.example.com".to_string()),
                    },
                ],
            }
        ),
        // Test case: Access location as dNSName
        case(
            Element::Sequence(vec![
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str(AuthorityInfoAccess::OCSP).unwrap()),
                    Element::ContextSpecific {
                        slot: 2,
                        element: Box::new(Element::OctetString(OctetString::from(b"ocsp.example.com".to_vec()))),
                    },
                ]),
            ]),
            AuthorityInfoAccess {
                descriptors: vec![AccessDescription {
                    access_method: ObjectIdentifier::from_str(AuthorityInfoAccess::OCSP).unwrap(),
                    access_location: GeneralName::DnsName("ocsp.example.com".to_string()),
                }],
            }
        ),
    )]
    fn test_authority_info_access_decode_success(input: Element, expected: AuthorityInfoAccess) {
        let result: Result<AuthorityInfoAccess, Error> = input.decode();
        assert!(result.is_ok(), "Failed to decode: {:?}", result);
        let actual = result.unwrap();
        assert_eq!(expected, actual);
    }

    #[rstest(
        input,
        expected_error_msg,
        // Test case: Empty sequence
        case(
            Element::Sequence(vec![]),
            "at least one AccessDescription required"
        ),
        // Test case: Not a Sequence
        case(
            Element::OctetString(OctetString::from(vec![0x01, 0x02])),
            "expected Sequence"
        ),
        // Test case: AccessDescription with wrong number of elements
        case(
            Element::Sequence(vec![
                Element::Sequence(vec![
                    Element::ObjectIdentifier(ObjectIdentifier::from_str(AuthorityInfoAccess::OCSP).unwrap()),
                ]),
            ]),
            "AccessDescription must have exactly 2 elements"
        ),
        // Test case: AccessDescription with non-OID as first element
        case(
            Element::Sequence(vec![
                Element::Sequence(vec![
                    Element::OctetString(OctetString::from(vec![0x01])),
                    Element::ContextSpecific {
                        slot: 6,
                        element: Box::new(Element::OctetString(OctetString::from(b"http://ocsp.example.com".to_vec()))),
                    },
                ]),
            ]),
            "accessMethod must be ObjectIdentifier"
        ),
        // Test case: AccessDescription not a Sequence
        case(
            Element::Sequence(vec![
                Element::OctetString(OctetString::from(vec![0x01])),
            ]),
            "AccessDescription must be a Sequence"
        ),
    )]
    fn test_authority_info_access_decode_failure(input: Element, expected_error_msg: &str) {
        let result: Result<AuthorityInfoAccess, Error> = input.decode();
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

    #[test]
    fn test_authority_info_access_parse_from_real_der() {
        // Real DER-encoded AuthorityInfoAccess with OCSP and CA Issuers
        // 30 46: SEQUENCE, length 70 (0x46)
        //   30 20: SEQUENCE, length 32 (0x20) - AccessDescription #1
        //     06 08 2B 06 01 05 05 07 30 01: OID 1.3.6.1.5.5.7.48.1 (OCSP)
        //     86 14: [6] IMPLICIT (uniformResourceIdentifier), length 20 (0x14)
        //     "http://ocsp.example.com" (23 bytes)
        //   30 22: SEQUENCE, length 34 (0x22) - AccessDescription #2
        //     06 08 2B 06 01 05 05 07 30 02: OID 1.3.6.1.5.5.7.48.2 (CA Issuers)
        //     86 16: [6] IMPLICIT (uniformResourceIdentifier), length 22 (0x16)
        //     "http://ca.example.com/cert.crt" (31 bytes)
        let der_bytes = vec![
            0x30, 0x60, // SEQUENCE, length 96 (updated)
            // AccessDescription #1: OCSP
            0x30, 0x2B, // SEQUENCE, length 43
            0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, // OID OCSP
            0x86, 0x1F, // [6] IMPLICIT, length 31
            0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x6F, 0x63, 0x73, 0x70, 0x2E, 0x65, 0x78,
            0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x6F, 0x63, 0x73, 0x70,
            0x2D, 0x73, 0x65, // "http://ocsp.example.com/ocsp-se"
            // AccessDescription #2: CA Issuers
            0x30, 0x31, // SEQUENCE, length 49
            0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02, // OID CA Issuers
            0x86, 0x25, // [6] IMPLICIT, length 37
            0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x63, 0x61, 0x2E, 0x65, 0x78, 0x61, 0x6D,
            0x70, 0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x69, 0x73, 0x73, 0x75, 0x65, 0x72,
            0x2F, 0x63, 0x65, 0x72, 0x74, 0x2E, 0x63, 0x72,
            0x74, // "http://ca.example.com/issuer/cert.crt"
        ];
        let octet_string = OctetString::from(der_bytes);

        let extension = Extension {
            id: ObjectIdentifier::from_str(AuthorityInfoAccess::OID).unwrap(),
            critical: false,
            value: octet_string,
        };

        let result = extension.parse::<AuthorityInfoAccess>();
        assert!(result.is_ok(), "Failed to parse: {:?}", result);
        let aia = result.unwrap();

        assert_eq!(aia.descriptors.len(), 2);

        // Check first descriptor (OCSP)
        assert_eq!(
            aia.descriptors[0].access_method.to_string(),
            AuthorityInfoAccess::OCSP
        );
        match &aia.descriptors[0].access_location {
            GeneralName::Uri(uri) => {
                assert!(uri.starts_with("http://ocsp.example.com"));
            }
            _ => panic!("Expected Uri for OCSP"),
        }

        // Check second descriptor (CA Issuers)
        assert_eq!(
            aia.descriptors[1].access_method.to_string(),
            AuthorityInfoAccess::CA_ISSUERS
        );
        match &aia.descriptors[1].access_location {
            GeneralName::Uri(uri) => {
                assert!(uri.starts_with("http://ca.example.com"));
            }
            _ => panic!("Expected Uri for CA Issuers"),
        }
    }
}
