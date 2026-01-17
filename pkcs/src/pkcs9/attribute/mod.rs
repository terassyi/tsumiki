/// PKCS#9: Selected Object Classes and Attribute Types
/// RFC 2985
///
/// This module provides definitions for PKCS#9 attributes.
use asn1::{ASN1Object, AsOid, Element, ObjectIdentifier, OctetString};
use der::Der;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::pkcs9::error::{Error, Result};
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};

/// Type alias for PKCS#9 String.
///
/// According to RFC 2985, PKCS9String is a CHOICE of IA5String or DirectoryString.
/// This implementation uses String internally for simplicity and ergonomics.
pub type PKCS9String = String;

pub mod challenge_password;
pub mod content_type;
pub mod countersignature;
pub mod extension_request;
pub mod friendly_name;
pub mod local_key_id;
pub mod message_digest;
pub mod signing_time;
pub mod smime_capabilities;
pub mod unstructured_address;
pub mod unstructured_name;

pub use challenge_password::ChallengePassword;
pub use content_type::ContentType;
pub use countersignature::Countersignature;
pub use extension_request::ExtensionRequest;
pub use friendly_name::FriendlyName;
pub use local_key_id::LocalKeyId;
pub use message_digest::MessageDigest;
pub use signing_time::SigningTime;
pub use smime_capabilities::{SMIMECapabilities, SMIMECapability};
pub use unstructured_address::UnstructuredAddress;
pub use unstructured_name::UnstructuredName;

/// Raw attribute structure defined in RFC 2985
///
/// ```asn1
/// Attribute ::= SEQUENCE {
///     type    OBJECT IDENTIFIER,
///     values  SET OF AttributeValue
/// }
/// ```
///
/// AttributeValue is ANY type. The values are stored as raw bytes (OctetString)
/// for lazy parsing, similar to X.509 Extensions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawAttribute {
    /// The attribute type (OID)
    attribute_type: ObjectIdentifier,
    /// The attribute values (SET OF ANY) stored as raw DER bytes
    /// This allows for lazy parsing of specific attribute types
    values: OctetString,
}

impl RawAttribute {
    /// Get the attribute type OID
    pub fn attribute_type(&self) -> &ObjectIdentifier {
        &self.attribute_type
    }

    /// Get the raw values as OctetString
    pub fn values(&self) -> &OctetString {
        &self.values
    }

    /// Parse the attribute values as a specific attribute type
    pub fn parse<T: Attribute>(&self) -> Result<T> {
        // Verify OID matches
        if self.attribute_type != T::OID {
            return Err(Error::OidMismatch {
                expected: T::OID.to_string(),
                actual: self.attribute_type.to_string(),
            });
        }
        T::parse(&self.values)
    }
}

// Marker traits
impl DecodableFrom<Element> for RawAttribute {}
impl EncodableTo<RawAttribute> for Element {}

// Decoder implementation
impl Decoder<Element, RawAttribute> for Element {
    type Error = Error;

    fn decode(&self) -> Result<RawAttribute> {
        let Element::Sequence(seq) = self else {
            return Err(Error::InvalidAttribute(
                "Attribute must be a SEQUENCE".into(),
            ));
        };

        if seq.len() != 2 {
            return Err(Error::InvalidAttribute(format!(
                "Attribute SEQUENCE must have 2 elements, got {}",
                seq.len()
            )));
        }

        // First element: type (OBJECT IDENTIFIER)
        let Element::ObjectIdentifier(attribute_type) = &seq[0] else {
            return Err(Error::InvalidAttribute(
                "First element of Attribute must be OBJECT IDENTIFIER".into(),
            ));
        };

        // Second element: values (SET OF ANY)
        let Element::Set(_) = &seq[1] else {
            return Err(Error::InvalidAttribute(
                "Second element of Attribute must be SET".into(),
            ));
        };

        // Encode the SET back to DER bytes and store as OctetString for lazy parsing
        let asn1_obj = ASN1Object::new(vec![seq[1].clone()]);
        let der = asn1_obj.encode().map_err(Error::from)?;
        let der_bytes = der.encode().map_err(Error::from)?;

        Ok(RawAttribute {
            attribute_type: attribute_type.clone(),
            values: OctetString::from(der_bytes),
        })
    }
}

// Encoder implementation
impl Encoder<RawAttribute, Element> for RawAttribute {
    type Error = Error;

    fn encode(&self) -> Result<Element> {
        let der = Decoder::<&[u8], Der>::decode(&self.values.as_ref()).map_err(Error::from)?;
        let asn1_obj = Decoder::<Der, ASN1Object>::decode(&der).map_err(Error::from)?;

        let values_element = asn1_obj
            .elements()
            .first()
            .ok_or_else(|| Error::InvalidAttribute("Empty ASN1Object".into()))?
            .clone();

        Ok(Element::Sequence(vec![
            Element::ObjectIdentifier(self.attribute_type.clone()),
            values_element,
        ]))
    }
}

/// Trait for PKCS#9 attributes that can be parsed from RawAttribute.values
///
/// This trait defines the interface for parsing specific attribute types
/// from the raw DER-encoded attribute values, similar to X.509's StandardExtension trait.
pub trait Attribute: Sized {
    /// The OID string for this attribute type
    const OID: &'static str;

    /// Parse the attribute values (DER-encoded SET OF in OctetString)
    fn parse(values: &OctetString) -> Result<Self>;
}

/// Attributes type as defined in PKCS#8 and PKCS#9
///
/// Attributes ::= SET OF Attribute
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attributes(Vec<RawAttribute>);

impl Attributes {
    /// Create a new Attributes collection
    pub fn new(attributes: Vec<RawAttribute>) -> Self {
        Self(attributes)
    }

    /// Get the number of attributes
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the collection is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Get an attribute by OID
    pub fn get_by_oid<O: AsOid>(&self, oid: O) -> Result<Option<&RawAttribute>> {
        let oid_obj = oid
            .as_oid()
            .map_err(|e| Error::InvalidAttribute(e.to_string()))?;
        Ok(self.0.iter().find(|attr| attr.attribute_type() == &oid_obj))
    }

    /// Get and parse a specific attribute by type
    pub fn attribute<T: Attribute>(&self) -> Result<Option<T>> {
        if let Some(attr) = self.get_by_oid(T::OID)? {
            Ok(Some(T::parse(attr.values())?))
        } else {
            Ok(None)
        }
    }

    /// Get all attributes as a slice
    pub fn as_slice(&self) -> &[RawAttribute] {
        &self.0
    }

    /// Convert to inner Vec
    pub fn into_inner(self) -> Vec<RawAttribute> {
        self.0
    }
}

impl AsRef<[RawAttribute]> for Attributes {
    fn as_ref(&self) -> &[RawAttribute] {
        &self.0
    }
}

impl std::ops::Deref for Attributes {
    type Target = [RawAttribute];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<RawAttribute>> for Attributes {
    fn from(attributes: Vec<RawAttribute>) -> Self {
        Self(attributes)
    }
}

impl From<Attributes> for Vec<RawAttribute> {
    fn from(attributes: Attributes) -> Self {
        attributes.0
    }
}

impl IntoIterator for Attributes {
    type Item = RawAttribute;
    type IntoIter = std::vec::IntoIter<RawAttribute>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Attributes {
    type Item = &'a RawAttribute;
    type IntoIter = std::slice::Iter<'a, RawAttribute>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl DecodableFrom<Element> for Attributes {}

// Decoder for Attributes from Element (expecting SET)
impl Decoder<Element, Attributes> for Element {
    type Error = Error;

    fn decode(&self) -> Result<Attributes> {
        let Element::Set(elements) = self else {
            return Err(Error::InvalidAttribute("Attributes must be a SET".into()));
        };

        let attributes = elements
            .iter()
            .map(|elem| elem.decode())
            .collect::<Result<Vec<RawAttribute>>>()?;

        Ok(Attributes::new(attributes))
    }
}

impl EncodableTo<Attributes> for Element {}

// Encoder for Attributes to Element (SET)
impl Encoder<Attributes, Element> for Attributes {
    type Error = Error;

    fn encode(&self) -> Result<Element> {
        let elements = self
            .0
            .iter()
            .map(|attr| attr.encode())
            .collect::<Result<Vec<Element>>>()?;
        Ok(Element::Set(elements))
    }
}

/// Parsed PKCS#9 attributes for serialization and display.
///
/// This structure holds all parsed attribute types, similar to RawExtensions in X.509.
/// Each field is optional and will only be populated if the corresponding attribute
/// is present in the attribute set.
#[derive(Debug, Clone, Serialize)]
pub struct ParsedAttributes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) content_type: Option<ContentType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) message_digest: Option<MessageDigest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) signing_time: Option<SigningTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) countersignature: Option<Countersignature>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) challenge_password: Option<ChallengePassword>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) unstructured_name: Option<UnstructuredName>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) unstructured_address: Option<UnstructuredAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) extension_request: Option<ExtensionRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) smime_capabilities: Option<SMIMECapabilities>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) friendly_name: Option<FriendlyName>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) local_key_id: Option<LocalKeyId>,
}

impl From<&[RawAttribute]> for ParsedAttributes {
    fn from(attributes: &[RawAttribute]) -> Self {
        let mut parsed = ParsedAttributes {
            content_type: None,
            message_digest: None,
            signing_time: None,
            countersignature: None,
            challenge_password: None,
            unstructured_name: None,
            unstructured_address: None,
            extension_request: None,
            smime_capabilities: None,
            friendly_name: None,
            local_key_id: None,
        };

        for attr in attributes {
            let oid_str = attr.attribute_type().to_string();
            match oid_str.as_str() {
                ContentType::OID => {
                    parsed.content_type = attr.parse::<ContentType>().ok();
                }
                MessageDigest::OID => {
                    parsed.message_digest = attr.parse::<MessageDigest>().ok();
                }
                SigningTime::OID => {
                    parsed.signing_time = attr.parse::<SigningTime>().ok();
                }
                Countersignature::OID => {
                    parsed.countersignature = attr.parse::<Countersignature>().ok();
                }
                ChallengePassword::OID => {
                    parsed.challenge_password = attr.parse::<ChallengePassword>().ok();
                }
                UnstructuredName::OID => {
                    parsed.unstructured_name = attr.parse::<UnstructuredName>().ok();
                }
                UnstructuredAddress::OID => {
                    parsed.unstructured_address = attr.parse::<UnstructuredAddress>().ok();
                }
                ExtensionRequest::OID => {
                    parsed.extension_request = attr.parse::<ExtensionRequest>().ok();
                }
                SMIMECapabilities::OID => {
                    parsed.smime_capabilities = attr.parse::<SMIMECapabilities>().ok();
                }
                FriendlyName::OID => {
                    parsed.friendly_name = attr.parse::<FriendlyName>().ok();
                }
                LocalKeyId::OID => {
                    parsed.local_key_id = attr.parse::<LocalKeyId>().ok();
                }
                _ => {
                    // Unknown attributes are silently skipped
                }
            }
        }

        parsed
    }
}

impl fmt::Display for ParsedAttributes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ct) = &self.content_type {
            writeln!(f, "    Content Type: {}", ct)?;
        }
        if let Some(md) = &self.message_digest {
            writeln!(f, "    Message Digest: {}", md)?;
        }
        if let Some(st) = &self.signing_time {
            writeln!(f, "    Signing Time: {}", st)?;
        }
        if let Some(cs) = &self.countersignature {
            writeln!(f, "    Countersignature:")?;
            writeln!(f, "        CMS Version: {:?}", cs.signer_info().version())?;
            writeln!(f, "        Signer: {:?}", cs.signer_info().sid())?;
            writeln!(
                f,
                "        Digest Algorithm: {}",
                cs.signer_info().digest_algorithm().algorithm
            )?;
            writeln!(
                f,
                "        Signature Algorithm: {}",
                cs.signer_info().signature_algorithm().algorithm
            )?;
        }
        if let Some(cp) = &self.challenge_password {
            writeln!(f, "    Challenge Password: {}", cp)?;
        }
        if let Some(un) = &self.unstructured_name {
            writeln!(f, "    Unstructured Name: {}", un)?;
        }
        if let Some(ua) = &self.unstructured_address {
            writeln!(f, "    Unstructured Address: {}", ua)?;
        }
        if let Some(er) = &self.extension_request {
            writeln!(f, "    Extension Request:")?;
            writeln!(f, "        {} extension(s)", er.extensions().len())?;
        }
        if let Some(sc) = &self.smime_capabilities {
            writeln!(f, "    S/MIME Capabilities:")?;
            for (i, cap) in sc.capabilities().iter().enumerate() {
                write!(f, "        [{}] {}", i, cap.capability_id())?;
                if cap.parameters().is_some() {
                    writeln!(f, " (with parameters)")?;
                } else {
                    writeln!(f)?;
                }
            }
        }
        if let Some(fn_attr) = &self.friendly_name {
            writeln!(f, "    Friendly Name: {}", fn_attr)?;
        }
        if let Some(lk) = &self.local_key_id {
            writeln!(f, "    Local Key ID: {}", lk)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asn1::ObjectIdentifier;
    use rstest::rstest;
    use std::str::FromStr;

    fn create_attribute(oid: &str, value: Element) -> RawAttribute {
        let oid = ObjectIdentifier::from_str(oid).unwrap();
        let set = Element::Set(vec![value]);
        let attr_seq = Element::Sequence(vec![Element::ObjectIdentifier(oid), set]);
        attr_seq.decode().unwrap()
    }

    #[rstest]
    #[case("Test Key")]
    #[case("My Certificate")]
    #[case("Production Key")]
    fn test_parsed_attributes_friendly_name(#[case] name: &str) {
        let bmp_value = Element::BMPString(asn1::BMPString::new(name).unwrap());
        let raw_attr = create_attribute(FriendlyName::OID, bmp_value);

        let parsed = ParsedAttributes::from([raw_attr].as_slice());
        assert!(parsed.friendly_name.is_some());
        assert_eq!(parsed.friendly_name.unwrap().name(), name);
    }

    #[rstest]
    #[case(vec![0x01, 0x02, 0x03, 0x04])]
    #[case(vec![0xAB, 0xCD])]
    #[case(vec![0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA])]
    fn test_parsed_attributes_local_key_id(#[case] key_id: Vec<u8>) {
        let octet_value = Element::OctetString(OctetString::from(key_id.clone()));
        let raw_attr = create_attribute(LocalKeyId::OID, octet_value);

        let parsed = ParsedAttributes::from([raw_attr].as_slice());
        assert!(parsed.local_key_id.is_some());
        assert_eq!(parsed.local_key_id.unwrap().key_id().as_bytes(), &key_id);
    }

    #[test]
    fn test_parsed_attributes_multiple() {
        let name = "My Key";
        let key_id = vec![0xAB, 0xCD];

        // FriendlyName
        let bmp_value = Element::BMPString(asn1::BMPString::new(name).unwrap());
        let raw_attr1 = create_attribute(FriendlyName::OID, bmp_value);

        // LocalKeyId
        let octet_value = Element::OctetString(OctetString::from(key_id.clone()));
        let raw_attr2 = create_attribute(LocalKeyId::OID, octet_value);

        // Parse both
        let parsed = ParsedAttributes::from([raw_attr1, raw_attr2].as_slice());
        assert!(parsed.friendly_name.is_some());
        assert!(parsed.local_key_id.is_some());
        assert_eq!(parsed.friendly_name.unwrap().name(), name);
        assert_eq!(parsed.local_key_id.unwrap().key_id().as_bytes(), &key_id);
    }

    #[rstest]
    #[case("1.2.3.4.5")]
    #[case("2.999.1")]
    #[case("1.3.6.1.4.1.99999")]
    fn test_parsed_attributes_unknown_ignored(#[case] oid: &str) {
        let value = Element::OctetString(OctetString::from(vec![0x42]));
        let raw_attr = create_attribute(oid, value);

        let parsed = ParsedAttributes::from([raw_attr].as_slice());
        assert!(parsed.friendly_name.is_none());
        assert!(parsed.local_key_id.is_none());
    }

    #[rstest]
    #[case("My Certificate", "Friendly Name")]
    #[case("Test Key", "Friendly Name")]
    fn test_parsed_attributes_display(#[case] name: &str, #[case] expected: &str) {
        let bmp_value = Element::BMPString(asn1::BMPString::new(name).unwrap());
        let raw_attr = create_attribute(FriendlyName::OID, bmp_value);

        let parsed = ParsedAttributes::from([raw_attr].as_slice());
        let display = format!("{}", parsed);
        assert!(display.contains(expected));
        assert!(display.contains(name));
    }
}
