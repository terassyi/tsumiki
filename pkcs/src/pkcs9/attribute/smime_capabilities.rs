//! PKCS#9 smimeCapabilities attribute (OID: 1.2.840.113549.1.9.15)
//!
//! Defined in RFC 2633 Section 2.5.2
//!
//! ```asn1
//! smimeCapabilities ATTRIBUTE ::= {
//!     WITH SYNTAX SMIMECapabilities
//!     SINGLE VALUE TRUE
//!     ID smime-aa-smimeCapabilities
//! }
//!
//! SMIMECapabilities ::= SEQUENCE OF SMIMECapability
//!
//! SMIMECapability ::= SEQUENCE {
//!     capabilityID OBJECT IDENTIFIER,
//!     parameters ANY DEFINED BY capabilityID OPTIONAL
//! }
//! ```
//!
//! The smimeCapabilities attribute type specifies the cryptographic
//! capabilities supported by a S/MIME client. This allows recipients
//! to choose an appropriate encryption algorithm when sending encrypted
//! messages.

use asn1::{ASN1Object, Element, ObjectIdentifier, OctetString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;

use crate::pkcs9::error::{Error, Result};

use super::Attribute;

/// A single S/MIME capability
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SMIMECapability {
    /// The capability OID (e.g., encryption algorithm)
    capability_id: ObjectIdentifier,
    /// Optional parameters for the capability
    parameters: Option<Element>,
}

impl Serialize for SMIMECapability {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("SMIMECapability", 2)?;
        state.serialize_field("capabilityId", &self.capability_id.to_string())?;
        if let Some(ref params) = self.parameters {
            state.serialize_field("parameters", &format!("{:?}", params))?;
        }
        state.end()
    }
}

impl<'de> Deserialize<'de> for SMIMECapability {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "camelCase")]
        enum Field {
            CapabilityId,
            Parameters,
        }

        struct SMIMECapabilityVisitor;

        impl<'de> Visitor<'de> for SMIMECapabilityVisitor {
            type Value = SMIMECapability;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct SMIMECapability")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<SMIMECapability, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut capability_id = None;
                let mut _parameters_str: Option<String> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::CapabilityId => {
                            if capability_id.is_some() {
                                return Err(de::Error::duplicate_field("capabilityId"));
                            }
                            let oid_str: String = map.next_value()?;
                            capability_id =
                                Some(ObjectIdentifier::from_str(&oid_str).map_err(|e| {
                                    de::Error::custom(format!("Invalid OID: {}", e))
                                })?);
                        }
                        Field::Parameters => {
                            _parameters_str = Some(map.next_value()?);
                            // Note: We cannot reconstruct Element from debug string,
                            // so parameters will be None after deserialization
                        }
                    }
                }

                let capability_id =
                    capability_id.ok_or_else(|| de::Error::missing_field("capabilityId"))?;
                Ok(SMIMECapability {
                    capability_id,
                    parameters: None, // Cannot reconstruct from serialized form
                })
            }
        }

        deserializer.deserialize_struct(
            "SMIMECapability",
            &["capabilityId", "parameters"],
            SMIMECapabilityVisitor,
        )
    }
}

impl SMIMECapability {
    /// Create a new SMIMECapability with an algorithm OID
    pub fn new(capability_id: ObjectIdentifier) -> Self {
        Self {
            capability_id,
            parameters: None,
        }
    }

    /// Create a new SMIMECapability with an algorithm OID and parameters
    pub fn new_with_params(capability_id: ObjectIdentifier, parameters: Element) -> Self {
        Self {
            capability_id,
            parameters: Some(parameters),
        }
    }

    /// Get the capability ID (algorithm OID)
    pub fn capability_id(&self) -> &ObjectIdentifier {
        &self.capability_id
    }

    /// Get the optional parameters
    pub fn parameters(&self) -> Option<&Element> {
        self.parameters.as_ref()
    }
}

/// S/MIME capabilities attribute
///
/// Contains a list of cryptographic algorithms and capabilities
/// supported by the S/MIME client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SMIMECapabilities {
    /// List of supported capabilities
    capabilities: Vec<SMIMECapability>,
}

impl Serialize for SMIMECapabilities {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("SMIMECapabilities", 1)?;
        state.serialize_field("capabilities", &self.capabilities)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for SMIMECapabilities {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};

        #[derive(Deserialize)]
        #[serde(field_identifier)]
        enum Field {
            #[serde(rename = "capabilities")]
            Capabilities,
        }

        struct SMIMECapabilitiesVisitor;

        impl<'de> Visitor<'de> for SMIMECapabilitiesVisitor {
            type Value = SMIMECapabilities;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct SMIMECapabilities")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<SMIMECapabilities, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut capabilities = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Capabilities => {
                            if capabilities.is_some() {
                                return Err(de::Error::duplicate_field("capabilities"));
                            }
                            capabilities = Some(map.next_value()?);
                        }
                    }
                }

                let capabilities =
                    capabilities.ok_or_else(|| de::Error::missing_field("capabilities"))?;
                Ok(SMIMECapabilities { capabilities })
            }
        }

        deserializer.deserialize_struct(
            "SMIMECapabilities",
            &["capabilities"],
            SMIMECapabilitiesVisitor,
        )
    }
}

impl SMIMECapabilities {
    /// Create a new SMIMECapabilities with a list of capabilities
    pub fn new(capabilities: Vec<SMIMECapability>) -> Self {
        Self { capabilities }
    }

    /// Get the list of capabilities
    pub fn capabilities(&self) -> &[SMIMECapability] {
        &self.capabilities
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.capabilities.is_empty()
    }

    /// Get the number of capabilities
    pub fn len(&self) -> usize {
        self.capabilities.len()
    }
}

impl Attribute for SMIMECapabilities {
    /// OID for smimeCapabilities: 1.2.840.113549.1.9.15
    const OID: &'static str = "1.2.840.113549.1.9.15";

    fn parse(values: &OctetString) -> Result<Self> {
        // Parse the SET OF SMIMECapabilities
        let asn1_obj = ASN1Object::try_from(values).map_err(Error::from)?;

        let elements = asn1_obj.elements();
        let first_element = elements
            .first()
            .ok_or(Error::AttributeEmptyAsn1Object("smimeCapabilities"))?;

        // The first element should be a SET
        let Element::Set(set) = first_element else {
            return Err(Error::AttributeExpectedElementType {
                attr: "smimeCapabilities",
                expected: "SET",
            });
        };

        // Get the SEQUENCE OF SMIMECapability from the SET
        let first_set_element = set
            .first()
            .ok_or(Error::AttributeEmptyValuesSet("smimeCapabilities"))?;

        let Element::Sequence(seq) = first_set_element else {
            return Err(Error::AttributeExpectedElementType {
                attr: "smimeCapabilities",
                expected: "SEQUENCE",
            });
        };

        // Parse each SMIMECapability using iterator
        let capabilities = seq
            .iter()
            .map(|elem| {
                let Element::Sequence(cap_seq) = elem else {
                    return Err(Error::SmimeCapabilitiesExpectedSequence);
                };

                // First element is the capability ID (OID), optional second is parameters
                let (capability_id, parameters) = match cap_seq.as_slice() {
                    [Element::ObjectIdentifier(oid)] => (oid.clone(), None),
                    [Element::ObjectIdentifier(oid), params] => (oid.clone(), Some(params.clone())),
                    [_, ..] => {
                        return Err(Error::SmimeCapabilitiesExpectedOid);
                    }
                    [] => {
                        return Err(Error::SmimeCapabilitiesInvalidElementCount(0));
                    }
                };

                Ok(SMIMECapability {
                    capability_id,
                    parameters,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self { capabilities })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asn1::Element;
    use der::Der;
    use rstest::rstest;
    use std::str::FromStr;
    use tsumiki::encoder::Encoder;

    #[test]
    fn test_smime_capabilities_oid() {
        assert_eq!(SMIMECapabilities::OID, "1.2.840.113549.1.9.15");
    }

    #[rstest]
    #[case("2.16.840.1.101.3.4.1.2")] // AES128-CBC
    #[case("2.16.840.1.101.3.4.1.42")] // AES256-CBC
    #[case("1.2.840.113549.3.7")] // 3DES
    fn test_smime_capability_new(#[case] oid_str: &str) {
        let oid = ObjectIdentifier::from_str(oid_str).unwrap();
        let cap = SMIMECapability::new(oid.clone());
        assert_eq!(cap.capability_id(), &oid);
        assert!(cap.parameters().is_none());
    }

    #[rstest]
    #[case("1.2.840.113549.1.1.1", Element::Null)] // RSA with NULL
    #[case("1.2.840.113549.3.2", Element::Integer(asn1::Integer::from(vec![128])))] // RC2-128
    fn test_smime_capability_new_with_params(#[case] oid_str: &str, #[case] params: Element) {
        let oid = ObjectIdentifier::from_str(oid_str).unwrap();
        let cap = SMIMECapability::new_with_params(oid.clone(), params.clone());
        assert_eq!(cap.capability_id(), &oid);
        assert_eq!(cap.parameters(), Some(&params));
    }

    #[rstest]
    #[case(vec![], 0, true)]
    #[case(vec![SMIMECapability::new(ObjectIdentifier::from_str("2.16.840.1.101.3.4.1.2").unwrap())], 1, false)]
    #[case(vec![
        SMIMECapability::new(ObjectIdentifier::from_str("2.16.840.1.101.3.4.1.2").unwrap()),
        SMIMECapability::new(ObjectIdentifier::from_str("2.16.840.1.101.3.4.1.42").unwrap()),
    ], 2, false)]
    fn test_smime_capabilities_new(
        #[case] caps: Vec<SMIMECapability>,
        #[case] expected_len: usize,
        #[case] expected_empty: bool,
    ) {
        let smime_caps = SMIMECapabilities::new(caps);
        assert_eq!(smime_caps.len(), expected_len);
        assert_eq!(smime_caps.is_empty(), expected_empty);
    }

    #[rstest]
    #[case("2.16.840.1.101.3.4.1.2", false)] // AES128-CBC, single capability
    #[case("2.16.840.1.101.3.4.1.42", false)] // AES256-CBC, single capability
    fn test_smime_capabilities_parse_single(#[case] oid_str: &str, #[case] has_params: bool) {
        // Create a SET containing a SEQUENCE of SMIMECapability
        let oid = ObjectIdentifier::from_str(oid_str).unwrap();

        let cap_elements: Vec<_> = std::iter::once(Element::ObjectIdentifier(oid.clone()))
            .chain(has_params.then_some(Element::Null))
            .collect();

        let capability = Element::Sequence(cap_elements);
        let capabilities_seq = Element::Sequence(vec![capability]);
        let set = Element::Set(vec![capabilities_seq]);
        let asn1_obj = ASN1Object::new(vec![set]);

        let der: Der = asn1_obj.encode().expect("Failed to encode");
        let der_bytes = der.encode().expect("Failed to encode to bytes");
        let values = OctetString::from(der_bytes);

        let parsed = SMIMECapabilities::parse(&values).expect("Failed to parse");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed.capabilities()[0].capability_id(), &oid);
        assert_eq!(parsed.capabilities()[0].parameters().is_some(), has_params);
    }

    #[rstest]
    #[case(vec!["2.16.840.1.101.3.4.1.2", "2.16.840.1.101.3.4.1.42"], vec![false, false])]
    #[case(vec!["2.16.840.1.101.3.4.1.2", "2.16.840.1.101.3.4.1.42", "1.2.840.113549.3.7"], vec![false, false, true])]
    fn test_smime_capabilities_parse_multiple(
        #[case] oid_strs: Vec<&str>,
        #[case] has_params: Vec<bool>,
    ) {
        // Create capabilities with multiple algorithms
        let capabilities: Vec<Element> = oid_strs
            .iter()
            .zip(has_params.iter())
            .map(|(oid_str, &has_param)| {
                let oid = ObjectIdentifier::from_str(oid_str).unwrap();
                let elements: Vec<_> = std::iter::once(Element::ObjectIdentifier(oid))
                    .chain(has_param.then_some(Element::Null))
                    .collect();
                Element::Sequence(elements)
            })
            .collect();

        let capabilities_seq = Element::Sequence(capabilities);
        let set = Element::Set(vec![capabilities_seq]);
        let asn1_obj = ASN1Object::new(vec![set]);

        let der: Der = asn1_obj.encode().expect("Failed to encode");
        let der_bytes = der.encode().expect("Failed to encode to bytes");
        let values = OctetString::from(der_bytes);

        let parsed = SMIMECapabilities::parse(&values).expect("Failed to parse");
        assert_eq!(parsed.len(), oid_strs.len());
        for (i, oid_str) in oid_strs.iter().enumerate() {
            let expected_oid = ObjectIdentifier::from_str(oid_str).unwrap();
            assert_eq!(parsed.capabilities()[i].capability_id(), &expected_oid);
            assert_eq!(
                parsed.capabilities()[i].parameters().is_some(),
                has_params[i]
            );
        }
    }

    #[rstest]
    #[case(vec![], "AttributeEmptyValuesSet")]
    #[case(vec![Element::Null], "AttributeExpectedElementType")]
    #[case(vec![Element::Sequence(vec![Element::Null])], "SmimeCapabilitiesExpectedSequence")]
    #[case(vec![Element::Sequence(vec![Element::Sequence(vec![])])], "SmimeCapabilitiesInvalidElementCount")]
    #[case(vec![Element::Sequence(vec![Element::Sequence(vec![Element::Null])])], "SmimeCapabilitiesExpectedOid")]
    fn test_smime_capabilities_parse_errors(
        #[case] set_elements: Vec<Element>,
        #[case] error_msg: &str,
    ) {
        let set = Element::Set(set_elements);
        let asn1_obj = ASN1Object::new(vec![set]);
        let der: Der = asn1_obj.encode().expect("Failed to encode");
        let der_bytes = der.encode().expect("Failed to encode to bytes");
        let values = OctetString::from(der_bytes);

        let result = SMIMECapabilities::parse(&values);
        assert!(result.is_err());
        let err_str = format!("{:?}", result.unwrap_err());
        assert!(err_str.contains(error_msg));
    }

    #[rstest]
    #[case(vec!["2.16.840.1.101.3.4.1.2"], 1)]
    #[case(vec!["2.16.840.1.101.3.4.1.2", "2.16.840.1.101.3.4.1.42"], 2)]
    #[case(vec!["2.16.840.1.101.3.4.1.2", "2.16.840.1.101.3.4.1.42", "1.2.840.113549.3.7"], 3)]
    fn test_smime_capabilities_accessors(#[case] oid_strs: Vec<&str>, #[case] expected_len: usize) {
        let capabilities: Vec<SMIMECapability> = oid_strs
            .iter()
            .map(|oid_str| {
                let oid = ObjectIdentifier::from_str(oid_str).unwrap();
                SMIMECapability::new(oid)
            })
            .collect();

        let caps = SMIMECapabilities::new(capabilities);

        assert_eq!(caps.len(), expected_len);
        assert_eq!(caps.is_empty(), expected_len == 0);
        assert_eq!(caps.capabilities().len(), expected_len);

        for (i, oid_str) in oid_strs.iter().enumerate() {
            assert_eq!(caps.capabilities()[i].capability_id().to_string(), *oid_str);
        }
    }

    #[test]
    fn test_smime_capabilities_serialize() {
        let oid1 = ObjectIdentifier::from_str("2.16.840.1.101.3.4.1.2").unwrap();
        let oid2 = ObjectIdentifier::from_str("1.2.840.113549.3.7").unwrap();
        let cap1 = SMIMECapability::new(oid1);
        let cap2 = SMIMECapability::new_with_params(oid2, Element::Null);

        let caps = SMIMECapabilities::new(vec![cap1, cap2]);

        // Test JSON serialization
        let json = serde_json::to_string_pretty(&caps).unwrap();
        assert!(json.contains("2.16.840.1.101.3.4.1.2"));
        assert!(json.contains("1.2.840.113549.3.7"));
        assert!(json.contains("capabilityId"));

        // Test deserialization
        let deserialized: SMIMECapabilities = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.capabilities().len(), 2);
    }

    #[test]
    fn test_smime_capability_serialize() {
        let oid = ObjectIdentifier::from_str("2.16.840.1.101.3.4.1.42").unwrap();
        let cap = SMIMECapability::new(oid.clone());

        let json = serde_json::to_string(&cap).unwrap();
        assert!(json.contains("2.16.840.1.101.3.4.1.42"));
        assert!(json.contains("capabilityId"));

        let deserialized: SMIMECapability = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.capability_id().to_string(), oid.to_string());
    }
}
