use std::fmt;
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};
use tsumiki_asn1::{ASN1Object, Element, ObjectIdentifier, OctetString};
use tsumiki_pkix_types::OidName;

use super::error;
use crate::error::Error;
use crate::extensions::Extension;

/*
RFC 5280 Section 4.2.1.8: Subject Directory Attributes
https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.8

id-ce-subjectDirectoryAttributes OBJECT IDENTIFIER ::= { id-ce 9 }

SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF AttributeSet{{SupportedAttributes}}

AttributeSet ::= SEQUENCE {
    type      AttributeType,
    values    SET OF AttributeValue
}

`AttributeSet` is named `SubjectDirectoryAttribute` here to avoid name collision
with a potential future `tsumiki_pkix_types::Attribute` lifted from PKCS#9.
*/

/// A single X.509 Subject Directory Attribute (RFC 5280 §4.2.1.8 / Appendix A `Attribute`).
///
/// ASN.1 (RFC 5280 Appendix A.1, PKIX1Explicit88):
/// ```text
/// Attribute ::= SEQUENCE {
///     type    AttributeType,
///     values  SET OF AttributeValue
///         -- at least one value is required
/// }
/// AttributeType  ::= OBJECT IDENTIFIER
/// AttributeValue ::= ANY -- DEFINED BY AttributeType
/// ```
///
/// `attribute_type` corresponds to the ASN.1 `type` field (renamed because
/// `type` is a Rust reserved keyword). `values` is stored as raw [`Element`]
/// since RFC 5280 does not constrain the value type beyond `ANY DEFINED BY type`.
/// Helper methods to project well-known OIDs (e.g. RFC 3739 `dateOfBirth`) onto
/// typed values are intentionally out of scope here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectDirectoryAttribute {
    pub attribute_type: ObjectIdentifier,
    pub values: Vec<Element>,
}

impl DecodableFrom<Element> for SubjectDirectoryAttribute {}

impl Decoder<Element, SubjectDirectoryAttribute> for Element {
    type Error = Error;

    fn decode(&self) -> Result<SubjectDirectoryAttribute, Self::Error> {
        match self {
            Element::Sequence(elements) => match elements.as_slice() {
                [Element::ObjectIdentifier(oid), Element::Set(values)] => {
                    if values.is_empty() {
                        return Err(error::Error::SubjectDirectoryAttributeEmptyValues.into());
                    }
                    Ok(SubjectDirectoryAttribute {
                        attribute_type: oid.clone(),
                        values: values.clone(),
                    })
                }
                [Element::ObjectIdentifier(_), _] => {
                    Err(error::Error::SubjectDirectoryAttributeExpectedSet.into())
                }
                [_, _] => Err(error::Error::SubjectDirectoryAttributeExpectedOid.into()),
                _ => Err(error::Error::SubjectDirectoryAttributeInvalidStructure.into()),
            },
            _ => {
                Err(error::Error::ExpectedSequence(error::Kind::SubjectDirectoryAttributes).into())
            }
        }
    }
}

impl EncodableTo<SubjectDirectoryAttribute> for Element {}

impl Encoder<SubjectDirectoryAttribute, Element> for SubjectDirectoryAttribute {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        if self.values.is_empty() {
            return Err(error::Error::SubjectDirectoryAttributeEmptyValues.into());
        }

        // DER requires SET OF elements to be sorted by their encoded byte
        // representation (X.690 §11.6). The asn1 crate's `Element::Set` encoder
        // does not currently sort, so we sort here before constructing the SET.
        let sorted_values = sort_set_elements(&self.values)?;

        Ok(Element::Sequence(vec![
            Element::ObjectIdentifier(self.attribute_type.clone()),
            Element::Set(sorted_values),
        ]))
    }
}

/// Sort SET OF elements by their DER-encoded byte representation per X.690 §11.6.
fn sort_set_elements(values: &[Element]) -> Result<Vec<Element>, Error> {
    let mut encoded_pairs: Vec<(Vec<u8>, Element)> = values
        .iter()
        .map(|elem| {
            let tlv: tsumiki_der::Tlv = elem.encode().map_err(Error::InvalidASN1)?;
            let bytes: Vec<u8> = tlv.encode()?;
            Ok((bytes, elem.clone()))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    encoded_pairs.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(encoded_pairs.into_iter().map(|(_, elem)| elem).collect())
}

/// Subject Directory Attributes extension ([RFC 5280 §4.2.1.8](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.8)).
///
/// MUST be marked non-critical per RFC 5280.
///
/// Serialization (serde) is not currently implemented because `AttributeValue`
/// is held as a raw [`Element`], which does not implement `Serialize`. Until
/// that is addressed, this extension is omitted from JSON / YAML output of
/// `ParsedExtensions` (see the project's "今後の課題" — Element serde support).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectDirectoryAttributes {
    pub attributes: Vec<SubjectDirectoryAttribute>,
}

impl SubjectDirectoryAttributes {
    /// Date of Birth attribute (RFC 3739 §5)
    /// OID: 1.3.6.1.5.5.7.9.1
    pub const DATE_OF_BIRTH: &'static str = "1.3.6.1.5.5.7.9.1";

    /// Place of Birth attribute (RFC 3739 §5)
    /// OID: 1.3.6.1.5.5.7.9.2
    pub const PLACE_OF_BIRTH: &'static str = "1.3.6.1.5.5.7.9.2";

    /// Gender attribute (RFC 3739 §5)
    /// OID: 1.3.6.1.5.5.7.9.3
    pub const GENDER: &'static str = "1.3.6.1.5.5.7.9.3";

    /// Country of Citizenship attribute (RFC 3739 §5)
    /// OID: 1.3.6.1.5.5.7.9.4
    pub const COUNTRY_OF_CITIZENSHIP: &'static str = "1.3.6.1.5.5.7.9.4";

    /// Country of Residence attribute (RFC 3739 §5)
    /// OID: 1.3.6.1.5.5.7.9.5
    pub const COUNTRY_OF_RESIDENCE: &'static str = "1.3.6.1.5.5.7.9.5";
}

impl DecodableFrom<OctetString> for SubjectDirectoryAttributes {}

impl Decoder<OctetString, SubjectDirectoryAttributes> for OctetString {
    type Error = Error;

    fn decode(&self) -> Result<SubjectDirectoryAttributes, Self::Error> {
        let asn1_obj = ASN1Object::try_from(self).map_err(Error::InvalidASN1)?;

        match asn1_obj.elements() {
            [elem, ..] => elem.decode(),
            [] => Err(error::Error::SubjectDirectoryAttributesEmpty.into()),
        }
    }
}

impl DecodableFrom<Element> for SubjectDirectoryAttributes {}

impl Decoder<Element, SubjectDirectoryAttributes> for Element {
    type Error = Error;

    fn decode(&self) -> Result<SubjectDirectoryAttributes, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                if elements.is_empty() {
                    return Err(error::Error::SubjectDirectoryAttributesEmpty.into());
                }

                let attributes = elements
                    .iter()
                    .map(|elem| elem.decode())
                    .collect::<Result<Vec<SubjectDirectoryAttribute>, _>>()?;

                Ok(SubjectDirectoryAttributes { attributes })
            }
            _ => {
                Err(error::Error::ExpectedSequence(error::Kind::SubjectDirectoryAttributes).into())
            }
        }
    }
}

impl EncodableTo<SubjectDirectoryAttributes> for Element {}

impl Encoder<SubjectDirectoryAttributes, Element> for SubjectDirectoryAttributes {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        if self.attributes.is_empty() {
            return Err(error::Error::SubjectDirectoryAttributesEmpty.into());
        }

        let attr_elements = self
            .attributes
            .iter()
            .map(|attr| attr.encode())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Element::Sequence(attr_elements))
    }
}

impl Extension for SubjectDirectoryAttributes {
    /// OID for SubjectDirectoryAttributes extension (2.5.29.9)
    const OID: &'static str = "2.5.29.9";

    fn parse(value: &OctetString) -> Result<Self, Error> {
        value.decode()
    }
}

impl OidName for SubjectDirectoryAttributes {
    fn oid_name(&self) -> Option<&'static str> {
        Some("subjectDirectoryAttributes")
    }
}

impl fmt::Display for SubjectDirectoryAttributes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ext_name = self.oid_name().unwrap_or("subjectDirectoryAttributes");
        writeln!(f, "            X509v3 {}:", ext_name)?;
        for attr in &self.attributes {
            let attr_name = match attr.attribute_type.to_string().as_str() {
                Self::DATE_OF_BIRTH => "Date of Birth",
                Self::PLACE_OF_BIRTH => "Place of Birth",
                Self::GENDER => "Gender",
                Self::COUNTRY_OF_CITIZENSHIP => "Country of Citizenship",
                Self::COUNTRY_OF_RESIDENCE => "Country of Residence",
                _ => "Unknown",
            };
            let values_str = attr
                .values
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            writeln!(f, "                {} - {}", attr_name, values_str)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::RawExtension;
    use chrono::NaiveDate;
    use rstest::rstest;
    use std::str::FromStr;

    // RFC 3739 §5 OIDs used in tests
    const DATE_OF_BIRTH: &str = "1.3.6.1.5.5.7.9.1";
    const COUNTRY_OF_CITIZENSHIP: &str = "1.3.6.1.5.5.7.9.4";

    fn date_of_birth_element() -> Element {
        Element::GeneralizedTime(
            NaiveDate::from_ymd_opt(1990, 1, 1)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap(),
        )
    }

    fn country_element(country: &str) -> Element {
        Element::PrintableString(country.to_string())
    }

    #[rstest]
    #[case(
        // Single attribute: dateOfBirth (RFC 3739)
        Element::Sequence(vec![
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str(DATE_OF_BIRTH).unwrap()),
                Element::Set(vec![date_of_birth_element()]),
            ]),
        ]),
        vec![SubjectDirectoryAttribute {
            attribute_type: ObjectIdentifier::from_str(DATE_OF_BIRTH).unwrap(),
            values: vec![date_of_birth_element()],
        }]
    )]
    #[case(
        // Single attribute: countryOfCitizenship (RFC 3739)
        Element::Sequence(vec![
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str(COUNTRY_OF_CITIZENSHIP).unwrap()),
                Element::Set(vec![country_element("JP")]),
            ]),
        ]),
        vec![SubjectDirectoryAttribute {
            attribute_type: ObjectIdentifier::from_str(COUNTRY_OF_CITIZENSHIP).unwrap(),
            values: vec![country_element("JP")],
        }]
    )]
    #[case(
        // Multiple attributes
        Element::Sequence(vec![
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str(DATE_OF_BIRTH).unwrap()),
                Element::Set(vec![date_of_birth_element()]),
            ]),
            Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str(COUNTRY_OF_CITIZENSHIP).unwrap()),
                Element::Set(vec![country_element("US")]),
            ]),
        ]),
        vec![
            SubjectDirectoryAttribute {
                attribute_type: ObjectIdentifier::from_str(DATE_OF_BIRTH).unwrap(),
                values: vec![date_of_birth_element()],
            },
            SubjectDirectoryAttribute {
                attribute_type: ObjectIdentifier::from_str(COUNTRY_OF_CITIZENSHIP).unwrap(),
                values: vec![country_element("US")],
            },
        ]
    )]
    fn test_subject_directory_attributes_decode_success(
        #[case] input: Element,
        #[case] expected_attrs: Vec<SubjectDirectoryAttribute>,
    ) {
        let result: Result<SubjectDirectoryAttributes, Error> = input.decode();
        let sda = result.expect("decode failed");
        assert_eq!(sda.attributes, expected_attrs);
    }

    #[rstest]
    #[case(Element::Sequence(vec![]))]
    fn test_subject_directory_attributes_decode_empty(#[case] input: Element) {
        let result: Result<SubjectDirectoryAttributes, Error> = input.decode();
        assert!(matches!(
            result,
            Err(Error::ExtensionError(
                error::Error::SubjectDirectoryAttributesEmpty
            ))
        ));
    }

    #[rstest]
    #[case(Element::Sequence(vec![
        Element::Sequence(vec![
            Element::ObjectIdentifier(ObjectIdentifier::from_str(DATE_OF_BIRTH).unwrap()),
            // values is not a SET
            Element::OctetString(OctetString::from(vec![0x01])),
        ]),
    ]))]
    fn test_subject_directory_attributes_decode_values_not_set(#[case] input: Element) {
        let result: Result<SubjectDirectoryAttributes, Error> = input.decode();
        assert!(matches!(
            result,
            Err(Error::ExtensionError(
                error::Error::SubjectDirectoryAttributeExpectedSet
            ))
        ));
    }

    #[rstest]
    #[case(Element::Sequence(vec![
        Element::Sequence(vec![
            // attribute_type is not OID
            Element::OctetString(OctetString::from(vec![0x01])),
            Element::Set(vec![country_element("JP")]),
        ]),
    ]))]
    fn test_subject_directory_attributes_decode_type_not_oid(#[case] input: Element) {
        let result: Result<SubjectDirectoryAttributes, Error> = input.decode();
        assert!(matches!(
            result,
            Err(Error::ExtensionError(
                error::Error::SubjectDirectoryAttributeExpectedOid
            ))
        ));
    }

    #[rstest]
    #[case(Element::Sequence(vec![
        Element::Sequence(vec![
            Element::ObjectIdentifier(ObjectIdentifier::from_str(COUNTRY_OF_CITIZENSHIP).unwrap()),
            // empty SET
            Element::Set(vec![]),
        ]),
    ]))]
    fn test_subject_directory_attributes_decode_empty_values(#[case] input: Element) {
        let result: Result<SubjectDirectoryAttributes, Error> = input.decode();
        assert!(matches!(
            result,
            Err(Error::ExtensionError(
                error::Error::SubjectDirectoryAttributeEmptyValues
            ))
        ));
    }

    #[rstest]
    #[case(SubjectDirectoryAttributes {
        attributes: vec![
            SubjectDirectoryAttribute {
                attribute_type: ObjectIdentifier::from_str(COUNTRY_OF_CITIZENSHIP).unwrap(),
                values: vec![country_element("JP")],
            },
        ],
    })]
    #[case(SubjectDirectoryAttributes {
        attributes: vec![
            SubjectDirectoryAttribute {
                attribute_type: ObjectIdentifier::from_str(DATE_OF_BIRTH).unwrap(),
                values: vec![date_of_birth_element()],
            },
            SubjectDirectoryAttribute {
                attribute_type: ObjectIdentifier::from_str(COUNTRY_OF_CITIZENSHIP).unwrap(),
                values: vec![country_element("US")],
            },
        ],
    })]
    fn test_subject_directory_attributes_encode_decode(
        #[case] original: SubjectDirectoryAttributes,
    ) {
        let encoded = original.encode().expect("encode failed");
        let decoded: SubjectDirectoryAttributes = encoded.decode().expect("decode failed");
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_subject_directory_attributes_parse_from_extension() {
        // Build a SubjectDirectoryAttributes value, encode it to DER, then parse
        // it back via the Extension trait (the same path Certificate parsing uses).
        let original = SubjectDirectoryAttributes {
            attributes: vec![SubjectDirectoryAttribute {
                attribute_type: ObjectIdentifier::from_str(COUNTRY_OF_CITIZENSHIP).unwrap(),
                values: vec![country_element("JP")],
            }],
        };
        let encoded_elem = original.encode().expect("encode failed");
        let tlv: tsumiki_der::Tlv = encoded_elem.encode().expect("tlv encode failed");
        let der_bytes: Vec<u8> = tlv.encode().expect("der encode failed");

        let extension = RawExtension::new(
            ObjectIdentifier::from_str(SubjectDirectoryAttributes::OID).unwrap(),
            false,
            OctetString::from(der_bytes),
        );

        let parsed = extension
            .parse::<SubjectDirectoryAttributes>()
            .expect("parse failed");
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_set_of_elements_sorted_on_encode() {
        // Two PrintableString values intentionally provided out of DER sort order.
        // The encoder should sort them by encoded bytes (X.690 §11.6).
        let unsorted = vec![country_element("JP"), country_element("CA")];
        let sorted = sort_set_elements(&unsorted).expect("sort failed");

        // PrintableString tag is 0x13; "CA" < "JP" lexicographically.
        // After sorting we expect ["CA", "JP"].
        assert_eq!(sorted, vec![country_element("CA"), country_element("JP")]);
    }
}
