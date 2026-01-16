use asn1::{ASN1Object, Element, Integer, OctetString};
use serde::{Deserialize, Serialize};
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};

use crate::error::Error;
use crate::extensions::Extension;

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

impl Extension for BasicConstraints {
    /// OID for BasicConstraints extension (2.5.29.19)
    const OID: &'static str = "2.5.29.19";

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
            Err(Error::InvalidBasicConstraints(
                "expected Sequence".to_string(),
            ))
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

impl EncodableTo<BasicConstraints> for Element {}

impl Encoder<BasicConstraints, Element> for BasicConstraints {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        let ca = self.ca.then_some(Element::Boolean(true));

        let path_len = self.path_len_constraint.map(|len| {
            let bytes = len.to_be_bytes();
            let start = bytes
                .iter()
                .position(|&b| b != 0)
                .unwrap_or(bytes.len() - 1);
            let slice = bytes.get(start..).unwrap_or(&bytes);
            Element::Integer(Integer::from(slice))
        });

        let elements = ca.into_iter().chain(path_len).collect();

        Ok(Element::Sequence(elements))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

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
        let result: Result<BasicConstraints, _> = input.decode();
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
    #[case(BasicConstraints { ca: false, path_len_constraint: None })]
    #[case(BasicConstraints { ca: true, path_len_constraint: None })]
    #[case(BasicConstraints { ca: true, path_len_constraint: Some(0) })]
    #[case(BasicConstraints { ca: true, path_len_constraint: Some(5) })]
    #[case(BasicConstraints { ca: false, path_len_constraint: Some(10) })]
    fn test_basic_constraints_encode_decode(#[case] original: BasicConstraints) {
        let encoded = original.encode();
        assert!(encoded.is_ok(), "Failed to encode: {:?}", encoded);

        let element = encoded.unwrap();
        let decoded: Result<BasicConstraints, _> = element.decode();
        assert!(decoded.is_ok(), "Failed to decode: {:?}", decoded);

        let roundtrip = decoded.unwrap();
        assert_eq!(original, roundtrip);
    }
}
