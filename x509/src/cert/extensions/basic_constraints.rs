use serde::{Deserialize, Serialize};
use std::fmt;
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};
use tsumiki_asn1::{ASN1Object, Element, Integer, OctetString};
use tsumiki_pkix_types::OidName;

use super::error;
use crate::error::Error;
use crate::extensions::Extension;

/*
RFC 5280 Section 4.2.1.9
BasicConstraints ::= SEQUENCE {
    cA                      BOOLEAN DEFAULT FALSE,
    pathLenConstraint       INTEGER (0..MAX) OPTIONAL
}
*/

/// Basic Constraints extension ([RFC 5280 Section 4.2.1.9](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9)).
///
/// Identifies whether the subject of the certificate is a CA and the maximum
/// depth of valid certification paths that include this certificate.
///
/// # Fields
/// - `ca`: Whether the certified public key may be used to verify certificate signatures
/// - `path_len_constraint`: Maximum number of non-self-issued intermediate certificates
///   that may follow this certificate in a valid certification path
///
/// # Usage
/// This extension is critical for PKI operation and should always be marked as critical
/// in CA certificates. For end-entity certificates, `ca` should be FALSE.
///
/// # Example
/// ```no_run
/// use std::str::FromStr;
/// use tsumiki_x509::Certificate;
/// use tsumiki_x509::extensions::BasicConstraints;
///
/// let cert = Certificate::from_str("-----BEGIN CERTIFICATE-----...").unwrap();
/// if let Some(bc) = cert.extension::<BasicConstraints>().unwrap() {
///     if bc.ca {
///         println!("This is a CA certificate");
///         if let Some(pathlen) = bc.path_len_constraint {
///             println!("Maximum path length: {}", pathlen);
///         }
///     }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasicConstraints {
    /// Whether this certificate represents a CA
    pub ca: bool,
    /// Optional maximum path length for certificate chains
    pub path_len_constraint: Option<u32>,
}

impl Extension for BasicConstraints {
    /// OID for BasicConstraints extension (2.5.29.19)
    const OID: &'static str = "2.5.29.19";

    fn parse(value: &OctetString) -> Result<Self, Error> {
        // OctetString -> ASN1Object -> Element (Sequence) -> BasicConstraints
        let asn1_obj = ASN1Object::try_from(value).map_err(Error::InvalidASN1)?;

        // The first element should be a Sequence
        match asn1_obj.elements() {
            [elem @ Element::Sequence(_), ..] => elem.decode(),
            [_, ..] => Err(error::Error::ExpectedSequence(error::Kind::BasicConstraints).into()),
            [] => Err(error::Error::EmptySequence(error::Kind::BasicConstraints).into()),
        }
    }
}

impl DecodableFrom<Element> for BasicConstraints {}

impl Decoder<Element, BasicConstraints> for Element {
    type Error = Error;

    fn decode(&self) -> Result<BasicConstraints, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                let (ca, path_len_constraint) =
                    elements
                        .iter()
                        .try_fold((false, None), |(ca, path_len), elem| match elem {
                            Element::Boolean(b) => Ok((*b, path_len)),
                            Element::Integer(i) => {
                                let value = i
                                    .to_u32()
                                    .ok_or(error::Error::PathLenConstraintOutOfRange)?;
                                Ok((ca, Some(value)))
                            }
                            _ => Err(error::Error::UnexpectedElementType(
                                error::Kind::BasicConstraints,
                            )),
                        })?;

                Ok(BasicConstraints {
                    ca,
                    path_len_constraint,
                })
            }
            _ => Err(error::Error::ExpectedSequence(error::Kind::BasicConstraints).into()),
        }
    }
}

impl OidName for BasicConstraints {
    fn oid_name(&self) -> Option<&'static str> {
        Some("basicConstraints")
    }
}

impl fmt::Display for BasicConstraints {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ext_name = self.oid_name().unwrap_or("basicConstraints");
        writeln!(f, "            X509v3 {}: critical", ext_name)?;
        if self.ca {
            write!(f, "                CA:TRUE")?;
            if let Some(pathlen) = self.path_len_constraint {
                writeln!(f, ", pathlen:{}", pathlen)
            } else {
                writeln!(f)
            }
        } else {
            writeln!(f, "                CA:FALSE")
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
                Element::Integer(tsumiki_asn1::Integer::from(vec![0x00])),
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
                Element::Integer(tsumiki_asn1::Integer::from(vec![0x01])),
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
                Element::Integer(tsumiki_asn1::Integer::from(vec![0x0a])),
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
            "expected SEQUENCE"
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
