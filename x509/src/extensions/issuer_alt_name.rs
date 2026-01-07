use asn1::{ASN1Object, Element, OctetString};
use serde::{Deserialize, Serialize};
use tsumiki::decoder::{DecodableFrom, Decoder};

use crate::error::Error;
use crate::extensions::StandardExtension;
use crate::extensions::general_name::GeneralName;

/*
RFC 5280 Section 4.2.1.7

IssuerAltName ::= GeneralNames

GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName

The issuer alternative name extension allows additional identities to be bound
to the issuer of the certificate. Defined name forms include Internet email addresses,
DNS names, IP addresses, and URIs. Multiple instances of a name form may appear.

This extension MUST be non-critical.
*/

/// IssuerAltName represents the Issuer Alternative Name extension
/// OID: 2.5.29.18
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerAltName {
    pub names: Vec<GeneralName>,
}

impl DecodableFrom<OctetString> for IssuerAltName {}

impl Decoder<OctetString, IssuerAltName> for OctetString {
    type Error = Error;

    fn decode(&self) -> Result<IssuerAltName, Self::Error> {
        // IssuerAltName -> ASN1Object -> Element (Sequence) -> IssuerAltName
        let asn1_obj = ASN1Object::try_from(self).map_err(Error::InvalidASN1)?;
        let elements = asn1_obj.elements();

        if elements.is_empty() {
            return Err(Error::InvalidIssuerAltName("empty sequence".to_string()));
        }

        // The first element should be a Sequence (GeneralNames)
        elements[0].decode()
    }
}

impl DecodableFrom<Element> for IssuerAltName {}

impl Decoder<Element, IssuerAltName> for Element {
    type Error = Error;

    fn decode(&self) -> Result<IssuerAltName, Self::Error> {
        match self {
            Element::Sequence(elements) => {
                if elements.is_empty() {
                    return Err(Error::InvalidIssuerAltName(
                        "empty sequence - at least one GeneralName required".to_string(),
                    ));
                }

                let mut names = Vec::new();
                for elem in elements {
                    // Each element should be a context-specific tagged GeneralName
                    let general_name: GeneralName = elem.decode()?;
                    names.push(general_name);
                }

                Ok(IssuerAltName { names })
            }
            _ => Err(Error::InvalidIssuerAltName("expected Sequence".to_string())),
        }
    }
}

impl StandardExtension for IssuerAltName {
    const OID: &'static str = "2.5.29.18";

    fn parse(value: &OctetString) -> Result<Self, Error> {
        value.decode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asn1::{Element, OctetString};
    use rstest::rstest;
    use std::net::IpAddr;

    #[rstest(
        input,
        expected,
        // Test case: Single dNSName
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    constructed: false,
            slot: 2,
                    element: Box::new(Element::OctetString(OctetString::from(b"ca.example.com".to_vec()))),
                },
            ]),
            IssuerAltName {
                names: vec![GeneralName::DnsName("ca.example.com".to_string())],
            }
        ),
        // Test case: rfc822Name (email)
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    constructed: false,
            slot: 1,
                    element: Box::new(Element::OctetString(OctetString::from(b"ca@example.com".to_vec()))),
                },
            ]),
            IssuerAltName {
                names: vec![GeneralName::Rfc822Name("ca@example.com".to_string())],
            }
        ),
        // Test case: IPv4 address
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    constructed: false,
            slot: 7,
                    element: Box::new(Element::OctetString(OctetString::from(vec![192, 0, 2, 1]))),
                },
            ]),
            IssuerAltName {
                names: vec![GeneralName::IpAddress(
                    crate::extensions::IpAddressOrRange::Address(IpAddr::from([192, 0, 2, 1]))
                )],
            }
        ),
        // Test case: URI
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    constructed: false,
            slot: 6,
                    element: Box::new(Element::OctetString(OctetString::from(b"https://ca.example.com".to_vec()))),
                },
            ]),
            IssuerAltName {
                names: vec![GeneralName::Uri("https://ca.example.com".to_string())],
            }
        ),
        // Test case: Multiple names (DNS, email, URI)
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    constructed: false,
            slot: 2,
                    element: Box::new(Element::OctetString(OctetString::from(b"ca.example.com".to_vec()))),
                },
                Element::ContextSpecific {
                    constructed: false,
            slot: 1,
                    element: Box::new(Element::OctetString(OctetString::from(b"ca@example.com".to_vec()))),
                },
                Element::ContextSpecific {
                    constructed: false,
            slot: 6,
                    element: Box::new(Element::OctetString(OctetString::from(b"https://ca.example.com".to_vec()))),
                },
            ]),
            IssuerAltName {
                names: vec![
                    GeneralName::DnsName("ca.example.com".to_string()),
                    GeneralName::Rfc822Name("ca@example.com".to_string()),
                    GeneralName::Uri("https://ca.example.com".to_string()),
                ],
            }
        ),
    )]
    fn test_issuer_alt_name_decode_success(input: Element, expected: IssuerAltName) {
        let result: Result<IssuerAltName, Error> = input.decode();
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
            "empty sequence"
        ),
        // Test case: Not a Sequence
        case(
            Element::Boolean(true),
            "expected Sequence"
        ),
        // Test case: Invalid IP address length (3 bytes)
        case(
            Element::Sequence(vec![
                Element::ContextSpecific {
                    constructed: false,
            slot: 7,
                    element: Box::new(Element::OctetString(OctetString::from(vec![192, 0, 2]))),
                },
            ]),
            "iPAddress must be 4, 8, 16, or 32 bytes"
        ),
        // Test case: Non-context-specific element
        case(
            Element::Sequence(vec![
                Element::OctetString(OctetString::from(b"example.com".to_vec())),
            ]),
            "GeneralName must be context-specific element"
        ),
    )]
    fn test_issuer_alt_name_decode_failure(input: Element, expected_error_msg: &str) {
        let result: Result<IssuerAltName, Error> = input.decode();
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
}
