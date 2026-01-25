use std::fmt;
use std::net::IpAddr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};
use tsumiki_asn1::{Element, ObjectIdentifier, OctetString};

use super::error;
use crate::DirectoryString;
use crate::Name;
use crate::error::Error;

/// Represents an IP address or an IP network range (for NameConstraints)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpAddressOrRange {
    /// Single IP address (4 bytes for IPv4, 16 bytes for IPv6)
    Address(IpAddr),
    /// IP network range (8 bytes for IPv4, 32 bytes for IPv6)
    /// Used in NameConstraints extension
    Network(IpNet),
}

impl IpAddressOrRange {
    /// Check if this represents a network range
    pub fn is_network(&self) -> bool {
        matches!(self, IpAddressOrRange::Network(_))
    }

    /// Check if this represents a single address
    pub fn is_address(&self) -> bool {
        matches!(self, IpAddressOrRange::Address(_))
    }

    /// Get the IP address (for single addresses) or network address (for ranges)
    pub fn addr(&self) -> IpAddr {
        match self {
            IpAddressOrRange::Address(addr) => *addr,
            IpAddressOrRange::Network(net) => net.addr(),
        }
    }
}

impl std::fmt::Display for IpAddressOrRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpAddressOrRange::Address(addr) => write!(f, "{}", addr),
            IpAddressOrRange::Network(net) => write!(f, "{}", net),
        }
    }
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
    /// iPAddress [7] - IP address or network range
    /// - 4 bytes: single IPv4 address
    /// - 8 bytes: IPv4 network (address + mask) for NameConstraints
    /// - 16 bytes: single IPv6 address
    /// - 32 bytes: IPv6 network (address + mask) for NameConstraints
    IpAddress(IpAddressOrRange),
    /// registeredID [8] - Registered OBJECT IDENTIFIER
    RegisteredId(ObjectIdentifier),
}

impl GeneralName {
    /// Parse a GeneralName based on its context-specific tag slot
    pub(crate) fn parse_from_context_specific(
        slot: u8,
        element: &Element,
    ) -> Result<GeneralName, Error> {
        match slot {
            0 => {
                // otherName [0] IMPLICIT OtherName (SEQUENCE)
                match element {
                    Element::Sequence(seq) => {
                        if seq.len() < 2 {
                            return Err(error::Error::OtherNameInvalidElementCount.into());
                        }
                        // First: type-id (OBJECT IDENTIFIER)
                        let type_id = match &seq[0] {
                            Element::ObjectIdentifier(oid) => oid.clone(),
                            _ => {
                                return Err(error::Error::OtherNameExpectedOid.into());
                            }
                        };
                        // Second: [0] EXPLICIT value
                        let value = match &seq[1] {
                            Element::ContextSpecific {
                                constructed: true,
                                slot: 0,
                                element: val,
                                ..
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
                                return Err(error::Error::OtherNameExpectedExplicitTag.into());
                            }
                        };
                        Ok(GeneralName::OtherName(OtherName { type_id, value }))
                    }
                    _ => Err(error::Error::ExpectedSequence(error::Kind::GeneralName).into()),
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
                match element {
                    Element::OctetString(os) => {
                        Ok(GeneralName::X400Address(os.as_bytes().to_vec()))
                    }
                    Element::Sequence(_) => {
                        // May come as Sequence if parsed recursively
                        Ok(GeneralName::X400Address(
                            format!("{:?}", element).into_bytes(),
                        ))
                    }
                    _ => Err(error::Error::UnexpectedElementType(error::Kind::GeneralName).into()),
                }
            }
            4 => {
                // directoryName [4] IMPLICIT Name (SEQUENCE)
                match element {
                    Element::Sequence(_) => {
                        // Decode as Name
                        let name: Name = element.decode()?;
                        Ok(GeneralName::DirectoryName(name))
                    }
                    _ => Err(error::Error::ExpectedSequence(error::Kind::GeneralName).into()),
                }
            }
            5 => {
                // ediPartyName [5] IMPLICIT EDIPartyName (SEQUENCE)
                match element {
                    Element::Sequence(seq) => {
                        let (name_assigner, party_name) = seq.iter().try_fold(
                            (None, None),
                            |(assigner, party), elem| match elem {
                                Element::ContextSpecific {
                                    slot: 0, element, ..
                                } => {
                                    // nameAssigner [0]
                                    let dir_string: DirectoryString =
                                        element.as_ref().decode().map_err(|_| {
                                            error::Error::EdiPartyNameInvalidNameAssigner
                                        })?;
                                    Ok((Some(dir_string.into()), party))
                                }
                                Element::ContextSpecific {
                                    slot: 1, element, ..
                                } => {
                                    // partyName [1]
                                    let dir_string: DirectoryString = element
                                        .as_ref()
                                        .decode()
                                        .map_err(|_| error::Error::EdiPartyNameInvalidPartyName)?;
                                    Ok((assigner, Some(dir_string.into())))
                                }
                                _ => Err(error::Error::UnexpectedElementType(
                                    error::Kind::GeneralName,
                                )),
                            },
                        )?;

                        let party_name =
                            party_name.ok_or(error::Error::EdiPartyNameMissingPartyName)?;
                        Ok(GeneralName::EdiPartyName(EdiPartyName {
                            name_assigner,
                            party_name,
                        }))
                    }
                    _ => Err(error::Error::ExpectedSequence(error::Kind::GeneralName).into()),
                }
            }
            6 => {
                // uniformResourceIdentifier [6] IMPLICIT IA5String
                Self::parse_ia5_string(element).map(GeneralName::Uri)
            }
            7 => {
                // iPAddress [7] IMPLICIT OCTET STRING
                // RFC 5280: For SubjectAltName, this is 4 or 16 bytes
                // For NameConstraints, this is 8 or 32 bytes (address + mask)
                match element {
                    Element::OctetString(os) => {
                        let bytes = os.as_bytes();
                        let ip = match bytes {
                            // IPv4: 4 bytes (single address)
                            [a, b, c, d] => {
                                IpAddressOrRange::Address(IpAddr::from([*a, *b, *c, *d]))
                            }
                            // IPv4 network: 8 bytes (address + mask)
                            [a0, a1, a2, a3, m0, m1, m2, m3] => {
                                let addr = std::net::Ipv4Addr::from([*a0, *a1, *a2, *a3]);
                                let mask = std::net::Ipv4Addr::from([*m0, *m1, *m2, *m3]);

                                // Convert netmask to prefix length
                                let prefix_len =
                                    mask.octets().iter().map(|&b| b.count_ones()).sum::<u32>()
                                        as u8;

                                let net = Ipv4Net::new(addr, prefix_len)
                                    .map_err(|e| error::Error::InvalidIpv4Network(e.to_string()))?;
                                IpAddressOrRange::Network(IpNet::V4(net))
                            }
                            // IPv6: 16 bytes (single address)
                            [
                                b0,
                                b1,
                                b2,
                                b3,
                                b4,
                                b5,
                                b6,
                                b7,
                                b8,
                                b9,
                                b10,
                                b11,
                                b12,
                                b13,
                                b14,
                                b15,
                            ] => {
                                let octets = [
                                    *b0, *b1, *b2, *b3, *b4, *b5, *b6, *b7, *b8, *b9, *b10, *b11,
                                    *b12, *b13, *b14, *b15,
                                ];
                                IpAddressOrRange::Address(IpAddr::from(octets))
                            }
                            // IPv6 network: 32 bytes (address + mask)
                            bytes if bytes.len() == 32 => {
                                let (addr_bytes, mask_bytes) = bytes.split_at(16);
                                let addr_octets: [u8; 16] =
                                    addr_bytes.try_into().map_err(|_| {
                                        error::Error::InvalidIpv6Network(
                                            "invalid IPv6 address".to_string(),
                                        )
                                    })?;
                                let mask_octets: [u8; 16] =
                                    mask_bytes.try_into().map_err(|_| {
                                        error::Error::InvalidIpv6Network(
                                            "invalid IPv6 mask".to_string(),
                                        )
                                    })?;

                                let addr = std::net::Ipv6Addr::from(addr_octets);
                                let mask = std::net::Ipv6Addr::from(mask_octets);

                                // Convert netmask to prefix length
                                let prefix_len =
                                    mask.octets().iter().map(|&b| b.count_ones()).sum::<u32>()
                                        as u8;

                                let net = Ipv6Net::new(addr, prefix_len)
                                    .map_err(|e| error::Error::InvalidIpv6Network(e.to_string()))?;
                                IpAddressOrRange::Network(IpNet::V6(net))
                            }
                            _ => {
                                return Err(
                                    error::Error::InvalidIpAddressLength(bytes.len()).into()
                                );
                            }
                        };
                        Ok(GeneralName::IpAddress(ip))
                    }
                    _ => Err(error::Error::ExpectedOctetString(error::Kind::GeneralName).into()),
                }
            }
            8 => {
                // registeredID [8] IMPLICIT OBJECT IDENTIFIER
                match element {
                    Element::OctetString(os) => {
                        // IMPLICIT OID comes as OctetString, need to parse
                        let oid = ObjectIdentifier::try_from(os.as_bytes())
                            .map_err(|_| error::Error::InvalidOidEncoding)?;
                        Ok(GeneralName::RegisteredId(oid))
                    }
                    Element::ObjectIdentifier(oid) => {
                        // EXPLICIT OID (less common)
                        Ok(GeneralName::RegisteredId(oid.clone()))
                    }
                    _ => Err(error::Error::ExpectedOid(error::Kind::GeneralName).into()),
                }
            }
            _ => Err(error::Error::UnknownGeneralNameTag(slot).into()),
        }
    }

    /// Parse IA5String from IMPLICIT context-specific element
    fn parse_ia5_string(element: &Element) -> Result<String, Error> {
        match element {
            Element::OctetString(os) => {
                // IMPLICIT IA5String comes as OctetString
                String::from_utf8(os.as_bytes().to_vec())
                    .map_err(|_| error::Error::GeneralNameInvalidAscii.into())
            }
            Element::IA5String(s) => Ok(s.clone()),
            _ => Err(error::Error::UnexpectedElementType(error::Kind::GeneralName).into()),
        }
    }
}

impl EncodableTo<IpAddressOrRange> for Element {}

impl Encoder<IpAddressOrRange, Element> for IpAddressOrRange {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        let bytes = match self {
            IpAddressOrRange::Address(IpAddr::V4(addr)) => addr.octets().to_vec(),
            IpAddressOrRange::Address(IpAddr::V6(addr)) => addr.octets().to_vec(),
            IpAddressOrRange::Network(IpNet::V4(net)) => {
                let addr_bytes = net.addr().octets();
                let prefix_len = net.prefix_len();
                let mask = !0u32 << (32 - prefix_len);
                let mask_bytes = mask.to_be_bytes();
                [&addr_bytes[..], &mask_bytes[..]].concat()
            }
            IpAddressOrRange::Network(IpNet::V6(net)) => {
                let addr_bytes = net.addr().octets();
                let prefix_len = net.prefix_len();
                let mask = !0u128 << (128 - prefix_len);
                let mask_bytes = mask.to_be_bytes();
                [&addr_bytes[..], &mask_bytes[..]].concat()
            }
        };
        Ok(Element::OctetString(OctetString::from(bytes)))
    }
}

impl fmt::Display for GeneralName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GeneralName::DnsName(dns) => write!(f, "DNS:{}", dns),
            GeneralName::IpAddress(ip) => write!(f, "IP Address:{}", ip),
            GeneralName::Rfc822Name(email) => write!(f, "email:{}", email),
            GeneralName::Uri(uri) => write!(f, "URI:{}", uri),
            GeneralName::DirectoryName(name) => write!(f, "DirName:{}", name),
            GeneralName::RegisteredId(oid) => write!(f, "Registered ID:{:?}", oid),
            GeneralName::OtherName(other) => write!(f, "othername:{:?}", other.type_id),
            GeneralName::X400Address(_) => write!(f, "X400Address"),
            GeneralName::EdiPartyName(_) => write!(f, "EdiPartyName"),
        }
    }
}

impl DecodableFrom<Element> for GeneralName {}

impl Decoder<Element, GeneralName> for Element {
    type Error = Error;

    fn decode(&self) -> Result<GeneralName, Self::Error> {
        match self {
            Element::ContextSpecific { slot, element, .. } => {
                GeneralName::parse_from_context_specific(*slot, element)
            }
            _ => Err(error::Error::UnexpectedElementType(error::Kind::GeneralName).into()),
        }
    }
}

impl EncodableTo<GeneralName> for Element {}

impl Encoder<GeneralName, Element> for GeneralName {
    type Error = Error;

    fn encode(&self) -> Result<Element, Self::Error> {
        match self {
            GeneralName::OtherName(other) => {
                let value_elem = Element::ContextSpecific {
                    constructed: true,
                    slot: 0,
                    element: Box::new(Element::OctetString(OctetString::from(other.value.clone()))),
                };
                Ok(Element::ContextSpecific {
                    constructed: true,
                    slot: 0,
                    element: Box::new(Element::Sequence(vec![
                        Element::ObjectIdentifier(other.type_id.clone()),
                        value_elem,
                    ])),
                })
            }
            GeneralName::Rfc822Name(s) | GeneralName::DnsName(s) | GeneralName::Uri(s) => {
                let slot = match self {
                    GeneralName::Rfc822Name(_) => 1,
                    GeneralName::DnsName(_) => 2,
                    GeneralName::Uri(_) => 6,
                    _ => unreachable!(),
                };
                Ok(Element::ContextSpecific {
                    constructed: false,
                    slot,
                    element: Box::new(Element::OctetString(OctetString::from(
                        s.as_bytes().to_vec(),
                    ))),
                })
            }
            GeneralName::X400Address(bytes) => Ok(Element::ContextSpecific {
                constructed: false,
                slot: 3,
                element: Box::new(Element::OctetString(OctetString::from(bytes.clone()))),
            }),
            GeneralName::DirectoryName(name) => {
                let name_elem = name.encode()?;
                Ok(Element::ContextSpecific {
                    constructed: true,
                    slot: 4,
                    element: Box::new(name_elem),
                })
            }
            GeneralName::EdiPartyName(edi) => {
                let elements = std::iter::once(edi.name_assigner.as_ref().map(|na| {
                    Element::ContextSpecific {
                        constructed: false,
                        slot: 0,
                        element: Box::new(Element::OctetString(OctetString::from(
                            na.as_bytes().to_vec(),
                        ))),
                    }
                }))
                .chain(std::iter::once(Some(Element::ContextSpecific {
                    constructed: false,
                    slot: 1,
                    element: Box::new(Element::OctetString(OctetString::from(
                        edi.party_name.as_bytes().to_vec(),
                    ))),
                })))
                .flatten()
                .collect();

                Ok(Element::ContextSpecific {
                    constructed: true,
                    slot: 5,
                    element: Box::new(Element::Sequence(elements)),
                })
            }
            GeneralName::IpAddress(ip) => {
                let ip_elem = ip.encode()?;
                Ok(Element::ContextSpecific {
                    constructed: false,
                    slot: 7,
                    element: Box::new(ip_elem),
                })
            }
            GeneralName::RegisteredId(oid) => Ok(Element::ContextSpecific {
                constructed: false,
                slot: 8,
                element: Box::new(Element::ObjectIdentifier(oid.clone())),
            }),
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
