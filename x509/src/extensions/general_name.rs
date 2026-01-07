use std::net::IpAddr;

use asn1::{Element, ObjectIdentifier};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use tsumiki::decoder::{DecodableFrom, Decoder};

use crate::error::Error;
use crate::{DirectoryString, Name};

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
                    _ => Err(Error::InvalidGeneralName(
                        "x400Address must be ORAddress".to_string(),
                    )),
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
                    _ => Err(Error::InvalidGeneralName(
                        "directoryName must be Sequence (Name)".to_string(),
                    )),
                }
            }
            5 => {
                // ediPartyName [5] IMPLICIT EDIPartyName (SEQUENCE)
                match element {
                    Element::Sequence(seq) => {
                        let mut name_assigner = None;
                        let mut party_name = None;

                        for elem in seq {
                            match elem {
                                Element::ContextSpecific {
                                    slot: 0, element, ..
                                } => {
                                    // nameAssigner [0]
                                    let dir_string: DirectoryString =
                                        element.as_ref().decode().map_err(|_| {
                                            Error::InvalidGeneralName(
                                                "invalid nameAssigner".to_string(),
                                            )
                                        })?;
                                    name_assigner = Some(dir_string.into());
                                }
                                Element::ContextSpecific {
                                    slot: 1, element, ..
                                } => {
                                    // partyName [1]
                                    let dir_string: DirectoryString =
                                        element.as_ref().decode().map_err(|_| {
                                            Error::InvalidGeneralName(
                                                "invalid partyName".to_string(),
                                            )
                                        })?;
                                    party_name = Some(dir_string.into());
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
                // RFC 5280: For SubjectAltName, this is 4 or 16 bytes
                // For NameConstraints, this is 8 or 32 bytes (address + mask)
                match element {
                    Element::OctetString(os) => {
                        let bytes = os.as_bytes();
                        let ip = match bytes.len() {
                            4 => {
                                // IPv4: 4 bytes (single address)
                                let octets: [u8; 4] = bytes.try_into().unwrap();
                                IpAddressOrRange::Address(IpAddr::from(octets))
                            }
                            8 => {
                                // IPv4 network: 8 bytes (address + mask)
                                let addr_octets: [u8; 4] = bytes[0..4].try_into().unwrap();
                                let mask_octets: [u8; 4] = bytes[4..8].try_into().unwrap();

                                let addr = std::net::Ipv4Addr::from(addr_octets);
                                let mask = std::net::Ipv4Addr::from(mask_octets);

                                // Convert netmask to prefix length
                                let prefix_len =
                                    mask.octets().iter().map(|&b| b.count_ones()).sum::<u32>()
                                        as u8;

                                let net = Ipv4Net::new(addr, prefix_len).map_err(|e| {
                                    Error::InvalidGeneralName(format!(
                                        "invalid IPv4 network: {}",
                                        e
                                    ))
                                })?;
                                IpAddressOrRange::Network(IpNet::V4(net))
                            }
                            16 => {
                                // IPv6: 16 bytes (single address)
                                let octets: [u8; 16] = bytes.try_into().unwrap();
                                IpAddressOrRange::Address(IpAddr::from(octets))
                            }
                            32 => {
                                // IPv6 network: 32 bytes (address + mask)
                                let addr_octets: [u8; 16] = bytes[0..16].try_into().unwrap();
                                let mask_octets: [u8; 16] = bytes[16..32].try_into().unwrap();

                                let addr = std::net::Ipv6Addr::from(addr_octets);
                                let mask = std::net::Ipv6Addr::from(mask_octets);

                                // Convert netmask to prefix length
                                let prefix_len =
                                    mask.octets().iter().map(|&b| b.count_ones()).sum::<u32>()
                                        as u8;

                                let net = Ipv6Net::new(addr, prefix_len).map_err(|e| {
                                    Error::InvalidGeneralName(format!(
                                        "invalid IPv6 network: {}",
                                        e
                                    ))
                                })?;
                                IpAddressOrRange::Network(IpNet::V6(net))
                            }
                            _ => {
                                return Err(Error::InvalidGeneralName(format!(
                                    "iPAddress must be 4, 8, 16, or 32 bytes, got {}",
                                    bytes.len()
                                )));
                            }
                        };
                        Ok(GeneralName::IpAddress(ip))
                    }
                    _ => Err(Error::InvalidGeneralName(
                        "iPAddress must be OctetString".to_string(),
                    )),
                }
            }
            8 => {
                // registeredID [8] IMPLICIT OBJECT IDENTIFIER
                match element {
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
    fn parse_ia5_string(element: &Element) -> Result<String, Error> {
        match element {
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
            Element::ContextSpecific { slot, element, .. } => {
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
