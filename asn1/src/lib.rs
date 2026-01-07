use std::{fmt::Display, str::FromStr};

use chrono::NaiveDateTime;
use der::{Der, PrimitiveTag, TAG_CONSTRUCTED, Tag, Tlv};
use error::Error;
use num_bigint::BigInt;
use num_traits::ToPrimitive;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tsumiki::decoder::{DecodableFrom, Decoder};
use tsumiki::encoder::{EncodableTo, Encoder};

pub mod error;

#[derive(Debug, Clone)]
pub struct ASN1Object {
    elements: Vec<Element>,
}

impl ASN1Object {
    pub fn elements(&self) -> &[Element] {
        &self.elements
    }

    pub fn new(elements: Vec<Element>) -> Self {
        ASN1Object { elements }
    }
}

impl DecodableFrom<Der> for ASN1Object {}

impl Decoder<Der, ASN1Object> for Der {
    type Error = Error;
    fn decode(&self) -> Result<ASN1Object, Error> {
        let mut elements = Vec::new();
        for tlv in self.elements() {
            let element = Element::try_from(tlv)?;
            elements.push(element);
        }
        Ok(ASN1Object { elements })
    }
}

impl EncodableTo<ASN1Object> for Der {}

impl Encoder<ASN1Object, Der> for ASN1Object {
    type Error = Error;

    fn encode(&self) -> Result<Der, Self::Error> {
        let mut tlvs = Vec::new();
        for element in &self.elements {
            tlvs.push(element.encode()?);
        }
        Ok(Der::new(tlvs))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Element {
    Boolean(bool),
    Integer(Integer),
    BitString(BitString),
    OctetString(OctetString),
    Null,
    ObjectIdentifier(ObjectIdentifier),
    UTF8String(String),
    Sequence(Vec<Element>),
    Set(Vec<Element>),
    PrintableString(String),
    IA5String(String),
    UTCTime(NaiveDateTime),
    GeneralizedTime(NaiveDateTime),
    ContextSpecific {
        slot: u8,
        constructed: bool,
        element: Box<Element>,
    },
    Unimplemented(Tlv),
}

impl TryFrom<&Tlv> for Element {
    type Error = Error;

    fn try_from(tlv: &Tlv) -> Result<Self, Self::Error> {
        match tlv.tag() {
            der::Tag::Primitive(primitive_tag, _value) => match primitive_tag {
                PrimitiveTag::Boolean => {
                    if let Some(data) = tlv.data() {
                        match data.first() {
                            Some(0x00) => Ok(Element::Boolean(false)),
                            Some(0xff) => Ok(Element::Boolean(true)),
                            _ => Err(Error::InvalidBoolean),
                        }
                    } else {
                        Err(Error::InvalidBoolean)
                    }
                }
                PrimitiveTag::Integer => {
                    if let Some(data) = tlv.data() {
                        let integer = Integer::from(data);
                        Ok(Element::Integer(integer))
                    } else {
                        Err(Error::InvalidInteger("Integer tag has no data".to_string()))
                    }
                }
                PrimitiveTag::BitString => {
                    if let Some(data) = tlv.data() {
                        let bit_string = BitString::try_from(data)?;
                        Ok(Element::BitString(bit_string))
                    } else {
                        // Can we have a BitString with no data?
                        Err(Error::InvalidBitString(
                            "BitString tag has no data".to_string(),
                        ))
                    }
                }
                PrimitiveTag::OctetString => {
                    if let Some(data) = tlv.data() {
                        let octet_string = OctetString::from(data);
                        Ok(Element::OctetString(octet_string))
                    } else {
                        // I'm not sure if we can have an OctetString with no data.
                        Ok(Element::OctetString(OctetString { inner: Vec::new() }))
                    }
                }
                PrimitiveTag::Null => Ok(Element::Null),
                PrimitiveTag::ObjectIdentifier => {
                    if let Some(data) = tlv.data() {
                        let oid = ObjectIdentifier::try_from(data)?;
                        Ok(Element::ObjectIdentifier(oid))
                    } else {
                        Err(Error::InvalidObjectIdentifier(
                            "ObjectIdentifier tag has no data".to_string(),
                        ))
                    }
                }
                PrimitiveTag::UTF8String => {
                    if let Some(data) = tlv.data() {
                        let utf8_string = String::from_utf8(data.to_vec())
                            .map_err(|e| Error::InvalidUTF8String(e.to_string()))?;
                        Ok(Element::UTF8String(utf8_string))
                    } else {
                        Ok(Element::UTF8String(String::new()))
                    }
                }
                PrimitiveTag::Sequence => {
                    if let Some(tlvs) = tlv.tlvs() {
                        let mut elements = Vec::new();
                        for sub_tlv in tlvs.iter() {
                            let element = Element::try_from(sub_tlv)?;
                            elements.push(element);
                        }
                        Ok(Element::Sequence(elements))
                    } else {
                        Ok(Element::Sequence(Vec::new()))
                    }
                }
                PrimitiveTag::Set => {
                    if let Some(tlvs) = tlv.tlvs() {
                        let mut elements = Vec::new();
                        for sub_tlv in tlvs.iter() {
                            let element = Element::try_from(sub_tlv)?;
                            elements.push(element);
                        }
                        Ok(Element::Set(elements))
                    } else {
                        Ok(Element::Set(Vec::new()))
                    }
                }
                PrimitiveTag::PrintableString => {
                    if let Some(data) = tlv.data() {
                        let printable_string = String::from_utf8(data.to_vec())
                            .map_err(|e| Error::InvalidPrintableString(e.to_string()))?;
                        Ok(Element::PrintableString(printable_string))
                    } else {
                        Ok(Element::PrintableString(String::new()))
                    }
                }
                PrimitiveTag::IA5String => {
                    if let Some(data) = tlv.data() {
                        let ia5_string = String::from_utf8(data.to_vec())
                            .map_err(|e| Error::InvalidIA5String(e.to_string()))?;
                        Ok(Element::IA5String(ia5_string))
                    } else {
                        Ok(Element::IA5String(String::new()))
                    }
                }
                PrimitiveTag::UTCTime => {
                    if let Some(data) = tlv.data() {
                        let time = parse_utc_time(data)?;
                        Ok(Element::UTCTime(time))
                    } else {
                        Err(Error::InvalidUTCTime("UTCTime tag has no data".to_string()))
                    }
                }
                PrimitiveTag::GeneralizedTime => {
                    if let Some(data) = tlv.data() {
                        let time = parse_generalized_time(data)?;
                        Ok(Element::GeneralizedTime(time))
                    } else {
                        Err(Error::InvalidGeneralizedTime(
                            "GeneralizedTime tag has no data".to_string(),
                        ))
                    }
                }
                PrimitiveTag::Unimplemented(_) => {
                    // Handle unimplemented tags gracefully
                    Ok(Element::Unimplemented(tlv.clone()))
                }
            },
            der::Tag::ContextSpecific { slot, constructed } => {
                if *constructed {
                    // Constructed: contains nested TLV(s)
                    if let Some(tlvs) = tlv.tlvs() {
                        if tlvs.len() != 1 {
                            return Err(Error::InvalidContextSpecific {
                                slot: *slot,
                                msg: "context-specific constructed must have exactly one sub-tlv"
                                    .to_string(),
                            });
                        }
                        if let Some(tlv) = tlvs.first() {
                            let element = Element::try_from(tlv)?;
                            Ok(Element::ContextSpecific {
                                slot: *slot,
                                constructed: true,
                                element: Box::new(element),
                            })
                        } else {
                            Err(Error::InvalidContextSpecific {
                                slot: *slot,
                                msg: "context-specific constructed has no data".to_string(),
                            })
                        }
                    } else {
                        Err(Error::InvalidContextSpecific {
                            slot: *slot,
                            msg: "context-specific constructed has no tlvs".to_string(),
                        })
                    }
                } else {
                    // Primitive: IMPLICIT tagging
                    // Store raw data as OctetString - the upper layer decoder interprets based on schema
                    if let Some(data) = tlv.data() {
                        Ok(Element::ContextSpecific {
                            slot: *slot,
                            constructed: false,
                            element: Box::new(Element::OctetString(OctetString::from(
                                data.to_vec(),
                            ))),
                        })
                    } else {
                        Err(Error::InvalidContextSpecific {
                            slot: *slot,
                            msg: "context-specific primitive has no data".to_string(),
                        })
                    }
                }
            }
        }
    }
}

impl Display for Element {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Element::Boolean(b) => write!(f, "Boolean({})", b),
            Element::Integer(i) => write!(f, "Integer({})", i),
            Element::BitString(bs) => write!(f, "BitString({})", bs),
            Element::OctetString(os) => write!(f, "OctetString({})", os),
            Element::Null => write!(f, "Null"),
            Element::ObjectIdentifier(oid) => write!(f, "ObjectIdentifier({})", oid),
            Element::UTF8String(s) => write!(f, "UTF8String({})", s),
            Element::Sequence(seq) => write!(f, "Sequence({:?})", seq),
            Element::Set(set) => write!(f, "Set({:?})", set),
            Element::PrintableString(s) => write!(f, "PrintableString({})", s),
            Element::IA5String(s) => write!(f, "IA5String({})", s),
            Element::UTCTime(dt) => write!(f, "UTCTime({})", dt),
            Element::GeneralizedTime(dt) => write!(f, "GeneralizedTime({})", dt),
            Element::ContextSpecific {
                slot,
                constructed,
                element,
            } => {
                write!(
                    f,
                    "ContextSpecific(slot: {}, constructed: {}, element: {})",
                    slot, constructed, element
                )
            }
            Element::Unimplemented(tlv) => write!(f, "Unimplemented({:?})", tlv),
        }
    }
}

impl TryFrom<&Element> for Tlv {
    type Error = Error;

    fn try_from(element: &Element) -> Result<Self, Self::Error> {
        match element {
            Element::Boolean(b) => {
                let tag = Tag::Primitive(PrimitiveTag::Boolean, u8::from(&PrimitiveTag::Boolean));
                let data = vec![if *b { 0xFF } else { 0x00 }];
                Ok(Tlv::new_primitive(tag, data))
            }
            Element::Integer(i) => {
                let tag = Tag::Primitive(PrimitiveTag::Integer, u8::from(&PrimitiveTag::Integer));
                let data = i.as_bigint().to_signed_bytes_be();
                Ok(Tlv::new_primitive(tag, data))
            }
            Element::BitString(bs) => {
                let tag =
                    Tag::Primitive(PrimitiveTag::BitString, u8::from(&PrimitiveTag::BitString));
                let mut data = Vec::with_capacity(bs.as_bytes().len() + 1);
                data.push(bs.unused_bits());
                data.extend_from_slice(bs.as_bytes());
                Ok(Tlv::new_primitive(tag, data))
            }
            Element::OctetString(os) => {
                let tag = Tag::Primitive(
                    PrimitiveTag::OctetString,
                    u8::from(&PrimitiveTag::OctetString),
                );
                Ok(Tlv::new_primitive(tag, os.as_bytes().to_vec()))
            }
            Element::Null => {
                let tag = Tag::Primitive(PrimitiveTag::Null, u8::from(&PrimitiveTag::Null));
                Ok(Tlv::new_primitive(tag, vec![]))
            }
            Element::ObjectIdentifier(oid) => {
                let tag = Tag::Primitive(
                    PrimitiveTag::ObjectIdentifier,
                    u8::from(&PrimitiveTag::ObjectIdentifier),
                );
                let data = Vec::try_from(oid.clone())?;
                Ok(Tlv::new_primitive(tag, data))
            }
            Element::UTF8String(s) => {
                let tag = Tag::Primitive(
                    PrimitiveTag::UTF8String,
                    u8::from(&PrimitiveTag::UTF8String),
                );
                Ok(Tlv::new_primitive(tag, s.as_bytes().to_vec()))
            }
            Element::Sequence(elements) => {
                let tag = Tag::Primitive(
                    PrimitiveTag::Sequence,
                    u8::from(&PrimitiveTag::Sequence) | TAG_CONSTRUCTED,
                );
                let tlvs = elements
                    .iter()
                    .map(Tlv::try_from)
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Tlv::new_constructed(tag, tlvs))
            }
            Element::Set(elements) => {
                let tag = Tag::Primitive(
                    PrimitiveTag::Set,
                    u8::from(&PrimitiveTag::Set) | TAG_CONSTRUCTED,
                );
                let tlvs = elements
                    .iter()
                    .map(Tlv::try_from)
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Tlv::new_constructed(tag, tlvs))
            }
            Element::PrintableString(s) => {
                let tag = Tag::Primitive(
                    PrimitiveTag::PrintableString,
                    u8::from(&PrimitiveTag::PrintableString),
                );
                Ok(Tlv::new_primitive(tag, s.as_bytes().to_vec()))
            }
            Element::IA5String(s) => {
                let tag =
                    Tag::Primitive(PrimitiveTag::IA5String, u8::from(&PrimitiveTag::IA5String));
                Ok(Tlv::new_primitive(tag, s.as_bytes().to_vec()))
            }
            Element::UTCTime(dt) => {
                let tag = Tag::Primitive(PrimitiveTag::UTCTime, u8::from(&PrimitiveTag::UTCTime));
                let time_str = dt.format("%y%m%d%H%M%SZ").to_string();
                Ok(Tlv::new_primitive(tag, time_str.as_bytes().to_vec()))
            }
            Element::GeneralizedTime(dt) => {
                let tag = Tag::Primitive(
                    PrimitiveTag::GeneralizedTime,
                    u8::from(&PrimitiveTag::GeneralizedTime),
                );
                let time_str = dt.format("%Y%m%d%H%M%SZ").to_string();
                Ok(Tlv::new_primitive(tag, time_str.as_bytes().to_vec()))
            }
            Element::ContextSpecific {
                slot,
                constructed,
                element,
            } => {
                let tag = Tag::ContextSpecific {
                    slot: *slot,
                    constructed: *constructed,
                };

                if *constructed {
                    // EXPLICIT tagging: wrap the inner element
                    let inner_tlv = Tlv::try_from(element.as_ref())?;
                    Ok(Tlv::new_constructed(tag, vec![inner_tlv]))
                } else {
                    // IMPLICIT tagging: extract the raw data from inner element
                    match element.as_ref() {
                        Element::OctetString(os) => {
                            Ok(Tlv::new_primitive(tag, os.as_bytes().to_vec()))
                        }
                        _ => {
                            // For other types, encode to Tlv and extract data
                            let inner_tlv = Tlv::try_from(element.as_ref())?;
                            if let Some(data) = inner_tlv.data() {
                                Ok(Tlv::new_primitive(tag, data.to_vec()))
                            } else {
                                Err(Error::InvalidElement(
                                    "IMPLICIT tagging requires primitive inner element".to_string(),
                                ))
                            }
                        }
                    }
                }
            }
            Element::Unimplemented(_) => Err(Error::InvalidElement(
                "Cannot encode Unimplemented element".to_string(),
            )),
        }
    }
}

impl EncodableTo<Element> for Tlv {}

impl Encoder<Element, Tlv> for Element {
    type Error = Error;

    fn encode(&self) -> Result<Tlv, Self::Error> {
        Tlv::try_from(self)
    }
}

// ASN1 integer is possible to be a positive and negative value.
// This can be arbitrary sized values.
// In this implementation, we implement DER only. So this only accepts by 126 bytes length.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Integer {
    inner: BigInt,
}

impl Integer {
    /// Returns a reference to the inner BigInt
    pub fn as_bigint(&self) -> &BigInt {
        &self.inner
    }

    /// Converts the Integer to u32 if it fits in the range
    pub fn to_u32(&self) -> Option<u32> {
        self.inner.to_u32()
    }

    /// Converts the Integer to i32 if it fits in the range
    pub fn to_i32(&self) -> Option<i32> {
        self.inner.to_i32()
    }

    /// Converts the Integer to i64 if it fits in the range
    pub fn to_i64(&self) -> Option<i64> {
        self.inner.to_i64()
    }

    /// Converts the Integer to u64 if it fits in the range
    pub fn to_u64(&self) -> Option<u64> {
        self.inner.to_u64()
    }
}

impl Serialize for Integer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.inner.to_string())
    }
}

impl<'de> Deserialize<'de> for Integer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let inner = s.parse::<BigInt>().map_err(serde::de::Error::custom)?;
        Ok(Integer { inner })
    }
}

impl From<&[u8]> for Integer {
    fn from(value: &[u8]) -> Self {
        Integer {
            inner: BigInt::from_signed_bytes_be(value),
        }
    }
}

impl From<&Vec<u8>> for Integer {
    fn from(value: &Vec<u8>) -> Self {
        Integer {
            inner: BigInt::from_signed_bytes_be(value),
        }
    }
}

impl From<Vec<u8>> for Integer {
    fn from(value: Vec<u8>) -> Self {
        Integer {
            inner: BigInt::from_signed_bytes_be(&value),
        }
    }
}

impl TryFrom<Integer> for i64 {
    type Error = Error;

    fn try_from(value: Integer) -> Result<Self, Self::Error> {
        value
            .inner
            .to_i64()
            .ok_or_else(|| Error::InvalidInteger("Integer value out of range for i64".to_string()))
    }
}

impl TryFrom<&Integer> for i64 {
    type Error = Error;

    fn try_from(value: &Integer) -> Result<Self, Self::Error> {
        value
            .inner
            .to_i64()
            .ok_or_else(|| Error::InvalidInteger("Integer value out of range for i64".to_string()))
    }
}

impl TryFrom<Integer> for u64 {
    type Error = Error;

    fn try_from(value: Integer) -> Result<Self, Self::Error> {
        value
            .inner
            .to_u64()
            .ok_or_else(|| Error::InvalidInteger("Integer value out of range for u64".to_string()))
    }
}

impl TryFrom<&Integer> for u64 {
    type Error = Error;

    fn try_from(value: &Integer) -> Result<Self, Self::Error> {
        value
            .inner
            .to_u64()
            .ok_or_else(|| Error::InvalidInteger("Integer value out of range for u64".to_string()))
    }
}

impl Display for Integer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectIdentifier {
    inner: Vec<u64>,
}

impl Serialize for ObjectIdentifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = match self.inner.first() {
            Some(n) => self.inner[1..]
                .iter()
                .fold(n.to_string(), |s, n| s + "." + &n.to_string()),
            None => String::new(),
        };
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for ObjectIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let inner = s
            .split('.')
            .map(|s| s.parse::<u64>().map_err(serde::de::Error::custom))
            .collect::<Result<Vec<u64>, _>>()?;
        Ok(ObjectIdentifier { inner })
    }
}

impl TryFrom<Vec<u8>> for ObjectIdentifier {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl TryFrom<&[u8]> for ObjectIdentifier {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(Error::InvalidObjectIdentifier(
                "ObjectIdentifier cannot be empty".to_string(),
            ));
        }

        let mut values = Vec::new();
        let first = value[0] as u64;
        values.push(first / 40);
        values.push(first % 40);

        let mut val = 0u64;
        for v in value[1..].iter() {
            val = (val << 7) | (*v as u64 & 0x7F);
            if *v & 0x80 == 0 {
                // If the continuation bit is not set, we have reached the end of this value
                values.push(val);
                val = 0; // Reset for the next value
            }
        }
        if val != 0 {
            // If there is a leftover value, it means the encoding was incorrect
            return Err(Error::InvalidObjectIdentifier(
                "Incomplete encoding in ObjectIdentifier".to_string(),
            ));
        }

        Ok(ObjectIdentifier { inner: values })
    }
}

impl TryFrom<ObjectIdentifier> for Vec<u8> {
    type Error = Error;

    fn try_from(oid: ObjectIdentifier) -> Result<Self, Self::Error> {
        if oid.inner.len() < 2 {
            return Err(Error::InvalidObjectIdentifier(format!(
                "invalid length: {}",
                oid
            )));
        }

        let mut result = Vec::new();
        // SHould I check overflow?
        // Encode the first two elements of the OID
        let first = (oid.inner[0] * 40 + oid.inner[1]) as u8;
        result.push(first);

        // Encode the remaining elements of the OID
        for v in oid.inner[2..].iter() {
            let mut encoded = Vec::new();
            let mut value = *v;
            while value > 0 {
                encoded.push(value as u8 & 0x7F);
                value >>= 7;
            }

            while let Some(b) = encoded.pop() {
                // If this is not the last byte, set the continuation bit
                if !encoded.is_empty() {
                    result.push(b | 0x80);
                } else {
                    result.push(b);
                }
            }
        }

        Ok(result)
    }
}

impl Display for ObjectIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self.inner.first() {
            Some(n) => self.inner[1..]
                .iter()
                .fold(n.to_string(), |s, n| s + "." + &n.to_string()),
            None => String::new(),
        };
        write!(f, "{}", s)
    }
}

impl FromStr for ObjectIdentifier {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let split = s.split(".");
        let values = split
            .map(|s| s.parse::<u64>().map_err(Error::ParseInt))
            .collect::<Result<Vec<u64>, Error>>()?;
        Ok(ObjectIdentifier { inner: values })
    }
}

impl PartialEq<&str> for ObjectIdentifier {
    fn eq(&self, other: &&str) -> bool {
        self.inner
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(".")
            == *other
    }
}

impl PartialEq<ObjectIdentifier> for &str {
    fn eq(&self, other: &ObjectIdentifier) -> bool {
        *self
            == other
                .inner
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(".")
    }
}

/// Trait for types that can be converted to an ObjectIdentifier
pub trait AsOid {
    fn as_oid(&self) -> Result<ObjectIdentifier, Error>;
}

impl AsOid for ObjectIdentifier {
    fn as_oid(&self) -> Result<ObjectIdentifier, Error> {
        Ok(self.clone())
    }
}

impl AsOid for &ObjectIdentifier {
    fn as_oid(&self) -> Result<ObjectIdentifier, Error> {
        Ok((*self).clone())
    }
}

impl AsOid for &str {
    fn as_oid(&self) -> Result<ObjectIdentifier, Error> {
        ObjectIdentifier::from_str(self).map_err(|e| {
            Error::InvalidObjectIdentifier(format!("invalid OID string '{}': {}", self, e))
        })
    }
}

impl AsOid for String {
    fn as_oid(&self) -> Result<ObjectIdentifier, Error> {
        self.as_str().as_oid()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitString {
    unused: u8,
    data: Vec<u8>,
}

impl serde::Serialize for BitString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            use serde::ser::SerializeStruct;
            let mut state = serializer.serialize_struct("BitString", 2)?;
            state.serialize_field("bit_length", &self.bit_len())?;

            // Convert to hex string with colon separators
            let hex_string = self
                .data
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(":");
            state.serialize_field("bits", &hex_string)?;

            state.end()
        } else {
            (self.unused, &self.data).serialize(serializer)
        }
    }
}

impl<'de> serde::Deserialize<'de> for BitString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let _bit_str = String::deserialize(deserializer)?;
            Err(serde::de::Error::custom(
                "BitString deserialization from bit string not supported",
            ))
        } else {
            let (unused, data) = <(u8, Vec<u8>)>::deserialize(deserializer)?;
            Ok(BitString { unused, data })
        }
    }
}

impl BitString {
    /// Creates a new BitString with the specified number of unused bits and data
    pub fn new(unused: u8, data: Vec<u8>) -> Self {
        BitString { unused, data }
    }

    /// Returns the number of unused bits in the last byte
    pub fn unused_bits(&self) -> u8 {
        self.unused
    }

    /// Returns a reference to the underlying byte data
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Consumes the BitString and returns the underlying byte data
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    /// Returns the total number of bits (excluding unused bits)
    pub fn bit_len(&self) -> usize {
        if self.data.is_empty() {
            0
        } else {
            self.data.len() * 8 - self.unused as usize
        }
    }
}

impl AsRef<[u8]> for BitString {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl TryFrom<Vec<u8>> for BitString {
    type Error = Error;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        match value.first() {
            Some(&b) => Ok(BitString {
                unused: b,
                data: value[1..].to_vec(),
            }),
            None => Err(Error::InvalidBitString(
                "BitString cannot be empty".to_string(),
            )),
        }
    }
}

impl TryFrom<&[u8]> for BitString {
    type Error = Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        match value.first() {
            Some(&b) => Ok(BitString {
                unused: b,
                data: value[1..].to_vec(),
            }),
            None => Err(Error::InvalidBitString(
                "BitString cannot be empty".to_string(),
            )),
        }
    }
}

impl From<BitString> for Vec<u8> {
    fn from(value: BitString) -> Self {
        let mut result = Vec::with_capacity(value.data.len() + 1);
        result.push(value.unused);
        result.extend(value.data);
        result
    }
}

impl Display for BitString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut result = String::new();

        for (i, byte) in self.data.iter().enumerate() {
            if i == self.data.len() - 1 && self.unused > 0 {
                // Handle the last byte with unused bits
                let valid_bits = byte >> self.unused;
                let bit_count = 8 - self.unused as usize;
                result.push_str(&format!(
                    "{:0bit_count$b}",
                    valid_bits,
                    bit_count = bit_count
                ));
            } else {
                // Process full bytes
                result.push_str(&format!("{:08b}", byte));
            }
        }

        write!(f, "{}", result)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OctetString {
    inner: Vec<u8>,
}

impl Serialize for OctetString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            // Serialize as hex string for human-readable formats (JSON, YAML, etc.)
            let hex_string = self
                .inner
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            serializer.serialize_str(&hex_string)
        } else {
            // Serialize as byte array for binary formats
            self.inner.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for OctetString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            // Deserialize from hex string for human-readable formats
            let hex_string = String::deserialize(deserializer)?;
            let mut inner = Vec::new();
            // Remove any whitespace or common separators
            let cleaned =
                hex_string.replace(|c: char| c.is_whitespace() || c == ':' || c == '-', "");
            if cleaned.len() % 2 != 0 {
                return Err(serde::de::Error::custom("hex string must have even length"));
            }
            for i in (0..cleaned.len()).step_by(2) {
                let byte_str = &cleaned[i..i + 2];
                let byte = u8::from_str_radix(byte_str, 16)
                    .map_err(|e| serde::de::Error::custom(format!("invalid hex string: {}", e)))?;
                inner.push(byte);
            }

            Ok(OctetString { inner })
        } else {
            // Deserialize from byte array for binary formats
            let inner = Vec::<u8>::deserialize(deserializer)?;
            Ok(OctetString { inner })
        }
    }
}

impl OctetString {
    /// Returns the inner bytes as a slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Returns a mutable reference to the inner bytes
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }

    /// Consumes self and returns the inner bytes
    pub fn into_bytes(self) -> Vec<u8> {
        self.inner
    }
}

impl TryFrom<&OctetString> for ASN1Object {
    type Error = Error;

    fn try_from(value: &OctetString) -> Result<Self, Self::Error> {
        let der: Der = value.as_ref().decode().map_err(Error::FailedToDecodeDer)?;
        der.decode()
    }
}

impl TryFrom<OctetString> for ASN1Object {
    type Error = Error;

    fn try_from(value: OctetString) -> Result<Self, Self::Error> {
        let der: Der = value.as_ref().decode().map_err(Error::FailedToDecodeDer)?;
        der.decode()
    }
}

impl AsRef<[u8]> for OctetString {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl AsMut<[u8]> for OctetString {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }
}

impl From<Vec<u8>> for OctetString {
    fn from(value: Vec<u8>) -> Self {
        OctetString { inner: value }
    }
}

impl From<&[u8]> for OctetString {
    fn from(value: &[u8]) -> Self {
        OctetString {
            inner: value.to_vec(),
        }
    }
}

impl Display for OctetString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self
            .inner
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<String>>()
            .join("");
        write!(f, "{}", s)
    }
}

fn parse_utc_time(data: &[u8]) -> Result<NaiveDateTime, Error> {
    NaiveDateTime::parse_from_str(
        std::str::from_utf8(data).map_err(|e| Error::InvalidUTCTime(e.to_string()))?,
        "%y%m%d%H%M%SZ",
    )
    .map_err(|e| Error::InvalidUTCTime(e.to_string()))
}

fn parse_generalized_time(data: &[u8]) -> Result<NaiveDateTime, Error> {
    NaiveDateTime::parse_from_str(
        std::str::from_utf8(data).map_err(|e| Error::InvalidGeneralizedTime(e.to_string()))?,
        "%Y%m%d%H%M%SZ",
    )
    .map_err(|e| Error::InvalidGeneralizedTime(e.to_string()))
}

#[cfg(test)]
mod tests {
    use chrono::NaiveDateTime;
    use rstest::rstest;
    use std::str::FromStr;

    use crate::{BitString, Integer, ObjectIdentifier, OctetString, ASN1Object, Element};
    use num_bigint::BigInt;
    use der::{Tag, Tlv, PrimitiveTag, TAG_CONSTRUCTED};
    use tsumiki::encoder::Encoder;

    #[rstest(input, expected, case(vec![0x01], "1"), case(vec![0x03, 0xd4, 0x15, 0x31, 0x8e, 0x2c, 0x57, 0x1d, 0x29, 0x05, 0xfc, 0x3e, 0x05, 0x27, 0x68, 0x9d, 0x0d, 0x09], "333504890676592408951587385614406537514249"))]
    fn test_parse_element_integer(input: Vec<u8>, expected: &str) {
        let expected_num = Integer {
            inner: BigInt::from_str(expected).unwrap(),
        };

        let value = Integer::from(input.as_slice());

        assert_eq!(expected_num, value);
    }

    #[rstest(
        input,
        expected_json,
        case(Integer { inner: BigInt::from(0) }, r#""0""#),
        case(Integer { inner: BigInt::from(1) }, r#""1""#),
        case(Integer { inner: BigInt::from(255) }, r#""255""#),
        case(Integer { inner: BigInt::from(-1) }, r#""-1""#),
        case(Integer { inner: BigInt::from_str("333504890676592408951587385614406537514249").unwrap() }, r#""333504890676592408951587385614406537514249""#)
    )]
    fn test_integer_serialize(input: Integer, expected_json: &str) {
        let json = serde_json::to_string(&input).unwrap();
        assert_eq!(expected_json, json);
    }

    #[rstest(
        json_input,
        expected,
        case(r#""0""#, Integer { inner: BigInt::from(0) }),
        case(r#""1""#, Integer { inner: BigInt::from(1) }),
        case(r#""255""#, Integer { inner: BigInt::from(255) }),
        case(r#""-1""#, Integer { inner: BigInt::from(-1) }),
        case(r#""333504890676592408951587385614406537514249""#, Integer { inner: BigInt::from_str("333504890676592408951587385614406537514249").unwrap() })
    )]
    fn test_integer_deserialize(json_input: &str, expected: Integer) {
        let integer: Integer = serde_json::from_str(json_input).unwrap();
        assert_eq!(expected, integer);
    }

    #[rstest(
        input,
        case(Integer { inner: BigInt::from(0) }),
        case(Integer { inner: BigInt::from(1) }),
        case(Integer { inner: BigInt::from(255) }),
        case(Integer { inner: BigInt::from(-1) }),
        case(Integer { inner: BigInt::from_str("12345678901234567890").unwrap() }),
        case(Integer { inner: BigInt::from_str("333504890676592408951587385614406537514249").unwrap() })
    )]
    fn test_integer_serialize_deserialize_roundtrip(input: Integer) {
        let json = serde_json::to_string(&input).unwrap();
        let deserialized: Integer = serde_json::from_str(&json).unwrap();
        assert_eq!(input, deserialized);
    }

    #[rstest(input, expected, case(ObjectIdentifier { inner: vec![0x01, 0x02, 0x03, 0x04]}, "1.2.3.4"))]
    fn test_object_identifier_to_string(input: ObjectIdentifier, expected: &str) {
        let actual = input.to_string();
        assert_eq!(expected, actual);
    }

    #[rstest(input, expected, case("1.2.3.4" ,ObjectIdentifier { inner: vec![0x01, 0x02, 0x03, 0x04]} ))]
    fn test_object_identifier_from_string(input: &str, expected: ObjectIdentifier) {
        let actual = ObjectIdentifier::from_str(input).unwrap();
        assert_eq!(expected, actual);
    }

    #[rstest(input, expected,
    // Test case for ISO/ITU-T joint standards (1.2)
    case(vec![0x2A], ObjectIdentifier { inner: vec![1, 2] }),
    // Test case for ISO/IEC standard (1.3.6.1.4.1)
    case(vec![0x2B, 0x06, 0x01, 0x04, 0x01], ObjectIdentifier { inner: vec![1, 3, 6, 1, 4, 1] }),
    // Test case for ITU-T standard (0.9.2342.19200300.100.1.1)
    case(vec![0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x01], ObjectIdentifier { inner: vec![0, 9, 2342, 19200300, 100, 1, 1] }),
    // Test case for large values (1.2.840.113549)
    case(vec![0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D], ObjectIdentifier { inner: vec![1, 2, 840, 113549] }),
    // Test case for multi-byte encoding (1.2.840.113549.1.1.5)
    case(vec![0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05], ObjectIdentifier { inner: vec![1, 2, 840, 113549, 1, 1, 5] }),
    )]
    fn test_object_identifier_from_bytes(input: Vec<u8>, expected: ObjectIdentifier) {
        let actual = ObjectIdentifier::try_from(input).unwrap();
        assert_eq!(expected, actual);
    }

    #[rstest(input, expected,
    // Test case for ISO/ITU-T joint standards (1.2)
    case(ObjectIdentifier { inner: vec![1, 2] }, vec![0x2A]),
    // Test case for ISO/IEC standard (1.3.6.1.4.1)
    case(ObjectIdentifier { inner: vec![1, 3, 6, 1, 4, 1] }, vec![0x2B, 0x06, 0x01, 0x04, 0x01]),
    // Test case for ITU-T standard (0.9.2342.19200300.100.1.1)
    case(ObjectIdentifier { inner: vec![0, 9, 2342, 19200300, 100, 1, 1] }, vec![0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x01]),
    // Test case for large values (1.2.840.113549)
    case(ObjectIdentifier { inner: vec![1, 2, 840, 113549] }, vec![0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D]),
    // Test case for multi-byte encoding (1.2.840.113549.1.1.5)
    case(ObjectIdentifier { inner: vec![1, 2, 840, 113549, 1, 1, 5] }, vec![0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05]),
    )]
    fn test_object_identifier_to_bytes(input: ObjectIdentifier, expected: Vec<u8>) {
        let actual = Vec::<u8>::try_from(input).unwrap();
        assert_eq!(expected, actual);
    }

    #[rstest(input, expected,
        // Test case: No unused bits, single byte
        case(BitString { unused: 0, data: vec![0b10101010] }, "10101010"),
        // Test case: No unused bits, multiple bytes
        case(BitString { unused: 0, data: vec![0b10101010, 0b11001100] }, "1010101011001100"),
        // Test case: Unused bits in the last byte
        case(BitString { unused: 2, data: vec![0b10101010, 0b11001100] }, "10101010110011"),
        // Test case: Empty data
        case(BitString { unused: 0, data: vec![] }, ""),
        // Test case: Single byte with unused bits
        case(BitString { unused: 4, data: vec![0b10100000] }, "1010"),
        // Test case: Multiple bytes with unused bits
        case(BitString { unused: 2, data: vec![0b10101010, 0b11001100] }, "10101010110011")
    )]
    fn test_bitstring_to_string(input: BitString, expected: &str) {
        let actual = input.to_string();
        assert_eq!(expected, actual);
    }

    #[rstest(input, expected,
        // Test case: Single byte
        case(OctetString { inner: vec![0x01] }, "01"),
        // Test case: Multiple bytes
        case(OctetString { inner: vec![0x01, 0x02, 0x03] }, "010203"),
        // Test case: Empty data
        case(OctetString { inner: vec![] }, ""),
        // Test case: Bytes with high values
        case(OctetString { inner: vec![0xff, 0xab, 0xcd] }, "ffabcd"),
        // Test case: Mixed values
        case(OctetString { inner: vec![0x00, 0x7f, 0x80, 0xff] }, "007f80ff")
    )]
    fn test_octetstring_to_string(input: OctetString, expected: &str) {
        let actual = input.to_string();
        assert_eq!(actual, expected);
    }

    #[rstest(input, expected_json,
        // Test case: Empty OctetString
        case(OctetString { inner: vec![] }, r#""""#),
        // Test case: Single byte
        case(OctetString { inner: vec![0x01] }, r#""01""#),
        // Test case: Multiple bytes
        case(OctetString { inner: vec![0x01, 0x02, 0x03] }, r#""010203""#),
        // Test case: High value bytes
        case(OctetString { inner: vec![0xff, 0xab, 0xcd] }, r#""ffabcd""#),
    )]
    fn test_octetstring_serialize(input: OctetString, expected_json: &str) {
        let json = serde_json::to_string(&input).unwrap();
        assert_eq!(json, expected_json);
    }

    #[rstest(json_input, expected,
        // Test case: Empty OctetString
        case(r#""""#, OctetString { inner: vec![] }),
        // Test case: Single byte
        case(r#""01""#, OctetString { inner: vec![0x01] }),
        // Test case: Multiple bytes
        case(r#""010203""#, OctetString { inner: vec![0x01, 0x02, 0x03] }),
        // Test case: High value bytes
        case(r#""ffabcd""#, OctetString { inner: vec![0xff, 0xab, 0xcd] }),
        // Test case: Uppercase hex
        case(r#""FFABCD""#, OctetString { inner: vec![0xff, 0xab, 0xcd] }),
        // Test case: Mixed case
        case(r#""FfAbCd""#, OctetString { inner: vec![0xff, 0xab, 0xcd] }),
    )]
    fn test_octetstring_deserialize(json_input: &str, expected: OctetString) {
        let octet_string: OctetString = serde_json::from_str(json_input).unwrap();
        assert_eq!(octet_string, expected);
    }

    #[rstest(input,
        case(OctetString { inner: vec![] }),
        case(OctetString { inner: vec![0x01] }),
        case(OctetString { inner: vec![0x01, 0x02, 0x03, 0x04, 0x05] }),
        case(OctetString { inner: vec![0xff, 0xab, 0xcd, 0xef] }),
    )]
    fn test_octetstring_serialize_deserialize_roundtrip(input: OctetString) {
        let json = serde_json::to_string(&input).unwrap();
        let deserialized: OctetString = serde_json::from_str(&json).unwrap();
        assert_eq!(input, deserialized);
    }

    const UTC_TIME_FORMAT: &str = "%Y-%m-%d %H:%M:%S";
    #[rstest(input, expected,
        case(vec![0x31, 0x39, 0x31, 0x32, 0x31, 0x36, 0x30, 0x33, 0x30, 0x32, 0x31, 0x30, 0x5a], NaiveDateTime::parse_from_str("2019-12-16 03:02:10", UTC_TIME_FORMAT).unwrap()),
        case(vec![0x31, 0x39, 0x31, 0x32, 0x32, 0x38, 0x31, 0x36, 0x33, 0x33, 0x33, 0x36, 0x5a], NaiveDateTime::parse_from_str("2019-12-28 16:33:36", UTC_TIME_FORMAT).unwrap()),
        case(vec![0x31, 0x39, 0x30, 0x39, 0x32, 0x39, 0x31, 0x36, 0x33, 0x33, 0x33, 0x36, 0x5a], NaiveDateTime::parse_from_str("2019-09-29 16:33:36", UTC_TIME_FORMAT).unwrap())
    )]
    fn test_parse_der_to_utc_time(input: Vec<u8>, expected: NaiveDateTime) {
        use crate::parse_utc_time;

        let utc_time = parse_utc_time(&input).unwrap();
        assert_eq!(expected, utc_time);
    }

    #[rstest(input, expected,
        case(vec![0x32, 0x30, 0x31, 0x39, 0x31, 0x32, 0x31, 0x36, 0x30, 0x33, 0x30, 0x32, 0x31, 0x30, 0x5a], NaiveDateTime::parse_from_str("2019-12-16 03:02:10", UTC_TIME_FORMAT).unwrap()),
        case(vec![0x32, 0x30, 0x31, 0x39, 0x31, 0x32, 0x32, 0x38, 0x31, 0x36, 0x33, 0x33, 0x33, 0x36, 0x5a], NaiveDateTime::parse_from_str("2019-12-28 16:33:36", UTC_TIME_FORMAT).unwrap()),
        case(vec![0x32, 0x30, 0x31, 0x39, 0x30, 0x39, 0x32, 0x39, 0x31, 0x36, 0x33, 0x33, 0x33, 0x36, 0x5a], NaiveDateTime::parse_from_str("2019-09-29 16:33:36", UTC_TIME_FORMAT).unwrap())
    )]
    fn test_parse_der_to_generalized_time(input: Vec<u8>, expected: NaiveDateTime) {
        use crate::parse_generalized_time;

        let utc_time = parse_generalized_time(&input).unwrap();
        assert_eq!(expected, utc_time);
    }

    // This test data is same as the data in der/src/lib.rs.
    const TEST_PEM_CERT1: &str = r"-----BEGIN CERTIFICATE-----
MIICLDCCAdKgAwIBAgIBADAKBggqhkjOPQQDAjB9MQswCQYDVQQGEwJCRTEPMA0G
A1UEChMGR251VExTMSUwIwYDVQQLExxHbnVUTFMgY2VydGlmaWNhdGUgYXV0aG9y
aXR5MQ8wDQYDVQQIEwZMZXV2ZW4xJTAjBgNVBAMTHEdudVRMUyBjZXJ0aWZpY2F0
ZSBhdXRob3JpdHkwHhcNMTEwNTIzMjAzODIxWhcNMTIxMjIyMDc0MTUxWjB9MQsw
CQYDVQQGEwJCRTEPMA0GA1UEChMGR251VExTMSUwIwYDVQQLExxHbnVUTFMgY2Vy
dGlmaWNhdGUgYXV0aG9yaXR5MQ8wDQYDVQQIEwZMZXV2ZW4xJTAjBgNVBAMTHEdu
dVRMUyBjZXJ0aWZpY2F0ZSBhdXRob3JpdHkwWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAARS2I0jiuNn14Y2sSALCX3IybqiIJUvxUpj+oNfzngvj/Niyv2394BWnW4X
uQ4RTEiywK87WRcWMGgJB5kX/t2no0MwQTAPBgNVHRMBAf8EBTADAQH/MA8GA1Ud
DwEB/wQFAwMHBgAwHQYDVR0OBBYEFPC0gf6YEr+1KLlkQAPLzB9mTigDMAoGCCqG
SM49BAMCA0gAMEUCIDGuwD1KPyG+hRf88MeyMQcqOFZD0TbVleF+UsAGQ4enAiEA
l4wOuDwKQa+upc8GftXE2C//4mKANBC6It01gUaTIpo=
-----END CERTIFICATE-----";

    /*
    * Generated by
    $ openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout test_key.pem \
        -out test_cert.pem \
        -days 365 \
        -subj "/C=JP/ST=Tokyo/L=Chiyoda/O=Test Org/OU=Test Unit/CN=localhost"
    */
    const TEST_PEM_CERT2: &str = r"-----BEGIN CERTIFICATE-----
MIIDtTCCAp2gAwIBAgIUaFA0CT8XkKbEtG6JefcmPZp6ThowDQYJKoZIhvcNAQEL
BQAwajELMAkGA1UEBhMCSlAxDjAMBgNVBAgMBVRva3lvMRAwDgYDVQQHDAdDaGl5
b2RhMREwDwYDVQQKDAhUZXN0IE9yZzESMBAGA1UECwwJVGVzdCBVbml0MRIwEAYD
VQQDDAlsb2NhbGhvc3QwHhcNMjUwNTIzMDkxMDQ3WhcNMjYwNTIzMDkxMDQ3WjBq
MQswCQYDVQQGEwJKUDEOMAwGA1UECAwFVG9reW8xEDAOBgNVBAcMB0NoaXlvZGEx
ETAPBgNVBAoMCFRlc3QgT3JnMRIwEAYDVQQLDAlUZXN0IFVuaXQxEjAQBgNVBAMM
CWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALZBodqN
qwafTo+pEyxjMfxHdGPsMLzdHAyHbnfIoaegpaSNG+Gj3XYg8om/F4IPwe73L9wf
2QXjrA86fW4eSumwff+AlIc70wMUOHcJTRdRLNfF3O7BHgtS1Am9P3cANsw1IVec
0DBYB8SZG0v7kt6EZ24ygznz1ptl0noKkVp6ocEUYC8B+Kr5qsm7qz2vef9QPlli
IEm9Za0UFs/r1jjcxfz3GwYQkburRU+bdIO61SCiFyTsqp166XRNSN5ECINwjkxC
CB/9QjeiKjNkyHfC6u1N8Is8fJVA6kUKFyTsPlvs9dzAi3AtNlQsN8p3uRKxZ7Ks
E2hTchypMWozHCkCAwEAAaNTMFEwHQYDVR0OBBYEFPwPDgsW4wRdDj25yLSUYFzB
YX8LMB8GA1UdIwQYMBaAFPwPDgsW4wRdDj25yLSUYFzBYX8LMA8GA1UdEwEB/wQF
MAMBAf8wDQYJKoZIhvcNAQELBQADggEBAJOMSkpB5GWZRw4grEmDKmT8CODNvDBT
S/btPF+unH0fssiqjdQ/qm/Q23Ry1y8paIvXT9IaCRDF5vYhM5A1S9+ryylIM+G4
bAvsEgXUDmLB7LHzETg+7HSYe32iyh0p3EA/LAKdr3zh12bOAdQhRXooQdVjffhc
AKftLxa4Xx7P+w/oPqOdt/f1BQyqsSdQ9iTCnvCbuZ2q3qzFf0ehZXiebXbU5zDc
gqAQgXRgYgyMebhkGdi+V+G75ZSYgOD0zfcoL/p1fW9hr5PPqX7SXcyh8f8Q/ZIL
fgx5sjr+fC3fvET/buw4EnKBhR+sSxn1T70hwP3aXd6wHN0vkMgaJPM=
-----END CERTIFICATE-----";

    const TEST_PEM_PRIV_KEY1: &str = r"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC2QaHajasGn06P
qRMsYzH8R3Rj7DC83RwMh253yKGnoKWkjRvho912IPKJvxeCD8Hu9y/cH9kF46wP
On1uHkrpsH3/gJSHO9MDFDh3CU0XUSzXxdzuwR4LUtQJvT93ADbMNSFXnNAwWAfE
mRtL+5LehGduMoM589abZdJ6CpFaeqHBFGAvAfiq+arJu6s9r3n/UD5ZYiBJvWWt
FBbP69Y43MX89xsGEJG7q0VPm3SDutUgohck7Kqdeul0TUjeRAiDcI5MQggf/UI3
oiozZMh3wurtTfCLPHyVQOpFChck7D5b7PXcwItwLTZULDfKd7kSsWeyrBNoU3Ic
qTFqMxwpAgMBAAECggEABSbYyOE9Rtwk79mjIZuSM6Pfbd2kyQnk+5OuczNYInFf
jUWx1pB3t5mZ0Xv10abZYARbtXiu/UQgvnN0TTMNAgsLnLfJOwNdZRZivDaml7Sj
NFwy8QrDayWFudrAGwCGDAKqdRwJJHywh4WeaGjtj12lwM8rt20lkVHw/6Mh1bFa
Yo2mprDvq/xxqtmqL3I9iqbWPHRg4uGbq2lRD3UAE+Ig1nlY9TmdekNOvQxDLQGV
0yGLVEE3Yjn9QYE+zs21iyYgV7NjEDw+FLzJ3yWb4UBtSiwAzd0XeOUgWx3IYEXF
J/pSEFgBZdRm0JviQ2+qYH/4zKaWnhjwERa4D/H/UwKBgQD3wjoHG7bVCW7BMOWw
mSFM7wZZ6nZItuaobPZbKXQxmXlbPEWJatW6bPcb9YAaw+VUWLXJyvD52N8M9r4E
hUvUermCLrWU0rqD+0q1+j2iLqfzAg8X0jKYAJMR2ESBmDC8p/40xNOtFxG6uhST
cUnykNbl0SYlDbWtYTSdkf5EowKBgQC8UZ/vCPx1PnF2ycdlGqZ/2valuR1EgHXK
ce+mZmg62l4imkAxI3oJJHJh0r99x75yyzBMRhPJKq5P80x6KpqZfH8DBMfWF4fu
83ark/KQXe4M6RAkH+/MH2jsFWpg9c6WQleizoky8bLaDfBGZyVfHfY+FL0Z/zHj
IXhtDyEcwwKBgQDkjs7NQ+nUedEsc5lQ4tLvkAmB5WOdDO2YLnzN+F3ya6yiV+Wm
MWJdiqwjpMS67EChIP0C3S6UrlaGNRFyRi2AJH8B82kbk5Lwsl9npSQ6e2QAL8QQ
q550zwLdkW8RRn6fazJ9J55GrWNzqLnWksou9SLp+5l+0TjqayQIwGealQKBgGby
rF7tZ63kg/yvVBzWU90jY6C3MOPI4hvY62zpIOPDiqCZ+KukPEuRLCKEJoDpWBjD
MVURHjHj7kTwuYczkS6FG54X1/MXDA259M7ZY0o+vys5ocRN3TaWmTIuhugYmGYW
QHhVNjWuYdrIseia7Jgx9fJ8PeBfXPNQ0de05KInAoGAbbsbgtWqL5E9aWn2d0BN
MYfyU9h1doVwVB/ZdzPtS6BuzrtfZ+Oov86tHqnEvUPs7C8Nvzx8HXbT5mdnSgea
RJi/eAqNhqr/YHf8CvlRjMWHnNLlzqrST9aHKeZwPNr+1o/2PeEZCPShUAHZKmf9
e8ZYGIc4gvs5McdrVUyYGUs=
-----END PRIVATE KEY-----";

    use tsumiki::decoder::Decoder;

    #[rstest(
        input,
        _expected,
        case(TEST_PEM_CERT1, None),
        case(TEST_PEM_CERT2, None),
        case(TEST_PEM_PRIV_KEY1, None)
    )]
    fn test_decode_asn1_from_der(input: &str, _expected: Option<()>) {
        use der::Der;
        use pem::Pem;

        let pem: Pem = input.decode().unwrap();
        let der: Der = pem.decode().unwrap();
        // Only ensure not to panic.
        let obj = der.decode().unwrap();
        println!("{:?}", obj);
    }

    #[rstest(
        input,
        expected_json,
        // Test case for ISO/ITU-T joint standards (1.2)
        case(ObjectIdentifier { inner: vec![1, 2] }, r#""1.2""#),
        // Test case for ISO/IEC standard (1.3.6.1.4.1)
        case(ObjectIdentifier { inner: vec![1, 3, 6, 1, 4, 1] }, r#""1.3.6.1.4.1""#),
        // Test case for large values (1.2.840.113549)
        case(ObjectIdentifier { inner: vec![1, 2, 840, 113549] }, r#""1.2.840.113549""#),
        // Test case for multi-byte encoding (1.2.840.113549.1.1.5)
        case(ObjectIdentifier { inner: vec![1, 2, 840, 113549, 1, 1, 5] }, r#""1.2.840.113549.1.1.5""#),
        // Test case for SHA-256 with RSA encryption OID
        case(ObjectIdentifier { inner: vec![1, 2, 840, 113549, 1, 1, 11] }, r#""1.2.840.113549.1.1.11""#)
    )]
    fn test_object_identifier_serialize(input: ObjectIdentifier, expected_json: &str) {
        let json = serde_json::to_string(&input).unwrap();
        assert_eq!(expected_json, json);
    }

    #[rstest(
        json_input,
        expected,
        // Test case for ISO/ITU-T joint standards (1.2)
        case(r#""1.2""#, ObjectIdentifier { inner: vec![1, 2] }),
        // Test case for ISO/IEC standard (1.3.6.1.4.1)
        case(r#""1.3.6.1.4.1""#, ObjectIdentifier { inner: vec![1, 3, 6, 1, 4, 1] }),
        // Test case for large values (1.2.840.113549)
        case(r#""1.2.840.113549""#, ObjectIdentifier { inner: vec![1, 2, 840, 113549] }),
        // Test case for multi-byte encoding (1.2.840.113549.1.1.5)
        case(r#""1.2.840.113549.1.1.5""#, ObjectIdentifier { inner: vec![1, 2, 840, 113549, 1, 1, 5] }),
        // Test case for SHA-256 with RSA encryption OID
        case(r#""1.2.840.113549.1.1.11""#, ObjectIdentifier { inner: vec![1, 2, 840, 113549, 1, 1, 11] })
    )]
    fn test_object_identifier_deserialize(json_input: &str, expected: ObjectIdentifier) {
        let oid: ObjectIdentifier = serde_json::from_str(json_input).unwrap();
        assert_eq!(expected, oid);
    }

    #[rstest(
        input,
        // Test case for round-trip serialization
        case(ObjectIdentifier { inner: vec![1, 2] }),
        case(ObjectIdentifier { inner: vec![1, 3, 6, 1, 4, 1] }),
        case(ObjectIdentifier { inner: vec![1, 2, 840, 113549] }),
        case(ObjectIdentifier { inner: vec![1, 2, 840, 113549, 1, 1, 5] }),
        case(ObjectIdentifier { inner: vec![0, 9, 2342, 19200300, 100, 1, 1] })
    )]
    fn test_object_identifier_serialize_deserialize_roundtrip(input: ObjectIdentifier) {
        let json = serde_json::to_string(&input).unwrap();
        let deserialized: ObjectIdentifier = serde_json::from_str(&json).unwrap();
        assert_eq!(input, deserialized);
    }

    use super::Error;

    #[rstest(
        element,
        expected_tag,
        expected_data,
        // Boolean tests
        case(
            Element::Boolean(true),
            Tag::Primitive(PrimitiveTag::Boolean, 0x01),
            vec![0xFF]
        ),
        case(
            Element::Boolean(false),
            Tag::Primitive(PrimitiveTag::Boolean, 0x01),
            vec![0x00]
        ),
        // Integer tests - zero
        case(
            Element::Integer(Integer { inner: BigInt::from(0) }),
            Tag::Primitive(PrimitiveTag::Integer, 0x02),
            vec![0x00]
        ),
        // Integer tests - positive single byte
        case(
            Element::Integer(Integer { inner: BigInt::from(1) }),
            Tag::Primitive(PrimitiveTag::Integer, 0x02),
            vec![0x01]
        ),
        case(
            Element::Integer(Integer { inner: BigInt::from(127) }),
            Tag::Primitive(PrimitiveTag::Integer, 0x02),
            vec![0x7F]
        ),
        // Integer tests - positive multi-byte (needs padding)
        case(
            Element::Integer(Integer { inner: BigInt::from(128) }),
            Tag::Primitive(PrimitiveTag::Integer, 0x02),
            vec![0x00, 0x80]
        ),
        case(
            Element::Integer(Integer { inner: BigInt::from(255) }),
            Tag::Primitive(PrimitiveTag::Integer, 0x02),
            vec![0x00, 0xFF]
        ),
        case(
            Element::Integer(Integer { inner: BigInt::from(256) }),
            Tag::Primitive(PrimitiveTag::Integer, 0x02),
            vec![0x01, 0x00]
        ),
        // Integer tests - negative
        case(
            Element::Integer(Integer { inner: BigInt::from(-1) }),
            Tag::Primitive(PrimitiveTag::Integer, 0x02),
            vec![0xFF]
        ),
        case(
            Element::Integer(Integer { inner: BigInt::from(-128) }),
            Tag::Primitive(PrimitiveTag::Integer, 0x02),
            vec![0x80]
        ),
        case(
            Element::Integer(Integer { inner: BigInt::from(-129) }),
            Tag::Primitive(PrimitiveTag::Integer, 0x02),
            vec![0xFF, 0x7F]
        ),
        // Null test
        case(
            Element::Null,
            Tag::Primitive(PrimitiveTag::Null, 0x05),
            vec![]
        ),
        // OctetString tests
        case(
            Element::OctetString(OctetString::from(vec![])),
            Tag::Primitive(PrimitiveTag::OctetString, 0x04),
            vec![]
        ),
        case(
            Element::OctetString(OctetString::from(vec![0x00])),
            Tag::Primitive(PrimitiveTag::OctetString, 0x04),
            vec![0x00]
        ),
        case(
            Element::OctetString(OctetString::from(vec![0x01, 0x02, 0x03])),
            Tag::Primitive(PrimitiveTag::OctetString, 0x04),
            vec![0x01, 0x02, 0x03]
        ),
        case(
            Element::OctetString(OctetString::from(vec![0xFF; 10])),
            Tag::Primitive(PrimitiveTag::OctetString, 0x04),
            vec![0xFF; 10]
        ),
        // UTF8String tests
        case(
            Element::UTF8String("".to_string()),
            Tag::Primitive(PrimitiveTag::UTF8String, 0x0C),
            vec![]
        ),
        case(
            Element::UTF8String("a".to_string()),
            Tag::Primitive(PrimitiveTag::UTF8String, 0x0C),
            b"a".to_vec()
        ),
        case(
            Element::UTF8String("hello".to_string()),
            Tag::Primitive(PrimitiveTag::UTF8String, 0x0C),
            b"hello".to_vec()
        ),
        case(
            Element::UTF8String("こんにちは".to_string()),
            Tag::Primitive(PrimitiveTag::UTF8String, 0x0C),
            "こんにちは".as_bytes().to_vec()
        ),
        // PrintableString tests
        case(
            Element::PrintableString("".to_string()),
            Tag::Primitive(PrimitiveTag::PrintableString, 0x13),
            vec![]
        ),
        case(
            Element::PrintableString("A".to_string()),
            Tag::Primitive(PrimitiveTag::PrintableString, 0x13),
            b"A".to_vec()
        ),
        case(
            Element::PrintableString("test".to_string()),
            Tag::Primitive(PrimitiveTag::PrintableString, 0x13),
            b"test".to_vec()
        ),
        case(
            Element::PrintableString("Test String 123".to_string()),
            Tag::Primitive(PrimitiveTag::PrintableString, 0x13),
            b"Test String 123".to_vec()
        ),
        // IA5String tests
        case(
            Element::IA5String("".to_string()),
            Tag::Primitive(PrimitiveTag::IA5String, 0x16),
            vec![]
        ),
        case(
            Element::IA5String("a".to_string()),
            Tag::Primitive(PrimitiveTag::IA5String, 0x16),
            b"a".to_vec()
        ),
        case(
            Element::IA5String("example".to_string()),
            Tag::Primitive(PrimitiveTag::IA5String, 0x16),
            b"example".to_vec()
        ),
        case(
            Element::IA5String("user@example.com".to_string()),
            Tag::Primitive(PrimitiveTag::IA5String, 0x16),
            b"user@example.com".to_vec()
        ),
        // BitString tests - with unused bits
        case(
            Element::BitString(BitString::new(0, vec![])),
            Tag::Primitive(PrimitiveTag::BitString, 0x03),
            vec![0x00] // unused bits only
        ),
        case(
            Element::BitString(BitString::new(0, vec![0xFF])),
            Tag::Primitive(PrimitiveTag::BitString, 0x03),
            vec![0x00, 0xFF] // 0 unused bits + data
        ),
        case(
            Element::BitString(BitString::new(1, vec![0xFF, 0x80])),
            Tag::Primitive(PrimitiveTag::BitString, 0x03),
            vec![0x01, 0xFF, 0x80] // 1 unused bit + data
        ),
        case(
            Element::BitString(BitString::new(4, vec![0xF0])),
            Tag::Primitive(PrimitiveTag::BitString, 0x03),
            vec![0x04, 0xF0] // 4 unused bits + data
        ),
        case(
            Element::BitString(BitString::new(7, vec![0x80])),
            Tag::Primitive(PrimitiveTag::BitString, 0x03),
            vec![0x07, 0x80] // 7 unused bits + data
        ),
        case(
            Element::BitString(BitString::new(0, vec![0x00, 0xFF, 0xAA, 0x55])),
            Tag::Primitive(PrimitiveTag::BitString, 0x03),
            vec![0x00, 0x00, 0xFF, 0xAA, 0x55] // 0 unused bits + 4 bytes data
        ),
        // ObjectIdentifier tests - various common OIDs with expected encodings
        case(
            Element::ObjectIdentifier(ObjectIdentifier { inner: vec![0, 9] }),
            Tag::Primitive(PrimitiveTag::ObjectIdentifier, 0x06),
            vec![0x09] // 0*40 + 9 = 9
        ),
        case(
            Element::ObjectIdentifier(ObjectIdentifier { inner: vec![1, 2] }),
            Tag::Primitive(PrimitiveTag::ObjectIdentifier, 0x06),
            vec![0x2A] // 1*40 + 2 = 42 = 0x2A
        ),
        case(
            Element::ObjectIdentifier(ObjectIdentifier { inner: vec![1, 3, 6, 1] }),
            Tag::Primitive(PrimitiveTag::ObjectIdentifier, 0x06),
            vec![0x2B, 0x06, 0x01] // 1*40+3=43, 6, 1
        ),
        case(
            Element::ObjectIdentifier(ObjectIdentifier { inner: vec![2, 5, 4, 3] }), // CN = 2.5.4.3
            Tag::Primitive(PrimitiveTag::ObjectIdentifier, 0x06),
            vec![0x55, 0x04, 0x03] // 2*40+5=85=0x55, 4, 3
        ),
        case(
            Element::ObjectIdentifier(ObjectIdentifier { inner: vec![2, 5, 4, 6] }), // C = 2.5.4.6
            Tag::Primitive(PrimitiveTag::ObjectIdentifier, 0x06),
            vec![0x55, 0x04, 0x06] // 2*40+5=85=0x55, 4, 6
        ),
        case(
            Element::ObjectIdentifier(ObjectIdentifier { inner: vec![2, 5, 4, 10] }), // O = 2.5.4.10
            Tag::Primitive(PrimitiveTag::ObjectIdentifier, 0x06),
            vec![0x55, 0x04, 0x0A] // 2*40+5=85=0x55, 4, 10
        ),
        case(
            Element::ObjectIdentifier(ObjectIdentifier { inner: vec![1, 2, 840, 113549] }), // RSA = 1.2.840.113549
            Tag::Primitive(PrimitiveTag::ObjectIdentifier, 0x06),
            vec![0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D] // 42, 840 (0x86 0x48), 113549 (0x86 0xF7 0x0D)
        ),
        case(
            Element::ObjectIdentifier(ObjectIdentifier { inner: vec![1, 2, 840, 113549, 1, 1, 1] }), // rsaEncryption
            Tag::Primitive(PrimitiveTag::ObjectIdentifier, 0x06),
            vec![0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
        ),
        case(
            Element::ObjectIdentifier(ObjectIdentifier { inner: vec![1, 2, 840, 113549, 1, 1, 5] }), // sha1WithRSAEncryption
            Tag::Primitive(PrimitiveTag::ObjectIdentifier, 0x06),
            vec![0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05]
        ),
        case(
            Element::ObjectIdentifier(ObjectIdentifier { inner: vec![1, 2, 840, 113549, 1, 1, 11] }), // sha256WithRSAEncryption
            Tag::Primitive(PrimitiveTag::ObjectIdentifier, 0x06),
            vec![0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B]
        ),
        case(
            Element::ObjectIdentifier(ObjectIdentifier { inner: vec![2, 5, 29, 15] }), // keyUsage = 2.5.29.15
            Tag::Primitive(PrimitiveTag::ObjectIdentifier, 0x06),
            vec![0x55, 0x1D, 0x0F] // 2*40+5=85=0x55, 29=0x1D, 15=0x0F
        ),
        case(
            Element::ObjectIdentifier(ObjectIdentifier { inner: vec![2, 5, 29, 19] }), // basicConstraints = 2.5.29.19
            Tag::Primitive(PrimitiveTag::ObjectIdentifier, 0x06),
            vec![0x55, 0x1D, 0x13] // 2*40+5=85=0x55, 29=0x1D, 19=0x13
        )
    )]
    fn test_element_to_tlv_primitive(element: Element, expected_tag: Tag, expected_data: Vec<u8>) {
        let tlv = Tlv::try_from(&element).unwrap();
        assert_eq!(tlv.tag(), &expected_tag);
        assert_eq!(tlv.data(), Some(expected_data.as_slice()));
    }

    #[rstest(
        sequence,
        expected_child_tags,
        // Empty Sequence
        case(
            Element::Sequence(vec![]),
            vec![]
        ),
        // Sequence with one element
        case(
            Element::Sequence(vec![
                Element::Integer(Integer { inner: BigInt::from(42) })
            ]),
            vec![Tag::Primitive(PrimitiveTag::Integer, 0x02)]
        ),
        // Sequence with multiple primitive elements
        case(
            Element::Sequence(vec![
                Element::Integer(Integer { inner: BigInt::from(1) }),
                Element::Boolean(true),
                Element::Null
            ]),
            vec![
                Tag::Primitive(PrimitiveTag::Integer, 0x02),
                Tag::Primitive(PrimitiveTag::Boolean, 0x01),
                Tag::Primitive(PrimitiveTag::Null, 0x05)
            ]
        ),
        // Sequence with string elements
        case(
            Element::Sequence(vec![
                Element::UTF8String("hello".to_string()),
                Element::PrintableString("world".to_string())
            ]),
            vec![
                Tag::Primitive(PrimitiveTag::UTF8String, 0x0C),
                Tag::Primitive(PrimitiveTag::PrintableString, 0x13)
            ]
        ),
        // Sequence with mixed types
        case(
            Element::Sequence(vec![
                Element::Integer(Integer { inner: BigInt::from(100) }),
                Element::OctetString(OctetString::from(vec![0x01, 0x02])),
                Element::BitString(BitString::new(0, vec![0xFF])),
                Element::ObjectIdentifier(ObjectIdentifier { inner: vec![1, 2] })
            ]),
            vec![
                Tag::Primitive(PrimitiveTag::Integer, 0x02),
                Tag::Primitive(PrimitiveTag::OctetString, 0x04),
                Tag::Primitive(PrimitiveTag::BitString, 0x03),
                Tag::Primitive(PrimitiveTag::ObjectIdentifier, 0x06)
            ]
        ),
        // Nested Sequence - one level
        case(
            Element::Sequence(vec![
                Element::Integer(Integer { inner: BigInt::from(1) }),
                Element::Sequence(vec![
                    Element::Boolean(true),
                    Element::Null
                ]),
                Element::UTF8String("end".to_string())
            ]),
            vec![
                Tag::Primitive(PrimitiveTag::Integer, 0x02),
                Tag::Primitive(PrimitiveTag::Sequence, 0x30),
                Tag::Primitive(PrimitiveTag::UTF8String, 0x0C)
            ]
        ),
        // Nested Sequence - multiple levels
        case(
            Element::Sequence(vec![
                Element::Sequence(vec![
                    Element::Sequence(vec![
                        Element::Integer(Integer { inner: BigInt::from(1) })
                    ])
                ]),
                Element::Boolean(false)
            ]),
            vec![
                Tag::Primitive(PrimitiveTag::Sequence, 0x30),
                Tag::Primitive(PrimitiveTag::Boolean, 0x01)
            ]
        ),
        // Sequence containing Set
        case(
            Element::Sequence(vec![
                Element::Integer(Integer { inner: BigInt::from(42) }),
                Element::Set(vec![
                    Element::UTF8String("test".to_string()),
                    Element::PrintableString("value".to_string())
                ])
            ]),
            vec![
                Tag::Primitive(PrimitiveTag::Integer, 0x02),
                Tag::Primitive(PrimitiveTag::Set, 0x31)
            ]
        )
    )]
    fn test_element_to_tlv_sequence(sequence: Element, expected_child_tags: Vec<Tag>) {
        let Element::Sequence(ref elements) = sequence else {
            panic!("Expected Sequence");
        };

        let tlv = Tlv::try_from(&sequence).unwrap();

        // Verify tag
        assert_eq!(tlv.tag(), &Tag::Primitive(PrimitiveTag::Sequence, 0x30));

        // Verify constructed bit is set
        if let Tag::Primitive(_, byte) = tlv.tag() {
            assert_eq!(
                byte & TAG_CONSTRUCTED,
                TAG_CONSTRUCTED,
                "Sequence must have constructed bit set"
            );
        }

        // Verify no primitive data
        assert!(
            tlv.data().is_none(),
            "Sequence should not have primitive data"
        );

        // Verify Vec<Tlv> structure
        let child_tlvs = tlv.tlvs().expect("Sequence should have Vec<Tlv>");
        assert_eq!(
            child_tlvs.len(),
            expected_child_tags.len(),
            "Number of child TLVs must match expected count"
        );
        assert_eq!(
            child_tlvs.len(),
            elements.len(),
            "Number of child TLVs must match number of elements"
        );

        // Verify each child has the expected tag
        for (i, (child_tlv, expected_tag)) in child_tlvs
            .iter()
            .zip(expected_child_tags.iter())
            .enumerate()
        {
            assert_eq!(
                child_tlv.tag(),
                expected_tag,
                "Sequence child {} tag mismatch",
                i
            );
        }
    }

    #[rstest(
        set,
        expected_child_tags,
        // Empty Set
        case(
            Element::Set(vec![]),
            vec![]
        ),
        // Set with one element
        case(
            Element::Set(vec![
                Element::UTF8String("test".to_string())
            ]),
            vec![Tag::Primitive(PrimitiveTag::UTF8String, 0x0C)]
        ),
        // Set with multiple elements
        case(
            Element::Set(vec![
                Element::UTF8String("test".to_string()),
                Element::Integer(Integer { inner: BigInt::from(100) })
            ]),
            vec![
                Tag::Primitive(PrimitiveTag::UTF8String, 0x0C),
                Tag::Primitive(PrimitiveTag::Integer, 0x02)
            ]
        ),
        // Set with various types
        case(
            Element::Set(vec![
                Element::PrintableString("Country".to_string()),
                Element::ObjectIdentifier(ObjectIdentifier { inner: vec![2, 5, 4, 6] }),
                Element::UTF8String("JP".to_string())
            ]),
            vec![
                Tag::Primitive(PrimitiveTag::PrintableString, 0x13),
                Tag::Primitive(PrimitiveTag::ObjectIdentifier, 0x06),
                Tag::Primitive(PrimitiveTag::UTF8String, 0x0C)
            ]
        ),
        // Nested Set - contains another Set
        case(
            Element::Set(vec![
                Element::Integer(Integer { inner: BigInt::from(1) }),
                Element::Set(vec![
                    Element::UTF8String("nested".to_string()),
                    Element::Boolean(true)
                ])
            ]),
            vec![
                Tag::Primitive(PrimitiveTag::Integer, 0x02),
                Tag::Primitive(PrimitiveTag::Set, 0x31)
            ]
        ),
        // Set containing Sequence
        case(
            Element::Set(vec![
                Element::Sequence(vec![
                    Element::Integer(Integer { inner: BigInt::from(1) }),
                    Element::Integer(Integer { inner: BigInt::from(2) })
                ]),
                Element::UTF8String("value".to_string())
            ]),
            vec![
                Tag::Primitive(PrimitiveTag::Sequence, 0x30),
                Tag::Primitive(PrimitiveTag::UTF8String, 0x0C)
            ]
        ),
        // Complex nested structure
        case(
            Element::Set(vec![
                Element::Sequence(vec![
                    Element::Set(vec![
                        Element::Integer(Integer { inner: BigInt::from(1) })
                    ])
                ])
            ]),
            vec![Tag::Primitive(PrimitiveTag::Sequence, 0x30)]
        )
    )]
    fn test_element_to_tlv_set(set: Element, expected_child_tags: Vec<Tag>) {
        let Element::Set(ref elements) = set else {
            panic!("Expected Set");
        };

        let tlv = Tlv::try_from(&set).unwrap();

        // Verify tag
        assert_eq!(tlv.tag(), &Tag::Primitive(PrimitiveTag::Set, 0x31));

        // Verify constructed bit is set
        if let Tag::Primitive(_, byte) = tlv.tag() {
            assert_eq!(
                byte & TAG_CONSTRUCTED,
                TAG_CONSTRUCTED,
                "Set must have constructed bit set"
            );
        }

        // Verify no primitive data
        assert!(tlv.data().is_none(), "Set should not have primitive data");

        // Verify Vec<Tlv> structure
        let child_tlvs = tlv.tlvs().expect("Set should have Vec<Tlv>");
        assert_eq!(
            child_tlvs.len(),
            expected_child_tags.len(),
            "Number of child TLVs must match expected count"
        );
        assert_eq!(
            child_tlvs.len(),
            elements.len(),
            "Number of child TLVs must match number of elements"
        );

        // Verify each child has the expected tag
        for (i, (child_tlv, expected_tag)) in child_tlvs
            .iter()
            .zip(expected_child_tags.iter())
            .enumerate()
        {
            assert_eq!(
                child_tlv.tag(),
                expected_tag,
                "Set child {} tag mismatch",
                i
            );
        }
    }

    #[rstest(
        element,
        expected_slot,
        expected_constructed,
        expected_inner_tag,
        // EXPLICIT tagging (constructed=true) - primitive types
        case(
            Element::ContextSpecific {
                slot: 0,
                constructed: true,
                element: Box::new(Element::Integer(Integer { inner: BigInt::from(42) }))
            },
            0,
            true,
            Tag::Primitive(PrimitiveTag::Integer, 0x02)
        ),
        case(
            Element::ContextSpecific {
                slot: 1,
                constructed: true,
                element: Box::new(Element::Boolean(true))
            },
            1,
            true,
            Tag::Primitive(PrimitiveTag::Boolean, 0x01)
        ),
        case(
            Element::ContextSpecific {
                slot: 2,
                constructed: true,
                element: Box::new(Element::Null)
            },
            2,
            true,
            Tag::Primitive(PrimitiveTag::Null, 0x05)
        ),
        case(
            Element::ContextSpecific {
                slot: 3,
                constructed: true,
                element: Box::new(Element::UTF8String("test".to_string()))
            },
            3,
            true,
            Tag::Primitive(PrimitiveTag::UTF8String, 0x0C)
        ),
        case(
            Element::ContextSpecific {
                slot: 4,
                constructed: true,
                element: Box::new(Element::PrintableString("TEST".to_string()))
            },
            4,
            true,
            Tag::Primitive(PrimitiveTag::PrintableString, 0x13)
        ),
        case(
            Element::ContextSpecific {
                slot: 5,
                constructed: true,
                element: Box::new(Element::IA5String("test@example.com".to_string()))
            },
            5,
            true,
            Tag::Primitive(PrimitiveTag::IA5String, 0x16)
        ),
        case(
            Element::ContextSpecific {
                slot: 6,
                constructed: true,
                element: Box::new(Element::BitString(BitString::new(0, vec![0b10101010])))
            },
            6,
            true,
            Tag::Primitive(PrimitiveTag::BitString, 0x03)
        ),
        case(
            Element::ContextSpecific {
                slot: 7,
                constructed: true,
                element: Box::new(Element::OctetString(OctetString::from(vec![0x01, 0x02, 0x03])))
            },
            7,
            true,
            Tag::Primitive(PrimitiveTag::OctetString, 0x04)
        ),
        case(
            Element::ContextSpecific {
                slot: 8,
                constructed: true,
                element: Box::new(Element::ObjectIdentifier(ObjectIdentifier::try_from(vec![0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D]).unwrap()))
            },
            8,
            true,
            Tag::Primitive(PrimitiveTag::ObjectIdentifier, 0x06)
        ),
        // EXPLICIT tagging (constructed=true) - structured types
        case(
            Element::ContextSpecific {
                slot: 9,
                constructed: true,
                element: Box::new(Element::Sequence(vec![
                    Element::Integer(Integer { inner: BigInt::from(1) }),
                    Element::Boolean(true)
                ]))
            },
            9,
            true,
            Tag::Primitive(PrimitiveTag::Sequence, 0x30)
        ),
        case(
            Element::ContextSpecific {
                slot: 10,
                constructed: true,
                element: Box::new(Element::Set(vec![
                    Element::Integer(Integer { inner: BigInt::from(2) }),
                    Element::UTF8String("value".to_string())
                ]))
            },
            10,
            true,
            Tag::Primitive(PrimitiveTag::Set, 0x31)
        ),
        // EXPLICIT tagging - nested context specific
        case(
            Element::ContextSpecific {
                slot: 11,
                constructed: true,
                element: Box::new(Element::ContextSpecific {
                    slot: 0,
                    constructed: true,
                    element: Box::new(Element::Integer(Integer { inner: BigInt::from(100) }))
                })
            },
            11,
            true,
            Tag::ContextSpecific { slot: 0, constructed: true }
        ),
        // IMPLICIT tagging (constructed=false) - primitive types
        case(
            Element::ContextSpecific {
                slot: 0,
                constructed: false,
                element: Box::new(Element::Integer(Integer { inner: BigInt::from(42) }))
            },
            0,
            false,
            Tag::Primitive(PrimitiveTag::Integer, 0x02)
        ),
        case(
            Element::ContextSpecific {
                slot: 1,
                constructed: false,
                element: Box::new(Element::Boolean(false))
            },
            1,
            false,
            Tag::Primitive(PrimitiveTag::Boolean, 0x01)
        ),
        case(
            Element::ContextSpecific {
                slot: 2,
                constructed: false,
                element: Box::new(Element::OctetString(OctetString::from(vec![0x01, 0x02])))
            },
            2,
            false,
            Tag::Primitive(PrimitiveTag::OctetString, 0x04)
        ),
        case(
            Element::ContextSpecific {
                slot: 3,
                constructed: false,
                element: Box::new(Element::UTF8String("implicit".to_string()))
            },
            3,
            false,
            Tag::Primitive(PrimitiveTag::UTF8String, 0x0C)
        ),
        case(
            Element::ContextSpecific {
                slot: 4,
                constructed: false,
                element: Box::new(Element::PrintableString("IMPLICIT".to_string()))
            },
            4,
            false,
            Tag::Primitive(PrimitiveTag::PrintableString, 0x13)
        ),
        case(
            Element::ContextSpecific {
                slot: 5,
                constructed: false,
                element: Box::new(Element::IA5String("implicit@example.com".to_string()))
            },
            5,
            false,
            Tag::Primitive(PrimitiveTag::IA5String, 0x16)
        ),
        case(
            Element::ContextSpecific {
                slot: 6,
                constructed: false,
                element: Box::new(Element::BitString(BitString::new(0, vec![0xFF, 0x00])))
            },
            6,
            false,
            Tag::Primitive(PrimitiveTag::BitString, 0x03)
        ),
        case(
            Element::ContextSpecific {
                slot: 7,
                constructed: false,
                element: Box::new(Element::ObjectIdentifier(ObjectIdentifier::try_from(vec![0x55, 0x04, 0x03]).unwrap()))
            },
            7,
            false,
            Tag::Primitive(PrimitiveTag::ObjectIdentifier, 0x06)
        ),
        // IMPLICIT tagging - various slot numbers
        case(
            Element::ContextSpecific {
                slot: 15,
                constructed: false,
                element: Box::new(Element::Integer(Integer { inner: BigInt::from(999) }))
            },
            15,
            false,
            Tag::Primitive(PrimitiveTag::Integer, 0x02)
        ),
        case(
            Element::ContextSpecific {
                slot: 30,
                constructed: false,
                element: Box::new(Element::UTF8String("high_slot".to_string()))
            },
            30,
            false,
            Tag::Primitive(PrimitiveTag::UTF8String, 0x0C)
        )
    )]
    fn test_element_to_tlv_context_specific(
        element: Element,
        expected_slot: u8,
        expected_constructed: bool,
        expected_inner_tag: Tag,
    ) {
        let tlv = Tlv::try_from(&element).unwrap();

        // Verify ContextSpecific tag with expected slot and constructed flag
        assert_eq!(
            tlv.tag(),
            &Tag::ContextSpecific {
                slot: expected_slot,
                constructed: expected_constructed
            }
        );

        if expected_constructed {
            // EXPLICIT tagging should have exactly one child TLV
            assert!(
                tlv.tlvs().is_some(),
                "EXPLICIT tagging should have Vec<Tlv>"
            );
            let child_tlvs = tlv.tlvs().unwrap();
            assert_eq!(
                child_tlvs.len(),
                1,
                "EXPLICIT tagging should have exactly one child"
            );
            assert!(
                tlv.data().is_none(),
                "EXPLICIT tagging should not have primitive data"
            );

            // Verify the inner element has the expected tag
            let inner_tlv = &child_tlvs[0];
            assert_eq!(
                inner_tlv.tag(),
                &expected_inner_tag,
                "Inner element tag mismatch"
            );
        } else {
            // IMPLICIT tagging should have data
            assert!(
                tlv.data().is_some(),
                "IMPLICIT tagging should have primitive data"
            );
            assert!(
                tlv.tlvs().is_none(),
                "IMPLICIT tagging should not have Vec<Tlv>"
            );
        }
    }

    #[rstest(
        datetime_str,
        // Valid UTC times - various years
        case("230101120000Z"),  // 2023
        case("991231235959Z"),  // 1999
        case("500630120000Z"),  // 2050
        case("000101000000Z"),  // 2000 - Y2K
        case("490630235959Z"),  // 2049 - last year in 20xx range
        case("500101000000Z"),  // 2050 - first year in 19xx range
        case("700101120000Z"),  // 1970 - Unix epoch
        case("991231000000Z"),  // 1999 end
        // Edge cases - different times
        case("230615000000Z"),  // midnight
        case("230615120000Z"),  // noon
        case("230615235959Z"),  // last second of day
        case("230101010101Z"),  // repeating digits
        case("231231235959Z")   // last second of year
    )]
    fn test_element_to_tlv_utc_time(datetime_str: &str) {
        let dt =
            NaiveDateTime::parse_from_str(&format!("20{}", &datetime_str[..12]), "%Y%m%d%H%M%S")
                .unwrap();

        let element = Element::UTCTime(dt);
        let tlv = Tlv::try_from(&element).unwrap();

        assert_eq!(tlv.tag(), &Tag::Primitive(PrimitiveTag::UTCTime, 0x17));
        assert!(tlv.data().is_some());

        // Verify the encoded data matches expected format
        let data = tlv.data().unwrap();
        assert_eq!(data.len(), 13); // YYMMDDhhmmssZ
        assert_eq!(data[12], b'Z'); // Should end with 'Z'
    }

    #[rstest(
        datetime_str,
        // Valid Generalized times - 4-digit years
        case("20230101120000Z"),  // 2023
        case("19991231235959Z"),  // 1999
        case("20500630120000Z"),  // 2050
        case("20000101000000Z"),  // 2000 - Y2K
        case("19700101000000Z"),  // 1970 - Unix epoch
        case("21000101120000Z"),  // 2100 - next century
        case("20491231235959Z"),  // 2049
        case("19500101000000Z"),  // 1950
        // Edge cases - different times
        case("20230615000000Z"),  // midnight
        case("20230615120000Z"),  // noon
        case("20230615235959Z"),  // last second of day
        case("20230101010101Z"),  // repeating digits
        case("20231231235959Z"),  // last second of year
        // Far future/past
        case("29991231235959Z"),  // year 2999
        case("10000101000000Z")   // year 1000
    )]
    fn test_element_to_tlv_generalized_time(datetime_str: &str) {
        let dt = NaiveDateTime::parse_from_str(&datetime_str[..14], "%Y%m%d%H%M%S").unwrap();

        let element = Element::GeneralizedTime(dt);
        let tlv = Tlv::try_from(&element).unwrap();

        assert_eq!(
            tlv.tag(),
            &Tag::Primitive(PrimitiveTag::GeneralizedTime, 0x18)
        );
        assert!(tlv.data().is_some());

        // Verify the encoded data matches expected format
        let data = tlv.data().unwrap();
        assert_eq!(data.len(), 15); // YYYYMMDDhhmmssZ
        assert_eq!(data[14], b'Z'); // Should end with 'Z'
    }

    #[rstest]
    fn test_element_to_tlv_unimplemented_error() {
        let dummy_tlv = Tlv::new_primitive(Tag::Primitive(PrimitiveTag::Boolean, 0x01), vec![0xFF]);
        let element = Element::Unimplemented(dummy_tlv);

        let result = Tlv::try_from(&element);
        assert!(result.is_err());

        match result {
            Err(Error::InvalidElement(msg)) => {
                assert!(msg.contains("Cannot encode Unimplemented"));
            }
            _ => panic!("Expected InvalidElement error"),
        }
    }

    #[rstest(
        cert_pem,
        case(TEST_PEM_CERT1),
        case(TEST_PEM_CERT2)
    )]
    fn test_roundtrip_certificate(cert_pem: &str) {
        // PEM -> Der -> ASN1Object -> Der
        let pem: pem::Pem = cert_pem.parse().expect("Failed to parse PEM");
        let original_der: der::Der = pem.decode().expect("Failed to decode PEM to Der");

        let asn1_obj: ASN1Object = original_der.decode().expect("Failed to decode Der to ASN1Object");
        let re_encoded_der = asn1_obj.encode().expect("Failed to encode ASN1Object to Der");

        assert_eq!(original_der, re_encoded_der);
    }
}
