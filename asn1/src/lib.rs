use std::{fmt::Display, str::FromStr};

use chrono::NaiveDateTime;
use der::{Der, Tag, Tlv};
use error::Error;
use num_bigint::BigInt;
use tsumiki::decoder::{DecodableFrom, Decoder};

pub mod error;

#[derive(Debug, Clone)]
struct ASN1Object {
    elements: Vec<Element>,
}

impl ASN1Object {
    pub fn elements(&self) -> &[Element] {
        &self.elements
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

#[derive(Debug, Clone)]
enum Element {
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
    Unimplemented(Tlv),
}

impl TryFrom<&Tlv> for Element {
    type Error = Error;

    fn try_from(tlv: &Tlv) -> Result<Self, Self::Error> {
        match tlv.tag() {
            Tag::Integer => {
                if let Some(data) = tlv.data() {
                    let integer = Integer::from(data);
                    Ok(Element::Integer(integer))
                } else {
                    Err(Error::InvalidInteger("Integer tag has no data".to_string()))
                }
            }
            Tag::BitString => {
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
            Tag::OctetString => {
                if let Some(data) = tlv.data() {
                    let octet_string = OctetString::from(data);
                    Ok(Element::OctetString(octet_string))
                } else {
                    // I'm not sure if we can have an OctetString with no data.
                    Ok(Element::OctetString(OctetString { inner: Vec::new() }))
                }
            }
            Tag::Null => Ok(Element::Null),
            Tag::ObjectIdentifier => {
                if let Some(data) = tlv.data() {
                    let oid = ObjectIdentifier::try_from(data)?;
                    Ok(Element::ObjectIdentifier(oid))
                } else {
                    Err(Error::InvalidObjectIdentifier(
                        "ObjectIdentifier tag has no data".to_string(),
                    ))
                }
            }
            Tag::UTF8String => {
                if let Some(data) = tlv.data() {
                    let utf8_string = String::from_utf8(data.to_vec())
                        .map_err(|e| Error::InvalidUTF8String(e.to_string()))?;
                    Ok(Element::UTF8String(utf8_string))
                } else {
                    Ok(Element::UTF8String(String::new()))
                }
            }
            Tag::Sequence => {
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
            Tag::Set => {
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
            Tag::PrintableString => {
                if let Some(data) = tlv.data() {
                    let printable_string = String::from_utf8(data.to_vec())
                        .map_err(|e| Error::InvalidPrintableString(e.to_string()))?;
                    Ok(Element::PrintableString(printable_string))
                } else {
                    Ok(Element::PrintableString(String::new()))
                }
            }
            Tag::IA5String => {
                if let Some(data) = tlv.data() {
                    let ia5_string = String::from_utf8(data.to_vec())
                        .map_err(|e| Error::InvalidIA5String(e.to_string()))?;
                    Ok(Element::IA5String(ia5_string))
                } else {
                    Ok(Element::IA5String(String::new()))
                }
            }
            Tag::UTCTime => {
                if let Some(data) = tlv.data() {
                    let time = parse_utc_time(data)?;
                    Ok(Element::UTCTime(time))
                } else {
                    Err(Error::InvalidUTCTime("UTCTime tag has no data".to_string()))
                }
            }
            Tag::GeneralizedTime => {
                if let Some(data) = tlv.data() {
                    let time = parse_generalized_time(data)?;
                    Ok(Element::GeneralizedTime(time))
                } else {
                    Err(Error::InvalidGeneralizedTime(
                        "GeneralizedTime tag has no data".to_string(),
                    ))
                }
            }
            Tag::Unimplemented(_) => {
                // Handle unimplemented tags gracefully
                Ok(Element::Unimplemented(tlv.clone()))
            }
        }
    }
}

// ASN1 integer is possible to be a positive and negative value.
// This can be arbitrary sized values.
// In this implementation, we implement DER only. So this only accepts by 126 bytes length.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Integer {
    inner: BigInt,
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

impl Display for Integer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ObjectIdentifier {
    inner: Vec<u64>,
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

#[derive(Debug, Clone)]
struct BitString {
    unused: u8,
    data: Vec<u8>,
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
struct OctetString {
    inner: Vec<u8>,
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

    use crate::{BitString, Integer, ObjectIdentifier, OctetString};
    use num_bigint::BigInt;

    #[rstest(input, expected, case(vec![0x01], "1"), case(vec![0x03, 0xd4, 0x15, 0x31, 0x8e, 0x2c, 0x57, 0x1d, 0x29, 0x05, 0xfc, 0x3e, 0x05, 0x27, 0x68, 0x9d, 0x0d, 0x09], "333504890676592408951587385614406537514249"))]
    fn test_parse_element_integer(input: Vec<u8>, expected: &str) {
        let expected_num = Integer {
            inner: BigInt::from_str(expected).unwrap(),
        };

        let value = Integer::from(input.as_slice());

        assert_eq!(expected_num, value);
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
        let actual = ObjectIdentifier::try_from(input.as_slice()).unwrap();
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
        let _obj = der.decode().unwrap();
    }
}
