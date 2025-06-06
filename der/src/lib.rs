use error::Error;
use nom::{IResult, Parser};
use pem::Pem;
use tsumiki::decoder::{DecodableFrom, Decoder};

mod error;

#[derive(Debug, Clone)]
pub struct Der {
    elements: Vec<Tlv>,
}

impl Der {
    pub fn elements(&self) -> &[Tlv] {
        &self.elements
    }
}

impl DecodableFrom<Vec<u8>> for Der {}

impl Decoder<Vec<u8>, Der> for Vec<u8> {
    type Error = Error;

    fn decode(&self) -> Result<Der, Self::Error> {
        let mut tlvs = Vec::new();
        let mut input = self.as_slice();
        while !input.is_empty() {
            let (new_input, tlv) = Tlv::parse(input).map_err(|e| match e {
                nom::Err::Error(e) => Error::Parser(e.code),
                nom::Err::Incomplete(e) => Error::ParserIncomplete(e),
                nom::Err::Failure(e) => Error::Parser(e.code),
            })?;
            input = new_input;
            tlvs.push(tlv);
        }
        Ok(Der { elements: tlvs })
    }
}

impl DecodableFrom<Pem> for Der {}

impl Decoder<Pem, Der> for Pem {
    type Error = Error;

    fn decode(&self) -> Result<Der, Self::Error> {
        // TODO: consider better syntax
        let data = Decoder::<Pem, Vec<u8>>::decode(self).map_err(Error::Pem)?;
        data.decode()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag {
    inner: u8,
    primitive: PrimitiveTag,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum PrimitiveTag {
    Boolean = 0x01,
    Integer = 0x02,
    BitString = 0x03,
    OctetString = 0x04,
    Null = 0x05,
    ObjectIdentifier = 0x06,
    UTF8String = 0x0c,
    Sequence = 0x30,
    Set = 0x31,
    PrintableString = 0x13,
    IA5String = 0x16,
    UTCTime = 0x17,
    GeneralizedTime = 0x18,
    Version = 0xa0,
    Unimplemented(u8),
}

impl PrimitiveTag {
    fn is_structured(&self) -> bool {
        u8::from(self) & 0b0010_0000 != 0
    }

    fn is_context_specific(&self) -> bool {
        u8::from(self) & 0b1000_0000 != 0
    }
}

impl From<u8> for PrimitiveTag {
    fn from(value: u8) -> Self {
        match value {
            0x01 => Self::Boolean,
            0x02 => Self::Integer,
            0x03 => Self::BitString,
            0x04 => Self::OctetString,
            0x05 => Self::Null,
            0x06 => Self::ObjectIdentifier,
            0x0c => Self::UTF8String,
            0x30 => Self::Sequence,
            0x31 => Self::Set,
            0x13 => Self::PrintableString,
            0x16 => Self::IA5String,
            0x17 => Self::UTCTime,
            0x18 => Self::GeneralizedTime,
            0xa0 => Self::Version,
            _ => PrimitiveTag::Unimplemented(value),
        }
    }
}

impl From<&PrimitiveTag> for u8 {
    fn from(value: &PrimitiveTag) -> Self {
        match value {
            PrimitiveTag::Boolean => 0x01,
            PrimitiveTag::Integer => 0x02,
            PrimitiveTag::BitString => 0x03,
            PrimitiveTag::OctetString => 0x04,
            PrimitiveTag::Null => 0x05,
            PrimitiveTag::ObjectIdentifier => 0x06,
            PrimitiveTag::UTF8String => 0x0c,
            PrimitiveTag::Sequence => 0x30,
            PrimitiveTag::Set => 0x31,
            PrimitiveTag::PrintableString => 0x13,
            PrimitiveTag::IA5String => 0x16,
            PrimitiveTag::UTCTime => 0x17,
            PrimitiveTag::GeneralizedTime => 0x18,
            PrimitiveTag::Version => 0xa0,
            PrimitiveTag::Unimplemented(value) => *value,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Tlv {
    tag: PrimitiveTag,
    // length: u64,
    value: Value,
}

#[derive(Debug, Clone)]
enum Value {
    Tlv(Vec<Tlv>),
    Data(Vec<u8>),
}

impl Tlv {
    pub fn tag(&self) -> PrimitiveTag {
        self.tag
    }

    pub fn data(&self) -> Option<&[u8]> {
        match &self.value {
            Value::Data(data) => Some(data),
            Value::Tlv(_) => None,
        }
    }

    pub fn tlvs(&self) -> Option<&[Tlv]> {
        match &self.value {
            Value::Tlv(tlvs) => Some(tlvs),
            Value::Data(_) => None,
        }
    }

    fn parse(input: &[u8]) -> IResult<&[u8], Tlv> {
        let (input, tag) = parse_tag(input)?;
        let (input, length) = parse_length(input)?;
        let (input, data) = nom::bytes::complete::take(length).parse(input)?;

        if tag.is_structured() {
            // parse TLV recursively.
            let mut tlvs = Vec::new();
            let mut data = data;
            while !data.is_empty() {
                let (new_input, v) = Self::parse(data)?;
                data = new_input;
                tlvs.push(v);
            }

            return Ok((
                input,
                Tlv {
                    tag,
                    value: Value::Tlv(tlvs),
                },
            ));
        }

        Ok((
            input,
            Tlv {
                tag,
                value: Value::Data(data.to_vec()),
            },
        ))
    }
}

fn parse_tag(input: &[u8]) -> IResult<&[u8], PrimitiveTag> {
    let (input, n) = nom::number::be_u8().parse(input)?;
    Ok((input, PrimitiveTag::from(n)))
}

fn parse_length(input: &[u8]) -> IResult<&[u8], u64> {
    let (input, n) = nom::number::be_u8().parse(input)?;
    if n & 0x80 == 0x80 {
        // long form
        // First 1 bit is a marker for long form.
        // Other bits represent bytes length of the length field.
        let length = n & 0x7f;
        let (input, bs) = nom::bytes::complete::take(length).parse(input)?;
        let n = bs.iter().enumerate().fold(0u64, |n, (i, &b)| {
            n + 256_u64.pow((bs.len() - i - 1) as u32) * b as u64
        });
        return Ok((input, n));
    }
    // short form: 0-127
    Ok((input, n as u64))
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use crate::{parse_length, Der, PrimitiveTag, Tlv, Value};
    use tsumiki::decoder::Decoder;

    #[rstest(input, expected, case(vec![0x02], PrimitiveTag::Integer), case(vec![0x02, 0x01], PrimitiveTag::Integer), case(vec![0x30, 0x01], PrimitiveTag::Sequence))]
    fn test_parse_tag(input: Vec<u8>, expected: PrimitiveTag) {
        use crate::parse_tag;

        let actual = parse_tag(&input).unwrap();

        assert_eq!(expected, actual.1);
    }

    #[rstest(input, expected,
        case(vec![0x02], 0x02),
        case(vec![0x02, 0x01], 0x02),
        case(vec![0x30, 0x01], 0x30),
        case(vec![0x82, 0x02, 0x10], 256 * 0x02 + 0x10),
        case(vec![0x83, 0x01, 0x00, 0x00], 256 * 256),
        case(vec![0x82, 0xff, 0xff], 256 * 0xff + 0xff),
    )]
    fn test_parse_length(input: Vec<u8>, expected: u64) {
        let actual = parse_length(&input).unwrap();

        assert_eq!(expected, actual.1);
    }

    #[rstest(input, expected,
        case(vec![0x02, 0x01, 0x01], Tlv{tag: PrimitiveTag::Integer, value: Value::Data(vec![0x01])}),
        case(vec![0x02, 0x09, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01], Tlv{tag: PrimitiveTag::Integer, value: Value::Data(vec![0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01])}),
        case(vec![0x13, 0x02, 0x68, 0x69], Tlv{tag: PrimitiveTag::PrintableString, value: Value::Data(vec![0x68, 0x69])}),
        case(vec![0x16, 0x02, 0x68, 0x69], Tlv{tag: PrimitiveTag::IA5String, value: Value::Data(vec![0x68, 0x69])}),
        case(vec![0x0c, 0x04, 0xf0, 0x9f, 0x98, 0x8e], Tlv{tag: PrimitiveTag::UTF8String, value: Value::Data(vec![0xf0, 0x9f, 0x98, 0x8e])}),
        case(vec![
            0x17, 0x11, 0x31, 0x39, 0x31, 0x32, 0x31, 0x35, 0x31, 0x39, 0x30, 0x32, 0x31, 0x30, 0x2d, 0x30,
            0x38, 0x30, 0x30,
        ], Tlv { tag: PrimitiveTag::UTCTime, value: Value::Data(vec![
            0x31, 0x39, 0x31, 0x32, 0x31, 0x35, 0x31, 0x39, 0x30, 0x32, 0x31, 0x30, 0x2d, 0x30,
            0x38, 0x30, 0x30,
        ])}),
        case(vec![
            0x18, 0x0d, 0x31, 0x39, 0x31, 0x32, 0x31, 0x36, 0x30, 0x33, 0x30, 0x32, 0x31, 0x30, 0x5a,
        ], Tlv{tag: PrimitiveTag::GeneralizedTime, value: Value::Data(vec![
            0x31, 0x39, 0x31, 0x32, 0x31, 0x36, 0x30, 0x33, 0x30, 0x32, 0x31, 0x30, 0x5a,
        ])}),
        case(vec![0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b], Tlv { tag: PrimitiveTag::ObjectIdentifier, value: Value::Data(vec![0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]) }),
        case(vec![0x05, 0x00], Tlv { tag: PrimitiveTag::Null, value: Value::Data(vec![]) }),
        case(vec![0x04, 0x04, 0x03, 0x02, 0x06, 0xa0], Tlv { tag: PrimitiveTag::OctetString, value: Value::Data(vec![0x03, 0x02, 0x06, 0xa0]) }),
        case(vec![0x03, 0x04, 0x06, 0x6e, 0x5d, 0xc0], Tlv { tag: PrimitiveTag::BitString, value: Value::Data(vec![0x06, 0x6e, 0x5d, 0xc0]) })
    )]
    fn test_tlv_parse_primitive(input: Vec<u8>, expected: Tlv) {
        let (_, actual) = Tlv::parse(&input).unwrap();
        compare_primitive_tlv(&expected, &actual);
    }

    #[rstest(input, expected,
        case(vec![0x30, 0x09, 0x02, 0x01, 0x07, 0x02, 0x01, 0x08, 0x02, 0x01, 0x09], Tlv { tag: PrimitiveTag::Sequence, value: Value::Tlv(vec![Tlv { tag: PrimitiveTag::Integer, value: Value::Data(vec![0x07]) }, Tlv { tag: PrimitiveTag::Integer, value: Value::Data(vec![0x08]) }, Tlv { tag: PrimitiveTag::Integer, value: Value::Data(vec![0x09]) }]) })
    )]
    fn test_tlv_parse_structured(input: Vec<u8>, expected: Tlv) {
        let (_, actual) = Tlv::parse(&input).unwrap();
        assert_eq!(expected.tag, actual.tag);
        match actual.value {
            Value::Data(_) => panic!("expected: Value::Tlv, but got Value::Data"),
            Value::Tlv(actual_tlvs) => match expected.value {
                Value::Data(_) => panic!("test data is invalid. required Value::Tlv"),
                Value::Tlv(expected_tlvs) => {
                    if actual_tlvs.len() != expected_tlvs.len() {
                        panic!(
                            "expected nested TLV length is {}, but got length is {}",
                            expected_tlvs.len(),
                            actual_tlvs.len()
                        )
                    }
                    for i in 0..expected_tlvs.len() {
                        compare_primitive_tlv(&expected_tlvs[i], &actual_tlvs[i]);
                    }
                }
            },
        }
    }

    fn compare_primitive_tlv(v1: &Tlv, v2: &Tlv) {
        assert_eq!(v1.tag, v2.tag);
        match &v2.value {
            Value::Data(v2_data) => match &v1.value {
                Value::Data(v1_data) => assert_eq!(v2_data, v1_data),
                Value::Tlv(_) => panic!("test data is invalid. required Value::Data"),
            },
            Value::Tlv(tlvs) => {
                panic!("v1: Value::Data, but got Value::Tlv({:?})", tlvs)
            }
        }
    }

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

    #[rstest(
        input,
        _expected,
        case(TEST_PEM_CERT1, None),
        case(TEST_PEM_CERT2, None),
        case(TEST_PEM_PRIV_KEY1, None)
    )]
    fn test_decode_der_from_pem(input: &str, _expected: Option<()>) {
        let pem = input.decode().unwrap();
        // Assuming not to panic here.
        let der: Der = pem.decode().unwrap();
        println!("{:?}", der);
    }
}
