use nom::{IResult, Parser};

mod error;

#[derive(Debug, Clone)]
struct Der {
    data: Vec<u8>,
}

// TODO: implement to parse tag class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
enum Tag {
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
    Unimplemented(u8),
}

impl From<u8> for Tag {
    fn from(value: u8) -> Self {
        match value {
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
            _ => Tag::Unimplemented(value),
        }
    }
}

#[derive(Debug, Clone)]
struct Tlv {
    tag: Tag,
    length: u64,
    value: Value,
}

#[derive(Debug, Clone)]
enum Value {
    Tlv(Vec<Tlv>),
    Data(Vec<u8>),
}

impl Tlv {
    fn parse(input: &[u8]) -> IResult<&[u8], Tlv> {
        let (input, tag) = parse_tag(input)?;
        let (input, length) = parse_length(input)?;
        let (input, data) = nom::bytes::complete::take(length).parse(input)?;

        if tag.eq(&Tag::Sequence) || tag.eq(&Tag::Set) {
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
                    length,
                    value: Value::Tlv(tlvs),
                },
            ));
        }

        Ok((
            input,
            Tlv {
                tag,
                length,
                value: Value::Data(data.to_vec()),
            },
        ))
    }
}

fn parse_tag(input: &[u8]) -> IResult<&[u8], Tag> {
    let (input, n) = nom::number::be_u8().parse(input)?;
    Ok((input, Tag::from(n)))
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

    use crate::{Tag, Tlv, Value, parse_length};

    #[rstest(input, expected, case(vec![0x02], Tag::Integer), case(vec![0x02, 0x01], Tag::Integer), case(vec![0x30, 0x01], Tag::Sequence))]
    fn test_parse_tag(input: Vec<u8>, expected: Tag) {
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
        case(vec![0x02, 0x01, 0x01], Tlv{tag: Tag::Integer, length: 1, value: Value::Data(vec![0x01])}),
        case(vec![0x02, 0x09, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01], Tlv{tag: Tag::Integer, length: 9, value: Value::Data(vec![0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01])}),
        case(vec![0x13, 0x02, 0x68, 0x69], Tlv{tag: Tag::PrintableString, length: 2, value: Value::Data(vec![0x68, 0x69])}),
        case(vec![0x16, 0x02, 0x68, 0x69], Tlv{tag: Tag::IA5String, length: 2, value: Value::Data(vec![0x68, 0x69])}),
        case(vec![0x0c, 0x04, 0xf0, 0x9f, 0x98, 0x8e], Tlv{tag: Tag::UTF8String, length: 4, value: Value::Data(vec![0xf0, 0x9f, 0x98, 0x8e])}),
        case(vec![
            0x17, 0x11, 0x31, 0x39, 0x31, 0x32, 0x31, 0x35, 0x31, 0x39, 0x30, 0x32, 0x31, 0x30, 0x2d, 0x30,
            0x38, 0x30, 0x30,
        ], Tlv { tag: Tag::UTCTime, length: 17, value: Value::Data(vec![
            0x31, 0x39, 0x31, 0x32, 0x31, 0x35, 0x31, 0x39, 0x30, 0x32, 0x31, 0x30, 0x2d, 0x30,
            0x38, 0x30, 0x30,
        ])}),
        case(vec![
            0x18, 0x0d, 0x31, 0x39, 0x31, 0x32, 0x31, 0x36, 0x30, 0x33, 0x30, 0x32, 0x31, 0x30, 0x5a,
        ], Tlv{tag: Tag::GeneralizedTime, length: 13, value: Value::Data(vec![
            0x31, 0x39, 0x31, 0x32, 0x31, 0x36, 0x30, 0x33, 0x30, 0x32, 0x31, 0x30, 0x5a,
        ])}),
        case(vec![0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b], Tlv { tag: Tag::ObjectIdentifier, length: 9, value: Value::Data(vec![0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]) }),
        case(vec![0x05, 0x00], Tlv { tag: Tag::Null, length: 0, value: Value::Data(vec![]) }),
        case(vec![0x04, 0x04, 0x03, 0x02, 0x06, 0xa0], Tlv { tag: Tag::OctetString, length: 4, value: Value::Data(vec![0x03, 0x02, 0x06, 0xa0]) }),
        case(vec![0x03, 0x04, 0x06, 0x6e, 0x5d, 0xc0], Tlv { tag: Tag::BitString, length: 4, value: Value::Data(vec![0x06, 0x6e, 0x5d, 0xc0]) })
    )]
    fn test_tlv_parse_primitive(input: Vec<u8>, expected: Tlv) {
        let (_, actual) = Tlv::parse(&input).unwrap();
        compare_primitive_tlv(&expected, &actual);
    }

    #[rstest(input, expected,
        case(vec![0x30, 0x09, 0x02, 0x01, 0x07, 0x02, 0x01, 0x08, 0x02, 0x01, 0x09], Tlv { tag: Tag::Sequence, length: 9, value: Value::Tlv(vec![Tlv { tag: Tag::Integer, length: 1, value: Value::Data(vec![0x07]) }, Tlv { tag: Tag::Integer, length: 1, value: Value::Data(vec![0x08]) }, Tlv { tag: Tag::Integer, length: 1, value: Value::Data(vec![0x09]) }]) })
    )]
    fn test_tlv_parse_structured(input: Vec<u8>, expected: Tlv) {
        let (_, actual) = Tlv::parse(&input).unwrap();
        assert_eq!(expected.tag, actual.tag);
        assert_eq!(expected.length, actual.length);
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
        assert_eq!(v1.length, v2.length);
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
}
