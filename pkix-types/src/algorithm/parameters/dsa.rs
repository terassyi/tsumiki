//! DSA Parameters
//!
//! Defined in [RFC 3279 Section 2.3.2](https://datatracker.ietf.org/doc/html/rfc3279#section-2.3.2)

use super::{AlgorithmParameter, Error, RawAlgorithmParameter, Result};
use crate::AlgorithmParameters;
use asn1::{Element, Integer};

/// DSA Parameters
///
/// [RFC 3279 Section 2.3.2](https://datatracker.ietf.org/doc/html/rfc3279#section-2.3.2):
/// ```asn1
/// Dss-Parms ::= SEQUENCE {
///     p   INTEGER,
///     q   INTEGER,
///     g   INTEGER
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsaParameters {
    /// Prime modulus p
    pub p: Integer,
    /// Prime divisor q (q divides p-1)
    pub q: Integer,
    /// Generator g
    pub g: Integer,
}

impl DsaParameters {
    /// Create new DSA parameters
    pub fn new(p: Integer, q: Integer, g: Integer) -> Self {
        Self { p, q, g }
    }
}

impl AlgorithmParameter for DsaParameters {
    fn parse(raw: &RawAlgorithmParameter) -> Result<Self> {
        raw.try_into()
    }
}

impl TryFrom<&DsaParameters> for RawAlgorithmParameter {
    type Error = Error;

    fn try_from(params: &DsaParameters) -> Result<Self> {
        Ok(Self::new(Element::Sequence(vec![
            Element::Integer(params.p.clone()),
            Element::Integer(params.q.clone()),
            Element::Integer(params.g.clone()),
        ])))
    }
}

impl TryFrom<&RawAlgorithmParameter> for DsaParameters {
    type Error = Error;

    fn try_from(raw: &RawAlgorithmParameter) -> Result<Self> {
        match raw.element() {
            Element::Sequence(elements) => {
                let [p_elem, q_elem, g_elem] = elements.as_slice() else {
                    return Err(Error::InvalidElementCount {
                        expected: 3,
                        actual: elements.len(),
                    });
                };

                let p = match p_elem {
                    Element::Integer(i) => i.clone(),
                    _ => {
                        return Err(Error::TypeMismatch {
                            expected: "INTEGER (p)".into(),
                            actual: "non-INTEGER".into(),
                        })
                    }
                };

                let q = match q_elem {
                    Element::Integer(i) => i.clone(),
                    _ => {
                        return Err(Error::TypeMismatch {
                            expected: "INTEGER (q)".into(),
                            actual: "non-INTEGER".into(),
                        })
                    }
                };

                let g = match g_elem {
                    Element::Integer(i) => i.clone(),
                    _ => {
                        return Err(Error::TypeMismatch {
                            expected: "INTEGER (g)".into(),
                            actual: "non-INTEGER".into(),
                        })
                    }
                };

                Ok(Self { p, q, g })
            }
            _ => Err(Error::InvalidDsaParameter(
                "Dss-Parms must be a SEQUENCE".into(),
            )),
        }
    }
}

impl TryFrom<RawAlgorithmParameter> for DsaParameters {
    type Error = Error;

    fn try_from(raw: RawAlgorithmParameter) -> Result<Self> {
        (&raw).try_into()
    }
}

impl TryFrom<&DsaParameters> for AlgorithmParameters {
    type Error = Error;

    fn try_from(params: &DsaParameters) -> Result<Self> {
        Ok(Self::Other(RawAlgorithmParameter::try_from(params)?))
    }
}

impl TryFrom<AlgorithmParameters> for DsaParameters {
    type Error = Error;

    fn try_from(params: AlgorithmParameters) -> Result<Self> {
        match params {
            AlgorithmParameters::Null => Err(Error::NullConversion),
            AlgorithmParameters::Other(raw) => Self::try_from(raw),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::parameters::RawAlgorithmParameter;
    use rstest::rstest;

    #[test]
    fn test_dsa_parameters_new() {
        let p = Integer::from(vec![0x17u8]);
        let q = Integer::from(vec![0x0bu8]);
        let g = Integer::from(vec![0x02u8]);

        let params = DsaParameters::new(p.clone(), q.clone(), g.clone());
        assert_eq!(params.p, p);
        assert_eq!(params.q, q);
        assert_eq!(params.g, g);
    }

    #[rstest]
    #[case(vec![0x01u8, 0x02, 0x03], vec![0x04u8, 0x05], vec![0x06u8])]
    #[case(vec![0x17u8], vec![0x0bu8], vec![0x02u8])]
    #[case(vec![0xffu8, 0xff], vec![0x01u8], vec![0x03u8, 0x05])]
    fn test_dsa_parameters_roundtrip(
        #[case] p_bytes: Vec<u8>,
        #[case] q_bytes: Vec<u8>,
        #[case] g_bytes: Vec<u8>,
    ) {
        let p = Integer::from(p_bytes);
        let q = Integer::from(q_bytes);
        let g = Integer::from(g_bytes);

        let params = DsaParameters::new(p, q, g);
        let raw = RawAlgorithmParameter::try_from(&params).unwrap();
        let decoded: DsaParameters = raw.try_into().unwrap();

        assert_eq!(params, decoded);
    }

    #[rstest]
    #[case(Element::Null, "not a SEQUENCE")]
    #[case(Element::Integer(Integer::from(vec![0x01u8])), "not a SEQUENCE")]
    fn test_dsa_parameters_invalid_not_sequence(
        #[case] element: Element,
        #[case] _expected_msg: &str,
    ) {
        let raw = RawAlgorithmParameter::new(element);
        let result: Result<DsaParameters> = raw.try_into();
        assert!(result.is_err());
    }

    #[rstest]
    #[case(vec![
        Element::Integer(Integer::from(vec![0x01u8])),
        Element::Integer(Integer::from(vec![0x02u8])),
    ])]
    #[case(vec![
        Element::Integer(Integer::from(vec![0x01u8])),
    ])]
    #[case(vec![
        Element::Integer(Integer::from(vec![0x01u8])),
        Element::Integer(Integer::from(vec![0x02u8])),
        Element::Integer(Integer::from(vec![0x03u8])),
        Element::Integer(Integer::from(vec![0x04u8])),
    ])]
    fn test_dsa_parameters_invalid_wrong_count(#[case] elements: Vec<Element>) {
        let element = Element::Sequence(elements);
        let raw = RawAlgorithmParameter::new(element);
        let result: Result<DsaParameters> = raw.try_into();
        assert!(result.is_err());
    }

    #[rstest]
    #[case(vec![
        Element::Integer(Integer::from(vec![0x01u8])),
        Element::Integer(Integer::from(vec![0x02u8])),
        Element::Null,
    ])]
    #[case(vec![
        Element::Integer(Integer::from(vec![0x01u8])),
        Element::Null,
        Element::Integer(Integer::from(vec![0x03u8])),
    ])]
    #[case(vec![
        Element::Null,
        Element::Integer(Integer::from(vec![0x02u8])),
        Element::Integer(Integer::from(vec![0x03u8])),
    ])]
    fn test_dsa_parameters_invalid_not_integers(#[case] elements: Vec<Element>) {
        let element = Element::Sequence(elements);
        let raw = RawAlgorithmParameter::new(element);
        let result: Result<DsaParameters> = raw.try_into();
        assert!(result.is_err());
    }
}
