mod error;

use std::{
    fmt::{Display, Formatter},
    str::FromStr,
};

use error::Error;
use regex::Regex;

const PRIVATE_KEY_LABEL: &str = "PRIVATE KEY";
const PUBLIC_KEY_LABEL: &str = "PUBLIC KEY";
const CERTIFICATE_LABEL: &str = "CERTIFICATE";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Label {
    PrivateKey,
    PublicKey,
    Certificate,
    Unknown,
}

impl Display for Label {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Label::PrivateKey => write!(f, "{}", PRIVATE_KEY_LABEL),
            Label::PublicKey => write!(f, "{}", PUBLIC_KEY_LABEL),
            Label::Certificate => write!(f, "{}", CERTIFICATE_LABEL),
            Label::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

impl FromStr for Label {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            PRIVATE_KEY_LABEL => Ok(Label::PrivateKey),
            PUBLIC_KEY_LABEL => Ok(Label::PublicKey),
            CERTIFICATE_LABEL => Ok(Label::Certificate),
            _ => Err(Error::InvalidLabel),
        }
    }
}

impl Label {
    fn get_label(line: &str) -> Result<Label, Error> {
        let re = Regex::new(&format!(r"-----(?:BEGIN|END) ([A-Z ]+)-----\s*"))
            .map_err(|_| Error::InvalidEncapsulationBoundary)?;
        if let Some(captured) = re.captures(line) {
            if captured.len() != 2 {
                return Err(Error::InvalidEncapsulationBoundary);
            }
            return captured
                .get(1)
                .ok_or(Error::InvalidEncapsulationBoundary)
                .map(|c| Label::from_str(c.as_str()))?;
        }

        Err(Error::InvalidEncapsulationBoundary)
    }
}

/*
ref: https://www.rfc-editor.org/rfc/rfc7468.html#section-3
*/

#[derive(Debug, Clone)]
pub(crate) struct Pem {
    label: Label,
    base64_data: String, // base64 encoded data
}

impl Pem {
    fn label(&self) -> Label {
        self.label
    }

    fn data(&self) -> &str {
        &self.base64_data
    }
}

impl FromStr for Pem {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut state = PemParsingState::default();
        let mut label = Label::Unknown;
        let mut base64_lines = vec![];
        let mut base64_finl_lines = vec![];
        let mut lines = s.lines();
        loop {
            match state {
                PemParsingState::Init => match lines.next() {
                    Some(line) => {
                        if line.is_empty() {
                            return Err(Error::MissingPreEncapsulationBoundary);
                        }
                        if let Ok(l) = Label::get_label(line) {
                            label = l;
                            state = PemParsingState::PreEncapsulationBoundary;
                        } else {
                            // TODO: correctly handle explanatory text
                            // https://www.rfc-editor.org/rfc/rfc7468.html#section-5.2
                            // Now. we simply ignore explanatory text.
                        }
                    }
                    None => return Err(Error::MissingPreEncapsulationBoundary),
                },
                PemParsingState::PreEncapsulationBoundary => match lines.next() {
                    Some(line) => {
                        if line.is_empty() || Label::get_label(line).is_ok() {
                            return Err(Error::MissingData);
                        }
                        if is_base64_finl(line) {
                            base64_finl_lines.push(line);
                            state = PemParsingState::Base64Finl;
                        } else {
                            base64_lines.push(line);
                            state = PemParsingState::Base64Lines;
                        }
                    }
                    None => return Err(Error::MissingData),
                },
                PemParsingState::Base64Lines => match lines.next() {
                    Some(line) => {
                        if line.is_empty() {
                            return Err(Error::InvalidBase64Line);
                        }
                        if let Ok(l) = Label::get_label(line) {
                            // reach postdb
                            if l.ne(&label) {
                                return Err(Error::LabelMissMatch);
                            }
                            state = PemParsingState::PostEncapsulationBoundary;
                        } else {
                            if is_base64_finl(line) {
                                base64_finl_lines.push(line);
                                state = PemParsingState::Base64Finl;
                            } else {
                                base64_lines.push(line);
                            }
                        }
                    }
                    None => return Err(Error::MissingPostEncapsulationBoundary),
                },
                PemParsingState::Base64Finl => match lines.next() {
                    Some(line) => {
                        if line.is_empty() {
                            return Err(Error::InvalidBase64Finl);
                        }
                        if let Ok(l) = Label::get_label(line) {
                            // reach postdb
                            if l.ne(&label) {
                                return Err(Error::LabelMissMatch);
                            }
                            state = PemParsingState::PostEncapsulationBoundary;
                        } else {
                            if !is_base64_finl(line) {
                                return Err(Error::InvalidBase64Finl);
                            }
                            base64_finl_lines.push(line);
                        }
                    }
                    None => return Err(Error::MissingPostEncapsulationBoundary),
                },
                PemParsingState::PostEncapsulationBoundary => break,
            }
        }
        let finl = base64_finl(&base64_finl_lines)?;
        base64_lines.push(&finl);

        Ok(Pem {
            label,
            base64_data: base64_lines.join(""),
        })
    }
}

/*
* pre-eb ->          base64finl -> post-eb
*        -> base64lines-|---------->
*            |_|
 */
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
enum PemParsingState {
    #[default]
    Init,
    PreEncapsulationBoundary,
    Base64Lines,
    Base64Finl,
    PostEncapsulationBoundary,
}

fn base64_line(line: &str) -> Result<String, Error> {
    let content = line.trim_end();
    if content.len() == 0 {
        return Err(Error::InvalidBase64Line);
    }
    Ok(content.to_string())
}

fn base64_finl(lines: &[&str]) -> Result<String, Error> {
    // base64finl = *base64char (base64pad *WSP eol base64pad / *2base64pad) *WSP eol
    // exp-1)
    // ..AB=\s\s\s\n
    // =\s\s\n
    // exp-2)
    // ..AB==\s\s\n
    if lines.iter().find(|l| l.is_empty()).is_some() {
        return Err(Error::InvalidBase64Finl);
    }
    let lines = lines.iter().map(|l| l.trim()).collect::<Vec<&str>>();
    let content = lines.join("");
    Ok(content)
}

fn is_base64_finl(line: &str) -> bool {
    if line.contains("=") {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use crate::Error;
    use crate::Label;
    use crate::Pem;
    use std::str::FromStr;

    #[rstest(
        input,
        expected,
        case("-----BEGIN PRIVATE KEY-----", Label::PrivateKey),
        case("-----END PUBLIC KEY-----", Label::PublicKey),
        case("-----END PUBLIC KEY-----     ", Label::PublicKey),
        case("-----END PUBLIC KEY-----  ", Label::PublicKey)
    )]
    fn test_get_label(input: &str, expected: Label) {
        let got = Label::get_label(input).unwrap();
        assert_eq!(expected, got);
    }

    const TEST_PEM1: &str = r"-----BEGIN PRIVATE KEY-----
AAA
-----END PRIVATE KEY-----
";
    const TEST_PEM2: &str = r"-----BEGIN PRIVATE KEY-----
AAA
BBB==
-----END PRIVATE KEY-----
";
    const TEST_PEM3: &str = r"-----BEGIN PRIVATE KEY-----
AAA
BBB=
=
-----END PRIVATE KEY-----
";
    const TEST_PEM4: &str = r"Subject: CN=Atlantis
Issuer: CN=Atlantis
-----BEGIN PRIVATE KEY-----
AAA=
-----END PRIVATE KEY-----
";
    const TEST_PEM5: &str = r"-----BEGIN CERTIFICATE-----
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

    #[rstest(
        input,
        expected_label,
        expected_data,
        case(TEST_PEM1, Label::PrivateKey, "AAA"),
        case(TEST_PEM2, Label::PrivateKey, "AAABBB=="),
        case(TEST_PEM3, Label::PrivateKey, "AAABBB=="),
        case(TEST_PEM4, Label::PrivateKey, "AAA="),
        case(
            TEST_PEM5,
            Label::Certificate,
            "MIICLDCCAdKgAwIBAgIBADAKBggqhkjOPQQDAjB9MQswCQYDVQQGEwJCRTEPMA0GA1UEChMGR251VExTMSUwIwYDVQQLExxHbnVUTFMgY2VydGlmaWNhdGUgYXV0aG9yaXR5MQ8wDQYDVQQIEwZMZXV2ZW4xJTAjBgNVBAMTHEdudVRMUyBjZXJ0aWZpY2F0ZSBhdXRob3JpdHkwHhcNMTEwNTIzMjAzODIxWhcNMTIxMjIyMDc0MTUxWjB9MQswCQYDVQQGEwJCRTEPMA0GA1UEChMGR251VExTMSUwIwYDVQQLExxHbnVUTFMgY2VydGlmaWNhdGUgYXV0aG9yaXR5MQ8wDQYDVQQIEwZMZXV2ZW4xJTAjBgNVBAMTHEdudVRMUyBjZXJ0aWZpY2F0ZSBhdXRob3JpdHkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARS2I0jiuNn14Y2sSALCX3IybqiIJUvxUpj+oNfzngvj/Niyv2394BWnW4XuQ4RTEiywK87WRcWMGgJB5kX/t2no0MwQTAPBgNVHRMBAf8EBTADAQH/MA8GA1UdDwEB/wQFAwMHBgAwHQYDVR0OBBYEFPC0gf6YEr+1KLlkQAPLzB9mTigDMAoGCCqGSM49BAMCA0gAMEUCIDGuwD1KPyG+hRf88MeyMQcqOFZD0TbVleF+UsAGQ4enAiEAl4wOuDwKQa+upc8GftXE2C//4mKANBC6It01gUaTIpo="
        )
    )]
    fn test_pem_from_str(input: &str, expected_label: Label, expected_data: &str) {
        let pem = Pem::from_str(input).unwrap();
        assert_eq!(expected_label, pem.label());
        assert_eq!(expected_data, pem.data());
    }

    const INVALID_TEST_PEM1: &str = r"";
    const INVALID_TEST_PEM2: &str = r"-----BEGIN PRIVATE KEY-----

-----END PRIVATE KEY-----
";
    const INVALID_TEST_PEM3: &str = r"-----BEGIN PRIVATE KEY-----
AAA
";
    const INVALID_TEST_PEM4: &str = r"-----BEGIN PRIVATE KEY-----
AAA

-----END PRIVATE KEY-----
";
    const INVALID_TEST_PEM5: &str = r"-----BEGIN PRIVATE KEY-----
AAA==
-----END PUBLIC KEY-----
";
    #[rstest(
        input,
        expected,
        case(INVALID_TEST_PEM1, Error::MissingPreEncapsulationBoundary),
        case(INVALID_TEST_PEM2, Error::MissingData),
        case(INVALID_TEST_PEM3, Error::MissingPostEncapsulationBoundary),
        case(INVALID_TEST_PEM4, Error::InvalidBase64Line),
        case(INVALID_TEST_PEM5, Error::LabelMissMatch)
    )]
    fn test_pem_from_str_with_error(input: &str, expected: Error) {
        if let Err(e) = Pem::from_str(input) {
            assert_eq!(expected, e);
        } else {
            panic!("this test should return an error");
        }
    }
}
