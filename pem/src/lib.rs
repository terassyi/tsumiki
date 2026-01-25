pub mod error;

use std::{
    fmt::{Display, Formatter},
    str::FromStr,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use error::Error;
use regex::Regex;
use tsumiki::decoder::{DecodableFrom, Decoder};

const PRIVATE_KEY_LABEL: &str = "PRIVATE KEY";
const ENCRYPTED_PRIVATE_KEY_LABEL: &str = "ENCRYPTED PRIVATE KEY";
const RSA_PRIVATE_KEY_LABEL: &str = "RSA PRIVATE KEY";
const EC_PRIVATE_KEY_LABEL: &str = "EC PRIVATE KEY";
const PUBLIC_KEY_LABEL: &str = "PUBLIC KEY";
const RSA_PUBLIC_KEY_LABEL: &str = "RSA PUBLIC KEY";
const CERTIFICATE_LABEL: &str = "CERTIFICATE";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Label {
    /// PKCS#8 private key (non-encrypted)
    PrivateKey,
    /// PKCS#8 encrypted private key
    EncryptedPrivateKey,
    /// PKCS#1 RSA private key
    RSAPrivateKey,
    /// SEC1 EC private key
    ECPrivateKey,
    /// X.509 SubjectPublicKeyInfo
    PublicKey,
    /// PKCS#1 RSA public key
    RSAPublicKey,
    /// X.509 Certificate
    Certificate,
    Unknown,
}

impl Display for Label {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Label::PrivateKey => write!(f, "{}", PRIVATE_KEY_LABEL),
            Label::EncryptedPrivateKey => write!(f, "{}", ENCRYPTED_PRIVATE_KEY_LABEL),
            Label::RSAPrivateKey => write!(f, "{}", RSA_PRIVATE_KEY_LABEL),
            Label::ECPrivateKey => write!(f, "{}", EC_PRIVATE_KEY_LABEL),
            Label::PublicKey => write!(f, "{}", PUBLIC_KEY_LABEL),
            Label::RSAPublicKey => write!(f, "{}", RSA_PUBLIC_KEY_LABEL),
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
            ENCRYPTED_PRIVATE_KEY_LABEL => Ok(Label::EncryptedPrivateKey),
            RSA_PRIVATE_KEY_LABEL => Ok(Label::RSAPrivateKey),
            EC_PRIVATE_KEY_LABEL => Ok(Label::ECPrivateKey),
            PUBLIC_KEY_LABEL => Ok(Label::PublicKey),
            RSA_PUBLIC_KEY_LABEL => Ok(Label::RSAPublicKey),
            CERTIFICATE_LABEL => Ok(Label::Certificate),
            _ => Err(Error::InvalidLabel),
        }
    }
}

impl Label {
    fn get_label(line: &str) -> Result<Label, Error> {
        let re = Regex::new(r"-----(?:BEGIN|END) ([A-Z ]+)-----\s*")
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
pub struct Pem {
    label: Label,
    base64_data: String, // base64 encoded data
}

impl Pem {
    pub fn new(label: Label, base64_data: String) -> Self {
        Pem { label, base64_data }
    }

    pub fn from_bytes(label: Label, data: &[u8]) -> Self {
        let base64_data = STANDARD.encode(data);
        Pem { label, base64_data }
    }

    pub fn label(&self) -> Label {
        self.label
    }

    pub fn data(&self) -> &str {
        &self.base64_data
    }
}

impl Display for Pem {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "-----BEGIN {}-----", self.label)?;
        // RFC 7468: base64 text should be wrapped at 64 characters
        for chunk in self.base64_data.as_bytes().chunks(64) {
            let line = std::str::from_utf8(chunk).map_err(|_| std::fmt::Error)?;
            writeln!(f, "{}", line)?;
        }
        write!(f, "-----END {}-----", self.label)
    }
}

/// Trait for types that can be converted to PEM format
pub trait ToPem {
    /// The error type returned by to_pem
    type Error;

    /// Get the PEM label for this type
    fn pem_label(&self) -> Label;

    /// Convert to PEM format
    fn to_pem(&self) -> Result<Pem, Self::Error>;
}

/// Trait for types that can be constructed from PEM format
pub trait FromPem: Sized {
    /// The error type returned by from_pem
    type Error;

    /// Get the expected PEM label for this type
    fn expected_label() -> Label;

    /// Construct from PEM format
    fn from_pem(pem: &Pem) -> Result<Self, Self::Error>;
}

impl DecodableFrom<Pem> for Vec<u8> {}

impl Decoder<Pem, Vec<u8>> for Pem {
    type Error = Error;

    fn decode(&self) -> Result<Vec<u8>, Self::Error> {
        // This discards label information from Pem format.
        let decoded = STANDARD.decode(self.data()).map_err(Error::Base64Decode)?;
        Ok(decoded)
    }
}

impl DecodableFrom<String> for Pem {}

impl Decoder<String, Pem> for String {
    type Error = Error;

    fn decode(&self) -> Result<Pem, Self::Error> {
        Pem::from_str(self)
    }
}

impl DecodableFrom<&str> for Pem {}

impl Decoder<&str, Pem> for &str {
    type Error = Error;

    fn decode(&self) -> Result<Pem, Self::Error> {
        Pem::from_str(self)
    }
}

/// Parse multiple PEM blocks from a string.
///
/// Returns a vector of all PEM blocks found in the input.
/// This is useful for parsing certificate chains or files containing
/// multiple certificates/keys.
///
/// # Example
/// ```
/// use pem::parse_many;
///
/// let pem_data = "-----BEGIN CERTIFICATE-----\nAAA=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nBBB=\n-----END CERTIFICATE-----";
/// let pems = parse_many(pem_data).unwrap();
/// assert_eq!(pems.len(), 2);
/// ```
pub fn parse_many(s: &str) -> Result<Vec<Pem>, Error> {
    // Normalize input: ensure each boundary marker is on its own line
    let normalized = s.replace("----------", "-----\n-----");

    let mut pems = Vec::new();
    let mut current_block: Option<(Label, Vec<&str>)> = None;

    for line in normalized.lines() {
        if let Ok(label) = Label::get_label(line) {
            if line.contains("BEGIN") {
                // Start a new block
                current_block = Some((label, vec![line]));
            } else if line.contains("END") {
                // End current block
                if let Some((begin_label, mut lines)) = current_block.take() {
                    if begin_label == label {
                        lines.push(line);
                        let block = lines.join("\n") + "\n";
                        pems.push(Pem::from_str(&block)?);
                    } else {
                        return Err(Error::LabelMissMatch);
                    }
                } else {
                    return Err(Error::MissingPreEncapsulationBoundary);
                }
            }
        } else if let Some((_, ref mut lines)) = current_block {
            // Inside a block, collect data lines
            lines.push(line);
        }
        // Ignore lines outside of PEM blocks
    }

    if current_block.is_some() {
        return Err(Error::MissingPostEncapsulationBoundary);
    }

    if pems.is_empty() {
        return Err(Error::MissingPreEncapsulationBoundary);
    }

    Ok(pems)
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
                        } else if is_base64_finl(line) {
                            base64_finl_lines.push(line);
                            state = PemParsingState::Base64Finl;
                        } else {
                            base64_lines.push(line);
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

fn base64_finl(lines: &[&str]) -> Result<String, Error> {
    // base64finl = *base64char (base64pad *WSP eol base64pad / *2base64pad) *WSP eol
    // exp-1)
    // ..AB=\s\s\s\n
    // =\s\s\n
    // exp-2)
    // ..AB==\s\s\n
    if lines.iter().any(|l| l.is_empty()) {
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
    use tsumiki::decoder::Decoder;

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

    const TEST_PEM_CERT2: &str = r"-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKL0UG+mRkmSMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTYxMjIxMTYzMDA1WhcNMjYxMjE5MTYzMDA1WjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAw3khLOKBaKp0I+rkfpJH6i1KBmfEpuCrzK5LMZaFZiVgW/SxXU31N1ee
4WMrNkfxbI4UlGhPmvlTjP7bvC5V0U28kCZ5s9PQb1FvkPvEJhw9aJVf3zr5wZRb
8PyBwP3qUfYYWdJmHAHSKb3wDTl4m9wW0i3BNJxW2FLCQU0hRGiCBnW3hEMCH8m2
P+kQhUITjy9VfNJmKi5dL3RDXZHN+9gYvwHAabMh8qdWKaJCxAiLN4AO9dVXqOJd
e1TuZ/Vl6qJ3hYT3T3DdVCJ7vHXLqXBnGMxbFhD8rJ4f5V7QRQVbKl1fWZRGtqzB
YaKyMMoHCMLa3qJvGDEJGTCKB1LEawIDAQABo1AwTjAdBgNVHQ4EFgQUo2hUXWzw
BI1kxA1WFCLKjWHHwdQwHwYDVR0jBBgwFoAUo2hUXWzwBI1kxA1WFCLKjWHHwdQw
DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAaDQl2e0vqOCqGNzYqZyY
S7RJVYW6WIoq7KdQ0m2Bz2NKRvh2KCqCLZvOuDWoOqMHIQM3FnOFv2FIzTT6sqLv
njRKYAx9Vd4NeMkPq3QHJU7RMkr3EGqFPB8/Zr/p8lZL5DsHKAQv0P9fxbLPxEqw
Db4tBf4sFjflSF5g3yD4UwmQvSvYGDW8LqhpSL0FZ8thCR4Ii9L9vGBr5fqB3pFM
uS6eN4Ck5fC4VaZuPKpCj6c7L5i8BDvPbZV4h6FJZFGpd7qPrCJUvYJH0u5MiLJh
H6Z2F5qzxFr3dVOYlTUQPYJGBZBpXgXL5fBnPWnPPuLFBNLNNqCpM5cY+c5dS9YE
pg==
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
            TEST_PEM_CERT1,
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

    #[rstest(
        pem_str,
        label,
        case(TEST_PEM_CERT1, Label::Certificate),
        case(TEST_PEM_CERT2, Label::Certificate)
    )]
    fn test_pem_roundtrip(pem_str: &str, label: Label) {
        let original_pem: Pem = pem_str.parse().unwrap();
        let decoded: Vec<u8> = original_pem.decode().unwrap();
        let re_encoded_pem = Pem::from_bytes(label, &decoded);

        // Verify the content is the same
        let re_decoded: Vec<u8> = re_encoded_pem.decode().unwrap();
        assert_eq!(decoded, re_decoded);
    }

    #[rstest]
    #[case::single(vec![TEST_PEM_CERT1], "\n", 1)]
    #[case::multiple(vec![TEST_PEM_CERT1, TEST_PEM_CERT2], "\n", 2)]
    #[case::with_whitespace(vec![TEST_PEM_CERT1, TEST_PEM_CERT2], "\n\n\n", 2)]
    #[case::no_trailing_newline(vec![TEST_PEM_CERT1, TEST_PEM_CERT2], "", 2)]
    fn test_parse_many(#[case] certs: Vec<&str>, #[case] sep: &str, #[case] expected_count: usize) {
        let input = certs
            .iter()
            .map(|c| c.trim_end())
            .collect::<Vec<_>>()
            .join(sep);
        let pems = crate::parse_many(&input).unwrap();
        assert_eq!(pems.len(), expected_count);
    }

    #[test]
    fn test_parse_many_empty() {
        let result = crate::parse_many("");
        assert!(result.is_err());
    }
}
