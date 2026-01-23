//! Certificate Chain
//!
//! A certificate chain is an ordered sequence of certificates where:
//! - The first certificate is the end-entity (leaf) certificate
//! - Each subsequent certificate is the issuer of the previous one
//! - The last certificate is typically a root CA (self-signed) or
//!   an intermediate CA trusted by the system

use std::ops::Deref;
use std::str::FromStr;

use pem::FromPem;
use serde::{Deserialize, Serialize};

use crate::Certificate;
use crate::error::Error;
use crate::extensions::BasicConstraints;

/// An ordered chain of X.509 certificates.
///
/// The chain is ordered from end-entity to root:
/// - Index 0: End-entity (leaf) certificate
/// - Index 1..n-1: Intermediate CA certificates
/// - Index n: Root CA certificate (optional, may be omitted)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateChain {
    certificates: Vec<Certificate>,
}

impl CertificateChain {
    /// Create a new certificate chain from a vector of certificates.
    ///
    /// The certificates should be ordered from end-entity to root.
    pub fn new(certificates: Vec<Certificate>) -> Self {
        Self { certificates }
    }

    /// Create an empty certificate chain.
    pub fn empty() -> Self {
        Self {
            certificates: Vec::new(),
        }
    }

    /// Returns the end-entity (leaf) certificate, if present.
    pub fn end_entity(&self) -> Option<&Certificate> {
        self.certificates.first()
    }

    /// Returns the intermediate certificates (all certificates except the end-entity).
    ///
    /// In a TLS certificate chain, the root CA is typically not included
    /// (it's expected to be in the client's trust store), so this returns
    /// all certificates after the end-entity.
    pub fn intermediates(&self) -> &[Certificate] {
        if self.certificates.len() <= 1 {
            &[]
        } else {
            &self.certificates[1..]
        }
    }

    /// Returns the number of certificates in the chain.
    pub fn len(&self) -> usize {
        self.certificates.len()
    }

    /// Returns true if the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.certificates.is_empty()
    }

    /// Returns an iterator over the certificates in the chain.
    pub fn iter(&self) -> std::slice::Iter<'_, Certificate> {
        self.certificates.iter()
    }

    /// Returns the certificates as a slice.
    pub fn as_slice(&self) -> &[Certificate] {
        &self.certificates
    }

    /// Consumes the chain and returns the underlying vector.
    pub fn into_vec(self) -> Vec<Certificate> {
        self.certificates
    }

    /// Adds a certificate to the end of the chain.
    pub fn push(&mut self, cert: Certificate) {
        self.certificates.push(cert);
    }

    /// Returns the root CA certificate if the last certificate in the chain is a root CA.
    ///
    /// A certificate is considered a root CA if it is:
    /// - Self-signed (Subject == Issuer)
    /// - Has BasicConstraints extension with CA=TRUE
    ///
    /// Note: TLS certificate chains typically do not include the root CA,
    /// so this method may return `None` even for valid chains.
    pub fn root(&self) -> Option<&Certificate> {
        self.certificates.last().filter(|cert| {
            let is_ca = cert
                .extension::<BasicConstraints>()
                .ok()
                .flatten()
                .map(|bc| bc.ca)
                .unwrap_or(false);

            cert.is_self_signed() && is_ca
        })
    }
}

impl From<Vec<Certificate>> for CertificateChain {
    fn from(certificates: Vec<Certificate>) -> Self {
        Self::new(certificates)
    }
}

impl From<Certificate> for CertificateChain {
    fn from(cert: Certificate) -> Self {
        Self::new(vec![cert])
    }
}

impl FromIterator<Certificate> for CertificateChain {
    fn from_iter<I: IntoIterator<Item = Certificate>>(iter: I) -> Self {
        Self::new(iter.into_iter().collect())
    }
}

impl Deref for CertificateChain {
    type Target = [Certificate];

    fn deref(&self) -> &Self::Target {
        &self.certificates
    }
}

impl<'a> IntoIterator for &'a CertificateChain {
    type Item = &'a Certificate;
    type IntoIter = std::slice::Iter<'a, Certificate>;

    fn into_iter(self) -> Self::IntoIter {
        self.certificates.iter()
    }
}

impl IntoIterator for CertificateChain {
    type Item = Certificate;
    type IntoIter = std::vec::IntoIter<Certificate>;

    fn into_iter(self) -> Self::IntoIter {
        self.certificates.into_iter()
    }
}

impl FromPem for CertificateChain {
    type Error = Error;

    fn expected_label() -> pem::Label {
        pem::Label::Certificate
    }

    fn from_pem(pem: &pem::Pem) -> Result<Self, Self::Error> {
        let cert = Certificate::from_pem(pem)?;
        Ok(Self::from(cert))
    }
}

impl FromStr for CertificateChain {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let pems = pem::parse_many(s)?;
        let certs = pems
            .iter()
            .filter(|p| p.label() == pem::Label::Certificate)
            .map(Certificate::from_pem)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::new(certs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    // Self-signed CA certificate with BasicConstraints CA=TRUE
    const TEST_CERT_V3_CA: &str = r"-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----";

    // End entity certificate (not self-signed, no CA constraint)
    const TEST_CERT_V3_EE: &str = r"-----BEGIN CERTIFICATE-----
MIIDrDCCApSgAwIBAgIJAJe8Uwe3KSplMA0GCSqGSIb3DQEBCwUAMFUxCzAJBgNV
BAYTAkpQMQ4wDAYDVQQIDAVUb2t5bzEYMBYGA1UECgwPVHN1bWlraSBQcm9qZWN0
MRwwGgYDVQQDDBNzZXJ2ZXIudHN1bWlraS50ZXN0MB4XDTI1MTIyODA5NTQyNloX
DTM1MTIyNjA5NTQyNlowVTELMAkGA1UEBhMCSlAxDjAMBgNVBAgMBVRva3lvMRgw
FgYDVQQKDA9Uc3VtaWtpIFByb2plY3QxHDAaBgNVBAMME3NlcnZlci50c3VtaWtp
LnRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDtc3gArhY+2ZPa
EEodwZSdV64JfI6LP/VJdCrJkrWw+cAjIoPd5IWYYM4quJjyS0sKJdOcG1ox+Vyk
V2Mx3Tu7a9HfkL94UVC6wkuqxn6ss1nF3WDwRpMKdk2osAkfC2DEy+gUTbSUP7nF
xLfzWnHsiKf7OQdnvqi1+ky77c2oYCsR4Gmc45/pmma8laHtD15nLrNw6QPNFXgi
tqVRsJAd887FP35vsxlKLSt1KtDplXPwVdTKIEoAfC3rbfS2RtHoLz2iScS4m97R
H2yd71R04UaBluloV6eVn+SYx6toglm2TigxQG/v0i/b4J5+tTLRFWSbSw6IXfPv
IpeO5QybAgMBAAGjfzB9MB0GA1UdDgQWBBQ3BSW6F/y0r7M6za10RFuSkEjWADAO
BgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMC0G
A1UdEQQmMCSCDHRzdW1pa2kudGVzdIIOKi50c3VtaWtpLnRlc3SHBH8AAAEwDQYJ
KoZIhvcNAQELBQADggEBAK+YTpe3eg622ATN9mXMUxyD+qHLdsjqaoe1XHyjZyZ7
uEERNtSw2FBxzg1YDh2dEZtWc8ybwPwJwpySo/7dq53BWZW6aBW0kMp3GLC/Od6C
k+8EFoao7SFr16XsGQJD4DNoKVvHKAE2FworjXdRUFswwtkoD8gdsK2sf2vgnBv8
HAVm7HukOAHpl5Cv4uoD57p1kfMH4T7q1yKz5e9kQi3Ta5vJzydMluZzgJQUxif1
3nAQuaKAyIZfiF4QTlaA8i8nodjhZeM6A0ZomnZeCVjigqkr706tbakcyyrbsjM4
I36SjnCvZLfTAZy2PzjD+JS43m/+2ydsdhU7+aUoR+w=
-----END CERTIFICATE-----";

    fn parse_cert(pem_str: &str) -> Certificate {
        pem_str.parse().unwrap()
    }

    #[rstest]
    #[case::empty(vec![], false)]
    #[case::single_ee(vec![TEST_CERT_V3_EE], false)]
    #[case::single_ca(vec![TEST_CERT_V3_CA], true)]
    #[case::ee_and_ca(vec![TEST_CERT_V3_EE, TEST_CERT_V3_CA], true)]
    #[case::ee_and_ee(vec![TEST_CERT_V3_EE, TEST_CERT_V3_EE], false)]
    #[case::ca_and_ee(vec![TEST_CERT_V3_CA, TEST_CERT_V3_EE], false)]
    fn test_root(#[case] cert_pems: Vec<&str>, #[case] expected_has_root: bool) {
        let certs: Vec<_> = cert_pems.iter().map(|pem| parse_cert(pem)).collect();
        let chain = CertificateChain::new(certs);

        assert_eq!(chain.root().is_some(), expected_has_root);
    }
}
