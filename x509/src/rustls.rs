//! Conversion between rustls-pki-types and tsumiki types.
//!
//! This module is only compiled when the `rustls` feature is enabled.

use rustls_pki_types::CertificateDer;

use crate::Certificate;
use crate::error::Error;
use asn1::ASN1Object;
use tsumiki::decoder::Decoder;
use tsumiki::encoder::Encoder;

/// Converts a `CertificateDer` to a `Certificate`.
impl TryFrom<CertificateDer<'_>> for Certificate {
    type Error = Error;

    fn try_from(cert_der: CertificateDer<'_>) -> Result<Self, Self::Error> {
        let der_bytes: &[u8] = cert_der.as_ref();
        let der = der_bytes
            .decode()
            .map_err(|e| Error::InvalidCertificate(format!("failed to parse DER: {}", e)))?;
        let asn1_obj = der.decode().map_err(Error::InvalidASN1)?;
        asn1_obj.decode()
    }
}

/// Converts a `&Certificate` to a `CertificateDer<'static>`.
impl TryFrom<&Certificate> for CertificateDer<'static> {
    type Error = Error;

    fn try_from(cert: &Certificate) -> Result<Self, Self::Error> {
        let asn1_obj: ASN1Object = cert.encode()?;
        let der = asn1_obj.encode().map_err(Error::InvalidASN1)?;
        let bytes = der
            .encode()
            .map_err(|e| Error::DerEncodingError(format!("{}", e)))?;
        Ok(CertificateDer::from(bytes))
    }
}

/// Converts a `Certificate` to a `CertificateDer<'static>`.
impl TryFrom<Certificate> for CertificateDer<'static> {
    type Error = Error;

    fn try_from(cert: Certificate) -> Result<Self, Self::Error> {
        CertificateDer::try_from(&cert)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::Extensions;
    use crate::{Validity, Version};
    use asn1::{BitString, Element, Integer, ObjectIdentifier, OctetString};
    use chrono::NaiveDateTime;
    use pem::Pem;
    use pkix_types::{
        AlgorithmIdentifier, AlgorithmParameters, CertificateSerialNumber, Name,
        SubjectPublicKeyInfo,
    };
    use rstest::rstest;
    use std::str::FromStr;

    // Test certificate V1 (RSA 2048-bit, no extensions)
    const TEST_CERT_V1_PEM: &str = r"-----BEGIN CERTIFICATE-----
MIIC3jCCAcYCCQD36esrlVEnfTANBgkqhkiG9w0BAQsFADAxMQswCQYDVQQGEwJK
UDEQMA4GA1UECgwHVHN1bWlraTEQMA4GA1UEAwwHdGVzdC12MTAeFw0yNTEyMjgw
OTU0MDlaFw0zNTEyMjYwOTU0MDlaMDExCzAJBgNVBAYTAkpQMRAwDgYDVQQKDAdU
c3VtaWtpMRAwDgYDVQQDDAd0ZXN0LXYxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEA4wIzS7OSAX5BGtOggT2npL7j07MK7tp8LdLQtVv4STTTldq5nB21
msh7WjrJ/DVzBljyoDOS+rRCe/33SakVCWtsvgXmlbr6/HYiHEFIeMj1U5qFHBPI
/yccZdwW0FdaKNoMDyaa6ii/uZ0mdm9Rh2BTmM6jbsKghGOPZNtt7cfPDOQEkbuX
tdTS8YNRxULsIVrKi3GEsITZylvpzaS2k8atsQyayE2I/wVCBuwnP8JKE7ZjXBCu
D1+RpXdeVIJFwG9oe7X1ejurwb+VRTZzLFr+p9f6D/1PXzjWGxxohG9ACKaMlWqO
+Ge0mODKwo7D+Z+2uR1t0W8eZp/Mg7PjHQIDAQABMA0GCSqGSIb3DQEBCwUAA4IB
AQAWbVDRrPKoZ+kAOKdl5rZ9DOtzTnAkYTIXKiI5kKsZQ05Rz0N3zjtv6WieHu4f
STa6A1EjsESx78VhqiWD451lfJTAPvofzY7f32ZrMhGPI5GIGQJXm3ykFNC57z/g
hZS04cvj1lqaWdp5DQ9ZrIS9PaBVcY+RtuRmIpbSuZukjGvG/W76fqajZWRwG6yW
lbz1C5n4m8n+m8zTLy28nxX7Fm/8h0c3/jjrJnkYQ98JIQuj9vyhH0SHloP/uoTI
arWjLcCEZ6DqqXiKc4ojkQvARkufeKpztUlgi7lrTfk6hG0RWp0jmY/OyV3OeTeP
ZyI1Mobuf6I2De0X96VkC+JV
-----END CERTIFICATE-----";

    // Test certificate V3 CA (RSA 4096-bit, with CA extensions)
    const TEST_CERT_V3_CA_PEM: &str = r"-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----";

    // Test certificate V3 End Entity (RSA 2048-bit, with SAN extension)
    const TEST_CERT_V3_EE_PEM: &str = r"-----BEGIN CERTIFICATE-----
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

    // Test certificate V3 ECDSA P-256 CA
    const TEST_CERT_V3_ECDSA_P256_PEM: &str = r"-----BEGIN CERTIFICATE-----
MIICAjCCAaigAwIBAgIJAKtsTdFGb77kMAoGCCqGSM49BAMCMFQxCzAJBgNVBAYT
AkpQMQ4wDAYDVQQIDAVUb2t5bzEYMBYGA1UECgwPVHN1bWlraSBQcm9qZWN0MRsw
GQYDVQQDDBJlYy1jYS50c3VtaWtpLnRlc3QwHhcNMjUxMjI4MTAyOTI0WhcNMzUx
MjI2MTAyOTI0WjBUMQswCQYDVQQGEwJKUDEOMAwGA1UECAwFVG9reW8xGDAWBgNV
BAoMD1RzdW1pa2kgUHJvamVjdDEbMBkGA1UEAwwSZWMtY2EudHN1bWlraS50ZXN0
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7sCe86byM+Pj8cbpthxg1eMhQ/MN
xgsLmedraZo9OXStkYhMFFqcFccwiIXLiWJgiIsVVpGn02uLpB4SOlu4FKNjMGEw
HQYDVR0OBBYEFDWBtOp+1zCPl3dUA52ZjY7C2F1tMB8GA1UdIwQYMBaAFDWBtOp+
1zCPl3dUA52ZjY7C2F1tMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGG
MAoGCCqGSM49BAMCA0gAMEUCIEtUSow92vKt7bYbjRszN8Db2UR6BSaz+q7kxo+X
Z1s+AiEAsj0FnruwSPLI6M1KzOjeNKTmFeDyYIw3zF1DVdCFOmc=
-----END CERTIFICATE-----";

    // Test certificate V3 ECDSA P-384
    const TEST_CERT_V3_ECDSA_P384_PEM: &str = r"-----BEGIN CERTIFICATE-----
MIICOjCCAcGgAwIBAgIJAPSkPOMqZro8MAoGCCqGSM49BAMCMEQxCzAJBgNVBAYT
AkpQMRgwFgYDVQQKDA9Uc3VtaWtpIFByb2plY3QxGzAZBgNVBAMMEmVjMzg0LnRz
dW1pa2kudGVzdDAeFw0yNTEyMjgxMDI5NDhaFw0zNTEyMjYxMDI5NDhaMEQxCzAJ
BgNVBAYTAkpQMRgwFgYDVQQKDA9Uc3VtaWtpIFByb2plY3QxGzAZBgNVBAMMEmVj
Mzg0LnRzdW1pa2kudGVzdDB2MBAGByqGSM49AgEGBSuBBAAiA2IABMZzYCpsCn/q
OkGGfxphk+24hS47tW849Z2xjzh2XJqLlKrcPcO+5zpWri7WNuo/DrsPXIgJdTxx
/b97Rq25TgtRLem5rux4uN0gMxf5qcRotqSXrN5eL7i8xPGrWBxw9aN/MH0wHQYD
VR0OBBYEFGVQxde1MT37ma9vjNCp9WVdUXsCMA4GA1UdDwEB/wQEAwIFoDAdBgNV
HSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwLQYDVR0RBCYwJIIMdHN1bWlraS50
ZXN0gg4qLnRzdW1pa2kudGVzdIcEfwAAATAKBggqhkjOPQQDAgNnADBkAjAVRQuq
66V6ZQQoCFGNDUbki4yWd4pKp2x2igVxJ+8yAJj0hSERlRP1cpnq5CWhOXgCMExy
sDuylxpp9szuj0bvfcO9JcS+V/5gPK0+5QxawidqE/ERQgBD9yj8ouw4F6BmKg==
-----END CERTIFICATE-----";

    fn build_test_certificate(cn: &str, serial: Vec<u8>, is_ca: bool) -> Certificate {
        let version_elem = Element::ContextSpecific {
            slot: 0,
            constructed: true,
            element: Box::new(Element::Integer(Integer::from(vec![0x02]))),
        };
        let version: Version = version_elem.decode().unwrap();

        let serial_number = CertificateSerialNumber::from(Integer::from(serial));

        let signature = AlgorithmIdentifier::new_with_params(
            ObjectIdentifier::from_str(AlgorithmIdentifier::OID_SHA256_WITH_RSA_ENCRYPTION)
                .unwrap(),
            AlgorithmParameters::Null,
        );

        let name_elem = Element::Sequence(vec![Element::Set(vec![Element::Sequence(vec![
            Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.4.3").unwrap()),
            Element::UTF8String(cn.to_string()),
        ])])]);
        let name: Name = name_elem.decode().unwrap();

        let not_before =
            NaiveDateTime::parse_from_str("2024-01-01 00:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
        let not_after =
            NaiveDateTime::parse_from_str("2025-01-01 00:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
        let validity_elem = Element::Sequence(vec![
            Element::UTCTime(not_before),
            Element::UTCTime(not_after),
        ]);
        let validity: Validity = validity_elem.decode().unwrap();

        let spki = SubjectPublicKeyInfo::new(
            AlgorithmIdentifier::new_with_params(
                ObjectIdentifier::from_str(AlgorithmIdentifier::OID_RSA_ENCRYPTION).unwrap(),
                AlgorithmParameters::Null,
            ),
            BitString::new(0, vec![0x00, 0x30, 0x0d]),
        );

        let ca_byte = if is_ca { 0xff } else { 0x00 };
        let extensions_elem = Element::ContextSpecific {
            slot: 3,
            constructed: true,
            element: Box::new(Element::Sequence(vec![Element::Sequence(vec![
                Element::ObjectIdentifier(ObjectIdentifier::from_str("2.5.29.19").unwrap()),
                Element::Boolean(true),
                Element::OctetString(OctetString::from(vec![0x30, 0x03, 0x01, 0x01, ca_byte])),
            ])])),
        };
        let extensions: Extensions = extensions_elem.decode().unwrap();

        let tbs_elem = Element::Sequence(vec![
            version.encode().unwrap(),
            serial_number.encode().unwrap(),
            signature.encode().unwrap(),
            name.encode().unwrap(),
            validity.encode().unwrap(),
            name.encode().unwrap(),
            spki.encode().unwrap(),
            extensions.encode().unwrap(),
        ]);

        let signature_value = BitString::new(0, vec![0xde, 0xad, 0xbe, 0xef]);

        let cert_elem = Element::Sequence(vec![
            tbs_elem,
            signature.encode().unwrap(),
            Element::BitString(signature_value),
        ]);

        cert_elem.decode().unwrap()
    }

    #[rstest]
    #[case::simple_cert("Test CA", vec![0x01], true)]
    #[case::end_entity("End Entity", vec![0x01, 0x02, 0x03, 0x04], false)]
    #[case::long_serial("Long Serial", vec![0x48, 0xc3, 0x54, 0x8e, 0x4a, 0x5e, 0xe7, 0x64], true)]
    fn test_certificate_to_certificate_der(
        #[case] cn: &str,
        #[case] serial: Vec<u8>,
        #[case] is_ca: bool,
    ) {
        let cert = build_test_certificate(cn, serial, is_ca);
        let cert_der = CertificateDer::try_from(&cert).unwrap();
        assert!(!cert_der.as_ref().is_empty());
    }

    #[rstest]
    #[case::simple_cert("Test CA", vec![0x01], true)]
    #[case::end_entity("End Entity", vec![0x01, 0x02, 0x03, 0x04], false)]
    #[case::long_serial("Long Serial", vec![0x48, 0xc3, 0x54, 0x8e, 0x4a, 0x5e, 0xe7, 0x64], true)]
    fn test_certificate_der_to_certificate(
        #[case] cn: &str,
        #[case] serial: Vec<u8>,
        #[case] is_ca: bool,
    ) {
        let cert = build_test_certificate(cn, serial.clone(), is_ca);
        let cert_der = CertificateDer::try_from(&cert).unwrap();
        let cert_back = Certificate::try_from(cert_der).unwrap();

        assert_eq!(
            cert.tbs_certificate().version(),
            cert_back.tbs_certificate().version()
        );
        assert_eq!(
            cert.tbs_certificate().serial_number(),
            cert_back.tbs_certificate().serial_number()
        );
    }

    #[rstest]
    #[case::simple_cert("Test CA", vec![0x01], true)]
    #[case::end_entity("End Entity", vec![0x01, 0x02, 0x03, 0x04], false)]
    #[case::long_serial("Long Serial", vec![0x48, 0xc3, 0x54, 0x8e, 0x4a, 0x5e, 0xe7, 0x64], true)]
    fn test_certificate_roundtrip(#[case] cn: &str, #[case] serial: Vec<u8>, #[case] is_ca: bool) {
        let cert = build_test_certificate(cn, serial, is_ca);

        let cert_der = CertificateDer::try_from(&cert).unwrap();
        let cert_roundtrip = Certificate::try_from(cert_der).unwrap();

        let original_der = CertificateDer::try_from(&cert).unwrap();
        let roundtrip_der = CertificateDer::try_from(&cert_roundtrip).unwrap();

        assert_eq!(original_der.as_ref(), roundtrip_der.as_ref());
    }

    #[rstest]
    #[case::simple_cert("Test CA", vec![0x01], true)]
    #[case::end_entity("End Entity", vec![0x01, 0x02, 0x03, 0x04], false)]
    fn test_certificate_owned_conversion(
        #[case] cn: &str,
        #[case] serial: Vec<u8>,
        #[case] is_ca: bool,
    ) {
        let cert = build_test_certificate(cn, serial, is_ca);
        let cert_der = CertificateDer::try_from(cert).unwrap();
        assert!(!cert_der.as_ref().is_empty());
    }

    #[rstest]
    #[case::v1_rsa2048(TEST_CERT_V1_PEM, Version::V1)]
    #[case::v3_ca_rsa4096(TEST_CERT_V3_CA_PEM, Version::V3)]
    #[case::v3_ee_rsa2048(TEST_CERT_V3_EE_PEM, Version::V3)]
    #[case::v3_ecdsa_p256(TEST_CERT_V3_ECDSA_P256_PEM, Version::V3)]
    #[case::v3_ecdsa_p384(TEST_CERT_V3_ECDSA_P384_PEM, Version::V3)]
    fn test_pem_to_certificate_to_certificate_der(
        #[case] pem_str: &str,
        #[case] expected_version: Version,
    ) {
        // PEM -> Certificate
        let pem = Pem::from_str(pem_str).unwrap();
        let cert: Certificate = pem.decode().unwrap();
        assert_eq!(cert.tbs_certificate().version(), &expected_version);

        // Certificate -> CertificateDer
        let cert_der = CertificateDer::try_from(&cert).unwrap();
        assert!(!cert_der.as_ref().is_empty());

        // CertificateDer -> Certificate (roundtrip)
        let cert_back = Certificate::try_from(cert_der).unwrap();
        assert_eq!(
            cert.tbs_certificate().version(),
            cert_back.tbs_certificate().version()
        );
        assert_eq!(
            cert.tbs_certificate().serial_number(),
            cert_back.tbs_certificate().serial_number()
        );
        assert_eq!(
            cert.tbs_certificate().issuer(),
            cert_back.tbs_certificate().issuer()
        );
        assert_eq!(
            cert.tbs_certificate().subject(),
            cert_back.tbs_certificate().subject()
        );
    }

    #[rstest]
    #[case::v1_rsa2048(TEST_CERT_V1_PEM)]
    #[case::v3_ca_rsa4096(TEST_CERT_V3_CA_PEM)]
    #[case::v3_ee_rsa2048(TEST_CERT_V3_EE_PEM)]
    #[case::v3_ecdsa_p256(TEST_CERT_V3_ECDSA_P256_PEM)]
    #[case::v3_ecdsa_p384(TEST_CERT_V3_ECDSA_P384_PEM)]
    fn test_pem_roundtrip_der_bytes_match(#[case] pem_str: &str) {
        // PEM -> DER bytes (original)
        let pem = Pem::from_str(pem_str).unwrap();
        let original_der_bytes: Vec<u8> = pem.decode().unwrap();

        // PEM -> Certificate -> CertificateDer
        let cert: Certificate = Pem::from_str(pem_str).unwrap().decode().unwrap();
        let cert_der = CertificateDer::try_from(&cert).unwrap();

        // Compare DER bytes
        assert_eq!(original_der_bytes, cert_der.as_ref());
    }
}
