mod common;

use common::{fixture_path, tsumiki};
use predicates::prelude::*;

#[test]
fn test_crl_inspect_text() {
    tsumiki()
        .args(["crl", "inspect", &fixture_path("sample.crl")])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Certificate Revocation List (CRL):",
        ))
        .stdout(predicate::str::contains("Version 2"))
        .stdout(predicate::str::contains(
            "Signature Algorithm: sha256WithRSAEncryption",
        ))
        .stdout(predicate::str::contains("Issuer: CN=Tsumiki Test CA"))
        .stdout(predicate::str::contains("X509v3 CRL Number:"))
        .stdout(predicate::str::contains("4096"))
        .stdout(predicate::str::contains("No Revoked Certificates."));
}

#[test]
fn test_crl_inspect_brief() {
    tsumiki()
        .args(["crl", "inspect", "-o", "brief", &fixture_path("sample.crl")])
        .assert()
        .success()
        .stdout(predicate::str::contains("Issuer: CN=Tsumiki Test CA"))
        .stdout(predicate::str::contains("Revoked: 0"));
}

#[test]
fn test_crl_inspect_json() {
    tsumiki()
        .args(["crl", "inspect", "-o", "json", &fixture_path("sample.crl")])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"tbs_cert_list\""))
        .stdout(predicate::str::contains("\"V2\""));
}

#[test]
fn test_crl_inspect_yaml() {
    tsumiki()
        .args(["crl", "inspect", "-o", "yaml", &fixture_path("sample.crl")])
        .assert()
        .success()
        .stdout(predicate::str::contains("tbs_cert_list:"));
}

// CRL with one revoked entry carrying a reasonCode entry extension —
// exercises the "Revoked Certificates" branch and entry-extension display.
#[test]
fn test_crl_inspect_revoked_entry() {
    tsumiki()
        .args(["crl", "inspect", &fixture_path("sample_revoked.crl")])
        .assert()
        .success()
        .stdout(predicate::str::contains("Revoked Certificates:"))
        .stdout(predicate::str::contains("Serial Number: 10:01"))
        .stdout(predicate::str::contains("Revocation Date:"))
        .stdout(predicate::str::contains("CRL entry extensions:"))
        .stdout(predicate::str::contains("X509v3 CRL Reason Code:"))
        .stdout(predicate::str::contains("Key Compromise"));
}

#[test]
fn test_crl_inspect_revoked_brief() {
    tsumiki()
        .args([
            "crl",
            "inspect",
            "-o",
            "brief",
            &fixture_path("sample_revoked.crl"),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Revoked: 1"));
}

// DER-encoded CRL (no PEM armor) — exercises the DER fallback parse path.
// Fixture generated with: openssl crl -in sample.crl -outform DER -out sample_der.crl
#[test]
fn test_crl_inspect_der_input() {
    tsumiki()
        .args(["crl", "inspect", &fixture_path("sample_der.crl")])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Certificate Revocation List (CRL):",
        ))
        .stdout(predicate::str::contains("Issuer: CN=Tsumiki Test CA"));
}

// --- filter flags (RFC 5280 §5 field selectors) ---

// A selector flag prints only that field and suppresses the full CRL dump.
#[test]
fn test_crl_inspect_show_issuer() {
    tsumiki()
        .args([
            "crl",
            "inspect",
            &fixture_path("sample.crl"),
            "--show-issuer",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Issuer: CN=Tsumiki Test CA"))
        .stdout(predicate::str::contains("Certificate Revocation List (CRL):").not());
}

#[test]
fn test_crl_inspect_show_dates() {
    tsumiki()
        .args([
            "crl",
            "inspect",
            &fixture_path("sample.crl"),
            "--show-dates",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Last Update:"))
        .stdout(predicate::str::contains("Next Update:"));
}

#[test]
fn test_crl_inspect_show_number() {
    tsumiki()
        .args([
            "crl",
            "inspect",
            &fixture_path("sample.crl"),
            "--show-number",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("CRL Number: 4096"));
}

#[test]
fn test_crl_inspect_list_revoked() {
    tsumiki()
        .args([
            "crl",
            "inspect",
            &fixture_path("sample_revoked.crl"),
            "--list-revoked",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Revoked Certificates:"))
        .stdout(predicate::str::contains("Serial Number: 10:01"))
        .stdout(predicate::str::contains("Revocation Date:"));
}

#[test]
fn test_crl_inspect_list_extensions() {
    tsumiki()
        .args([
            "crl",
            "inspect",
            &fixture_path("sample.crl"),
            "--list-extensions",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("CRL extensions:"))
        .stdout(predicate::str::contains("CRL Number:"));
}

// nextUpdate-based check, mirroring `cert inspect --check-expiry`: valid CRLs
// print "CRL is VALID" and exit 0; expired ones print "CRL is EXPIRED" and
// exit 1. sample.crl's nextUpdate is in the future, so this asserts the VALID
// path. NOTE: this becomes time-dependent once that nextUpdate passes — the
// fixture must then be regenerated with a later nextUpdate.
#[test]
fn test_crl_inspect_check_expiry() {
    tsumiki()
        .args([
            "crl",
            "inspect",
            &fixture_path("sample.crl"),
            "--check-expiry",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("CRL is VALID"));
}

// --max-entries is a modifier on --list-revoked and is rejected on its own.
#[test]
fn test_crl_inspect_max_entries_requires_list_revoked() {
    tsumiki()
        .args([
            "crl",
            "inspect",
            &fixture_path("sample_revoked.crl"),
            "--max-entries",
            "1",
        ])
        .assert()
        .failure();
}

// --max-entries caps the revoked list; the remainder is reported as omitted.
// sample_revoked.crl has one entry, so `--max-entries 0` omits it.
#[test]
fn test_crl_inspect_max_entries() {
    tsumiki()
        .args([
            "crl",
            "inspect",
            &fixture_path("sample_revoked.crl"),
            "--list-revoked",
            "--max-entries",
            "0",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("(1 more omitted)"));
}

#[test]
fn test_crl_inspect_file_not_found() {
    tsumiki()
        .args(["crl", "inspect", "nonexistent.crl"])
        .assert()
        .failure();
}

// Validate the JSON output structure (field names / nesting).
#[test]
fn test_crl_inspect_json_structure() {
    let output = tsumiki()
        .args(["crl", "inspect", "-o", "json", &fixture_path("sample.crl")])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");
    assert!(json.is_object(), "CRL JSON output should be an object");
    assert!(json.get("tbs_cert_list").is_some());
    assert!(json.get("signature_algorithm").is_some());
    assert!(json.get("signature_value").is_some());

    let tbs = json.get("tbs_cert_list").unwrap();
    assert!(tbs.get("version").is_some());
    assert!(tbs.get("issuer").is_some());
    assert!(tbs.get("this_update").is_some());
    assert!(tbs.get("revoked_certificates").is_some());
}
