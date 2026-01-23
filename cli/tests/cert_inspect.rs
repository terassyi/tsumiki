use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn test_cert_path(name: &str) -> String {
    project_root()
        .join("examples/certs")
        .join(name)
        .to_string_lossy()
        .to_string()
}

fn tsumiki() -> Command {
    let bin_path = project_root().join("target/debug/tsumiki");
    let mut cmd = Command::new(bin_path);
    cmd.current_dir(project_root());
    cmd
}

#[test]
fn test_cert_inspect_file_brief() {
    tsumiki()
        .args([
            "cert",
            "inspect",
            &test_cert_path("server.crt"),
            "-o",
            "brief",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("CN=localhost"));
}

#[test]
fn test_cert_inspect_file_text() {
    tsumiki()
        .args(["cert", "inspect", &test_cert_path("server.crt")])
        .assert()
        .success()
        .stdout(predicate::str::contains("Certificate:"))
        .stdout(predicate::str::contains("Subject:"));
}

#[test]
fn test_cert_inspect_show_subject() {
    tsumiki()
        .args([
            "cert",
            "inspect",
            &test_cert_path("server.crt"),
            "--show-subject",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Subject:"))
        .stdout(predicate::str::contains("CN=localhost"));
}

#[test]
fn test_cert_inspect_show_issuer() {
    tsumiki()
        .args([
            "cert",
            "inspect",
            &test_cert_path("server.crt"),
            "--show-issuer",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Issuer:"));
}

#[test]
fn test_cert_inspect_show_dates() {
    tsumiki()
        .args([
            "cert",
            "inspect",
            &test_cert_path("server.crt"),
            "--show-dates",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Not Before:"))
        .stdout(predicate::str::contains("Not After:"));
}

#[test]
fn test_cert_inspect_show_serial() {
    tsumiki()
        .args([
            "cert",
            "inspect",
            &test_cert_path("server.crt"),
            "--show-serial",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Serial Number:"));
}

#[test]
fn test_cert_inspect_json_output() {
    tsumiki()
        .args([
            "cert",
            "inspect",
            &test_cert_path("server.crt"),
            "-o",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"tbs_certificate\""));
}

#[test]
fn test_cert_inspect_yaml_output() {
    tsumiki()
        .args([
            "cert",
            "inspect",
            &test_cert_path("server.crt"),
            "-o",
            "yaml",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("tbs_certificate:"));
}

#[test]
fn test_cert_inspect_file_not_found() {
    tsumiki()
        .args(["cert", "inspect", "nonexistent.pem"])
        .assert()
        .failure();
}

#[test]
fn test_cert_inspect_remote_and_file_exclusive() {
    tsumiki()
        .args([
            "cert",
            "inspect",
            "--remote",
            "example.com",
            &test_cert_path("server.crt"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--remote cannot be used with file input",
        ));
}

#[test]
fn test_cert_inspect_remote() {
    tsumiki()
        .args(["cert", "inspect", "--remote", "google.com", "-o", "brief"])
        .assert()
        .success()
        .stdout(predicate::str::contains("google.com"));
}

#[test]
fn test_cert_inspect_remote_chain() {
    tsumiki()
        .args([
            "cert",
            "inspect",
            "--remote",
            "google.com",
            "--show-subject",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("--- Certificate"))
        .stdout(predicate::str::contains("Subject:"));
}

#[test]
fn test_cert_inspect_ca_certificate() {
    tsumiki()
        .args(["cert", "inspect", &test_cert_path("ca.crt"), "-o", "brief"])
        .assert()
        .success();
}

#[test]
fn test_cert_inspect_check_self_signed() {
    tsumiki()
        .args([
            "cert",
            "inspect",
            &test_cert_path("ca.crt"),
            "--check-self-signed",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Self-Signed:"));
}

// Certificate chain tests

#[test]
fn test_cert_inspect_chain_file() {
    tsumiki()
        .args(["cert", "inspect", &test_cert_path("chain.pem")])
        .assert()
        .success()
        .stdout(predicate::str::contains("--- Certificate 0 ---"))
        .stdout(predicate::str::contains("--- Certificate 1 ---"))
        .stdout(predicate::str::contains("CN=localhost"))
        .stdout(predicate::str::contains("CN=Tsumiki Example CA"));
}

#[test]
fn test_cert_inspect_chain_brief() {
    tsumiki()
        .args([
            "cert",
            "inspect",
            &test_cert_path("chain.pem"),
            "-o",
            "brief",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("CN=localhost"))
        .stdout(predicate::str::contains("CN=Tsumiki Example CA"));
}

#[test]
fn test_cert_inspect_chain_show_subject() {
    tsumiki()
        .args([
            "cert",
            "inspect",
            &test_cert_path("chain.pem"),
            "--show-subject",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("--- Certificate 0 ---"))
        .stdout(predicate::str::contains("--- Certificate 1 ---"));
}

// JSON output structure tests

#[test]
fn test_cert_inspect_json_structure() {
    let output = tsumiki()
        .args([
            "cert",
            "inspect",
            &test_cert_path("server.crt"),
            "-o",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");

    // Single certificate is output as a direct object
    assert!(json.is_object(), "JSON output should be an object");

    // Verify certificate structure
    assert!(json.get("tbs_certificate").is_some());
    assert!(json.get("signature_algorithm").is_some());
    assert!(json.get("signature_value").is_some());

    // Verify tbs_certificate structure
    let tbs = json.get("tbs_certificate").unwrap();
    assert!(tbs.get("version").is_some());
    assert!(tbs.get("serial_number").is_some());
    assert!(tbs.get("issuer").is_some());
    assert!(tbs.get("subject").is_some());
    assert!(tbs.get("validity").is_some());
}

#[test]
fn test_cert_inspect_chain_json_structure() {
    let output = tsumiki()
        .args([
            "cert",
            "inspect",
            &test_cert_path("chain.pem"),
            "-o",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");

    // Chain is output as { "certificates": [...] }
    assert!(json.is_object(), "JSON output should be an object");
    let certs = json
        .get("certificates")
        .expect("should have certificates field")
        .as_array()
        .expect("certificates should be an array");

    assert_eq!(certs.len(), 2, "Chain should have 2 certificates");

    // Verify both certificates have proper structure
    for cert in certs {
        assert!(cert.get("tbs_certificate").is_some());
        assert!(cert.get("signature_algorithm").is_some());
        assert!(cert.get("signature_value").is_some());
    }
}

#[test]
fn test_cert_inspect_json_validity_dates() {
    let output = tsumiki()
        .args([
            "cert",
            "inspect",
            &test_cert_path("server.crt"),
            "-o",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");
    let validity = json
        .get("tbs_certificate")
        .unwrap()
        .get("validity")
        .unwrap();

    assert!(validity.get("not_before").is_some());
    assert!(validity.get("not_after").is_some());
}

#[test]
fn test_cert_inspect_json_extensions() {
    let output = tsumiki()
        .args([
            "cert",
            "inspect",
            &test_cert_path("server.crt"),
            "-o",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");
    let extensions = json
        .get("tbs_certificate")
        .unwrap()
        .get("extensions")
        .unwrap();

    // Extensions is an object with extension names as keys
    assert!(extensions.is_object(), "Extensions should be an object");
    assert!(
        extensions.get("basic_constraints").is_some(),
        "Should have basic_constraints"
    );
    assert!(
        extensions.get("key_usage").is_some(),
        "Should have key_usage"
    );
    assert!(
        extensions.get("subject_alt_name").is_some(),
        "Should have subject_alt_name"
    );
}
