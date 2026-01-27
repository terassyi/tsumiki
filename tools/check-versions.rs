#!/usr/bin/env rust-script
//! Check that workspace member versions match their dependency versions.
//!
//! ```cargo
//! [dependencies]
//! toml = "0.8"
//! glob = "0.3"
//! ```

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or(Path::new("."));

    let mut versions: HashMap<String, String> = HashMap::new();
    let mut errors = Vec::new();

    // First pass: collect all package versions
    for entry in glob::glob(&format!("{}/**/Cargo.toml", workspace_root.display())).unwrap() {
        let path = match entry {
            Ok(p) => p,
            Err(_) => continue,
        };

        if path.to_string_lossy().contains("target") {
            continue;
        }

        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let toml: toml::Value = match content.parse() {
            Ok(t) => t,
            Err(_) => continue,
        };

        if let Some(package) = toml.get("package") {
            if let (Some(name), Some(version)) = (
                package.get("name").and_then(|v| v.as_str()),
                package.get("version").and_then(|v| v.as_str()),
            ) {
                versions.insert(name.to_string(), version.to_string());
            }
        }
    }

    // Second pass: check dependencies
    for entry in glob::glob(&format!("{}/**/Cargo.toml", workspace_root.display())).unwrap() {
        let path = match entry {
            Ok(p) => p,
            Err(_) => continue,
        };

        if path.to_string_lossy().contains("target") {
            continue;
        }

        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let toml: toml::Value = match content.parse() {
            Ok(t) => t,
            Err(_) => continue,
        };

        let package_name = toml
            .get("package")
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("unknown");

        for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
            if let Some(deps) = toml.get(section).and_then(|d| d.as_table()) {
                for (dep_name, dep_value) in deps {
                    // Only check workspace members (those starting with "tsumiki")
                    if !dep_name.starts_with("tsumiki") {
                        continue;
                    }

                    let dep_version = match dep_value {
                        toml::Value::Table(t) => t.get("version").and_then(|v| v.as_str()),
                        toml::Value::String(s) => Some(s.as_str()),
                        _ => None,
                    };

                    if let Some(expected_version) = versions.get(dep_name) {
                        match dep_version {
                            Some(v) if v != expected_version => {
                                errors.push(format!(
                                    "{}: {} requires {} = {}, but package version is {}",
                                    path.display(),
                                    package_name,
                                    dep_name,
                                    v,
                                    expected_version
                                ));
                            }
                            None => {
                                errors.push(format!(
                                    "{}: {} depends on {} without version specification",
                                    path.display(),
                                    package_name,
                                    dep_name
                                ));
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    if errors.is_empty() {
        println!("All workspace dependency versions are consistent.");
        ExitCode::SUCCESS
    } else {
        eprintln!("Version mismatches found:");
        for error in &errors {
            eprintln!("  {}", error);
        }
        ExitCode::FAILURE
    }
}
