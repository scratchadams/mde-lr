//! CI validation for the endpoint manifest (manifest/endpoints.toml).
//!
//! These tests ensure the manifest stays syntactically valid as endpoints are
//! added or modified. They deserialize the TOML file and check structural
//! invariants — every endpoint must have required fields, and the meta section
//! must declare a schema version.
//!
//! Semantic validation (checking endpoint paths against upstream MDE docs) is
//! deferred to a future milestone.

use serde::Deserialize;

/// Top-level manifest structure matching the TOML schema.
#[derive(Debug, Deserialize)]
struct Manifest {
    meta: Meta,
    endpoints: Vec<Endpoint>,
}

/// Manifest metadata — tracks schema version and last validation date.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Meta {
    schema_version: u32,
    last_validated: String,
}

/// A single endpoint entry in the manifest.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Endpoint {
    family: String,
    name: String,
    method: String,
    path: String,
    request_content_type: String,
    response_status: u16,
    permissions: Vec<String>,
    implemented: bool,
    #[serde(default)]
    notes: String,
}

#[test]
fn manifest_endpoints_toml_is_valid() {
    // Read and deserialize the manifest to verify structural correctness.
    // This test runs in CI to catch TOML syntax errors and missing fields
    // before they reach main.
    let content = std::fs::read_to_string("manifest/endpoints.toml")
        .expect("manifest/endpoints.toml should exist and be readable");

    let manifest: Manifest =
        toml::from_str(&content).expect("manifest/endpoints.toml should be valid TOML");

    // Schema version must be set (currently 1).
    assert!(
        manifest.meta.schema_version >= 1,
        "schema_version must be at least 1"
    );

    // Must have at least one endpoint defined.
    assert!(
        !manifest.endpoints.is_empty(),
        "manifest should contain at least one endpoint"
    );

    // Every endpoint must have non-empty required fields.
    for ep in &manifest.endpoints {
        assert!(!ep.family.is_empty(), "endpoint family must not be empty");
        assert!(!ep.name.is_empty(), "endpoint name must not be empty");
        assert!(!ep.method.is_empty(), "endpoint method must not be empty");
        assert!(!ep.path.is_empty(), "endpoint path must not be empty");
    }
}

#[test]
fn manifest_has_implemented_live_response_endpoints() {
    // Verify that the four implemented Live Response endpoints are marked
    // as implemented = true. This catches accidental regressions where
    // someone edits the manifest and flips a flag.
    let content = std::fs::read_to_string("manifest/endpoints.toml")
        .expect("manifest/endpoints.toml should exist");

    let manifest: Manifest = toml::from_str(&content).expect("valid TOML");

    let implemented: Vec<&Endpoint> = manifest
        .endpoints
        .iter()
        .filter(|ep| ep.implemented)
        .collect();

    assert!(
        implemented.len() >= 4,
        "at least 4 Live Response endpoints should be marked as implemented, found {}",
        implemented.len()
    );

    // Check specific endpoint names are present and implemented.
    let implemented_names: Vec<&str> = implemented.iter().map(|ep| ep.name.as_str()).collect();
    for expected in [
        "run_live_response",
        "get_machine_action",
        "get_live_response_result_download_link",
        "download_sas_result",
    ] {
        assert!(
            implemented_names.contains(&expected),
            "endpoint '{expected}' should be marked as implemented"
        );
    }
}

#[test]
fn manifest_endpoint_methods_are_valid_http_verbs() {
    // Guard against typos in the method field by checking that every
    // endpoint uses a recognized HTTP verb.
    let content = std::fs::read_to_string("manifest/endpoints.toml")
        .expect("manifest/endpoints.toml should exist");

    let manifest: Manifest = toml::from_str(&content).expect("valid TOML");

    let valid_methods = ["GET", "POST", "PUT", "PATCH", "DELETE"];
    for ep in &manifest.endpoints {
        assert!(
            valid_methods.contains(&ep.method.as_str()),
            "endpoint '{}' has invalid method '{}', expected one of {:?}",
            ep.name,
            ep.method,
            valid_methods
        );
    }
}
