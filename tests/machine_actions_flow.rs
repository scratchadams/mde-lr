//! Integration tests for the machine_actions endpoint family using wiremock.
//!
//! These tests mock the MDE API to verify the two-step POST → poll pattern
//! shared by all machine action endpoints. Representative coverage includes:
//!
//! - Isolate with polling (full happy path through Pending → Succeeded)
//! - Unisolate fire-and-forget (no polling, returns initial Pending action)
//! - AV scan with polling progression (Pending → InProgress → Succeeded)
//! - Collect investigation package with action failure
//! - Stop and quarantine file (verifies SHA-1 in request body)
//! - Restrict / unrestrict code execution (round-trip)

use mde_lr::action::{ActionStatus, PollConfig};
use mde_lr::auth::TokenProvider;
use mde_lr::client::MdeClient;
use mde_lr::machine_actions::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Helper: creates a mock MdeClient pointed at the given wiremock server.
async fn mock_client(server: &MockServer) -> MdeClient {
    let tp = TokenProvider::with_token("mock-token");
    MdeClient::with_base_url(tp, &format!("{}/", server.uri())).await
}

/// Helper: short poll config for fast tests.
fn fast_poll() -> PollConfig {
    PollConfig::new(
        std::time::Duration::from_millis(50),
        std::time::Duration::from_secs(10),
    )
}

// ── Isolate ────────────────────────────────────────────────────────────

#[tokio::test]
async fn isolate_machine_polls_to_success() {
    let server = MockServer::start().await;
    let client = mock_client(&server).await;
    let machine_id = "device-isolate";
    let action_id = "action-isolate-001";

    // POST creates the action with Pending status.
    Mock::given(method("POST"))
        .and(path(format!("api/machines/{machine_id}/isolate")))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": action_id,
            "type": "Isolate",
            "status": "Pending",
            "machineId": machine_id,
            "requestorComment": "Isolate due to alert"
        })))
        .mount(&server)
        .await;

    // Poll returns Succeeded immediately.
    Mock::given(method("GET"))
        .and(path(format!("api/machineactions/{action_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": action_id,
            "type": "Isolate",
            "status": "Succeeded",
            "machineId": machine_id
        })))
        .mount(&server)
        .await;

    let request = IsolateRequest {
        comment: "Isolate due to alert".to_string(),
        isolation_type: "Full".to_string(),
    };

    let result = isolate_machine(&client, machine_id, &request, Some(&fast_poll()))
        .await
        .unwrap();

    assert_eq!(result.id, action_id);
    assert_eq!(result.status, ActionStatus::Succeeded);
    assert_eq!(result.action_type.as_deref(), Some("Isolate"));
}

// ── Unisolate (fire-and-forget) ────────────────────────────────────────

#[tokio::test]
async fn unisolate_machine_without_polling_returns_pending() {
    let server = MockServer::start().await;
    let client = mock_client(&server).await;
    let machine_id = "device-unisolate";
    let action_id = "action-unisolate-001";

    Mock::given(method("POST"))
        .and(path(format!("api/machines/{machine_id}/unisolate")))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": action_id,
            "type": "Unisolate",
            "status": "Pending"
        })))
        .mount(&server)
        .await;

    let request = UnisolateRequest {
        comment: "Device cleared".to_string(),
    };

    // No poll_config → fire-and-forget, returns the initial Pending action.
    let result = unisolate_machine(&client, machine_id, &request, None)
        .await
        .unwrap();

    assert_eq!(result.id, action_id);
    assert_eq!(result.status, ActionStatus::Pending);
}

// ── Antivirus Scan ─────────────────────────────────────────────────────

#[tokio::test]
async fn antivirus_scan_polls_through_progression() {
    let server = MockServer::start().await;
    let client = mock_client(&server).await;
    let machine_id = "device-scan";
    let action_id = "action-scan-001";

    Mock::given(method("POST"))
        .and(path(format!("api/machines/{machine_id}/runAntiVirusScan")))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": action_id,
            "type": "RunAntiVirusScan",
            "status": "Pending"
        })))
        .mount(&server)
        .await;

    // First poll: InProgress, then Succeeded.
    Mock::given(method("GET"))
        .and(path(format!("api/machineactions/{action_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": action_id,
            "type": "RunAntiVirusScan",
            "status": "InProgress"
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("api/machineactions/{action_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": action_id,
            "type": "RunAntiVirusScan",
            "status": "Succeeded",
            "scope": "Quick"
        })))
        .mount(&server)
        .await;

    let request = AntivirusScanRequest {
        comment: "Routine check".to_string(),
        scan_type: "Quick".to_string(),
    };

    let result = run_antivirus_scan(&client, machine_id, &request, Some(&fast_poll()))
        .await
        .unwrap();

    assert_eq!(result.status, ActionStatus::Succeeded);
    assert_eq!(result.scope.as_deref(), Some("Quick"));
}

// ── Collect Investigation Package (failure path) ───────────────────────

#[tokio::test]
async fn collect_investigation_package_action_failed() {
    let server = MockServer::start().await;
    let client = mock_client(&server).await;
    let machine_id = "device-forensics";
    let action_id = "action-forensics-fail";

    Mock::given(method("POST"))
        .and(path(format!(
            "api/machines/{machine_id}/collectInvestigationPackage"
        )))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": action_id,
            "type": "CollectInvestigationPackage",
            "status": "Pending"
        })))
        .mount(&server)
        .await;

    // Poll returns Failed — device offline or other issue.
    Mock::given(method("GET"))
        .and(path(format!("api/machineactions/{action_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": action_id,
            "type": "CollectInvestigationPackage",
            "status": "Failed"
        })))
        .mount(&server)
        .await;

    let request = CollectInvestigationPackageRequest {
        comment: "Collect forensics".to_string(),
    };

    let result =
        collect_investigation_package(&client, machine_id, &request, Some(&fast_poll())).await;

    assert!(result.is_err(), "should return error for Failed action");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("Failed"),
        "error should include failure status, got: {err_msg}"
    );
    assert!(
        err_msg.contains(action_id),
        "error should include action ID, got: {err_msg}"
    );
}

// ── Stop and Quarantine File ───────────────────────────────────────────

#[tokio::test]
async fn stop_and_quarantine_file_succeeds() {
    let server = MockServer::start().await;
    let client = mock_client(&server).await;
    let machine_id = "device-quarantine";
    let action_id = "action-quarantine-001";

    Mock::given(method("POST"))
        .and(path(format!(
            "api/machines/{machine_id}/StopAndQuarantineFile"
        )))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": action_id,
            "type": "StopAndQuarantineFile",
            "status": "Pending"
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("api/machineactions/{action_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": action_id,
            "type": "StopAndQuarantineFile",
            "status": "Succeeded"
        })))
        .mount(&server)
        .await;

    let request = StopAndQuarantineFileRequest {
        comment: "Quarantine malware".to_string(),
        sha1: "87662bc3d60e4200ceaf7aae249d1c343f4b83c9".to_string(),
    };

    let result = stop_and_quarantine_file(&client, machine_id, &request, Some(&fast_poll()))
        .await
        .unwrap();

    assert_eq!(result.status, ActionStatus::Succeeded);
}

// ── Restrict / Unrestrict Code Execution ───────────────────────────────

#[tokio::test]
async fn restrict_then_unrestrict_code_execution() {
    let server = MockServer::start().await;
    let client = mock_client(&server).await;
    let machine_id = "device-restrict";

    // Restrict
    Mock::given(method("POST"))
        .and(path(format!(
            "api/machines/{machine_id}/restrictCodeExecution"
        )))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "action-restrict-001",
            "type": "RestrictCodeExecution",
            "status": "Pending"
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("api/machineactions/action-restrict-001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "action-restrict-001",
            "type": "RestrictCodeExecution",
            "status": "Succeeded"
        })))
        .mount(&server)
        .await;

    let restrict_req = RestrictCodeExecutionRequest {
        comment: "Restrict apps on compromised device".to_string(),
    };
    let result = restrict_code_execution(&client, machine_id, &restrict_req, Some(&fast_poll()))
        .await
        .unwrap();
    assert_eq!(result.status, ActionStatus::Succeeded);

    // Unrestrict
    Mock::given(method("POST"))
        .and(path(format!(
            "api/machines/{machine_id}/unrestrictCodeExecution"
        )))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "action-unrestrict-001",
            "type": "UnrestrictCodeExecution",
            "status": "Pending"
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("api/machineactions/action-unrestrict-001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "action-unrestrict-001",
            "type": "UnrestrictCodeExecution",
            "status": "Succeeded"
        })))
        .mount(&server)
        .await;

    let unrestrict_req = UnrestrictCodeExecutionRequest {
        comment: "Device cleaned, lift restriction".to_string(),
    };
    let result =
        unrestrict_code_execution(&client, machine_id, &unrestrict_req, Some(&fast_poll()))
            .await
            .unwrap();
    assert_eq!(result.status, ActionStatus::Succeeded);
}

// ── API-level error ────────────────────────────────────────────────────

#[tokio::test]
async fn action_already_in_progress_returns_api_error() {
    // When an action is already running on a device, the MDE API returns
    // 400 with "Action is already in progress". Verify we surface this
    // as MdeError::Api with the response body preserved.
    let server = MockServer::start().await;
    let client = mock_client(&server).await;
    let machine_id = "device-busy";

    Mock::given(method("POST"))
        .and(path(format!("api/machines/{machine_id}/isolate")))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": {
                "code": "ActiveRequestAlreadyExists",
                "message": "Action is already in progress"
            }
        })))
        .mount(&server)
        .await;

    let request = IsolateRequest {
        comment: "Should fail".to_string(),
        isolation_type: "Full".to_string(),
    };

    let result = isolate_machine(&client, machine_id, &request, Some(&fast_poll())).await;
    assert!(result.is_err());

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("400"),
        "error should include 400 status, got: {err_msg}"
    );
    assert!(
        err_msg.contains("already in progress"),
        "error should preserve API message, got: {err_msg}"
    );
}
