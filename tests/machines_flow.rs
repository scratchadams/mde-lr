//! Integration tests for the machines endpoint family using wiremock.
//!
//! These tests mock the MDE API to verify that the machines module
//! correctly constructs requests, handles responses, and propagates
//! errors for the three machines endpoints:
//!
//! - GET  /api/machines          — list_machines (with and without filter)
//! - GET  /api/machines/{id}     — get_machine
//! - PATCH /api/machines/{id}    — update_machine

use mde_lr::auth::TokenProvider;
use mde_lr::client::MdeClient;
use mde_lr::machines::*;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Helper: creates a mock MdeClient pointed at the given wiremock server.
async fn mock_client(server: &MockServer) -> MdeClient {
    let tp = TokenProvider::with_token("mock-token");
    MdeClient::with_base_url(tp, &format!("{}/", server.uri())).await
}

// ── list_machines ──────────────────────────────────────────────────────

#[tokio::test]
async fn list_machines_returns_devices() {
    let server = MockServer::start().await;
    let client = mock_client(&server).await;

    Mock::given(method("GET"))
        .and(path("api/machines"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "@odata.context": "https://api.security.microsoft.com/api/$metadata#Machines",
            "value": [
                {
                    "id": "device-001",
                    "computerDnsName": "host1.contoso.com",
                    "healthStatus": "Active",
                    "osPlatform": "Windows10",
                    "machineTags": ["Prod"]
                },
                {
                    "id": "device-002",
                    "computerDnsName": "host2.contoso.com",
                    "healthStatus": "Inactive",
                    "osPlatform": "Linux",
                    "machineTags": []
                }
            ]
        })))
        .mount(&server)
        .await;

    let machines = list_machines(&client, None).await.unwrap();

    assert_eq!(machines.len(), 2, "should return both devices");
    assert_eq!(machines[0].id, "device-001");
    assert_eq!(
        machines[0].computer_dns_name.as_deref(),
        Some("host1.contoso.com")
    );
    assert_eq!(machines[0].health_status.as_deref(), Some("Active"));
    assert_eq!(machines[0].machine_tags, vec!["Prod"]);
    assert_eq!(machines[1].id, "device-002");
    assert_eq!(machines[1].os_platform.as_deref(), Some("Linux"));
}

#[tokio::test]
async fn list_machines_with_filter_passes_odata_query() {
    let server = MockServer::start().await;
    let client = mock_client(&server).await;

    // The mock matches on both the path and the $filter query parameter
    // to verify that the filter is correctly passed through.
    Mock::given(method("GET"))
        .and(path("api/machines"))
        .and(query_param("$filter", "healthStatus eq 'Active'"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [
                {
                    "id": "active-device",
                    "healthStatus": "Active"
                }
            ]
        })))
        .mount(&server)
        .await;

    let machines = list_machines(&client, Some("healthStatus eq 'Active'"))
        .await
        .unwrap();

    assert_eq!(machines.len(), 1);
    assert_eq!(machines[0].id, "active-device");
    assert_eq!(machines[0].health_status.as_deref(), Some("Active"));
}

#[tokio::test]
async fn list_machines_empty_collection() {
    let server = MockServer::start().await;
    let client = mock_client(&server).await;

    Mock::given(method("GET"))
        .and(path("api/machines"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": []
        })))
        .mount(&server)
        .await;

    let machines = list_machines(&client, None).await.unwrap();
    assert!(machines.is_empty(), "should handle empty device list");
}

// ── get_machine ────────────────────────────────────────────────────────

#[tokio::test]
async fn get_machine_returns_single_device() {
    let server = MockServer::start().await;
    let client = mock_client(&server).await;
    let machine_id = "abc123def456";

    Mock::given(method("GET"))
        .and(path(format!("api/machines/{machine_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": machine_id,
            "computerDnsName": "workstation.contoso.com",
            "osPlatform": "Windows11",
            "healthStatus": "Active",
            "riskScore": "Medium",
            "exposureLevel": "Low",
            "deviceValue": "High",
            "machineTags": ["VIP", "Executive"],
            "lastIpAddress": "10.0.0.42",
            "osBuild": 22631,
            "osArchitecture": "64-bit"
        })))
        .mount(&server)
        .await;

    let machine = get_machine(&client, machine_id).await.unwrap();

    assert_eq!(machine.id, machine_id);
    assert_eq!(
        machine.computer_dns_name.as_deref(),
        Some("workstation.contoso.com")
    );
    assert_eq!(machine.os_platform.as_deref(), Some("Windows11"));
    assert_eq!(machine.risk_score.as_deref(), Some("Medium"));
    assert_eq!(machine.device_value.as_deref(), Some("High"));
    assert_eq!(machine.machine_tags, vec!["VIP", "Executive"]);
    assert_eq!(machine.os_build, Some(22631));
}

#[tokio::test]
async fn get_machine_not_found_returns_api_error() {
    let server = MockServer::start().await;
    let client = mock_client(&server).await;

    Mock::given(method("GET"))
        .and(path("api/machines/nonexistent"))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
            "error": {
                "code": "ResourceNotFound",
                "message": "Machine nonexistent was not found"
            }
        })))
        .mount(&server)
        .await;

    let result = get_machine(&client, "nonexistent").await;
    assert!(result.is_err(), "should return error for 404");

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("404"),
        "error should include 404 status, got: {err_msg}"
    );
}

// ── update_machine ─────────────────────────────────────────────────────

#[tokio::test]
async fn update_machine_returns_updated_device() {
    let server = MockServer::start().await;
    let client = mock_client(&server).await;
    let machine_id = "device-to-update";

    // The mock returns the machine with the updated fields applied.
    Mock::given(method("PATCH"))
        .and(path(format!("api/machines/{machine_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": machine_id,
            "computerDnsName": "updated.contoso.com",
            "healthStatus": "Active",
            "deviceValue": "High",
            "machineTags": ["VIP", "Prod", "NewTag"]
        })))
        .mount(&server)
        .await;

    let update = UpdateMachineRequest {
        machine_tags: Some(vec![
            "VIP".to_string(),
            "Prod".to_string(),
            "NewTag".to_string(),
        ]),
        device_value: Some("High".to_string()),
    };

    let machine = update_machine(&client, machine_id, &update).await.unwrap();

    assert_eq!(machine.id, machine_id);
    assert_eq!(machine.device_value.as_deref(), Some("High"));
    assert_eq!(
        machine.machine_tags,
        vec!["VIP", "Prod", "NewTag"],
        "tags should reflect the update"
    );
}

#[tokio::test]
async fn update_machine_tags_only() {
    let server = MockServer::start().await;
    let client = mock_client(&server).await;
    let machine_id = "device-tags-only";

    Mock::given(method("PATCH"))
        .and(path(format!("api/machines/{machine_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": machine_id,
            "deviceValue": "Normal",
            "machineTags": ["OnlyTag"]
        })))
        .mount(&server)
        .await;

    // Update tags only, leave deviceValue unchanged.
    let update = UpdateMachineRequest {
        machine_tags: Some(vec!["OnlyTag".to_string()]),
        device_value: None,
    };

    let machine = update_machine(&client, machine_id, &update).await.unwrap();
    assert_eq!(machine.machine_tags, vec!["OnlyTag"]);
    // deviceValue should be unchanged (returned by API as-is).
    assert_eq!(machine.device_value.as_deref(), Some("Normal"));
}
