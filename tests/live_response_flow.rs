//! Integration tests for the live response flow using wiremock.
//!
//! These tests mock the full 4-step MDE API interaction:
//! 1. POST runliveresponse → returns a Pending MachineAction
//! 2. GET machineactions/{id} → returns Succeeded after polling
//! 3. GET GetLiveResponseResultDownloadLink → returns a SAS URL
//! 4. GET SAS URL → returns raw bytes
//!
//! The mock server replaces both the MDE API (steps 1-3) and the Azure
//! Blob Storage download (step 4) since all requests route through the
//! same reqwest client.

use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::{method, path};
use mde_lr::auth::TokenProvider;
use mde_lr::client::MdeClient;
use mde_lr::live_response::*;

#[tokio::test]
async fn full_getfile_flow_returns_downloaded_bytes() {
    let server = MockServer::start().await;
    let tp = TokenProvider::with_token("mock-token");
    let client = MdeClient::with_base_url(tp, &format!("{}/", server.uri())).await;

    let action_id = "action-001";
    let machine_id = "device-abc";
    let file_content = b"fake-zip-file-content";

    // Step 1: POST runliveresponse → Pending action
    Mock::given(method("POST"))
        .and(path(format!("api/machines/{}/runliveresponse", machine_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": action_id,
            "status": "Pending"
        })))
        .mount(&server)
        .await;

    // Step 2: GET machineactions/{id} → Succeeded
    // In a real scenario this would transition through Pending → InProgress → Succeeded.
    // We return Succeeded immediately to keep the test fast.
    Mock::given(method("GET"))
        .and(path(format!("api/machineactions/{}", action_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": action_id,
            "status": "Succeeded"
        })))
        .mount(&server)
        .await;

    // Step 3: GET download link → SAS URL (pointing back at our mock server)
    let download_url = format!("{}/blob/result.zip", server.uri());
    Mock::given(method("GET"))
        .and(path(format!(
            "api/machineactions/{}/GetLiveResponseResultDownloadLink(index=0)",
            action_id
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": download_url
        })))
        .mount(&server)
        .await;

    // Step 4: GET the SAS URL → raw bytes
    Mock::given(method("GET"))
        .and(path("/blob/result.zip"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(file_content.as_slice()))
        .mount(&server)
        .await;

    let request = LiveResponseRequest {
        comment: "test getfile".to_string(),
        commands: vec![Command {
            command_type: CommandType::GetFile,
            params: vec![Param {
                key: "Path".to_string(),
                value: "C:\\temp\\evidence.zip".to_string(),
            }],
        }],
    };

    let results = run_live_response(&client, machine_id, &request).await.unwrap();

    assert_eq!(results.len(), 1, "should have one result per command");
    assert_eq!(results[0].as_ref(), file_content, "downloaded bytes should match");
}

#[tokio::test]
async fn runscript_result_can_be_parsed_from_downloaded_bytes() {
    let server = MockServer::start().await;
    let tp = TokenProvider::with_token("mock-token");
    let client = MdeClient::with_base_url(tp, &format!("{}/", server.uri())).await;

    let action_id = "action-002";
    let machine_id = "device-xyz";
    let script_output = serde_json::json!({
        "script_name": "whoami.ps1",
        "exit_code": 0,
        "script_output": "NT AUTHORITY\\SYSTEM\n",
        "script_errors": ""
    });

    Mock::given(method("POST"))
        .and(path(format!("api/machines/{}/runliveresponse", machine_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": action_id,
            "status": "Pending"
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("api/machineactions/{}", action_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": action_id,
            "status": "Succeeded"
        })))
        .mount(&server)
        .await;

    let download_url = format!("{}/blob/script_result.json", server.uri());
    Mock::given(method("GET"))
        .and(path(format!(
            "api/machineactions/{}/GetLiveResponseResultDownloadLink(index=0)",
            action_id
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": download_url
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/blob/script_result.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&script_output))
        .mount(&server)
        .await;

    let request = LiveResponseRequest {
        comment: "test runscript".to_string(),
        commands: vec![Command {
            command_type: CommandType::RunScript,
            params: vec![
                Param { key: "ScriptName".to_string(), value: "whoami.ps1".to_string() },
                Param { key: "Args".to_string(), value: "".to_string() },
            ],
        }],
    };

    let results = run_live_response(&client, machine_id, &request).await.unwrap();
    let parsed: ScriptResult = serde_json::from_slice(&results[0]).unwrap();

    assert_eq!(parsed.script_name, "whoami.ps1");
    assert_eq!(parsed.exit_code, 0);
    assert!(parsed.script_output.contains("SYSTEM"));
}

#[tokio::test]
async fn failed_action_returns_error() {
    let server = MockServer::start().await;
    let tp = TokenProvider::with_token("mock-token");
    let client = MdeClient::with_base_url(tp, &format!("{}/", server.uri())).await;

    let action_id = "action-fail";
    let machine_id = "device-down";

    Mock::given(method("POST"))
        .and(path(format!("api/machines/{}/runliveresponse", machine_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": action_id,
            "status": "Pending"
        })))
        .mount(&server)
        .await;

    // Polling returns Failed
    Mock::given(method("GET"))
        .and(path(format!("api/machineactions/{}", action_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": action_id,
            "status": "Failed"
        })))
        .mount(&server)
        .await;

    let request = LiveResponseRequest {
        comment: "should fail".to_string(),
        commands: vec![Command {
            command_type: CommandType::GetFile,
            params: vec![Param {
                key: "Path".to_string(),
                value: "C:\\nonexistent".to_string(),
            }],
        }],
    };

    let result = run_live_response(&client, machine_id, &request).await;
    assert!(result.is_err(), "should return an error for Failed actions");

    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("Failed"), "error should mention the failure status");
}

#[tokio::test]
async fn multi_command_returns_result_per_command() {
    let server = MockServer::start().await;
    let tp = TokenProvider::with_token("mock-token");
    let client = MdeClient::with_base_url(tp, &format!("{}/", server.uri())).await;

    let action_id = "action-multi";
    let machine_id = "device-multi";

    Mock::given(method("POST"))
        .and(path(format!("api/machines/{}/runliveresponse", machine_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": action_id,
            "status": "Pending"
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("api/machineactions/{}", action_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": action_id,
            "status": "Succeeded"
        })))
        .mount(&server)
        .await;

    // Two commands → two download links
    for i in 0..2 {
        let dl_url = format!("{}/blob/result_{}.bin", server.uri(), i);
        Mock::given(method("GET"))
            .and(path(format!(
                "api/machineactions/{}/GetLiveResponseResultDownloadLink(index={})",
                action_id, i
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": dl_url
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/blob/result_{}.bin", i)))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(format!("content-{}", i).into_bytes()),
            )
            .mount(&server)
            .await;
    }

    let request = LiveResponseRequest {
        comment: "multi-command".to_string(),
        commands: vec![
            Command {
                command_type: CommandType::RunScript,
                params: vec![Param {
                    key: "ScriptName".to_string(),
                    value: "script.ps1".to_string(),
                }],
            },
            Command {
                command_type: CommandType::GetFile,
                params: vec![Param {
                    key: "Path".to_string(),
                    value: "C:\\temp\\file.zip".to_string(),
                }],
            },
        ],
    };

    let results = run_live_response(&client, machine_id, &request).await.unwrap();

    assert_eq!(results.len(), 2, "should return one result per command");
    assert_eq!(results[0].as_ref(), b"content-0");
    assert_eq!(results[1].as_ref(), b"content-1");
}
