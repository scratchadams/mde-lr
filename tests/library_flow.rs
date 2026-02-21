//! Integration tests for the library file management endpoints using wiremock.
//!
//! These tests mock the MDE API to verify list, upload, and delete operations
//! on the Live Response library.

use mde_lr::auth::TokenProvider;
use mde_lr::client::MdeClient;
use mde_lr::library::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Helper: creates a mock MdeClient pointed at the given wiremock server.
async fn mock_client(server: &MockServer) -> MdeClient {
    let tp = TokenProvider::with_token("mock-token");
    MdeClient::with_base_url(tp, &format!("{}/", server.uri())).await
}

// ── List library files ──────────────────────────────────────────────────

#[tokio::test]
async fn list_library_files_returns_collection() {
    let server = MockServer::start().await;
    let client = mock_client(&server).await;

    Mock::given(method("GET"))
        .and(path("api/libraryfiles"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [
                {
                    "fileName": "collector.ps1",
                    "sha256": "abcd1234",
                    "description": "Forensic collector",
                    "hasParameters": true
                },
                {
                    "fileName": "cleanup.ps1",
                    "sha256": "efgh5678",
                    "hasParameters": false
                }
            ]
        })))
        .mount(&server)
        .await;

    let files = list_library_files(&client).await.unwrap();
    assert_eq!(files.len(), 2);
    assert_eq!(files[0].file_name, "collector.ps1");
    assert!(files[0].has_parameters);
    assert_eq!(files[1].file_name, "cleanup.ps1");
    assert!(!files[1].has_parameters);
}

#[tokio::test]
async fn list_library_files_handles_empty_collection() {
    let server = MockServer::start().await;
    let client = mock_client(&server).await;

    Mock::given(method("GET"))
        .and(path("api/libraryfiles"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": []
        })))
        .mount(&server)
        .await;

    let files = list_library_files(&client).await.unwrap();
    assert!(files.is_empty());
}

// ── Upload library file ─────────────────────────────────────────────────

#[tokio::test]
async fn upload_library_file_returns_created_file() {
    let server = MockServer::start().await;
    let client = mock_client(&server).await;

    Mock::given(method("POST"))
        .and(path("api/libraryfiles"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "fileName": "new-script.ps1",
            "sha256": "deadbeef",
            "description": "A new script",
            "createdBy": "admin@contoso.com",
            "hasParameters": false
        })))
        .mount(&server)
        .await;

    let result = upload_library_file(
        &client,
        "new-script.ps1",
        b"Write-Host 'Hello'".to_vec(),
        Some("A new script"),
        false,
    )
    .await
    .unwrap();

    assert_eq!(result.file_name, "new-script.ps1");
    assert_eq!(result.sha256.as_deref(), Some("deadbeef"));
    assert_eq!(result.description.as_deref(), Some("A new script"));
}

// ── Delete library file ─────────────────────────────────────────────────

#[tokio::test]
async fn delete_library_file_succeeds_on_204() {
    let server = MockServer::start().await;
    let client = mock_client(&server).await;

    Mock::given(method("DELETE"))
        .and(path("api/libraryfiles/old-script.ps1"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    delete_library_file(&client, "old-script.ps1")
        .await
        .expect("delete should succeed on 204 No Content");
}

#[tokio::test]
async fn delete_library_file_returns_error_on_404() {
    let server = MockServer::start().await;
    let client = mock_client(&server).await;

    Mock::given(method("DELETE"))
        .and(path("api/libraryfiles/nonexistent.ps1"))
        .respond_with(ResponseTemplate::new(404).set_body_string("Resource not found"))
        .mount(&server)
        .await;

    let err = delete_library_file(&client, "nonexistent.ps1")
        .await
        .unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("404"),
        "error should include 404 status, got: {err_msg}"
    );
}
