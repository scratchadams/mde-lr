//! Integration tests for the alert management endpoints using wiremock.
//!
//! These tests mock the MDE API to verify list, get, update, and batch
//! update operations on security alerts.

use mde_lr::alerts::*;
use mde_lr::auth::TokenProvider;
use mde_lr::client::MdeClient;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Helper: creates a mock MdeClient pointed at the given wiremock server.
async fn mock_client(server: &MockServer) -> MdeClient {
    let tp = TokenProvider::with_token("mock-token");
    MdeClient::with_base_url(tp, &format!("{}/", server.uri())).await
}

// ── List alerts ─────────────────────────────────────────────────────────

#[tokio::test]
async fn list_alerts_returns_collection() {
    let server = MockServer::start().await;
    let client = mock_client(&server).await;

    Mock::given(method("GET"))
        .and(path("api/alerts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [
                {
                    "id": "alert-001",
                    "title": "Suspicious activity detected",
                    "severity": "High",
                    "status": "New"
                },
                {
                    "id": "alert-002",
                    "title": "Malware detected",
                    "severity": "Medium",
                    "status": "InProgress"
                }
            ]
        })))
        .mount(&server)
        .await;

    let alerts = list_alerts(&client, None).await.unwrap();
    assert_eq!(alerts.len(), 2);
    assert_eq!(alerts[0].id, "alert-001");
    assert_eq!(alerts[0].severity.as_deref(), Some("High"));
    assert_eq!(alerts[1].id, "alert-002");
    assert_eq!(alerts[1].status.as_deref(), Some("InProgress"));
}

#[tokio::test]
async fn list_alerts_with_filter() {
    let server = MockServer::start().await;
    let client = mock_client(&server).await;

    // The mock matches any GET to /api/alerts (query params are in the path).
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [
                {"id": "alert-high-001", "severity": "High", "status": "New"}
            ]
        })))
        .mount(&server)
        .await;

    let alerts = list_alerts(&client, Some("severity eq 'High'"))
        .await
        .unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].id, "alert-high-001");
}

// ── Get alert ───────────────────────────────────────────────────────────

#[tokio::test]
async fn get_alert_returns_full_alert() {
    let server = MockServer::start().await;
    let client = mock_client(&server).await;

    Mock::given(method("GET"))
        .and(path("api/alerts/alert-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "alert-123",
            "title": "Credential theft detected",
            "severity": "High",
            "status": "New",
            "classification": null,
            "machineId": "device-001",
            "computerDnsName": "host.contoso.com",
            "mitreTechniques": ["T1003"],
            "comments": []
        })))
        .mount(&server)
        .await;

    let alert = get_alert(&client, "alert-123").await.unwrap();
    assert_eq!(alert.id, "alert-123");
    assert_eq!(alert.title.as_deref(), Some("Credential theft detected"));
    assert_eq!(alert.severity.as_deref(), Some("High"));
    assert_eq!(alert.machine_id.as_deref(), Some("device-001"));
    assert_eq!(alert.mitre_techniques, vec!["T1003"]);
}

#[tokio::test]
async fn get_alert_returns_error_on_404() {
    let server = MockServer::start().await;
    let client = mock_client(&server).await;

    Mock::given(method("GET"))
        .and(path("api/alerts/nonexistent"))
        .respond_with(ResponseTemplate::new(404).set_body_string("Alert not found"))
        .mount(&server)
        .await;

    let err = get_alert(&client, "nonexistent").await.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("404"),
        "error should include 404 status, got: {err_msg}"
    );
}

// ── Update alert ────────────────────────────────────────────────────────

#[tokio::test]
async fn update_alert_returns_updated_alert() {
    let server = MockServer::start().await;
    let client = mock_client(&server).await;

    Mock::given(method("PATCH"))
        .and(path("api/alerts/alert-456"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "alert-456",
            "title": "Suspicious activity",
            "severity": "Medium",
            "status": "Resolved",
            "classification": "FalsePositive",
            "determination": "NotMalicious",
            "assignedTo": "analyst@contoso.com"
        })))
        .mount(&server)
        .await;

    let update_req = UpdateAlertRequest {
        status: Some("Resolved".to_string()),
        assigned_to: Some("analyst@contoso.com".to_string()),
        classification: Some("FalsePositive".to_string()),
        determination: Some("NotMalicious".to_string()),
        comment: Some("Confirmed false positive".to_string()),
    };

    let alert = update_alert(&client, "alert-456", &update_req)
        .await
        .unwrap();
    assert_eq!(alert.id, "alert-456");
    assert_eq!(alert.status.as_deref(), Some("Resolved"));
    assert_eq!(alert.classification.as_deref(), Some("FalsePositive"));
    assert_eq!(alert.assigned_to.as_deref(), Some("analyst@contoso.com"));
}

#[tokio::test]
async fn update_alert_with_comment_only() {
    let server = MockServer::start().await;
    let client = mock_client(&server).await;

    Mock::given(method("PATCH"))
        .and(path("api/alerts/alert-789"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "alert-789",
            "title": "Some alert",
            "status": "New",
            "comments": [
                {
                    "comment": "Adding a note for audit trail",
                    "createdBy": "analyst@contoso.com",
                    "createdTime": "2026-02-20T10:00:00Z"
                }
            ]
        })))
        .mount(&server)
        .await;

    let update_req = UpdateAlertRequest {
        status: None,
        assigned_to: None,
        classification: None,
        determination: None,
        comment: Some("Adding a note for audit trail".to_string()),
    };

    let alert = update_alert(&client, "alert-789", &update_req)
        .await
        .unwrap();
    assert_eq!(alert.comments.len(), 1);
    assert_eq!(
        alert.comments[0].comment.as_deref(),
        Some("Adding a note for audit trail")
    );
}

// ── Batch update alerts ─────────────────────────────────────────────────

#[tokio::test]
async fn batch_update_alerts_succeeds() {
    let server = MockServer::start().await;
    let client = mock_client(&server).await;

    // Batch update returns 200 with empty body on success.
    Mock::given(method("PATCH"))
        .and(path("api/alerts/batchUpdate"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let batch_req = BatchUpdateAlertsRequest {
        alert_ids: vec![
            "alert-1".to_string(),
            "alert-2".to_string(),
            "alert-3".to_string(),
        ],
        status: Some("Resolved".to_string()),
        assigned_to: None,
        classification: Some("FalsePositive".to_string()),
        determination: Some("NotMalicious".to_string()),
        comment: Some("Batch close — false positives".to_string()),
    };

    batch_update_alerts(&client, &batch_req)
        .await
        .expect("batch update should succeed on 200");
}
