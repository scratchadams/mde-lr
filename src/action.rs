//! Shared machine-action types and polling abstraction for the MDE API.
//!
//! Many MDE API operations (live response, isolate, AV scan, collect
//! investigation package, etc.) follow the same async pattern:
//!
//! 1. **POST** to start the action — returns a `MachineAction` with `Pending` status.
//! 2. **Poll GET** `/api/machineactions/{id}` — wait until status reaches a
//!    terminal state (`Succeeded`, `Failed`, or `Cancelled`).
//!
//! This module provides the shared types (`MachineAction`, `ActionStatus`,
//! `PollConfig`) and the reusable [`poll_action`] function so that each
//! endpoint family doesn't need to re-implement the polling loop.

use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

use crate::client::MdeClient;
use crate::error::MdeError;

// ── Action types ─────────────────────────────────────────────────────

/// The lifecycle status of an MDE machine action.
///
/// Actions transition through these states:
///   Pending → InProgress → Succeeded | Failed | Cancelled
///
/// `Unknown` is a catch-all for any status string the API returns that we
/// don't recognize. This prevents deserialization failures if Microsoft
/// adds new status values in the future. During polling, `Unknown` is
/// treated the same as `Pending` — the loop continues waiting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionStatus {
    /// The action has been created but not yet picked up by the device.
    Pending,
    /// The device is actively executing the action.
    InProgress,
    /// The action completed successfully; results are available for download.
    Succeeded,
    /// The action failed (e.g. script error, device-side issue).
    Failed,
    /// The action was cancelled before completion.
    Cancelled,
    /// Catch-all for unrecognized status strings from the API.
    /// Treated as non-terminal during polling (the loop continues).
    #[serde(other)]
    Unknown,
}

/// Represents an MDE machine action as returned by POST (creation) and
/// GET (polling) endpoints.
///
/// The `status` field transitions through:
///   Pending → InProgress → Succeeded | Failed | Cancelled
///
/// The `id` and `status` fields are always present. Additional fields
/// are optional because the API may omit them depending on action type,
/// lifecycle stage, or tenant configuration. These extra fields provide
/// diagnostic context (who requested, when, on which device) that is
/// useful for logging, auditing, and troubleshooting.
///
/// Reference: <https://learn.microsoft.com/en-us/defender-endpoint/api/machineaction>
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineAction {
    /// The unique identifier for this action, assigned by the MDE API.
    /// Used to construct the polling URL and to correlate errors/logs.
    pub id: String,

    /// The current lifecycle status of the action.
    pub status: ActionStatus,

    /// The type of action (e.g. `"Isolate"`, `"RunAntiVirusScan"`,
    /// `"LiveResponse"`, `"CollectInvestigationPackage"`, etc.).
    #[serde(rename = "type", default)]
    pub action_type: Option<String>,

    /// Scope of the action. For isolation: `"Full"` or `"Selective"`.
    /// For AV scan: `"Quick"` or `"Full"`.
    #[serde(default)]
    pub scope: Option<String>,

    /// Identity of the user or application that initiated the action.
    #[serde(default)]
    pub requestor: Option<String>,

    /// The comment provided when the action was created.
    #[serde(default)]
    pub requestor_comment: Option<String>,

    /// The MDE machine ID on which the action was executed.
    #[serde(default)]
    pub machine_id: Option<String>,

    /// DNS name of the machine on which the action was executed.
    #[serde(default)]
    pub computer_dns_name: Option<String>,

    /// ISO 8601 timestamp of when the action was created.
    #[serde(default)]
    pub creation_date_time_utc: Option<String>,

    /// ISO 8601 timestamp of the last status update.
    #[serde(default)]
    pub last_update_date_time_utc: Option<String>,

    /// Action title (human-readable summary set by MDE).
    #[serde(default)]
    pub title: Option<String>,
}

// ── Polling configuration ────────────────────────────────────────────

/// Controls the polling behavior when waiting for a machine action to
/// reach a terminal state (Succeeded, Failed, or Cancelled).
///
/// Defaults:
/// - `interval`: 5 seconds between polls. This balances responsiveness
///   against API rate limits. MDE actions typically take 10-60 seconds.
/// - `timeout`: 10 minutes. Covers long-running script executions and
///   large file collections. Prevents infinite hangs if a device goes
///   offline mid-action.
///
/// To customize, construct directly or use `PollConfig::new()`:
/// ```ignore
/// let config = PollConfig {
///     interval: Duration::from_secs(10),
///     timeout: Duration::from_secs(300),
/// };
/// ```
#[derive(Clone)]
pub struct PollConfig {
    /// How long to wait between consecutive poll requests.
    pub interval: Duration,
    /// Maximum total time to spend polling before returning a timeout error.
    /// Measured from the start of the first poll, not from action creation.
    pub timeout: Duration,
}

impl PollConfig {
    /// Creates a new `PollConfig` with the specified interval and timeout.
    pub fn new(interval: Duration, timeout: Duration) -> Self {
        PollConfig { interval, timeout }
    }
}

impl Default for PollConfig {
    fn default() -> Self {
        PollConfig {
            interval: Duration::from_secs(5),
            timeout: Duration::from_secs(600), // 10 minutes
        }
    }
}

// ── Polling function ─────────────────────────────────────────────────

/// Polls an MDE machine action until it reaches a terminal status.
///
/// This is the shared polling loop used by all MDE operations that
/// return a `MachineAction` (live response, isolate, AV scan, etc.).
/// The caller is responsible for:
/// 1. POSTing to create the action and obtaining the initial `action_id`.
/// 2. Calling `poll_action` with that ID and desired polling parameters.
/// 3. Interpreting the returned `MachineAction` (which will always have
///    `ActionStatus::Succeeded` on the success path).
///
/// # Errors
///
/// - `MdeError::Timeout` — polling exceeded the configured timeout without
///   reaching a terminal state. Includes elapsed duration and action ID.
/// - `MdeError::ActionFailed` — the action reached `Failed` or `Cancelled`.
///   Includes the terminal status string and action ID.
/// - `MdeError::Api` — the MDE API returned a non-success HTTP status
///   during a poll request.
/// - `MdeError::Auth` — token refresh failed during polling.
/// - `MdeError::Network` — transport-level failure during a poll request.
pub async fn poll_action(
    client: &MdeClient,
    action_id: &str,
    config: &PollConfig,
) -> crate::error::Result<MachineAction> {
    let poll_path = format!("api/machineactions/{action_id}");
    let started = Instant::now();

    loop {
        tokio::time::sleep(config.interval).await;

        // Check timeout before making the next poll request, so we don't
        // send a request we already know we can't afford to wait for.
        if started.elapsed() > config.timeout {
            return Err(MdeError::Timeout {
                elapsed: started.elapsed(),
                action_id: action_id.to_string(),
            });
        }

        let status: MachineAction = client.get(&poll_path).await?;
        match status.status {
            // Terminal success — return the completed action to the caller.
            ActionStatus::Succeeded => return Ok(status),
            // Terminal failure — report and stop.
            ActionStatus::Failed | ActionStatus::Cancelled => {
                return Err(MdeError::ActionFailed {
                    status: format!("{:?}", status.status),
                    action_id: status.id,
                });
            }
            // Non-terminal — keep polling. This includes Pending, InProgress,
            // and Unknown (future API status values we don't recognize yet).
            ActionStatus::Pending | ActionStatus::InProgress | ActionStatus::Unknown => continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Serde tests ──────────────────────────────────────────────────

    #[test]
    fn machine_action_deserializes_known_status() {
        let json = r#"{
            "id": "abc-123",
            "type": "LiveResponse",
            "status": "Pending",
            "machineId": "device-456",
            "commands": []
        }"#;
        let action: MachineAction = serde_json::from_str(json).unwrap();
        assert_eq!(action.id, "abc-123");
        assert_eq!(action.status, ActionStatus::Pending);
        assert_eq!(action.action_type.as_deref(), Some("LiveResponse"));
        assert_eq!(action.machine_id.as_deref(), Some("device-456"));
    }

    #[test]
    fn machine_action_deserializes_full_response() {
        // Exercises all optional fields against the JSON representation
        // shown in the MDE API documentation.
        let json = r#"{
            "id": "5382f7ea-7557-4ab7-9782-d50480024a4e",
            "type": "Isolate",
            "scope": "Selective",
            "requestor": "Analyst@TestPrd.onmicrosoft.com",
            "requestorComment": "test for docs",
            "status": "Succeeded",
            "machineId": "7b1f4967d9728e5aa3c06a9e617a22a4a5a17378",
            "computerDnsName": "desktop-test",
            "creationDateTimeUtc": "2019-01-02T14:39:38.2262283Z",
            "lastUpdateDateTimeUtc": "2019-01-02T14:40:44.6596267Z",
            "title": "Isolate machine"
        }"#;
        let action: MachineAction = serde_json::from_str(json).unwrap();
        assert_eq!(action.id, "5382f7ea-7557-4ab7-9782-d50480024a4e");
        assert_eq!(action.status, ActionStatus::Succeeded);
        assert_eq!(action.action_type.as_deref(), Some("Isolate"));
        assert_eq!(action.scope.as_deref(), Some("Selective"));
        assert_eq!(
            action.requestor.as_deref(),
            Some("Analyst@TestPrd.onmicrosoft.com")
        );
        assert_eq!(action.requestor_comment.as_deref(), Some("test for docs"));
        assert_eq!(
            action.machine_id.as_deref(),
            Some("7b1f4967d9728e5aa3c06a9e617a22a4a5a17378")
        );
        assert_eq!(action.computer_dns_name.as_deref(), Some("desktop-test"));
        assert!(action.creation_date_time_utc.is_some());
        assert!(action.last_update_date_time_utc.is_some());
        assert_eq!(action.title.as_deref(), Some("Isolate machine"));
    }

    #[test]
    fn machine_action_deserializes_unknown_status_gracefully() {
        // If Microsoft adds a new status value, we should not panic or fail
        // deserialization — it maps to ActionStatus::Unknown instead.
        let json = r#"{
            "id": "abc-456",
            "status": "SomeNewStatus"
        }"#;
        let action: MachineAction = serde_json::from_str(json).unwrap();
        assert_eq!(action.status, ActionStatus::Unknown);
    }

    #[test]
    fn action_status_round_trips_through_serde() {
        // Verify all known variants survive serialize → deserialize.
        for status in [
            ActionStatus::Pending,
            ActionStatus::InProgress,
            ActionStatus::Succeeded,
            ActionStatus::Failed,
            ActionStatus::Cancelled,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let restored: ActionStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(restored, status, "round-trip failed for {json}");
        }
    }

    // ── PollConfig tests ─────────────────────────────────────────────

    #[test]
    fn poll_config_default_has_sane_values() {
        let config = PollConfig::default();
        assert_eq!(config.interval, Duration::from_secs(5));
        assert_eq!(config.timeout, Duration::from_secs(600));
    }

    #[test]
    fn poll_config_new_uses_provided_values() {
        let config = PollConfig::new(Duration::from_secs(2), Duration::from_secs(120));
        assert_eq!(config.interval, Duration::from_secs(2));
        assert_eq!(config.timeout, Duration::from_secs(120));
    }
}
