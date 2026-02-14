//! Live Response request types and orchestration for the MDE API.
//!
//! The Live Response API is a 4-step async flow:
//! 1. POST `/api/machines/{id}/runliveresponse` — starts the action (returns `Pending`).
//! 2. Poll `GET /api/machineactions/{id}` — wait until status reaches a terminal state.
//! 3. GET `.../GetLiveResponseResultDownloadLink(index=N)` — get a time-limited Azure SAS URL.
//! 4. Download from the SAS URL — raw bytes (no bearer auth; SAS token is in the query string).
//!
//! Both `RunScript` and `GetFile` results go through the same download-link
//! mechanism. The difference is in how the caller interprets the bytes:
//! - `RunScript`: JSON with `script_name`, `exit_code`, `script_output`, `script_errors`.
//! - `GetFile`: raw file bytes (typically a zip).

use serde::{Deserialize, Serialize};
use std::error::Error;
use std::time::{Duration, Instant};

use crate::client::MdeClient;

// ── Request types ──────────────────────────────────────────────────────

/// Top-level request body for the runliveresponse endpoint.
/// Field names are PascalCase to match the MDE API contract.
#[derive(Debug, Serialize, Deserialize)]
pub struct LiveResponseRequest {
    #[serde(rename = "Commands")]
    pub commands: Vec<Command>,
    #[serde(rename = "Comment")]
    pub comment: String,
}

/// A single command within a live response session.
/// Commands execute in order; if one fails, subsequent commands are skipped.
#[derive(Debug, Serialize, Deserialize)]
pub struct Command {
    #[serde(rename = "type")]
    pub command_type: CommandType,
    pub params: Vec<Param>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum CommandType {
    RunScript,
    GetFile,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Param {
    pub key: String,
    pub value: String,
}

// ── Response types ─────────────────────────────────────────────────────

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
    Pending,
    InProgress,
    Succeeded,
    Failed,
    Cancelled,
    /// Catch-all for unrecognized status strings from the API.
    /// Treated as non-terminal during polling (the loop continues).
    #[serde(other)]
    Unknown,
}

/// Represents the action status returned by POST (creation) and GET (polling).
/// The `status` field transitions through: Pending → InProgress → Succeeded | Failed | Cancelled.
#[derive(Debug, Deserialize)]
pub struct MachineAction {
    pub id: String,
    pub status: ActionStatus,
}

/// Wrapper for the download-link endpoint response.
/// `value` is a time-limited (30 min) Azure Blob Storage SAS URL.
#[derive(Debug, Deserialize)]
pub struct DownloadLink {
    pub value: String,
}

/// Parsed output from a RunScript command download.
/// The downloaded bytes are JSON in this shape.
#[derive(Debug, Deserialize)]
pub struct ScriptResult {
    pub script_name: String,
    pub exit_code: i32,
    pub script_output: String,
    pub script_errors: String,
}

// ── Polling configuration ──────────────────────────────────────────────

/// Controls the polling behavior when waiting for a live response action
/// to reach a terminal state (Succeeded, Failed, or Cancelled).
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

// ── Orchestration ──────────────────────────────────────────────────────

/// Runs a live response session end-to-end and returns the raw downloaded
/// bytes for each command in the request.
///
/// The caller is responsible for interpreting the bytes:
/// - For `RunScript`, deserialize as `ScriptResult`.
/// - For `GetFile`, the bytes are the file content (often a zip).
///
/// Polling behavior is controlled by `poll_config`. Pass `None` to use
/// defaults (5s interval, 10min timeout). See `PollConfig` for details.
///
/// Error conditions:
/// - Network or authentication failures at any step.
/// - The action reaches `Failed` or `Cancelled` status.
/// - Polling exceeds the configured timeout without reaching a terminal state.
pub async fn run_live_response(
    client: &MdeClient,
    machine_id: &str,
    request: &LiveResponseRequest,
    poll_config: Option<&PollConfig>,
) -> Result<Vec<bytes::Bytes>, Box<dyn Error + Send + Sync>> {
    let config = poll_config.cloned().unwrap_or_default();

    // Step 1: Start the live response action.
    let path = format!("api/machines/{machine_id}/runliveresponse");
    let action: MachineAction = client.post(&path, request).await?;

    // Step 2: Poll until the action reaches a terminal state or we time out.
    let poll_path = format!("api/machineactions/{}", action.id);
    let started = Instant::now();
    let completed = loop {
        tokio::time::sleep(config.interval).await;

        // Check timeout before making the next poll request, so we don't
        // send a request we already know we can't afford to wait for.
        if started.elapsed() > config.timeout {
            return Err(format!(
                "Polling timed out after {:?} for action {}",
                config.timeout, action.id
            )
            .into());
        }

        let status: MachineAction = client.get(&poll_path).await?;
        match status.status {
            // Terminal success — proceed to download.
            ActionStatus::Succeeded => break status,
            // Terminal failure — report and stop.
            ActionStatus::Failed | ActionStatus::Cancelled => {
                return Err(
                    format!("Live response action {:?}: {}", status.status, status.id).into(),
                );
            }
            // Non-terminal — keep polling. This includes Pending, InProgress,
            // and Unknown (future API status values we don't recognize yet).
            ActionStatus::Pending | ActionStatus::InProgress | ActionStatus::Unknown => continue,
        }
    };

    // Steps 3 & 4: For each command, get the download link then fetch the bytes.
    // The MDE API returns one download link per command, indexed in the same
    // order as the commands in the original request.
    let mut results = Vec::new();
    for (i, _cmd) in request.commands.iter().enumerate() {
        let link_path = format!(
            "api/machineactions/{}/GetLiveResponseResultDownloadLink(index={i})",
            completed.id
        );
        let link: DownloadLink = client.get(&link_path).await?;
        let data = client.download(&link.value).await?;
        results.push(data);
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Serde round-trip tests ─────────────────────────────────────────

    #[test]
    fn live_response_request_serializes_with_pascal_case_keys() {
        let req = LiveResponseRequest {
            comment: "test".to_string(),
            commands: vec![Command {
                command_type: CommandType::GetFile,
                params: vec![Param {
                    key: "Path".to_string(),
                    value: "C:\\temp\\file.txt".to_string(),
                }],
            }],
        };
        let json = serde_json::to_value(&req).unwrap();
        // API expects PascalCase keys
        assert!(
            json.get("Commands").is_some(),
            "should serialize as 'Commands'"
        );
        assert!(
            json.get("Comment").is_some(),
            "should serialize as 'Comment'"
        );
        assert!(
            json.get("commands").is_none(),
            "lowercase 'commands' should not appear"
        );
    }

    #[test]
    fn command_type_serializes_as_expected_strings() {
        let get_file = serde_json::to_string(&CommandType::GetFile).unwrap();
        let run_script = serde_json::to_string(&CommandType::RunScript).unwrap();
        assert_eq!(get_file, "\"GetFile\"");
        assert_eq!(run_script, "\"RunScript\"");
    }

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

    #[test]
    fn download_link_deserializes_sas_url() {
        let json = r#"{
            "@odata.context": "https://api.security.microsoft.com/api/$metadata#Edm.String",
            "value": "https://blob.core.windows.net/data/result?se=2026-01-01&sig=abc"
        }"#;
        let link: DownloadLink = serde_json::from_str(json).unwrap();
        assert!(link.value.starts_with("https://blob.core.windows.net"));
    }

    #[test]
    fn script_result_deserializes_from_download_content() {
        let json = r#"{
            "script_name": "whoami.ps1",
            "exit_code": 0,
            "script_output": "NT AUTHORITY\\SYSTEM\n",
            "script_errors": ""
        }"#;
        let result: ScriptResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.script_name, "whoami.ps1");
        assert_eq!(result.exit_code, 0);
        assert!(result.script_output.contains("SYSTEM"));
        assert!(result.script_errors.is_empty());
    }

    #[test]
    fn script_result_handles_nonzero_exit_code() {
        let json = r#"{
            "script_name": "bad.ps1",
            "exit_code": 1,
            "script_output": "",
            "script_errors": "Access denied"
        }"#;
        let result: ScriptResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.exit_code, 1);
        assert_eq!(result.script_errors, "Access denied");
    }

    #[test]
    fn getfile_request_roundtrip() {
        // Verify a GetFile request survives serialize → deserialize
        let original = LiveResponseRequest {
            comment: "Collect log".to_string(),
            commands: vec![Command {
                command_type: CommandType::GetFile,
                params: vec![Param {
                    key: "Path".to_string(),
                    value: "C:\\Windows\\TEMP\\log.zip".to_string(),
                }],
            }],
        };
        let json = serde_json::to_string(&original).unwrap();
        let restored: LiveResponseRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.commands.len(), 1);
        assert_eq!(
            restored.commands[0].params[0].value,
            "C:\\Windows\\TEMP\\log.zip"
        );
    }

    // ── PollConfig tests ──────────────────────────────────────────────

    #[test]
    fn poll_config_default_has_sane_values() {
        let config = PollConfig::default();
        assert_eq!(config.interval, Duration::from_secs(5));
        assert_eq!(config.timeout, Duration::from_secs(600));
    }
}
