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
//!
//! ## Shared action types
//!
//! The polling loop and action types (`ActionStatus`, `MachineAction`,
//! `PollConfig`) live in the [`crate::action`] module because they are
//! reused by other MDE endpoint families (isolate, AV scan, etc.).
//! For convenience, `ActionStatus` and `PollConfig` are re-exported here
//! so existing callers of `mde_lr::live_response::*` continue to work.

use serde::{Deserialize, Serialize};

use crate::action::{self, MachineAction};
use crate::client::MdeClient;

// Re-export shared action types so that existing callers who import from
// `live_response` (e.g. `use mde_lr::live_response::ActionStatus`) keep
// working without changing their import paths.
pub use crate::action::ActionStatus;
pub use crate::action::PollConfig;

// ── Request types ──────────────────────────────────────────────────────

/// Top-level request body for the runliveresponse endpoint.
/// Field names are PascalCase to match the MDE API contract.
#[derive(Debug, Serialize, Deserialize)]
pub struct LiveResponseRequest {
    /// The commands to execute on the remote device, in order.
    #[serde(rename = "Commands")]
    pub commands: Vec<Command>,
    /// Free-text comment attached to the action for audit purposes.
    #[serde(rename = "Comment")]
    pub comment: String,
}

/// A single command within a live response session.
/// Commands execute in order; if one fails, subsequent commands are skipped.
#[derive(Debug, Serialize, Deserialize)]
pub struct Command {
    /// The type of command to execute (`RunScript` or `GetFile`).
    #[serde(rename = "type")]
    pub command_type: CommandType,
    /// Key-value parameters for the command (e.g. `Path`, `ScriptName`).
    pub params: Vec<Param>,
}

/// The type of Live Response command to execute on the remote device.
#[derive(Debug, Serialize, Deserialize)]
pub enum CommandType {
    /// Execute a PowerShell script on the device and return its output.
    RunScript,
    /// Collect a file from the device and return its contents.
    GetFile,
    /// Upload a file from the MDE library to the device.
    PutFile,
}

/// A key-value parameter for a Live Response command.
///
/// Common keys include:
/// - `"Path"` — remote file path (for `GetFile`)
/// - `"ScriptName"` — script to execute (for `RunScript`)
/// - `"Args"` — arguments to pass to the script
#[derive(Debug, Serialize, Deserialize)]
pub struct Param {
    /// The parameter name (e.g. `"Path"`, `"ScriptName"`).
    pub key: String,
    /// The parameter value (e.g. a file path or script name).
    pub value: String,
}

// ── Response types ─────────────────────────────────────────────────────

/// Wrapper for the download-link endpoint response.
/// `value` is a time-limited (30 min) Azure Blob Storage SAS URL.
///
/// This is `pub(crate)` — callers of `run_live_response` receive the
/// downloaded bytes directly and never see the intermediate SAS URL.
#[derive(Debug, Deserialize)]
pub(crate) struct DownloadLink {
    pub(crate) value: String,
}

/// Parsed output from a RunScript command download.
/// The downloaded bytes are JSON in this shape.
#[derive(Debug, Deserialize)]
pub struct ScriptResult {
    /// The name of the script that was executed.
    pub script_name: String,
    /// The process exit code (0 = success, non-zero = error).
    pub exit_code: i32,
    /// The script's stdout output.
    pub script_output: String,
    /// The script's stderr output (empty string on success).
    pub script_errors: String,
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
/// defaults (5s interval, 10min timeout). See [`PollConfig`] for details.
///
/// Error variants returned:
/// - `MdeError::Auth` — token acquisition or refresh failed.
/// - `MdeError::Api` — MDE API returned a non-success HTTP status (with body preserved).
/// - `MdeError::Timeout` — polling exceeded the configured timeout.
/// - `MdeError::ActionFailed` — action reached `Failed` or `Cancelled` status.
/// - `MdeError::Network` — transport-level failure (DNS, TCP, TLS).
pub async fn run_live_response(
    client: &MdeClient,
    machine_id: &str,
    request: &LiveResponseRequest,
    poll_config: Option<&PollConfig>,
) -> crate::error::Result<Vec<bytes::Bytes>> {
    let config = poll_config.cloned().unwrap_or_default();

    // Step 1: Start the live response action.
    let path = format!("api/machines/{machine_id}/runliveresponse");
    let initial: MachineAction = client.post(&path, request).await?;

    // Step 2: Poll until the action reaches a terminal state or we time out.
    // This uses the shared polling abstraction from the action module, which
    // is also used by other MDE operations (isolate, AV scan, etc.).
    let completed = action::poll_action(client, &initial.id, &config).await?;

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
    use std::time::Duration;

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
        let put_file = serde_json::to_string(&CommandType::PutFile).unwrap();
        assert_eq!(get_file, "\"GetFile\"");
        assert_eq!(run_script, "\"RunScript\"");
        assert_eq!(put_file, "\"PutFile\"");
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

    // ── Re-export verification ───────────────────────────────────────

    #[test]
    fn action_status_is_accessible_through_live_response_module() {
        // Verify that ActionStatus is re-exported so existing callers
        // who import from live_response don't break.
        let status = ActionStatus::Succeeded;
        assert_eq!(status, ActionStatus::Succeeded);
    }

    #[test]
    fn poll_config_is_accessible_through_live_response_module() {
        // Verify that PollConfig can still be used via this module.
        let config = PollConfig::new(Duration::from_secs(1), Duration::from_secs(60));
        assert_eq!(config.interval, Duration::from_secs(1));
    }
}
