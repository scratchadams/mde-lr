//! Live Response request types and orchestration for the MDE API.
//!
//! The Live Response API is a 4-step async flow:
//! 1. POST `/api/machines/{id}/runliveresponse` — starts the action (returns `Pending`).
//! 2. Poll `GET /api/machineactions/{id}` — wait until status is `Succeeded`.
//! 3. GET `.../GetLiveResponseResultDownloadLink(index=N)` — get a time-limited Azure SAS URL.
//! 4. Download from the SAS URL — raw bytes (no bearer auth; SAS token is in the query string).
//!
//! Both `RunScript` and `GetFile` results go through the same download-link
//! mechanism. The difference is in how the caller interprets the bytes:
//! - `RunScript`: JSON with `script_name`, `exit_code`, `script_output`, `script_errors`.
//! - `GetFile`: raw file bytes (typically a zip).

use serde::{Serialize, Deserialize};
use std::error::Error;

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

/// Represents the action status returned by POST (creation) and GET (polling).
/// The `status` field transitions through: Pending → InProgress → Succeeded | Failed | Cancelled.
#[derive(Debug, Deserialize)]
pub struct MachineAction {
    pub id: String,
    pub status: String,
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

// ── Orchestration ──────────────────────────────────────────────────────

/// Runs a live response session end-to-end and returns the raw downloaded
/// bytes for each command in the request.
///
/// The caller is responsible for interpreting the bytes:
/// - For `RunScript`, deserialize as `ScriptResult`.
/// - For `GetFile`, the bytes are the file content (often a zip).
///
/// Polling uses a fixed 5-second interval. The loop runs indefinitely until
/// the action reaches a terminal state (`Succeeded`, `Failed`, `Cancelled`).
pub async fn run_live_response(
    client: &MdeClient,
    machine_id: &str,
    request: &LiveResponseRequest,
) -> Result<Vec<bytes::Bytes>, Box<dyn Error + Send + Sync>> {
    // Step 1: Start the live response action.
    let path = format!("api/machines/{}/runliveresponse", machine_id);
    let action: MachineAction = client.post(&path, request).await?;

    // Step 2: Poll until the action reaches a terminal state.
    let poll_path = format!("api/machineactions/{}", action.id);
    let completed = loop {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let status: MachineAction = client.get(&poll_path).await?;
        match status.status.as_str() {
            "Succeeded" => break status,
            "Failed" | "Cancelled" => {
                return Err(format!("Live response action {}: {}", status.status, status.id).into());
            }
            _ => continue, // Pending, InProgress, etc.
        }
    };

    // Steps 3 & 4: For each command, get the download link then fetch the bytes.
    let mut results = Vec::new();
    for (i, _cmd) in request.commands.iter().enumerate() {
        let link_path = format!(
            "api/machineactions/{}/GetLiveResponseResultDownloadLink(index={})",
            completed.id, i
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
        assert!(json.get("Commands").is_some(), "should serialize as 'Commands'");
        assert!(json.get("Comment").is_some(), "should serialize as 'Comment'");
        assert!(json.get("commands").is_none(), "lowercase 'commands' should not appear");
    }

    #[test]
    fn command_type_serializes_as_expected_strings() {
        let get_file = serde_json::to_string(&CommandType::GetFile).unwrap();
        let run_script = serde_json::to_string(&CommandType::RunScript).unwrap();
        assert_eq!(get_file, "\"GetFile\"");
        assert_eq!(run_script, "\"RunScript\"");
    }

    #[test]
    fn machine_action_deserializes_from_api_response() {
        let json = r#"{
            "id": "abc-123",
            "type": "LiveResponse",
            "status": "Pending",
            "machineId": "device-456",
            "commands": []
        }"#;
        let action: MachineAction = serde_json::from_str(json).unwrap();
        assert_eq!(action.id, "abc-123");
        assert_eq!(action.status, "Pending");
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
        assert_eq!(restored.commands[0].params[0].value, "C:\\Windows\\TEMP\\log.zip");
    }
}
