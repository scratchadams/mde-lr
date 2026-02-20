//! Machine action endpoints for the MDE API.
//!
//! This module covers the "Machine Actions" endpoint family — remediation
//! operations that are initiated via POST and then polled for completion.
//! Every function in this module follows the same two-step pattern:
//!
//! 1. **POST** to `/api/machines/{id}/<action>` — creates the action
//!    and returns a [`MachineAction`] with `Pending` status.
//! 2. **Poll** via [`poll_action`] — waits until the action reaches a
//!    terminal state (`Succeeded`, `Failed`, or `Cancelled`).
//!
//! The polling step is optional — each function accepts an
//! `Option<&PollConfig>` so callers can choose fire-and-forget (pass
//! `None` and use the returned action ID to poll later) or wait for
//! completion (pass `Some(&config)`).
//!
//! ## Endpoints
//!
//! | Function | API Path | Permission |
//! |----------|----------|------------|
//! | [`isolate_machine`] | POST `.../isolate` | `Machine.Isolate` |
//! | [`unisolate_machine`] | POST `.../unisolate` | `Machine.Isolate` |
//! | [`run_antivirus_scan`] | POST `.../runAntiVirusScan` | `Machine.Scan` |
//! | [`collect_investigation_package`] | POST `.../collectInvestigationPackage` | `Machine.CollectForensics` |
//! | [`stop_and_quarantine_file`] | POST `.../StopAndQuarantineFile` | `Machine.StopAndQuarantine` |
//! | [`restrict_code_execution`] | POST `.../restrictCodeExecution` | `Machine.RestrictExecution` |
//! | [`unrestrict_code_execution`] | POST `.../unrestrictCodeExecution` | `Machine.RestrictExecution` |
//!
//! ## References
//!
//! - <https://learn.microsoft.com/en-us/defender-endpoint/api/machineaction>
//! - <https://learn.microsoft.com/en-us/defender-endpoint/api/isolate-machine>

use serde::Serialize;

use crate::action::{MachineAction, PollConfig, poll_action};
use crate::client::MdeClient;

// ── Request types ──────────────────────────────────────────────────────
//
// All request bodies use PascalCase field names to match the MDE API
// contract. Each action endpoint has its own request struct because the
// required fields differ (e.g. IsolationType for isolate, ScanType for
// AV scan, Sha1 for stop-and-quarantine).

/// Request body for the isolate machine endpoint.
///
/// Reference: <https://learn.microsoft.com/en-us/defender-endpoint/api/isolate-machine>
#[derive(Debug, Serialize)]
pub struct IsolateRequest {
    /// Audit comment explaining why the device is being isolated. Required.
    #[serde(rename = "Comment")]
    pub comment: String,
    /// Type of isolation to apply:
    /// - `"Full"` — block all network access (managed devices).
    /// - `"Selective"` — restrict only certain apps from network access.
    /// - `"UnManagedDevice"` — contain an unmanaged device.
    #[serde(rename = "IsolationType")]
    pub isolation_type: String,
}

/// Request body for the unisolate (release from isolation) endpoint.
///
/// Reference: <https://learn.microsoft.com/en-us/defender-endpoint/api/unisolate-machine>
#[derive(Debug, Serialize)]
pub struct UnisolateRequest {
    /// Audit comment explaining why isolation is being lifted. Required.
    #[serde(rename = "Comment")]
    pub comment: String,
}

/// Request body for the run antivirus scan endpoint.
///
/// Reference: <https://learn.microsoft.com/en-us/defender-endpoint/api/run-av-scan>
#[derive(Debug, Serialize)]
pub struct AntivirusScanRequest {
    /// Audit comment explaining why the scan is being initiated. Required.
    #[serde(rename = "Comment")]
    pub comment: String,
    /// Type of scan to perform:
    /// - `"Quick"` — scan common malware locations only.
    /// - `"Full"` — scan the entire device (slower, more thorough).
    #[serde(rename = "ScanType")]
    pub scan_type: String,
}

/// Request body for the collect investigation package endpoint.
///
/// Reference: <https://learn.microsoft.com/en-us/defender-endpoint/api/collect-investigation-package>
#[derive(Debug, Serialize)]
pub struct CollectInvestigationPackageRequest {
    /// Audit comment explaining why forensic data is being collected. Required.
    #[serde(rename = "Comment")]
    pub comment: String,
}

/// Request body for the stop and quarantine file endpoint.
///
/// Reference: <https://learn.microsoft.com/en-us/defender-endpoint/api/stop-and-quarantine-file>
#[derive(Debug, Serialize)]
pub struct StopAndQuarantineFileRequest {
    /// Audit comment explaining why the file is being quarantined. Required.
    #[serde(rename = "Comment")]
    pub comment: String,
    /// SHA-1 hash of the file to stop and quarantine. Required.
    /// The file must not belong to a trusted publisher or be Microsoft-signed.
    #[serde(rename = "Sha1")]
    pub sha1: String,
}

/// Request body for the restrict code execution endpoint.
///
/// Reference: <https://learn.microsoft.com/en-us/defender-endpoint/api/restrict-code-execution>
#[derive(Debug, Serialize)]
pub struct RestrictCodeExecutionRequest {
    /// Audit comment explaining why app execution is being restricted. Required.
    #[serde(rename = "Comment")]
    pub comment: String,
}

/// Request body for the unrestrict code execution endpoint.
///
/// Reference: <https://learn.microsoft.com/en-us/defender-endpoint/api/unrestrict-code-execution>
#[derive(Debug, Serialize)]
pub struct UnrestrictCodeExecutionRequest {
    /// Audit comment explaining why the app restriction is being lifted. Required.
    #[serde(rename = "Comment")]
    pub comment: String,
}

// ── Shared helper ──────────────────────────────────────────────────────

/// Posts an action request and optionally polls until completion.
///
/// This helper encapsulates the two-step pattern shared by all machine
/// action endpoints: POST to create → poll until terminal status.
/// When `poll_config` is `None`, the action is created but not polled —
/// the caller receives the initial `MachineAction` (typically `Pending`)
/// and can poll later using [`poll_action`] directly.
async fn post_and_poll<B: Serialize>(
    client: &MdeClient,
    path: &str,
    body: &B,
    poll_config: Option<&PollConfig>,
) -> crate::error::Result<MachineAction> {
    let action: MachineAction = client.post(path, body).await?;

    match poll_config {
        Some(config) => poll_action(client, &action.id, config).await,
        None => Ok(action),
    }
}

// ── Endpoint functions ─────────────────────────────────────────────────

/// Isolates a device from the network.
///
/// Isolation prevents the device from communicating with external
/// networks while maintaining connectivity to the MDE cloud service.
/// Use [`unisolate_machine`] to release the device.
///
/// Pass `poll_config` to wait for the action to complete, or `None`
/// to fire-and-forget (the returned [`MachineAction`] will have the
/// action ID for later polling).
///
/// # Errors
///
/// - `MdeError::Api` — non-success HTTP status (e.g. 400 if an action
///   is already in progress on this device).
/// - `MdeError::ActionFailed` — the isolation action failed or was cancelled.
/// - `MdeError::Timeout` — polling exceeded the configured timeout.
/// - `MdeError::Auth` / `MdeError::Network` — auth or transport failure.
pub async fn isolate_machine(
    client: &MdeClient,
    machine_id: &str,
    request: &IsolateRequest,
    poll_config: Option<&PollConfig>,
) -> crate::error::Result<MachineAction> {
    let path = format!("api/machines/{machine_id}/isolate");
    post_and_poll(client, &path, request, poll_config).await
}

/// Releases a device from network isolation.
///
/// This reverses a previous [`isolate_machine`] call. The device will
/// regain full network connectivity once the action succeeds.
///
/// # Errors
///
/// Same error variants as [`isolate_machine`].
pub async fn unisolate_machine(
    client: &MdeClient,
    machine_id: &str,
    request: &UnisolateRequest,
    poll_config: Option<&PollConfig>,
) -> crate::error::Result<MachineAction> {
    let path = format!("api/machines/{machine_id}/unisolate");
    post_and_poll(client, &path, request, poll_config).await
}

/// Initiates a Microsoft Defender Antivirus scan on a device.
///
/// The scan runs alongside other AV solutions. Defender Antivirus can
/// be in Passive mode. Use `"Quick"` for common malware locations or
/// `"Full"` for a comprehensive device scan.
///
/// # Errors
///
/// Same error variants as [`isolate_machine`].
pub async fn run_antivirus_scan(
    client: &MdeClient,
    machine_id: &str,
    request: &AntivirusScanRequest,
    poll_config: Option<&PollConfig>,
) -> crate::error::Result<MachineAction> {
    let path = format!("api/machines/{machine_id}/runAntiVirusScan");
    post_and_poll(client, &path, request, poll_config).await
}

/// Collects a forensic investigation package from a device.
///
/// The package contains logs, registry hives, and other forensic
/// artifacts useful for incident investigation. The resulting package
/// can be downloaded via the machine action's download link after
/// the action succeeds.
///
/// # Errors
///
/// - `MdeError::Api` — 400 if a collection is already running on this device.
/// - Other error variants same as [`isolate_machine`].
pub async fn collect_investigation_package(
    client: &MdeClient,
    machine_id: &str,
    request: &CollectInvestigationPackageRequest,
    poll_config: Option<&PollConfig>,
) -> crate::error::Result<MachineAction> {
    let path = format!("api/machines/{machine_id}/collectInvestigationPackage");
    post_and_poll(client, &path, request, poll_config).await
}

/// Stops execution of a file on a device and quarantines it.
///
/// The file is identified by its SHA-1 hash. It must not belong to a
/// trusted third-party publisher or be signed by Microsoft.
///
/// # Errors
///
/// Same error variants as [`isolate_machine`].
pub async fn stop_and_quarantine_file(
    client: &MdeClient,
    machine_id: &str,
    request: &StopAndQuarantineFileRequest,
    poll_config: Option<&PollConfig>,
) -> crate::error::Result<MachineAction> {
    let path = format!("api/machines/{machine_id}/StopAndQuarantineFile");
    post_and_poll(client, &path, request, poll_config).await
}

/// Restricts application execution on a device.
///
/// Only applications signed by Microsoft or meeting Windows Defender
/// Application Control (WDAC) policy are allowed to run. All other
/// applications are blocked. Use [`unrestrict_code_execution`] to
/// lift the restriction.
///
/// # Errors
///
/// Same error variants as [`isolate_machine`].
pub async fn restrict_code_execution(
    client: &MdeClient,
    machine_id: &str,
    request: &RestrictCodeExecutionRequest,
    poll_config: Option<&PollConfig>,
) -> crate::error::Result<MachineAction> {
    let path = format!("api/machines/{machine_id}/restrictCodeExecution");
    post_and_poll(client, &path, request, poll_config).await
}

/// Removes application execution restrictions from a device.
///
/// This reverses a previous [`restrict_code_execution`] call, allowing
/// all applications to run again.
///
/// # Errors
///
/// Same error variants as [`isolate_machine`].
pub async fn unrestrict_code_execution(
    client: &MdeClient,
    machine_id: &str,
    request: &UnrestrictCodeExecutionRequest,
    poll_config: Option<&PollConfig>,
) -> crate::error::Result<MachineAction> {
    let path = format!("api/machines/{machine_id}/unrestrictCodeExecution");
    post_and_poll(client, &path, request, poll_config).await
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Request serialization tests ──────────────────────────────────
    //
    // Each request type must serialize to PascalCase keys matching the
    // MDE API contract exactly.

    #[test]
    fn isolate_request_serializes_with_pascal_case() {
        let req = IsolateRequest {
            comment: "Isolate due to alert".to_string(),
            isolation_type: "Full".to_string(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["Comment"], "Isolate due to alert");
        assert_eq!(json["IsolationType"], "Full");
        // Verify no snake_case keys leak through.
        assert!(json.get("comment").is_none());
        assert!(json.get("isolation_type").is_none());
    }

    #[test]
    fn unisolate_request_serializes_with_pascal_case() {
        let req = UnisolateRequest {
            comment: "Device cleared".to_string(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["Comment"], "Device cleared");
    }

    #[test]
    fn antivirus_scan_request_serializes_with_pascal_case() {
        let req = AntivirusScanRequest {
            comment: "Routine scan".to_string(),
            scan_type: "Quick".to_string(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["Comment"], "Routine scan");
        assert_eq!(json["ScanType"], "Quick");
    }

    #[test]
    fn collect_investigation_package_request_serializes() {
        let req = CollectInvestigationPackageRequest {
            comment: "Collect forensics".to_string(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["Comment"], "Collect forensics");
    }

    #[test]
    fn stop_and_quarantine_file_request_serializes() {
        let req = StopAndQuarantineFileRequest {
            comment: "Quarantine malware".to_string(),
            sha1: "87662bc3d60e4200ceaf7aae249d1c343f4b83c9".to_string(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["Comment"], "Quarantine malware");
        assert_eq!(json["Sha1"], "87662bc3d60e4200ceaf7aae249d1c343f4b83c9");
    }

    #[test]
    fn restrict_code_execution_request_serializes() {
        let req = RestrictCodeExecutionRequest {
            comment: "Restrict apps".to_string(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["Comment"], "Restrict apps");
    }

    #[test]
    fn unrestrict_code_execution_request_serializes() {
        let req = UnrestrictCodeExecutionRequest {
            comment: "Lift restriction".to_string(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["Comment"], "Lift restriction");
    }
}
