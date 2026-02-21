//! Live Response library file management for the MDE API.
//!
//! This module covers the "Library" endpoint family — management of
//! PowerShell scripts and other files stored in the MDE Live Response
//! library. These files are used by Live Response commands like
//! `RunScript` and `PutFile`.
//!
//! ## Endpoints
//!
//! | Function | API Path | Permission |
//! |----------|----------|------------|
//! | [`list_library_files`] | GET `/api/libraryfiles` | `Library.Manage` |
//! | [`upload_library_file`] | POST `/api/libraryfiles` | `Library.Manage` |
//! | [`delete_library_file`] | DELETE `/api/libraryfiles/{fileName}` | `Library.Manage` |
//!
//! ## Upload limitations
//!
//! File uploads use multipart/form-data and have a 20 MB size limit.
//! Because `reqwest::multipart::Form` is consumed on send (not `Clone`),
//! the upload method does **not** perform automatic 401 or 429 retry.
//! If the upload is rejected, the caller must rebuild the form and retry
//! at the application level.
//!
//! ## References
//!
//! - <https://learn.microsoft.com/en-us/defender-endpoint/api/list-library-files>
//! - <https://learn.microsoft.com/en-us/defender-endpoint/api/upload-library>
//! - <https://learn.microsoft.com/en-us/defender-endpoint/api/delete-library>

use serde::{Deserialize, Serialize};

use crate::client::MdeClient;
use crate::machines::ODataList;

// ── Response types ──────────────────────────────────────────────────────

/// A file in the MDE Live Response library.
///
/// Represents a script or other file that has been uploaded to the library
/// for use with Live Response commands. Field names use camelCase to match
/// the MDE API contract.
///
/// Reference: <https://learn.microsoft.com/en-us/defender-endpoint/api/library>
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LibraryFile {
    /// Name of the file in the library (e.g. `"Invoke-Collector.ps1"`).
    pub file_name: String,

    /// SHA-256 hash of the file content.
    #[serde(default)]
    pub sha256: Option<String>,

    /// User-provided description of the file's purpose.
    #[serde(default)]
    pub description: Option<String>,

    /// ISO 8601 timestamp of when the file was first uploaded.
    #[serde(default)]
    pub creation_time: Option<String>,

    /// ISO 8601 timestamp of the last modification.
    #[serde(default)]
    pub last_updated_time: Option<String>,

    /// Identity of the user or app that uploaded the file.
    #[serde(default)]
    pub created_by: Option<String>,

    /// Whether this script expects parameters when executed.
    #[serde(default)]
    pub has_parameters: bool,

    /// Description of the parameters this script accepts.
    #[serde(default)]
    pub parameters_description: Option<String>,
}

// ── Endpoint functions ──────────────────────────────────────────────────

/// Lists all files currently in the Live Response library.
///
/// Returns the full list of library files. The MDE API does not support
/// OData filtering on this endpoint — all files are returned in a single
/// response.
///
/// # Errors
///
/// - `MdeError::Api` — non-success HTTP status (e.g. 403 for insufficient
///   `Library.Manage` permission).
/// - `MdeError::Auth` — token acquisition or refresh failed.
/// - `MdeError::Network` — transport-level failure.
pub async fn list_library_files(client: &MdeClient) -> crate::error::Result<Vec<LibraryFile>> {
    let response: ODataList<LibraryFile> = client.get("api/libraryfiles").await?;
    Ok(response.value)
}

/// Uploads a file to the Live Response library.
///
/// The file is uploaded as multipart/form-data with the file content and
/// optional metadata fields (description, whether to overwrite existing).
/// Maximum file size is 20 MB.
///
/// **Important**: This method does not perform automatic 401 or 429 retry
/// because `reqwest::multipart::Form` is consumed on send. If the upload
/// fails, the caller must retry the entire operation.
///
/// # Arguments
///
/// * `client` — Authenticated MDE client.
/// * `file_name` — Name for the file in the library (e.g. `"collector.ps1"`).
/// * `file_bytes` — Raw content of the file to upload.
/// * `description` — Optional description of the file's purpose.
/// * `override_if_exists` — Whether to overwrite an existing file with the
///   same name. Defaults to `false` if not set.
///
/// # Errors
///
/// - `MdeError::Api` — non-success HTTP status (e.g. 400 for invalid file,
///   403 for insufficient permissions, 409 if file exists and override is false).
/// - `MdeError::Throttled` — the API returned 429 (no automatic retry for uploads).
/// - `MdeError::Auth` — token acquisition failed.
/// - `MdeError::Network` — transport-level failure.
pub async fn upload_library_file(
    client: &MdeClient,
    file_name: &str,
    file_bytes: Vec<u8>,
    description: Option<&str>,
    override_if_exists: bool,
) -> crate::error::Result<LibraryFile> {
    // Build the multipart form matching the MDE API contract.
    // Field names are case-sensitive: "file", "Description", "OverrideIfExists".
    let file_part = reqwest::multipart::Part::bytes(file_bytes).file_name(file_name.to_string());

    let mut form = reqwest::multipart::Form::new().part("file", file_part);

    if let Some(desc) = description {
        form = form.text("Description", desc.to_string());
    }

    if override_if_exists {
        form = form.text("OverrideIfExists", "true".to_string());
    }

    client.upload_multipart("api/libraryfiles", form).await
}

/// Deletes a file from the Live Response library by name.
///
/// Returns `Ok(())` on success (HTTP 204 No Content). The file is
/// permanently removed from the library and can no longer be referenced
/// by Live Response commands.
///
/// # Errors
///
/// - `MdeError::Api` — non-success HTTP status. A 404 means the file
///   was not found in the library.
/// - `MdeError::Auth` — token acquisition or refresh failed.
/// - `MdeError::Network` — transport-level failure.
pub async fn delete_library_file(client: &MdeClient, file_name: &str) -> crate::error::Result<()> {
    let path = format!("api/libraryfiles/{file_name}");
    client.delete(&path).await
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── LibraryFile deserialization ──────────────────────────────────

    #[test]
    fn library_file_deserializes_full_response() {
        // Exercises the full LibraryFile struct against a realistic API
        // response based on the MDE documentation.
        let json = r#"{
            "fileName": "Invoke-Collector.ps1",
            "sha256": "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344",
            "description": "Forensic data collector script",
            "creationTime": "2026-01-15T10:30:00Z",
            "lastUpdatedTime": "2026-02-01T14:20:00Z",
            "createdBy": "admin@contoso.com",
            "hasParameters": true,
            "parametersDescription": "-OutputPath: Directory for collected artifacts"
        }"#;
        let file: LibraryFile = serde_json::from_str(json).unwrap();
        assert_eq!(file.file_name, "Invoke-Collector.ps1");
        assert_eq!(
            file.sha256.as_deref(),
            Some("aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344")
        );
        assert_eq!(
            file.description.as_deref(),
            Some("Forensic data collector script")
        );
        assert!(file.has_parameters);
        assert!(file.parameters_description.is_some());
        assert_eq!(file.created_by.as_deref(), Some("admin@contoso.com"));
    }

    #[test]
    fn library_file_deserializes_minimal_response() {
        // The API may return sparse responses. Only fileName is required;
        // all other fields should gracefully default.
        let json = r#"{"fileName": "simple.ps1"}"#;
        let file: LibraryFile = serde_json::from_str(json).unwrap();
        assert_eq!(file.file_name, "simple.ps1");
        assert!(file.sha256.is_none());
        assert!(file.description.is_none());
        assert!(!file.has_parameters);
    }

    #[test]
    fn library_file_ignores_unknown_fields() {
        // Forward compatibility: new API fields should not break deserialization.
        let json = r#"{
            "fileName": "future.ps1",
            "sha256": "abcd1234",
            "newField": "surprise"
        }"#;
        let file: LibraryFile = serde_json::from_str(json).unwrap();
        assert_eq!(file.file_name, "future.ps1");
    }

    #[test]
    fn odata_list_deserializes_library_file_collection() {
        // Verify that ODataList<LibraryFile> works correctly since we
        // reuse the generic wrapper from the machines module.
        let json = r#"{
            "@odata.context": "https://api.security.microsoft.com/api/$metadata#LibraryFiles",
            "value": [
                {"fileName": "script1.ps1", "hasParameters": false},
                {"fileName": "script2.ps1", "hasParameters": true}
            ]
        }"#;
        let list: ODataList<LibraryFile> = serde_json::from_str(json).unwrap();
        assert_eq!(list.value.len(), 2);
        assert_eq!(list.value[0].file_name, "script1.ps1");
        assert!(list.value[1].has_parameters);
    }
}
