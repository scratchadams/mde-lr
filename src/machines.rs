//! Machine lookup and management for the MDE API.
//!
//! This module covers the "Machines" endpoint family:
//!
//! - [`list_machines`] — retrieve a filtered/paginated list of devices.
//! - [`get_machine`] — retrieve a single device by its MDE machine ID.
//! - [`update_machine`] — update mutable device properties (tags, device value).
//!
//! These are read/update-only endpoints (no action polling involved).
//! The response type [`Machine`] captures the device properties returned by
//! the MDE API. Fields use `Option` where the API may omit them depending
//! on device state, onboarding status, or tenant configuration.
//!
//! ## OData filtering
//!
//! [`list_machines`] accepts an optional `$filter` query string for
//! server-side filtering. The MDE API supports OData V4 filter expressions
//! on fields like `computerDnsName`, `healthStatus`, `osPlatform`,
//! `riskScore`, `lastSeen`, and others. Pass `None` to retrieve all
//! devices (up to the 10,000 page limit).
//!
//! ## Permissions
//!
//! All three endpoints require `Machine.ReadWrite.All` (application) or
//! `Machine.ReadWrite` (delegated) permission.

use serde::{Deserialize, Serialize};

use crate::client::MdeClient;

// ── Response types ─────────────────────────────────────────────────────

/// A device (machine) as returned by the MDE API.
///
/// Field names use camelCase to match the MDE API contract exactly.
/// Optional fields are those the API may omit depending on device state,
/// onboarding status, or tenant configuration. For example, `aadDeviceId`
/// is only present when the device is Microsoft Entra (Azure AD) joined.
///
/// Reference: <https://learn.microsoft.com/en-us/defender-endpoint/api/machine>
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Machine {
    /// Unique MDE identifier for this device (SHA-1 of machine identity).
    pub id: String,

    /// Fully qualified DNS name of the device (e.g. `"host.contoso.com"`).
    #[serde(default)]
    pub computer_dns_name: Option<String>,

    /// ISO 8601 timestamp of when MDE first observed this device.
    #[serde(default)]
    pub first_seen: Option<String>,

    /// ISO 8601 timestamp of the last full device report received.
    /// Note: this reflects the last device *update*, not the "last seen"
    /// value shown in the MDE portal UI.
    #[serde(default)]
    pub last_seen: Option<String>,

    /// Operating system platform (e.g. `"Windows10"`, `"Windows11"`,
    /// `"Linux"`, `"macOS"`).
    #[serde(default)]
    pub os_platform: Option<String>,

    /// Operating system version string (e.g. `"1709"`, `"22H2"`).
    #[serde(default)]
    pub version: Option<String>,

    /// Operating system build number (e.g. `19045`). May be null for
    /// some OS platforms.
    #[serde(default)]
    pub os_build: Option<i64>,

    /// Operating system architecture: `"32-bit"` or `"64-bit"`.
    #[serde(default)]
    pub os_architecture: Option<String>,

    /// Last known local IP address on the device's NIC.
    #[serde(default)]
    pub last_ip_address: Option<String>,

    /// Last known external (internet-facing) IP address.
    #[serde(default)]
    pub last_external_ip_address: Option<String>,

    /// Device health status: `Active`, `Inactive`,
    /// `ImpairedCommunication`, `NoSensorData`,
    /// `NoSensorDataImpairedCommunication`, or `Unknown`.
    #[serde(default)]
    pub health_status: Option<String>,

    /// Onboarding status: `onboarded`, `CanBeOnboarded`, `Unsupported`,
    /// or `InsufficientInfo`.
    #[serde(default)]
    pub onboarding_status: Option<String>,

    /// Risk score as evaluated by MDE: `None`, `Informational`, `Low`,
    /// `Medium`, or `High`.
    #[serde(default)]
    pub risk_score: Option<String>,

    /// Exposure level: `None`, `Low`, `Medium`, or `High`.
    #[serde(default)]
    pub exposure_level: Option<String>,

    /// Device value classification: `Normal`, `Low`, or `High`.
    /// This is one of the two fields updatable via [`update_machine`].
    #[serde(default)]
    pub device_value: Option<String>,

    /// Microsoft Entra (Azure AD) device ID. Only present when the
    /// device is Entra-joined.
    #[serde(default)]
    pub aad_device_id: Option<String>,

    /// RBAC device group name that this machine belongs to.
    #[serde(default)]
    pub rbac_group_name: Option<String>,

    /// RBAC device group numeric ID.
    #[serde(default)]
    pub rbac_group_id: Option<i64>,

    /// Tags assigned to this device. This is one of the two fields
    /// updatable via [`update_machine`].
    ///
    /// Note: the MDE PATCH endpoint *replaces* the entire tag set —
    /// include existing tags in the update request to preserve them.
    #[serde(default)]
    pub machine_tags: Vec<String>,
}

/// OData collection wrapper returned by list endpoints.
///
/// The MDE API wraps collections in `{ "value": [...] }` with an
/// optional `@odata.context` metadata field. This wrapper is generic
/// so it can be reused by other list endpoints (alerts, indicators, etc.)
/// if needed in the future.
#[derive(Debug, Deserialize)]
pub struct ODataList<T> {
    /// The array of result items.
    pub value: Vec<T>,
}

// ── Request types ──────────────────────────────────────────────────────

/// Request body for the PATCH `/api/machines/{id}` endpoint.
///
/// Only `machineTags` and `deviceValue` are updatable. Both are optional —
/// omit a field to leave it unchanged. However, note that `machineTags`
/// is a *replace* operation: if you include it, the provided list fully
/// replaces the existing tags. To add a tag, first GET the machine to
/// read current tags, then include them all in the update.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateMachineRequest {
    /// New tag set for the device. Replaces existing tags entirely.
    /// Set to `None` to leave tags unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine_tags: Option<Vec<String>>,

    /// New device value classification: `"Normal"`, `"Low"`, or `"High"`.
    /// Set to `None` to leave unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_value: Option<String>,
}

// ── Endpoint functions ─────────────────────────────────────────────────

/// Retrieves a paginated list of machines that have communicated with MDE.
///
/// Pass an OData `$filter` expression to narrow results server-side, or
/// `None` to retrieve all devices (up to the 10,000 page limit).
///
/// # Examples of filter expressions
///
/// - `"healthStatus eq 'Active'"` — only active devices.
/// - `"osPlatform eq 'Windows10'"` — only Windows 10 devices.
/// - `"lastSeen gt 2026-01-01T00:00:00Z"` — devices seen after a date.
/// - `"machineTags/any(t: t eq 'VIP')"` — devices with a specific tag.
///
/// See the MDE OData query documentation for the full expression syntax.
///
/// # Errors
///
/// - `MdeError::Api` — the MDE API returned a non-success status (e.g.
///   400 for a malformed filter, 403 for insufficient permissions).
/// - `MdeError::Auth` — token acquisition or refresh failed.
/// - `MdeError::Network` — transport-level failure.
pub async fn list_machines(
    client: &MdeClient,
    filter: Option<&str>,
) -> crate::error::Result<Vec<Machine>> {
    // Build the path with an optional $filter query parameter.
    // The MDE API accepts OData V4 filter syntax on /api/machines.
    let path = match filter {
        Some(f) => format!("api/machines?$filter={f}"),
        None => "api/machines".to_string(),
    };
    let response: ODataList<Machine> = client.get(&path).await?;
    Ok(response.value)
}

/// Retrieves a single machine by its MDE machine ID.
///
/// The `machine_id` is the SHA-1 identifier assigned by MDE (visible in
/// the portal URL and returned by list/action endpoints).
///
/// # Errors
///
/// - `MdeError::Api` — non-success HTTP status. A 404 means the machine
///   ID was not found or the caller lacks access to that device group.
/// - `MdeError::Auth` — token acquisition or refresh failed.
/// - `MdeError::Network` — transport-level failure.
pub async fn get_machine(client: &MdeClient, machine_id: &str) -> crate::error::Result<Machine> {
    let path = format!("api/machines/{machine_id}");
    client.get(&path).await
}

/// Updates mutable properties of a machine (tags and/or device value).
///
/// Returns the full updated [`Machine`] entity. Note that `machineTags`
/// is a *replace* operation — the provided list fully replaces existing
/// tags. To append a tag, first call [`get_machine`] to read current
/// tags, add the new tag to the list, then pass the full list here.
///
/// # Errors
///
/// - `MdeError::Api` — non-success HTTP status. Common cases:
///   - 404: machine not found.
///   - 400: invalid `deviceValue` string.
///   - 403: insufficient `Machine.ReadWrite.All` permission.
/// - `MdeError::Auth` — token acquisition or refresh failed.
/// - `MdeError::Network` — transport-level failure.
pub async fn update_machine(
    client: &MdeClient,
    machine_id: &str,
    update: &UpdateMachineRequest,
) -> crate::error::Result<Machine> {
    let path = format!("api/machines/{machine_id}");
    client.patch(&path, update).await
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Machine deserialization ──────────────────────────────────────

    #[test]
    fn machine_deserializes_full_response() {
        // Exercises the full Machine struct against a realistic API response
        // based on the MDE documentation example.
        let json = r#"{
            "id": "1e5bc9d7e413ddd7902c2932e418702b84d0cc07",
            "computerDnsName": "mymachine1.contoso.com",
            "firstSeen": "2018-08-02T14:55:03.7791856Z",
            "lastSeen": "2018-08-02T14:55:03.7791856Z",
            "osPlatform": "Windows10",
            "version": "1709",
            "osBuild": 18209,
            "osArchitecture": "64-bit",
            "lastIpAddress": "172.17.230.209",
            "lastExternalIpAddress": "167.220.196.71",
            "healthStatus": "Active",
            "onboardingStatus": "onboarded",
            "rbacGroupId": 140,
            "rbacGroupName": "The-A-Team",
            "riskScore": "Low",
            "exposureLevel": "Medium",
            "deviceValue": "Normal",
            "aadDeviceId": "80fe8ff8-2624-418e-9591-41f0491218f9",
            "machineTags": ["test tag 1", "test tag 2"]
        }"#;
        let machine: Machine = serde_json::from_str(json).unwrap();
        assert_eq!(machine.id, "1e5bc9d7e413ddd7902c2932e418702b84d0cc07");
        assert_eq!(
            machine.computer_dns_name.as_deref(),
            Some("mymachine1.contoso.com")
        );
        assert_eq!(machine.os_platform.as_deref(), Some("Windows10"));
        assert_eq!(machine.os_build, Some(18209));
        assert_eq!(machine.os_architecture.as_deref(), Some("64-bit"));
        assert_eq!(machine.health_status.as_deref(), Some("Active"));
        assert_eq!(machine.risk_score.as_deref(), Some("Low"));
        assert_eq!(machine.exposure_level.as_deref(), Some("Medium"));
        assert_eq!(machine.device_value.as_deref(), Some("Normal"));
        assert_eq!(
            machine.aad_device_id.as_deref(),
            Some("80fe8ff8-2624-418e-9591-41f0491218f9")
        );
        assert_eq!(machine.rbac_group_name.as_deref(), Some("The-A-Team"));
        assert_eq!(machine.rbac_group_id, Some(140));
        assert_eq!(machine.machine_tags, vec!["test tag 1", "test tag 2"]);
    }

    #[test]
    fn machine_deserializes_minimal_response() {
        // The API may return sparse responses for devices with limited
        // information (e.g. CanBeOnboarded status, no sensor data).
        // All Optional fields should gracefully default to None.
        let json = r#"{"id": "sparse-device-001"}"#;
        let machine: Machine = serde_json::from_str(json).unwrap();
        assert_eq!(machine.id, "sparse-device-001");
        assert!(machine.computer_dns_name.is_none());
        assert!(machine.os_platform.is_none());
        assert!(machine.health_status.is_none());
        assert!(machine.machine_tags.is_empty());
    }

    #[test]
    fn machine_ignores_unknown_fields() {
        // Forward compatibility: if the API adds new fields, deserialization
        // should not fail. serde's default behavior (deny_unknown_fields
        // is NOT set) handles this.
        let json = r#"{
            "id": "device-future",
            "computerDnsName": "future.contoso.com",
            "brandNewField": "surprise",
            "anotherNewThing": 42
        }"#;
        let machine: Machine = serde_json::from_str(json).unwrap();
        assert_eq!(machine.id, "device-future");
        assert_eq!(
            machine.computer_dns_name.as_deref(),
            Some("future.contoso.com")
        );
    }

    // ── ODataList deserialization ────────────────────────────────────

    #[test]
    fn odata_list_deserializes_machine_collection() {
        let json = r#"{
            "@odata.context": "https://api.security.microsoft.com/api/$metadata#Machines",
            "value": [
                {"id": "device-1", "computerDnsName": "host1.contoso.com"},
                {"id": "device-2", "computerDnsName": "host2.contoso.com"}
            ]
        }"#;
        let list: ODataList<Machine> = serde_json::from_str(json).unwrap();
        assert_eq!(list.value.len(), 2);
        assert_eq!(list.value[0].id, "device-1");
        assert_eq!(list.value[1].id, "device-2");
    }

    #[test]
    fn odata_list_handles_empty_collection() {
        let json = r#"{"value": []}"#;
        let list: ODataList<Machine> = serde_json::from_str(json).unwrap();
        assert!(list.value.is_empty());
    }

    // ── UpdateMachineRequest serialization ───────────────────────────

    #[test]
    fn update_request_serializes_both_fields() {
        let req = UpdateMachineRequest {
            machine_tags: Some(vec!["VIP".to_string(), "Prod".to_string()]),
            device_value: Some("High".to_string()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(
            json["machineTags"],
            serde_json::json!(["VIP", "Prod"]),
            "tags should serialize as camelCase array"
        );
        assert_eq!(json["deviceValue"], "High");
    }

    #[test]
    fn update_request_omits_none_fields() {
        // When a field is None, it should be omitted from the JSON body
        // entirely so the API leaves that property unchanged.
        let req = UpdateMachineRequest {
            machine_tags: None,
            device_value: Some("Low".to_string()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert!(
            json.get("machineTags").is_none(),
            "None machineTags should be omitted from JSON"
        );
        assert_eq!(json["deviceValue"], "Low");
    }

    #[test]
    fn update_request_tags_only() {
        let req = UpdateMachineRequest {
            machine_tags: Some(vec!["Demo".to_string()]),
            device_value: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["machineTags"], serde_json::json!(["Demo"]));
        assert!(
            json.get("deviceValue").is_none(),
            "None deviceValue should be omitted from JSON"
        );
    }
}
