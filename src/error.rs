//! Typed error hierarchy for the mde-lr crate.
//!
//! `MdeError` replaces the previous `Box<dyn Error + Send + Sync>` convention
//! with a structured enum that preserves diagnostic context at each failure
//! boundary. Every variant carries enough information for callers to:
//! - Distinguish the failure category (auth, API, timeout, parse, network).
//! - Inspect the original cause via `source()` (thiserror derives this
//!   automatically from `#[source]` fields).
//! - Display a human-readable message that includes the relevant context
//!   (status code, action ID, elapsed duration, etc.).
//!
//! Design rationale:
//! - Variants map to real system boundaries, not to internal implementation
//!   details. `Auth` covers the Azure AD token endpoint; `Api` covers the
//!   MDE REST API; `Timeout` covers the polling loop; etc.
//! - `Api` preserves the response body, fixing the previous limitation where
//!   `error_for_status()` discarded MDE's diagnostic error messages.
//! - `Network` wraps `reqwest::Error` for transport-level failures (DNS,
//!   TCP, TLS) that don't produce an HTTP status code.
//! - `Parse` wraps `serde_json::Error` for deserialization failures, which
//!   can occur if the API returns unexpected response shapes.

use reqwest::StatusCode;

/// Unified error type for all mde-lr library operations.
///
/// Each variant corresponds to a distinct failure boundary in the system.
/// The `#[source]` attribute on inner errors enables `Error::source()` chaining
/// so callers (and logging frameworks) can traverse the full cause chain.
#[derive(Debug, thiserror::Error)]
pub enum MdeError {
    /// Authentication failure at the Azure AD token endpoint.
    ///
    /// This covers:
    /// - Non-2xx responses from `/oauth2/v2.0/token` (invalid credentials,
    ///   expired secrets, misconfigured permissions). The `body` field
    ///   contains Azure AD's AADSTS error codes and human-readable messages.
    /// - Network failures reaching the token endpoint.
    /// - Missing token after a refresh attempt (internal invariant violation).
    #[error("authentication failed: {message}")]
    Auth {
        /// Human-readable description of the authentication failure,
        /// including HTTP status and Azure AD error body when available.
        message: String,
        /// The underlying transport or parse error, if any.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// The MDE API returned a non-success HTTP status code.
    ///
    /// Unlike the previous `error_for_status()` approach, this variant
    /// preserves the full response body. MDE error responses contain
    /// diagnostic codes and human-readable explanations that are essential
    /// for debugging permission issues, invalid request shapes, and
    /// server-side failures.
    #[error("API error {status}: {body}")]
    Api {
        /// The HTTP status code returned by the MDE API.
        status: StatusCode,
        /// The raw response body text. May contain JSON error details
        /// from MDE, or an empty string if the body could not be read.
        body: String,
    },

    /// The polling loop exceeded the configured timeout without the action
    /// reaching a terminal state (Succeeded, Failed, or Cancelled).
    ///
    /// This typically means the target device is offline, slow to respond,
    /// or the action is stuck server-side. The caller can retry with a
    /// longer timeout or investigate device connectivity.
    #[error("polling timed out after {elapsed:?} for action {action_id}")]
    Timeout {
        /// The total elapsed time when the timeout was detected.
        elapsed: std::time::Duration,
        /// The MDE action ID that was being polled.
        action_id: String,
    },

    /// The MDE action reached a terminal failure state (`Failed` or
    /// `Cancelled`) instead of `Succeeded`.
    ///
    /// This is distinct from `Api` errors — the HTTP request itself
    /// succeeded (200 OK), but the action's business logic failed.
    #[error("action {action_id} reached terminal status: {status}")]
    ActionFailed {
        /// The terminal status that was reached.
        status: String,
        /// The MDE action ID.
        action_id: String,
    },

    /// JSON deserialization failed when parsing an API response body.
    ///
    /// This can occur if the MDE API returns an unexpected response shape,
    /// or if the download content from a RunScript result is malformed.
    #[error("failed to parse response: {0}")]
    Parse(#[from] serde_json::Error),

    /// A network-level failure occurred (DNS resolution, TCP connection,
    /// TLS handshake, request timeout, etc.).
    ///
    /// No HTTP status code is available because the request did not
    /// complete. This wraps the underlying `reqwest::Error` which carries
    /// detailed transport diagnostics.
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),
}

/// Convenience alias used throughout the library.
/// Keeps function signatures concise while providing the full typed error.
pub type Result<T> = std::result::Result<T, MdeError>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::time::Duration;

    #[test]
    fn auth_error_displays_message() {
        let err = MdeError::Auth {
            message: "token request failed (401): AADSTS700016".to_string(),
            source: None,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("AADSTS700016"),
            "display should include the Azure AD error code"
        );
        assert!(
            msg.contains("authentication failed"),
            "display should indicate auth failure"
        );
    }

    #[test]
    fn auth_error_with_source_chains_correctly() {
        // Simulate a serde parse error as the underlying cause.
        let json_err: serde_json::Error = serde_json::from_str::<String>("not-json").unwrap_err();
        let err = MdeError::Auth {
            message: "failed to parse token response".to_string(),
            source: Some(Box::new(json_err)),
        };
        // The source() chain should reach the serde error.
        assert!(
            err.source().is_some(),
            "Auth error with source should have a chained cause"
        );
    }

    #[test]
    fn api_error_preserves_status_and_body() {
        let err = MdeError::Api {
            status: StatusCode::FORBIDDEN,
            body: r#"{"error":{"code":"Forbidden","message":"Insufficient permissions"}}"#
                .to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("403"), "display should include status code");
        assert!(
            msg.contains("Insufficient permissions"),
            "display should include response body"
        );
    }

    #[test]
    fn timeout_error_includes_duration_and_action_id() {
        let err = MdeError::Timeout {
            elapsed: Duration::from_secs(605),
            action_id: "action-abc-123".to_string(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("action-abc-123"),
            "display should include action ID"
        );
        assert!(
            msg.contains("605"),
            "display should include elapsed seconds"
        );
    }

    #[test]
    fn action_failed_error_includes_status_and_id() {
        let err = MdeError::ActionFailed {
            status: "Failed".to_string(),
            action_id: "action-xyz".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("Failed"), "display should include status");
        assert!(
            msg.contains("action-xyz"),
            "display should include action ID"
        );
    }

    #[test]
    fn parse_error_wraps_serde_json() {
        let json_err: serde_json::Error =
            serde_json::from_str::<String>("{{bad json}}").unwrap_err();
        let err = MdeError::Parse(json_err);
        let msg = err.to_string();
        assert!(
            msg.contains("failed to parse response"),
            "display should indicate parse failure"
        );
        // source() should be the serde_json::Error
        assert!(
            err.source().is_some(),
            "Parse variant should chain to serde_json::Error"
        );
    }

    #[test]
    fn error_is_send_and_sync() {
        // MdeError must be Send + Sync for use across async task boundaries.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MdeError>();
    }
}
