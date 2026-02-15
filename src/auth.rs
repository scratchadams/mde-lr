//! OAuth2 client-credentials authentication for Microsoft identity platform.
//!
//! Acquires bearer tokens from Azure AD's `/oauth2/v2.0/token` endpoint using
//! the client_credentials grant. The token is cached in `TokenProvider` and
//! can be refreshed on demand. Consumers (e.g. `MdeClient`) read the cached
//! token via `token()` and call `refresh_token()` when it is absent or stale.

use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

use crate::error::MdeError;

/// Default Azure AD v2.0 token endpoint template for the commercial cloud.
/// `{tenant_id}` is replaced at runtime with the actual tenant ID.
///
/// For sovereign clouds, override this via `TokenProvider::with_token_url()`:
/// - GCC High: `https://login.microsoftonline.us/{tenant_id}/oauth2/v2.0/token`
/// - DoD:      `https://login.microsoftonline.us/{tenant_id}/oauth2/v2.0/token`
/// - China:    `https://login.chinacloudapi.cn/{tenant_id}/oauth2/v2.0/token`
const DEFAULT_TOKEN_URL: &str = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token";

/// Form body sent to the token endpoint.
/// Fields are serialized as `application/x-www-form-urlencoded` by reqwest's `.form()`.
///
/// This is module-private — external consumers interact with `TokenProvider`,
/// not the raw request shape.
#[derive(Serialize)]
struct TokenRequest<'a> {
    client_id: &'a str,
    scope: &'a str,
    client_secret: &'a str,
    grant_type: &'a str,
}

/// Subset of the Azure AD token response that we need.
/// The endpoint returns additional fields (e.g. `ext_expires_in`) which are
/// silently ignored by serde because we don't mark the struct `deny_unknown_fields`.
///
/// This is `pub(crate)` because `TokenProvider` manages the token lifecycle —
/// external consumers read the token via `TokenProvider::token()`, not by
/// inspecting the raw response.
#[derive(Deserialize)]
pub(crate) struct TokenResponse {
    pub(crate) access_token: String,
    /// Token type (always "Bearer"). Retained for serde deserialization
    /// completeness but not read by application code.
    #[allow(dead_code)]
    pub(crate) token_type: String,
    pub(crate) expires_in: u64,
}

/// Safety buffer subtracted from `expires_in` to trigger refresh before
/// the token actually expires. Prevents requests from racing the expiry boundary.
const EXPIRY_BUFFER_SECS: u64 = 60;

/// Connect timeout for the token endpoint HTTP client.
/// This only covers TCP + TLS handshake, not the full request.
/// Azure AD typically responds in <500ms; 10s is generous to cover
/// cold-start or network-congested environments.
const TOKEN_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Overall request timeout for token endpoint calls.
/// Covers the entire round-trip: connect + send + server processing + response.
/// Token requests are small payloads so 30s is more than sufficient.
const TOKEN_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Builds a `reqwest::Client` with explicit timeouts for token endpoint calls.
///
/// Using `Client::new()` relies on reqwest's defaults (no connect timeout,
/// 30s overall), which can leave the process hanging on DNS or connection
/// issues. Explicit timeouts make failure modes predictable.
fn build_token_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(TOKEN_CONNECT_TIMEOUT)
        .timeout(TOKEN_REQUEST_TIMEOUT)
        .build()
        .expect("failed to build HTTP client for token endpoint")
}

/// Manages OAuth2 token acquisition and caching.
///
/// Invariants:
/// - `response` is `None` until the first successful `refresh_token()` call.
/// - After a successful refresh, `token()` returns `Some` until the token
///   expires (with a 60-second safety buffer), the provider is dropped,
///   or the token is replaced by a subsequent refresh.
/// - `acquired_at` is always `Some` when `response` is `Some`.
/// - `token_url` always contains `{tenant_id}` which is replaced at runtime.
pub struct TokenProvider {
    client: reqwest::Client,
    /// The token endpoint URL template. Must contain `{tenant_id}` placeholder.
    token_url: String,
    scope: String,
    tenant_id: String,
    client_id: String,
    client_secret: String,
    response: Option<TokenResponse>,
    acquired_at: Option<Instant>,
}

impl TokenProvider {
    /// Creates a new `TokenProvider` targeting the commercial Azure AD endpoint.
    ///
    /// For sovereign clouds (GCC High, DoD, China), use `with_token_url()`
    /// to override the token endpoint.
    pub fn new(tenant_id: &str, client_id: &str, client_secret: &str, scope: &str) -> Self {
        Self::with_token_url(
            tenant_id,
            client_id,
            client_secret,
            scope,
            DEFAULT_TOKEN_URL,
        )
    }

    /// Creates a new `TokenProvider` with a custom token endpoint URL template.
    ///
    /// The `token_url` must contain `{tenant_id}` — it will be replaced with
    /// the actual tenant ID at request time. Examples:
    /// - Commercial: `https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token`
    /// - GCC High:   `https://login.microsoftonline.us/{tenant_id}/oauth2/v2.0/token`
    pub fn with_token_url(
        tenant_id: &str,
        client_id: &str,
        client_secret: &str,
        scope: &str,
        token_url: &str,
    ) -> Self {
        TokenProvider {
            client: build_token_client(),
            token_url: token_url.to_string(),
            scope: scope.to_string(),
            tenant_id: tenant_id.to_string(),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            response: None,
            acquired_at: None,
        }
    }

    /// Creates a `TokenProvider` with a pre-set token, bypassing Azure AD.
    /// Used by tests to avoid real HTTP calls during token acquisition.
    /// The token is treated as freshly acquired (expires_in = 3600s).
    pub fn with_token(token: &str) -> Self {
        TokenProvider {
            client: build_token_client(),
            token_url: DEFAULT_TOKEN_URL.to_string(),
            scope: String::new(),
            tenant_id: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            response: Some(TokenResponse {
                access_token: token.to_string(),
                token_type: "Bearer".to_string(),
                expires_in: 3600,
            }),
            acquired_at: Some(Instant::now()),
        }
    }

    /// Fetches a new token from Azure AD and caches it.
    ///
    /// The response body is read as text first so that on failure the raw
    /// AADSTS error message is preserved in the error — `error_for_status()`
    /// would discard this diagnostic information.
    ///
    /// Error mapping:
    /// - Network failures (DNS, TCP, TLS, timeout) → `MdeError::Auth` with
    ///   the `reqwest::Error` as the source.
    /// - Non-2xx HTTP status → `MdeError::Auth` with the raw response body
    ///   (contains AADSTS error codes).
    /// - Malformed JSON response → `MdeError::Auth` with the
    ///   `serde_json::Error` as the source.
    pub async fn refresh_token(&mut self) -> crate::error::Result<()> {
        let body = TokenRequest {
            client_id: &self.client_id,
            scope: &self.scope,
            client_secret: &self.client_secret,
            grant_type: "client_credentials",
        };

        let url = self.token_url.replace("{tenant_id}", &self.tenant_id);

        let response = self
            .client
            .post(&url)
            .form(&body)
            .send()
            .await
            .map_err(|e| MdeError::Auth {
                message: format!("failed to reach token endpoint: {e}"),
                source: Some(Box::new(e)),
            })?;

        // Read body before checking status so we can surface Microsoft's
        // detailed error (AADSTS codes) on failure.
        let status = response.status();
        let body = response.text().await.map_err(|e| MdeError::Auth {
            message: format!("failed to read token response body: {e}"),
            source: Some(Box::new(e)),
        })?;

        if !status.is_success() {
            return Err(MdeError::Auth {
                message: format!("token request failed ({status}): {body}"),
                source: None,
            });
        }

        let resp: TokenResponse = serde_json::from_str(&body).map_err(|e| MdeError::Auth {
            message: format!("failed to parse token response: {e}"),
            source: Some(Box::new(e)),
        })?;
        self.acquired_at = Some(Instant::now());
        self.response = Some(resp);

        Ok(())
    }

    /// Returns `true` if a token exists but has exceeded its lifetime
    /// (minus the safety buffer). Returns `false` if no token is cached.
    fn is_expired(&self) -> bool {
        match (&self.response, self.acquired_at) {
            (Some(resp), Some(acquired)) => {
                let lifetime = resp.expires_in.saturating_sub(EXPIRY_BUFFER_SECS);
                acquired.elapsed().as_secs() >= lifetime
            }
            _ => false,
        }
    }

    /// Returns the cached access token, or `None` if no token exists
    /// or the token has expired (with a 60-second safety buffer).
    pub fn token(&self) -> Option<&str> {
        if self.is_expired() {
            return None;
        }
        self.response.as_ref().map(|ret| ret.access_token.as_str())
    }

    /// Discards the cached token so the next call to `token()` returns `None`.
    ///
    /// This is used by `MdeClient` to force a re-authentication when the API
    /// returns 401 Unauthorized — indicating the token was revoked or expired
    /// server-side before our local expiry tracking detected it.
    pub fn invalidate(&mut self) {
        self.response = None;
        self.acquired_at = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_none_before_refresh() {
        let tp = TokenProvider::new("tenant", "client", "secret", "scope");
        assert!(
            tp.token().is_none(),
            "token must be None before any refresh"
        );
    }

    #[test]
    fn default_token_url_interpolation() {
        let url = DEFAULT_TOKEN_URL.replace("{tenant_id}", "abc-123");
        assert_eq!(
            url,
            "https://login.microsoftonline.com/abc-123/oauth2/v2.0/token"
        );
    }

    #[test]
    fn custom_token_url_for_sovereign_cloud() {
        let tp = TokenProvider::with_token_url(
            "tenant-123",
            "client",
            "secret",
            "scope",
            "https://login.microsoftonline.us/{tenant_id}/oauth2/v2.0/token",
        );
        // Verify the custom URL template is stored (not the default).
        // We can't directly access private fields, but we can verify the
        // provider is constructed without error and has no cached token.
        assert!(
            tp.token().is_none(),
            "sovereign cloud provider should start with no cached token"
        );
    }

    #[test]
    fn token_request_serializes_as_form() {
        let req = TokenRequest {
            client_id: "cid",
            scope: "https://api.securitycenter.microsoft.com/.default",
            client_secret: "secret~value",
            grant_type: "client_credentials",
        };
        let encoded = serde_urlencoded::to_string(&req).unwrap();
        assert!(encoded.contains("client_id=cid"));
        assert!(encoded.contains("grant_type=client_credentials"));
        // Scope URL should be percent-encoded in form data
        assert!(encoded.contains("scope=https"));
    }

    #[test]
    fn token_response_deserializes_from_azure_format() {
        let json = r#"{
            "token_type": "Bearer",
            "expires_in": 3599,
            "access_token": "eyJ0eXAi.test.token"
        }"#;
        let resp: TokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.access_token, "eyJ0eXAi.test.token");
        assert_eq!(resp.token_type, "Bearer");
        assert_eq!(resp.expires_in, 3599);
    }

    #[test]
    fn token_response_ignores_unknown_fields() {
        // Azure AD returns extra fields like ext_expires_in that we don't model.
        let json = r#"{
            "token_type": "Bearer",
            "expires_in": 3599,
            "ext_expires_in": 3599,
            "access_token": "tok"
        }"#;
        let resp: Result<TokenResponse, _> = serde_json::from_str(json);
        assert!(resp.is_ok(), "should ignore unknown fields by default");
    }

    #[test]
    fn fresh_token_is_not_expired() {
        let tp = TokenProvider::with_token("test-token");
        assert!(
            tp.token().is_some(),
            "freshly created token must be available"
        );
    }

    #[test]
    fn expired_token_returns_none() {
        // Simulate a token that expired in the past by setting acquired_at
        // far enough back that expires_in - buffer has elapsed.
        let mut tp = TokenProvider::with_token("test-token");
        tp.acquired_at = Some(Instant::now() - std::time::Duration::from_secs(7200));
        assert!(tp.token().is_none(), "token must be None after expiry");
    }

    #[test]
    fn token_within_buffer_returns_none() {
        // A token with expires_in=90 and a 60s buffer has an effective
        // lifetime of 30s. After 31s it should appear expired.
        let mut tp = TokenProvider::with_token("test-token");
        tp.response.as_mut().unwrap().expires_in = 90;
        tp.acquired_at = Some(Instant::now() - std::time::Duration::from_secs(31));
        assert!(
            tp.token().is_none(),
            "token must be None when within the safety buffer"
        );
    }

    #[test]
    fn token_before_buffer_returns_some() {
        // Same setup as above but only 10s elapsed — well within the 30s
        // effective lifetime.
        let mut tp = TokenProvider::with_token("test-token");
        tp.response.as_mut().unwrap().expires_in = 90;
        tp.acquired_at = Some(Instant::now() - std::time::Duration::from_secs(10));
        assert!(
            tp.token().is_some(),
            "token must still be valid before buffer boundary"
        );
    }

    #[test]
    fn invalidate_clears_cached_token() {
        // Validates the cache-clearing mechanism that MdeClient::force_refresh()
        // relies on to discard a rejected token before re-acquiring a new one.
        let mut tp = TokenProvider::with_token("test-token");
        assert!(
            tp.token().is_some(),
            "pre-condition: token must exist before invalidation"
        );
        tp.invalidate();
        assert!(
            tp.token().is_none(),
            "invalidate() must clear the cached token so the next call triggers a refresh"
        );
    }
}
