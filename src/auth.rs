//! OAuth2 client-credentials authentication for Microsoft identity platform.
//!
//! Acquires bearer tokens from Azure AD's `/oauth2/v2.0/token` endpoint using
//! the client_credentials grant. The token is cached in `TokenProvider` and
//! can be refreshed on demand. Consumers (e.g. `MdeClient`) read the cached
//! token via `token()` and call `refresh_token()` when it is absent or stale.

use serde::{Deserialize, Serialize};
use std::error::Error;
use std::time::Instant;

/// Azure AD v2.0 token endpoint. `{tenant_id}` is replaced at runtime.
const TOKEN_URL: &str = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token";

/// Form body sent to the token endpoint.
/// Fields are serialized as `application/x-www-form-urlencoded` by reqwest's `.form()`.
#[derive(Serialize)]
pub struct TokenRequest<'a> {
    client_id: &'a str,
    scope: &'a str,
    client_secret: &'a str,
    grant_type: &'a str,
}

/// Subset of the Azure AD token response that we need.
/// The endpoint returns additional fields (e.g. `ext_expires_in`) which are
/// silently ignored by serde because we don't mark the struct `deny_unknown_fields`.
#[derive(Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

/// Safety buffer subtracted from `expires_in` to trigger refresh before
/// the token actually expires. Prevents requests from racing the expiry boundary.
const EXPIRY_BUFFER_SECS: u64 = 60;

/// Manages OAuth2 token acquisition and caching.
///
/// Invariants:
/// - `response` is `None` until the first successful `refresh_token()` call.
/// - After a successful refresh, `token()` returns `Some` until the token
///   expires (with a 60-second safety buffer), the provider is dropped,
///   or the token is replaced by a subsequent refresh.
/// - `acquired_at` is always `Some` when `response` is `Some`.
pub struct TokenProvider {
    client: reqwest::Client,
    scope: String,
    tenant_id: String,
    client_id: String,
    client_secret: String,
    response: Option<TokenResponse>,
    acquired_at: Option<Instant>,
}

impl TokenProvider {
    pub fn new(tenant_id: &str, client_id: &str, client_secret: &str, scope: &str) -> Self {
        TokenProvider {
            client: reqwest::Client::new(),
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
            client: reqwest::Client::new(),
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
    pub async fn refresh_token(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let body = TokenRequest {
            client_id: &self.client_id,
            scope: &self.scope,
            client_secret: &self.client_secret,
            grant_type: "client_credentials",
        };

        let url = TOKEN_URL.replace("{tenant_id}", &self.tenant_id);

        let response = self.client.post(&url).form(&body).send().await?;

        // Read body before checking status so we can surface Microsoft's
        // detailed error (AADSTS codes) on failure.
        let status = response.status();
        let body = response.text().await?;

        if !status.is_success() {
            return Err(format!("Token request failed ({}): {}", status, body).into());
        }

        let resp: TokenResponse = serde_json::from_str(&body)?;
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
    fn token_url_interpolation() {
        let url = TOKEN_URL.replace("{tenant_id}", "abc-123");
        assert_eq!(
            url,
            "https://login.microsoftonline.com/abc-123/oauth2/v2.0/token"
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
        assert!(
            tp.token().is_none(),
            "token must be None after expiry"
        );
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
}
