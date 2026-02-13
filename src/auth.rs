//! OAuth2 client-credentials authentication for Microsoft identity platform.
//!
//! Acquires bearer tokens from Azure AD's `/oauth2/v2.0/token` endpoint using
//! the client_credentials grant. The token is cached in `TokenProvider` and
//! can be refreshed on demand. Consumers (e.g. `MdeClient`) read the cached
//! token via `token()` and call `refresh_token()` when it is absent or stale.

use serde::{Serialize, Deserialize};
use serde_json::Value;
use std::error::Error;

/// Azure AD v2.0 token endpoint. `{tenant_id}` is replaced at runtime.
const TOKEN_URL: &str = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token";
const BASE_URL: &str = "https://api.security.microsoft.com/";

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

/// Manages OAuth2 token acquisition and caching.
///
/// Invariants:
/// - `response` is `None` until the first successful `refresh_token()` call.
/// - After a successful refresh, `token()` returns `Some` until the provider
///   is dropped or the token is replaced by a subsequent refresh.
pub struct TokenProvider {
    client: reqwest::Client,
    scope: String,
    tenant_id: String,
    client_id: String,
    client_secret: String,
    response: Option<TokenResponse>,
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
        }
    }

    /// Creates a `TokenProvider` with a pre-set token, bypassing Azure AD.
    /// Used by tests to avoid real HTTP calls during token acquisition.
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

        let response = self
            .client
            .post(&url)
            .form(&body)
            .send()
            .await?;

        // Read body before checking status so we can surface Microsoft's
        // detailed error (AADSTS codes) on failure.
        let status = response.status();
        let body = response.text().await?;

        if !status.is_success() {
            return Err(format!("Token request failed ({}): {}", status, body).into());
        }

        let resp: TokenResponse = serde_json::from_str(&body)?;
        self.response = Some(resp);

        Ok(())

    }

    pub async fn get(&mut self, path: &str) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let url = format!("{}{}", BASE_URL, path);
        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.response.as_mut().unwrap().access_token)
            .send()
            .await?
            .json()
            .await?;

        Ok(resp)
    }

    /// Returns the cached access token, or `None` if `refresh_token()` has
    /// not been called (or has not yet succeeded).
    pub fn token(&self) -> Option<&str> {
        self.response.as_ref().map(|ret| ret.access_token.as_str())
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_none_before_refresh() {
        let tp = TokenProvider::new("tenant", "client", "secret", "scope");
        assert!(tp.token().is_none(), "token must be None before any refresh");
    }

    #[test]
    fn token_url_interpolation() {
        let url = TOKEN_URL.replace("{tenant_id}", "abc-123");
        assert_eq!(url, "https://login.microsoftonline.com/abc-123/oauth2/v2.0/token");
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
}
