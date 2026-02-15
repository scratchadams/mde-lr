//! Authenticated HTTP client for the Microsoft Defender for Endpoint API.
//!
//! `MdeClient` wraps a `reqwest::Client` and a `TokenProvider` behind a
//! `Mutex`, providing ergonomic JSON-based request helpers (`get`, `post`,
//! `put`) and a raw byte download method for Azure SAS URLs.
//!
//! Token lifecycle:
//! - Lazy acquisition: the first request that finds no cached token triggers
//!   `refresh_token()` automatically via `bearer_token()`.
//! - Expiry-aware: `TokenProvider::token()` returns `None` when the cached
//!   token has expired, which triggers a fresh refresh on the next request.
//! - One-shot 401 retry: if the MDE API returns `401 Unauthorized` (e.g.
//!   because the token was revoked server-side before our local expiry check
//!   caught it), the client invalidates the cached token, refreshes once,
//!   and retries the request exactly once. A second 401 is treated as a
//!   hard failure — no infinite retry loop.

use crate::auth::TokenProvider;
use crate::error::MdeError;
use reqwest::{Client, Method, StatusCode};
use serde::{Serialize, de::DeserializeOwned};
use std::time::Duration;
use tokio::sync::Mutex;

/// Default MDE API base URL for the commercial cloud.
///
/// For sovereign clouds, pass a custom base URL to `MdeClient::new()`:
/// - GCC High:   `https://api-gcc.security.microsoft.us/`
/// - DoD:        `https://api-gov.security.microsoft.us/`
/// - China:      `https://api.security.microsoft.cn/`
///
/// The URL must end with a trailing slash — API paths are appended directly.
const DEFAULT_BASE_URL: &str = "https://api.security.microsoft.com/";

/// Connect timeout for the MDE API HTTP client.
/// Covers TCP + TLS handshake only. 10 seconds is generous for Azure services.
const API_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Overall request timeout for MDE API calls.
/// Covers the full round-trip including response body download.
/// Set to 5 minutes to accommodate large file downloads via SAS URLs
/// (GetFile results can be multi-MB zip files). Regular API calls
/// (polling, download links) complete well within this limit.
const API_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

/// Builds a `reqwest::Client` with explicit timeouts for MDE API calls.
///
/// Separating this from the `TokenProvider`'s client allows different
/// timeout policies: token requests are small and fast (30s), while
/// API requests may involve large file downloads (5min).
fn build_api_client() -> Client {
    Client::builder()
        .connect_timeout(API_CONNECT_TIMEOUT)
        .timeout(API_REQUEST_TIMEOUT)
        .build()
        .expect("failed to build HTTP client for MDE API")
}

/// Authenticated HTTP client for the MDE REST API.
///
/// Design decisions:
/// - `auth` is behind a `Mutex` because `refresh_token()` requires `&mut self`
///   while API methods only need `&self`. The lock is held only for the brief
///   token check/refresh, never across an HTTP round-trip.
/// - `base_url` is stored as a `String` rather than a `&'static str` so it
///   can be overridden in tests (e.g. pointing at a wiremock server).
pub struct MdeClient {
    client: Client,
    base_url: String,
    auth: Mutex<TokenProvider>,
}

impl MdeClient {
    /// Creates a new `MdeClient` targeting the specified API base URL.
    ///
    /// For the commercial cloud, pass `None` to use the default
    /// (`https://api.security.microsoft.com/`). For sovereign clouds,
    /// pass the cloud-specific base URL (must end with a trailing slash):
    /// - GCC High: `Some("https://api-gcc.security.microsoft.us/")`
    /// - DoD:      `Some("https://api-gov.security.microsoft.us/")`
    ///
    /// See `TokenProvider::with_token_url()` for the corresponding token
    /// endpoint overrides — both must target the same cloud environment.
    pub async fn new(auth: TokenProvider, base_url: Option<&str>) -> Self {
        MdeClient {
            client: build_api_client(),
            base_url: base_url.unwrap_or(DEFAULT_BASE_URL).to_string(),
            auth: Mutex::new(auth),
        }
    }

    /// Constructor that accepts a custom base URL, used by tests to point
    /// at a local mock server instead of the real MDE API.
    ///
    /// This is separate from `new()` to keep test intent explicit — callers
    /// in production code should use `new()` with an optional base URL.
    pub async fn with_base_url(auth: TokenProvider, base_url: &str) -> Self {
        MdeClient {
            client: build_api_client(),
            base_url: base_url.to_string(),
            auth: Mutex::new(auth),
        }
    }

    /// Returns a valid bearer token, refreshing if none is cached or if the
    /// current token has expired.
    ///
    /// The mutex is held only for the token check and optional refresh.
    /// If refresh itself fails, the error propagates to the caller.
    async fn bearer_token(&self) -> crate::error::Result<String> {
        let mut auth = self.auth.lock().await;
        if auth.token().is_none() {
            auth.refresh_token().await?;
        }

        auth.token()
            .map(str::to_owned)
            .ok_or_else(|| MdeError::Auth {
                message: "token missing after refresh".to_string(),
                source: None,
            })
    }

    /// Invalidates the current token and acquires a fresh one from Azure AD.
    ///
    /// Called when the API returns 401, indicating the token was rejected
    /// server-side (revocation, clock skew, etc.) before our local expiry
    /// tracking detected it.
    async fn force_refresh(&self) -> crate::error::Result<String> {
        let mut auth = self.auth.lock().await;
        auth.invalidate();
        auth.refresh_token().await?;

        auth.token()
            .map(str::to_owned)
            .ok_or_else(|| MdeError::Auth {
                message: "token missing after forced refresh".to_string(),
                source: None,
            })
    }

    /// Core HTTP method: sends an authenticated JSON request and deserializes
    /// the response. All verb-specific methods (`get`, `post`, `put`) delegate
    /// here.
    ///
    /// `path` is relative to `base_url` (no leading slash needed).
    /// `body` is serialized as JSON when present; omitted for GET requests.
    ///
    /// 401 retry behavior:
    /// - If the response is `401 Unauthorized`, the client assumes the token
    ///   was rejected server-side. It invalidates the cached token, acquires
    ///   a fresh one, and retries the request exactly once.
    /// - If the retry also returns a non-success status, the error propagates
    ///   to the caller as `MdeError::Api` (preserving the response body).
    /// - Non-401 error status codes (403, 404, 500, etc.) are never retried
    ///   and propagate immediately as `MdeError::Api`.
    async fn send_json<T: DeserializeOwned, B: Serialize + ?Sized>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> crate::error::Result<T> {
        let url = format!("{}{}", self.base_url, path);

        // First attempt with current (possibly cached) token.
        let token = self.bearer_token().await?;
        let resp = self
            .build_request(method.clone(), &url, &token, body)
            .send()
            .await
            .map_err(MdeError::Network)?;

        // On 401, force a token refresh and retry exactly once.
        // Any other status (success or non-401 error) skips the retry path.
        if resp.status() == StatusCode::UNAUTHORIZED {
            let fresh_token = self.force_refresh().await?;
            let retry_resp = self
                .build_request(method, &url, &fresh_token, body)
                .send()
                .await
                .map_err(MdeError::Network)?;

            return self.parse_response(retry_resp).await;
        }

        self.parse_response(resp).await
    }

    /// Checks the HTTP status code and deserializes the JSON response body.
    ///
    /// On non-success status codes, reads the full response body text and
    /// returns `MdeError::Api` with both the status and body preserved.
    /// This fixes the previous limitation where `error_for_status()` discarded
    /// the response body — MDE error responses contain diagnostic codes and
    /// human-readable explanations that are essential for debugging.
    async fn parse_response<T: DeserializeOwned>(
        &self,
        resp: reqwest::Response,
    ) -> crate::error::Result<T> {
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(MdeError::Api { status, body });
        }
        resp.json::<T>().await.map_err(MdeError::Network)
    }

    /// Constructs an authenticated request builder with optional JSON body.
    ///
    /// Factored out of `send_json` so the first attempt and retry can both
    /// build requests without duplicating the header/body attachment logic.
    fn build_request<B: Serialize + ?Sized>(
        &self,
        method: Method,
        url: &str,
        token: &str,
        body: Option<&B>,
    ) -> reqwest::RequestBuilder {
        let mut req = self.client.request(method, url).bearer_auth(token);
        if let Some(payload) = body {
            req = req.json(payload);
        }
        req
    }

    /// Sends an authenticated GET request and deserializes the JSON response.
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> crate::error::Result<T> {
        self.send_json::<T, ()>(Method::GET, path, None).await
    }

    /// Sends an authenticated POST request with a JSON body and deserializes
    /// the response.
    pub async fn post<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> crate::error::Result<T> {
        self.send_json(Method::POST, path, Some(body)).await
    }

    /// Sends an authenticated PUT request with a JSON body and deserializes
    /// the response.
    pub async fn put<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> crate::error::Result<T> {
        self.send_json(Method::PUT, path, Some(body)).await
    }

    /// Downloads raw bytes from an arbitrary URL without bearer auth.
    ///
    /// This exists for Azure Blob Storage SAS URLs returned by the
    /// `GetLiveResponseResultDownloadLink` endpoint. Those URLs carry their
    /// own authorization via query-string SAS tokens, so no bearer header
    /// is attached.
    ///
    /// Note: SAS URLs are not subject to 401 retry logic because they don't
    /// use bearer tokens — authentication is embedded in the URL itself.
    ///
    /// Error mapping:
    /// - Network failures → `MdeError::Network`
    /// - Non-2xx status → `MdeError::Api` with the status and response body
    pub async fn download(&self, url: &str) -> crate::error::Result<bytes::Bytes> {
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(MdeError::Network)?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(MdeError::Api { status, body });
        }

        resp.bytes().await.map_err(MdeError::Network)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::TokenProvider;
    use serde::Deserialize;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Minimal deserializable struct for testing JSON round-trip through
    /// `send_json` and `parse_response`. Keeps tests decoupled from the
    /// real MDE API model types.
    #[derive(Debug, Deserialize, PartialEq)]
    struct TestPayload {
        value: String,
    }

    /// Helper: creates a wiremock MockServer and an MdeClient pointed at it.
    /// Uses `TokenProvider::with_token()` to bypass Azure AD entirely.
    /// Suitable for tests that don't trigger token refresh (no 401 retry).
    async fn test_client() -> (MockServer, MdeClient) {
        let server = MockServer::start().await;
        let tp = TokenProvider::with_token("test-bearer-token");
        let client = MdeClient::with_base_url(tp, &format!("{}/", server.uri())).await;
        (server, client)
    }

    /// Helper: creates a MockServer and MdeClient where the token endpoint
    /// also points at the mock server. Required for tests that trigger
    /// `force_refresh()` (401 retry), because invalidate() clears the cached
    /// token and `refresh_token()` must hit a reachable endpoint.
    async fn test_client_with_token_endpoint() -> (MockServer, MdeClient) {
        let server = MockServer::start().await;
        let token_url = format!("{}/{{tenant_id}}/oauth2/v2.0/token", server.uri());
        let tp = TokenProvider::with_token_url(
            "test-tenant",
            "test-client",
            "test-secret",
            "https://api.securitycenter.microsoft.com/.default",
            &token_url,
        );
        // Pre-populate the token so the first request doesn't need a refresh.
        // We do this by mounting a token endpoint mock that will be used by
        // force_refresh() when a 401 triggers re-authentication.
        let client = MdeClient::with_base_url(tp, &format!("{}/", server.uri())).await;
        (server, client)
    }

    /// Mounts a mock token endpoint that returns a valid access token.
    /// Used by tests that exercise the 401 retry path.
    async fn mount_token_endpoint(server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/test-tenant/oauth2/v2.0/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "refreshed-token",
                "token_type": "Bearer",
                "expires_in": 3600
            })))
            .named("token endpoint")
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn bearer_token_returns_preloaded_token() {
        // TokenProvider::with_token() pre-populates the cache, so
        // bearer_token() should return it without any network call.
        let (_server, client) = test_client().await;
        let token = client.bearer_token().await.unwrap();
        assert_eq!(
            token, "test-bearer-token",
            "bearer_token() should return the pre-loaded token from with_token()"
        );
    }

    #[tokio::test]
    async fn get_returns_deserialized_json_on_success() {
        // Validates the happy path: GET → 200 JSON → deserialized struct.
        let (server, client) = test_client().await;

        Mock::given(method("GET"))
            .and(path("/api/test"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"value": "hello"})),
            )
            .expect(1)
            .mount(&server)
            .await;

        let result: TestPayload = client.get("api/test").await.unwrap();
        assert_eq!(result.value, "hello");
    }

    #[tokio::test]
    async fn send_json_retries_once_on_401_then_succeeds() {
        // The first API request returns 401 (simulating a server-side token
        // revocation). The client should invalidate the cached token, call
        // refresh_token() against the token endpoint, and retry the API
        // request exactly once with the fresh token.
        let (server, client) = test_client_with_token_endpoint().await;

        // The initial bearer_token() call finds no cached token, so it
        // hits the token endpoint first. Mount it before anything else.
        mount_token_endpoint(&server).await;

        // First API request returns 401 (only matches once).
        Mock::given(method("GET"))
            .and(path("/api/protected"))
            .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
            .up_to_n_times(1)
            .expect(1)
            .named("401 first attempt")
            .mount(&server)
            .await;

        // Second API request (the retry) returns 200.
        Mock::given(method("GET"))
            .and(path("/api/protected"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"value": "retry-ok"})),
            )
            .expect(1)
            .named("200 retry attempt")
            .mount(&server)
            .await;

        let result: TestPayload = client.get("api/protected").await.unwrap();
        assert_eq!(
            result.value, "retry-ok",
            "should return the response from the retry attempt"
        );
    }

    #[tokio::test]
    async fn send_json_returns_api_error_after_double_401() {
        // Both API attempts return 401 — the client must not retry infinitely.
        // After the second 401, it should return MdeError::Api with the
        // response body preserved.
        let (server, client) = test_client_with_token_endpoint().await;

        // Token endpoint for both the initial acquisition and the
        // force_refresh() triggered by the first 401.
        mount_token_endpoint(&server).await;

        Mock::given(method("GET"))
            .and(path("/api/always-401"))
            .respond_with(ResponseTemplate::new(401).set_body_string("token permanently revoked"))
            .expect(2)
            .named("persistent 401")
            .mount(&server)
            .await;

        let result: crate::error::Result<TestPayload> = client.get("api/always-401").await;
        let err = result.unwrap_err();

        match &err {
            MdeError::Api { status, body } => {
                assert_eq!(*status, StatusCode::UNAUTHORIZED);
                assert!(
                    body.contains("permanently revoked"),
                    "error body should be preserved from the second 401 response"
                );
            }
            other => panic!("expected MdeError::Api, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn parse_response_preserves_error_body_on_403() {
        // Non-401 errors should propagate immediately (no retry) with the
        // response body preserved for diagnostic purposes.
        let (server, client) = test_client().await;

        let error_body = r#"{"error":{"code":"Forbidden","message":"Insufficient permissions"}}"#;
        Mock::given(method("GET"))
            .and(path("/api/forbidden"))
            .respond_with(ResponseTemplate::new(403).set_body_string(error_body))
            .expect(1)
            .named("403 forbidden")
            .mount(&server)
            .await;

        let result: crate::error::Result<TestPayload> = client.get("api/forbidden").await;
        let err = result.unwrap_err();

        match &err {
            MdeError::Api { status, body } => {
                assert_eq!(*status, StatusCode::FORBIDDEN);
                assert!(
                    body.contains("Insufficient permissions"),
                    "MDE error body must be preserved for debugging"
                );
            }
            other => panic!("expected MdeError::Api, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn download_returns_raw_bytes_without_bearer_auth() {
        // Validates that download() fetches raw bytes from a SAS URL.
        // SAS URLs carry auth in the query string — download() uses a plain
        // GET without the Bearer header that send_json() attaches. We verify
        // correctness (right bytes returned) and also inspect the recorded
        // request to confirm no Authorization header was sent.
        let (server, client) = test_client().await;
        let expected_bytes = b"raw-file-content";

        Mock::given(method("GET"))
            .and(path("/blob/file.zip"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(expected_bytes.as_slice()))
            .expect(1)
            .named("SAS download")
            .mount(&server)
            .await;

        let bytes = client
            .download(&format!("{}/blob/file.zip", server.uri()))
            .await
            .unwrap();
        assert_eq!(
            bytes.as_ref(),
            expected_bytes,
            "download() should return raw bytes from the SAS URL"
        );

        // Inspect the recorded request to verify no bearer token was sent.
        // This is the key behavioral contract: SAS URLs must not receive
        // our API bearer token (it would leak credentials to Azure Blob Storage).
        let requests = server.received_requests().await.unwrap();
        let download_req = requests
            .iter()
            .find(|r| r.url.path() == "/blob/file.zip")
            .expect("should have received the download request");
        assert!(
            !download_req.headers.contains_key("Authorization"),
            "download() must not send an Authorization header to SAS URLs"
        );
    }
}
