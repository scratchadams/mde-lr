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
