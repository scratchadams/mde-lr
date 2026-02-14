//! Authenticated HTTP client for the Microsoft Defender for Endpoint API.
//!
//! `MdeClient` wraps a `reqwest::Client` and a `TokenProvider` behind a
//! `Mutex`, providing ergonomic JSON-based request helpers (`get`, `post`,
//! `put`) and a raw byte download method for Azure SAS URLs.
//!
//! Token refresh is lazy: the first request that finds no cached token will
//! trigger `refresh_token()` automatically via `bearer_token()`.

use crate::auth::TokenProvider;
use reqwest::{Client, Method};
use serde::{Serialize, de::DeserializeOwned};
use std::error::Error;
use tokio::sync::Mutex;

const BASE_URL: &str = "https://api.security.microsoft.com/";

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
    pub async fn new(auth: TokenProvider) -> Self {
        MdeClient {
            client: Client::new(),
            base_url: BASE_URL.to_string(),
            auth: Mutex::new(auth),
        }
    }

    /// Constructor that accepts a custom base URL, used by tests to point
    /// at a local mock server instead of the real MDE API.
    pub async fn with_base_url(auth: TokenProvider, base_url: &str) -> Self {
        MdeClient {
            client: Client::new(),
            base_url: base_url.to_string(),
            auth: Mutex::new(auth),
        }
    }

    /// Returns a valid bearer token, refreshing if none is cached.
    ///
    /// The mutex is held only for the token check and optional refresh.
    /// If refresh itself fails, the error propagates to the caller.
    async fn bearer_token(&self) -> Result<String, Box<dyn Error + Send + Sync>> {
        let mut auth = self.auth.lock().await;
        if auth.token().is_none() {
            auth.refresh_token().await?;
        }

        auth.token()
            .map(str::to_owned)
            .ok_or_else(|| "token missing after refresh".into())
    }

    /// Core HTTP method: sends an authenticated JSON request and deserializes
    /// the response. All verb-specific methods (`get`, `post`, `put`) delegate here.
    ///
    /// `path` is relative to `base_url` (no leading slash needed).
    /// `body` is serialized as JSON when present; omitted for GET requests.
    async fn send_json<T: DeserializeOwned, B: Serialize + ?Sized>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<T, Box<dyn Error + Send + Sync>> {
        let token = self.bearer_token().await?;
        let url = format!("{}{}", self.base_url, path);

        let mut req = self.client.request(method, &url).bearer_auth(token);
        if let Some(payload) = body {
            req = req.json(payload);
        }

        let resp = req.send().await?.error_for_status()?;
        Ok(resp.json::<T>().await?)
    }

    pub async fn get<T: DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<T, Box<dyn Error + Send + Sync>> {
        self.send_json::<T, ()>(Method::GET, path, None).await
    }

    pub async fn post<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, Box<dyn Error + Send + Sync>> {
        self.send_json(Method::POST, path, Some(body)).await
    }

    pub async fn put<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, Box<dyn Error + Send + Sync>> {
        self.send_json(Method::PUT, path, Some(body)).await
    }

    /// Downloads raw bytes from an arbitrary URL without bearer auth.
    ///
    /// This exists for Azure Blob Storage SAS URLs returned by the
    /// `GetLiveResponseResultDownloadLink` endpoint. Those URLs carry their
    /// own authorization via query-string SAS tokens, so no bearer header
    /// is attached.
    pub async fn download(&self, url: &str) -> Result<bytes::Bytes, Box<dyn Error + Send + Sync>> {
        let resp = self.client.get(url).send().await?.error_for_status()?;
        Ok(resp.bytes().await?)
    }
}
