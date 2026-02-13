use reqwest::{Method, Client};
use serde::{Serialize, de::DeserializeOwned};
use tokio::sync::Mutex;
use crate::auth::TokenProvider;
use std::error::Error;

const BASE_URL: &str = "https://api.security.microsoft.com/";

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
            auth: Mutex::new(auth)
        }
    }

    async fn bearer_token(&self) -> Result<String, Box<dyn Error + Send + Sync>> {
        let mut auth = self.auth.lock().await;
        if auth.token().is_none() {
            auth.refresh_token().await?;
        }

        auth.token()
            .map(str::to_owned)
            .ok_or_else(|| "token missing after refresh".into())
    }

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

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, Box<dyn Error + Send + Sync>> {
        self.send_json::<T, ()>(Method::GET, path, None).await
    }

    pub async fn post<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self, 
        path: &str, 
        body: &B
    ) -> Result <T, Box<dyn Error + Send + Sync>> {
        self.send_json(Method::POST, path, Some(body)).await
    }

    pub async fn put<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, Box<dyn Error + Send + Sync>> {
        self.send_json(Method::PUT, path, Some(body)).await
    }

    pub async fn download(&self, url: &str) -> Result<bytes::Bytes, Box<dyn Error + Send + Sync>> {
        let resp = self.client.get(url).send().await?.error_for_status()?;
        Ok(resp.bytes().await?)
    }
}