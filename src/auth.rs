use serde::{Serialize, Deserialize};
use serde_json::Value;
use std::error::Error;

const TOKEN_URL: &str = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token";
const BASE_URL: &str = "https://api.security.microsoft.com/";

#[derive(Serialize)]
pub struct TokenRequest<'a> {
    client_id: &'a str,
    scope: &'a str,
    client_secret: &'a str,
    grant_type: &'a str,
}

#[derive(Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

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

    pub fn token(&self) -> Option<&str> {
        //Some(&self.response.as_ref().unwrap().access_token)
        self.response.as_ref().map(|ret| ret.access_token.as_str())
    }

}
