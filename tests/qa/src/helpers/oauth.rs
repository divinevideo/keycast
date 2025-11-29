use crate::fixtures::{PkceChallenge, TestApp, TestUser};
use crate::helpers::server::TestServer;
use reqwest::header::{CONTENT_TYPE, ORIGIN};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub bunker_url: String,
    #[serde(default)]
    pub access_token: Option<String>,
    pub token_type: String,
    pub expires_in: i64,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(default)]
    pub error_description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizeResponse {
    pub code: String,
    pub redirect_uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollResponse {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
}

/// OAuth client for testing OAuth flows
pub struct OAuthClient {
    client: reqwest::Client,
    server: TestServer,
}

impl OAuthClient {
    pub fn new(server: TestServer) -> Self {
        Self {
            client: reqwest::Client::builder()
                .cookie_store(true)
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("Failed to create HTTP client"),
            server,
        }
    }

    /// Register a new user and return session cookies
    pub async fn register_user(&self, user: &TestUser) -> Result<(), String> {
        let url = self.server.api_url("/auth/register");

        let body = serde_json::json!({
            "email": user.email,
            "password": user.password
        });

        let resp = self
            .client
            .post(&url)
            .header(CONTENT_TYPE, "application/json")
            .header(ORIGIN, "http://localhost:5173")
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("Register request failed: {}", e))?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            Err(format!("Register failed with {}: {}", status, text))
        }
    }

    /// Login a user and return session (cookies stored in client)
    pub async fn login_user(&self, user: &TestUser) -> Result<String, String> {
        let url = self.server.api_url("/auth/login");

        let body = serde_json::json!({
            "email": user.email,
            "password": user.password
        });

        let resp = self
            .client
            .post(&url)
            .header(CONTENT_TYPE, "application/json")
            .header(ORIGIN, "http://localhost:5173")
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("Login request failed: {}", e))?;

        if resp.status().is_success() {
            // Parse the {success, pubkey} response
            let json: serde_json::Value = resp.json().await
                .map_err(|e| format!("Failed to parse login response: {}", e))?;

            json.get("pubkey")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| "No pubkey in login response".to_string())
        } else {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            Err(format!("Login failed with {}: {}", status, text))
        }
    }

    /// Initiate OAuth authorization flow (GET /oauth/authorize)
    /// Returns the redirect location or the authorization page HTML
    pub async fn initiate_authorize(
        &self,
        app: &TestApp,
        pkce: &PkceChallenge,
        state: Option<&str>,
    ) -> Result<String, String> {
        let mut url = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&code_challenge={}&code_challenge_method={}",
            self.server.oauth_url("/authorize"),
            urlencoding::encode(&app.client_id),
            urlencoding::encode(&app.redirect_uri),
            urlencoding::encode(&app.scope),
            urlencoding::encode(&pkce.challenge),
            urlencoding::encode(&pkce.method),
        );

        if let Some(s) = state {
            url.push_str(&format!("&state={}", urlencoding::encode(s)));
        }

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("Authorize request failed: {}", e))?;

        // Check for redirect (auto-approval)
        if resp.status().is_redirection() {
            if let Some(location) = resp.headers().get("location") {
                return Ok(location.to_str().unwrap_or("").to_string());
            }
        }

        // Otherwise return the HTML body
        resp.text()
            .await
            .map_err(|e| format!("Failed to read authorize response: {}", e))
    }

    /// Submit authorization approval (POST /oauth/authorize)
    pub async fn submit_authorize(
        &self,
        app: &TestApp,
        pkce: &PkceChallenge,
        approved: bool,
        state: Option<&str>,
    ) -> Result<AuthorizeResponse, String> {
        let url = self.server.oauth_url("/authorize");

        let mut body = serde_json::json!({
            "client_id": app.client_id,
            "redirect_uri": app.redirect_uri,
            "scope": app.scope,
            "approved": approved,
        });

        if !pkce.challenge.is_empty() {
            body["code_challenge"] = serde_json::Value::String(pkce.challenge.clone());
            body["code_challenge_method"] = serde_json::Value::String(pkce.method.clone());
        }

        if let Some(s) = state {
            body["state"] = serde_json::Value::String(s.to_string());
        }

        let resp = self
            .client
            .post(&url)
            .header(CONTENT_TYPE, "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("Authorize POST failed: {}", e))?;

        if resp.status().is_success() {
            resp.json::<AuthorizeResponse>()
                .await
                .map_err(|e| format!("Failed to parse authorize response: {}", e))
        } else if resp.status().is_redirection() {
            // Denial redirect
            if let Some(location) = resp.headers().get("location") {
                let loc = location.to_str().unwrap_or("");
                if loc.contains("error=access_denied") {
                    return Err("access_denied".to_string());
                }
                // Extract code from redirect URL if present
                if let Some(code_start) = loc.find("code=") {
                    let code_part = &loc[code_start + 5..];
                    let code = code_part
                        .split('&')
                        .next()
                        .unwrap_or("")
                        .to_string();
                    return Ok(AuthorizeResponse {
                        code,
                        redirect_uri: loc.to_string(),
                    });
                }
            }
            Err("Unexpected redirect".to_string())
        } else {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            Err(format!("Authorize POST failed with {}: {}", status, text))
        }
    }

    /// Exchange authorization code for tokens (POST /oauth/token)
    pub async fn exchange_code(
        &self,
        code: &str,
        app: &TestApp,
        pkce: &PkceChallenge,
    ) -> Result<TokenResponse, String> {
        let url = self.server.oauth_url("/token");

        let body = serde_json::json!({
            "grant_type": "authorization_code",
            "code": code,
            "client_id": app.client_id,
            "redirect_uri": app.redirect_uri,
            "code_verifier": pkce.verifier,
        });

        let resp = self
            .client
            .post(&url)
            .header(CONTENT_TYPE, "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("Token exchange failed: {}", e))?;

        if resp.status().is_success() {
            resp.json::<TokenResponse>()
                .await
                .map_err(|e| format!("Failed to parse token response: {}", e))
        } else {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            Err(format!("Token exchange failed with {}: {}", status, text))
        }
    }

    /// Poll for authorization code (GET /oauth/poll)
    pub async fn poll_authorization(&self, state: &str) -> Result<PollResponse, (u16, String)> {
        let url = format!("{}?state={}", self.server.oauth_url("/poll"), state);

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| (500, format!("Poll request failed: {}", e)))?;

        let status = resp.status().as_u16();

        if status == 200 || status == 202 {
            let poll_resp = resp
                .json::<PollResponse>()
                .await
                .map_err(|e| (status, format!("Failed to parse poll response: {}", e)))?;
            Ok(poll_resp)
        } else {
            let text = resp.text().await.unwrap_or_default();
            Err((status, text))
        }
    }

    /// Complete OAuth flow: register, login, authorize, exchange
    pub async fn complete_oauth_flow(
        &self,
        user: &TestUser,
        app: &TestApp,
    ) -> Result<TokenResponse, String> {
        // Register and login
        self.register_user(user).await.ok(); // Ignore if already registered
        let _login = self.login_user(user).await?;

        // Generate PKCE
        let pkce = PkceChallenge::generate_s256();

        // Submit authorization
        let auth_resp = self.submit_authorize(app, &pkce, true, None).await?;

        // Exchange code for tokens
        self.exchange_code(&auth_resp.code, app, &pkce).await
    }
}
