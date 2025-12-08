use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// HTTP RPC client for Keycast API
#[derive(Clone)]
pub struct RpcClient {
    client: Client,
    base_url: String,
}

#[derive(Debug, Serialize)]
struct RpcRequest {
    method: String,
    params: Vec<Value>,
}

#[derive(Debug, Deserialize)]
struct RpcResponse {
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug)]
pub struct RequestResult {
    pub duration: Duration,
    pub success: bool,
    pub status: Option<u16>,
    pub error: Option<String>,
}

/// Server-side metrics from /metrics endpoint
#[derive(Debug, Default, Clone)]
pub struct ServerMetrics {
    pub http_rpc_requests_total: u64,
    pub http_rpc_cache_hits: u64,
    pub http_rpc_cache_misses: u64,
    pub http_rpc_cache_size: u64,
    pub http_rpc_success: u64,
    pub http_rpc_auth_errors: u64,
}

impl ServerMetrics {
    /// Parse Prometheus-format metrics
    fn parse(text: &str) -> Self {
        let mut metrics = ServerMetrics::default();
        let parsed = parse_prometheus_metrics(text);

        metrics.http_rpc_requests_total = parsed
            .get("keycast_http_rpc_requests_total")
            .copied()
            .unwrap_or(0);
        metrics.http_rpc_cache_hits = parsed
            .get("keycast_http_rpc_cache_hits_total")
            .copied()
            .unwrap_or(0);
        metrics.http_rpc_cache_misses = parsed
            .get("keycast_http_rpc_cache_misses_total")
            .copied()
            .unwrap_or(0);
        metrics.http_rpc_cache_size = parsed
            .get("keycast_http_rpc_cache_size")
            .copied()
            .unwrap_or(0);
        metrics.http_rpc_success = parsed
            .get("keycast_http_rpc_success_total")
            .copied()
            .unwrap_or(0);
        metrics.http_rpc_auth_errors = parsed
            .get("keycast_http_rpc_auth_errors_total")
            .copied()
            .unwrap_or(0);

        metrics
    }
}

/// Parse simple Prometheus-format metrics
fn parse_prometheus_metrics(text: &str) -> HashMap<String, u64> {
    let mut metrics = HashMap::new();
    for line in text.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            if let Ok(value) = parts[1].parse::<u64>() {
                metrics.insert(parts[0].to_string(), value);
            }
        }
    }
    metrics
}

impl RpcClient {
    pub fn new(base_url: &str, pool_size: usize) -> Result<Self> {
        let client = Client::builder()
            .pool_max_idle_per_host(pool_size)
            .timeout(Duration::from_secs(30))
            .cookie_store(true) // Store GCLB cookie for session affinity
            .build()?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
        })
    }

    /// Fetch server-side metrics from /api/metrics endpoint
    pub async fn fetch_metrics(&self) -> Result<ServerMetrics> {
        let url = format!("{}/api/metrics", self.base_url);
        let response = self.client.get(&url).send().await?;
        let text = response.text().await?;
        Ok(ServerMetrics::parse(&text))
    }

    pub async fn call(&self, token: &str, method: &str, params: Vec<Value>) -> RequestResult {
        let start = Instant::now();
        let url = format!("{}/api/nostr", self.base_url);

        let result = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .json(&RpcRequest {
                method: method.to_string(),
                params,
            })
            .send()
            .await;

        let duration = start.elapsed();

        match result {
            Ok(response) => {
                let status = response.status().as_u16();
                if response.status().is_success() {
                    match response.json::<RpcResponse>().await {
                        Ok(body) => RequestResult {
                            duration,
                            success: body.error.is_none(),
                            status: Some(status),
                            error: body.error,
                        },
                        Err(e) => RequestResult {
                            duration,
                            success: false,
                            status: Some(status),
                            error: Some(format!("Failed to parse response: {}", e)),
                        },
                    }
                } else {
                    let error_text = response
                        .text()
                        .await
                        .unwrap_or_else(|_| "Unknown error".to_string());
                    RequestResult {
                        duration,
                        success: false,
                        status: Some(status),
                        error: Some(error_text),
                    }
                }
            }
            Err(e) => RequestResult {
                duration,
                success: false,
                status: None,
                error: Some(e.to_string()),
            },
        }
    }
}

/// HTTP client for registration API
#[derive(Clone)]
pub struct RegistrationClient {
    client: Client,
    base_url: String,
}

#[derive(Debug, Serialize)]
struct RegisterRequest {
    email: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct RegisterResponse {
    pubkey: String,
}

#[derive(Debug, Serialize)]
struct ApproveRequest {
    approved: bool,
    client_id: String,
    redirect_uri: String,
    scope: String,
    code_challenge: String,
    code_challenge_method: String,
}

#[derive(Debug, Deserialize)]
struct ApproveResponse {
    code: String,
}

#[derive(Debug, Serialize)]
struct TokenRequest {
    grant_type: String,
    code: String,
    client_id: String,
    redirect_uri: String,
    code_verifier: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
}

pub struct RegistrationResult {
    pub success: bool,
    pub pubkey: Option<String>,
    pub ucan_token: Option<String>,
    pub error: Option<String>,
}

impl RegistrationClient {
    pub fn new(base_url: &str, pool_size: usize) -> Result<Self> {
        let client = Client::builder()
            .pool_max_idle_per_host(pool_size)
            .timeout(Duration::from_secs(60))
            .build()?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
        })
    }

    pub async fn register(&self, email: &str, password: &str) -> RegistrationResult {
        let url = format!("{}/api/auth/register", self.base_url);

        let result = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Origin", &self.base_url)
            .json(&RegisterRequest {
                email: email.to_string(),
                password: password.to_string(),
            })
            .send()
            .await;

        match result {
            Ok(response) => {
                // Extract session UCAN from Set-Cookie header
                let session_token = Self::extract_session_cookie(response.headers());

                if response.status().is_success() {
                    match response.json::<RegisterResponse>().await {
                        Ok(body) => {
                            // Complete OAuth flow to get access_token for RPC
                            if let Some(ref token) = session_token {
                                match self.complete_oauth_flow(token).await {
                                    Ok(access_token) => RegistrationResult {
                                        success: true,
                                        pubkey: Some(body.pubkey),
                                        ucan_token: Some(access_token),
                                        error: None,
                                    },
                                    Err(e) => RegistrationResult {
                                        success: false,
                                        pubkey: Some(body.pubkey),
                                        ucan_token: None,
                                        error: Some(format!("OAuth flow failed: {}", e)),
                                    },
                                }
                            } else {
                                RegistrationResult {
                                    success: false,
                                    pubkey: Some(body.pubkey),
                                    ucan_token: None,
                                    error: Some("No session token in response".to_string()),
                                }
                            }
                        }
                        Err(e) => RegistrationResult {
                            success: false,
                            pubkey: None,
                            ucan_token: None,
                            error: Some(format!("Failed to parse response: {}", e)),
                        },
                    }
                } else {
                    let error_text = response
                        .text()
                        .await
                        .unwrap_or_else(|_| "Unknown error".to_string());
                    RegistrationResult {
                        success: false,
                        pubkey: None,
                        ucan_token: None,
                        error: Some(error_text),
                    }
                }
            }
            Err(e) => RegistrationResult {
                success: false,
                pubkey: None,
                ucan_token: None,
                error: Some(e.to_string()),
            },
        }
    }

    /// Complete OAuth flow with PKCE to get access_token for RPC
    /// 1. Generate PKCE verifier/challenge
    /// 2. POST /oauth/authorize with session cookie + code_challenge → get code
    /// 3. POST /oauth/token with code + code_verifier → get access_token (contains bunker_pubkey)
    async fn complete_oauth_flow(&self, session_token: &str) -> Result<String> {
        let client_id = "loadtest";
        let redirect_uri = format!("{}/callback", self.base_url);

        // Generate PKCE verifier and challenge
        let (code_verifier, code_challenge) = generate_pkce();

        // Step 1: Approve authorization with PKCE challenge
        let approve_url = format!("{}/api/oauth/authorize", self.base_url);
        let approve_response = self
            .client
            .post(&approve_url)
            .header("Content-Type", "application/json")
            .header("Origin", &self.base_url)
            .header("Cookie", format!("keycast_session={}", session_token))
            .json(&ApproveRequest {
                approved: true,
                client_id: client_id.to_string(),
                redirect_uri: redirect_uri.clone(),
                scope: "policy:social".to_string(),
                code_challenge,
                code_challenge_method: "S256".to_string(),
            })
            .send()
            .await?;

        if !approve_response.status().is_success() {
            let error = approve_response.text().await.unwrap_or_default();
            anyhow::bail!("OAuth authorize failed: {}", error);
        }

        let approve_body: ApproveResponse = approve_response.json().await?;
        let code = approve_body.code;

        // Step 2: Exchange code for access_token with PKCE verifier
        let token_url = format!("{}/api/oauth/token", self.base_url);
        let token_response = self
            .client
            .post(&token_url)
            .header("Content-Type", "application/json")
            .header("Origin", &self.base_url)
            .json(&TokenRequest {
                grant_type: "authorization_code".to_string(),
                code,
                client_id: client_id.to_string(),
                redirect_uri,
                code_verifier,
            })
            .send()
            .await?;

        if !token_response.status().is_success() {
            let error = token_response.text().await.unwrap_or_default();
            anyhow::bail!("OAuth token exchange failed: {}", error);
        }

        let token_body: TokenResponse = token_response.json().await?;
        token_body
            .access_token
            .ok_or_else(|| anyhow::anyhow!("No access_token in response"))
    }

    fn extract_session_cookie(headers: &reqwest::header::HeaderMap) -> Option<String> {
        headers.get_all("set-cookie").iter().find_map(|cookie| {
            let cookie_str = cookie.to_str().ok()?;
            if cookie_str.starts_with("keycast_session=") {
                let token = cookie_str
                    .strip_prefix("keycast_session=")?
                    .split(';')
                    .next()?;
                Some(token.to_string())
            } else {
                None
            }
        })
    }

    /// Register with timing information for load test metrics
    pub async fn register_timed(&self, email: &str, password: &str) -> RequestResult {
        let start = Instant::now();
        let result = self.register(email, password).await;
        let duration = start.elapsed();

        RequestResult {
            duration,
            success: result.success,
            status: if result.success { Some(201) } else { Some(500) },
            error: result.error,
        }
    }
}

/// Generate PKCE code_verifier and code_challenge (S256 method)
/// Returns (verifier, challenge)
fn generate_pkce() -> (String, String) {
    // Generate 32 random bytes
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);

    // Base64 URL-safe encode as verifier
    let verifier = URL_SAFE_NO_PAD.encode(bytes);

    // SHA256 hash the verifier
    let hash = Sha256::digest(verifier.as_bytes());

    // Base64 URL-safe encode the hash as challenge
    let challenge = URL_SAFE_NO_PAD.encode(hash);

    (verifier, challenge)
}
