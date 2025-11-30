use nostr::nips::nip46::NostrConnectURI;
use nostr::{Event, Keys};
use nostr_connect::prelude::NostrConnect;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRequest {
    pub method: String,
    #[serde(default)]
    pub params: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponse {
    #[serde(default)]
    pub result: Option<serde_json::Value>,
    #[serde(default)]
    pub error: Option<String>,
}

/// NIP-46 client for testing remote signing
pub struct Nip46Client {
    bunker_url: String,
    /// The bunker pubkey (from bunker URL). Note: This may differ from user_pubkey after HKDF derivation.
    bunker_pubkey: String,
    access_token: Option<String>,
    api_base_url: String,
}

impl Nip46Client {
    /// Create client from OAuth token response
    pub fn from_token_response(
        bunker_url: String,
        access_token: Option<String>,
        api_base_url: String,
    ) -> Result<Self, String> {
        // Parse bunker URL to extract bunker pubkey
        let uri = NostrConnectURI::parse(&bunker_url)
            .map_err(|e| format!("Failed to parse bunker URL: {}", e))?;

        let bunker_pubkey = uri
            .remote_signer_public_key()
            .ok_or("No remote signer public key in bunker URL")?
            .to_hex();

        Ok(Self {
            bunker_url,
            bunker_pubkey,
            access_token,
            api_base_url,
        })
    }

    pub fn bunker_url(&self) -> &str {
        &self.bunker_url
    }

    /// Returns the bunker pubkey (from the bunker URL).
    /// Note: This is different from the user's signing pubkey (use get_public_key() for that).
    pub fn bunker_pubkey(&self) -> &str {
        &self.bunker_pubkey
    }

    /// Make an RPC call to the REST API endpoint
    async fn rpc_call(&self, method: &str, params: Vec<serde_json::Value>) -> Result<RpcResponse, String> {
        let client = reqwest::Client::new();
        let url = format!("{}/api/nostr", self.api_base_url);

        let request = RpcRequest {
            method: method.to_string(),
            params,
        };

        let mut req_builder = client.post(&url).json(&request);

        if let Some(token) = &self.access_token {
            req_builder = req_builder.header("Authorization", format!("Bearer {}", token));
        }

        let resp = req_builder
            .send()
            .await
            .map_err(|e| format!("RPC request failed: {}", e))?;

        if resp.status().is_success() {
            resp.json::<RpcResponse>()
                .await
                .map_err(|e| format!("Failed to parse RPC response: {}", e))
        } else {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            Err(format!("RPC call failed with {}: {}", status, text))
        }
    }

    /// Get the user's public key
    pub async fn get_public_key(&self) -> Result<String, String> {
        let resp = self.rpc_call("get_public_key", vec![]).await?;

        if let Some(error) = resp.error {
            return Err(error);
        }

        resp.result
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .ok_or_else(|| "No result in response".to_string())
    }

    /// Sign an event
    pub async fn sign_event(&self, unsigned_event: serde_json::Value) -> Result<Event, String> {
        let resp = self
            .rpc_call("sign_event", vec![unsigned_event])
            .await?;

        if let Some(error) = resp.error {
            return Err(error);
        }

        let result = resp
            .result
            .ok_or_else(|| "No result in response".to_string())?;

        // Result could be a string (JSON) or an object
        let event_json = if let Some(s) = result.as_str() {
            serde_json::from_str(s).map_err(|e| format!("Failed to parse event JSON: {}", e))?
        } else {
            result
        };

        serde_json::from_value(event_json)
            .map_err(|e| format!("Failed to deserialize event: {}", e))
    }

    /// Sign a simple text note (kind 1)
    pub async fn sign_text_note(&self, content: &str) -> Result<Event, String> {
        // Fetch the actual user pubkey (different from bunker_pubkey after HKDF derivation)
        let user_pubkey = self.get_public_key().await?;

        let unsigned = serde_json::json!({
            "kind": 1,
            "content": content,
            "tags": [],
            "created_at": chrono::Utc::now().timestamp(),
            "pubkey": user_pubkey
        });

        self.sign_event(unsigned).await
    }

    /// Encrypt using NIP-44
    pub async fn nip44_encrypt(&self, pubkey: &str, plaintext: &str) -> Result<String, String> {
        let resp = self
            .rpc_call(
                "nip44_encrypt",
                vec![
                    serde_json::Value::String(pubkey.to_string()),
                    serde_json::Value::String(plaintext.to_string()),
                ],
            )
            .await?;

        if let Some(error) = resp.error {
            return Err(error);
        }

        resp.result
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .ok_or_else(|| "No result in response".to_string())
    }

    /// Decrypt using NIP-44
    pub async fn nip44_decrypt(&self, pubkey: &str, ciphertext: &str) -> Result<String, String> {
        let resp = self
            .rpc_call(
                "nip44_decrypt",
                vec![
                    serde_json::Value::String(pubkey.to_string()),
                    serde_json::Value::String(ciphertext.to_string()),
                ],
            )
            .await?;

        if let Some(error) = resp.error {
            return Err(error);
        }

        resp.result
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .ok_or_else(|| "No result in response".to_string())
    }

    /// Encrypt using NIP-04 (legacy)
    pub async fn nip04_encrypt(&self, pubkey: &str, plaintext: &str) -> Result<String, String> {
        let resp = self
            .rpc_call(
                "nip04_encrypt",
                vec![
                    serde_json::Value::String(pubkey.to_string()),
                    serde_json::Value::String(plaintext.to_string()),
                ],
            )
            .await?;

        if let Some(error) = resp.error {
            return Err(error);
        }

        resp.result
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .ok_or_else(|| "No result in response".to_string())
    }

    /// Decrypt using NIP-04 (legacy)
    pub async fn nip04_decrypt(&self, pubkey: &str, ciphertext: &str) -> Result<String, String> {
        let resp = self
            .rpc_call(
                "nip04_decrypt",
                vec![
                    serde_json::Value::String(pubkey.to_string()),
                    serde_json::Value::String(ciphertext.to_string()),
                ],
            )
            .await?;

        if let Some(error) = resp.error {
            return Err(error);
        }

        resp.result
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .ok_or_else(|| "No result in response".to_string())
    }
}

/// Connect to a NIP-46 signer via relay (not REST RPC)
pub async fn connect_via_relay(
    bunker_url: &str,
    timeout: Duration,
) -> Result<NostrConnect, String> {
    let uri = NostrConnectURI::parse(bunker_url)
        .map_err(|e| format!("Failed to parse bunker URL: {}", e))?;

    let app_keys = Keys::generate();

    NostrConnect::new(uri, app_keys, timeout, None)
        .map_err(|e| format!("Failed to connect to signer: {}", e))
}

/// Parse a bunker URL and extract components
pub fn parse_bunker_url(bunker_url: &str) -> Result<(String, Vec<String>, String), String> {
    let uri = NostrConnectURI::parse(bunker_url)
        .map_err(|e| format!("Failed to parse bunker URL: {}", e))?;

    let pubkey = uri
        .remote_signer_public_key()
        .ok_or("No remote signer public key in bunker URL")?
        .to_hex();
    let relays: Vec<String> = uri.relays().iter().map(|r| r.to_string()).collect();
    let secret = uri.secret().map(|s| s.to_string()).unwrap_or_default();

    Ok((pubkey, relays, secret))
}
