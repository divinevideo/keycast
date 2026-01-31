// ABOUTME: Divine Name Server integration for username claiming
// ABOUTME: Calls divine-name-server API to sync usernames with NIP-98 auth

use nostr_sdk::prelude::*;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_NAME_SERVER_URL: &str = "https://names.divine.video";

#[derive(Debug, Serialize)]
struct ClaimRequest {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct ClaimResponse {
    pub ok: bool,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub pubkey: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub profile_url: Option<String>,
    #[serde(default)]
    pub nip05: Option<Nip05Info>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Nip05Info {
    pub main_domain: String,
    pub underscore_subdomain: String,
    pub host_style: String,
}

#[derive(Debug, thiserror::Error)]
pub enum DivineNameError {
    #[error("NIP-98 signing failed: {0}")]
    SigningError(String),
    #[error("HTTP request failed: {0}")]
    RequestError(#[from] reqwest::Error),
    #[error("Username claim failed: {0}")]
    ClaimError(String),
    #[error("Invalid response: {0}")]
    ResponseError(String),
}

/// Create a NIP-98 auth event for the claim endpoint
async fn create_nip98_event(
    keys: &Keys,
    url: &str,
    method: &str,
    body: &str,
) -> Result<Event, DivineNameError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Calculate payload hash
    let mut hasher = Sha256::new();
    hasher.update(body.as_bytes());
    let payload_hash = hex::encode(hasher.finalize());

    // Build NIP-98 event
    let event = EventBuilder::new(Kind::HttpAuth, "")
        .tags(vec![
            Tag::custom(TagKind::custom("u"), vec![url.to_string()]),
            Tag::custom(TagKind::custom("method"), vec![method.to_string()]),
            Tag::custom(TagKind::custom("payload"), vec![payload_hash]),
        ])
        .custom_created_at(Timestamp::from(now))
        .sign(keys)
        .await
        .map_err(|e| DivineNameError::SigningError(e.to_string()))?;

    Ok(event)
}

/// Claim a username on divine-name-server
pub async fn claim_username(
    keys: &Keys,
    username: &str,
    relays: Option<Vec<String>>,
) -> Result<ClaimResponse, DivineNameError> {
    let base_url = std::env::var("DIVINE_NAME_SERVER_URL")
        .unwrap_or_else(|_| DEFAULT_NAME_SERVER_URL.to_string());
    let url = format!("{}/api/username/claim", base_url.trim_end_matches('/'));

    // Prepare request body
    let body = ClaimRequest {
        name: username.to_string(),
        relays,
    };
    let body_json = serde_json::to_string(&body)
        .map_err(|e| DivineNameError::ResponseError(e.to_string()))?;

    // Create NIP-98 auth event
    let auth_event = create_nip98_event(keys, &url, "POST", &body_json).await?;
    let auth_json = serde_json::to_string(&auth_event)
        .map_err(|e| DivineNameError::SigningError(e.to_string()))?;
    let auth_header = format!("Nostr {}", base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        auth_json.as_bytes()
    ));

    // Make HTTP request
    let client = Client::new();
    let response = client
        .post(&url)
        .header("Authorization", auth_header)
        .header("Content-Type", "application/json")
        .body(body_json)
        .send()
        .await?;

    let status = response.status();
    let response_text = response.text().await?;

    // Parse response
    let claim_response: ClaimResponse = serde_json::from_str(&response_text)
        .map_err(|e| DivineNameError::ResponseError(format!(
            "Failed to parse response: {}. Status: {}, Body: {}",
            e, status, response_text
        )))?;

    if !claim_response.ok {
        return Err(DivineNameError::ClaimError(
            claim_response.error.unwrap_or_else(|| "Unknown error".to_string())
        ));
    }

    Ok(claim_response)
}

/// Check if divine name server integration is enabled
pub fn is_enabled() -> bool {
    std::env::var("DIVINE_NAME_SERVER_URL").is_ok() ||
    std::env::var("ENABLE_DIVINE_NAMES").map(|v| v == "true" || v == "1").unwrap_or(false)
}

/// Response from the availability check endpoint
#[derive(Debug, Deserialize)]
pub struct AvailabilityResponse {
    pub ok: bool,
    pub available: bool,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub canonical: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

/// Check if a username is available on divine-name-server (no auth required)
/// Returns (available, reason) - reason is set when not available
pub async fn check_availability(username: &str) -> Result<(bool, Option<String>), DivineNameError> {
    let base_url = std::env::var("DIVINE_NAME_SERVER_URL")
        .unwrap_or_else(|_| DEFAULT_NAME_SERVER_URL.to_string());
    let url = format!("{}/api/username/check/{}", base_url.trim_end_matches('/'), username);

    let client = Client::new();
    let response = client
        .get(&url)
        .send()
        .await?;

    let status = response.status();
    let response_text = response.text().await?;

    let check_response: AvailabilityResponse = serde_json::from_str(&response_text)
        .map_err(|e| DivineNameError::ResponseError(format!(
            "Failed to parse availability response: {}. Status: {}, Body: {}",
            e, status, response_text
        )))?;

    if !check_response.ok {
        return Err(DivineNameError::ResponseError(
            check_response.error.unwrap_or_else(|| "Unknown error".to_string())
        ));
    }

    Ok((check_response.available, check_response.reason))
}

/// Response from the by-pubkey lookup endpoint
#[derive(Debug, Deserialize)]
pub struct PubkeyLookupResponse {
    pub ok: bool,
    pub found: bool,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub canonical: Option<String>,
    #[serde(default)]
    pub pubkey: Option<String>,
    #[serde(default)]
    pub profile_url: Option<String>,
    #[serde(default)]
    pub nip05: Option<Nip05Info>,
    #[serde(default)]
    pub error: Option<String>,
}

/// Look up a username by pubkey on divine-name-server (no auth required)
pub async fn lookup_by_pubkey(pubkey: &str) -> Result<Option<PubkeyLookupResponse>, DivineNameError> {
    let base_url = std::env::var("DIVINE_NAME_SERVER_URL")
        .unwrap_or_else(|_| DEFAULT_NAME_SERVER_URL.to_string());
    let url = format!("{}/api/username/by-pubkey/{}", base_url.trim_end_matches('/'), pubkey);

    let client = Client::new();
    let response = client
        .get(&url)
        .send()
        .await?;

    let status = response.status();
    let response_text = response.text().await?;

    let lookup_response: PubkeyLookupResponse = serde_json::from_str(&response_text)
        .map_err(|e| DivineNameError::ResponseError(format!(
            "Failed to parse lookup response: {}. Status: {}, Body: {}",
            e, status, response_text
        )))?;

    if !lookup_response.ok {
        return Err(DivineNameError::ResponseError(
            lookup_response.error.unwrap_or_else(|| "Unknown error".to_string())
        ));
    }

    if lookup_response.found {
        Ok(Some(lookup_response))
    } else {
        Ok(None)
    }
}
