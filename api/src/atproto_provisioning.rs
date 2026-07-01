use std::sync::OnceLock;
use std::time::Duration;

use reqwest::{Client, Url};
use serde::Serialize;

const DEFAULT_HANDLE_DOMAIN: &str = "divine.video";
const CONTROL_PLANE_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const CONTROL_PLANE_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const ATPROTO_UNAVAILABLE_MESSAGE: &str =
    "ATProto enablement is temporarily unavailable. Please try again later.";

#[derive(Debug, thiserror::Error)]
pub enum AtprotoProvisioningError {
    #[error("ATProto control-plane dependency is not configured")]
    DependencyNotConfigured,
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("provisioning service returned {status}: {body}")]
    UnexpectedStatus {
        status: reqwest::StatusCode,
        body: String,
    },
}

impl AtprotoProvisioningError {
    pub fn is_dependency_unavailable(&self) -> bool {
        match self {
            AtprotoProvisioningError::DependencyNotConfigured
            | AtprotoProvisioningError::Request(_) => true,
            AtprotoProvisioningError::UnexpectedStatus { status, .. } => status.is_server_error(),
        }
    }

    pub fn public_message(&self) -> &'static str {
        if self.is_dependency_unavailable() {
            ATPROTO_UNAVAILABLE_MESSAGE
        } else {
            "ATProto provisioning failed. Please try again later."
        }
    }
}

#[derive(Debug, Serialize)]
struct EnableProvisioningRequest {
    nostr_pubkey: String,
    handle: String,
    crosspost_enabled: bool,
}

/// Shared HTTP client for control-plane calls, built once with explicit
/// connect/request timeouts so an unresponsive control plane fails fast into a
/// scoped ATProto 503 instead of hanging the request.
fn control_plane_client() -> &'static Client {
    static CLIENT: OnceLock<Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        Client::builder()
            .connect_timeout(CONTROL_PLANE_CONNECT_TIMEOUT)
            .timeout(CONTROL_PLANE_REQUEST_TIMEOUT)
            .build()
            .unwrap_or_else(|_| Client::new())
    })
}

/// Returns true when the parsed URL carries a path component beyond the root.
/// Endpoint URLs are built by string concatenation onto the base, so a non-root
/// path would mangle the resulting endpoint and must be rejected here (kept
/// consistent with the startup validation in keycast/src/main.rs).
fn has_non_root_path(parsed: &Url) -> bool {
    !matches!(parsed.path(), "" | "/")
}

fn control_plane_base_url() -> Result<String, AtprotoProvisioningError> {
    let base = std::env::var("DIVINE_SKY_ATPROTO_CONTROL_PLANE_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or(AtprotoProvisioningError::DependencyNotConfigured)?;

    let parsed =
        Url::parse(&base).map_err(|_| AtprotoProvisioningError::DependencyNotConfigured)?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || has_non_root_path(&parsed)
    {
        return Err(AtprotoProvisioningError::DependencyNotConfigured);
    }

    Ok(base)
}

fn handle_domain() -> String {
    std::env::var("DIVINE_HANDLE_DOMAIN").unwrap_or_else(|_| DEFAULT_HANDLE_DOMAIN.to_string())
}

fn maybe_apply_service_auth(request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    if let Ok(token) = std::env::var("KEYCAST_ATPROTO_TOKEN") {
        let trimmed = token.trim();
        if !trimmed.is_empty() {
            return request.bearer_auth(trimmed.to_string());
        }
    }
    request
}

pub async fn request_enable(
    nostr_pubkey: &str,
    username: &str,
    crosspost_enabled: bool,
) -> Result<(), AtprotoProvisioningError> {
    let base = control_plane_base_url()?;
    let domain = handle_domain();
    let url = format!("{}/api/account-links/opt-in", base.trim_end_matches('/'));
    let handle = format!("{}.{}", username.trim().to_ascii_lowercase(), domain);

    let body = EnableProvisioningRequest {
        nostr_pubkey: nostr_pubkey.to_string(),
        handle,
        crosspost_enabled,
    };

    let client = control_plane_client();
    let response = maybe_apply_service_auth(client.post(url).json(&body))
        .send()
        .await?;

    if response.status().is_success() {
        return Ok(());
    }

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    Err(AtprotoProvisioningError::UnexpectedStatus { status, body })
}

pub async fn request_reenable(nostr_pubkey: &str) -> Result<(), AtprotoProvisioningError> {
    let base = control_plane_base_url()?;
    let encoded_pubkey = urlencoding::encode(nostr_pubkey);
    let url = format!(
        "{}/api/account-links/{}/enable",
        base.trim_end_matches('/'),
        encoded_pubkey
    );

    let client = control_plane_client();
    let response = maybe_apply_service_auth(client.post(url)).send().await?;

    if response.status().is_success() {
        return Ok(());
    }

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    Err(AtprotoProvisioningError::UnexpectedStatus { status, body })
}

pub async fn request_disable(nostr_pubkey: &str) -> Result<(), AtprotoProvisioningError> {
    let base = control_plane_base_url()?;
    let encoded_pubkey = urlencoding::encode(nostr_pubkey);
    let url = format!(
        "{}/api/account-links/{}/disable",
        base.trim_end_matches('/'),
        encoded_pubkey
    );

    let client = control_plane_client();
    let response = maybe_apply_service_auth(client.post(url)).send().await?;

    if response.status().is_success() {
        return Ok(());
    }

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    Err(AtprotoProvisioningError::UnexpectedStatus { status, body })
}

#[cfg(test)]
mod tests {
    use super::has_non_root_path;
    use reqwest::Url;

    fn parse(url: &str) -> Url {
        Url::parse(url).expect("test URL should parse")
    }

    #[test]
    fn root_paths_are_accepted() {
        assert!(!has_non_root_path(&parse("https://control.example.com")));
        assert!(!has_non_root_path(&parse("https://control.example.com/")));
    }

    #[test]
    fn non_root_paths_are_rejected() {
        assert!(has_non_root_path(&parse("https://control.example.com/api")));
        assert!(has_non_root_path(&parse(
            "https://control.example.com/api/"
        )));
        assert!(has_non_root_path(&parse(
            "https://control.example.com/nested/path"
        )));
    }
}
