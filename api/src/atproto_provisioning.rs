use std::sync::OnceLock;
use std::time::Duration;

use reqwest::{Client, Url};
use serde::Serialize;

const DEFAULT_HANDLE_DOMAIN: &str = "divine.video";
const CONTROL_PLANE_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const CONTROL_PLANE_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const ATPROTO_UNAVAILABLE_MESSAGE: &str =
    "ATProto enablement is temporarily unavailable. Please try again later.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ControlPlaneUrlError {
    #[error("must be a valid http(s) URL")]
    InvalidUrl,
    #[error("must be a valid http(s) URL")]
    InvalidScheme,
    #[error("must not include query strings or fragments")]
    QueryOrFragment,
    #[error("must not include a path component")]
    PathComponent,
}

#[derive(Debug, thiserror::Error)]
pub enum AtprotoProvisioningError {
    #[error("ATProto control-plane dependency is not configured")]
    DependencyNotConfigured,
    #[error("remote dependency is at capacity")]
    AtCapacity(#[from] crate::api::http::expensive_work::RemoteFetchAtCapacity),
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
            | AtprotoProvisioningError::AtCapacity(_)
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

fn has_non_root_path(parsed: &Url) -> bool {
    !matches!(parsed.path(), "" | "/")
}

/// Validates the control-plane base URL before endpoint paths are appended.
pub fn validate_control_plane_base_url(base: &str) -> Result<(), ControlPlaneUrlError> {
    let parsed = Url::parse(base).map_err(|_| ControlPlaneUrlError::InvalidUrl)?;

    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(ControlPlaneUrlError::InvalidScheme);
    }

    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(ControlPlaneUrlError::QueryOrFragment);
    }

    if has_non_root_path(&parsed) {
        return Err(ControlPlaneUrlError::PathComponent);
    }

    Ok(())
}

fn control_plane_base_url() -> Result<String, AtprotoProvisioningError> {
    let base = std::env::var("DIVINE_SKY_ATPROTO_CONTROL_PLANE_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or(AtprotoProvisioningError::DependencyNotConfigured)?;

    validate_control_plane_base_url(&base)
        .map_err(|_| AtprotoProvisioningError::DependencyNotConfigured)?;

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
    let _remote_permit = crate::api::http::expensive_work::admit_remote_fetch()?;
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
    let _remote_permit = crate::api::http::expensive_work::admit_remote_fetch()?;
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
    let _remote_permit = crate::api::http::expensive_work::admit_remote_fetch()?;
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
    use super::{validate_control_plane_base_url, ControlPlaneUrlError};

    #[test]
    fn root_paths_are_accepted() {
        assert!(validate_control_plane_base_url("https://control.example.com").is_ok());
        assert!(validate_control_plane_base_url("https://control.example.com/").is_ok());
    }

    #[test]
    fn non_root_paths_are_rejected() {
        for url in [
            "https://control.example.com/api",
            "https://control.example.com/api/",
            "https://control.example.com/nested/path",
        ] {
            assert_eq!(
                validate_control_plane_base_url(url),
                Err(ControlPlaneUrlError::PathComponent)
            );
        }
    }

    #[test]
    fn query_strings_and_fragments_are_rejected() {
        for url in [
            "https://control.example.com?tenant=prod",
            "https://control.example.com#provisioning",
        ] {
            assert_eq!(
                validate_control_plane_base_url(url),
                Err(ControlPlaneUrlError::QueryOrFragment)
            );
        }
    }

    #[test]
    fn non_http_urls_are_rejected() {
        assert_eq!(
            validate_control_plane_base_url("ftp://control.example.com"),
            Err(ControlPlaneUrlError::InvalidScheme)
        );
        assert_eq!(
            validate_control_plane_base_url("not a url"),
            Err(ControlPlaneUrlError::InvalidUrl)
        );
    }
}
