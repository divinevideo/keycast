// ABOUTME: ActivityPub RSA key custody + HTTP-Signature signing oracle
// ABOUTME: Authenticated by KEYCAST_SERVICE_TOKEN (gateway) OR UCAN (user); tenant from Host
// ABOUTME: Pure oracle — signs caller-supplied bytes; never returns the private key

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use keycast_core::ap_signing::{self, AP_KEY_TYPE};
use keycast_core::repositories::{ApActorKeysRepository, RepositoryError, UserRepository};
use nostr_sdk::PublicKey;
use serde::{Deserialize, Serialize};

use crate::api::http::auth::extract_user_from_token;
use crate::api::http::routes::AuthState;
use crate::api::tenant::TenantExtractor;

// ---- error type (isolated from AuthError; same {"error": msg} JSON shape) ----

#[derive(Debug)]
pub enum ApError {
    Unauthorized(String),
    Forbidden(String),
    BadRequest(String),
    NotFound(String),
    Internal(String),
}

impl IntoResponse for ApError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m),
            ApError::Forbidden(m) => (StatusCode::FORBIDDEN, m),
            ApError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApError::NotFound(m) => (StatusCode::NOT_FOUND, m),
            ApError::Internal(m) => {
                tracing::error!("AP signing internal error: {}", m);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
        };
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

// ---- auth: resolve the acting user_pubkey from service token OR UCAN ----

/// Constant-time check of the bearer against KEYCAST_SERVICE_TOKEN.
/// Mirrors `admin::authorize_service_token` (duplicated to keep that path untouched).
fn is_service_token(headers: &HeaderMap) -> bool {
    use subtle::ConstantTimeEq;

    let expected = match std::env::var("KEYCAST_SERVICE_TOKEN") {
        Ok(t) if !t.trim().is_empty() => t.trim().to_string(),
        _ => return false,
    };
    let actual = match headers.get("authorization").and_then(|v| v.to_str().ok()) {
        Some(a) => a,
        None => return false,
    };
    let expected_hash = blake3::hash(format!("Bearer {expected}").as_bytes());
    let actual_hash = blake3::hash(actual.as_bytes());
    expected_hash
        .as_bytes()
        .ct_eq(actual_hash.as_bytes())
        .into()
}

fn validate_hex_pubkey(pubkey: &str) -> Result<String, ApError> {
    PublicKey::from_hex(pubkey)
        .map(|pk| pk.to_hex())
        .map_err(|_| ApError::BadRequest("Invalid hex pubkey".to_string()))
}

/// Resolve the acting user_pubkey for a request.
/// - Service token: `body_pubkey` is REQUIRED (gateway acts for any actor in the tenant).
/// - UCAN: pubkey comes from the token; if `body_pubkey` is present it must match.
async fn resolve_principal(
    headers: &HeaderMap,
    tenant_id: i64,
    body_pubkey: Option<&str>,
) -> Result<String, ApError> {
    if is_service_token(headers) {
        let pk = body_pubkey.ok_or_else(|| {
            ApError::BadRequest("pubkey is required for service-token calls".into())
        })?;
        return validate_hex_pubkey(pk);
    }

    // UCAN path
    let token_pubkey = extract_user_from_token(headers, tenant_id)
        .await
        .map_err(|_| ApError::Unauthorized("Authentication required".to_string()))?;

    if let Some(pk) = body_pubkey {
        let pk = validate_hex_pubkey(pk)?;
        if pk != token_pubkey {
            return Err(ApError::Forbidden(
                "Cannot act on behalf of another user".to_string(),
            ));
        }
    }
    Ok(token_pubkey)
}

/// Reject signing for suspended/banned accounts (mirrors auth::sign_event).
async fn ensure_active(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    user_pubkey: &str,
) -> Result<(), ApError> {
    let user_repo = UserRepository::new(pool.clone());
    if let Some((status, _, _)) = user_repo
        .get_user_status(user_pubkey, tenant_id)
        .await
        .map_err(|e| ApError::Internal(e.to_string()))?
    {
        if !status.is_active() {
            return Err(ApError::Forbidden("Account restricted".to_string()));
        }
    }
    Ok(())
}

// ---- request/response types ----

#[derive(Debug, Deserialize)]
pub struct CreateKeyRequest {
    /// Hex Nostr pubkey of the actor. Required for service-token callers.
    pub pubkey: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct KeyResponse {
    pub pubkey: String,
    pub public_key_pem: String,
    pub key_type: String,
    pub created: bool,
}

#[derive(Debug, Serialize)]
pub struct PublicKeyResponse {
    pub pubkey: String,
    pub public_key_pem: String,
    pub key_type: String,
}

#[derive(Debug, Deserialize)]
pub struct SignRequest {
    /// Hex Nostr pubkey of the actor. Required for service-token callers.
    pub pubkey: Option<String>,
    /// Exact draft-cavage signing string. Signed as its UTF-8 bytes.
    pub signing_string: String,
}

#[derive(Debug, Serialize)]
pub struct SignResponse {
    pub pubkey: String,
    pub signature: String,
    pub algorithm: &'static str,
}

// ---- handlers ----

/// POST /api/ap/keys — create-or-return the actor's RSA key. Idempotent: never regenerates.
pub async fn create_key(
    tenant: TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Json(req): Json<CreateKeyRequest>,
) -> Result<Json<KeyResponse>, ApError> {
    let tenant_id = tenant.0.id;
    let user_pubkey = resolve_principal(&headers, tenant_id, req.pubkey.as_deref()).await?;
    let pool = &auth_state.state.db;
    let repo = ApActorKeysRepository::new(pool.clone());

    // Idempotent: if a key exists, return it unchanged.
    if let Some((pem, key_type)) = repo
        .find_public_pem(tenant_id, &user_pubkey)
        .await
        .map_err(|e| ApError::Internal(e.to_string()))?
    {
        return Ok(Json(KeyResponse {
            pubkey: user_pubkey,
            public_key_pem: pem,
            key_type,
            created: false,
        }));
    }

    // Generate (CPU-bound) off the async runtime.
    let material = tokio::task::spawn_blocking(ap_signing::generate_rsa_2048)
        .await
        .map_err(|e| ApError::Internal(format!("join error: {e}")))?
        .map_err(|e| ApError::Internal(e.to_string()))?;

    let encrypted = auth_state
        .state
        .key_manager
        .encrypt(&material.pkcs8_der)
        .await
        .map_err(|e| ApError::Internal(e.to_string()))?;

    // create() may race a concurrent create; the UNIQUE constraint is the backstop.
    match repo
        .create(
            tenant_id,
            &user_pubkey,
            &encrypted,
            &material.public_pem,
            AP_KEY_TYPE,
        )
        .await
    {
        Ok(()) => Ok(Json(KeyResponse {
            pubkey: user_pubkey,
            public_key_pem: material.public_pem,
            key_type: AP_KEY_TYPE.to_string(),
            created: true,
        })),
        Err(RepositoryError::Duplicate) => {
            // Lost a race: another request created it. Return the winner's key.
            let (pem, key_type) = repo
                .find_public_pem(tenant_id, &user_pubkey)
                .await
                .map_err(|e| ApError::Internal(e.to_string()))?
                .ok_or_else(|| ApError::Internal("key insert conflict but no row".into()))?;
            Ok(Json(KeyResponse {
                pubkey: user_pubkey,
                public_key_pem: pem,
                key_type,
                created: false,
            }))
        }
        Err(e) => Err(ApError::Internal(e.to_string())),
    }
}

/// GET /api/ap/keys/{pubkey} — return the actor's public PEM. Never decrypts.
pub async fn get_key(
    tenant: TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Path(pubkey): Path<String>,
) -> Result<Json<PublicKeyResponse>, ApError> {
    let tenant_id = tenant.0.id;
    let user_pubkey = resolve_principal(&headers, tenant_id, Some(&pubkey)).await?;
    let repo = ApActorKeysRepository::new(auth_state.state.db.clone());

    let (pem, key_type) = repo
        .find_public_pem(tenant_id, &user_pubkey)
        .await
        .map_err(|e| ApError::Internal(e.to_string()))?
        .ok_or_else(|| ApError::NotFound("No AP key for this actor".to_string()))?;

    Ok(Json(PublicKeyResponse {
        pubkey: user_pubkey,
        public_key_pem: pem,
        key_type,
    }))
}

/// POST /api/ap/sign — sign the exact signing-string bytes; return base64 RSA-SHA256.
pub async fn sign(
    tenant: TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Json(req): Json<SignRequest>,
) -> Result<Json<SignResponse>, ApError> {
    let tenant_id = tenant.0.id;
    let user_pubkey = resolve_principal(&headers, tenant_id, req.pubkey.as_deref()).await?;
    let pool = &auth_state.state.db;

    ensure_active(pool, tenant_id, &user_pubkey).await?;

    let repo = ApActorKeysRepository::new(pool.clone());
    let row = repo
        .find_for_tenant(tenant_id, &user_pubkey)
        .await
        .map_err(|e| ApError::Internal(e.to_string()))?
        .ok_or_else(|| ApError::NotFound("No AP key for this actor".to_string()))?;

    let der = auth_state
        .state
        .key_manager
        .decrypt(&row.encrypted_private_key)
        .await
        .map_err(|e| ApError::Internal(e.to_string()))?;

    let message = req.signing_string.into_bytes();
    let signature = tokio::task::spawn_blocking(move || ap_signing::sign_base64(&der, &message))
        .await
        .map_err(|e| ApError::Internal(format!("join error: {e}")))?
        .map_err(|e| ApError::Internal(e.to_string()))?;

    Ok(Json(SignResponse {
        pubkey: user_pubkey,
        signature,
        algorithm: "rsa-sha256",
    }))
}
