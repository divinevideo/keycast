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
use keycast_core::repositories::{
    ApActorKeysRepository, OAuthAuthorizationRepository, RepositoryError, UserRepository,
};
use nostr_sdk::PublicKey;
use serde::{Deserialize, Serialize};

use crate::api::http::auth::extract_user_and_origin_from_token;
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

fn actor_username(actor: &str) -> Result<String, ApError> {
    let actor = actor.trim();
    let without_scheme = actor
        .strip_prefix("https://")
        .or_else(|| actor.strip_prefix("http://"))
        .ok_or_else(|| ApError::BadRequest("Invalid actor URL".to_string()))?;
    let (_host, path) = without_scheme
        .split_once('/')
        .ok_or_else(|| ApError::BadRequest("Invalid actor URL".to_string()))?;
    let username = path
        .strip_prefix("ap/users/")
        .ok_or_else(|| ApError::BadRequest("Invalid actor URL".to_string()))?;
    if username.is_empty() || username.contains('/') {
        return Err(ApError::BadRequest("Invalid actor URL".to_string()));
    }
    Ok(username.to_string())
}

async fn resolve_actor_pubkey(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    actor: &str,
) -> Result<String, ApError> {
    let username = actor_username(actor)?;
    UserRepository::new(pool.clone())
        .find_pubkey_by_username(&username, tenant_id)
        .await
        .map_err(|e| ApError::Internal(e.to_string()))?
        .ok_or_else(|| ApError::NotFound("No user for this actor".to_string()))
}

async fn resolve_requested_pubkey(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    body_pubkey: Option<&str>,
    actor: Option<&str>,
) -> Result<Option<String>, ApError> {
    match (body_pubkey, actor) {
        (Some(pk), None) => Ok(Some(validate_hex_pubkey(pk)?)),
        (None, Some(actor)) => Ok(Some(resolve_actor_pubkey(pool, tenant_id, actor).await?)),
        (Some(pk), Some(actor)) => {
            let pk = validate_hex_pubkey(pk)?;
            let actor_pk = resolve_actor_pubkey(pool, tenant_id, actor).await?;
            if pk != actor_pk {
                return Err(ApError::Forbidden(
                    "pubkey does not match actor".to_string(),
                ));
            }
            Ok(Some(pk))
        }
        (None, None) => Ok(None),
    }
}

/// Resolve the acting user_pubkey for a request.
/// - Service token: `pubkey` or `actor` is REQUIRED (gateway acts for an existing actor in the tenant).
/// - UCAN: requires a live OAuth authorization bunker and cannot act for a different actor/pubkey.
async fn resolve_principal(
    headers: &HeaderMap,
    pool: &sqlx::PgPool,
    tenant_id: i64,
    body_pubkey: Option<&str>,
    actor: Option<&str>,
) -> Result<String, ApError> {
    let requested = resolve_requested_pubkey(pool, tenant_id, body_pubkey, actor).await?;

    if is_service_token(headers) {
        return requested.ok_or_else(|| {
            ApError::BadRequest("pubkey or actor is required for service-token calls".into())
        });
    }

    // UCAN path
    let (token_pubkey, _redirect_origin, bunker_pubkey) =
        extract_user_and_origin_from_token(headers, tenant_id)
            .await
            .map_err(|_| ApError::Unauthorized("Authentication required".to_string()))?;

    let bunker_pubkey = bunker_pubkey.ok_or_else(|| {
        ApError::Unauthorized("OAuth authorization required for AP signing".to_string())
    })?;
    let oauth_repo = OAuthAuthorizationRepository::new(pool.clone());
    if !oauth_repo
        .exists_active_for_bunker(&bunker_pubkey, &token_pubkey, tenant_id)
        .await
        .map_err(|e| ApError::Internal(e.to_string()))?
    {
        return Err(ApError::Unauthorized(
            "OAuth authorization is revoked or expired".to_string(),
        ));
    }

    if let Some(pk) = requested {
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
    let Some((status, _, _)) = user_repo
        .get_user_status(user_pubkey, tenant_id)
        .await
        .map_err(|e| ApError::Internal(e.to_string()))?
    else {
        return Err(ApError::NotFound("No user for this actor".to_string()));
    };
    if !status.is_active() {
        return Err(ApError::Forbidden("Account restricted".to_string()));
    }
    Ok(())
}

// ---- request/response types ----

#[derive(Debug, Deserialize)]
pub struct CreateKeyRequest {
    /// Hex Nostr pubkey of the actor. Required for service-token callers.
    pub pubkey: Option<String>,
    /// ActivityPub actor URL, e.g. https://divine.video/ap/users/alice.
    pub actor: Option<String>,
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
    /// ActivityPub actor URL, e.g. https://divine.video/ap/users/alice.
    pub actor: Option<String>,
    /// Exact draft-cavage signing string. Signed as its UTF-8 bytes.
    pub signing_string: String,
}

#[derive(Debug, Serialize)]
pub struct SignResponse {
    pub pubkey: String,
    pub signature: String,
    pub algorithm: &'static str,
}

async fn create_actor_key(
    repo: &ApActorKeysRepository,
    auth_state: &AuthState,
    tenant_id: i64,
    user_pubkey: &str,
) -> Result<(String, String, bool), ApError> {
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
            user_pubkey,
            &encrypted,
            &material.public_pem,
            AP_KEY_TYPE,
        )
        .await
    {
        Ok(()) => Ok((material.public_pem, AP_KEY_TYPE.to_string(), true)),
        Err(RepositoryError::Duplicate) => {
            let (pem, key_type) = repo
                .find_public_pem(tenant_id, user_pubkey)
                .await
                .map_err(|e| ApError::Internal(e.to_string()))?
                .ok_or_else(|| ApError::Internal("key insert conflict but no row".into()))?;
            Ok((pem, key_type, false))
        }
        Err(e) => Err(ApError::Internal(e.to_string())),
    }
}

async fn find_or_create_actor_key(
    repo: &ApActorKeysRepository,
    auth_state: &AuthState,
    tenant_id: i64,
    user_pubkey: &str,
) -> Result<(String, String, bool), ApError> {
    if let Some((pem, key_type)) = repo
        .find_public_pem(tenant_id, user_pubkey)
        .await
        .map_err(|e| ApError::Internal(e.to_string()))?
    {
        return Ok((pem, key_type, false));
    }
    create_actor_key(repo, auth_state, tenant_id, user_pubkey).await
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
    let pool = &auth_state.state.db;
    let user_pubkey = resolve_principal(
        &headers,
        pool,
        tenant_id,
        req.pubkey.as_deref(),
        req.actor.as_deref(),
    )
    .await?;
    ensure_active(pool, tenant_id, &user_pubkey).await?;
    let repo = ApActorKeysRepository::new(pool.clone());

    let (pem, key_type, created) =
        find_or_create_actor_key(&repo, &auth_state, tenant_id, &user_pubkey).await?;
    Ok(Json(KeyResponse {
        pubkey: user_pubkey,
        public_key_pem: pem,
        key_type,
        created,
    }))
}

/// GET /api/ap/keys/{pubkey-or-actor} — return the actor's public PEM. Never decrypts.
pub async fn get_key(
    tenant: TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Path(pubkey): Path<String>,
) -> Result<Json<PublicKeyResponse>, ApError> {
    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;
    let user_pubkey = if PublicKey::from_hex(&pubkey).is_ok() {
        resolve_principal(&headers, pool, tenant_id, Some(&pubkey), None).await?
    } else {
        resolve_principal(&headers, pool, tenant_id, None, Some(&pubkey)).await?
    };
    ensure_active(pool, tenant_id, &user_pubkey).await?;
    let repo = ApActorKeysRepository::new(auth_state.state.db.clone());

    let (pem, key_type, _) =
        find_or_create_actor_key(&repo, &auth_state, tenant_id, &user_pubkey).await?;

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
    let pool = &auth_state.state.db;
    let user_pubkey = resolve_principal(
        &headers,
        pool,
        tenant_id,
        req.pubkey.as_deref(),
        req.actor.as_deref(),
    )
    .await?;

    ensure_active(pool, tenant_id, &user_pubkey).await?;

    let repo = ApActorKeysRepository::new(pool.clone());
    let row = match repo
        .find_for_tenant(tenant_id, &user_pubkey)
        .await
        .map_err(|e| ApError::Internal(e.to_string()))?
    {
        Some(row) => row,
        None => {
            create_actor_key(&repo, &auth_state, tenant_id, &user_pubkey).await?;
            repo.find_for_tenant(tenant_id, &user_pubkey)
                .await
                .map_err(|e| ApError::Internal(e.to_string()))?
                .ok_or_else(|| ApError::Internal("key created but no row found".into()))?
        }
    };
    if row.key_type != AP_KEY_TYPE {
        return Err(ApError::BadRequest(format!(
            "Unsupported AP key type: {}",
            row.key_type
        )));
    }

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
