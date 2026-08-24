// ABOUTME: REST RPC API that mirrors NIP-46 methods for low-latency signing
// ABOUTME: Allows HTTP-based signing instead of relay-based NIP-46 communication

use crate::activity_log::ActivityLogResult;
use crate::handlers::http_rpc_handler::{HandlerError, HttpRpcHandler};
use crate::state::{AccountGateState, AccountStatusCache};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::prelude::*;
use chrono::{DateTime, Utc};
use keycast_core::creator_binding::MAX_CREATOR_BINDING_PAYLOAD_BYTES;
use keycast_core::metrics::METRICS;
use keycast_core::repositories::{
    OAuthAuthorizationRepository, PersonalKeysRepository, PolicyRepository, UserRepository,
};
use keycast_core::signing_session::{parse_cache_key, CacheKey, SigningSession};
use keycast_core::traits::CustomPermission;
use nostr_sdk::{Event, JsonUtil, Keys, PublicKey, UnsignedEvent};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use super::auth::AuthError;
use super::routes::AuthState;

/// Wall-clock bound for a single HTTP RPC request, held just under the route's
/// tower timeout so this handler is the one that normally reports the timeout.
///
/// Defined in `core` because the budgets nested inside it — the SQLx acquire
/// timeout and the KMS retry loop — are asserted against it there.
const HANDLER_TIMEOUT: Duration = keycast_core::request_bounds::HTTP_RPC_HANDLER_TIMEOUT;

/// Maximum gift wraps accepted in a single `nip17_unwrap_batch` request.
/// Bounds per-request work and keeps the body well under axum's 2 MB default
/// limit (gift wraps are ~1-2 KB each). Mirrors the `batch_lookup_users` cap.
const MAX_UNWRAP_BATCH: usize = 100;

/// Maximum recipients accepted in one `nip17_wrap_batch` request.
/// The shared rumor is processed sequentially so this is also a hard bound on
/// per-request seal and gift-wrap crypto.
const MAX_WRAP_BATCH: usize = 100;

#[derive(Debug)]
enum AccountGateLoadError {
    Unavailable,
    Query,
}

/// RPC request format (mirrors NIP-46)
#[derive(Debug, Deserialize)]
pub struct NostrRpcRequest {
    pub method: String,
    #[serde(default)]
    pub params: Vec<JsonValue>,
}

/// RPC response format
#[derive(Debug, Serialize)]
pub struct NostrRpcResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl NostrRpcResponse {
    fn success(result: JsonValue) -> Self {
        Self {
            result: Some(result),
            error: None,
        }
    }

    fn error(message: impl Into<String>) -> Self {
        Self {
            result: None,
            error: Some(message.into()),
        }
    }
}

#[derive(Debug)]
pub enum RpcError {
    Auth(AuthError),
    AccountSuspended(String),
    InvalidParams(String),
    UnsupportedMethod(String),
    SigningFailed(String),
    EncryptionFailed(String),
    DecryptionFailed(String),
    Unavailable(String),
    Timeout(String),
    Internal(String),
}

impl IntoResponse for RpcError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            RpcError::Auth(e) => return e.into_response(),
            RpcError::AccountSuspended(msg) => (StatusCode::FORBIDDEN, msg),
            RpcError::InvalidParams(msg) => (StatusCode::BAD_REQUEST, msg),
            RpcError::UnsupportedMethod(method) => (
                StatusCode::BAD_REQUEST,
                format!("Unsupported method: {}", method),
            ),
            RpcError::SigningFailed(msg) => (StatusCode::BAD_REQUEST, msg),
            RpcError::EncryptionFailed(msg) => (StatusCode::BAD_REQUEST, msg),
            RpcError::DecryptionFailed(msg) => (StatusCode::BAD_REQUEST, msg),
            RpcError::Unavailable(msg) => (StatusCode::SERVICE_UNAVAILABLE, msg),
            RpcError::Timeout(msg) => (StatusCode::GATEWAY_TIMEOUT, msg),
            RpcError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        (status, Json(NostrRpcResponse::error(message))).into_response()
    }
}

impl From<AuthError> for RpcError {
    fn from(e: AuthError) -> Self {
        RpcError::Auth(e)
    }
}

impl From<HandlerError> for RpcError {
    fn from(e: HandlerError) -> Self {
        match e {
            HandlerError::AuthorizationInvalid => RpcError::Auth(AuthError::InvalidToken),
            HandlerError::PermissionDenied => {
                RpcError::Auth(AuthError::Forbidden("Operation denied by policy".into()))
            }
            HandlerError::InvalidRequest(msg) => RpcError::InvalidParams(msg),
            HandlerError::Signing(msg) => RpcError::SigningFailed(msg),
            HandlerError::Encryption(msg) => RpcError::EncryptionFailed(msg),
        }
    }
}

/// POST /api/nostr - JSON-RPC style endpoint for NIP-46 operations
///
/// Supports all NIP-46 methods:
/// - get_public_key: Returns user's hex pubkey
/// - sign_event: Signs an unsigned event
/// - sign_canonical: Signs a base64-encoded creator-binding payload
/// - nip04_encrypt: Encrypts plaintext using NIP-04
/// - nip04_decrypt: Decrypts ciphertext using NIP-04
/// - nip44_encrypt: Encrypts plaintext using NIP-44
/// - nip44_decrypt: Decrypts ciphertext using NIP-44
/// - nip17_unwrap_batch: Unwraps a batch of NIP-59 gift wraps (1059→seal→rumor),
///   returning ordered per-item `{rumor, sender}` / `{error}` slots. Amortizes the
///   per-request auth/status overhead and collapses the client's 2 RPCs-per-DM.
/// - nip17_wrap_batch: Wraps one shared NIP-17 rumor for an ordered recipient
///   list, returning per-recipient `{gift_wrap}` / `{error}` slots. Preserves
///   the existing NIP-44 encryption and kind-13 signing policy checks.
///
/// Uses BLAKE3 token cache - on cache hit, skips UCAN verification entirely.
/// All operations use cached handler with in-memory permission validation (no DB hits).
pub async fn nostr_rpc(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Json(req): Json<NostrRpcRequest>,
) -> Result<Json<NostrRpcResponse>, RpcError> {
    let method = req.method.clone();
    let started = Instant::now();
    // The route also carries a tower timeout, but that layer drops this future
    // whole, so a request bounded there records no latency sample at all — the
    // long tail this endpoint exists to measure would be the one bucket that
    // stays empty. Bound the handler here instead, where the method label and
    // the observation survive, and leave the layer as a wider backstop for the
    // work outside this function.
    let response = match tokio::time::timeout(
        HANDLER_TIMEOUT,
        nostr_rpc_inner(tenant, auth_state, headers, req),
    )
    .await
    {
        Ok(response) => response,
        Err(_) => Err(RpcError::Timeout(format!(
            "RPC request timed out after {}s",
            HANDLER_TIMEOUT.as_secs()
        ))),
    };
    let outcome = http_rpc_outcome(&response);
    METRICS.observe_http_rpc_request(&method, outcome, started.elapsed());
    response
}

async fn nostr_rpc_inner(
    tenant: crate::api::tenant::TenantExtractor,
    auth_state: AuthState,
    headers: HeaderMap,
    req: NostrRpcRequest,
) -> Result<Json<NostrRpcResponse>, RpcError> {
    // Track total HTTP RPC requests
    METRICS.inc_http_rpc_request();

    // Extract raw Authorization header for BLAKE3 caching
    let auth_header = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(RpcError::Auth(AuthError::MissingToken))?;

    let pool = &auth_state.state.db;
    let tenant_id = tenant.0.id;

    tracing::debug!("RPC request: method={}", req.method);

    // Get cached handler using BLAKE3(token) as cache key
    // On cache hit: skips UCAN verification entirely (~25% CPU savings)
    // On cache miss: verifies UCAN, loads from DB, caches result
    let handler = match get_handler(&auth_state, pool, auth_header, tenant_id, &headers).await {
        Ok(h) => h,
        Err(e) => {
            METRICS.inc_http_rpc_auth_error();
            return Err(e);
        }
    };

    // For mutating operations (sign/encrypt/decrypt), check user account status.
    // get_public_key is NOT gated -- suspended users need to retrieve their pubkey.
    // The same per-request row also carries verified_minor, which drives the DM
    // containment gate below (support-trust-safety#183). This short-lived cache
    // removes the mandatory pool checkout from warm calls while bounding
    // cross-instance status and minor-safety changes to five seconds.
    // `sign_event` still reads the row, because the verified_minor gate below
    // depends on it, but is not refused on account status (keycast#373).
    let needs_status_check = !matches!(req.method.as_str(), "get_public_key");
    let verified_minor = if needs_status_check {
        let deny_when_restricted = req.method.as_str() != "sign_event";
        check_user_status_active(
            &auth_state.state.account_status_cache,
            pool,
            &handler.user_pubkey_hex(),
            tenant_id,
            deny_when_restricted,
        )
        .await?
    } else {
        false
    };

    // Dispatch based on method - all permission checks use cached data (no DB hits)
    let result = match req.method.as_str() {
        "get_public_key" => JsonValue::String(handler.user_pubkey_hex()),

        "sign_event" => {
            let unsigned_event = parse_unsigned_event(&req.params)?;

            if verified_minor {
                enforce_minor_dm_sign(&handler, &unsigned_event)?;
            }

            // Handler validates expiration, revocation, and permissions (all cached)
            let signed = handler.sign_event(unsigned_event).await?;

            tracing::info!(
                "RPC: Signed event {} kind={}",
                signed.id,
                signed.kind.as_u16()
            );

            log_activity(&auth_state, handler.is_oauth(), handler.authorization_id());

            serde_json::to_value(&signed)
                .map_err(|e| RpcError::Internal(format!("JSON serialization failed: {}", e)))?
        }

        "sign_canonical" => {
            let payload = parse_canonical_payload_params(&req.params)?;

            // Creator-binding payloads are not DMs, so the verified_minor DM
            // containment gate does not apply. Handler validity and custom
            // signing permissions still apply before signing.
            let signature = handler.sign_canonical(payload).await?;

            tracing::info!(
                "RPC: Signed creator-binding payload authorization_id={}",
                handler.authorization_id()
            );

            log_activity(&auth_state, handler.is_oauth(), handler.authorization_id());

            JsonValue::String(signature)
        }

        "nip44_encrypt" => {
            let (recipient_pubkey, plaintext) = parse_encrypt_params(&req.params)?;

            if verified_minor {
                enforce_minor_dm_encrypt(&handler, &recipient_pubkey)?;
            }

            // Handler validates expiration, revocation, and permissions (all cached)
            // Crypto runs on spawn_blocking to avoid blocking async workers
            let ciphertext = handler.nip44_encrypt(&recipient_pubkey, &plaintext).await?;

            log_activity(&auth_state, handler.is_oauth(), handler.authorization_id());

            JsonValue::String(ciphertext)
        }

        "nip44_decrypt" => {
            let (sender_pubkey, ciphertext) = parse_decrypt_params(&req.params)?;

            // Handler validates expiration, revocation, and permissions (all cached)
            // Crypto runs on spawn_blocking to avoid blocking async workers
            let plaintext = handler.nip44_decrypt(&sender_pubkey, &ciphertext).await?;

            log_activity(&auth_state, handler.is_oauth(), handler.authorization_id());

            // Expose secret only at serialization boundary
            JsonValue::String(plaintext.expose_secret().to_string())
        }

        "nip17_unwrap_batch" => {
            // Size cap keeps the request under axum's 2 MB default body limit and
            // bounds per-request work (mirrors the batch_lookup_users cap precedent).
            if req.params.is_empty() {
                return Err(RpcError::InvalidParams("Empty gift wrap batch".into()));
            }
            if req.params.len() > MAX_UNWRAP_BATCH {
                return Err(RpcError::InvalidParams(format!(
                    "Maximum {} gift wraps per batch",
                    MAX_UNWRAP_BATCH
                )));
            }

            // Whole-batch validity gate: an expired/revoked authorization can
            // decrypt nothing, so fail the batch rather than emitting N error
            // slots (matches the single-method behavior).
            if !handler.is_valid() {
                return Err(RpcError::Auth(AuthError::InvalidToken));
            }

            // Server does BOTH gift-wrap decrypt layers internally, so the client
            // makes one call per page instead of 2 sequential RPCs per message.
            let results = unwrap_gift_wrap_batch(&handler, &req.params).await;

            // One coalesced activity log for the whole batch (per-request semantics).
            log_activity(&auth_state, handler.is_oauth(), handler.authorization_id());

            JsonValue::Array(results)
        }

        "nip17_wrap_batch" => {
            let batch = parse_nip17_wrap_batch_params(&req.params)?;

            // Common rumor failures invalidate every possible recipient slot,
            // so reject them once at request level before any crypto.
            if batch.rumor.pubkey != handler.public_key() {
                return Err(RpcError::InvalidParams(
                    "Rumor author must match signer".into(),
                ));
            }
            batch
                .rumor
                .verify_id()
                .map_err(|_| RpcError::InvalidParams("Invalid rumor id".into()))?;

            // Whole-batch validity gate, matching nip17_unwrap_batch. The
            // handler primitives still recheck validity at each operation.
            if !handler.is_valid() {
                return Err(RpcError::Auth(AuthError::InvalidToken));
            }

            if verified_minor {
                enforce_minor_dm_rumor(&handler, &batch.rumor)?;
                // Validate every parseable encryption target before building
                // any slot. Malformed targets cannot receive a wrap and remain
                // isolated as `invalid_recipient` slots.
                for recipient in batch
                    .recipients
                    .iter()
                    .filter_map(|recipient| recipient.as_ref().ok())
                {
                    enforce_minor_dm_encrypt(&handler, recipient)?;
                }
            }

            // Sequential construction bounds blocking crypto and naturally
            // preserves duplicate and positional recipient semantics.
            let results = wrap_gift_wrap_batch(&handler, &batch.rumor, &batch.recipients).await;

            // One coalesced activity update for the whole RPC request.
            log_activity(&auth_state, handler.is_oauth(), handler.authorization_id());

            JsonValue::Array(results)
        }

        "nip04_encrypt" => {
            let (recipient_pubkey, plaintext) = parse_encrypt_params(&req.params)?;

            if verified_minor {
                enforce_minor_dm_encrypt(&handler, &recipient_pubkey)?;
            }

            // Handler validates expiration, revocation, and permissions (all cached)
            // Crypto runs on spawn_blocking to avoid blocking async workers
            let ciphertext = handler.nip04_encrypt(&recipient_pubkey, &plaintext).await?;

            log_activity(&auth_state, handler.is_oauth(), handler.authorization_id());

            JsonValue::String(ciphertext)
        }

        "nip04_decrypt" => {
            let (sender_pubkey, ciphertext) = parse_decrypt_params(&req.params)?;

            // Handler validates expiration, revocation, and permissions (all cached)
            // Crypto runs on spawn_blocking to avoid blocking async workers
            let plaintext = handler.nip04_decrypt(&sender_pubkey, &ciphertext).await?;

            log_activity(&auth_state, handler.is_oauth(), handler.authorization_id());

            // Expose secret only at serialization boundary
            JsonValue::String(plaintext.expose_secret().to_string())
        }

        method => {
            return Err(RpcError::UnsupportedMethod(method.to_string()));
        }
    };

    // Track successful requests
    METRICS.inc_http_rpc_success();

    Ok(Json(NostrRpcResponse::success(result)))
}

/// Classify a repository error from the cold RPC path.
///
/// A pool acquire timeout under saturation is transient, so it gets the same
/// retryable 503 the warm status check already returns. Anything else stays a
/// 500. Detail goes to the log, never to the response: this endpoint is reached
/// before the caller is known to be legitimate, and connect-level failures carry
/// host, DNS and TLS text.
fn map_repo_error(context: &str, error: keycast_core::repositories::RepositoryError) -> RpcError {
    use keycast_core::repositories::RepositoryError;

    match error {
        RepositoryError::Unavailable(detail) => {
            tracing::warn!(context, %detail, "HTTP RPC database unavailable");
            RpcError::Unavailable("Database temporarily unavailable".to_string())
        }
        other => {
            tracing::error!(context, error = %other, "HTTP RPC database error");
            RpcError::Internal(format!("Database error: {}", context))
        }
    }
}

fn http_rpc_outcome(response: &Result<Json<NostrRpcResponse>, RpcError>) -> &'static str {
    match response {
        Ok(_) => "success",
        Err(RpcError::Auth(_)) => "auth_error",
        Err(RpcError::InvalidParams(_))
        | Err(RpcError::UnsupportedMethod(_))
        | Err(RpcError::SigningFailed(_))
        | Err(RpcError::EncryptionFailed(_))
        | Err(RpcError::DecryptionFailed(_)) => "client_error",
        Err(RpcError::AccountSuspended(_)) => "account_restricted",
        Err(RpcError::Unavailable(_)) => "unavailable",
        Err(RpcError::Timeout(_)) => "timeout",
        Err(RpcError::Internal(_)) => "error",
    }
}

/// Read the account gate state before a mutating operation.
///
/// Cache misses query Postgres and fail closed. Concurrent misses for one account
/// are coalesced, backend errors are not cached, and local admin writes invalidate
/// immediately. Changes made on another instance take effect within
/// [`crate::state::ACCOUNT_STATUS_CACHE_TTL`].
/// Returns the account's `verified_minor` flag (same row, no extra query) for
/// the DM containment gate; a missing user row is a refusal, never a default.
///
/// `deny_when_restricted` decides whether a non-active status refuses the call.
/// It is false for `sign_event` (keycast#373): the row is still read, because the
/// verified_minor gate depends on it, but a suspended or banned account may still
/// sign. Signing is how an account proves it is itself and how its holder exports
/// and republishes elsewhere. Enforcement governs what Divine hosts — the relay
/// rejects banned authors on write — not whether the identity can act off Divine.
async fn check_user_status_active(
    cache: &AccountStatusCache,
    pool: &sqlx::PgPool,
    user_pubkey_hex: &str,
    tenant_id: i64,
    deny_when_restricted: bool,
) -> Result<bool, RpcError> {
    let status_started = Instant::now();
    METRICS.set_http_rpc_db_pool_state(pool.size(), pool.num_idle() as u32);
    let cache_key = (tenant_id, user_pubkey_hex.to_string());
    let pool = pool.clone();
    let pubkey = user_pubkey_hex.to_string();

    let cache_hit = cache.get(&cache_key).await.is_some();
    if cache_hit {
        METRICS.inc_http_rpc_account_status_cache_hit();
    } else {
        METRICS.inc_http_rpc_account_status_cache_miss();
    }

    let status = match cache
        .try_get_with(cache_key, async move {
            load_account_gate_state(&pool, &pubkey, tenant_id).await
        })
        .await
    {
        Ok(status) => status,
        Err(error) => {
            let result = Err(match error.as_ref() {
                AccountGateLoadError::Unavailable => {
                    RpcError::Unavailable("Database temporarily unavailable".to_string())
                }
                AccountGateLoadError::Query => {
                    RpcError::Internal("Database error checking user status".to_string())
                }
            });
            METRICS.observe_http_rpc_status_check(
                http_rpc_outcome_for_status_check(&result),
                status_started.elapsed(),
            );
            return result;
        }
    };

    METRICS.set_http_rpc_account_status_cache_size(cache.entry_count());

    let result = match status {
        AccountGateState::Present {
            status,
            verified_minor,
        } if status == "active" => Ok(verified_minor),
        AccountGateState::Present {
            status,
            verified_minor,
        } if !deny_when_restricted => {
            tracing::info!(
                event = "rpc.sign_allowed_for_restricted_account",
                status = %status,
                "Signing allowed for a restricted account (keycast#373)"
            );
            Ok(verified_minor)
        }
        AccountGateState::Present { .. } => {
            Err(RpcError::AccountSuspended("Account restricted".to_string()))
        }
        AccountGateState::Missing => Err(RpcError::Auth(AuthError::InvalidToken)),
    };

    if !cache_hit {
        METRICS.observe_http_rpc_status_check(
            http_rpc_outcome_for_status_check(&result),
            status_started.elapsed(),
        );
    }
    result
}

async fn load_account_gate_state(
    pool: &sqlx::PgPool,
    user_pubkey_hex: &str,
    tenant_id: i64,
) -> Result<AccountGateState, AccountGateLoadError> {
    let acquire_started = Instant::now();
    let mut conn = match pool.acquire().await {
        Ok(conn) => {
            METRICS.observe_http_rpc_db_acquire(
                "check_user_status_active",
                "success",
                acquire_started.elapsed(),
            );
            conn
        }
        Err(e) => {
            METRICS.observe_http_rpc_db_acquire(
                "check_user_status_active",
                "unavailable",
                acquire_started.elapsed(),
            );
            // Detail to the log only: connect-level failures carry host, DNS and
            // TLS text and this response is reachable before the caller is known
            // to be legitimate.
            tracing::warn!(error = %e, "HTTP RPC could not acquire a connection for the status check");
            return Err(AccountGateLoadError::Unavailable);
        }
    };

    let status: Option<(String, bool)> = sqlx::query_as(
        "SELECT status, verified_minor FROM users WHERE pubkey = $1 AND tenant_id = $2",
    )
    .bind(user_pubkey_hex)
    .bind(tenant_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "HTTP RPC user status query failed");
        AccountGateLoadError::Query
    })?;

    Ok(match status {
        Some((status, verified_minor)) => AccountGateState::Present {
            status,
            verified_minor,
        },
        None => AccountGateState::Missing,
    })
}

pub(crate) async fn invalidate_account_status_cache(
    cache: &AccountStatusCache,
    user_pubkey_hex: &str,
    tenant_id: i64,
) {
    cache
        .invalidate(&(tenant_id, user_pubkey_hex.to_string()))
        .await;
    METRICS.set_http_rpc_account_status_cache_size(cache.entry_count());
}

fn http_rpc_outcome_for_status_check(result: &Result<bool, RpcError>) -> &'static str {
    match result {
        Ok(_) => "success",
        Err(RpcError::Auth(_)) => "auth_error",
        Err(RpcError::AccountSuspended(_)) => "account_restricted",
        Err(RpcError::Unavailable(_)) => "unavailable",
        Err(_) => "error",
    }
}

/// Uniform client-facing message for verified_minor DM gate refusals — matches
/// the policy-denial message so account state is not leaked through error text.
const MINOR_DM_DENIED_MSG: &str = "Operation denied by policy";

/// Apply the verified_minor DM containment gate to a sign request
/// (support-trust-safety#183). The denial detail is logged server-side only.
fn enforce_minor_dm_sign(
    handler: &Arc<HttpRpcHandler>,
    unsigned: &UnsignedEvent,
) -> Result<(), RpcError> {
    keycast_core::verified_minor_dm::validate_minor_sign(handler.keys(), unsigned).map_err(
        |denied| {
            tracing::warn!(
                event = "minor_dm_gate.sign_denied",
                user_pubkey = %handler.user_pubkey_hex(),
                kind = unsigned.kind.as_u16(),
                reason = %denied,
                "verified_minor DM sign refused"
            );
            RpcError::Auth(AuthError::Forbidden(MINOR_DM_DENIED_MSG.into()))
        },
    )
}

/// Apply the verified_minor DM containment gate to an encrypt request
/// (support-trust-safety#183). The denial detail is logged server-side only.
fn enforce_minor_dm_encrypt(
    handler: &Arc<HttpRpcHandler>,
    recipient: &PublicKey,
) -> Result<(), RpcError> {
    keycast_core::verified_minor_dm::validate_minor_encrypt(&handler.public_key(), recipient)
        .map_err(|denied| {
            tracing::warn!(
                event = "minor_dm_gate.encrypt_denied",
                user_pubkey = %handler.user_pubkey_hex(),
                recipient = %recipient.to_hex(),
                reason = %denied,
                "verified_minor DM encrypt refused"
            );
            RpcError::Auth(AuthError::Forbidden(MINOR_DM_DENIED_MSG.into()))
        })
}

/// Apply the verified_minor containment gate to an already-parsed raw rumor
/// before Keycast composes any per-recipient seals.
fn enforce_minor_dm_rumor(
    handler: &Arc<HttpRpcHandler>,
    rumor: &UnsignedEvent,
) -> Result<(), RpcError> {
    keycast_core::verified_minor_dm::validate_minor_rumor_recipients(&handler.public_key(), rumor)
        .map_err(|denied| {
            tracing::warn!(
                event = "minor_dm_gate.rumor_denied",
                user_pubkey = %handler.user_pubkey_hex(),
                kind = rumor.kind.as_u16(),
                reason = %denied,
                "verified_minor NIP-17 rumor refused"
            );
            RpcError::Auth(AuthError::Forbidden(MINOR_DM_DENIED_MSG.into()))
        })
}

/// Load an HttpRpcHandler on-demand from DB and cache it
/// Called when http_handler_cache misses for the given bunker_pubkey
/// Loads authorization metadata, user keys, AND permissions - all cached in handler
async fn load_handler_on_demand(
    auth_state: &AuthState,
    pool: &sqlx::PgPool,
    bunker_pubkey_hex: &str,
    tenant_id: i64,
    dpop_cnf_jkt: Option<String>,
) -> Result<Arc<HttpRpcHandler>, RpcError> {
    let key_manager = auth_state.state.key_manager.as_ref();

    // Query oauth_authorization for this bunker_pubkey, scoped to tenant
    // Includes: expires_at, revoked_at (for validity), policy_id (for permissions)
    let oauth_auth_repo = OAuthAuthorizationRepository::new(pool.clone());
    let auth_data = oauth_auth_repo
        .find_by_bunker_pubkey_for_tenant(bunker_pubkey_hex, tenant_id)
        .await
        .map_err(|e| map_repo_error("loading authorization", e))?;

    let (auth_id, user_pubkey, auth_handle_opt, expires_at, revoked_at, policy_id) =
        auth_data.ok_or(RpcError::Auth(AuthError::InvalidToken))?;

    // Load permissions for this authorization's policy (if any)
    let permissions: Vec<Box<dyn CustomPermission>> = if let Some(pid) = policy_id {
        let policy_repo = PolicyRepository::new(pool.clone());
        let db_permissions = policy_repo
            .get_permissions(pid)
            .await
            .map_err(|e| map_repo_error("loading permissions", e))?;

        // Convert to CustomPermission trait objects
        db_permissions
            .iter()
            .filter_map(|p| p.to_custom_permission().ok())
            .collect()
    } else {
        // No policy = full access (empty permissions vec)
        vec![]
    };

    // Get user's encrypted secret key, scoped to tenant
    let personal_keys_repo = PersonalKeysRepository::new(pool.clone());
    let encrypted_secret: Vec<u8> = personal_keys_repo
        .find_encrypted_key_for_tenant(&user_pubkey, tenant_id)
        .await
        .map_err(|e| map_repo_error("loading personal key", e))?
        .ok_or_else(|| RpcError::Internal("Personal keys not found".to_string()))?;

    // Decrypt the secret key
    let decrypted_secret = key_manager
        .decrypt(&encrypted_secret)
        .await
        .map_err(|e| RpcError::Internal(format!("Decryption failed: {}", e)))?;

    let secret_key = nostr_sdk::secp256k1::SecretKey::from_slice(&decrypted_secret)
        .map_err(|e| RpcError::Internal(format!("Invalid secret key bytes: {}", e)))?;
    let user_keys = Keys::new(secret_key.into());

    // Parse cache keys
    let bunker_key = parse_cache_key(bunker_pubkey_hex)
        .map_err(|e| RpcError::Internal(format!("Invalid bunker_pubkey: {}", e)))?;

    // For authorization_handle, use it if present, otherwise use bunker_pubkey as fallback
    let auth_handle = if let Some(ref handle) = auth_handle_opt {
        parse_cache_key(handle)
            .map_err(|e| RpcError::Internal(format!("Invalid authorization_handle: {}", e)))?
    } else {
        bunker_key // Fallback: use bunker_pubkey as handle for legacy auths
    };

    // Create signing session (pure crypto wrapper - just keys)
    let session = Arc::new(SigningSession::new(user_keys));

    // Create handler with cached authorization metadata, permissions, and cache keys
    let handler = Arc::new(HttpRpcHandler::new(
        session,
        auth_id as i64,
        expires_at,
        revoked_at,
        permissions,
        true, // OAuth authorization
        bunker_key,
        auth_handle,
        dpop_cnf_jkt,
    ));

    // Note: Caching is done by caller with BLAKE3(token) key, not here
    // This allows skipping UCAN verification entirely on cache hits

    Ok(handler)
}

/// Construct the absolute htu (HTTP Target URI) from request headers per RFC 9449.
/// Uses x-forwarded-proto for scheme and Host header for host.
fn construct_htu(headers: &HeaderMap) -> String {
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http");
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    format!("{}://{}/api/nostr", scheme, host)
}

/// Compute BLAKE3 hash of token for cache lookup
/// BLAKE3 is ~500ns for 500-byte token vs ~1-2ms for Schnorr verification (2000-4000x faster)
fn compute_token_cache_key(auth_header: &str) -> Option<CacheKey> {
    let token = auth_header.strip_prefix("Bearer ")?;
    Some(*blake3::hash(token.as_bytes()).as_bytes())
}

fn map_dpop_error_to_rpc_error(error: anyhow::Error, context: &str) -> RpcError {
    if crate::ucan_auth::is_replay_cache_unavailable_error(&error) {
        tracing::error!("RPC: DPoP verification failed ({context}): {}", error);
        RpcError::Internal("DPoP replay protection temporarily unavailable. Please retry.".into())
    } else {
        tracing::warn!("RPC: DPoP verification failed ({context}): {}", error);
        RpcError::Auth(AuthError::InvalidToken)
    }
}

async fn enforce_cached_dpop_binding(
    handler: &HttpRpcHandler,
    headers: &HeaderMap,
    htu: &str,
) -> Result<(), RpcError> {
    let Some(expected_jkt) = handler.expected_dpop_jkt() else {
        return Ok(());
    };

    match crate::ucan_auth::verify_dpop_proof(headers, "POST", htu, Some(expected_jkt)).await {
        Ok(Some(_)) => {
            tracing::debug!("RPC: DPoP binding verified on cache hit");
            Ok(())
        }
        Ok(None) => {
            tracing::warn!(
                "RPC: DPoP-bound token used without DPoP proof on cache hit (jkt={})",
                &expected_jkt[..8.min(expected_jkt.len())]
            );
            Err(RpcError::Auth(AuthError::InvalidToken))
        }
        Err(e) => Err(map_dpop_error_to_rpc_error(e, "cache hit")),
    }
}

/// Check if issuer matches server pubkey (server-signed UCAN)
fn is_server_signed(ucan: &ucan::Ucan) -> bool {
    crate::ucan_auth::is_server_signed(ucan)
}

/// Load handler for preloaded user (server-signed UCAN, no bunker_pubkey)
/// Originally for unclaimed Vine imports; gate dropped to allow admin-issued
/// preload UCANs to keep signing for accounts after claim — needed to publish
/// additional legacy Vine archives discovered after handover.
///
/// Caller must pass the UCAN's `redirect_origin` and `exp` so we can (1) reject
/// non-preload server-signed UCANs (admin sessions, claim UCANs, etc.) and (2)
/// propagate the UCAN expiry into the cached handler so warm cache hits stop
/// signing once the UCAN lifetime ends.
async fn load_preloaded_user_handler(
    auth_state: &AuthState,
    pool: &sqlx::PgPool,
    user_pubkey_hex: &str,
    tenant_id: i64,
    redirect_origin: &str,
    ucan_expires_at: Option<DateTime<Utc>>,
    dpop_cnf_jkt: Option<String>,
) -> Result<Arc<HttpRpcHandler>, RpcError> {
    // Only accept UCANs minted by generate_preload_ucan (admin.rs).
    // Other server-signed UCANs (admin sessions, claim flow) must not be usable
    // to sign as preload users via this path.
    if redirect_origin != "preload" {
        tracing::warn!(
            "Preloaded user RPC denied: redirect_origin={} for user {}",
            redirect_origin,
            &user_pubkey_hex[..8]
        );
        return Err(RpcError::Auth(AuthError::InvalidToken));
    }

    let key_manager = auth_state.state.key_manager.as_ref();

    // Verify user exists (encrypted key lookup below will also catch missing rows).
    let user_repo = UserRepository::new(pool.clone());
    if user_repo
        .is_unclaimed(user_pubkey_hex, tenant_id)
        .await
        .map_err(|e| map_repo_error("checking preloaded user", e))?
        .is_none()
    {
        tracing::warn!(
            "Preloaded user RPC denied: user {} not found",
            &user_pubkey_hex[..8]
        );
        return Err(RpcError::Auth(AuthError::InvalidToken));
    }

    // Get user's encrypted secret key, scoped to tenant
    let personal_keys_repo = PersonalKeysRepository::new(pool.clone());
    let encrypted_secret: Vec<u8> = personal_keys_repo
        .find_encrypted_key_for_tenant(user_pubkey_hex, tenant_id)
        .await
        .map_err(|e| map_repo_error("loading preloaded personal key", e))?
        .ok_or_else(|| {
            RpcError::Internal("Personal keys not found for preloaded user".to_string())
        })?;

    // Decrypt the secret key
    let decrypted_secret = key_manager
        .decrypt(&encrypted_secret)
        .await
        .map_err(|e| RpcError::Internal(format!("Decryption failed: {}", e)))?;

    let secret_key = nostr_sdk::secp256k1::SecretKey::from_slice(&decrypted_secret)
        .map_err(|e| RpcError::Internal(format!("Invalid secret key bytes: {}", e)))?;
    let user_keys = Keys::new(secret_key.into());

    // Create a synthetic cache key from user pubkey (for cache storage)
    let cache_key = parse_cache_key(user_pubkey_hex)
        .map_err(|e| RpcError::Internal(format!("Invalid user_pubkey: {}", e)))?;

    // Create signing session
    let session = Arc::new(SigningSession::new(user_keys));

    // Create handler with NO policy restrictions (empty permissions = full access).
    // The cached handler's expiry is the UCAN's exp: cache hits short-circuit UCAN
    // validation entirely, so without this, a warm cache entry would keep signing
    // past the UCAN's lifetime until the entry was idle-evicted.
    let handler = Arc::new(HttpRpcHandler::new(
        session,
        0,               // No authorization_id - this is direct access
        ucan_expires_at, // Stop signing when the UCAN expires (Daniel feedback)
        None,            // Not revoked
        vec![],          // No permissions = full access
        false,           // Not OAuth (preloaded user mode)
        cache_key,
        cache_key, // Use same key for auth_handle
        dpop_cnf_jkt,
    ));

    tracing::info!(
        "Preloaded user handler created for pubkey: {}",
        &user_pubkey_hex[..8]
    );

    Ok(handler)
}

/// Get the HttpRpcHandler for this request using BLAKE3 token cache
///
/// FAST PATH (cache hit): BLAKE3(token) lookup → return handler (~500ns)
/// - Skips UCAN parsing and Schnorr signature verification entirely
///
/// SLOW PATH (cache miss): Full UCAN verification → DB load → cache insert
/// Three authentication modes are supported:
/// 1. OAuth tokens: bunker_pubkey in UCAN → load from oauth_authorizations
/// 2. Preloaded users: server-signed UCAN without bunker_pubkey → load personal key directly
/// 3. Session UCANs: user-signed without bunker_pubkey → rejected (use OAuth flow)
///
/// All subsequent operations (sign, encrypt, decrypt) use cached data - no DB hits.
async fn get_handler(
    auth_state: &AuthState,
    pool: &sqlx::PgPool,
    auth_header: &str,
    tenant_id: i64,
    headers: &HeaderMap,
) -> Result<Arc<HttpRpcHandler>, RpcError> {
    // Compute BLAKE3 hash for cache lookup (~500ns)
    let blake3_key =
        compute_token_cache_key(auth_header).ok_or(RpcError::Auth(AuthError::InvalidToken))?;

    // FAST PATH: Check cache by BLAKE3(token) - skips UCAN entirely!
    if let Some(handler) = auth_state.state.http_handler_cache.get(&blake3_key).await {
        // Check cached validity (no DB hit for expired/revoked)
        if !handler.is_valid() {
            // Evict invalid handler from cache
            auth_state
                .state
                .http_handler_cache
                .invalidate(&blake3_key)
                .await;
            return Err(RpcError::Auth(AuthError::InvalidToken));
        }

        // On cache hit, enforce DPoP binding from cached UCAN cnf.jkt.
        let htu = construct_htu(headers);
        enforce_cached_dpop_binding(&handler, headers, &htu).await?;

        // Cache hit! Skip full UCAN verification
        METRICS.inc_http_rpc_cache_hit();
        tracing::trace!("RPC: Cache hit (BLAKE3)");
        return Ok(handler);
    }

    // SLOW PATH: Cache miss - full UCAN verification
    METRICS.inc_http_rpc_cache_miss();

    // Verify UCAN and extract bunker_pubkey (Schnorr signature verification ~1-2ms)
    let (user_pubkey, redirect_origin, bunker_pubkey, ucan) =
        crate::ucan_auth::validate_ucan_token(auth_header, tenant_id)
            .await
            .map_err(|_| RpcError::Auth(AuthError::InvalidToken))?;

    // Extract UCAN expiry (unix seconds → DateTime<Utc>) so cached preload
    // handlers can be invalidated once the UCAN lifetime ends.
    let ucan_expires_at: Option<DateTime<Utc>> =
        DateTime::<Utc>::from_timestamp(*ucan.expires_at() as i64, 0);

    let dpop_cnf_jkt = crate::ucan_auth::extract_cnf_jkt_from_ucan(&ucan);

    // Enforce DPoP binding if the UCAN contains cnf.jkt.
    if let Some(expected_jkt) = dpop_cnf_jkt.as_deref() {
        // RFC 9449 requires htu to be the absolute URI (scheme + host + path)
        let htu = construct_htu(headers);
        match crate::ucan_auth::verify_dpop_proof(headers, "POST", &htu, Some(expected_jkt)).await {
            Ok(Some(_)) => {
                tracing::debug!("RPC: DPoP binding verified for cnf.jkt");
            }
            Ok(None) => {
                tracing::warn!(
                    "RPC: DPoP-bound token used without DPoP proof (jkt={})",
                    &expected_jkt[..8.min(expected_jkt.len())]
                );
                return Err(RpcError::Auth(AuthError::InvalidToken));
            }
            Err(e) => {
                return Err(map_dpop_error_to_rpc_error(e, "cache miss"));
            }
        }
    }

    // Determine which authentication mode to use
    let handler = if let Some(bunker_key_hex) = bunker_pubkey {
        // MODE 1: OAuth token with bunker_pubkey - load from oauth_authorizations (tenant-scoped)
        let h = load_handler_on_demand(
            auth_state,
            pool,
            &bunker_key_hex,
            tenant_id,
            dpop_cnf_jkt.clone(),
        )
        .await?;
        tracing::debug!(
            "RPC: Loaded OAuth handler for bunker {}",
            &bunker_key_hex[..8]
        );
        h
    } else if is_server_signed(&ucan) {
        // MODE 2: Preloaded user - server-signed UCAN without bunker_pubkey
        // Used for Vine import; works for both unclaimed and claimed accounts so
        // admins can publish additional legacy archives after handover.
        // The callee rejects server-signed UCANs whose redirect_origin != "preload"
        // so admin-session / claim UCANs cannot fall through this path.
        let h = load_preloaded_user_handler(
            auth_state,
            pool,
            &user_pubkey,
            tenant_id,
            &redirect_origin,
            ucan_expires_at,
            dpop_cnf_jkt.clone(),
        )
        .await?;
        tracing::debug!(
            "RPC: Loaded preloaded user handler for pubkey {}",
            &user_pubkey[..8]
        );
        h
    } else {
        // MODE 3: Session UCAN (user-signed, no bunker_pubkey) - not valid for RPC
        // Users must go through OAuth flow to get a bunker_pubkey token
        tracing::warn!(
            "RPC: Rejected session UCAN for user {} (no bunker_pubkey, not server-signed)",
            &user_pubkey[..8]
        );
        return Err(RpcError::Auth(AuthError::InvalidToken));
    };

    if !handler.is_valid() {
        return Err(RpcError::Auth(AuthError::InvalidToken));
    }

    // Insert into cache with BLAKE3(token) as key
    auth_state
        .state
        .http_handler_cache
        .insert(blake3_key, handler.clone())
        .await;

    // Update cache size metric
    METRICS.set_http_rpc_cache_size(auth_state.state.http_handler_cache.entry_count());

    Ok(handler)
}

/// Parse unsigned event from params (first param is the event object)
fn parse_unsigned_event(params: &[JsonValue]) -> Result<UnsignedEvent, RpcError> {
    let event_value = params
        .first()
        .ok_or_else(|| RpcError::InvalidParams("Missing event parameter".into()))?;

    // Handle both string (NIP-46 style) and object (direct JSON) formats
    let unsigned_event: UnsignedEvent = if let Some(event_str) = event_value.as_str() {
        serde_json::from_str(event_str)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid event JSON: {}", e)))?
    } else {
        serde_json::from_value(event_value.clone())
            .map_err(|e| RpcError::InvalidParams(format!("Invalid event format: {}", e)))?
    };

    Ok(unsigned_event)
}

/// Parse encrypt params: [pubkey, plaintext]
fn parse_encrypt_params(params: &[JsonValue]) -> Result<(PublicKey, String), RpcError> {
    let pubkey_hex = params
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::InvalidParams("Missing recipient pubkey parameter".into()))?;

    let plaintext = params
        .get(1)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::InvalidParams("Missing plaintext parameter".into()))?;

    let pubkey = PublicKey::from_hex(pubkey_hex)
        .map_err(|e| RpcError::InvalidParams(format!("Invalid pubkey: {}", e)))?;

    Ok((pubkey, plaintext.to_string()))
}

/// Parse decrypt params: [pubkey, ciphertext]
fn parse_decrypt_params(params: &[JsonValue]) -> Result<(PublicKey, String), RpcError> {
    let pubkey_hex = params
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::InvalidParams("Missing sender pubkey parameter".into()))?;

    let ciphertext = params
        .get(1)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::InvalidParams("Missing ciphertext parameter".into()))?;

    let pubkey = PublicKey::from_hex(pubkey_hex)
        .map_err(|e| RpcError::InvalidParams(format!("Invalid pubkey: {}", e)))?;

    Ok((pubkey, ciphertext.to_string()))
}

/// Parse sign_canonical params: [base64_payload]
fn parse_canonical_payload_params(params: &[JsonValue]) -> Result<Vec<u8>, RpcError> {
    if params.len() != 1 {
        return Err(RpcError::InvalidParams(
            "Expected base64 payload parameter".into(),
        ));
    }

    let encoded = params
        .first()
        .and_then(JsonValue::as_str)
        .ok_or_else(|| RpcError::InvalidParams("Missing base64 payload parameter".into()))?;

    let max_encoded_len = MAX_CREATOR_BINDING_PAYLOAD_BYTES.div_ceil(3) * 4;
    if encoded.len() > max_encoded_len {
        return Err(RpcError::InvalidParams(
            "Creator-binding payload exceeds maximum size".into(),
        ));
    }

    let payload = BASE64_STANDARD
        .decode(encoded)
        .map_err(|e| RpcError::InvalidParams(format!("Invalid base64 payload: {}", e)))?;

    if payload.len() > MAX_CREATOR_BINDING_PAYLOAD_BYTES {
        return Err(RpcError::InvalidParams(
            "Creator-binding payload exceeds maximum size".into(),
        ));
    }

    Ok(payload)
}

struct Nip17WrapBatchParams {
    rumor: UnsignedEvent,
    recipients: Vec<Result<PublicKey, ()>>,
}

/// Parse `[rumor_object, [recipient_pubkey_hex...]]`.
///
/// The shared rumor and recipient-list shape are request-level concerns.
/// Individual malformed recipient entries remain positional per-item errors so
/// valid siblings can still be wrapped without reindexing the response.
fn parse_nip17_wrap_batch_params(params: &[JsonValue]) -> Result<Nip17WrapBatchParams, RpcError> {
    if params.len() != 2 {
        return Err(RpcError::InvalidParams(
            "Expected rumor and recipient list parameters".into(),
        ));
    }

    let rumor_value = params
        .first()
        .filter(|value| value.is_object())
        .ok_or_else(|| RpcError::InvalidParams("Missing rumor object".into()))?;
    let rumor: UnsignedEvent = serde_json::from_value(rumor_value.clone())
        .map_err(|e| RpcError::InvalidParams(format!("Invalid rumor format: {}", e)))?;
    if !matches!(rumor.kind.as_u16(), 14 | 15) {
        return Err(RpcError::InvalidParams(
            "Rumor kind must be 14 or 15".into(),
        ));
    }

    let recipient_values = params
        .get(1)
        .and_then(JsonValue::as_array)
        .ok_or_else(|| RpcError::InvalidParams("Missing recipient list".into()))?;
    if recipient_values.is_empty() {
        return Err(RpcError::InvalidParams("Empty recipient list".into()));
    }
    if recipient_values.len() > MAX_WRAP_BATCH {
        return Err(RpcError::InvalidParams(format!(
            "Maximum {} recipients per batch",
            MAX_WRAP_BATCH
        )));
    }

    let recipients = recipient_values
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or(())
                .and_then(|hex| PublicKey::from_hex(hex).map_err(|_| ()))
        })
        .collect();

    Ok(Nip17WrapBatchParams { rumor, recipients })
}

fn error_slot(code: &str) -> JsonValue {
    serde_json::json!({ "error": code })
}

/// Build ordered, index-aligned gift wraps for one shared rumor.
///
/// Construction is deliberately sequential: a request can contain at most
/// [`MAX_WRAP_BATCH`] recipients, and one in-flight recipient at a time keeps
/// per-request work bounded while preserving duplicate slots.
async fn wrap_gift_wrap_batch(
    handler: &Arc<HttpRpcHandler>,
    rumor: &UnsignedEvent,
    recipients: &[Result<PublicKey, ()>],
) -> Vec<JsonValue> {
    let mut rumor = rumor.clone();
    rumor.ensure_id();
    let plaintext = rumor.as_json();

    let mut results = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let slot = match recipient {
            Err(()) => error_slot("invalid_recipient"),
            Ok(recipient) => match handler
                .nip17_wrap_prevalidated_plaintext(&plaintext, recipient)
                .await
            {
                Ok(gift_wrap) => match serde_json::to_value(gift_wrap) {
                    Ok(event) => serde_json::json!({ "gift_wrap": event }),
                    Err(_) => error_slot("internal"),
                },
                Err(error) => error_slot(error.code()),
            },
        };
        results.push(slot);
    }
    results
}

/// Unwrap a batch of NIP-59 gift wraps into ordered, index-aligned result slots.
///
/// Each slot is `{"rumor": <kind14 unsigned event>, "sender": "<hex>"}` on
/// success or `{"error": "<code>"}` on a per-item failure — one bad gift wrap
/// never fails the batch.
///
/// Every item is fanned out into a [`tokio::task::JoinSet`] so the per-item tasks
/// are tied to THIS request's future: if the client disconnects, dropping the set
/// aborts the still-pending tasks instead of leaving them to decrypt in the
/// background. Abort cannot preempt a per-item `spawn_blocking` closure that has
/// already started — that work is instead bounded, and its blocking-pool slot
/// accounted for, by the global `UNWRAP_CRYPTO_PERMITS` semaphore held inside
/// `HttpRpcHandler::nip17_unwrap`. That same semaphore is the single shared cap on
/// concurrent unwrap crypto, so spawning every item at once only parks cheap async
/// tasks on it and never floods the blocking pool. Results are reassembled by
/// index, so the response stays positionally aligned with the request (NIP-17
/// history is ordered) regardless of completion order.
async fn unwrap_gift_wrap_batch(
    handler: &Arc<HttpRpcHandler>,
    items: &[JsonValue],
) -> Vec<JsonValue> {
    let mut set: tokio::task::JoinSet<(usize, JsonValue)> = tokio::task::JoinSet::new();
    for (idx, item) in items.iter().enumerate() {
        let handler = handler.clone();
        let item = item.clone();
        set.spawn(async move {
            let event: Event = match serde_json::from_value(item) {
                Ok(e) => e,
                Err(_) => return (idx, error_slot("invalid_event")),
            };
            let slot = match handler.nip17_unwrap(event).await {
                Ok(unwrapped) => match serde_json::to_value(&unwrapped.rumor) {
                    Ok(rumor) => serde_json::json!({
                        "rumor": rumor,
                        "sender": unwrapped.sender.to_hex(),
                    }),
                    Err(_) => error_slot("internal"),
                },
                Err(e) => error_slot(e.code()),
            };
            (idx, slot)
        });
    }

    // Pre-fill with internal-error slots so a task that fails to report a result
    // (e.g. a JoinError from a panicked task) still yields a valid, index-aligned
    // slot rather than a hole in the ordered response.
    let mut results = vec![error_slot("internal"); items.len()];
    while let Some(joined) = set.join_next().await {
        if let Ok((idx, slot)) = joined {
            results[idx] = slot;
        }
    }
    results
}

fn log_activity(auth_state: &AuthState, is_oauth: bool, authorization_id: i64) {
    match auth_state
        .state
        .activity_logger
        .record(is_oauth, authorization_id)
    {
        ActivityLogResult::Queued
        | ActivityLogResult::SkippedNonOauth
        | ActivityLogResult::Disabled => {}
        ActivityLogResult::Dropped => {
            METRICS.inc_http_rpc_activity_dropped();
            tracing::warn!("Dropped OAuth authorization activity update because queue is full");
        }
        // The writer should stop after the HTTP drain. If it is already gone,
        // this is a real lost update and not the no-op that a never-configured
        // logger is.
        ActivityLogResult::WriterStopped => {
            METRICS.inc_http_rpc_activity_dropped();
            tracing::warn!(
                "Dropped OAuth authorization activity update because the writer stopped"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature as P256Signature, SigningKey};
    use rand::rngs::OsRng;

    #[test]
    fn cold_path_pool_exhaustion_is_a_retryable_503_without_leaking_detail() {
        use keycast_core::repositories::RepositoryError;

        let unavailable = map_repo_error(
            "loading authorization",
            RepositoryError::Unavailable("pool timed out".into()),
        );
        assert_eq!(http_rpc_outcome(&Err(unavailable)), "unavailable");

        let leaky = map_repo_error(
            "loading authorization",
            RepositoryError::Unavailable("connect to db.internal:5432 refused".into()),
        );
        let body = format!("{:?}", leaky);
        assert!(
            !body.contains("db.internal"),
            "connect-level detail must stay in the log, not the response: {body}"
        );

        let internal = map_repo_error(
            "loading authorization",
            RepositoryError::Database("relation does not exist".into()),
        );
        assert_eq!(http_rpc_outcome(&Err(internal)), "error");
    }

    #[test]
    fn handler_timeout_is_a_504_observed_as_its_own_outcome() {
        let timed_out: Result<Json<NostrRpcResponse>, RpcError> =
            Err(RpcError::Timeout("RPC request timed out after 8s".into()));

        assert_eq!(http_rpc_outcome(&timed_out), "timeout");
        assert_eq!(
            RpcError::Timeout("RPC request timed out after 8s".into())
                .into_response()
                .status(),
            StatusCode::GATEWAY_TIMEOUT
        );
    }

    fn create_test_handler_with_dpop(expected_jkt: Option<String>) -> HttpRpcHandler {
        let keys = Keys::generate();
        let session = Arc::new(SigningSession::new(keys));
        HttpRpcHandler::new(
            session,
            1,
            None,
            None,
            vec![],
            true,
            [0u8; 32],
            [1u8; 32],
            expected_jkt,
        )
    }

    fn create_dpop_proof(signing_key: &SigningKey, method: &str, htu: &str, jti: &str) -> String {
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().expect("x coordinate"));
        let y = URL_SAFE_NO_PAD.encode(point.y().expect("y coordinate"));
        let iat = chrono::Utc::now().timestamp();

        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": x,
                "y": y
            }
        });
        let payload = serde_json::json!({
            "htm": method,
            "htu": htu,
            "iat": iat,
            "jti": jti
        });

        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header json"));
        let payload_b64 =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload json"));
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let signature: P256Signature = signing_key.sign(signing_input.as_bytes());
        let (r_bytes, s_bytes) = signature.split_bytes();
        let mut sig_raw = Vec::with_capacity(64);
        sig_raw.extend_from_slice(&r_bytes);
        sig_raw.extend_from_slice(&s_bytes);
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig_raw);

        format!("{}.{}.{}", header_b64, payload_b64, sig_b64)
    }

    fn thumbprint_for_signing_key(signing_key: &SigningKey) -> String {
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);
        let jwk_map: serde_json::Map<String, serde_json::Value> =
            serde_json::from_value(serde_json::json!({
                "kty": "EC",
                "crv": "P-256",
                "x": URL_SAFE_NO_PAD.encode(point.x().expect("x coordinate")),
                "y": URL_SAFE_NO_PAD.encode(point.y().expect("y coordinate"))
            }))
            .expect("jwk map");

        crate::ucan_auth::dpop::jwk_thumbprint(&jwk_map).expect("jwk thumbprint")
    }

    #[test]
    fn test_parse_unsigned_event_object() {
        let params = vec![serde_json::json!({
            "kind": 1,
            "content": "Hello",
            "tags": [],
            "created_at": 1234567890,
            "pubkey": "0000000000000000000000000000000000000000000000000000000000000000"
        })];

        let result = parse_unsigned_event(&params);
        assert!(result.is_ok());
        let event = result.unwrap();
        assert_eq!(event.kind.as_u16(), 1);
        assert_eq!(event.content, "Hello");
    }

    #[test]
    fn test_parse_unsigned_event_string() {
        let event_str = r#"{"kind":1,"content":"Hello","tags":[],"created_at":1234567890,"pubkey":"0000000000000000000000000000000000000000000000000000000000000000"}"#;
        let params = vec![JsonValue::String(event_str.to_string())];

        let result = parse_unsigned_event(&params);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_encrypt_params() {
        let params = vec![
            JsonValue::String(
                "0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            ),
            JsonValue::String("Hello, world!".to_string()),
        ];

        let result = parse_encrypt_params(&params);
        assert!(result.is_ok());
        let (pubkey, plaintext) = result.unwrap();
        assert_eq!(plaintext, "Hello, world!");
        assert_eq!(
            pubkey.to_hex(),
            "0000000000000000000000000000000000000000000000000000000000000001"
        );
    }

    #[test]
    fn test_parse_encrypt_params_missing_pubkey() {
        let params = vec![];
        let result = parse_encrypt_params(&params);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_encrypt_params_missing_plaintext() {
        let params = vec![JsonValue::String(
            "0000000000000000000000000000000000000000000000000000000000000001".to_string(),
        )];
        let result = parse_encrypt_params(&params);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_canonical_payload_params() {
        let payload = br#"{"version":1}"#;
        let params = vec![JsonValue::String(BASE64_STANDARD.encode(payload))];

        let parsed =
            parse_canonical_payload_params(&params).expect("valid base64 payload should parse");

        assert_eq!(parsed, payload);
    }

    #[test]
    fn test_parse_canonical_payload_params_rejects_invalid_base64() {
        let params = vec![JsonValue::String("***".to_string())];

        let err = parse_canonical_payload_params(&params).expect_err("invalid base64 rejects");

        match err {
            RpcError::InvalidParams(message) => {
                assert!(message.contains("Invalid base64 payload"));
            }
            other => panic!("expected InvalidParams, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_canonical_payload_params_rejects_oversize_payload() {
        let payload = vec![b'a'; MAX_CREATOR_BINDING_PAYLOAD_BYTES + 1];
        let params = vec![JsonValue::String(BASE64_STANDARD.encode(payload))];

        let err = parse_canonical_payload_params(&params).expect_err("oversize payload rejects");

        match err {
            RpcError::InvalidParams(message) => {
                assert!(message.contains("exceeds maximum size"));
            }
            other => panic!("expected InvalidParams, got {other:?}"),
        }
    }

    fn wrap_rumor_value(author: PublicKey, recipient: PublicKey) -> JsonValue {
        let rumor =
            nostr_sdk::EventBuilder::private_msg_rumor(recipient, "batch send").build(author);
        serde_json::to_value(rumor).expect("serialize rumor")
    }

    fn assert_gift_wrap_has_recipient_p_tag(slot: &JsonValue, recipient: &PublicKey) {
        let recipient_hex = recipient.to_hex();
        let tags = slot["gift_wrap"]["tags"]
            .as_array()
            .expect("gift wrap has tags");
        assert!(
            tags.iter().any(|tag| {
                let Some(parts) = tag.as_array() else {
                    return false;
                };
                parts.first().and_then(JsonValue::as_str) == Some("p")
                    && parts.get(1).and_then(JsonValue::as_str) == Some(recipient_hex.as_str())
            }),
            "gift wrap must include recipient p tag"
        );
    }

    #[test]
    fn parse_wrap_batch_accepts_shared_rumor_and_preserves_recipient_slots() {
        let sender = Keys::generate();
        let receiver = Keys::generate();
        let receiver_hex = receiver.public_key().to_hex();
        let params = vec![
            wrap_rumor_value(sender.public_key(), receiver.public_key()),
            serde_json::json!([receiver_hex, "not-a-pubkey", receiver.public_key().to_hex()]),
        ];

        let parsed = parse_nip17_wrap_batch_params(&params).expect("valid batch shape");

        assert_eq!(parsed.rumor.pubkey, sender.public_key());
        assert_eq!(parsed.recipients.len(), 3);
        assert_eq!(
            parsed.recipients[0].as_ref().expect("valid recipient"),
            &receiver.public_key()
        );
        assert!(parsed.recipients[1].is_err());
        assert_eq!(
            parsed.recipients[2].as_ref().expect("duplicate recipient"),
            &receiver.public_key()
        );
    }

    #[test]
    fn parse_wrap_batch_rejects_empty_and_over_cap_recipient_lists() {
        let sender = Keys::generate();
        let receiver = Keys::generate();
        let rumor = wrap_rumor_value(sender.public_key(), receiver.public_key());

        let empty = parse_nip17_wrap_batch_params(&[rumor.clone(), serde_json::json!([])]);
        assert!(matches!(empty, Err(RpcError::InvalidParams(_))));

        let recipients = vec![receiver.public_key().to_hex(); MAX_WRAP_BATCH + 1];
        let over_cap =
            parse_nip17_wrap_batch_params(&[rumor, serde_json::to_value(recipients).unwrap()]);
        assert!(matches!(over_cap, Err(RpcError::InvalidParams(_))));
    }

    #[test]
    fn parse_wrap_batch_rejects_malformed_or_non_nip17_rumor() {
        let malformed = parse_nip17_wrap_batch_params(&[
            serde_json::json!({ "kind": 14 }),
            serde_json::json!(["not-a-pubkey"]),
        ]);
        assert!(matches!(malformed, Err(RpcError::InvalidParams(_))));

        let sender = Keys::generate();
        let receiver = Keys::generate();
        let note = nostr_sdk::EventBuilder::text_note("not a rumor").build(sender.public_key());
        let wrong_kind = parse_nip17_wrap_batch_params(&[
            serde_json::to_value(note).unwrap(),
            serde_json::json!([receiver.public_key().to_hex()]),
        ]);
        assert!(matches!(wrong_kind, Err(RpcError::InvalidParams(_))));
    }

    #[test]
    fn test_rpc_response_success() {
        let response = NostrRpcResponse::success(JsonValue::String("test".to_string()));
        assert!(response.result.is_some());
        assert!(response.error.is_none());
    }

    #[test]
    fn test_rpc_response_error() {
        let response = NostrRpcResponse::error("test error");
        assert!(response.result.is_none());
        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap(), "test error");
    }

    #[test]
    fn test_map_dpop_error_to_rpc_error_replay_cache_unavailable_is_internal() {
        let error = anyhow::Error::new(crate::ucan_auth::dpop::ReplayCacheUnavailableError::new(
            "DPoP replay protection unavailable",
        ));
        let mapped = map_dpop_error_to_rpc_error(error, "test");
        assert!(matches!(mapped, RpcError::Internal(_)));
    }

    #[test]
    fn test_map_dpop_error_to_rpc_error_invalid_proof_is_auth_error() {
        let mapped = map_dpop_error_to_rpc_error(anyhow::anyhow!("invalid dpop proof"), "test");
        assert!(matches!(mapped, RpcError::Auth(AuthError::InvalidToken)));
    }

    #[tokio::test]
    async fn test_cache_hit_dpop_bound_missing_proof_rejected() {
        let handler = create_test_handler_with_dpop(Some("expected-thumbprint".to_string()));
        let headers = HeaderMap::new();

        let result =
            enforce_cached_dpop_binding(&handler, &headers, "https://example.com/api/nostr").await;
        assert!(matches!(
            result,
            Err(RpcError::Auth(AuthError::InvalidToken))
        ));
    }

    #[tokio::test]
    async fn test_cache_hit_dpop_unbound_missing_proof_allowed() {
        let handler = create_test_handler_with_dpop(None);
        let headers = HeaderMap::new();

        let result =
            enforce_cached_dpop_binding(&handler, &headers, "https://example.com/api/nostr").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_cache_hit_dpop_bound_valid_proof_allowed() {
        let signing_key = SigningKey::random(&mut OsRng);
        let expected_jkt = thumbprint_for_signing_key(&signing_key);
        let handler = create_test_handler_with_dpop(Some(expected_jkt));
        let htu = "https://example.com/api/nostr";
        let proof = create_dpop_proof(
            &signing_key,
            "POST",
            htu,
            &format!("cache-hit-jti-{}", uuid::Uuid::new_v4()),
        );

        let mut headers = HeaderMap::new();
        headers.insert("DPoP", proof.parse().expect("valid header value"));

        let result = enforce_cached_dpop_binding(&handler, &headers, htu).await;
        assert!(result.is_ok());
    }

    /// Build a kind:1059 gift wrap (from `sender` to `receiver`) carrying a kind:14
    /// DM rumor with the given text, serialized to its JSON event value.
    async fn gift_wrap_value(sender: &Keys, receiver: &PublicKey, text: &str) -> JsonValue {
        let rumor =
            nostr_sdk::EventBuilder::private_msg_rumor(*receiver, text).build(sender.public_key());
        let wrap = nostr_sdk::EventBuilder::gift_wrap(
            sender,
            receiver,
            rumor,
            Vec::<nostr_sdk::Tag>::new(),
        )
        .await
        .expect("gift wrap should build");
        serde_json::to_value(&wrap).expect("serialize gift wrap")
    }

    /// `unwrap_gift_wrap_batch` fans every item out concurrently and reassembles
    /// results by index. The integration ordering test uses only 4 items, so this
    /// drives a full `MAX_UNWRAP_BATCH` page through the function directly and
    /// asserts every slot's content + authenticated sender stays index-aligned
    /// with the request regardless of completion order.
    #[tokio::test]
    async fn unwrap_gift_wrap_batch_preserves_order() {
        let handler = Arc::new(create_test_handler_with_dpop(None));
        let receiver = handler.public_key();

        // A full page (100), larger than the global unwrap crypto-permit pool, so
        // items queue on the semaphore and complete out of order — exercising both
        // the permit-queueing path and the index-reassembly that re-orders them.
        const N: usize = MAX_UNWRAP_BATCH;
        let mut senders = Vec::with_capacity(N);
        let mut items = Vec::with_capacity(N);
        for i in 0..N {
            let sender = Keys::generate();
            items.push(gift_wrap_value(&sender, &receiver, &format!("ordered message {i}")).await);
            senders.push(sender);
        }

        let results = unwrap_gift_wrap_batch(&handler, &items).await;
        assert_eq!(results.len(), N, "one ordered slot per input");

        for (i, slot) in results.iter().enumerate() {
            assert!(
                slot.get("error").is_none(),
                "slot {i} should succeed, got {slot:?}"
            );
            assert_eq!(
                slot["rumor"]["content"].as_str().unwrap(),
                format!("ordered message {i}"),
                "content out of order at slot {i}"
            );
            assert_eq!(
                slot["sender"].as_str().unwrap(),
                senders[i].public_key().to_hex(),
                "authenticated sender out of order at slot {i}"
            );
        }
    }

    #[tokio::test]
    async fn wrap_gift_wrap_batch_preserves_order_duplicates_and_partial_errors() {
        let handler = Arc::new(create_test_handler_with_dpop(None));
        let receiver_a = Keys::generate();
        let receiver_b = Keys::generate();
        let rumor = nostr_sdk::EventBuilder::private_msg_rumor(
            receiver_a.public_key(),
            "ordered batch send",
        )
        .build(handler.public_key());
        let recipients = vec![
            Ok(receiver_a.public_key()),
            Err(()),
            Ok(receiver_b.public_key()),
            Ok(receiver_a.public_key()),
        ];

        let results = wrap_gift_wrap_batch(&handler, &rumor, &recipients).await;

        assert_eq!(results.len(), recipients.len());
        assert_eq!(results[1]["error"].as_str(), Some("invalid_recipient"));
        for (idx, receiver) in [
            (0usize, &receiver_a),
            (2usize, &receiver_b),
            (3usize, &receiver_a),
        ] {
            assert_gift_wrap_has_recipient_p_tag(&results[idx], &receiver.public_key());
            let wrap: Event = serde_json::from_value(results[idx]["gift_wrap"].clone())
                .expect("successful slot contains an event");
            let unwrapped = nostr_sdk::nips::nip59::UnwrappedGift::from_gift_wrap(receiver, &wrap)
                .await
                .expect("intended recipient unwraps");
            assert_eq!(unwrapped.sender, handler.public_key());
            assert_eq!(unwrapped.rumor.content, "ordered batch send");
        }
        assert_ne!(
            results[0]["gift_wrap"]["id"], results[3]["gift_wrap"]["id"],
            "duplicate recipients get distinct ephemeral outer wraps"
        );
    }
}
