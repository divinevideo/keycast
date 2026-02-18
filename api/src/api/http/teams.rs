use crate::api::types::*;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use secrecy::ExposeSecret;

use nostr_sdk::prelude::*;

use sqlx::PgPool;

use crate::api::error::{ApiError, ApiResult};
use crate::api::extractors::UcanAuth;
use crate::state::{get_key_manager, get_secret_pool};
use keycast_core::custom_permissions::{allowed_kinds::AllowedKindsConfig, AVAILABLE_PERMISSIONS};
use keycast_core::repositories::{
    AuthorizationRepository, PolicyRepository, StoredKeyRepository, TeamRepository, UserRepository,
};
use keycast_core::types::authorization::{Authorization, AuthorizationWithRelations};
use keycast_core::types::policy::PolicyWithPermissions;
use keycast_core::types::stored_key::PublicStoredKey;
use keycast_core::types::team::{KeyWithRelations, Team, TeamWithRelations};
use keycast_core::types::user::TeamUser;

pub async fn list_teams(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    UcanAuth {
        pubkey: user_pubkey_hex,
        ..
    }: UcanAuth,
) -> ApiResult<Json<Vec<TeamWithRelations>>> {
    let tenant_id = tenant.0.id;

    let user_pubkey = PublicKey::from_hex(&user_pubkey_hex)
        .map_err(|_| ApiError::bad_request("Invalid pubkey"))?;

    let user_repo = UserRepository::new(pool.clone());
    let user = user_repo
        .find_by_pubkey(tenant_id, &user_pubkey)
        .await
        .map_err(|_| ApiError::not_found("User not found"))?;

    let teams_with_relations = user.teams(&pool, tenant_id).await?;

    Ok(Json(teams_with_relations))
}

pub async fn create_team(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    auth: UcanAuth,
    Json(request): Json<CreateTeamRequest>,
) -> ApiResult<Json<TeamWithRelations>> {
    let tenant_id = tenant.0.id;
    let user_pubkey_hex = &auth.pubkey;

    // Check admin access for team creation
    if !super::admin::is_full_admin(&auth) {
        tracing::warn!(
            "Team creation denied for non-admin pubkey: {}",
            user_pubkey_hex
        );
        return Err(ApiError::forbidden(
            "Team creation is restricted to authorized users. Contact admin for access.",
        ));
    }

    let allowed_kinds_config = serde_json::to_value(AllowedKindsConfig::default())
        .map_err(|_| ApiError::bad_request("Couldn't serialize allowed kinds config"))?;

    let team_repo = TeamRepository::new(pool.clone());
    let team_with_relations = team_repo
        .create_with_admin(
            tenant_id,
            &request.name,
            user_pubkey_hex,
            allowed_kinds_config,
        )
        .await?;

    Ok(Json(team_with_relations))
}

pub async fn get_team(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    UcanAuth {
        pubkey: user_pubkey_hex,
        ..
    }: UcanAuth,
    Path(team_id): Path<i32>,
) -> ApiResult<Json<TeamWithRelations>> {
    let tenant_id = tenant.0.id;
    verify_admin(&pool, &user_pubkey_hex, team_id, tenant_id).await?;

    let team_repo = TeamRepository::new(pool.clone());
    let team_with_relations = team_repo
        .find_with_relations(tenant_id, team_id)
        .await
        .map_err(|_| ApiError::not_found("Team not found"))?;

    Ok(Json(team_with_relations))
}

pub async fn update_team(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    UcanAuth {
        pubkey: user_pubkey_hex,
        ..
    }: UcanAuth,
    Json(request): Json<UpdateTeamRequest>,
) -> ApiResult<Json<Team>> {
    let tenant_id = tenant.0.id;
    verify_admin(&pool, &user_pubkey_hex, request.id, tenant_id).await?;

    let team_repo = TeamRepository::new(pool.clone());
    let team = team_repo
        .update(tenant_id, request.id, &request.name)
        .await
        .map_err(|_| ApiError::not_found("Team not found"))?;

    Ok(Json(team))
}

pub async fn delete_team(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    UcanAuth {
        pubkey: user_pubkey_hex,
        ..
    }: UcanAuth,
    Path(team_id): Path<i32>,
) -> ApiResult<StatusCode> {
    let tenant_id = tenant.0.id;
    verify_admin(&pool, &user_pubkey_hex, team_id, tenant_id).await?;

    let team_repo = TeamRepository::new(pool.clone());
    team_repo
        .delete(tenant_id, team_id)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to delete team: {}", e)))?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn add_user(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    UcanAuth {
        pubkey: user_pubkey_hex,
        ..
    }: UcanAuth,
    Path(team_id): Path<i32>,
    Json(request): Json<AddTeammateRequest>,
) -> ApiResult<Json<TeamUser>> {
    let tenant_id = tenant.0.id;
    verify_admin(&pool, &user_pubkey_hex, team_id, tenant_id).await?;

    let new_user_pubkey = PublicKey::from_hex(&request.user_pubkey)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;

    let user_repo = UserRepository::new(pool.clone());
    let team_repo = TeamRepository::new(pool.clone());

    // Verify the user isn't already a member of the team
    if team_repo
        .is_member(team_id, &new_user_pubkey.to_hex())
        .await?
    {
        return Err(ApiError::BadRequest(
            "User already a member of this team".to_string(),
        ));
    }

    // Ensure user exists (creates if not)
    user_repo
        .find_or_create(tenant_id, &new_user_pubkey)
        .await?;

    // Add the team membership
    let team_user = team_repo
        .add_member(team_id, &new_user_pubkey.to_hex(), request.role.as_str())
        .await?;

    Ok(Json(team_user))
}

pub async fn remove_user(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    UcanAuth {
        pubkey: user_pubkey_hex,
        ..
    }: UcanAuth,
    Path((team_id, user_pubkey)): Path<(i32, String)>,
) -> ApiResult<StatusCode> {
    let tenant_id = tenant.0.id;
    verify_admin(&pool, &user_pubkey_hex, team_id, tenant_id).await?;

    let removed_user_pubkey =
        PublicKey::from_hex(&user_pubkey).map_err(|e| ApiError::bad_request(e.to_string()))?;

    let team_repo = TeamRepository::new(pool.clone());

    // Check if the user is deleting themselves
    if user_pubkey_hex == removed_user_pubkey.to_hex() {
        // At least one admin has to remain in the team
        let remaining_admin_count = team_repo
            .count_other_admins(team_id, &removed_user_pubkey.to_hex())
            .await?;

        if remaining_admin_count == 0 {
            return Err(ApiError::forbidden(
                "Cannot delete the last admin from the team.",
            ));
        }
    }

    // Remove the team membership
    team_repo
        .remove_member(team_id, &removed_user_pubkey.to_hex())
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn add_key(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    UcanAuth {
        pubkey: user_pubkey_hex,
        ..
    }: UcanAuth,
    Path(team_id): Path<i32>,
    Json(request): Json<AddKeyRequest>,
) -> ApiResult<Json<PublicStoredKey>> {
    let tenant_id = tenant.0.id;
    verify_admin(&pool, &user_pubkey_hex, team_id, tenant_id).await?;

    let keys =
        Keys::parse(&request.secret_key).map_err(|e| ApiError::bad_request(e.to_string()))?;

    // Encrypt the secret key
    let key_manager = get_key_manager().map_err(|e| ApiError::internal(e.to_string()))?;
    let encrypted_secret = key_manager
        .encrypt(keys.secret_key().as_secret_bytes())
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;

    let key_repo = StoredKeyRepository::new(pool.clone());
    let key = key_repo
        .create(
            tenant_id,
            team_id,
            &request.name,
            &keys.public_key().to_hex(),
            &encrypted_secret,
        )
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(Json(key.into()))
}

pub async fn remove_key(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    UcanAuth {
        pubkey: user_pubkey_hex,
        ..
    }: UcanAuth,
    Path((team_id, pubkey)): Path<(i32, String)>,
) -> ApiResult<StatusCode> {
    let tenant_id = tenant.0.id;
    verify_admin(&pool, &user_pubkey_hex, team_id, tenant_id).await?;

    let removed_stored_key_public_key =
        PublicKey::from_hex(&pubkey).map_err(|e| ApiError::bad_request(e.to_string()))?;

    let key_repo = StoredKeyRepository::new(pool.clone());
    key_repo
        .delete_by_pubkey(tenant_id, team_id, &removed_stored_key_public_key.to_hex())
        .await
        .map_err(|_| ApiError::not_found("Key not found"))?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_key(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    UcanAuth {
        pubkey: user_pubkey_hex,
        ..
    }: UcanAuth,
    Path((team_id, pubkey)): Path<(i32, String)>,
) -> ApiResult<Json<KeyWithRelations>> {
    let tenant_id = tenant.0.id;
    verify_admin(&pool, &user_pubkey_hex, team_id, tenant_id).await?;

    let stored_key_public_key =
        PublicKey::from_hex(&pubkey).map_err(|e| ApiError::bad_request(e.to_string()))?;

    let team_repo = TeamRepository::new(pool.clone());
    let key_repo = StoredKeyRepository::new(pool.clone());
    let policy_repo = PolicyRepository::new(pool.clone());
    let auth_repo = AuthorizationRepository::new(pool.clone());

    let team = team_repo
        .find(tenant_id, team_id)
        .await
        .map_err(|_| ApiError::not_found("Team not found"))?;

    let stored_key = key_repo
        .find_by_pubkey(tenant_id, team_id, &stored_key_public_key.to_hex())
        .await
        .map_err(|_| ApiError::not_found("Stored key not found"))?;

    let authorizations = auth_repo
        .find_by_stored_key(tenant_id, stored_key.id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    let mut complete_authorizations = Vec::new();

    for auth in authorizations {
        let policy = policy_repo
            .find(auth.policy_id)
            .await
            .map_err(|_| ApiError::not_found("Policy not found"))?;

        complete_authorizations.push(AuthorizationWithRelations {
            authorization: auth.clone(),
            policy,
            // bunker URL is only available at creation time (secret is now hashed)
            bunker_connection_string: None,
        });
    }

    Ok(Json(KeyWithRelations {
        team,
        stored_key: stored_key.into(),
        authorizations: complete_authorizations,
    }))
}

pub async fn add_authorization(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    UcanAuth {
        pubkey: user_pubkey_hex,
        ..
    }: UcanAuth,
    Path((team_id, pubkey)): Path<(i32, String)>,
    Json(request): Json<AddAuthorizationRequest>,
) -> ApiResult<Json<AuthorizationCreatedResponse>> {
    let tenant_id = tenant.0.id;
    verify_admin(&pool, &user_pubkey_hex, team_id, tenant_id).await?;

    let stored_key_public_key =
        PublicKey::from_hex(&pubkey).map_err(|e| ApiError::bad_request(e.to_string()))?;

    let key_repo = StoredKeyRepository::new(pool.clone());
    let policy_repo = PolicyRepository::new(pool.clone());
    let auth_repo = AuthorizationRepository::new(pool.clone());

    let stored_key = key_repo
        .find_by_pubkey(tenant_id, team_id, &stored_key_public_key.to_hex())
        .await
        .map_err(|_| ApiError::not_found("Stored key not found"))?;

    // Verify policy exists and belongs to this team
    if !policy_repo
        .exists_for_team(team_id, request.policy_id)
        .await?
    {
        return Err(ApiError::not_found("Policy not found"));
    }

    // Get pre-computed (secret, hash) from pool - instant, no waiting for bcrypt
    let secret_pool = get_secret_pool().map_err(|e| ApiError::internal(e.to_string()))?;
    let secret_pair = secret_pool
        .get()
        .await
        .ok_or_else(|| ApiError::internal("Secret pool exhausted".to_string()))?;
    let connection_secret = secret_pair.secret;
    let secret_hash = secret_pair.hash;

    // Derive bunker keys from stored_key secret using HKDF with secret_hash as entropy
    // This avoids an extra KMS call at runtime - the signer can re-derive using the same inputs
    let key_manager = get_key_manager().map_err(|e| ApiError::internal(e.to_string()))?;
    let decrypted_stored_key = key_manager
        .decrypt(&stored_key.secret_key)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to decrypt stored key: {}", e)))?;
    let stored_key_secret = nostr_sdk::SecretKey::from_slice(&decrypted_stored_key)
        .map_err(|e| ApiError::internal(format!("Invalid stored key: {}", e)))?;
    let bunker_keys =
        keycast_core::bunker_key::derive_bunker_keys(&stored_key_secret, &secret_hash);

    let relays =
        serde_json::to_value(&request.relays).map_err(|e| ApiError::bad_request(e.to_string()))?;

    // Create authorization
    let authorization = auth_repo
        .create(
            tenant_id,
            stored_key.id,
            request.policy_id,
            &secret_hash,
            &bunker_keys.public_key().to_hex(),
            &relays,
            request.max_uses,
            request.expires_at,
            request.label.as_deref(),
        )
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    // Generate bunker URL - only available at creation time (secret is hashed for storage)
    let bunker_url = Authorization::generate_bunker_url(
        &bunker_keys.public_key().to_hex(),
        connection_secret.expose_secret(),
    );

    Ok(Json(AuthorizationCreatedResponse {
        authorization,
        bunker_url,
    }))
}

pub async fn delete_authorization(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    UcanAuth {
        pubkey: user_pubkey_hex,
        ..
    }: UcanAuth,
    Path((team_id, pubkey, auth_id)): Path<(i32, String, i32)>,
) -> ApiResult<StatusCode> {
    let tenant_id = tenant.0.id;
    verify_admin(&pool, &user_pubkey_hex, team_id, tenant_id).await?;

    let stored_key_public_key =
        PublicKey::from_hex(&pubkey).map_err(|e| ApiError::bad_request(e.to_string()))?;

    let key_repo = StoredKeyRepository::new(pool.clone());
    let auth_repo = AuthorizationRepository::new(pool.clone());

    // Verify stored key exists and belongs to this team
    let stored_key = key_repo
        .find_by_pubkey(tenant_id, team_id, &stored_key_public_key.to_hex())
        .await
        .map_err(|_| ApiError::not_found("Stored key not found"))?;

    // Delete the authorization
    let deleted = auth_repo
        .delete_for_stored_key(tenant_id, auth_id, stored_key.id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    if !deleted {
        return Err(ApiError::not_found("Authorization not found"));
    }

    Ok(StatusCode::NO_CONTENT)
}

pub async fn add_policy(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    UcanAuth {
        pubkey: user_pubkey_hex,
        ..
    }: UcanAuth,
    Path(team_id): Path<i32>,
    Json(request): Json<CreatePolicyRequest>,
) -> ApiResult<Json<PolicyWithPermissions>> {
    let tenant_id = tenant.0.id;
    verify_admin(&pool, &user_pubkey_hex, team_id, tenant_id).await?;

    // Filter to valid permission identifiers
    let permission_configs: Vec<(String, serde_json::Value)> = request
        .permissions
        .into_iter()
        .filter(|p| {
            if AVAILABLE_PERMISSIONS.contains(&p.identifier.as_str()) {
                true
            } else {
                tracing::warn!("Skipping unknown permission identifier: {}", p.identifier);
                false
            }
        })
        .map(|p| (p.identifier, p.config))
        .collect();

    let policy_repo = PolicyRepository::new(pool.clone());
    let policy_with_permissions = policy_repo
        .create_with_permissions(team_id, &request.name, permission_configs)
        .await?;

    Ok(Json(policy_with_permissions))
}

pub async fn verify_admin<'a>(
    pool: &'a PgPool,
    pubkey_hex: &'a str,
    team_id: i32,
    tenant_id: i64,
) -> ApiResult<()> {
    let pubkey =
        PublicKey::from_hex(pubkey_hex).map_err(|_| ApiError::bad_request("Invalid pubkey"))?;

    let user_repo = UserRepository::new(pool.clone());
    match user_repo.is_team_admin(tenant_id, &pubkey, team_id).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(ApiError::forbidden(
            "You are not authorized to access this team",
        )),
        Err(_) => Err(ApiError::auth("Failed to verify admin status")),
    }
}
