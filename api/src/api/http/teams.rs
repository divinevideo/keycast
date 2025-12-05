use crate::api::types::*;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};

use nostr_sdk::prelude::*;

use sqlx::PgPool;

use crate::api::error::{ApiError, ApiResult};
use crate::api::extractors::UcanAuth;
use crate::state::get_key_manager;
use keycast_core::custom_permissions::{allowed_kinds::AllowedKindsConfig, AVAILABLE_PERMISSIONS};
use keycast_core::types::authorization::{
    Authorization, AuthorizationWithRelations, UserAuthorization,
};
use keycast_core::types::permission::{Permission, PolicyPermission};
use keycast_core::types::policy::{Policy, PolicyWithPermissions};
use keycast_core::types::stored_key::{PublicStoredKey, StoredKey};
use keycast_core::types::team::{KeyWithRelations, Team, TeamWithRelations};
use keycast_core::types::user::{TeamUser, User};

pub async fn list_teams(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    UcanAuth(user_pubkey_hex): UcanAuth,
) -> ApiResult<Json<Vec<TeamWithRelations>>> {
    let tenant_id = tenant.0.id;

    let user_pubkey = PublicKey::from_hex(&user_pubkey_hex)
        .map_err(|_| ApiError::bad_request("Invalid pubkey"))?;

    let user = match User::find_by_pubkey(&pool, tenant_id, &user_pubkey).await {
        Ok(user) => user,
        Err(_) => {
            return Err(ApiError::not_found("User not found"));
        }
    };

    let teams_with_relations = user.teams(&pool, tenant_id).await?;

    Ok(Json(teams_with_relations))
}

pub async fn create_team(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    UcanAuth(user_pubkey_hex): UcanAuth,
    Json(request): Json<CreateTeamRequest>,
) -> ApiResult<Json<TeamWithRelations>> {
    let tenant_id = tenant.0.id;

    // Check whitelist for team creation (if configured)
    if let Ok(allowed_pubkeys) = std::env::var("ALLOWED_PUBKEYS") {
        if !allowed_pubkeys.is_empty() {
            let allowed: Vec<&str> = allowed_pubkeys.split(',').map(|s| s.trim()).collect();

            if !allowed.contains(&user_pubkey_hex.as_str()) {
                tracing::warn!(
                    "Team creation denied for non-whitelisted pubkey: {}",
                    user_pubkey_hex
                );
                return Err(ApiError::forbidden(
                    "Team creation is restricted to authorized users. Contact admin for access.",
                ));
            }

            tracing::info!(
                "Team creation authorized for whitelisted pubkey: {}",
                user_pubkey_hex
            );
        }
    }

    let mut tx = pool.begin().await?;

    // First, try to insert the user if they don't exist
    sqlx::query(
        r#"
            INSERT INTO users (tenant_id, pubkey, created_at, updated_at)
            VALUES ($1, $2, NOW(), NOW())
            ON CONFLICT (pubkey) DO NOTHING
            "#,
    )
    .bind(tenant_id)
    .bind(&user_pubkey_hex)
    .execute(&mut *tx)
    .await?;

    // Then, insert the team
    let team = sqlx::query_as::<_, Team>(
        r#"
            INSERT INTO teams (tenant_id, name, created_at, updated_at)
            VALUES ($1, $2, NOW(), NOW())
            RETURNING *
            "#,
    )
    .bind(tenant_id)
    .bind(request.name)
    .fetch_one(&mut *tx)
    .await?;

    // Then, create the team_user relationship with admin role
    let team_user = sqlx::query_as::<_, TeamUser>(
        r#"
            INSERT INTO team_users (team_id, user_pubkey, role, created_at, updated_at)
            VALUES ($1, $2, 'admin', NOW(), NOW())
            RETURNING *
            "#,
    )
    .bind(team.id)
    .bind(&user_pubkey_hex)
    .fetch_one(&mut *tx)
    .await?;

    // Create a default policy for the team (all permissions allowed)
    let policy = sqlx::query_as::<_, Policy>(
        r#"
            INSERT INTO policies (team_id, name, created_at, updated_at)
            VALUES ($1, 'All Access', NOW(), NOW())
            RETURNING *
            "#,
    )
    .bind(team.id)
    .fetch_one(&mut *tx)
    .await?;

    let allowed_kinds_config = serde_json::to_value(AllowedKindsConfig::default())
        .map_err(|_| ApiError::bad_request("Couldn't serialize allowed kinds config"))?;

    let permission = sqlx::query_as::<_, Permission>(
        r#"
            INSERT INTO permissions (identifier, config, created_at, updated_at)
            VALUES ('allowed_kinds', $1, NOW(), NOW())
            RETURNING *
            "#,
    )
    .bind(allowed_kinds_config)
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query_as::<_, PolicyPermission>(
        r#"
            INSERT INTO policy_permissions (policy_id, permission_id, created_at, updated_at)
            VALUES ($1, $2, NOW(), NOW())
            RETURNING *
            "#,
    )
    .bind(policy.id)
    .bind(permission.id)
    .fetch_one(&mut *tx)
    .await?;

    let policy_with_permissions = PolicyWithPermissions {
        policy,
        permissions: vec![permission],
    };

    // Commit the transaction
    tx.commit().await?;

    Ok(Json(TeamWithRelations {
        team,
        team_users: vec![team_user],
        stored_keys: vec![],
        policies: vec![policy_with_permissions],
    }))
}

pub async fn get_team(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    UcanAuth(user_pubkey_hex): UcanAuth,
    Path(team_id): Path<i32>,
) -> ApiResult<Json<TeamWithRelations>> {
    let tenant_id = tenant.0.id;
    verify_admin(&pool, &user_pubkey_hex, team_id, tenant_id).await?;

    let team_with_relations = Team::find_with_relations(&pool, tenant_id, team_id).await?;

    Ok(Json(team_with_relations))
}

pub async fn update_team(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    UcanAuth(user_pubkey_hex): UcanAuth,
    Json(request): Json<UpdateTeamRequest>,
) -> ApiResult<Json<Team>> {
    let tenant_id = tenant.0.id;
    verify_admin(&pool, &user_pubkey_hex, request.id, tenant_id).await?;

    let mut tx = pool.begin().await?;

    let team = sqlx::query_as::<_, Team>(
        r#"
        UPDATE teams SET name = $1 WHERE tenant_id = $2 AND id = $3
        RETURNING *
        "#,
    )
    .bind(request.name)
    .bind(tenant_id)
    .bind(request.id)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Json(team))
}

pub async fn delete_team(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    UcanAuth(user_pubkey_hex): UcanAuth,
    Path(team_id): Path<i32>,
) -> ApiResult<StatusCode> {
    let tenant_id = tenant.0.id;
    verify_admin(&pool, &user_pubkey_hex, team_id, tenant_id).await?;

    let mut tx = pool.begin().await?;

    // Delete order is important to avoid foreign key constraints

    // Delete user_authorizations for all authorizations linked to stored keys in this team
    sqlx::query(
        r#"
            DELETE FROM user_authorizations
            WHERE authorization_id IN (
                SELECT a.id
                FROM authorizations a
                JOIN stored_keys sk ON a.stored_key_id = sk.id
                WHERE a.tenant_id = $1 AND sk.tenant_id = $1 AND sk.team_id = $2
            )
            "#,
    )
    .bind(tenant_id)
    .bind(team_id)
    .execute(&mut *tx)
    .await?;

    // Delete authorizations for all stored keys in this team
    sqlx::query(
        r#"
            DELETE FROM authorizations
            WHERE tenant_id = $1 AND stored_key_id IN (
                SELECT id FROM stored_keys WHERE tenant_id = $1 AND team_id = $2
            )
            "#,
    )
    .bind(tenant_id)
    .bind(team_id)
    .execute(&mut *tx)
    .await?;

    // Delete stored keys for this team
    sqlx::query("DELETE FROM stored_keys WHERE tenant_id = $1 AND team_id = $2")
        .bind(tenant_id)
        .bind(team_id)
        .execute(&mut *tx)
        .await?;

    // Delete policy_permissions for all policies in this team
    sqlx::query(
        r#"
            DELETE FROM policy_permissions
            WHERE policy_id IN (
                SELECT id FROM policies WHERE team_id = $1
            )
            "#,
    )
    .bind(team_id)
    .execute(&mut *tx)
    .await?;

    // Delete permissions that were associated with this team's policies
    sqlx::query(
        r#"
            DELETE FROM permissions
            WHERE id IN (
                SELECT permission_id
                FROM policy_permissions
                WHERE policy_id IN (
                    SELECT id FROM policies WHERE team_id = $1
                )
            )
            "#,
    )
    .bind(team_id)
    .execute(&mut *tx)
    .await?;

    // Delete policies for this team
    sqlx::query("DELETE FROM policies WHERE team_id = $1")
        .bind(team_id)
        .execute(&mut *tx)
        .await?;

    // Delete team_users
    sqlx::query("DELETE FROM team_users WHERE team_id = $1")
        .bind(team_id)
        .execute(&mut *tx)
        .await?;

    // Finally delete the team
    sqlx::query("DELETE FROM teams WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(team_id)
        .execute(&mut *tx)
        .await?;

    // Commit the transaction
    tx.commit().await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn add_user(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    UcanAuth(user_pubkey_hex): UcanAuth,
    Path(team_id): Path<i32>,
    Json(request): Json<AddTeammateRequest>,
) -> ApiResult<Json<TeamUser>> {
    let tenant_id = tenant.0.id;
    verify_admin(&pool, &user_pubkey_hex, team_id, tenant_id).await?;

    let mut tx = pool.begin().await?;

    let new_user_pubkey = PublicKey::from_hex(&request.user_pubkey)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;

    // Verify the user isn't already a member of the team
    if sqlx::query_as::<_, TeamUser>(
        r#"
        SELECT * FROM team_users WHERE team_id = $1 AND user_pubkey = $2
        "#,
    )
    .bind(team_id)
    .bind(new_user_pubkey.to_hex())
    .fetch_optional(&mut *tx)
    .await?
    .is_some()
    {
        return Err(ApiError::BadRequest(
            "User already a member of this team".to_string(),
        ));
    }

    // First, try to insert the user if they don't exist
    sqlx::query(
        r#"
        INSERT INTO users (tenant_id, pubkey, created_at, updated_at)
        VALUES ($1, $2, NOW(), NOW())
        ON CONFLICT (pubkey) DO NOTHING
        "#,
    )
    .bind(tenant_id)
    .bind(new_user_pubkey.to_hex())
    .execute(&mut *tx)
    .await?;

    // Then, insert the team_user relationship
    let team_user = sqlx::query_as::<_, TeamUser>(
        r#"
        INSERT INTO team_users (team_id, user_pubkey, role, created_at, updated_at)
        VALUES ($1, $2, $3, NOW(), NOW())
        RETURNING *
        "#,
    )
    .bind(team_id)
    .bind(new_user_pubkey.to_hex())
    .bind(request.role)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Json(team_user))
}

pub async fn remove_user(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    UcanAuth(user_pubkey_hex): UcanAuth,
    Path((team_id, user_pubkey)): Path<(i32, String)>,
) -> ApiResult<StatusCode> {
    let tenant_id = tenant.0.id;
    verify_admin(&pool, &user_pubkey_hex, team_id, tenant_id).await?;

    let mut tx = pool.begin().await?;

    let removed_user_pubkey =
        PublicKey::from_hex(&user_pubkey).map_err(|e| ApiError::bad_request(e.to_string()))?;

    // Check if the user is deleting themselves
    if user_pubkey_hex == removed_user_pubkey.to_hex() {
        // At least one admin has to remain in the team
        let remaining_admin_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM team_users WHERE team_id = $1 AND user_pubkey != $2 AND role = 'admin'")
            .bind(team_id)
            .bind(removed_user_pubkey.to_hex())
            .fetch_one(&mut *tx)
            .await?;

        if remaining_admin_count == 0 {
            return Err(ApiError::forbidden(
                "Cannot delete the last admin from the team.",
            ));
        }
    }

    // Delete the team_user relationship
    sqlx::query("DELETE FROM team_users WHERE team_id = $1 AND user_pubkey = $2")
        .bind(team_id)
        .bind(removed_user_pubkey.to_hex())
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn add_key(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    UcanAuth(user_pubkey_hex): UcanAuth,
    Path(team_id): Path<i32>,
    Json(request): Json<AddKeyRequest>,
) -> ApiResult<Json<PublicStoredKey>> {
    let tenant_id = tenant.0.id;
    verify_admin(&pool, &user_pubkey_hex, team_id, tenant_id).await?;

    let mut tx = pool.begin().await?;

    let keys =
        Keys::parse(&request.secret_key).map_err(|e| ApiError::bad_request(e.to_string()))?;

    // Encrypt the secret key
    let key_manager = get_key_manager().map_err(|e| ApiError::internal(e.to_string()))?;
    let encrypted_secret = key_manager
        .encrypt(keys.secret_key().as_secret_bytes())
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;

    // Insert the key
    let key = sqlx::query_as::<_, StoredKey>(
        r#"
         INSERT INTO stored_keys (tenant_id, team_id, name, pubkey, secret_key, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
         RETURNING *
         "#,
    )
    .bind(tenant_id)
    .bind(team_id)
    .bind(request.name)
    .bind(keys.public_key().to_hex())
    .bind(encrypted_secret)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    tx.commit().await?;

    Ok(Json(key.into()))
}

pub async fn remove_key(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    UcanAuth(user_pubkey_hex): UcanAuth,
    Path((team_id, pubkey)): Path<(i32, String)>,
) -> ApiResult<StatusCode> {
    let tenant_id = tenant.0.id;
    verify_admin(&pool, &user_pubkey_hex, team_id, tenant_id).await?;

    let mut tx = pool.begin().await?;

    let removed_stored_key_public_key =
        PublicKey::from_hex(&pubkey).map_err(|e| ApiError::bad_request(e.to_string()))?;

    // First get the stored key ID
    let stored_key = sqlx::query_as::<_, StoredKey>(
        "SELECT * FROM stored_keys WHERE tenant_id = $1 AND team_id = $2 AND pubkey = $3",
    )
    .bind(tenant_id)
    .bind(team_id)
    .bind(removed_stored_key_public_key.to_hex())
    .fetch_one(&mut *tx)
    .await?;

    // Delete all user_authorizations for this key using the correct stored_key_id
    sqlx::query(
        "DELETE FROM user_authorizations WHERE authorization_id IN (SELECT id FROM authorizations WHERE tenant_id = $1 AND stored_key_id = $2)"
    )
    .bind(tenant_id)
    .bind(stored_key.id)
    .execute(&mut *tx)
    .await?;

    // Delete all authorizations for this key using the correct stored_key_id
    sqlx::query("DELETE FROM authorizations WHERE tenant_id = $1 AND stored_key_id = $2")
        .bind(tenant_id)
        .bind(stored_key.id)
        .execute(&mut *tx)
        .await?;

    // Finally delete the key itself
    sqlx::query("DELETE FROM stored_keys WHERE tenant_id = $1 AND team_id = $2 AND pubkey = $3")
        .bind(tenant_id)
        .bind(team_id)
        .bind(removed_stored_key_public_key.to_hex())
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_key(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    UcanAuth(user_pubkey_hex): UcanAuth,
    Path((team_id, pubkey)): Path<(i32, String)>,
) -> ApiResult<Json<KeyWithRelations>> {
    let tenant_id = tenant.0.id;
    verify_admin(&pool, &user_pubkey_hex, team_id, tenant_id).await?;

    let mut tx = pool.begin().await?;

    let stored_key_public_key =
        PublicKey::from_hex(&pubkey).map_err(|e| ApiError::bad_request(e.to_string()))?;

    let team = sqlx::query_as::<_, Team>(
        r#"
            SELECT * FROM teams WHERE tenant_id = $1 AND id = $2
            "#,
    )
    .bind(tenant_id)
    .bind(team_id)
    .fetch_one(&mut *tx)
    .await?;

    let stored_key = sqlx::query_as::<_, StoredKey>(
        r#"
            SELECT * FROM stored_keys WHERE tenant_id = $1 AND team_id = $2 AND pubkey = $3
            "#,
    )
    .bind(tenant_id)
    .bind(team_id)
    .bind(stored_key_public_key.to_hex())
    .fetch_one(&mut *tx)
    .await?;

    // First fetch authorizations with policies
    let authorizations = sqlx::query_as::<_, Authorization>(
        r#"
            SELECT *
            FROM authorizations
            WHERE tenant_id = $1 AND stored_key_id = $2
            "#,
    )
    .bind(tenant_id)
    .bind(stored_key.id)
    .fetch_all(&mut *tx)
    .await?;

    // Then fetch users for each authorization and combine
    let mut complete_authorizations = Vec::new();

    for auth in authorizations {
        let policy = sqlx::query_as::<_, Policy>(
            r#"
                SELECT *
                FROM policies
                WHERE id = $1
                "#,
        )
        .bind(auth.policy_id)
        .fetch_one(&mut *tx)
        .await?;

        let users = sqlx::query_as::<_, UserAuthorization>(
            r#"
                SELECT user_pubkey, created_at, updated_at
                FROM user_authorizations
                WHERE authorization_id = $1
                "#,
        )
        .bind(auth.id)
        .fetch_all(&mut *tx)
        .await?;

        complete_authorizations.push(AuthorizationWithRelations {
            authorization: auth.clone(),
            policy,
            users,
            bunker_connection_string: auth
                .bunker_connection_string()
                .await
                .map_err(|e| ApiError::internal(e.to_string()))?,
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
    UcanAuth(user_pubkey_hex): UcanAuth,
    Path((team_id, pubkey)): Path<(i32, String)>,
    Json(request): Json<AddAuthorizationRequest>,
) -> ApiResult<Json<Authorization>> {
    let tenant_id = tenant.0.id;
    verify_admin(&pool, &user_pubkey_hex, team_id, tenant_id).await?;

    let stored_key_public_key =
        PublicKey::from_hex(&pubkey).map_err(|e| ApiError::bad_request(e.to_string()))?;

    let mut tx = pool.begin().await?;

    let stored_key = sqlx::query_as::<_, StoredKey>(
        r#"
            SELECT * FROM stored_keys WHERE tenant_id = $1 AND team_id = $2 AND pubkey = $3
            "#,
    )
    .bind(tenant_id)
    .bind(team_id)
    .bind(stored_key_public_key.to_hex())
    .fetch_one(&mut *tx)
    .await?;

    // Verify policy exists and belongs to this team
    let policy_exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM policies WHERE team_id = $1 AND id = $2)",
    )
    .bind(team_id)
    .bind(request.policy_id)
    .fetch_one(&mut *tx)
    .await?;

    if !policy_exists {
        return Err(ApiError::not_found("Policy not found"));
    }

    // Create bunker keys for this authorization
    let bunker_keys = Keys::generate();

    // Encrypt the secret key
    let key_manager = get_key_manager().unwrap();
    let encrypted_bunker_secret = key_manager
        .encrypt(bunker_keys.secret_key().as_secret_bytes())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    // create a secret uuid for the authorization connection string
    let secret = uuid::Uuid::new_v4().to_string();

    let relays =
        serde_json::to_value(&request.relays).map_err(|e| ApiError::bad_request(e.to_string()))?;

    // Create authorization
    let authorization = sqlx::query_as::<_, Authorization>(
            r#"
            INSERT INTO authorizations (tenant_id, stored_key_id, policy_id, secret, bunker_public_key, bunker_secret, relays, max_uses, expires_at, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(stored_key.id)
        .bind(request.policy_id)
        .bind(secret)
        .bind(bunker_keys.public_key().to_hex())
        .bind(encrypted_bunker_secret)
        .bind(relays)
        .bind(request.max_uses)
        .bind(request.expires_at)
        .fetch_one(&mut *tx)
        .await?;

    tx.commit().await?;

    Ok(Json(authorization))
}

pub async fn delete_authorization(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    UcanAuth(user_pubkey_hex): UcanAuth,
    Path((team_id, pubkey, auth_id)): Path<(i32, String, i32)>,
) -> ApiResult<StatusCode> {
    let tenant_id = tenant.0.id;
    verify_admin(&pool, &user_pubkey_hex, team_id, tenant_id).await?;

    let stored_key_public_key =
        PublicKey::from_hex(&pubkey).map_err(|e| ApiError::bad_request(e.to_string()))?;

    let mut tx = pool.begin().await?;

    // Verify stored key exists and belongs to this team
    let stored_key = sqlx::query_as::<_, StoredKey>(
        r#"SELECT * FROM stored_keys WHERE tenant_id = $1 AND team_id = $2 AND pubkey = $3"#,
    )
    .bind(tenant_id)
    .bind(team_id)
    .bind(stored_key_public_key.to_hex())
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::not_found("Stored key not found"))?;

    // Delete user_authorizations first (foreign key constraint)
    sqlx::query("DELETE FROM user_authorizations WHERE authorization_id = $1")
        .bind(auth_id)
        .execute(&mut *tx)
        .await?;

    // Delete the authorization (verify it belongs to the right stored key)
    let result = sqlx::query(
        r#"DELETE FROM authorizations WHERE tenant_id = $1 AND id = $2 AND stored_key_id = $3"#,
    )
    .bind(tenant_id)
    .bind(auth_id)
    .bind(stored_key.id)
    .execute(&mut *tx)
    .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Authorization not found"));
    }

    tx.commit().await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn add_policy(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    UcanAuth(user_pubkey_hex): UcanAuth,
    Path(team_id): Path<i32>,
    Json(request): Json<CreatePolicyRequest>,
) -> ApiResult<Json<PolicyWithPermissions>> {
    let tenant_id = tenant.0.id;
    verify_admin(&pool, &user_pubkey_hex, team_id, tenant_id).await?;
    let mut tx = pool.begin().await?;

    // Create the permissions
    let mut permissions = Vec::new();
    for permission in request.permissions {
        // Skip if the permission identifier is not in AVAILABLE_PERMISSIONS
        if !AVAILABLE_PERMISSIONS.contains(&permission.identifier.as_str()) {
            tracing::warn!(
                "Skipping unknown permission identifier: {}",
                permission.identifier
            );
            continue;
        }

        let permission = sqlx::query_as::<_, Permission>(
            "INSERT INTO permissions (identifier, config, created_at, updated_at) VALUES ($1, $2, NOW(), NOW()) RETURNING *",
        )
        .bind(permission.identifier)
        .bind(permission.config)
        .fetch_one(&mut *tx)
        .await?;

        permissions.push(permission);
    }

    // Create the policy
    let policy = sqlx::query_as::<_, Policy>(
        "INSERT INTO policies (team_id, name, created_at, updated_at) VALUES ($1, $2, NOW(), NOW()) RETURNING *",
    )
    .bind(team_id)
    .bind(request.name)
    .fetch_one(&mut *tx)
    .await?;

    // create the policy permissions
    for permission in &permissions {
        sqlx::query(
            "INSERT INTO policy_permissions (policy_id, permission_id, created_at, updated_at) VALUES ($1, $2, NOW(), NOW())",
        )
        .bind(policy.id)
        .bind(permission.id)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    Ok(Json(PolicyWithPermissions {
        policy,
        permissions,
    }))
}

pub async fn verify_admin<'a>(
    pool: &'a PgPool,
    pubkey_hex: &'a str,
    team_id: i32,
    tenant_id: i64,
) -> ApiResult<()> {
    let pubkey =
        PublicKey::from_hex(pubkey_hex).map_err(|_| ApiError::bad_request("Invalid pubkey"))?;

    match User::is_team_admin(pool, tenant_id, &pubkey, team_id).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(ApiError::forbidden(
            "You are not authorized to access this team",
        )),
        Err(_) => Err(ApiError::auth("Failed to verify admin status")),
    }
}
