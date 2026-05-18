use crate::types::policy::PolicyWithPermissions;
use crate::types::stored_key::{PublicStoredKey, StoredKey};
use crate::types::team::{Team, TeamWithRelations};
use chrono::DateTime;
use nostr_sdk::PublicKey;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum UserError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Couldn't fetch relations")]
    Relations,
    #[error("User not found")]
    NotFound,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "TEXT", rename_all = "lowercase")]
pub enum UserStatus {
    #[default]
    Active,
    Suspended,
    Banned,
}

impl UserStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            UserStatus::Active => "active",
            UserStatus::Suspended => "suspended",
            UserStatus::Banned => "banned",
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, UserStatus::Active)
    }
}

/// A user is a representation of a Nostr user (based solely on a pubkey value)
#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct User {
    /// The user's Nostr pubkey in hex format (NIP-46: `user-pubkey`)
    pub pubkey: String,
    /// The date and time the user was created
    pub created_at: DateTime<chrono::Utc>,
    /// The date and time the user was last updated
    pub updated_at: DateTime<chrono::Utc>,
    pub status: UserStatus,
    pub suspended_reason: Option<String>,
    pub suspended_at: Option<DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserAtprotoState {
    pub enabled: bool,
    pub state: Option<String>,
    pub did: Option<String>,
    pub error: Option<String>,
    pub updated_at: Option<DateTime<chrono::Utc>>,
}

/// A team user is a representation of a user's membership in a team, this is a join table
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct TeamUser {
    /// The user's Nostr pubkey in hex format (NIP-46: `user-pubkey`)
    pub user_pubkey: String,
    /// The team id
    pub team_id: i32,
    /// The user's role in the team
    pub role: TeamUserRole,
    /// The date and time the user was created
    pub created_at: DateTime<chrono::Utc>,
    /// The date and time the user was last updated
    pub updated_at: DateTime<chrono::Utc>,
}

/// The role of a user in a team
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "TEXT", rename_all = "lowercase")]
pub enum TeamUserRole {
    Admin,
    Member,
}

impl TeamUserRole {
    /// Convert the role to its string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            TeamUserRole::Admin => "admin",
            TeamUserRole::Member => "member",
        }
    }
}

impl User {
    pub async fn find_by_pubkey(
        pool: &PgPool,
        tenant_id: i64,
        pubkey: &PublicKey,
    ) -> Result<Self, UserError> {
        match sqlx::query_as::<_, User>(
            "SELECT pubkey, created_at, updated_at, status, suspended_reason, suspended_at FROM users WHERE tenant_id = $1 AND pubkey = $2",
        )
        .bind(tenant_id)
        .bind(pubkey.to_hex())
        .fetch_one(pool)
        .await
        {
            Ok(user) => Ok(user),
            Err(sqlx::Error::RowNotFound) => Err(UserError::NotFound),
            Err(e) => {
                eprintln!("Error fetching user: {:?}", e);
                Err(UserError::Database(e))
            }
        }
    }

    pub async fn teams(
        &self,
        pool: &PgPool,
        tenant_id: i64,
    ) -> Result<Vec<TeamWithRelations>, UserError> {
        // Fetch teams user belongs to
        let teams = sqlx::query_as::<_, Team>(
            "SELECT id, name, created_at, updated_at FROM teams
             WHERE tenant_id = $1 AND id IN (SELECT team_id FROM team_users WHERE user_pubkey = $2)",
        )
        .bind(tenant_id)
        .bind(&self.pubkey)
        .fetch_all(pool)
        .await?;

        if teams.is_empty() {
            return Ok(Vec::new());
        }

        // Collect team IDs for batch queries
        let team_ids: Vec<i32> = teams.iter().map(|t| t.id).collect();

        // Batch fetch all team_users for all teams
        let all_team_users = sqlx::query_as::<_, TeamUser>(
            "SELECT user_pubkey, team_id, role, created_at, updated_at
             FROM team_users WHERE team_id = ANY($1)",
        )
        .bind(&team_ids)
        .fetch_all(pool)
        .await?;

        // Batch fetch all stored_keys for all teams
        let all_stored_keys = sqlx::query_as::<_, StoredKey>(
            "SELECT id, team_id, name, pubkey, secret_key, created_at, updated_at
             FROM stored_keys WHERE tenant_id = $1 AND team_id = ANY($2)",
        )
        .bind(tenant_id)
        .bind(&team_ids)
        .fetch_all(pool)
        .await?;

        // Batch fetch all policies with permissions for all teams
        let all_policies_with_permissions =
            Team::get_policies_with_permissions_batch(pool, &team_ids)
                .await
                .map_err(|_| UserError::Relations)?;

        // Group results by team_id
        let mut teams_with_relations = Vec::with_capacity(teams.len());
        for team in teams {
            let team_users: Vec<TeamUser> = all_team_users
                .iter()
                .filter(|tu| tu.team_id == team.id)
                .cloned()
                .collect();

            let stored_keys: Vec<PublicStoredKey> = all_stored_keys
                .iter()
                .filter(|sk| sk.team_id == team.id)
                .cloned()
                .map(|k| k.into())
                .collect();

            let policies: Vec<PolicyWithPermissions> = all_policies_with_permissions
                .iter()
                .filter(|p| p.policy.team_id == Some(team.id))
                .cloned()
                .collect();

            teams_with_relations.push(TeamWithRelations {
                team,
                team_users,
                stored_keys,
                policies,
            });
        }

        Ok(teams_with_relations)
    }

    /// Check if a user is an admin of a team
    pub async fn is_team_admin(
        pool: &PgPool,
        _tenant_id: i64,
        pubkey: &PublicKey,
        team_id: i32,
    ) -> Result<bool, UserError> {
        let query = "SELECT COUNT(*) FROM team_users WHERE user_pubkey = $1 AND team_id = $2 AND role = 'admin'";
        let count = sqlx::query_scalar::<_, i64>(query)
            .bind(pubkey.to_hex())
            .bind(team_id)
            .fetch_one(pool)
            .await?;
        Ok(count > 0)
    }

    /// Check if a user is a member of a team
    pub async fn is_team_member(
        pool: &PgPool,
        _tenant_id: i64,
        pubkey: &PublicKey,
        team_id: i32,
    ) -> Result<bool, UserError> {
        let query = "SELECT COUNT(*) FROM team_users WHERE user_pubkey = $1 AND team_id = $2 AND role = 'member'";
        let count = sqlx::query_scalar::<_, i64>(query)
            .bind(pubkey.to_hex())
            .bind(team_id)
            .fetch_one(pool)
            .await?;
        Ok(count > 0)
    }

    /// Check if a user is part of a team (admin or member)
    pub async fn is_team_teammate(
        pool: &PgPool,
        _tenant_id: i64,
        pubkey: &PublicKey,
        team_id: i32,
    ) -> Result<bool, UserError> {
        let query = "SELECT COUNT(*) FROM team_users WHERE user_pubkey = $1 AND team_id = $2";
        let count = sqlx::query_scalar::<_, i64>(query)
            .bind(pubkey.to_hex())
            .bind(team_id)
            .fetch_one(pool)
            .await?;
        Ok(count > 0)
    }
}
