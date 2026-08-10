use crate::repositories::RepositoryError;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};

macro_rules! atproto_oauth_session_columns {
    () => {
        "id, tenant_id, client_id, redirect_uri, scope, state, code_challenge, \
         code_challenge_method, request_uri, par_expires_at, user_pubkey, atproto_did, \
         approved_at, authorization_code, authorization_code_expires_at, access_token_jti, \
         access_token_expires_at, refresh_token_hash, refresh_token_expires_at, \
         refresh_token_revoked_at, revoked_at, dpop_jkt, dpop_nonce, client_auth_method, \
         client_auth_alg, client_auth_kid, client_auth_jkt, created_at, updated_at"
    };
}

#[derive(Debug, Clone, FromRow)]
pub struct AtprotoOAuthSession {
    pub id: i32,
    pub tenant_id: i64,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub request_uri: String,
    pub par_expires_at: DateTime<Utc>,
    pub user_pubkey: Option<String>,
    pub atproto_did: Option<String>,
    pub approved_at: Option<DateTime<Utc>>,
    pub authorization_code: Option<String>,
    pub authorization_code_expires_at: Option<DateTime<Utc>>,
    pub access_token_jti: Option<String>,
    pub access_token_expires_at: Option<DateTime<Utc>>,
    pub refresh_token_hash: Option<String>,
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub refresh_token_revoked_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub dpop_jkt: Option<String>,
    pub dpop_nonce: Option<String>,
    pub client_auth_method: String,
    pub client_auth_alg: Option<String>,
    pub client_auth_kid: Option<String>,
    pub client_auth_jkt: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct CreateAtprotoOAuthSessionParams {
    pub tenant_id: i64,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub request_uri: String,
    pub par_expires_at: DateTime<Utc>,
    pub dpop_jkt: Option<String>,
    pub dpop_nonce: Option<String>,
    pub client_auth_method: String,
    pub client_auth_alg: Option<String>,
    pub client_auth_kid: Option<String>,
    pub client_auth_jkt: Option<String>,
}

#[derive(Debug, Clone)]
pub struct IssueAtprotoTokensParams {
    pub authorization_code: String,
    pub authorization_code_expires_at: DateTime<Utc>,
    pub access_token_jti: String,
    pub access_token_expires_at: DateTime<Utc>,
    pub refresh_token_hash: String,
    pub refresh_token_expires_at: DateTime<Utc>,
    pub dpop_jkt: Option<String>,
    pub dpop_nonce: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AtprotoOAuthSessionRepository {
    pool: PgPool,
}

impl AtprotoOAuthSessionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create_par(
        &self,
        params: CreateAtprotoOAuthSessionParams,
    ) -> Result<AtprotoOAuthSession, RepositoryError> {
        sqlx::query_as::<_, AtprotoOAuthSession>(
            "INSERT INTO atproto_oauth_sessions
             (tenant_id, client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, request_uri, par_expires_at, dpop_jkt, dpop_nonce, client_auth_method, client_auth_alg, client_auth_kid, client_auth_jkt)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
             RETURNING *",
        )
        .bind(params.tenant_id)
        .bind(&params.client_id)
        .bind(&params.redirect_uri)
        .bind(&params.scope)
        .bind(&params.state)
        .bind(&params.code_challenge)
        .bind(&params.code_challenge_method)
        .bind(&params.request_uri)
        .bind(params.par_expires_at)
        .bind(&params.dpop_jkt)
        .bind(&params.dpop_nonce)
        .bind(&params.client_auth_method)
        .bind(&params.client_auth_alg)
        .bind(&params.client_auth_kid)
        .bind(&params.client_auth_jkt)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    pub async fn find_by_request_uri(
        &self,
        request_uri: &str,
    ) -> Result<Option<AtprotoOAuthSession>, RepositoryError> {
        sqlx::query_as::<_, AtprotoOAuthSession>(concat!(
            "SELECT ",
            atproto_oauth_session_columns!(),
            " FROM atproto_oauth_sessions
             WHERE request_uri = $1
               AND revoked_at IS NULL"
        ))
        .bind(request_uri)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    pub async fn approve_request(
        &self,
        request_uri: &str,
        user_pubkey: &str,
        atproto_did: &str,
    ) -> Result<Option<AtprotoOAuthSession>, RepositoryError> {
        sqlx::query_as::<_, AtprotoOAuthSession>(
            "UPDATE atproto_oauth_sessions
             SET user_pubkey = $2,
                 atproto_did = $3,
                 approved_at = NOW()
             WHERE request_uri = $1
               AND revoked_at IS NULL
             RETURNING *",
        )
        .bind(request_uri)
        .bind(user_pubkey)
        .bind(atproto_did)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    pub async fn store_token_artifacts(
        &self,
        request_uri: &str,
        params: IssueAtprotoTokensParams,
    ) -> Result<Option<AtprotoOAuthSession>, RepositoryError> {
        sqlx::query_as::<_, AtprotoOAuthSession>(
            "UPDATE atproto_oauth_sessions
             SET authorization_code = $2,
                 authorization_code_expires_at = $3,
                 access_token_jti = $4,
                 access_token_expires_at = $5,
                 refresh_token_hash = $6,
                 refresh_token_expires_at = $7,
                 dpop_jkt = $8,
                 dpop_nonce = $9
             WHERE request_uri = $1
               AND revoked_at IS NULL
             RETURNING *",
        )
        .bind(request_uri)
        .bind(&params.authorization_code)
        .bind(params.authorization_code_expires_at)
        .bind(&params.access_token_jti)
        .bind(params.access_token_expires_at)
        .bind(&params.refresh_token_hash)
        .bind(params.refresh_token_expires_at)
        .bind(&params.dpop_jkt)
        .bind(&params.dpop_nonce)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    pub async fn find_by_authorization_code(
        &self,
        authorization_code: &str,
    ) -> Result<Option<AtprotoOAuthSession>, RepositoryError> {
        sqlx::query_as::<_, AtprotoOAuthSession>(concat!(
            "SELECT ",
            atproto_oauth_session_columns!(),
            " FROM atproto_oauth_sessions
             WHERE authorization_code = $1
               AND revoked_at IS NULL
               AND authorization_code_expires_at > NOW()"
        ))
        .bind(authorization_code)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    pub async fn store_authorization_code(
        &self,
        request_uri: &str,
        authorization_code: &str,
        authorization_code_expires_at: DateTime<Utc>,
    ) -> Result<Option<AtprotoOAuthSession>, RepositoryError> {
        sqlx::query_as::<_, AtprotoOAuthSession>(
            "UPDATE atproto_oauth_sessions
             SET authorization_code = $2,
                 authorization_code_expires_at = $3
             WHERE request_uri = $1
               AND revoked_at IS NULL
             RETURNING *",
        )
        .bind(request_uri)
        .bind(authorization_code)
        .bind(authorization_code_expires_at)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    pub async fn consume_authorization_code(
        &self,
        authorization_code: &str,
    ) -> Result<Option<AtprotoOAuthSession>, RepositoryError> {
        sqlx::query_as::<_, AtprotoOAuthSession>(
            "UPDATE atproto_oauth_sessions
             SET authorization_code = NULL,
                 authorization_code_expires_at = NULL
             WHERE authorization_code = $1
               AND revoked_at IS NULL
               AND authorization_code_expires_at > NOW()
             RETURNING *",
        )
        .bind(authorization_code)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    pub async fn find_by_refresh_token_hash(
        &self,
        refresh_token_hash: &str,
    ) -> Result<Option<AtprotoOAuthSession>, RepositoryError> {
        sqlx::query_as::<_, AtprotoOAuthSession>(concat!(
            "SELECT ",
            atproto_oauth_session_columns!(),
            " FROM atproto_oauth_sessions
             WHERE refresh_token_hash = $1
               AND revoked_at IS NULL
               AND refresh_token_revoked_at IS NULL
               AND refresh_token_expires_at > NOW()"
        ))
        .bind(refresh_token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    pub async fn rotate_refresh_token(
        &self,
        request_uri: &str,
        previous_refresh_token_hash: &str,
        params: IssueAtprotoTokensParams,
    ) -> Result<Option<AtprotoOAuthSession>, RepositoryError> {
        sqlx::query_as::<_, AtprotoOAuthSession>(
            "UPDATE atproto_oauth_sessions
             SET access_token_jti = $3,
                 access_token_expires_at = $4,
                 refresh_token_hash = $5,
                 refresh_token_expires_at = $6,
                 dpop_jkt = $7,
                 dpop_nonce = $8
             WHERE request_uri = $1
               AND refresh_token_hash = $2
               AND revoked_at IS NULL
               AND refresh_token_revoked_at IS NULL
               AND refresh_token_expires_at > NOW()
             RETURNING *",
        )
        .bind(request_uri)
        .bind(previous_refresh_token_hash)
        .bind(&params.access_token_jti)
        .bind(params.access_token_expires_at)
        .bind(&params.refresh_token_hash)
        .bind(params.refresh_token_expires_at)
        .bind(&params.dpop_jkt)
        .bind(&params.dpop_nonce)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    pub async fn update_dpop_nonce(
        &self,
        request_uri: &str,
        dpop_nonce: &str,
    ) -> Result<Option<AtprotoOAuthSession>, RepositoryError> {
        sqlx::query_as::<_, AtprotoOAuthSession>(
            "UPDATE atproto_oauth_sessions
             SET dpop_nonce = $2
             WHERE request_uri = $1
               AND revoked_at IS NULL
             RETURNING *",
        )
        .bind(request_uri)
        .bind(dpop_nonce)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    pub async fn revoke_refresh_session(
        &self,
        refresh_token_hash: &str,
    ) -> Result<Option<AtprotoOAuthSession>, RepositoryError> {
        sqlx::query_as::<_, AtprotoOAuthSession>(
            "UPDATE atproto_oauth_sessions
             SET refresh_token_revoked_at = NOW(),
                 revoked_at = COALESCE(revoked_at, NOW())
             WHERE refresh_token_hash = $1
               AND refresh_token_revoked_at IS NULL
             RETURNING *",
        )
        .bind(refresh_token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    pub async fn revoke_refresh_sessions_for_user(
        &self,
        tenant_id: i64,
        user_pubkey: &str,
    ) -> Result<u64, RepositoryError> {
        let result = sqlx::query(
            "UPDATE atproto_oauth_sessions
             SET refresh_token_revoked_at = CASE
                     WHEN refresh_token_hash IS NOT NULL
                         THEN COALESCE(refresh_token_revoked_at, NOW())
                     ELSE refresh_token_revoked_at
                 END,
                 revoked_at = COALESCE(revoked_at, NOW())
             WHERE tenant_id = $1
               AND user_pubkey = $2
               AND revoked_at IS NULL",
        )
        .bind(tenant_id)
        .bind(user_pubkey)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    pub async fn revoke_sessions_for_pubkey(
        &self,
        user_pubkey: &str,
    ) -> Result<u64, RepositoryError> {
        let result = sqlx::query(
            "UPDATE atproto_oauth_sessions
             SET refresh_token_revoked_at = CASE
                     WHEN refresh_token_hash IS NOT NULL
                         THEN COALESCE(refresh_token_revoked_at, NOW())
                     ELSE refresh_token_revoked_at
                 END,
                 revoked_at = COALESCE(revoked_at, NOW())
             WHERE user_pubkey = $1
               AND revoked_at IS NULL",
        )
        .bind(user_pubkey)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    pub async fn revoke_session(
        &self,
        request_uri: &str,
    ) -> Result<Option<AtprotoOAuthSession>, RepositoryError> {
        sqlx::query_as::<_, AtprotoOAuthSession>(
            "UPDATE atproto_oauth_sessions
             SET refresh_token_revoked_at = CASE
                     WHEN refresh_token_hash IS NOT NULL
                         THEN COALESCE(refresh_token_revoked_at, NOW())
                     ELSE refresh_token_revoked_at
                 END,
                 revoked_at = COALESCE(revoked_at, NOW())
             WHERE request_uri = $1
             RETURNING *",
        )
        .bind(request_uri)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }
}
