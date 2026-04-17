// ABOUTME: Repository module for data access operations
// ABOUTME: Provides abstraction layer between handlers and database

mod atproto_oauth_session;
mod auth_event;
mod authorization;
mod claim_token;
mod error;
mod oauth_authorization;
mod oauth_code;
mod personal_keys;
mod policy;
mod refresh_token;
mod registered_client;
mod stored_key;
mod team;
mod user;

pub use atproto_oauth_session::{
    AtprotoOAuthSession, AtprotoOAuthSessionRepository, CreateAtprotoOAuthSessionParams,
    IssueAtprotoTokensParams,
};
pub use auth_event::{AuthEventRecord, AuthEventRepository, AuthEventRow};
pub use authorization::AuthorizationRepository;
pub use claim_token::ClaimTokenRepository;
pub use error::RepositoryError;
pub use oauth_authorization::{CreateOAuthAuthorizationParams, OAuthAuthorizationRepository};
pub use oauth_code::{
    OAuthCodeData, OAuthCodeRepository, StoreOAuthCodeParams, StoreOAuthCodeWithRegistrationParams,
};
pub use personal_keys::PersonalKeysRepository;
pub use policy::PolicyRepository;
pub use refresh_token::RefreshTokenRepository;
pub use registered_client::RegisteredClientRepository;
pub use stored_key::StoredKeyRepository;
pub use team::TeamRepository;
pub use user::{AdminUserDetails, DeleteAccountResult, UserRepository, VerificationTokenData};
