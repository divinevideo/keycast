#![cfg(feature = "integration-tests")]

// ABOUTME: Integration tests for "Continue with Google / Apple": POST /api/headless/social-login and the login page
// ABOUTME: Mints provider-shaped ID tokens with a local RSA key served through a stub JWKS source

use axum::{
    body::Body,
    extract::{rejection::JsonRejection, Query, State},
    http::{header, HeaderMap, Request, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Extension, Json, Router,
};
use base64::Engine;
use chrono::Utc;
use jwt_simple::prelude::{Claims, Duration as JwtDuration, RS256KeyPair, RSAKeyPairLike};
use keycast_api::ucan_auth::{nostr_pubkey_to_did, NostrKeyMaterial};
use keycast_api::{
    api::{
        http::{
            auth::{
                change_password, confirm_email_change, export_key, reset_password, verify_email,
                ChangePasswordRequest, ConfirmEmailChangeRequest, ResetPasswordRequest,
                VerifyEmailRequest,
            },
            oauth::{authorize_get, token, AuthorizeRequest, TokenRequest, TokenRequestBody},
            routes::AuthState,
            social_login::{
                headless_social_login, web_social_login, HeadlessSocialLoginRequest,
                WebSocialLoginRequest,
            },
        },
        tenant::{Tenant, TenantExtractor},
    },
    auth_cleanup::delete_legacy_stale_signup_rows,
    email_service::{DevEmailSender, EmailSender},
    handlers::http_rpc_handler::new_http_handler_cache,
    social_identity::{
        sha256_hex, AppleSettings, AppleWebSettings, GoogleSettings, GoogleWebSettings, JwkSet,
        JwksFetchError, JwksFetcher, SignInChannel, SocialIdentityVerifier, SocialLoginProviders,
        SocialLoginSettings,
    },
    state::KeycastState,
    ucan_auth::validate_ucan_token,
    BcryptAdmission,
};
use keycast_core::{
    encryption::{KeyManager, KeyManagerError},
    repositories::{
        CreateSocialAccountOutcome, NewSocialAccount, UserIdentityRepository, UserRepository,
    },
    secret_pool::SecretPool,
    social_login::SocialProvider,
};
use moka::future::Cache;
use nostr_sdk::Keys;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, OnceLock,
};
use tower::ServiceExt;
use ucan::builder::UcanBuilder;
use uuid::Uuid;
use zeroize::Zeroizing;

mod common;

const GOOGLE_SERVER_CLIENT: &str = "server.apps.googleusercontent.com";
const GOOGLE_IOS_CLIENT: &str = "ios.apps.googleusercontent.com";
const APPLE_BUNDLE: &str = "co.example.app";
/// The login page signs in to Apple with a Services ID; bundle IDs only work in the app.
const APPLE_SERVICES_ID: &str = "co.example.app.web";
const APPLE_WEB_RETURN_URL: &str = "https://login.divine.example/api/oauth/authorize";
const GOOGLE_ISSUER: &str = "https://accounts.google.com";
const APPLE_ISSUER: &str = "https://appleid.apple.com";
const KID: &str = "social-test-key";
const CLIENT_ID: &str = "DivineMobileSocialTest";
const REDIRECT_URI: &str = "https://login.divine.example/app/callback";
const CODE_VERIFIER: &str = "social-login-test-code-verifier-0123456789-abcdefghijklmnop";

// ============================================================================
// Fixtures
// ============================================================================

/// One RSA key per test binary: key generation is slow in debug builds.
fn signing_key() -> &'static RS256KeyPair {
    static KEY: OnceLock<RS256KeyPair> = OnceLock::new();
    KEY.get_or_init(|| {
        RS256KeyPair::generate(2048)
            .expect("generate test RSA key")
            .with_key_id(KID)
    })
}

fn other_signing_key() -> &'static RS256KeyPair {
    static KEY: OnceLock<RS256KeyPair> = OnceLock::new();
    KEY.get_or_init(|| {
        RS256KeyPair::generate(2048)
            .expect("generate second test RSA key")
            .with_key_id(KID)
    })
}

fn jwks_for(key: &RS256KeyPair) -> JwkSet {
    let components = key.public_key().to_components();
    let encode = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    serde_json::from_value(serde_json::json!({
        "keys": [{
            "kty": "RSA",
            "kid": KID,
            "alg": "RS256",
            "use": "sig",
            "n": encode(&components.n),
            "e": encode(&components.e),
        }]
    }))
    .expect("valid JWKS")
}

/// JWKS source that counts fetches and can be switched into failing.
struct StubJwks {
    set: JwkSet,
    calls: AtomicUsize,
    failing: AtomicBool,
}

impl StubJwks {
    fn new(set: JwkSet) -> Self {
        Self {
            set,
            calls: AtomicUsize::new(0),
            failing: AtomicBool::new(false),
        }
    }
}

#[async_trait::async_trait]
impl JwksFetcher for StubJwks {
    async fn fetch(&self, _provider: SocialProvider) -> Result<JwkSet, JwksFetchError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.failing.load(Ordering::SeqCst) {
            Err(JwksFetchError::Failed("stubbed outage".to_string()))
        } else {
            Ok(self.set.clone())
        }
    }
}

fn settings() -> SocialLoginSettings {
    SocialLoginSettings {
        google: Some(GoogleSettings {
            audiences: vec![GOOGLE_SERVER_CLIENT.to_string()],
            authorized_parties: vec![GOOGLE_IOS_CLIENT.to_string()],
        }),
        apple: Some(AppleSettings {
            audiences: vec![APPLE_BUNDLE.to_string()],
        }),
        // As in production, the login page uses the same web client the apps address tokens to.
        google_web: Some(GoogleWebSettings {
            client_id: GOOGLE_SERVER_CLIENT.to_string(),
        }),
        apple_web: Some(AppleWebSettings {
            services_id: APPLE_SERVICES_ID.to_string(),
            redirect_uri: APPLE_WEB_RETURN_URL.to_string(),
        }),
        apple_signing_key: None,
    }
}

struct TestKeyManager;

#[async_trait::async_trait]
impl KeyManager for TestKeyManager {
    async fn encrypt(&self, plaintext_bytes: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        Ok(plaintext_bytes.to_vec())
    }

    async fn decrypt(
        &self,
        ciphertext_bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyManagerError> {
        Ok(Zeroizing::new(ciphertext_bytes.to_vec()))
    }
}

struct Context {
    pool: PgPool,
    auth_state: AuthState,
    jwks: Arc<StubJwks>,
    providers: Arc<SocialLoginProviders>,
    email_sender: Arc<DevEmailSender>,
    pubkeys: std::sync::Mutex<Vec<String>>,
}

async fn context_with(jwks: Arc<StubJwks>, redis: bool) -> Context {
    context_with_settings(jwks, redis, settings()).await
}

async fn context_with_settings(
    jwks: Arc<StubJwks>,
    redis: bool,
    settings: SocialLoginSettings,
) -> Context {
    // Applies pending migrations, so the suite does not depend on another one running first.
    let pool = common::setup_test_db().await;

    let redis = if redis {
        let redis_url = std::env::var("TEST_REDIS_URL")
            .unwrap_or_else(|_| "redis://localhost:16379".to_string());
        let client = redis::Client::open(redis_url).expect("valid test Redis URL");
        let connection = redis::aio::ConnectionManager::new(client)
            .await
            .expect("connect to test Redis");
        Some(keycast_api::PrefixedRedis::new(
            connection,
            Some(format!("social-login:{}", Uuid::new_v4())),
        ))
    } else {
        None
    };

    let bcrypt = BcryptAdmission::new(1, std::time::Duration::from_secs(1));
    let secret_pool = Box::leak(Box::new(SecretPool::new(1)));
    let _producer = secret_pool.spawn_producer(bcrypt.clone());
    let key_manager: Arc<Box<dyn KeyManager>> = Arc::new(Box::new(TestKeyManager));
    let auth_state = AuthState {
        state: Arc::new(KeycastState {
            db: pool.clone(),
            key_manager,
            signer_handlers: None,
            http_handler_cache: new_http_handler_cache(),
            account_status_cache: keycast_api::state::new_account_status_cache(),
            server_keys: Keys::generate(),
            tenant_cache: Cache::builder().max_capacity(10).build(),
            bcrypt,
            redis,
            secret_pool: secret_pool.receiver(),
            activity_logger: keycast_api::activity_log::ActivityLogger::disabled(),
        }),
        auth_tx: None,
    };
    let providers = Arc::new(SocialLoginProviders::new(
        SocialIdentityVerifier::new(settings, jwks.clone()),
        None,
    ));

    Context {
        pool,
        auth_state,
        jwks,
        providers,
        email_sender: Arc::new(DevEmailSender::new()),
        pubkeys: std::sync::Mutex::new(Vec::new()),
    }
}

async fn context() -> Context {
    context_with(Arc::new(StubJwks::new(jwks_for(signing_key()))), true).await
}

fn tenant() -> TenantExtractor {
    TenantExtractor(Arc::new(Tenant {
        id: 1,
        domain: "localhost".to_string(),
        name: "Test Tenant".to_string(),
        settings: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }))
}

impl Context {
    fn app(&self) -> Router {
        let auth_state = self.auth_state.clone();
        let providers = self.providers.clone();
        let email_sender: Arc<dyn EmailSender> = self.email_sender.clone();
        Router::new().route(
            "/headless/social-login",
            post(
                move |headers: HeaderMap,
                      payload: Result<Json<HeadlessSocialLoginRequest>, JsonRejection>| {
                    let auth_state = auth_state.clone();
                    let providers = providers.clone();
                    let email_sender = email_sender.clone();
                    async move {
                        headless_social_login(
                            tenant(),
                            State(auth_state),
                            Extension(providers),
                            Extension(email_sender),
                            headers,
                            payload,
                        )
                        .await
                    }
                },
            ),
        )
    }

    async fn post_raw(&self, body: String) -> (StatusCode, serde_json::Value) {
        let response = self
            .app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/headless/social-login")
                    .header("host", "localhost")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        if let Some(pubkey) = json["pubkey"].as_str() {
            self.track(pubkey);
        }
        (status, json)
    }

    async fn post(&self, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
        self.post_raw(body.to_string()).await
    }

    fn track(&self, pubkey: &str) {
        self.pubkeys.lock().unwrap().push(pubkey.to_string());
    }

    async fn cleanup(&self) {
        let pubkeys = self.pubkeys.lock().unwrap().clone();
        for pubkey in pubkeys {
            for statement in [
                "DELETE FROM oauth_refresh_tokens WHERE authorization_id IN
                     (SELECT id FROM oauth_authorizations WHERE user_pubkey = $1)",
                "DELETE FROM oauth_authorizations WHERE user_pubkey = $1",
                "DELETE FROM oauth_codes WHERE user_pubkey = $1",
                "DELETE FROM auth_events WHERE pubkey = $1",
                "DELETE FROM users WHERE pubkey = $1",
            ] {
                let _ = sqlx::query(statement)
                    .bind(&pubkey)
                    .execute(&self.pool)
                    .await;
            }
        }
    }
}

fn code_challenge() -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(CODE_VERIFIER))
}

fn request(provider: &str, id_token: &str, raw_nonce: &str) -> serde_json::Value {
    serde_json::json!({
        "provider": provider,
        "id_token": id_token,
        "raw_nonce": raw_nonce,
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": "policy:full",
        "code_challenge": code_challenge(),
        "code_challenge_method": "S256",
        "state": "state-123",
        "app_version": "1.2.3",
    })
}

#[derive(Serialize)]
struct ProviderClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email_verified: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    azp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hd: Option<String>,
}

/// A provider token under construction. Defaults describe a valid token.
struct TokenSpec {
    issuer: String,
    audience: String,
    subject: String,
    nonce: Option<String>,
    claims: ProviderClaims,
    valid_for_secs: u64,
    expires_ago_secs: Option<u64>,
    key: &'static RS256KeyPair,
}

impl TokenSpec {
    fn google(subject: &str, email: &str, raw_nonce: &str) -> Self {
        Self {
            issuer: GOOGLE_ISSUER.to_string(),
            audience: GOOGLE_SERVER_CLIENT.to_string(),
            subject: subject.to_string(),
            nonce: Some(sha256_hex(raw_nonce)),
            claims: ProviderClaims {
                email: Some(email.to_string()),
                email_verified: Some(serde_json::json!(true)),
                azp: Some(GOOGLE_IOS_CLIENT.to_string()),
                hd: None,
            },
            valid_for_secs: 3600,
            expires_ago_secs: None,
            key: signing_key(),
        }
    }

    fn apple(subject: &str, email: &str, raw_nonce: &str) -> Self {
        Self {
            issuer: APPLE_ISSUER.to_string(),
            audience: APPLE_BUNDLE.to_string(),
            subject: subject.to_string(),
            nonce: Some(sha256_hex(raw_nonce)),
            claims: ProviderClaims {
                email: Some(email.to_string()),
                // Apple sends the string form.
                email_verified: Some(serde_json::json!("true")),
                azp: None,
                hd: None,
            },
            valid_for_secs: 600,
            expires_ago_secs: None,
            key: signing_key(),
        }
    }

    /// A token Google Identity Services issues on the login page: `azp` is the web client.
    fn google_web(subject: &str, email: &str, raw_nonce: &str) -> Self {
        let mut spec = Self::google(subject, email, raw_nonce);
        spec.claims.azp = Some(GOOGLE_SERVER_CLIENT.to_string());
        spec
    }

    /// A token Sign in with Apple JS issues on the login page, addressed to the Services ID.
    fn apple_web(subject: &str, email: &str, raw_nonce: &str) -> Self {
        let mut spec = Self::apple(subject, email, raw_nonce);
        spec.audience = APPLE_SERVICES_ID.to_string();
        spec
    }

    fn sign(self) -> String {
        let mut claims =
            Claims::with_custom_claims(self.claims, JwtDuration::from_secs(self.valid_for_secs))
                .with_issuer(self.issuer)
                .with_audience(self.audience)
                .with_subject(self.subject);
        if let Some(nonce) = self.nonce {
            claims = claims.with_nonce(nonce);
        }
        if let Some(ago) = self.expires_ago_secs {
            let now = Utc::now().timestamp() as u64;
            claims.issued_at = Some(JwtDuration::from_secs(now - ago - 3600));
            claims.expires_at = Some(JwtDuration::from_secs(now - ago));
        }
        self.key.sign(claims).expect("sign test ID token")
    }
}

/// A change that makes an otherwise valid token invalid.
type TokenMutation = Box<dyn Fn(&mut TokenSpec)>;

fn unique(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4().simple())
}

fn gmail() -> String {
    format!("{}@gmail.com", unique("social"))
}

async fn insert_password_user(pool: &PgPool, email: &str, verified: bool) -> String {
    let pubkey = Keys::generate().public_key().to_hex();
    insert_password_user_as(pool, &pubkey, email, verified).await;
    pubkey
}

async fn insert_password_user_as(pool: &PgPool, pubkey: &str, email: &str, verified: bool) {
    let password_hash = bcrypt::hash("correct horse battery staple", 4).unwrap();
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
         VALUES ($1, 1, $2, $3, $4, NOW(), NOW())",
    )
    .bind(pubkey)
    .bind(email)
    .bind(password_hash)
    .bind(verified)
    .execute(pool)
    .await
    .expect("insert password user");
}

async fn identity_count(pool: &PgPool, pubkey: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM user_identities WHERE user_pubkey = $1")
        .bind(pubkey)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn latest_event(pool: &PgPool, email: &str) -> (String, Option<String>, Option<i32>) {
    sqlx::query_as(
        "SELECT outcome, reason_code, http_status FROM auth_events
         WHERE tenant_id = 1 AND endpoint = '/api/headless/social-login' AND email = $1
         ORDER BY occurred_at DESC, id DESC LIMIT 1",
    )
    .bind(email)
    .fetch_one(pool)
    .await
    .expect("social-login auth event")
}

// ============================================================================
// Account resolution
// ============================================================================

#[tokio::test]
async fn new_google_user_gets_an_account_and_a_code_that_exchanges() {
    std::env::set_var("BUNKER_RELAYS", "wss://relay.example.test");
    let ctx = context().await;
    let email = gmail();
    let nonce = unique("nonce");
    let id_token = TokenSpec::google(&unique("google-sub"), &email.to_uppercase(), &nonce).sign();

    let (status, body) = ctx.post(request("google", &id_token, &nonce)).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["success"], true);
    assert_eq!(body["created"], true);
    assert_eq!(body["state"], "state-123");
    let pubkey = body["pubkey"].as_str().unwrap().to_string();
    assert_eq!(pubkey.len(), 64);

    let (stored_email, password_hash, verified): (String, Option<String>, bool) =
        sqlx::query_as("SELECT email, password_hash, email_verified FROM users WHERE pubkey = $1")
            .bind(&pubkey)
            .fetch_one(&ctx.pool)
            .await
            .unwrap();
    assert_eq!(stored_email, email, "email is stored normalized");
    assert!(password_hash.is_none());
    assert!(verified);
    assert_eq!(
        UserIdentityRepository::new(ctx.pool.clone())
            .providers_for_user(1, &pubkey)
            .await
            .unwrap(),
        vec!["google".to_string()]
    );
    assert_eq!(latest_event(&ctx.pool, &email).await.0, "success");

    // The code behaves exactly like a password-login code at the token endpoint.
    let response = match token(
        tenant(),
        State(ctx.auth_state.clone()),
        Extension(common::test_email_sender()),
        TokenRequestBody(TokenRequest {
            grant_type: Some("authorization_code".to_string()),
            code: Some(body["code"].as_str().unwrap().to_string()),
            client_id: CLIENT_ID.to_string(),
            redirect_uri: Some(REDIRECT_URI.to_string()),
            code_verifier: Some(CODE_VERIFIER.to_string()),
            refresh_token: None,
        }),
    )
    .await
    {
        Ok(response) => response,
        Err(error) => error.into_response(),
    };
    let exchange_status = response.status();
    let exchange = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let exchange: serde_json::Value = serde_json::from_slice(&exchange).unwrap();

    ctx.cleanup().await;
    assert_eq!(exchange_status, StatusCode::OK, "{exchange}");
    assert!(exchange["bunker_url"].is_string(), "{exchange}");
    assert!(exchange["access_token"].is_string(), "{exchange}");
}

#[tokio::test]
async fn returning_identity_signs_in_to_the_same_account() {
    let ctx = context().await;
    let subject = unique("apple-sub");
    let email = format!("{}@privaterelay.appleid.com", unique("relay"));

    let first_nonce = unique("nonce");
    let first = TokenSpec::apple(&subject, &email, &first_nonce).sign();
    let (status, created) = ctx.post(request("apple", &first, &first_nonce)).await;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert_eq!(created["created"], true);

    // Apple omits the email on later sign-ins with some flows; the subject is what matters.
    let second_nonce = unique("nonce");
    let mut second = TokenSpec::apple(&subject, &email, &second_nonce);
    second.claims.email = None;
    let (status, again) = ctx
        .post(request("apple", &second.sign(), &second_nonce))
        .await;

    ctx.cleanup().await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(again["created"], false);
    assert_eq!(again["pubkey"], created["pubkey"]);
}

#[tokio::test]
async fn gmail_address_links_to_the_verified_password_account() {
    let ctx = context().await;
    let email = gmail();
    let existing = insert_password_user(&ctx.pool, &email, true).await;
    ctx.track(&existing);
    let nonce = unique("nonce");
    let token = TokenSpec::google(&unique("google-sub"), &email, &nonce).sign();

    let (status, body) = ctx.post(request("google", &token, &nonce)).await;
    let notified = ctx
        .email_sender
        .get_captured_emails()
        .into_iter()
        .any(|captured| captured.to == email && captured.subject.contains("Google"));

    let identities = identity_count(&ctx.pool, &existing).await;
    ctx.cleanup().await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["pubkey"], existing.as_str());
    assert_eq!(body["created"], false);
    assert_eq!(identities, 1);
    assert!(
        notified,
        "the account owner is told about the new sign-in method"
    );
}

#[tokio::test]
async fn workspace_domain_links_through_the_hd_claim() {
    let ctx = context().await;
    let email = format!("{}@company.example", unique("worker"));
    let existing = insert_password_user(&ctx.pool, &email, true).await;
    ctx.track(&existing);
    let nonce = unique("nonce");
    let mut spec = TokenSpec::google(&unique("google-sub"), &email, &nonce);
    spec.claims.hd = Some("company.example".to_string());

    let (status, body) = ctx.post(request("google", &spec.sign(), &nonce)).await;

    ctx.cleanup().await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["pubkey"], existing.as_str());
}

#[tokio::test]
async fn apple_verified_email_links_to_the_verified_account() {
    let ctx = context().await;
    let email = format!("{}@icloud.example", unique("apple"));
    let existing = insert_password_user(&ctx.pool, &email, true).await;
    ctx.track(&existing);
    let nonce = unique("nonce");
    let token = TokenSpec::apple(&unique("apple-sub"), &email, &nonce).sign();

    let (status, body) = ctx.post(request("apple", &token, &nonce)).await;

    ctx.cleanup().await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["pubkey"], existing.as_str());
    assert_eq!(body["created"], false);
}

#[tokio::test]
async fn google_address_on_another_domain_needs_a_manual_link() {
    let ctx = context().await;
    let email = format!("{}@yahoo.example", unique("personal"));
    let existing = insert_password_user(&ctx.pool, &email, true).await;
    ctx.track(&existing);
    let nonce = unique("nonce");
    let token = TokenSpec::google(&unique("google-sub"), &email, &nonce).sign();

    let (status, body) = ctx.post(request("google", &token, &nonce)).await;

    let identities = identity_count(&ctx.pool, &existing).await;
    let event = latest_event(&ctx.pool, &email).await;
    ctx.cleanup().await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "ACCOUNT_LINK_REQUIRED");
    assert_eq!(identities, 0);
    assert_eq!(
        event,
        (
            "failure".to_string(),
            Some("account_link_required".to_string()),
            Some(409)
        )
    );
}

/// Links an unconfirmed sign-up still holds, as they would be after registering and starting an
/// email change and a password reset.
struct PendingLinks {
    verification: String,
    reset: String,
    email_change: String,
}

async fn give_pending_links(pool: &PgPool, pubkey: &str) -> PendingLinks {
    let links = PendingLinks {
        verification: unique("verify"),
        reset: unique("reset"),
        email_change: unique("change"),
    };
    sqlx::query(
        "UPDATE users SET
             email_verification_token = $2,
             email_verification_expires_at = NOW() + INTERVAL '1 day',
             email_verification_sent_at = NOW(),
             password_reset_token = $3,
             password_reset_expires_at = NOW() + INTERVAL '1 hour',
             pending_email = $4,
             pending_email_new_token = $5,
             pending_email_old_token = $6,
             pending_email_expires_at = NOW() + INTERVAL '1 day',
             pending_email_sent_at = NOW(),
             email_marketing_consent = 'opted_in',
             email_marketing_consent_at = NOW()
         WHERE pubkey = $1",
    )
    .bind(pubkey)
    .bind(&links.verification)
    .bind(&links.reset)
    .bind(format!("{}@example.com", unique("next")))
    .bind(&links.email_change)
    .bind(unique("old-side"))
    .execute(pool)
    .await
    .expect("give pending links");
    links
}

/// Whether a JSON handler answered with a 2xx status.
fn succeeded<T: IntoResponse, E: IntoResponse>(result: Result<T, E>) -> bool {
    match result {
        Ok(response) => response.into_response().status().is_success(),
        Err(error) => error.into_response().status().is_success(),
    }
}

#[tokio::test]
async fn an_unconfirmed_account_gives_up_its_email_to_a_new_account() {
    let ctx = context().await;
    let email = gmail();
    let unconfirmed = insert_password_user(&ctx.pool, &email, false).await;
    ctx.track(&unconfirmed);
    let links = give_pending_links(&ctx.pool, &unconfirmed).await;
    let nonce = unique("nonce");
    let token = TokenSpec::google(&unique("google-sub"), &email, &nonce).sign();

    let (status, body) = ctx.post(request("google", &token, &nonce)).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["created"], true);
    let pubkey = body["pubkey"].as_str().unwrap().to_string();
    assert_ne!(pubkey, unconfirmed);

    // The new account holds the address; the unconfirmed row stays, with no email and no links.
    let new_email: Option<String> = sqlx::query_scalar("SELECT email FROM users WHERE pubkey = $1")
        .bind(&pubkey)
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
    #[allow(clippy::type_complexity)]
    let old: (
        Option<String>,
        bool,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        bool,
    ) = sqlx::query_as(
        "SELECT email, COALESCE(email_verified, false), email_verification_token,
                password_reset_token, pending_email, pending_email_new_token,
                pending_email_old_token, password_hash IS NOT NULL
         FROM users WHERE pubkey = $1",
    )
    .bind(&unconfirmed)
    .fetch_one(&ctx.pool)
    .await
    .expect("the unconfirmed row is kept");
    let event: (String, Option<String>, serde_json::Value) = sqlx::query_as(
        "SELECT outcome, reason_code, metadata_json FROM auth_events
         WHERE tenant_id = 1 AND endpoint = '/api/headless/social-login' AND email = $1
         ORDER BY occurred_at DESC, id DESC LIMIT 1",
    )
    .bind(&email)
    .fetch_one(&ctx.pool)
    .await
    .expect("social-login auth event");
    let marketing_tombstones: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM email_marketing_deletions WHERE email = $1")
            .bind(&email)
            .fetch_one(&ctx.pool)
            .await
            .unwrap();

    // The links sent to the address before can no longer act on either account.
    let verified = succeeded(
        verify_email(
            tenant(),
            State(ctx.auth_state.clone()),
            HeaderMap::new(),
            Json(VerifyEmailRequest {
                token: links.verification.clone(),
            }),
        )
        .await,
    );
    let reset = succeeded(
        reset_password(
            tenant(),
            State(ctx.auth_state.clone()),
            HeaderMap::new(),
            Json(ResetPasswordRequest {
                token: links.reset.clone(),
                new_password: "a brand new passphrase 123".to_string(),
            }),
        )
        .await,
    );
    let email_changed = succeeded(
        confirm_email_change(
            tenant(),
            State(ctx.pool.clone()),
            HeaderMap::new(),
            Json(ConfirmEmailChangeRequest {
                token: links.email_change.clone(),
            }),
        )
        .await,
    );
    let old_row_verified: bool =
        sqlx::query_scalar("SELECT COALESCE(email_verified, false) FROM users WHERE pubkey = $1")
            .bind(&unconfirmed)
            .fetch_one(&ctx.pool)
            .await
            .unwrap();

    sqlx::query("DELETE FROM email_marketing_deletions WHERE email = $1")
        .bind(&email)
        .execute(&ctx.pool)
        .await
        .unwrap();
    ctx.cleanup().await;
    assert_eq!(new_email.as_deref(), Some(email.as_str()));
    assert_eq!(old.0, None, "email removed");
    assert!(!old.1, "still unconfirmed");
    assert_eq!(
        (&old.2, &old.3, &old.4, &old.5, &old.6),
        (&None, &None, &None, &None, &None),
        "verification, reset and email-change links cleared"
    );
    assert!(old.7, "the row itself is kept as it was");
    assert_eq!(event.0, "success");
    assert_eq!(event.1.as_deref(), Some("unconfirmed_email_released"));
    assert_eq!(
        event.2["released_unconfirmed_accounts"],
        serde_json::json!([unconfirmed])
    );
    assert_eq!(
        marketing_tombstones, 1,
        "an opted-in address no account holds any more is removed from the email platform"
    );
    assert!(!verified, "old verification link");
    assert!(!reset, "old password reset link");
    assert!(!email_changed, "old email change link");
    assert!(
        !old_row_verified,
        "the verification link did not confirm the old row"
    );
}

#[tokio::test]
async fn a_confirmed_account_beside_unconfirmed_case_variants_still_links() {
    let ctx = context().await;
    let local = unique("variants");
    let lower = format!("{local}@gmail.com");
    let upper = format!("{}@gmail.com", local.to_uppercase());
    let confirmed = insert_password_user(&ctx.pool, &lower, true).await;
    let unconfirmed = insert_password_user(&ctx.pool, &upper, false).await;
    ctx.track(&confirmed);
    ctx.track(&unconfirmed);
    let nonce = unique("nonce");
    let token = TokenSpec::google(&unique("google-sub"), &lower, &nonce).sign();

    let (status, body) = ctx.post(request("google", &token, &nonce)).await;

    let unconfirmed_email: Option<String> =
        sqlx::query_scalar("SELECT email FROM users WHERE pubkey = $1")
            .bind(&unconfirmed)
            .fetch_one(&ctx.pool)
            .await
            .unwrap();
    ctx.cleanup().await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["pubkey"], confirmed.as_str());
    assert_eq!(body["created"], false);
    // Linking takes nothing from anyone; only creating an account releases an address.
    assert_eq!(unconfirmed_email.as_deref(), Some(upper.as_str()));
}

#[tokio::test]
async fn an_account_confirmed_meanwhile_keeps_its_email_and_is_linked() {
    let ctx = context().await;
    let email = gmail();
    let account = insert_password_user(&ctx.pool, &email, false).await;
    ctx.track(&account);

    // The owner confirms between the decision to create and the transaction that would create:
    // the transaction sees the confirmed row and leaves it alone.
    sqlx::query("UPDATE users SET email_verified = true WHERE pubkey = $1")
        .bind(&account)
        .execute(&ctx.pool)
        .await
        .unwrap();
    let keys = Keys::generate();
    let late = UserIdentityRepository::new(ctx.pool.clone())
        .create_account(NewSocialAccount {
            tenant_id: 1,
            pubkey: &keys.public_key().to_hex(),
            email: &email,
            encrypted_secret: &keys.secret_key().to_secret_bytes(),
            provider: SocialProvider::Google,
            subject: &unique("google-sub"),
        })
        .await
        .expect("create account");
    let kept: Option<String> = sqlx::query_scalar("SELECT email FROM users WHERE pubkey = $1")
        .bind(&account)
        .fetch_one(&ctx.pool)
        .await
        .unwrap();

    // Resolving again, as the sign-in does after EmailTaken, links to the confirmed account.
    let nonce = unique("nonce");
    let token = TokenSpec::google(&unique("google-sub"), &email, &nonce).sign();
    let (status, body) = ctx.post(request("google", &token, &nonce)).await;

    ctx.cleanup().await;
    assert_eq!(late, CreateSocialAccountOutcome::EmailTaken);
    assert_eq!(kept.as_deref(), Some(email.as_str()));
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["pubkey"], account.as_str());
    assert_eq!(body["created"], false);
}

#[tokio::test]
async fn confirmed_case_variants_of_one_address_are_refused() {
    let ctx = context().await;
    let local = unique("twins");
    let lower = format!("{local}@gmail.com");
    let upper = format!("{}@gmail.com", local.to_uppercase());
    let first = insert_password_user(&ctx.pool, &lower, true).await;
    let second = insert_password_user(&ctx.pool, &upper, true).await;
    ctx.track(&first);
    ctx.track(&second);
    let nonce = unique("nonce");
    let token = TokenSpec::google(&unique("google-sub"), &lower, &nonce).sign();

    let (status, body) = ctx.post(request("google", &token, &nonce)).await;

    ctx.cleanup().await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "ACCOUNT_LINK_REQUIRED");
}

#[tokio::test]
async fn missing_or_unverified_provider_email_is_refused() {
    let ctx = context().await;

    let nonce = unique("nonce");
    let mut missing = TokenSpec::apple(&unique("apple-sub"), "unused@example.com", &nonce);
    missing.claims.email = None;
    let (status, body) = ctx.post(request("apple", &missing.sign(), &nonce)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "EMAIL_MISSING");

    let nonce = unique("nonce");
    let email = gmail();
    let mut unverified = TokenSpec::google(&unique("google-sub"), &email, &nonce);
    unverified.claims.email_verified = Some(serde_json::json!(false));
    let (status, body) = ctx
        .post(request("google", &unverified.sign(), &nonce))
        .await;
    let created: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE LOWER(email) = $1")
        .bind(&email)
        .fetch_one(&ctx.pool)
        .await
        .unwrap();

    ctx.cleanup().await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "EMAIL_NOT_VERIFIED");
    assert_eq!(created, 0);
}

#[tokio::test]
async fn concurrent_first_sign_ins_with_one_email_share_one_account() {
    let ctx = context().await;
    let email = gmail();
    // Distinct provider accounts (e.g. Apple and Google) racing on the same address.
    let requests: Vec<(String, String)> = (0..4)
        .map(|_| {
            let nonce = unique("nonce");
            (
                TokenSpec::google(&unique("google-sub"), &email, &nonce).sign(),
                nonce,
            )
        })
        .collect();

    let results = futures_util::future::join_all(
        requests
            .iter()
            .map(|(id_token, nonce)| ctx.post(request("google", id_token, nonce))),
    )
    .await;

    let accounts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE LOWER(email) = $1")
        .bind(&email)
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
    let created = results
        .iter()
        .filter(|(_, body)| body["created"] == true)
        .count();
    ctx.cleanup().await;
    assert!(
        results.iter().all(|(status, _)| *status == StatusCode::OK),
        "{results:?}"
    );
    assert_eq!(accounts, 1, "{results:?}");
    assert_eq!(created, 1, "{results:?}");
    let pubkeys: std::collections::HashSet<_> = results
        .iter()
        .map(|(_, body)| body["pubkey"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(pubkeys.len(), 1, "{results:?}");
}

#[tokio::test]
async fn one_provider_account_gets_one_attempt_at_a_time() {
    let ctx = context().await;
    let subject = unique("google-sub");
    let email = gmail();
    let requests: Vec<(String, String)> = (0..4)
        .map(|_| {
            let nonce = unique("nonce");
            (TokenSpec::google(&subject, &email, &nonce).sign(), nonce)
        })
        .collect();

    let results = futures_util::future::join_all(
        requests
            .iter()
            .map(|(id_token, nonce)| ctx.post(request("google", id_token, nonce))),
    )
    .await;

    let accounts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE LOWER(email) = $1")
        .bind(&email)
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
    ctx.cleanup().await;
    assert_eq!(accounts, 1, "{results:?}");
    // Requests that lose the per-subject slot are told to retry, never given another account.
    assert!(
        results.iter().all(
            |(status, _)| *status == StatusCode::OK || *status == StatusCode::TOO_MANY_REQUESTS
        ),
        "{results:?}"
    );
}

// ============================================================================
// Token verification
// ============================================================================

#[tokio::test]
async fn tokens_failing_any_check_are_rejected_as_invalid() {
    let ctx = context().await;
    let email = gmail();

    let mut cases: Vec<(&str, &str, TokenMutation)> = vec![
        (
            "wrong issuer",
            "google",
            Box::new(|spec| spec.issuer = "https://accounts.evil.example".to_string()),
        ),
        (
            "wrong audience",
            "google",
            Box::new(|spec| spec.audience = "someone-else.apps.googleusercontent.com".to_string()),
        ),
        (
            "unknown authorized party",
            "google",
            Box::new(|spec| spec.claims.azp = Some("other.apps.googleusercontent.com".to_string())),
        ),
        (
            "missing authorized party",
            "google",
            Box::new(|spec| spec.claims.azp = None),
        ),
        (
            "expired",
            "google",
            Box::new(|spec| spec.expires_ago_secs = Some(600)),
        ),
        (
            "signed by another key",
            "google",
            Box::new(|spec| spec.key = other_signing_key()),
        ),
        (
            "nonce of another request",
            "google",
            Box::new(|spec| spec.nonce = Some(sha256_hex("another-nonce"))),
        ),
        (
            "raw nonce instead of its hash",
            "google",
            Box::new(|spec| spec.nonce = None),
        ),
        ("Google token sent as Apple", "apple", Box::new(|_| {})),
    ];

    for (name, provider, mutate) in cases.drain(..) {
        let nonce = unique("nonce");
        let mut spec = TokenSpec::google(&unique("google-sub"), &email, &nonce);
        mutate(&mut spec);
        let (status, body) = ctx.post(request(provider, &spec.sign(), &nonce)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{name}: {body}");
        assert_eq!(body["code"], "INVALID_TOKEN", "{name}: {body}");
    }

    let (status, body) = ctx.post(request("google", "not-a-jwt", "nonce")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    let accounts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE LOWER(email) = $1")
        .bind(&email)
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
    assert_eq!(accounts, 0, "no rejected token may create an account");
}

#[tokio::test]
async fn a_token_is_accepted_only_once() {
    let ctx = context().await;
    let email = gmail();
    let nonce = unique("nonce");
    let token = TokenSpec::google(&unique("google-sub"), &email, &nonce).sign();

    let (first_status, first) = ctx.post(request("google", &token, &nonce)).await;
    let (replay_status, replay) = ctx.post(request("google", &token, &nonce)).await;
    let event = latest_event(&ctx.pool, &email).await;

    ctx.cleanup().await;
    assert_eq!(first_status, StatusCode::OK, "{first}");
    assert_eq!(replay_status, StatusCode::UNAUTHORIZED, "{replay}");
    assert_eq!(replay["code"], "INVALID_TOKEN");
    assert_eq!(event.1.as_deref(), Some("replayed_token"));
}

#[tokio::test]
async fn without_shared_replay_storage_sign_in_fails_closed() {
    let ctx = context_with(Arc::new(StubJwks::new(jwks_for(signing_key()))), false).await;
    let nonce = unique("nonce");
    let token = TokenSpec::google(&unique("google-sub"), &gmail(), &nonce).sign();

    let (status, body) = ctx.post(request("google", &token, &nonce)).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["code"], "SERVICE_UNAVAILABLE");
}

#[tokio::test]
async fn provider_keys_are_cached_and_kept_through_an_outage() {
    let jwks = Arc::new(StubJwks::new(jwks_for(signing_key())));
    let ctx = context_with(jwks.clone(), true).await;
    let verifier = SocialIdentityVerifier::new(settings(), jwks.clone())
        .with_jwks_timing(std::time::Duration::ZERO, std::time::Duration::ZERO);

    let nonce = unique("nonce");
    let token = TokenSpec::google(&unique("google-sub"), &gmail(), &nonce).sign();
    verifier
        .verify(SocialProvider::Google, SignInChannel::App, &token, &nonce)
        .await
        .expect("first verification fetches keys");
    assert_eq!(jwks.calls.load(Ordering::SeqCst), 1);

    // Keys are stale (TTL zero) and the provider is down: the known key keeps working.
    jwks.failing.store(true, Ordering::SeqCst);
    verifier
        .verify(SocialProvider::Google, SignInChannel::App, &token, &nonce)
        .await
        .expect("stale keys survive a failed refresh");
    assert_eq!(jwks.calls.load(Ordering::SeqCst), 2);

    // With the default timing, one fetch serves many requests.
    let calls_before = ctx.jwks.calls.load(Ordering::SeqCst);
    ctx.jwks.failing.store(false, Ordering::SeqCst);
    for _ in 0..3 {
        let nonce = unique("nonce");
        let token = TokenSpec::google(&unique("google-sub"), &gmail(), &nonce).sign();
        ctx.providers
            .verifier
            .verify(SocialProvider::Google, SignInChannel::App, &token, &nonce)
            .await
            .unwrap();
    }
    assert_eq!(ctx.jwks.calls.load(Ordering::SeqCst), calls_before + 1);
}

#[tokio::test]
async fn unreachable_provider_without_cached_keys_is_unavailable() {
    let jwks = Arc::new(StubJwks::new(jwks_for(signing_key())));
    jwks.failing.store(true, Ordering::SeqCst);
    let ctx = context_with(jwks, true).await;
    let nonce = unique("nonce");
    let token = TokenSpec::google(&unique("google-sub"), &gmail(), &nonce).sign();

    let (status, body) = ctx.post(request("google", &token, &nonce)).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["code"], "PROVIDER_UNAVAILABLE");
}

#[tokio::test]
async fn unconfigured_provider_is_unavailable() {
    let mut ctx = context().await;
    let mut google_only = settings();
    google_only.apple = None;
    ctx.providers = Arc::new(SocialLoginProviders::new(
        SocialIdentityVerifier::new(google_only, ctx.jwks.clone()),
        None,
    ));
    let nonce = unique("nonce");
    let token = TokenSpec::apple(&unique("apple-sub"), &gmail(), &nonce).sign();

    let (status, body) = ctx.post(request("apple", &token, &nonce)).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["code"], "PROVIDER_UNAVAILABLE");
}

#[tokio::test]
async fn malformed_requests_are_invalid_requests() {
    let ctx = context().await;
    let nonce = unique("nonce");
    let token = TokenSpec::google(&unique("google-sub"), &gmail(), &nonce).sign();

    let mut unknown_provider = request("facebook", &token, &nonce);
    let mut plain_pkce = request("google", &token, &nonce);
    plain_pkce["code_challenge_method"] = serde_json::json!("plain");
    let mut no_pkce = request("google", &token, &nonce);
    no_pkce.as_object_mut().unwrap().remove("code_challenge");
    let mut bad_redirect = request("google", &token, &nonce);
    bad_redirect["redirect_uri"] = serde_json::json!("not a url");
    let mut unknown_policy = request("google", &token, &nonce);
    unknown_policy["scope"] = serde_json::json!("policy:does-not-exist");
    unknown_provider["provider"] = serde_json::json!("facebook");

    for body in [
        unknown_provider,
        plain_pkce,
        no_pkce,
        bad_redirect,
        unknown_policy,
    ] {
        let (status, response) = ctx.post(body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body} -> {response}");
        assert_eq!(response["code"], "INVALID_REQUEST", "{body} -> {response}");
    }

    let (status, response) = ctx.post_raw("{\"provider\":\"google\"}".to_string()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(response["code"], "INVALID_REQUEST");
}

// ============================================================================
// Accounts without a password
// ============================================================================

async fn create_social_account(ctx: &Context) -> (String, String) {
    let email = gmail();
    let nonce = unique("nonce");
    let token = TokenSpec::google(&unique("google-sub"), &email, &nonce).sign();
    let (status, body) = ctx.post(request("google", &token, &nonce)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    (body["pubkey"].as_str().unwrap().to_string(), email)
}

#[tokio::test]
async fn cleanup_keeps_accounts_that_sign_in_through_a_provider() {
    let ctx = context().await;
    let (social_pubkey, _) = create_social_account(&ctx).await;
    let legacy_pubkey = Keys::generate().public_key().to_hex();
    ctx.track(&legacy_pubkey);
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, created_at, updated_at)
         VALUES ($1, 1, $2, NOW() - INTERVAL '1 hour', NOW())",
    )
    .bind(&legacy_pubkey)
    .bind(format!("{}@example.com", unique("legacy")))
    .execute(&ctx.pool)
    .await
    .unwrap();
    sqlx::query("UPDATE users SET created_at = NOW() - INTERVAL '1 hour' WHERE pubkey = $1")
        .bind(&social_pubkey)
        .execute(&ctx.pool)
        .await
        .unwrap();

    delete_legacy_stale_signup_rows(&ctx.pool).await.unwrap();

    let repo = UserRepository::new(ctx.pool.clone());
    let social_exists = repo.exists(&social_pubkey, 1).await.unwrap();
    let legacy_exists = repo.exists(&legacy_pubkey, 1).await.unwrap();
    ctx.cleanup().await;
    assert!(social_exists, "a Google-only account must survive cleanup");
    assert!(
        !legacy_exists,
        "an abandoned legacy signup row is still removed"
    );
}

/// Bearer token signed with the account's own key, as the apps hold after a token exchange.
async fn bearer_for(pool: &PgPool, pubkey: &str) -> String {
    // TestKeyManager stores keys in the clear, so the custodial key can be read back.
    let secret: Vec<u8> =
        sqlx::query_scalar("SELECT encrypted_secret_key FROM personal_keys WHERE user_pubkey = $1")
            .bind(pubkey)
            .fetch_one(pool)
            .await
            .expect("personal key");
    let keys = Keys::new(nostr_sdk::SecretKey::from_slice(&secret).expect("secret key"));
    assert_eq!(keys.public_key().to_hex(), pubkey);
    let ucan = UcanBuilder::default()
        .issued_by(&NostrKeyMaterial::from_keys(keys.clone()))
        .for_audience(&nostr_pubkey_to_did(&keys.public_key()))
        .with_lifetime(3600)
        .with_fact(serde_json::json!({
            "tenant_id": 1,
            "email": "social-login@example.com",
            "redirect_origin": "https://login.divine.video",
        }))
        .build()
        .expect("build UCAN")
        .sign()
        .await
        .expect("sign UCAN");
    format!("Bearer {}", ucan.encode().expect("encode UCAN"))
}

async fn json_of(response: axum::response::Response) -> (StatusCode, serde_json::Value) {
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn password_operations_report_password_not_set() {
    let ctx = context().await;
    let (pubkey, _) = create_social_account(&ctx).await;
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        bearer_for(&ctx.pool, &pubkey).await.parse().unwrap(),
    );
    headers.insert("host", "localhost".parse().unwrap());

    let change = change_password(
        tenant(),
        State(ctx.pool.clone()),
        Extension(ctx.auth_state.state.bcrypt.clone()),
        headers.clone(),
        Json(ChangePasswordRequest {
            current_password: "anything".to_string(),
            new_password: "a brand new passphrase".to_string(),
        }),
    )
    .await
    .map(IntoResponse::into_response)
    .unwrap_or_else(IntoResponse::into_response);
    let export = export_key(
        tenant(),
        State(ctx.auth_state.clone()),
        headers,
        Json(serde_json::json!({"password": "anything"})),
    )
    .await
    .map(IntoResponse::into_response)
    .unwrap_or_else(IntoResponse::into_response);

    let (change_status, change_body) = json_of(change).await;
    let (export_status, export_body) = json_of(export).await;
    ctx.cleanup().await;
    assert_eq!(change_status, StatusCode::CONFLICT, "{change_body}");
    assert_eq!(change_body["code"], "PASSWORD_NOT_SET");
    assert_eq!(export_status, StatusCode::CONFLICT, "{export_body}");
    assert_eq!(export_body["code"], "PASSWORD_NOT_SET");
}

#[tokio::test]
async fn deleting_the_account_removes_its_provider_links() {
    let ctx = context().await;
    let (pubkey, _) = create_social_account(&ctx).await;
    assert_eq!(identity_count(&ctx.pool, &pubkey).await, 1);

    UserRepository::new(ctx.pool.clone())
        .delete_account(&pubkey, 1)
        .await
        .expect("delete account");

    let remaining = identity_count(&ctx.pool, &pubkey).await;
    ctx.cleanup().await;
    assert_eq!(remaining, 0);
}

#[tokio::test]
async fn apple_sign_in_stores_a_verified_exchanged_grant() {
    use jwt_simple::prelude::{ECDSAP256KeyPairLike, ES256KeyPair};
    use keycast_api::social_identity::{AppleSigningKey, AppleTokenClient};
    use secrecy::SecretString;

    let mut ctx = context().await;
    let subject = unique("apple-sub");
    let nonce = unique("nonce");
    let email = gmail();
    let id_token = TokenSpec::apple(&subject, &email, &nonce).sign();
    let mut grant = TokenSpec::apple(&subject, &email, &nonce);
    grant.nonce = None;
    let grant_id = grant.sign();
    let endpoint =
        Router::new().route(
            "/token",
            post(move || {
                let grant_id = grant_id.clone();
                async move {
                    Json(serde_json::json!({"id_token": grant_id, "refresh_token": "fixture"}))
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, endpoint).await.unwrap() });
    let mut config = settings();
    config.apple_signing_key = Some(AppleSigningKey {
        team_id: "fixture-team".into(),
        key_id: "fixture-key".into(),
        private_key_pem: SecretString::from(ES256KeyPair::generate().to_pem().unwrap()),
    });
    let exchange = AppleTokenClient::from_settings(&config)
        .unwrap()
        .with_token_url(format!("http://{address}/token"));
    ctx.providers = Arc::new(SocialLoginProviders::new(
        SocialIdentityVerifier::new(config, ctx.jwks.clone()),
        Some(exchange),
    ));
    let mut payload = request("apple", &id_token, &nonce);
    payload["authorization_code"] = serde_json::json!("fixture-code");
    let (status, body) = ctx.post(payload).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let pubkey = body["pubkey"].as_str().unwrap();
    ctx.track(pubkey);
    let client: String = sqlx::query_scalar(
        "SELECT grant_row.client_id FROM apple_identity_grants grant_row
         JOIN user_identities identity ON grant_row.identity_id = identity.id
         WHERE identity.user_pubkey = $1",
    )
    .bind(pubkey)
    .fetch_one(&ctx.pool)
    .await
    .unwrap();
    assert_eq!(client, APPLE_BUNDLE);
    ctx.cleanup().await;
    server.abort();
}

#[tokio::test]
async fn apple_account_deletion_stages_each_client_grant() {
    let ctx = context().await;
    let subject = unique("apple-sub");
    let nonce = unique("nonce");
    let token = TokenSpec::apple(&subject, &gmail(), &nonce).sign();
    let (status, body) = ctx.post(request("apple", &token, &nonce)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let pubkey = body["pubkey"].as_str().unwrap();
    ctx.track(pubkey);
    let repo = keycast_core::repositories::UserIdentityRepository::new(ctx.pool.clone());
    let native = unique("native-client");
    let hosted = unique("hosted-client");
    for client in [&native, &hosted] {
        assert!(repo
            .store_apple_refresh_token(1, &subject, pubkey, b"fixture", client)
            .await
            .unwrap());
    }
    UserRepository::new(ctx.pool.clone())
        .delete_account(pubkey, 1)
        .await
        .unwrap();
    let grants: Vec<String> = sqlx::query_scalar(
        "DELETE FROM apple_grant_revocations WHERE client_id IN ($1, $2) RETURNING client_id",
    )
    .bind(native)
    .bind(hosted)
    .fetch_all(&ctx.pool)
    .await
    .unwrap();
    assert_eq!(grants.len(), 2);
    assert_eq!(identity_count(&ctx.pool, pubkey).await, 0);
    ctx.cleanup().await;
}

#[tokio::test]
async fn changing_the_key_moves_provider_links_to_the_new_key() {
    let ctx = context().await;
    let email = gmail();
    let old_pubkey = insert_password_user(&ctx.pool, &email, true).await;
    ctx.track(&old_pubkey);
    let subject = unique("google-sub");
    let nonce = unique("nonce");
    let token = TokenSpec::google(&subject, &email, &nonce).sign();
    let (status, body) = ctx.post(request("google", &token, &nonce)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["pubkey"], old_pubkey.as_str());

    let new_keys = Keys::generate();
    let new_pubkey = new_keys.public_key().to_hex();
    ctx.track(&new_pubkey);
    UserRepository::new(ctx.pool.clone())
        .change_key_transaction(
            &old_pubkey,
            &new_pubkey,
            1,
            &email,
            "hash",
            &new_keys.secret_key().to_secret_bytes(),
        )
        .await
        .expect("change key");

    let nonce = unique("nonce");
    let token = TokenSpec::google(&subject, &email, &nonce).sign();
    let (status, after) = ctx.post(request("google", &token, &nonce)).await;

    ctx.cleanup().await;
    assert_eq!(status, StatusCode::OK, "{after}");
    assert_eq!(after["pubkey"], new_pubkey.as_str());
    assert_eq!(after["created"], false);
}

// ============================================================================
// Hosted login page (GET /api/oauth/authorize, POST /api/oauth/social-login)
// ============================================================================

const NONCE_COOKIE: &str = "keycast_social_nonce";

/// A response from the login page or its sign-in endpoint.
struct WebResponse {
    status: StatusCode,
    cookies: Vec<String>,
    body: String,
}

impl WebResponse {
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or(serde_json::Value::Null)
    }

    /// Value of the named cookie this response sets, with its attributes.
    fn cookie(&self, name: &str) -> Option<&str> {
        self.cookies
            .iter()
            .map(String::as_str)
            .find(|cookie| cookie.starts_with(&format!("{name}=")))
    }

    fn cookie_value(&self, name: &str) -> Option<String> {
        let cookie = self.cookie(name)?;
        let value = cookie.split(';').next()?.split_once('=')?.1;
        Some(value.to_string())
    }
}

impl Context {
    fn web_app(&self) -> Router {
        let auth_state = self.auth_state.clone();
        let page_state = self.auth_state.clone();
        let providers = self.providers.clone();
        let page_providers = self.providers.clone();
        let email_sender: Arc<dyn EmailSender> = self.email_sender.clone();
        Router::new()
            .route(
                "/oauth/authorize",
                get(
                    move |headers: HeaderMap, Query(params): Query<AuthorizeRequest>| {
                        let auth_state = page_state.clone();
                        let providers = page_providers.clone();
                        async move {
                            match authorize_get(
                                tenant(),
                                State(auth_state),
                                Extension(providers),
                                headers,
                                Query(params),
                            )
                            .await
                            {
                                Ok(response) => response,
                                Err(error) => error.into_response(),
                            }
                        }
                    },
                ),
            )
            .route(
                "/oauth/social-login",
                post(
                    move |headers: HeaderMap,
                          payload: Result<Json<WebSocialLoginRequest>, JsonRejection>| {
                        let auth_state = auth_state.clone();
                        let providers = providers.clone();
                        let email_sender = email_sender.clone();
                        async move {
                            match web_social_login(
                                tenant(),
                                State(auth_state),
                                Extension(providers),
                                Extension(email_sender),
                                headers,
                                payload,
                            )
                            .await
                            {
                                Ok(response) => response,
                                Err(error) => error.into_response(),
                            }
                        }
                    },
                ),
            )
    }

    async fn web(&self, request: Request<Body>) -> WebResponse {
        let response = self.web_app().oneshot(request).await.unwrap();
        let status = response.status();
        let cookies = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap().to_string())
            .collect();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let response = WebResponse {
            status,
            cookies,
            body: String::from_utf8(bytes.to_vec()).unwrap(),
        };
        if let Some(pubkey) = response.json()["pubkey"].as_str() {
            self.track(pubkey);
        }
        response
    }

    /// The login page a client opens, sending `cookie` when given.
    async fn login_page(&self, query: &str, cookie: Option<&str>) -> WebResponse {
        let mut request = Request::builder()
            .method("GET")
            .uri(format!(
                "/oauth/authorize?client_id={CLIENT_ID}&redirect_uri={}&scope=policy:full{query}",
                urlencoding::encode(REDIRECT_URI)
            ))
            .header("host", "localhost");
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        self.web(request.body(Body::empty()).unwrap()).await
    }

    /// Open the login page and return the raw nonce its cookie carries.
    async fn login_page_nonce(&self) -> String {
        let page = self.login_page("", None).await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
        page.cookie_value(NONCE_COOKIE)
            .expect("the login page stores a nonce")
    }

    async fn web_sign_in(
        &self,
        provider: &str,
        id_token: &str,
        raw_nonce: Option<&str>,
    ) -> WebResponse {
        let body = serde_json::json!({
            "provider": provider,
            "id_token": id_token,
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
        });
        let mut request = Request::builder()
            .method("POST")
            .uri("/oauth/social-login")
            .header("host", "localhost")
            .header("content-type", "application/json");
        if let Some(raw_nonce) = raw_nonce {
            request = request.header(header::COOKIE, format!("{NONCE_COOKIE}={raw_nonce}"));
        }
        self.web(request.body(Body::from(body.to_string())).unwrap())
            .await
    }
}

async fn insert_personal_key(pool: &PgPool, pubkey: &str, keys: &Keys) {
    sqlx::query(
        "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id, created_at, updated_at)
         VALUES ($1, $2, 1, NOW(), NOW())",
    )
    .bind(pubkey)
    .bind(keys.secret_key().to_secret_bytes().to_vec())
    .execute(pool)
    .await
    .expect("insert personal key");
}

#[tokio::test]
async fn login_page_offers_apple_then_google_and_keeps_the_raw_nonce_in_a_cookie() {
    let ctx = context().await;

    let page = ctx.login_page("", None).await;

    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    let cookie = page.cookie(NONCE_COOKIE).expect("nonce cookie");
    for attribute in ["HttpOnly", "Secure", "SameSite=Lax", "Path=/api/oauth"] {
        assert!(cookie.contains(attribute), "{cookie}");
    }
    let raw_nonce = page.cookie_value(NONCE_COOKIE).unwrap();
    assert_eq!(raw_nonce.len(), 64);
    // The page hands Google and Apple the hash; the raw value stays in the HttpOnly cookie.
    assert!(page.body.contains(&sha256_hex(&raw_nonce)));
    assert!(!page.body.contains(&raw_nonce));
    let apple = page.body.find("id=\"apple_signin\"").expect("Apple button");
    let google = page
        .body
        .find("id=\"google_signin\"")
        .expect("Google button");
    let email_form = page.body.find("id=\"login_view\"").expect("email form");
    assert!(apple < google && google < email_form);
    assert!(page.body.contains("https://accounts.google.com/gsi/client"));
    assert!(page.body.contains("appleid.auth.js"));
    assert!(page.body.contains(APPLE_SERVICES_ID));
    assert!(page.body.contains(APPLE_WEB_RETURN_URL));

    // A second page in the same browser keeps the nonce, so either page can finish.
    let again = ctx
        .login_page("", Some(&format!("{NONCE_COOKIE}={raw_nonce}")))
        .await;
    assert_eq!(again.cookie_value(NONCE_COOKIE), Some(raw_nonce));
}

#[tokio::test]
async fn login_page_shows_only_the_configured_providers() {
    let jwks = Arc::new(StubJwks::new(jwks_for(signing_key())));
    let apps_only = SocialLoginSettings {
        google_web: None,
        apple_web: None,
        ..settings()
    };
    let ctx = context_with_settings(jwks.clone(), true, apps_only).await;
    let page = ctx.login_page("", None).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(!page.body.contains("id=\"social_signin\""));
    assert!(!page.body.contains("accounts.google.com/gsi"));
    assert!(page.cookie(NONCE_COOKIE).is_none());
    // The endpoint agrees: Google is not available on the web.
    let nonce = sha256_hex(&unique("nonce"));
    let token = TokenSpec::google_web(&unique("google-sub"), &gmail(), &nonce).sign();
    let response = ctx.web_sign_in("google", &token, Some(&nonce)).await;
    assert_eq!(
        response.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        response.body
    );
    assert_eq!(response.json()["code"], "PROVIDER_UNAVAILABLE");

    let google_only = SocialLoginSettings {
        apple_web: None,
        ..settings()
    };
    let ctx = context_with_settings(jwks, true, google_only).await;
    let page = ctx.login_page("", None).await;
    assert!(page.body.contains("id=\"google_signin\""));
    assert!(!page.body.contains("id=\"apple_signin\""));
    assert!(!page.body.contains("appleid.auth.js"));

    // A client bringing its own key registers with that key, never a provider account.
    let byok = Keys::generate().public_key().to_hex();
    let page = ctx.login_page(&format!("&byok_pubkey={byok}"), None).await;
    assert!(!page.body.contains("id=\"social_signin\""));
    assert!(page.cookie(NONCE_COOKIE).is_none());
}

#[tokio::test]
async fn google_on_the_login_page_creates_an_account_and_signs_in_like_a_password() {
    let ctx = context().await;
    let raw_nonce = ctx.login_page_nonce().await;
    let email = gmail();
    let token = TokenSpec::google_web(&unique("google-sub"), &email, &raw_nonce).sign();

    let response = ctx.web_sign_in("google", &token, Some(&raw_nonce)).await;

    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    let body = response.json();
    assert_eq!(body["success"], true);
    assert_eq!(body["created"], true);
    let pubkey = body["pubkey"].as_str().unwrap().to_string();
    // The nonce is spent; the session cookie is the one POST /api/oauth/login sets.
    assert!(response
        .cookie(NONCE_COOKIE)
        .is_some_and(|cookie| cookie.contains("Max-Age=0")));
    let session = response
        .cookie_value("keycast_session")
        .expect("session cookie");
    let (session_pubkey, redirect_origin, _, _) =
        validate_ucan_token(&format!("Bearer {session}"), 1)
            .await
            .expect("valid session UCAN");
    assert_eq!(session_pubkey, pubkey);
    assert_eq!(redirect_origin, "https://login.divine.example");
    let event: (String, Option<String>) = sqlx::query_as(
        "SELECT outcome, reason_code FROM auth_events
         WHERE tenant_id = 1 AND endpoint = '/api/oauth/social-login' AND email = $1
         ORDER BY occurred_at DESC, id DESC LIMIT 1",
    )
    .bind(&email)
    .fetch_one(&ctx.pool)
    .await
    .expect("login page auth event");

    // Reloading the authorize page with the session continues to the account chooser, exactly
    // as after a password sign-in.
    let next = ctx
        .login_page("", Some(&format!("keycast_session={session}")))
        .await;

    ctx.cleanup().await;
    assert_eq!(event, ("success".to_string(), None));
    assert_eq!(next.status, StatusCode::OK, "{}", next.body);
    assert!(
        next.body.contains("Use a different account"),
        "{}",
        next.body
    );
    assert!(next.body.contains(&email));
}

#[tokio::test]
async fn apple_on_the_login_page_reaches_the_account_the_app_uses() {
    let ctx = context().await;
    let raw_nonce = ctx.login_page_nonce().await;
    let subject = unique("apple-sub");
    let email = format!("{}@privaterelay.appleid.com", unique("relay"));
    let token = TokenSpec::apple_web(&subject, &email, &raw_nonce).sign();

    let response = ctx.web_sign_in("apple", &token, Some(&raw_nonce)).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    let web = response.json();
    assert_eq!(web["created"], true);

    // With the Services ID grouped under the app's App ID, Apple reports the same subject.
    let nonce = unique("nonce");
    let app_token = TokenSpec::apple(&subject, &email, &nonce).sign();
    let (status, app) = ctx.post(request("apple", &app_token, &nonce)).await;

    ctx.cleanup().await;
    assert_eq!(status, StatusCode::OK, "{app}");
    assert_eq!(app["pubkey"], web["pubkey"]);
    assert_eq!(app["created"], false);
}

#[tokio::test]
async fn login_page_and_app_tokens_are_not_interchangeable() {
    let ctx = context().await;
    let raw_nonce = ctx.login_page_nonce().await;

    // App-issued tokens on the login page: Google's authorized party is the iOS client, Apple's
    // audience is the bundle ID.
    for (provider, token) in [
        (
            "google",
            TokenSpec::google(&unique("google-sub"), &gmail(), &raw_nonce).sign(),
        ),
        (
            "apple",
            TokenSpec::apple(&unique("apple-sub"), &gmail(), &raw_nonce).sign(),
        ),
    ] {
        let response = ctx.web_sign_in(provider, &token, Some(&raw_nonce)).await;
        assert_eq!(
            response.status,
            StatusCode::UNAUTHORIZED,
            "{provider}: {}",
            response.body
        );
        assert_eq!(response.json()["code"], "INVALID_TOKEN");
    }

    // Login-page tokens in the app endpoint.
    for (provider, token) in [
        (
            "google",
            TokenSpec::google_web(&unique("google-sub"), &gmail(), &raw_nonce).sign(),
        ),
        (
            "apple",
            TokenSpec::apple_web(&unique("apple-sub"), &gmail(), &raw_nonce).sign(),
        ),
    ] {
        let (status, body) = ctx.post(request(provider, &token, &raw_nonce)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{provider}: {body}");
        assert_eq!(body["code"], "INVALID_TOKEN");
    }
}

#[tokio::test]
async fn login_page_sign_in_needs_the_pages_nonce_cookie() {
    let ctx = context().await;
    let raw_nonce = ctx.login_page_nonce().await;
    let token = TokenSpec::google_web(&unique("google-sub"), &gmail(), &raw_nonce).sign();

    let without_cookie = ctx.web_sign_in("google", &token, None).await;
    assert_eq!(without_cookie.status, StatusCode::BAD_REQUEST);
    assert_eq!(without_cookie.json()["code"], "INVALID_REQUEST");

    // A token minted for another page's nonce does not match this browser's cookie.
    let other_nonce = ctx.login_page_nonce().await;
    let mismatched = ctx.web_sign_in("google", &token, Some(&other_nonce)).await;
    assert_eq!(mismatched.status, StatusCode::UNAUTHORIZED);
    assert_eq!(mismatched.json()["code"], "INVALID_TOKEN");
}

#[tokio::test]
async fn login_page_links_like_the_app_and_refuses_what_the_app_refuses() {
    let ctx = context().await;
    let raw_nonce = ctx.login_page_nonce().await;

    // A verified password account on Gmail is linked, and its session is that account's.
    let email = gmail();
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    insert_password_user_as(&ctx.pool, &pubkey, &email, true).await;
    ctx.track(&pubkey);
    insert_personal_key(&ctx.pool, &pubkey, &keys).await;
    let token = TokenSpec::google_web(&unique("google-sub"), &email, &raw_nonce).sign();
    let linked = ctx.web_sign_in("google", &token, Some(&raw_nonce)).await;

    // An address on another domain stays an explicit choice, shown on the page.
    let other = format!("{}@example.com", unique("person"));
    let other_pubkey = insert_password_user(&ctx.pool, &other, true).await;
    ctx.track(&other_pubkey);
    let raw_nonce = ctx.login_page_nonce().await;
    let token = TokenSpec::google_web(&unique("google-sub"), &other, &raw_nonce).sign();
    let refused = ctx.web_sign_in("google", &token, Some(&raw_nonce)).await;
    let notified = ctx
        .email_sender
        .get_captured_emails()
        .iter()
        .any(|captured| captured.to == email && captured.subject.contains("Google"));

    ctx.cleanup().await;
    assert_eq!(linked.status, StatusCode::OK, "{}", linked.body);
    assert_eq!(linked.json()["pubkey"], pubkey.as_str());
    assert_eq!(linked.json()["created"], false);
    assert!(linked.cookie("keycast_session").is_some());
    assert!(notified, "the owner hears about the new sign-in method");
    assert_eq!(refused.status, StatusCode::CONFLICT, "{}", refused.body);
    assert_eq!(refused.json()["code"], "ACCOUNT_LINK_REQUIRED");
    assert!(refused.cookie("keycast_session").is_none());
}
