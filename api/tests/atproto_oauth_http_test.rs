mod common;

use axum::{
    body::Body,
    extract::State,
    http::{header, Request, StatusCode},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use http_body_util::BodyExt;
use keycast_api::api::http::atproto_oauth::{authorize, par, token};
use keycast_api::api::http::auth::generate_server_signed_ucan;
use nostr_sdk::{Keys, ToBech32};
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    elliptic_curve::rand_core::OsRng,
};
use serde_json::Value;
use serial_test::serial;
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use uuid::Uuid;

const TEST_ATPROTO_JWT_KEY_HEX: &str =
    "8f2a55949068468ad5d670dfd0c0a33d5b9e7e1a2c0d2059f0f8f8779d4d078d";
const TEST_ATPROTO_PDS_DID: &str = "did:web:pds.divine.test";
const TEST_SERVER_SECRET_HEX: &str =
    "7a1f55949068468ad5d670dfd0c0a33d5b9e7e1a2c0d2059f0f8f8779d4d0123";

struct DpopKeyMaterial {
    signing_key: SigningKey,
    jwk: Value,
    jkt: String,
}

struct ClientAuthKeyMaterial {
    signing_key: SigningKey,
    jwk: Value,
    jkt: String,
    kid: String,
}

fn pkce_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

fn http_uri(path: &str) -> String {
    format!("https://login.divine.video{path}")
}

fn access_token_hash(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

fn decode_jwt_payload(token: &str) -> Value {
    let payload = token.split('.').nth(1).unwrap();
    let bytes = URL_SAFE_NO_PAD.decode(payload).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn dpop_key_material() -> DpopKeyMaterial {
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let encoded_point = verifying_key.to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(encoded_point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(encoded_point.y().unwrap());
    let jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
    });
    let thumbprint_input = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    let jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(thumbprint_input.as_bytes()));

    DpopKeyMaterial {
        signing_key,
        jwk,
        jkt,
    }
}

fn client_auth_key_material() -> ClientAuthKeyMaterial {
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let encoded_point = verifying_key.to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(encoded_point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(encoded_point.y().unwrap());
    let kid = format!("kid-{}", Uuid::new_v4());
    let jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
        "kid": kid,
        "use": "sig",
        "alg": "ES256",
    });
    let thumbprint_input = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    let jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(thumbprint_input.as_bytes()));

    ClientAuthKeyMaterial {
        signing_key,
        jwk,
        jkt,
        kid,
    }
}

fn dpop_proof(
    key_material: &DpopKeyMaterial,
    method: &str,
    htu: &str,
    nonce: Option<&str>,
    ath: Option<&str>,
) -> String {
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": key_material.jwk,
    });
    let mut claims = serde_json::json!({
        "jti": format!("dpop-{}", Uuid::new_v4()),
        "htm": method,
        "htu": htu,
        "iat": chrono::Utc::now().timestamp(),
    });
    if let Some(nonce) = nonce {
        claims["nonce"] = serde_json::json!(nonce);
    }
    if let Some(ath) = ath {
        claims["ath"] = serde_json::json!(ath);
    }

    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let signature: Signature = key_material.signing_key.sign(signing_input.as_bytes());

    format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

fn private_key_jwt_assertion(
    key_material: &ClientAuthKeyMaterial,
    client_id: &str,
    aud: &str,
) -> String {
    let header = serde_json::json!({
        "typ": "JWT",
        "alg": "ES256",
        "kid": key_material.kid,
    });
    let now = chrono::Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": client_id,
        "sub": client_id,
        "aud": aud,
        "exp": now + 240,
        "iat": now,
        "jti": format!("client-assertion-{}", Uuid::new_v4()),
    });
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let signature: Signature = key_material.signing_key.sign(signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

#[derive(Clone)]
struct ConfidentialClientMetadata {
    metadata: Value,
}

async fn confidential_metadata_handler(
    State(state): State<ConfidentialClientMetadata>,
) -> Json<Value> {
    Json(state.metadata)
}

async fn start_confidential_client_metadata_server(
    redirect_uri: &str,
    key_material: &ClientAuthKeyMaterial,
    dpop_bound_access_tokens: bool,
) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client_id = format!("http://{addr}/client-metadata.json");
    let metadata = serde_json::json!({
        "client_id": client_id,
        "redirect_uris": [redirect_uri],
        "token_endpoint_auth_method": "private_key_jwt",
        "token_endpoint_auth_signing_alg": "ES256",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "dpop_bound_access_tokens": dpop_bound_access_tokens,
        "jwks": {
            "keys": [key_material.jwk.clone()]
        }
    });

    let app = Router::new()
        .route("/client-metadata.json", get(confidential_metadata_handler))
        .with_state(ConfidentialClientMetadata { metadata });
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    client_id
}

fn app(pool: sqlx::PgPool) -> Router {
    Router::new()
        .route("/atproto/oauth/par", post(par))
        .route("/atproto/oauth/authorize", get(authorize))
        .route("/atproto/oauth/token", post(token))
        .with_state(pool)
}

async fn create_test_tenant(pool: &sqlx::PgPool, domain: &str) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO tenants (domain, name, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())
         RETURNING id",
    )
    .bind(domain)
    .bind(format!("Tenant for {domain}"))
    .fetch_one(pool)
    .await
    .unwrap()
}

fn configure_atproto_env() -> Keys {
    unsafe {
        std::env::set_var("APP_URL", "https://login.divine.video");
        std::env::set_var("ALLOWED_TENANT_DOMAINS", "login.divine.video");
        std::env::remove_var("ENABLE_TENANT_AUTO_PROVISIONING");
        std::env::set_var(
            "ATPROTO_OAUTH_JWT_PRIVATE_KEY_HEX",
            TEST_ATPROTO_JWT_KEY_HEX,
        );
        std::env::set_var("ATPROTO_OAUTH_PDS_DID", TEST_ATPROTO_PDS_DID);
        std::env::set_var("BUNKER_RELAYS", "wss://relay.test.example");
    }

    let server_keys = Keys::parse(TEST_SERVER_SECRET_HEX).unwrap();
    unsafe {
        std::env::set_var("SERVER_NSEC", server_keys.secret_key().to_bech32().unwrap());
    }

    server_keys
}

#[tokio::test]
#[serial]
async fn par_authorize_and_token_exchange_with_existing_login_session() {
    let server_keys = configure_atproto_env();

    let pool = common::setup_test_db().await;
    let app = app(pool.clone());

    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();
    let user_did = "did:plc:testalice";
    let email = format!("alice-{}@example.com", Uuid::new_v4());
    let code_verifier = "pkce-verifier-1234567890";
    let code_challenge = pkce_challenge(code_verifier);
    let dpop_key = dpop_key_material();

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, email_verified, atproto_enabled, atproto_state, atproto_did, created_at, updated_at)
         VALUES ($1, 1, $2, true, true, 'ready', $3, NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(&email)
    .bind(user_did)
    .execute(&pool)
    .await
    .unwrap();

    let par_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/atproto/oauth/par")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    "DPoP",
                    dpop_proof(&dpop_key, "POST", &http_uri("/atproto/oauth/par"), None, None),
                )
                .body(Body::from(format!(
                    "client_id={}&redirect_uri={}&scope=atproto&state=csrf-123&code_challenge={}&code_challenge_method=S256",
                    urlencoding::encode("https://client.example"),
                    urlencoding::encode("https://client.example/callback"),
                    urlencoding::encode(&code_challenge),
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(par_response.status(), StatusCode::OK);
    let par_nonce = par_response
        .headers()
        .get("DPoP-Nonce")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
        .expect("PAR response should issue a DPoP nonce");
    let par_body = par_response.into_body().collect().await.unwrap().to_bytes();
    let par_payload: Value = serde_json::from_slice(&par_body).unwrap();
    let request_uri = par_payload["request_uri"].as_str().unwrap().to_string();
    let stored_jkt: Option<String> =
        sqlx::query_scalar("SELECT dpop_jkt FROM atproto_oauth_sessions WHERE request_uri = $1")
            .bind(&request_uri)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored_jkt.as_deref(), Some(dpop_key.jkt.as_str()));

    let redirect_to_login = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/atproto/oauth/authorize?request_uri={}",
                    urlencoding::encode(&request_uri)
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(redirect_to_login.status(), StatusCode::SEE_OTHER);
    assert!(redirect_to_login
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("/login?redirect="));

    let session_token = generate_server_signed_ucan(
        &user_keys.public_key(),
        1,
        &email,
        "https://login.divine.video",
        None,
        &server_keys,
        true,
        None,
        None,
    )
    .await
    .unwrap();

    let authorized = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/atproto/oauth/authorize?request_uri={}",
                    urlencoding::encode(&request_uri)
                ))
                .header(header::COOKIE, format!("keycast_session={session_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(authorized.status(), StatusCode::SEE_OTHER);
    let callback_location = authorized
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(callback_location.starts_with("https://client.example/callback?"));

    let callback_url = reqwest::Url::parse(&callback_location).unwrap();
    let code = callback_url
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.to_string())
        .unwrap();

    let token_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/atproto/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    "DPoP",
                    dpop_proof(
                        &dpop_key,
                        "POST",
                        &http_uri("/atproto/oauth/token"),
                        Some(&par_nonce),
                        None,
                    ),
                )
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={}&client_id={}&redirect_uri={}&code_verifier={}",
                    urlencoding::encode(&code),
                    urlencoding::encode("https://client.example"),
                    urlencoding::encode("https://client.example/callback"),
                    urlencoding::encode(code_verifier),
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(token_response.status(), StatusCode::OK);
    let token_nonce = token_response
        .headers()
        .get("DPoP-Nonce")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
        .expect("token response should rotate the DPoP nonce");
    let token_body = token_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let token_payload: Value = serde_json::from_slice(&token_body).unwrap();
    let access_token = token_payload["access_token"].as_str().unwrap();
    let access_payload = decode_jwt_payload(access_token);

    assert_eq!(token_payload["token_type"], "DPoP");
    assert_eq!(token_payload["scope"], "atproto");
    assert_eq!(token_payload["sub"], user_did);
    assert!(access_token.len() > 32);
    assert!(token_payload["refresh_token"].as_str().unwrap().len() > 32);
    assert_eq!(access_payload["cnf"]["jkt"], dpop_key.jkt);
    assert_ne!(token_nonce, par_nonce);
}

#[tokio::test]
#[serial]
async fn authorize_rejects_when_atproto_link_is_not_ready() {
    let server_keys = configure_atproto_env();

    let pool = common::setup_test_db().await;
    let app = app(pool.clone());

    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();
    let email = format!("pending-{}@example.com", Uuid::new_v4());

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, email_verified, atproto_enabled, atproto_state, created_at, updated_at)
         VALUES ($1, 1, $2, true, true, 'pending', NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(&email)
    .execute(&pool)
    .await
    .unwrap();

    let par_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/atproto/oauth/par")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    "DPoP",
                    dpop_proof(
                        &dpop_key_material(),
                        "POST",
                        &http_uri("/atproto/oauth/par"),
                        None,
                        None,
                    ),
                )
                .body(Body::from(
                    "client_id=https%3A%2F%2Fclient.example&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&scope=atproto&code_challenge=challenge&code_challenge_method=S256",
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let par_body = par_response.into_body().collect().await.unwrap().to_bytes();
    let par_payload: Value = serde_json::from_slice(&par_body).unwrap();
    let request_uri = par_payload["request_uri"].as_str().unwrap();

    let session_token = generate_server_signed_ucan(
        &user_keys.public_key(),
        1,
        &email,
        "https://login.divine.video",
        None,
        &server_keys,
        true,
        None,
        None,
    )
    .await
    .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/atproto/oauth/authorize?request_uri={}",
                    urlencoding::encode(request_uri)
                ))
                .header(header::COOKIE, format!("keycast_session={session_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
#[serial]
async fn par_uses_request_host_tenant_for_authorize_flow() {
    let server_keys = configure_atproto_env();

    let pool = common::setup_test_db().await;
    let app = app(pool.clone());

    let tenant_domain = format!("tenant-{}.example.com", Uuid::new_v4());
    unsafe {
        std::env::set_var(
            "ALLOWED_TENANT_DOMAINS",
            format!("login.divine.video,{tenant_domain}"),
        );
    }
    let tenant_id = create_test_tenant(&pool, &tenant_domain).await;

    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();
    let user_did = "did:plc:testtenant";
    let email = format!("tenant-{}@example.com", Uuid::new_v4());

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, email_verified, atproto_enabled, atproto_state, atproto_did, created_at, updated_at)
         VALUES ($1, $2, $3, true, true, 'ready', $4, NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .bind(&email)
    .bind(user_did)
    .execute(&pool)
    .await
    .unwrap();

    let par_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/atproto/oauth/par")
                .header(header::HOST, &tenant_domain)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    "DPoP",
                    dpop_proof(
                        &dpop_key_material(),
                        "POST",
                        &http_uri("/atproto/oauth/par"),
                        None,
                        None,
                    ),
                )
                .body(Body::from(
                    "client_id=https%3A%2F%2Fclient.example&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&scope=atproto&code_challenge=tenant-challenge&code_challenge_method=S256",
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(par_response.status(), StatusCode::OK);
    let par_body = par_response.into_body().collect().await.unwrap().to_bytes();
    let par_payload: Value = serde_json::from_slice(&par_body).unwrap();
    let request_uri = par_payload["request_uri"].as_str().unwrap().to_string();
    let stored_tenant_id: i64 =
        sqlx::query_scalar("SELECT tenant_id FROM atproto_oauth_sessions WHERE request_uri = $1")
            .bind(&request_uri)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored_tenant_id, tenant_id);

    let session_token = generate_server_signed_ucan(
        &user_keys.public_key(),
        tenant_id,
        &email,
        "https://login.divine.video",
        None,
        &server_keys,
        true,
        None,
        None,
    )
    .await
    .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/atproto/oauth/authorize?request_uri={}",
                    urlencoding::encode(&request_uri)
                ))
                .header(header::COOKIE, format!("keycast_session={session_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
#[serial]
async fn authorize_rejects_revoked_request_uri_before_redirecting() {
    let server_keys = configure_atproto_env();

    let pool = common::setup_test_db().await;
    let app = app(pool.clone());

    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();
    let user_did = "did:plc:testrevoked";
    let email = format!("revoked-{}@example.com", Uuid::new_v4());

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, email_verified, atproto_enabled, atproto_state, atproto_did, created_at, updated_at)
         VALUES ($1, 1, $2, true, true, 'ready', $3, NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(&email)
    .bind(user_did)
    .execute(&pool)
    .await
    .unwrap();

    let par_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/atproto/oauth/par")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    "DPoP",
                    dpop_proof(
                        &dpop_key_material(),
                        "POST",
                        &http_uri("/atproto/oauth/par"),
                        None,
                        None,
                    ),
                )
                .body(Body::from(
                    "client_id=https%3A%2F%2Fclient.example&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&scope=atproto&code_challenge=revoked-challenge&code_challenge_method=S256",
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(par_response.status(), StatusCode::OK);
    let par_body = par_response.into_body().collect().await.unwrap().to_bytes();
    let par_payload: Value = serde_json::from_slice(&par_body).unwrap();
    let request_uri = par_payload["request_uri"].as_str().unwrap().to_string();

    sqlx::query("UPDATE atproto_oauth_sessions SET revoked_at = NOW() WHERE request_uri = $1")
        .bind(&request_uri)
        .execute(&pool)
        .await
        .unwrap();

    let session_token = generate_server_signed_ucan(
        &user_keys.public_key(),
        1,
        &email,
        "https://login.divine.video",
        None,
        &server_keys,
        true,
        None,
        None,
    )
    .await
    .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/atproto/oauth/authorize?request_uri={}",
                    urlencoding::encode(&request_uri)
                ))
                .header(header::COOKIE, format!("keycast_session={session_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let stored_code: Option<String> = sqlx::query_scalar(
        "SELECT authorization_code FROM atproto_oauth_sessions WHERE request_uri = $1",
    )
    .bind(&request_uri)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(stored_code.is_none());
}

#[tokio::test]
#[serial]
async fn par_rejects_requests_without_dpop_proof() {
    configure_atproto_env();

    let pool = common::setup_test_db().await;
    let app = app(pool);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/atproto/oauth/par")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(
                    "client_id=https%3A%2F%2Fclient.example&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&scope=atproto&code_challenge=challenge&code_challenge_method=S256",
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial]
async fn refresh_token_rotation_requires_the_bound_dpop_key() {
    let server_keys = configure_atproto_env();

    let pool = common::setup_test_db().await;
    let app = app(pool.clone());

    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();
    let user_did = "did:plc:testrefresh";
    let email = format!("refresh-{}@example.com", Uuid::new_v4());
    let code_verifier = "refresh-verifier-1234567890";
    let code_challenge = pkce_challenge(code_verifier);
    let dpop_key = dpop_key_material();
    let wrong_key = dpop_key_material();

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, email_verified, atproto_enabled, atproto_state, atproto_did, created_at, updated_at)
         VALUES ($1, 1, $2, true, true, 'ready', $3, NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(&email)
    .bind(user_did)
    .execute(&pool)
    .await
    .unwrap();

    let par_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/atproto/oauth/par")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    "DPoP",
                    dpop_proof(&dpop_key, "POST", &http_uri("/atproto/oauth/par"), None, None),
                )
                .body(Body::from(format!(
                    "client_id={}&redirect_uri={}&scope=atproto&state=csrf-456&code_challenge={}&code_challenge_method=S256",
                    urlencoding::encode("https://client.example"),
                    urlencoding::encode("https://client.example/callback"),
                    urlencoding::encode(&code_challenge),
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    let par_nonce = par_response
        .headers()
        .get("DPoP-Nonce")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
        .expect("PAR response should issue a DPoP nonce");
    let par_body = par_response.into_body().collect().await.unwrap().to_bytes();
    let par_payload: Value = serde_json::from_slice(&par_body).unwrap();
    let request_uri = par_payload["request_uri"].as_str().unwrap().to_string();

    let session_token = generate_server_signed_ucan(
        &user_keys.public_key(),
        1,
        &email,
        "https://login.divine.video",
        None,
        &server_keys,
        true,
        None,
        None,
    )
    .await
    .unwrap();

    let authorized = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/atproto/oauth/authorize?request_uri={}",
                    urlencoding::encode(&request_uri)
                ))
                .header(header::COOKIE, format!("keycast_session={session_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let callback_location = authorized
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let callback_url = reqwest::Url::parse(&callback_location).unwrap();
    let code = callback_url
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.to_string())
        .unwrap();

    let token_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/atproto/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    "DPoP",
                    dpop_proof(
                        &dpop_key,
                        "POST",
                        &http_uri("/atproto/oauth/token"),
                        Some(&par_nonce),
                        None,
                    ),
                )
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={}&client_id={}&redirect_uri={}&code_verifier={}",
                    urlencoding::encode(&code),
                    urlencoding::encode("https://client.example"),
                    urlencoding::encode("https://client.example/callback"),
                    urlencoding::encode(code_verifier),
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    let token_nonce = token_response
        .headers()
        .get("DPoP-Nonce")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
        .expect("token response should rotate the DPoP nonce");
    let token_body = token_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let token_payload: Value = serde_json::from_slice(&token_body).unwrap();
    let refresh_token = token_payload["refresh_token"].as_str().unwrap().to_string();
    let access_token = token_payload["access_token"].as_str().unwrap().to_string();

    let refresh_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/atproto/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    "DPoP",
                    dpop_proof(
                        &dpop_key,
                        "POST",
                        &http_uri("/atproto/oauth/token"),
                        Some(&token_nonce),
                        None,
                    ),
                )
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={}&client_id={}",
                    urlencoding::encode(&refresh_token),
                    urlencoding::encode("https://client.example"),
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(refresh_response.status(), StatusCode::OK);
    let refresh_nonce = refresh_response
        .headers()
        .get("DPoP-Nonce")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
        .expect("refresh response should rotate the DPoP nonce");
    let refresh_body = refresh_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let refresh_payload: Value = serde_json::from_slice(&refresh_body).unwrap();
    let rotated_refresh_token = refresh_payload["refresh_token"].as_str().unwrap();
    let rotated_access_token = refresh_payload["access_token"].as_str().unwrap();

    assert_ne!(rotated_refresh_token, refresh_token);
    assert_ne!(rotated_access_token, access_token);
    assert_eq!(
        decode_jwt_payload(rotated_access_token)["cnf"]["jkt"],
        dpop_key.jkt
    );

    let reused_refresh = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/atproto/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    "DPoP",
                    dpop_proof(
                        &dpop_key,
                        "POST",
                        &http_uri("/atproto/oauth/token"),
                        Some(&refresh_nonce),
                        None,
                    ),
                )
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={}&client_id={}",
                    urlencoding::encode(&refresh_token),
                    urlencoding::encode("https://client.example"),
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(reused_refresh.status(), StatusCode::BAD_REQUEST);

    let wrong_key_refresh = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/atproto/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    "DPoP",
                    dpop_proof(
                        &wrong_key,
                        "POST",
                        &http_uri("/atproto/oauth/token"),
                        Some(&refresh_nonce),
                        None,
                    ),
                )
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={}&client_id={}",
                    urlencoding::encode(rotated_refresh_token),
                    urlencoding::encode("https://client.example"),
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(wrong_key_refresh.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        decode_jwt_payload(rotated_access_token)["cnf"]["jkt"],
        dpop_key.jkt
    );
    assert_eq!(access_token_hash(rotated_access_token).len(), 43);
}

#[tokio::test]
#[serial]
async fn confidential_client_requires_private_key_jwt_at_par_and_keeps_key_binding() {
    let server_keys = configure_atproto_env();

    let pool = common::setup_test_db().await;
    let app = app(pool.clone());

    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();
    let user_did = "did:plc:testconfidential";
    let email = format!("confidential-{}@example.com", Uuid::new_v4());
    let code_verifier = "confidential-verifier-1234567890";
    let code_challenge = pkce_challenge(code_verifier);
    let redirect_uri = "https://client.example/confidential/callback";
    let dpop_key = dpop_key_material();
    let client_auth_key = client_auth_key_material();
    let wrong_client_auth_key = client_auth_key_material();
    let client_id =
        start_confidential_client_metadata_server(redirect_uri, &client_auth_key, true).await;

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, email_verified, atproto_enabled, atproto_state, atproto_did, created_at, updated_at)
         VALUES ($1, 1, $2, true, true, 'ready', $3, NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(&email)
    .bind(user_did)
    .execute(&pool)
    .await
    .unwrap();

    let missing_assertion_par = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/atproto/oauth/par")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    "DPoP",
                    dpop_proof(&dpop_key, "POST", &http_uri("/atproto/oauth/par"), None, None),
                )
                .body(Body::from(format!(
                    "client_id={}&redirect_uri={}&scope=atproto&state=csrf-confidential&code_challenge={}&code_challenge_method=S256",
                    urlencoding::encode(&client_id),
                    urlencoding::encode(redirect_uri),
                    urlencoding::encode(&code_challenge),
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_assertion_par.status(), StatusCode::BAD_REQUEST);

    let par_assertion =
        private_key_jwt_assertion(&client_auth_key, &client_id, "https://login.divine.video");
    let par_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/atproto/oauth/par")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    "DPoP",
                    dpop_proof(&dpop_key, "POST", &http_uri("/atproto/oauth/par"), None, None),
                )
                .body(Body::from(format!(
                    "client_id={}&redirect_uri={}&scope=atproto&state=csrf-confidential&code_challenge={}&code_challenge_method=S256&client_assertion_type={}&client_assertion={}",
                    urlencoding::encode(&client_id),
                    urlencoding::encode(redirect_uri),
                    urlencoding::encode(&code_challenge),
                    urlencoding::encode("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                    urlencoding::encode(&par_assertion),
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let par_status = par_response.status();
    let par_nonce = par_response
        .headers()
        .get("DPoP-Nonce")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let par_body = par_response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        par_status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&par_body)
    );
    let par_nonce = par_nonce.unwrap();
    let par_payload: Value = serde_json::from_slice(&par_body).unwrap();
    let request_uri = par_payload["request_uri"].as_str().unwrap().to_string();
    let client_binding: (String, Option<String>, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT client_auth_method, client_auth_alg, client_auth_kid, client_auth_jkt FROM atproto_oauth_sessions WHERE request_uri = $1",
    )
    .bind(&request_uri)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(client_binding.0, "private_key_jwt");
    assert_eq!(client_binding.1.as_deref(), Some("ES256"));
    assert_eq!(
        client_binding.2.as_deref(),
        Some(client_auth_key.kid.as_str())
    );
    assert_eq!(
        client_binding.3.as_deref(),
        Some(client_auth_key.jkt.as_str())
    );

    let session_token = generate_server_signed_ucan(
        &user_keys.public_key(),
        1,
        &email,
        "https://login.divine.video",
        None,
        &server_keys,
        true,
        None,
        None,
    )
    .await
    .unwrap();

    let authorized = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/atproto/oauth/authorize?request_uri={}",
                    urlencoding::encode(&request_uri)
                ))
                .header(header::COOKIE, format!("keycast_session={session_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authorized.status(), StatusCode::SEE_OTHER);
    let callback_url = reqwest::Url::parse(
        authorized
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let code = callback_url
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.to_string())
        .unwrap();

    let token_assertion =
        private_key_jwt_assertion(&client_auth_key, &client_id, "https://login.divine.video");
    let token_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/atproto/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    "DPoP",
                    dpop_proof(
                        &dpop_key,
                        "POST",
                        &http_uri("/atproto/oauth/token"),
                        Some(&par_nonce),
                        None,
                    ),
                )
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={}&client_id={}&redirect_uri={}&code_verifier={}&client_assertion_type={}&client_assertion={}",
                    urlencoding::encode(&code),
                    urlencoding::encode(&client_id),
                    urlencoding::encode(redirect_uri),
                    urlencoding::encode(code_verifier),
                    urlencoding::encode("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                    urlencoding::encode(&token_assertion),
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(token_response.status(), StatusCode::OK);
    let token_nonce = token_response
        .headers()
        .get("DPoP-Nonce")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
        .unwrap();
    let token_payload: Value = serde_json::from_slice(
        &token_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    let refresh_token = token_payload["refresh_token"].as_str().unwrap();

    let wrong_refresh_assertion = private_key_jwt_assertion(
        &wrong_client_auth_key,
        &client_id,
        "https://login.divine.video",
    );
    let wrong_key_refresh = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/atproto/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    "DPoP",
                    dpop_proof(
                        &dpop_key,
                        "POST",
                        &http_uri("/atproto/oauth/token"),
                        Some(&token_nonce),
                        None,
                    ),
                )
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={}&client_id={}&client_assertion_type={}&client_assertion={}",
                    urlencoding::encode(refresh_token),
                    urlencoding::encode(&client_id),
                    urlencoding::encode("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                    urlencoding::encode(&wrong_refresh_assertion),
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong_key_refresh.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial]
async fn confidential_client_par_rejects_when_dpop_bound_access_tokens_is_false() {
    configure_atproto_env();

    let pool = common::setup_test_db().await;
    let app = app(pool);

    let code_verifier = "confidential-dpop-flag-verifier";
    let code_challenge = pkce_challenge(code_verifier);
    let redirect_uri = "https://client.example/confidential/callback";
    let dpop_key = dpop_key_material();
    let client_auth_key = client_auth_key_material();
    let client_id =
        start_confidential_client_metadata_server(redirect_uri, &client_auth_key, false).await;
    let par_assertion =
        private_key_jwt_assertion(&client_auth_key, &client_id, "https://login.divine.video");

    let par_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/atproto/oauth/par")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    "DPoP",
                    dpop_proof(&dpop_key, "POST", &http_uri("/atproto/oauth/par"), None, None),
                )
                .body(Body::from(format!(
                    "client_id={}&redirect_uri={}&scope=atproto&state=csrf-confidential&code_challenge={}&code_challenge_method=S256&client_assertion_type={}&client_assertion={}",
                    urlencoding::encode(&client_id),
                    urlencoding::encode(redirect_uri),
                    urlencoding::encode(&code_challenge),
                    urlencoding::encode("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                    urlencoding::encode(&par_assertion),
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(par_response.status(), StatusCode::BAD_REQUEST);
}
