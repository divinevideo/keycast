use axum::http::{header, HeaderMap};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use keycast_api::api::http::{atproto_oauth, oauth};
use keycast_api::ucan_auth::nostr_pubkey_to_did;
use nostr_sdk::Keys;
use p256::ecdsa::{
    signature::{Signature as _, Signer},
    Signature, SigningKey,
};
use p256::elliptic_curve::rand_core::OsRng;
use serde_json::Value;
use serial_test::serial;

struct EnvGuard {
    key: &'static str,
    previous: Option<String>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let previous = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self { key, previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        if let Some(ref value) = self.previous {
            std::env::set_var(self.key, value);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

fn encode_json(value: &Value) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).expect("json should serialize"))
}

fn build_dpop_components() -> (Value, Value, SigningKey) {
    let signing_key = SigningKey::random(&mut OsRng);
    let encoded_point = signing_key.verifying_key().to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(encoded_point.x().expect("point should have x"));
    let y = URL_SAFE_NO_PAD.encode(encoded_point.y().expect("point should have y"));

    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
        }
    });
    let payload = serde_json::json!({
        "htu": "https://entryway.divine.video/api/oauth/token",
        "htm": "POST",
        "iat": chrono::Utc::now().timestamp(),
        "jti": format!("test-jti-{}", uuid::Uuid::new_v4()),
    });

    (header, payload, signing_key)
}

fn build_dpop_proof() -> String {
    let (header, payload, signing_key) = build_dpop_components();
    let header_b64 = encode_json(&header);
    let payload_b64 = encode_json(&payload);
    let message = format!("{}.{}", header_b64, payload_b64);
    let signature: Signature = signing_key.sign(message.as_bytes());

    format!("{}.{}.signature", header_b64, payload_b64,).replace(
        ".signature",
        &format!(".{}", URL_SAFE_NO_PAD.encode(signature.as_bytes())),
    )
}

#[tokio::test]
#[serial]
async fn entryway_token_exchange_binds_ucan_to_dpop_jkt() {
    let _enabled = EnvGuard::set("ATPROTO_ENTRYWAY_ENABLED", "true");
    let _origin = EnvGuard::set("ATPROTO_ENTRYWAY_ORIGIN", "https://entryway.divine.video");
    let _hosts = EnvGuard::set("ATPROTO_ENTRYWAY_HOSTS", "entryway.divine.video");

    let proof = build_dpop_proof();
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, "entryway.divine.video".parse().unwrap());
    headers.insert("DPoP", proof.parse().unwrap());

    let expected_htu = "https://entryway.divine.video/api/oauth/token";
    let dpop_jkt = atproto_oauth::resolve_dpop_jkt(&headers, expected_htu)
        .expect("DPOP proof should parse")
        .expect("entryway host should require DPoP");
    assert!(!dpop_jkt.is_empty());

    let server_keys = Keys::generate();
    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key();
    let user_did = nostr_pubkey_to_did(&user_pubkey);

    let token = oauth::generate_server_signed_ucan_with_dpop(
        &user_pubkey,
        1,
        "alice@example.com",
        "https://entryway.divine.video",
        None,
        &server_keys,
        false,
        None,
        Some(&dpop_jkt),
    )
    .await
    .expect("DPOP-bound UCAN should be generated");

    let ucan = ucan::Ucan::try_from_token_string(&token).expect("token should decode");
    assert_eq!(ucan.audience(), &user_did);

    let cnf_jkt = ucan.facts().iter().find_map(|fact| {
        fact.get("cnf")
            .and_then(Value::as_object)
            .and_then(|cnf| cnf.get("jkt"))
            .and_then(Value::as_str)
    });

    assert_eq!(cnf_jkt, Some(dpop_jkt.as_str()));
}

#[tokio::test]
#[serial]
async fn entryway_token_exchange_rejects_invalid_dpop_signature() {
    let _enabled = EnvGuard::set("ATPROTO_ENTRYWAY_ENABLED", "true");
    let _origin = EnvGuard::set("ATPROTO_ENTRYWAY_ORIGIN", "https://entryway.divine.video");
    let _hosts = EnvGuard::set("ATPROTO_ENTRYWAY_HOSTS", "entryway.divine.video");

    let proof = build_dpop_proof();
    let mut parts = proof.split('.').map(str::to_string).collect::<Vec<_>>();
    let mut payload: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(&parts[1])
            .expect("payload should be base64url"),
    )
    .expect("payload should be json");
    payload["jti"] = Value::String("tampered-jti".to_string());
    parts[1] = encode_json(&payload);
    let proof = parts.join(".");

    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, "entryway.divine.video".parse().unwrap());
    headers.insert("DPoP", proof.parse().unwrap());

    let expected_htu = "https://entryway.divine.video/api/oauth/token";
    let error = atproto_oauth::resolve_dpop_jkt(&headers, expected_htu)
        .expect_err("tampered DPoP proofs must be rejected");

    match error {
        oauth::OAuthError::InvalidRequest(message) => {
            assert!(message.contains("signature"));
        }
        other => panic!("expected invalid_request error, got {:?}", other),
    }
}
