use nostr::Keys;
use serde::{Deserialize, Serialize};

/// Test user data
#[derive(Debug, Clone)]
pub struct TestUser {
    pub email: String,
    pub password: String,
    pub keys: Keys,
}

impl TestUser {
    pub fn generate() -> Self {
        let keys = Keys::generate();
        let random_suffix: u64 = rand::random();
        Self {
            email: format!("test_{}@example.com", random_suffix),
            password: format!("TestPassword123!_{}", random_suffix),
            keys,
        }
    }

    pub fn pubkey_hex(&self) -> String {
        self.keys.public_key().to_hex()
    }
}

/// Test OAuth application configuration
#[derive(Debug, Clone)]
pub struct TestApp {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
}

impl Default for TestApp {
    fn default() -> Self {
        Self {
            client_id: "test-app".to_string(),
            redirect_uri: "http://localhost:5173/callback".to_string(),
            scope: "policy:social".to_string(),
        }
    }
}

impl TestApp {
    pub fn with_scope(mut self, scope: &str) -> Self {
        self.scope = scope.to_string();
        self
    }

    pub fn redirect_origin(&self) -> String {
        let url = url::Url::parse(&self.redirect_uri).expect("Invalid redirect_uri");
        format!("{}://{}", url.scheme(), url.host_str().unwrap_or("localhost"))
    }
}

/// Test event templates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestEvent {
    pub kind: u16,
    pub content: String,
    pub tags: Vec<Vec<String>>,
}

impl TestEvent {
    pub fn text_note(content: &str) -> Self {
        Self {
            kind: 1,
            content: content.to_string(),
            tags: vec![],
        }
    }

    pub fn dm(content: &str, recipient: &str) -> Self {
        Self {
            kind: 4,
            content: content.to_string(),
            tags: vec![vec!["p".to_string(), recipient.to_string()]],
        }
    }

    pub fn reaction(event_id: &str, pubkey: &str) -> Self {
        Self {
            kind: 7,
            content: "+".to_string(),
            tags: vec![
                vec!["e".to_string(), event_id.to_string()],
                vec!["p".to_string(), pubkey.to_string()],
            ],
        }
    }
}

/// PKCE test data
#[derive(Debug, Clone)]
pub struct PkceChallenge {
    pub verifier: String,
    pub challenge: String,
    pub method: String,
}

impl PkceChallenge {
    pub fn generate_s256() -> Self {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use sha2::{Digest, Sha256};

        // Generate a random verifier (43-128 chars)
        let verifier: String = (0..64)
            .map(|_| {
                let idx = rand::random::<usize>() % 62;
                let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                chars[idx] as char
            })
            .collect();

        // Compute S256 challenge
        let hash = Sha256::digest(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(hash);

        Self {
            verifier,
            challenge,
            method: "S256".to_string(),
        }
    }

    pub fn with_nsec(nsec: &str) -> Self {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use sha2::{Digest, Sha256};

        // Generate random prefix
        let prefix: String = (0..32)
            .map(|_| {
                let idx = rand::random::<usize>() % 62;
                let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                chars[idx] as char
            })
            .collect();

        // BYOK format: {random}.{nsec}
        let verifier = format!("{}.{}", prefix, nsec);

        // Compute S256 challenge
        let hash = Sha256::digest(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(hash);

        Self {
            verifier,
            challenge,
            method: "S256".to_string(),
        }
    }
}
