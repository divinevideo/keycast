use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use rand::Rng;
use sqlx::FromRow;

/// Claim token expiry in days (7 days)
pub const CLAIM_TOKEN_EXPIRY_DAYS: i64 = 7;

/// Account claim token for preloaded users to claim their accounts
#[derive(Debug, FromRow)]
pub struct ClaimToken {
    pub id: i32,
    pub token: String,
    pub user_pubkey: String,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub created_by_pubkey: Option<String>,
    pub tenant_id: i64,
}

/// Aggregate statistics for claim tokens in a tenant
#[derive(Debug)]
pub struct ClaimTokenStats {
    pub total_generated: i64,
    pub total_claimed: i64,
    pub total_expired: i64,
    pub total_pending: i64,
}

/// Generate a cryptographically random claim token (256 bits, base64url encoded)
pub fn generate_claim_token() -> String {
    let bytes: [u8; 32] = rand::thread_rng().gen();
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_claim_token_length() {
        let token = generate_claim_token();
        // 32 bytes in base64url (no padding) = 43 chars
        assert_eq!(token.len(), 43);
    }

    #[test]
    fn test_generate_claim_token_uniqueness() {
        let token1 = generate_claim_token();
        let token2 = generate_claim_token();
        assert_ne!(token1, token2);
    }

    #[test]
    fn test_generate_claim_token_url_safe() {
        let token = generate_claim_token();
        // URL-safe base64 should not contain + or / or =
        assert!(!token.contains('+'));
        assert!(!token.contains('/'));
        assert!(!token.contains('='));
    }

    #[test]
    fn test_generate_claim_token_decodable() {
        let token = generate_claim_token();
        let decoded = URL_SAFE_NO_PAD.decode(&token).expect("should decode");
        assert_eq!(decoded.len(), 32);
    }
}
