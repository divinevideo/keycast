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
    // Set by admin Invalidate or by Regenerate when it replaces prior tokens.
    // When set, the claim handler treats the token as AdminInvalidated rather
    // than Expired.
    pub invalidated_at: Option<DateTime<Utc>>,
    pub invalidated_by: Option<String>,
    pub invalidation_reason: Option<String>,
}

/// Discriminated state of a claim token, derived from its row + peers.
/// Used by the claim HTTP handler to choose the correct error page when a
/// token string doesn't validate on first pass.
#[derive(Debug)]
pub enum ClaimTokenState {
    /// Token exists, is unused, is not admin-invalidated, and has not yet expired.
    Valid(ClaimToken),
    /// No row matches the token string.
    Unrecognized,
    /// Token row exists and `used_at IS NOT NULL`.
    AlreadyClaimed(ClaimToken),
    /// Token row exists and `invalidated_at IS NOT NULL` (set by admin
    /// Invalidate or by Regenerate replacing the token).
    AdminInvalidated(ClaimToken),
    /// Token is past `expires_at`, was not admin-invalidated, and a newer
    /// valid token exists for the same user.
    Replaced {
        current: ClaimToken,
        newer: ClaimToken,
    },
    /// Token is past `expires_at`, was not admin-invalidated, and no newer
    /// valid token exists.
    Expired(ClaimToken),
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
