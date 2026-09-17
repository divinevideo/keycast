// ABOUTME: Public, privacy-minimizing lookup for the frozen OG Diviner chit.
// ABOUTME: Returns one eligibility boolean without exposing signup metadata or a roster.

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    Json,
};
use keycast_core::repositories::{og_diviner_cutoff, UserRepository};
use nostr_sdk::PublicKey;
use serde::Serialize;
use sqlx::PgPool;

#[derive(Debug, Serialize)]
pub struct OgDivinerEligibilityResponse {
    eligible: bool,
}

pub async fn get_og_diviner_eligibility(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    Path(pubkey): Path<String>,
) -> impl IntoResponse {
    let Ok(pubkey) = PublicKey::parse(pubkey.trim()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid public key"})),
        )
            .into_response();
    };

    let repository = UserRepository::new(pool);

    match repository
        .is_og_diviner(&pubkey.to_hex(), tenant.0.id, og_diviner_cutoff())
        .await
    {
        Ok(eligible) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=86400, stale-if-error=604800"),
            );
            (headers, Json(OgDivinerEligibilityResponse { eligible })).into_response()
        }
        Err(error) => {
            tracing::error!(error = %error, "OG Diviner eligibility lookup failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Eligibility lookup failed"})),
            )
                .into_response()
        }
    }
}
