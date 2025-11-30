// ABOUTME: Shared test utilities and safety guards
// ABOUTME: Ensures tests never accidentally connect to production database

use sqlx::PgPool;

/// CRITICAL: Validates that DATABASE_URL points to localhost only.
/// This prevents accidental execution of tests against production databases.
///
/// # Panics
/// Panics if DATABASE_URL:
/// - Does not contain "localhost" or "127.0.0.1"
/// - Contains known production identifiers like "keycast-db", "cloud", or IP addresses
pub fn assert_test_database_url() {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());

    // Extract host portion for checking (don't log full URL with credentials)
    let host_info = url
        .split('@')
        .nth(1)
        .unwrap_or(&url)
        .split('/')
        .next()
        .unwrap_or("unknown");

    // Must be localhost or 127.0.0.1
    let is_localhost = url.contains("localhost") || url.contains("127.0.0.1");
    assert!(
        is_localhost,
        "\n\n\
        ╔══════════════════════════════════════════════════════════════════╗\n\
        ║  REFUSING TO RUN: DATABASE_URL must point to localhost           ║\n\
        ║                                                                  ║\n\
        ║  Tests detected a non-localhost database connection:             ║\n\
        ║  Host: {:<55} ║\n\
        ║                                                                  ║\n\
        ║  To fix:                                                         ║\n\
        ║  1. Start local postgres: docker run -p 5432:5432 postgres:16    ║\n\
        ║  2. Set DATABASE_URL=postgres://postgres:password@localhost/test ║\n\
        ╚══════════════════════════════════════════════════════════════════╝\n\n",
        host_info
    );

    // Additional check: must NOT contain known production identifiers
    let production_indicators = [
        "keycast-db",      // Cloud SQL instance name
        "cloud",           // Generic cloud indicator
        "prod",            // Production indicator
        "130.211.",        // GCP IP range
        "35.192.",         // GCP IP range
        "34.66.",          // GCP IP range
    ];

    for indicator in production_indicators {
        assert!(
            !url.to_lowercase().contains(indicator),
            "\n\n\
            ╔══════════════════════════════════════════════════════════════════╗\n\
            ║  REFUSING TO RUN: DATABASE_URL appears to be a production DB     ║\n\
            ║                                                                  ║\n\
            ║  Detected production indicator: {:<32} ║\n\
            ║                                                                  ║\n\
            ║  Tests must NEVER run against production databases.              ║\n\
            ║  Please use a local database for testing.                        ║\n\
            ╚══════════════════════════════════════════════════════════════════╝\n\n",
            indicator
        );
    }
}

/// Connect to test database with safety checks.
/// This is the preferred way to get a database pool in tests.
///
/// # Panics
/// Panics if DATABASE_URL is not a localhost database.
#[allow(dead_code)]
pub async fn setup_test_db() -> PgPool {
    // CRITICAL: Check database URL before connecting
    assert_test_database_url();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());

    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to test database");

    // Run migrations
    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    pool
}

// Unit tests for the safety guard moved to a separate test file
// to avoid race conditions with set_var affecting parallel tests.
// The safety guard is tested implicitly when running integration tests.
