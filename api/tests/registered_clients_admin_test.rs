// ABOUTME: Repository-level integration tests for admin CRUD on registered_clients
// ABOUTME: Verifies list/create/update/delete, per-tenant scoping, uniqueness, and validation

mod common;

use keycast_core::repositories::{RegisteredClient, RegisteredClientRepository, RepositoryError};

const TENANT_A: i64 = 1;
// Tenant B uses an id that does not exist as a real tenant FK; the
// registered_clients table has no FK on tenant_id (see migration 0008),
// so any integer is acceptable here.
const TENANT_B: i64 = 999;

/// Build a repository whose test setup clears the listed client_ids.
/// This prevents cross-test interference in parallel/repeated test execution
/// against a shared database: each test cleans up exactly what it will create.
/// Callers pass every client_id they will insert so that re-running the suite
/// (which leaves rows behind) does not collide on the unique (tenant_id,
/// client_id) constraint.
async fn fresh_repo(client_ids: &[&str]) -> RegisteredClientRepository {
    let pool = common::setup_test_db().await;
    for cid in client_ids {
        sqlx::query("DELETE FROM registered_clients WHERE client_id = $1")
            .bind(cid)
            .execute(&pool)
            .await
            .unwrap();
    }
    RegisteredClientRepository::new(pool)
}

#[tokio::test]
async fn create_then_list_returns_row_for_tenant() {
    let repo = fresh_repo(&["test-client-1"]).await;

    let created = repo
        .create(
            TENANT_A,
            "test-client-1",
            "Test Client 1",
            &[
                "https://app.example.com/cb".to_string(),
                "https://*.preview.example.com/cb".to_string(),
            ],
        )
        .await
        .unwrap();

    assert_eq!(created.tenant_id, TENANT_A);
    assert_eq!(created.client_id, "test-client-1");
    assert_eq!(created.name, "Test Client 1");
    assert_eq!(created.allowed_redirect_uris.len(), 2);

    let listed = repo.list(TENANT_A).await.unwrap();
    assert!(
        listed.iter().any(|c| c.client_id == "test-client-1"),
        "newly created client should appear in list for tenant"
    );
}

#[tokio::test]
async fn list_is_scoped_per_tenant() {
    let repo = fresh_repo(&["tenant-a-client-x", "tenant-b-client-x"]).await;

    repo.create(
        TENANT_A,
        "tenant-a-client-x",
        "A",
        &["https://a.example.com/cb".to_string()],
    )
    .await
    .unwrap();
    repo.create(
        TENANT_B,
        "tenant-b-client-x",
        "B",
        &["https://b.example.com/cb".to_string()],
    )
    .await
    .unwrap();

    let a_list = repo.list(TENANT_A).await.unwrap();
    let b_list = repo.list(TENANT_B).await.unwrap();

    assert!(a_list.iter().any(|c| c.client_id == "tenant-a-client-x"));
    assert!(!a_list.iter().any(|c| c.client_id == "tenant-b-client-x"));

    assert!(b_list.iter().any(|c| c.client_id == "tenant-b-client-x"));
    assert!(!b_list.iter().any(|c| c.client_id == "tenant-a-client-x"));
}

#[tokio::test]
async fn create_duplicate_client_id_for_same_tenant_errors() {
    let repo = fresh_repo(&["test-dup"]).await;

    repo.create(
        TENANT_A,
        "test-dup",
        "First",
        &["https://example.com/cb".to_string()],
    )
    .await
    .unwrap();

    let err = repo
        .create(
            TENANT_A,
            "test-dup",
            "Second",
            &["https://example.com/cb".to_string()],
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, RepositoryError::Duplicate),
        "expected Duplicate, got {:?}",
        err
    );
}

#[tokio::test]
async fn create_same_client_id_different_tenants_succeeds() {
    let repo = fresh_repo(&["test-shared-id"]).await;

    repo.create(
        TENANT_A,
        "test-shared-id",
        "A version",
        &["https://a.example.com/cb".to_string()],
    )
    .await
    .unwrap();
    repo.create(
        TENANT_B,
        "test-shared-id",
        "B version",
        &["https://b.example.com/cb".to_string()],
    )
    .await
    .expect("same client_id under a different tenant must be allowed");
}

#[tokio::test]
async fn create_rejects_empty_redirect_uris() {
    let repo = fresh_repo(&["test-empty-uris"]).await;

    let err = repo
        .create(TENANT_A, "test-empty-uris", "X", &Vec::<String>::new())
        .await
        .unwrap_err();
    assert!(
        matches!(err, RepositoryError::Integrity(_)),
        "expected Integrity (validation) error, got {:?}",
        err
    );
}

#[tokio::test]
async fn create_rejects_empty_client_id() {
    let repo = fresh_repo(&["test-empty-id"]).await;

    let err = repo
        .create(TENANT_A, "", "X", &["https://example.com/cb".to_string()])
        .await
        .unwrap_err();
    assert!(
        matches!(err, RepositoryError::Integrity(_)),
        "expected Integrity (validation) error, got {:?}",
        err
    );
}

#[tokio::test]
async fn create_rejects_empty_name() {
    let repo = fresh_repo(&["test-empty-name"]).await;

    let err = repo
        .create(
            TENANT_A,
            "test-empty-name",
            "   ", // whitespace-only name
            &["https://example.com/cb".to_string()],
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, RepositoryError::Integrity(_)),
        "expected Integrity (validation) error for empty-after-trim name, got {:?}",
        err
    );
}

#[tokio::test]
async fn create_rejects_multiple_asterisks_in_pattern() {
    let repo = fresh_repo(&["test-multi-star"]).await;

    let err = repo
        .create(
            TENANT_A,
            "test-multi-star",
            "Test",
            &["https://*.foo.com/*/cb".to_string()],
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, RepositoryError::Integrity(_)),
        "expected Integrity for multiple asterisks, got {:?}",
        err
    );
}

#[tokio::test]
async fn update_renames_and_replaces_uris() {
    let repo = fresh_repo(&["test-update"]).await;

    let created = repo
        .create(
            TENANT_A,
            "test-update",
            "Original",
            &["https://example.com/cb".to_string()],
        )
        .await
        .unwrap();

    let updated = repo
        .update(
            created.id,
            TENANT_A,
            Some("Renamed"),
            Some(&[
                "https://example.com/cb".to_string(),
                "https://*.preview.example.com/cb".to_string(),
            ]),
        )
        .await
        .unwrap();

    assert_eq!(updated.name, "Renamed");
    assert_eq!(updated.allowed_redirect_uris.len(), 2);
    assert!(updated.updated_at >= created.updated_at);
}

#[tokio::test]
async fn update_cannot_cross_tenants() {
    let repo = fresh_repo(&["test-cross-tenant"]).await;

    let created = repo
        .create(
            TENANT_A,
            "test-cross-tenant",
            "A",
            &["https://a.example.com/cb".to_string()],
        )
        .await
        .unwrap();

    // Attempting to update from a different tenant id MUST return NotFound
    let err = repo
        .update(created.id, TENANT_B, Some("hijacked"), None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, RepositoryError::NotFound(_)),
        "expected NotFound across tenants, got {:?}",
        err
    );
}

#[tokio::test]
async fn update_rejects_empty_redirect_uris() {
    let repo = fresh_repo(&["test-update-empty"]).await;

    let created = repo
        .create(
            TENANT_A,
            "test-update-empty",
            "X",
            &["https://example.com/cb".to_string()],
        )
        .await
        .unwrap();

    let err = repo
        .update(created.id, TENANT_A, None, Some(&Vec::<String>::new()))
        .await
        .unwrap_err();
    assert!(
        matches!(err, RepositoryError::Integrity(_)),
        "expected Integrity (validation) error, got {:?}",
        err
    );
}

#[tokio::test]
async fn delete_removes_row_and_is_tenant_scoped() {
    let repo = fresh_repo(&["test-delete"]).await;

    let created = repo
        .create(
            TENANT_A,
            "test-delete",
            "X",
            &["https://example.com/cb".to_string()],
        )
        .await
        .unwrap();

    // Wrong tenant: should not delete and should report NotFound
    let err = repo.delete(created.id, TENANT_B).await.unwrap_err();
    assert!(
        matches!(err, RepositoryError::NotFound(_)),
        "expected NotFound across tenants, got {:?}",
        err
    );

    // Right tenant: deletes
    repo.delete(created.id, TENANT_A).await.unwrap();

    let listed = repo.list(TENANT_A).await.unwrap();
    assert!(!listed.iter().any(|c: &RegisteredClient| c.id == created.id));
}

#[test]
fn test_pattern_matches_exact_uri() {
    use keycast_core::repositories::test_redirect_pattern;
    assert!(test_redirect_pattern(
        "https://app.example.com/cb",
        "https://app.example.com/cb"
    ));
    assert!(!test_redirect_pattern(
        "https://app.example.com/cb",
        "https://evil.com/cb"
    ));
}

#[test]
fn test_pattern_matches_wildcard_subdomain() {
    use keycast_core::repositories::test_redirect_pattern;
    assert!(test_redirect_pattern(
        "https://*.example.com/cb",
        "https://staging.example.com/cb"
    ));
    // Wildcard segment cannot contain '/'
    assert!(!test_redirect_pattern(
        "https://*.example.com/cb",
        "https://evil.com/.example.com/cb"
    ));
}

#[tokio::test]
async fn create_trims_redirect_uri_whitespace() {
    let repo = fresh_repo(&["test-whitespace-client"]).await;

    // Create with whitespace around URI - should be trimmed automatically
    let created = repo
        .create(
            TENANT_A,
            "test-whitespace-client",
            "Test",
            &[" https://app.example.com/cb ".to_string()],
        )
        .await
        .unwrap();

    // The stored URI should be trimmed (not have surrounding whitespace)
    assert_eq!(created.allowed_redirect_uris.len(), 1);
    assert_eq!(
        created.allowed_redirect_uris[0], "https://app.example.com/cb",
        "redirect URIs should be trimmed before persisting"
    );
}

#[tokio::test]
async fn update_trims_redirect_uri_whitespace() {
    let repo = fresh_repo(&["test-update-trim-client"]).await;

    // Create with proper URIs
    let created = repo
        .create(
            TENANT_A,
            "test-update-trim-client",
            "Test",
            &["https://app.example.com/cb".to_string()],
        )
        .await
        .unwrap();

    // Update with whitespace URI - should be trimmed automatically
    let updated = repo
        .update(
            created.id,
            TENANT_A,
            None,
            Some(&[" https://new.example.com/cb ".to_string()]),
        )
        .await
        .unwrap();

    assert_eq!(updated.allowed_redirect_uris.len(), 1);
    assert_eq!(
        updated.allowed_redirect_uris[0], "https://new.example.com/cb",
        "redirect URIs should be trimmed on update"
    );
}
