mod common;

use keycast_core::repositories::RegisteredClientRepository;

#[tokio::test]
async fn migrations_register_divine_invite_admin_oauth_client() {
    let pool = common::setup_test_db().await;
    let repo = RegisteredClientRepository::new(pool);

    let allowed_redirects = repo
        .get_allowed_redirect_uris("divine-invite-admin", 1)
        .await
        .unwrap()
        .expect("divine-invite-admin should be seeded as a registered OAuth client");

    assert_eq!(
        allowed_redirects,
        vec!["https://invite.divine.video/admin".to_string()]
    );

    repo.validate_redirect_uri(
        "divine-invite-admin",
        "https://invite.divine.video/admin",
        1,
    )
    .await
    .unwrap();

    assert!(repo
        .validate_redirect_uri(
            "divine-invite-admin",
            "https://invite.divine.video/callback",
            1,
        )
        .await
        .is_err());
}

#[tokio::test]
async fn registered_clients_tenant_id_is_bigint() {
    // Every other tenant_id column in this schema is BIGINT (tenants.id,
    // users.tenant_id, oauth_authorizations.tenant_id, etc.). 0008 originally
    // declared registered_clients.tenant_id as INTEGER; the follow-up widens
    // it so the API i64 surface no longer needs ::BIGINT casts on read.
    let pool = common::setup_test_db().await;

    let data_type: String = sqlx::query_scalar(
        "SELECT data_type FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'registered_clients'
           AND column_name = 'tenant_id'",
    )
    .fetch_one(&pool)
    .await
    .expect("registered_clients.tenant_id column must exist");

    assert_eq!(
        data_type, "bigint",
        "registered_clients.tenant_id should be bigint to match all other tenant_id columns",
    );
}
