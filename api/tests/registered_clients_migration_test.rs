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
