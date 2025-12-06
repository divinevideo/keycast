use crate::client::RegistrationClient;
use crate::SetupArgs;
use crate::SetupMode;
use anyhow::{Context, Result};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Test user credentials (stored in JSON file)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestUser {
    pub pubkey: String,
    pub email: String,
    pub ucan_token: String,
}

/// Output format for the credentials file
#[derive(Debug, Serialize, Deserialize)]
pub struct TestUsersFile {
    pub url: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub users: Vec<TestUser>,
}

pub async fn run_setup(args: SetupArgs) -> Result<()> {
    let is_localhost = args.url.contains("localhost") || args.url.contains("127.0.0.1");
    let has_db = args.database_url.is_some();

    // Determine mode
    let mode = match args.mode {
        Some(m) => m,
        None => {
            if is_localhost && has_db {
                tracing::info!("Auto-detected DB mode (localhost with DATABASE_URL)");
                SetupMode::Db
            } else {
                tracing::info!("Auto-detected HTTP mode");
                SetupMode::Http
            }
        }
    };

    let users = match mode {
        SetupMode::Db => {
            let db_url = args
                .database_url
                .context("DATABASE_URL required for DB mode")?;
            setup_db_mode(&args.url, &db_url, &args.master_key_path, args.users).await?
        }
        SetupMode::Http => setup_http_mode(&args.url, args.users, args.concurrency).await?,
    };

    // Save to file
    let output = TestUsersFile {
        url: args.url.clone(),
        created_at: chrono::Utc::now(),
        users,
    };

    let json = serde_json::to_string_pretty(&output)?;
    std::fs::write(&args.output, &json)?;

    tracing::info!("Saved {} users to {:?}", output.users.len(), args.output);

    Ok(())
}

async fn setup_http_mode(url: &str, count: usize, concurrency: usize) -> Result<Vec<TestUser>> {
    tracing::info!(
        "Creating {} users via HTTP registration API with {} concurrent requests",
        count,
        concurrency
    );

    let client = Arc::new(RegistrationClient::new(url, concurrency * 2)?);
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let counter = Arc::new(AtomicUsize::new(0));
    let success_counter = Arc::new(AtomicUsize::new(0));

    // Use timestamp prefix for unique emails
    let run_id = chrono::Utc::now().timestamp();

    let mut handles = Vec::with_capacity(count);

    for i in 0..count {
        let client = client.clone();
        let semaphore = semaphore.clone();
        let counter = counter.clone();
        let success_counter = success_counter.clone();

        let handle = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();

            // Generate unique email with run timestamp
            let email = format!("lt{}-{}@test.local", run_id, i);
            let password = generate_password();

            let result = client.register(&email, &password).await;

            let current = counter.fetch_add(1, Ordering::Relaxed) + 1;
            if current % 100 == 0 || current == count {
                let success = success_counter.load(Ordering::Relaxed);
                tracing::info!(
                    "Progress: {}/{} registrations attempted ({} new)",
                    current,
                    count,
                    success
                );
            }

            if result.success {
                success_counter.fetch_add(1, Ordering::Relaxed);
                Some(TestUser {
                    pubkey: result.pubkey.unwrap_or_default(),
                    email,
                    ucan_token: result.ucan_token.unwrap_or_default(),
                })
            } else {
                if let Some(error) = &result.error {
                    // Only log first few errors to avoid spam
                    if counter.load(Ordering::Relaxed) < 10 {
                        tracing::warn!("Failed to register {}: {}", email, error);
                    }
                }
                None
            }
        });

        handles.push(handle);
    }

    // Collect results
    let mut users = Vec::with_capacity(count);
    for handle in handles {
        if let Some(user) = handle.await? {
            users.push(user);
        }
    }

    tracing::info!(
        "Setup complete: {} users ready for testing (requested {})",
        users.len(),
        count
    );

    if users.is_empty() {
        anyhow::bail!("Failed to create any users");
    }

    Ok(users)
}

async fn setup_db_mode(
    _url: &str,
    db_url: &str,
    _master_key_path: &std::path::Path,
    count: usize,
) -> Result<Vec<TestUser>> {
    tracing::info!("Creating {} users via direct database access", count);

    // Connect to database
    let pool = sqlx::PgPool::connect(db_url).await?;

    // Get or create tenant
    let tenant_id = get_or_create_tenant(&pool, "loadtest.keycast.local").await?;

    let mut users = Vec::with_capacity(count);

    for i in 0..count {
        let user = create_db_user(&pool, tenant_id, i).await?;
        users.push(user);

        if (i + 1) % 1000 == 0 || i + 1 == count {
            tracing::info!("Progress: {}/{} users created", i + 1, count);
        }
    }

    Ok(users)
}

async fn get_or_create_tenant(pool: &sqlx::PgPool, domain: &str) -> Result<i64> {
    // Try to get existing tenant
    let existing: Option<(i64,)> = sqlx::query_as("SELECT id FROM tenants WHERE domain = $1")
        .bind(domain)
        .fetch_optional(pool)
        .await?;

    if let Some((id,)) = existing {
        return Ok(id);
    }

    // Create new tenant
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO tenants (domain, name, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())
         RETURNING id",
    )
    .bind(domain)
    .bind("Load Test Tenant")
    .fetch_one(pool)
    .await?;

    Ok(id)
}

async fn create_db_user(pool: &sqlx::PgPool, tenant_id: i64, index: usize) -> Result<TestUser> {
    use nostr_sdk::Keys;

    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let email = format!("loadtest-{}@test.local", index);
    let password_hash = "$2b$12$loadtest.placeholder.hash"; // Placeholder hash

    // Insert user
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
         VALUES ($1, $2, $3, $4, true, NOW(), NOW())
         ON CONFLICT (pubkey) DO NOTHING",
    )
    .bind(&pubkey)
    .bind(tenant_id)
    .bind(&email)
    .bind(password_hash)
    .execute(pool)
    .await?;

    // Create OAuth authorization for the HTTP RPC endpoint
    // NOTE: bunker_keys must be created BEFORE generating UCAN because
    // the UCAN needs to include bunker_pubkey for HTTP RPC access
    let bunker_keys = Keys::generate();
    let bunker_pubkey = bunker_keys.public_key().to_hex();

    // Generate UCAN token with bunker_pubkey (required for HTTP RPC)
    let ucan_token = crate::ucan::generate_ucan_token(
        &keys,
        tenant_id,
        &email,
        "http://loadtest.keycast.local",
        &bunker_pubkey,
    )
    .await?;
    let secret = generate_password();
    let auth_handle = hex::encode(rand::random::<[u8; 32]>());

    sqlx::query(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, bunker_public_key, secret, relays,
          tenant_id, authorization_handle, handle_expires_at, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, NOW() + INTERVAL '30 days', NOW(), NOW())
         ON CONFLICT DO NOTHING",
    )
    .bind(&pubkey)
    .bind("http://loadtest.keycast.local")
    .bind(&bunker_pubkey)
    .bind(&secret)
    .bind(r#"["wss://relay.example.com"]"#)
    .bind(tenant_id)
    .bind(&auth_handle)
    .execute(pool)
    .await?;

    Ok(TestUser {
        pubkey,
        email,
        ucan_token,
    })
}

fn generate_password() -> String {
    use rand::distributions::Alphanumeric;
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}
