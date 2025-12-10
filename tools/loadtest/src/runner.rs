use crate::client::{RegistrationClient, RpcClient};
use crate::metrics::{Metrics, TestMetadata};
use crate::setup::{TestUser, TestUsersFile};
use crate::{RpcMethod, RunArgs, TestScenario};
use anyhow::Result;
use rand::distributions::Alphanumeric;
use rand::Rng;
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

pub async fn run_loadtest(args: RunArgs) -> Result<()> {
    // For registration mode, we don't need existing users
    let is_registration_mode = matches!(args.method, RpcMethod::Register);

    let users = if is_registration_mode {
        tracing::info!("Starting REGISTRATION load test against {}", args.url);
        tracing::info!(
            "Concurrency: {}, Duration: {}s (creating new users)",
            args.concurrency,
            args.duration
        );
        Arc::new(Vec::new())
    } else {
        // Load users from file for RPC methods
        let users_json = std::fs::read_to_string(&args.users_file)?;
        let users_file: TestUsersFile = serde_json::from_str(&users_json)?;
        let users = Arc::new(users_file.users);

        if users.is_empty() {
            anyhow::bail!("No users found in {:?}", args.users_file);
        }

        tracing::info!(
            "Starting load test against {} with {} users",
            args.url,
            users.len()
        );
        tracing::info!(
            "Scenario: {:?}, Concurrency: {}, Duration: {}s",
            args.scenario,
            args.concurrency,
            args.duration
        );
        users
    };

    // Create per-user clients to ensure proper load distribution across instances
    // Each user needs their own connection pool so Google's load balancer assigns
    // them to different backend instances (session affinity works at TCP level)
    let user_clients: Arc<HashMap<usize, RpcClient>> = if !users.is_empty() {
        let mut clients = HashMap::new();
        for (i, _user) in users.iter().enumerate() {
            // Moderate pool per user - each user maintains their own connections
            // Larger pool handles high concurrency better
            clients.insert(i, RpcClient::new(&args.url, 50)?);
        }
        tracing::info!(
            "Created {} per-user HTTP clients for session affinity",
            clients.len()
        );
        Arc::new(clients)
    } else {
        Arc::new(HashMap::new())
    };

    // Shared client only for metrics endpoint
    let shared_client = Arc::new(RpcClient::new(&args.url, args.concurrency * 2)?);
    // Use timestamp + random suffix to avoid email collisions across parallel load testers
    let random_suffix: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(6)
        .map(char::from)
        .collect();
    let run_id = format!("{}-{}", chrono::Utc::now().timestamp(), random_suffix);

    // Fetch server metrics before test
    let metrics_before = match shared_client.fetch_metrics().await {
        Ok(m) => {
            tracing::info!(
                "Server metrics before: requests={}, cache_hits={}, cache_misses={}, cache_size={}",
                m.http_rpc_requests_total,
                m.http_rpc_cache_hits,
                m.http_rpc_cache_misses,
                m.http_rpc_cache_size
            );
            Some(m)
        }
        Err(e) => {
            tracing::warn!("Could not fetch server metrics: {}", e);
            None
        }
    };
    let metrics = Arc::new(Metrics::new());
    let semaphore = Arc::new(Semaphore::new(args.concurrency));
    let running = Arc::new(AtomicBool::new(true));
    let request_counter = Arc::new(AtomicUsize::new(0));

    let duration = Duration::from_secs(args.duration);
    let ramp_up = Duration::from_secs(args.ramp_up);
    let start = Instant::now();

    // Spawn progress reporter
    let progress_metrics = metrics.clone();
    let progress_running = running.clone();
    let report_interval = args.report_interval;
    let progress_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(report_interval));
        while progress_running.load(Ordering::Relaxed) {
            interval.tick().await;
            progress_metrics.add_timeline_point();
            let snapshot = progress_metrics.snapshot();
            let rps = if snapshot.elapsed_secs > 0.0 {
                snapshot.requests_total as f64 / snapshot.elapsed_secs
            } else {
                0.0
            };
            tracing::info!(
                "Progress: {} req, {:.1} req/s, p50={:.1}ms, p99={:.1}ms, errors={}",
                snapshot.requests_total,
                rps,
                snapshot.latency_p50_ms,
                snapshot.latency_p99_ms,
                snapshot.requests_error
            );
        }
    });

    // Spawn worker tasks
    let mut handles = Vec::new();
    for worker_id in 0..args.concurrency {
        let user_clients = user_clients.clone();
        let base_url = args.url.clone();
        let metrics = metrics.clone();
        let semaphore = semaphore.clone();
        let running = running.clone();
        let users = users.clone();
        let counter = request_counter.clone();
        let scenario = args.scenario;
        let method = args.method;
        let max_requests = args.requests;
        let run_id = run_id.clone();

        // Calculate ramp-up delay for this worker
        let worker_delay = if args.concurrency > 1 {
            ramp_up.as_millis() as u64 * worker_id as u64 / (args.concurrency - 1) as u64
        } else {
            0
        };

        let handle = tokio::spawn(async move {
            // Ramp-up delay
            if worker_delay > 0 {
                tokio::time::sleep(Duration::from_millis(worker_delay)).await;
            }

            let hot_count = if users.is_empty() {
                1
            } else {
                (users.len() / 10).max(1)
            };

            loop {
                // Check termination conditions
                if start.elapsed() > duration {
                    break;
                }
                if !running.load(Ordering::Relaxed) {
                    break;
                }
                if max_requests > 0 && counter.load(Ordering::Relaxed) >= max_requests {
                    break;
                }

                let _permit = semaphore.acquire().await.unwrap();
                let request_num = counter.fetch_add(1, Ordering::Relaxed);

                // Execute request based on method
                let result = if matches!(method, RpcMethod::Register) {
                    // Registration mode: create fresh client per user for realistic simulation.
                    // Each user gets their own GCLB cookie, so their registration flow
                    // (register → authorize → token) sticks to one instance via session affinity.
                    // Different users will naturally distribute across instances.
                    let user_client = match RegistrationClient::new_for_single_user(&base_url) {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::error!("Failed to create registration client: {}", e);
                            continue;
                        }
                    };
                    let email = format!("lt{}-{}@bench.local", run_id, request_num);
                    let password = generate_password();
                    user_client.register_timed(&email, &password).await
                } else {
                    // RPC mode: select existing user and their dedicated client
                    let user_index = select_user_index(&users, scenario, request_num, hot_count);
                    let user = &users[user_index];
                    let client = user_clients.get(&user_index).expect("user client exists");
                    execute_request(client, user, method).await
                };

                // Log first few errors for debugging
                if !result.success && request_num < 3 {
                    if let Some(ref err) = result.error {
                        tracing::warn!("Request {} failed: {}", request_num, err);
                    }
                }

                metrics.record_request(result.duration, result.success, result.status);
            }
        });

        handles.push(handle);
    }

    // Wait for all workers
    for handle in handles {
        let _ = handle.await;
    }

    // Stop progress reporter
    running.store(false, Ordering::Relaxed);
    let _ = progress_handle.await;

    // Fetch server metrics after test
    let metrics_after = match shared_client.fetch_metrics().await {
        Ok(m) => {
            tracing::info!(
                "Server metrics after: requests={}, cache_hits={}, cache_misses={}, cache_size={}",
                m.http_rpc_requests_total,
                m.http_rpc_cache_hits,
                m.http_rpc_cache_misses,
                m.http_rpc_cache_size
            );
            Some(m)
        }
        Err(e) => {
            tracing::warn!("Could not fetch server metrics: {}", e);
            None
        }
    };

    // Calculate and display server-side cache metrics
    if let (Some(before), Some(after)) = (&metrics_before, &metrics_after) {
        let cache_hits = after
            .http_rpc_cache_hits
            .saturating_sub(before.http_rpc_cache_hits);
        let cache_misses = after
            .http_rpc_cache_misses
            .saturating_sub(before.http_rpc_cache_misses);
        let total = cache_hits + cache_misses;
        let hit_ratio = if total > 0 {
            cache_hits as f64 / total as f64 * 100.0
        } else {
            0.0
        };

        println!("\n=== Server-Side Cache Metrics ===");
        println!("Cache hits:   {} ({:.1}%)", cache_hits, hit_ratio);
        println!("Cache misses: {} ({:.1}%)", cache_misses, 100.0 - hit_ratio);
        println!("Cache size:   {}", after.http_rpc_cache_size);
    }

    // Finalize metrics
    metrics.finish();
    metrics.add_timeline_point();

    // Generate results
    let metadata = TestMetadata {
        url: args.url.clone(),
        scenario: format!("{:?}", args.scenario),
        method: format!("{:?}", args.method),
        concurrency: args.concurrency,
        duration_secs: args.duration,
        user_count: users.len(),
        timestamp: chrono::Utc::now(),
    };

    let results = metrics.to_results(metadata);

    // Print summary
    println!("\n{}", results.format_text());

    // Save to file
    let json = serde_json::to_string_pretty(&results)?;
    std::fs::write(&args.output, &json)?;
    tracing::info!("Results saved to {:?}", args.output);

    Ok(())
}

fn select_user_index(
    users: &[TestUser],
    scenario: TestScenario,
    request_num: usize,
    hot_count: usize,
) -> usize {
    match scenario {
        TestScenario::WarmCache => {
            // Always use first user
            0
        }
        TestScenario::ColdStart => {
            // Rotate through all users
            request_num % users.len()
        }
        TestScenario::Mixed => {
            // 80% hot users, 20% cold users (deterministic based on request_num)
            // If not enough users for separate pools, just rotate through all
            if users.len() <= hot_count {
                request_num % users.len()
            } else if !request_num.is_multiple_of(5) {
                // 80% hot user (from first 10%)
                request_num % hot_count
            } else {
                // 20% cold user (from remaining 90%)
                let cold_pool = users.len() - hot_count;
                hot_count + (request_num % cold_pool)
            }
        }
    }
}

async fn execute_request(
    client: &RpcClient,
    user: &TestUser,
    method: RpcMethod,
) -> crate::client::RequestResult {
    let (method_name, params) = match method {
        RpcMethod::GetPublicKey => ("get_public_key", vec![]),
        RpcMethod::SignEvent => {
            let event = json!({
                "kind": 1,
                "content": format!("Load test {}", chrono::Utc::now().timestamp()),
                "tags": [],
                "created_at": chrono::Utc::now().timestamp(),
                "pubkey": user.pubkey
            });
            ("sign_event", vec![event])
        }
        RpcMethod::Nip44Encrypt => {
            // Generate random recipient
            let recipient = nostr_sdk::Keys::generate().public_key().to_hex();
            (
                "nip44_encrypt",
                vec![json!(recipient), json!("test message for load testing")],
            )
        }
        RpcMethod::Register => {
            // Handled separately in worker loop, not through RPC
            unreachable!("Register is handled directly, not through execute_request")
        }
    };

    client.call(&user.ucan_token, method_name, params).await
}

fn generate_password() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}
