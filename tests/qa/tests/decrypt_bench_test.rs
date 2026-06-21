// ABOUTME: Benchmark — serial vs bounded-parallel nip44_decrypt RPC throughput.
// ABOUTME: Models the mobile DM drain (each gift wrap = 2 sequential decrypts:
// ABOUTME: gift->seal, seal->rumor) parallelized across messages. Proves the
// ABOUTME: Keycast HTTP RPC server does NOT serialize per-token decrypts, so a
// ABOUTME: bounded-concurrency client (Fix A) scales near-linearly. Run against
// ABOUTME: the local stack (USE_GCP_KMS=false), so per-call latency is the local
// ABOUTME: symmetric path, NOT the prod ~300ms GCP-KMS handler-miss cost — a
// ABOUTME: projection at prod latency is printed from the measured concurrency.

use futures::stream::{self, StreamExt};
use keycast_qa_tests::fixtures::{TestApp, TestUser};
use keycast_qa_tests::helpers::nip46::Nip46Client;
use keycast_qa_tests::helpers::oauth::OAuthClient;
use keycast_qa_tests::helpers::server::TestServer;
use nostr::Keys;
use std::time::{Duration, Instant};

#[derive(serde::Serialize)]
struct RpcReq<'a> {
    method: &'a str,
    params: Vec<serde_json::Value>,
}

#[derive(serde::Deserialize)]
struct RpcResp {
    result: Option<serde_json::Value>,
    error: Option<String>,
}

async fn decrypt_once(
    client: &reqwest::Client,
    url: &str,
    token: &str,
    pubkey: &str,
    ciphertext: &str,
    extra_ms: u64,
) -> Result<f64, String> {
    let t = Instant::now();
    let req = RpcReq {
        method: "nip44_decrypt",
        params: vec![serde_json::json!(pubkey), serde_json::json!(ciphertext)],
    };
    let resp = client
        .post(url)
        .header("Authorization", format!("Bearer {token}"))
        .json(&req)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = resp.status();
    let body: RpcResp = resp.json().await.map_err(|e| e.to_string())?;
    if let Some(err) = body.error {
        return Err(format!("rpc error ({status}): {err}"));
    }
    if body.result.is_none() {
        return Err(format!("no result ({status})"));
    }
    // Optional injected per-call latency (BENCH_EXTRA_LATENCY_MS): models the
    // prod GCP-KMS + network response time that the local stack lacks, so the
    // serial-vs-parallel overlap is measured rather than just projected.
    if extra_ms > 0 {
        tokio::time::sleep(Duration::from_millis(extra_ms)).await;
    }
    Ok(t.elapsed().as_secs_f64() * 1000.0)
}

fn pct(sorted: &[f64], p: usize) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    sorted[(sorted.len() * p / 100).min(sorted.len() - 1)]
}

// Perf benchmark, not a gating test: it needs a live keycast + does an OAuth
// flow and timing, so it is opt-in. Run it explicitly against a running stack:
//   TEST_SERVER_URL=http://localhost:43000 \
//   DATABASE_URL=postgres://postgres:password@localhost:15432/keycast \
//   cargo test -p keycast-qa-tests --test decrypt_bench_test -- --ignored --nocapture
// Local keycast runs USE_GCP_KMS=false, so per-call latency is the local
// symmetric path; pass BENCH_EXTRA_LATENCY_MS=300 to model the prod KMS cost.
#[ignore = "perf benchmark; run explicitly with --ignored against a live keycast"]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn bench_serial_vs_parallel_nip44_decrypt() {
    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    let extra_ms: u64 = std::env::var("BENCH_EXTRA_LATENCY_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server.clone());
    let user = TestUser::generate();
    let app = TestApp::default();

    // Register, then verify email. Emails are disabled locally so the token sits
    // in the users table; the async bcrypt worker means verify must be polled
    // until it stops returning "processing".
    oauth.register_user(&user).await.ok();

    let pool = server
        .db_pool()
        .await
        .expect("db pool (set DATABASE_URL=postgres://postgres:password@localhost:15432/keycast)");
    let mut vtoken: Option<String> = None;
    for _ in 0..25 {
        vtoken = sqlx::query_scalar::<_, Option<String>>(
            "SELECT email_verification_token FROM users WHERE email = $1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(&user.email)
        .fetch_optional(&pool)
        .await
        .unwrap_or(None)
        .flatten();
        if vtoken.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let vtoken = vtoken.expect("verification token in users table");

    let http = reqwest::Client::new();
    let mut verified = false;
    for _ in 0..20 {
        let r = http
            .post(format!("{}/api/auth/verify-email", server.base_url))
            .header("Origin", "http://localhost:5173")
            .json(&serde_json::json!({ "token": vtoken }))
            .send()
            .await
            .expect("verify-email request");
        let body: serde_json::Value = r.json().await.unwrap_or_default();
        if body.get("success").and_then(|v| v.as_bool()) == Some(true) {
            verified = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(800)).await;
    }
    assert!(verified, "email verification did not complete");

    let token_resp = oauth
        .complete_oauth_flow(&user, &app)
        .await
        .expect("OAuth flow should complete");
    let token = token_resp.access_token.clone().expect("access token");
    let url = format!("{}/api/nostr", server.base_url);

    // Setup (untimed): build distinct (pubkey, ciphertext) pairs so each decrypt
    // exercises a real per-sender ECDH conversation-key derivation.
    let nip46 = Nip46Client::from_token_response(
        token_resp.bunker_url.clone(),
        Some(token.clone()),
        server.base_url.clone(),
    )
    .expect("client");

    let n_distinct = 24usize;
    let mut pairs: Vec<(String, String)> = Vec::with_capacity(n_distinct);
    for i in 0..n_distinct {
        let pk = Keys::generate().public_key().to_hex();
        let pt = format!("benchmark message {i} — the quick brown fox jumps over the lazy dog");
        let ct = nip46.nip44_encrypt(&pk, &pt).await.expect("encrypt");
        pairs.push((pk, ct));
    }

    let client = reqwest::Client::builder()
        .build()
        .expect("reqwest client");

    // Warm the per-token handler cache (untimed).
    for (pk, ct) in pairs.iter().take(6) {
        decrypt_once(&client, &url, &token, pk, ct, 0).await.expect("warmup");
    }

    // Each DM requires TWO sequential decrypts (gift->seal, seal->rumor).
    let messages: usize = 100;
    let decrypts_per_msg = 2usize;
    let total_decrypts = messages * decrypts_per_msg;

    // ---- SERIAL: every decrypt awaited one at a time (current mobile behavior). ----
    let mut per_call: Vec<f64> = Vec::with_capacity(total_decrypts);
    let t0 = Instant::now();
    for m in 0..messages {
        for k in 0..decrypts_per_msg {
            let (pk, ct) = &pairs[(m + k) % pairs.len()];
            let ms = decrypt_once(&client, &url, &token, pk, ct, extra_ms)
                .await
                .expect("serial decrypt");
            per_call.push(ms);
        }
    }
    let serial_total = t0.elapsed().as_secs_f64() * 1000.0;
    per_call.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let avg = per_call.iter().sum::<f64>() / per_call.len() as f64;

    // ---- PARALLEL: one task per message (its 2 decrypts stay sequential),
    //      messages run at bounded concurrency C. This is exactly Fix A. ----
    async fn run_parallel(
        client: &reqwest::Client,
        url: &str,
        token: &str,
        pairs: &[(String, String)],
        messages: usize,
        decrypts_per_msg: usize,
        conc: usize,
        extra_ms: u64,
    ) -> f64 {
        let t = Instant::now();
        stream::iter(0..messages)
            .map(|m| async move {
                for k in 0..decrypts_per_msg {
                    let (pk, ct) = &pairs[(m + k) % pairs.len()];
                    decrypt_once(client, url, token, pk, ct, extra_ms)
                        .await
                        .expect("parallel decrypt");
                }
            })
            .buffer_unordered(conc)
            .collect::<Vec<_>>()
            .await;
        t.elapsed().as_secs_f64() * 1000.0
    }

    let par4 = run_parallel(&client, &url, &token, &pairs, messages, decrypts_per_msg, 4, extra_ms).await;
    let par8 = run_parallel(&client, &url, &token, &pairs, messages, decrypts_per_msg, 8, extra_ms).await;
    let par16 = run_parallel(&client, &url, &token, &pairs, messages, decrypts_per_msg, 16, extra_ms).await;

    println!("\n========= nip44_decrypt: SERIAL vs BOUNDED-PARALLEL (local keycast, USE_GCP_KMS=false) =========");
    println!(
        "model: {messages} DMs x {decrypts_per_msg} sequential decrypts = {total_decrypts} RPCs; {n_distinct} distinct sender keys; 1 shared keep-alive client"
    );
    println!("injected per-call latency = {extra_ms} ms (BENCH_EXTRA_LATENCY_MS; models prod KMS+network)");
    println!(
        "per-call latency (local): avg={avg:6.2}  p50={:6.2}  p95={:6.2}  p99={:6.2} ms",
        pct(&per_call, 50),
        pct(&per_call, 95),
        pct(&per_call, 99)
    );
    println!("------------------------------------------------------------------------------------------------");
    println!("SERIAL      total = {serial_total:9.1} ms");
    println!("PARALLEL c=4  total = {par4:9.1} ms   speedup x{:.2}", serial_total / par4);
    println!("PARALLEL c=8  total = {par8:9.1} ms   speedup x{:.2}", serial_total / par8);
    println!("PARALLEL c=16 total = {par16:9.1} ms   speedup x{:.2}", serial_total / par16);
    println!("------------------------------------------------------------------------------------------------");
    println!("PROJECTION at production per-call latency (GCP-KMS warm-handler path, from device logs):");
    for plat in [250.0f64, 300.0, 400.0] {
        let serial_proj = plat * total_decrypts as f64;
        println!(
            "  @ {plat:.0} ms/call: SERIAL ~{:.1}s  ->  PARALLEL c=8 ~{:.1}s   (drain of {messages} DMs)",
            serial_proj / 1000.0,
            serial_proj / 8000.0
        );
    }
    println!("================================================================================================\n");

    assert!(par8 < serial_total, "parallel@8 must beat serial");
}
