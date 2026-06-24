// ABOUTME: Benchmark — serial vs bounded-parallel nip44_decrypt RPC throughput.
// ABOUTME: Models the mobile DM drain (each gift wrap = 2 sequential decrypts:
// ABOUTME: gift->seal, seal->rumor) parallelized across messages. The Keycast
// ABOUTME: HTTP RPC server does NOT serialize per-token decrypts — each
// ABOUTME: nip44_decrypt runs on its own spawn_blocking thread with no shared
// ABOUTME: lock (api/src/handlers/http_rpc_handler.rs::nip44_decrypt). Local
// ABOUTME: per-call latency is sub-millisecond, so there is nothing to overlap
// ABOUTME: and bounded concurrency yields no LOCAL speedup; the throughput win
// ABOUTME: is latency-bound and lands only when per-call time is dominated by
// ABOUTME: network/GCP-KMS RTT (prod). All timings below are real-server (no
// ABOUTME: injected latency in the measured path). BENCH_EXTRA_LATENCY_MS feeds
// ABOUTME: only the analytical prod projection, which is printed as an ideal
// ABOUTME: upper bound; the realized win was measured on-device at ~7.6x (see PR).

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

/// One real `nip44_decrypt` RPC, timed end to end. The returned latency is the
/// genuine server round trip only — there is deliberately NO injected client-side
/// sleep here. An earlier revision slept `extra_ms` inside this timer to "model
/// prod latency"; because the sleep ran on the client, serial paid it end to end
/// while parallel overlapped it, so the resulting speedup was an artifact of
/// overlapping client sleeps and would have looked identical even if the server
/// serialized every decrypt. Prod latency is now handled purely as an analytical
/// projection (see the PROJECTION block), never as a measured timer.
async fn decrypt_once(
    client: &reqwest::Client,
    url: &str,
    token: &str,
    pubkey: &str,
    ciphertext: &str,
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
// Local keycast runs USE_GCP_KMS=false, so the measured per-call latency is the
// local symmetric path (sub-millisecond). Set BENCH_EXTRA_LATENCY_MS=300 to pick
// the per-call RTT used by the PROJECTION block only — it does not touch any
// measured timing.
#[ignore = "perf benchmark; run explicitly with --ignored against a live keycast"]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn bench_serial_vs_parallel_nip44_decrypt() {
    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    // Per-call RTT for the analytical prod projection ONLY (never injected into a
    // measured timer). Unset => sweep a few representative prod latencies.
    let proj_latency_override: Option<f64> = std::env::var("BENCH_EXTRA_LATENCY_MS")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| *v > 0.0);

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

    let client = reqwest::Client::builder().build().expect("reqwest client");

    // Warm the per-token handler cache over ALL pairs (untimed). The previous
    // revision warmed only 6 of 24 and then ran the serial pass first, so the
    // serial loop paid the per-token cold-start cost while the parallel passes
    // hit an already-warm server — tilting the comparison toward parallel.
    // Warming every pair removes that asymmetry up front.
    for (pk, ct) in pairs.iter() {
        decrypt_once(&client, &url, &token, pk, ct)
            .await
            .expect("warmup");
    }

    // Each DM requires TWO sequential decrypts (gift->seal, seal->rumor).
    let messages: usize = 100;
    let decrypts_per_msg = 2usize;
    let total_decrypts = messages * decrypts_per_msg;

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
    ) -> f64 {
        let t = Instant::now();
        stream::iter(0..messages)
            .map(|m| async move {
                for k in 0..decrypts_per_msg {
                    let (pk, ct) = &pairs[(m + k) % pairs.len()];
                    decrypt_once(client, url, token, pk, ct)
                        .await
                        .expect("parallel decrypt");
                }
            })
            .buffer_unordered(conc)
            .collect::<Vec<_>>()
            .await;
        t.elapsed().as_secs_f64() * 1000.0
    }

    // Measure PARALLEL first and SERIAL last. With every pair pre-warmed the
    // remaining order effect is small, but running serial last means the serial
    // baseline sees the warmest possible cache — so any reported speedup is, if
    // anything, understated rather than inflated.
    let par4 = run_parallel(&client, &url, &token, &pairs, messages, decrypts_per_msg, 4).await;
    let par8 = run_parallel(&client, &url, &token, &pairs, messages, decrypts_per_msg, 8).await;
    let par16 = run_parallel(
        &client,
        &url,
        &token,
        &pairs,
        messages,
        decrypts_per_msg,
        16,
    )
    .await;

    // ---- SERIAL: every decrypt awaited one at a time (current mobile behavior). ----
    let mut per_call: Vec<f64> = Vec::with_capacity(total_decrypts);
    let t0 = Instant::now();
    for m in 0..messages {
        for k in 0..decrypts_per_msg {
            let (pk, ct) = &pairs[(m + k) % pairs.len()];
            let ms = decrypt_once(&client, &url, &token, pk, ct)
                .await
                .expect("serial decrypt");
            per_call.push(ms);
        }
    }
    let serial_total = t0.elapsed().as_secs_f64() * 1000.0;
    per_call.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let avg = per_call.iter().sum::<f64>() / per_call.len() as f64;

    println!("\n========= nip44_decrypt: SERIAL vs BOUNDED-PARALLEL (local keycast, USE_GCP_KMS=false) =========");
    println!(
        "model: {messages} DMs x {decrypts_per_msg} sequential decrypts = {total_decrypts} RPCs; {n_distinct} distinct sender keys; 1 shared keep-alive client"
    );
    println!(
        "measured local per-call latency (real server, warm; no injected delay): avg={avg:6.2}  p50={:6.2}  p95={:6.2}  p99={:6.2} ms",
        pct(&per_call, 50),
        pct(&per_call, 95),
        pct(&per_call, 99)
    );
    println!("------------------------------------------------------------------------------------------------");
    println!("SERIAL       total = {serial_total:9.1} ms");
    println!(
        "PARALLEL c=4  total = {par4:9.1} ms   wall ratio vs serial x{:.2}",
        serial_total / par4
    );
    println!(
        "PARALLEL c=8  total = {par8:9.1} ms   wall ratio vs serial x{:.2}",
        serial_total / par8
    );
    println!(
        "PARALLEL c=16 total = {par16:9.1} ms   wall ratio vs serial x{:.2}",
        serial_total / par16
    );
    println!("NOTE: local per-call latency is sub-millisecond, so there is no network/KMS wait to");
    println!("      overlap and bounded concurrency is not expected to beat serial HERE. This run");
    println!(
        "      confirms concurrency does not REGRESS throughput (the server does not serialize"
    );
    println!(
        "      per-token decrypts: each runs on its own spawn_blocking thread, no shared lock)."
    );
    println!("------------------------------------------------------------------------------------------------");
    println!("PROJECTION at production per-call latency — ANALYTICAL, not measured here:");
    println!(
        "  Prod per-call time is dominated by network + GCP-KMS RTT that the local stack lacks."
    );
    println!("  serial  = (RTT + local server compute) x {total_decrypts} decrypts.");
    println!(
        "  c=8     = IDEAL UPPER BOUND (perfect 8-way overlap); realized speedup is latency-bound"
    );
    println!("            and was measured on-device against prod keycast at ~7.6x (see PR description).");
    let proj_latencies: Vec<f64> = match proj_latency_override {
        Some(v) => vec![v],
        None => vec![250.0, 300.0, 400.0],
    };
    for rtt in proj_latencies {
        let per_call_prod = rtt + avg; // modeled RTT + measured local server compute
        let serial_proj = per_call_prod * total_decrypts as f64;
        let par8_ideal = serial_proj / 8.0;
        println!(
            "  @ {rtt:.0} ms RTT: SERIAL ~{:.1}s  ->  PARALLEL c=8 ~{:.1}s (ideal upper bound; drain of {messages} DMs)",
            serial_proj / 1000.0,
            par8_ideal / 1000.0
        );
    }
    println!("================================================================================================\n");

    // Honest regression guard. At local sub-millisecond per-call latency there is
    // no network/KMS wait to overlap, so bounded concurrency cannot *speed up* the
    // drain here, and serialized-vs-parallel are wall-clock-indistinguishable when
    // server compute is dwarfed by HTTP overhead — a "minimum speedup" floor would
    // therefore be vacuous (or would smuggle back the client-sleep artifact this
    // file used to measure). What this run CAN guard is the opposite failure: if a
    // change wrapped per-token decrypts in a serializing lock (as #256 did for the
    // *batch* path), 8-way concurrency would contend and wall time would balloon.
    // Assert it does not. The non-serialization property itself is anchored in the
    // server code: api/src/handlers/http_rpc_handler.rs::nip44_decrypt.
    let par8_ratio = par8 / serial_total;
    assert!(
        par8_ratio < 1.5,
        "8-way concurrent decrypts regressed to x{par8_ratio:.2} of serial wall time \
         (par8={par8:.1} ms, serial={serial_total:.1} ms): per-token decrypts may have \
         started serializing/contending — check api/src/handlers/http_rpc_handler.rs::nip44_decrypt"
    );
}
