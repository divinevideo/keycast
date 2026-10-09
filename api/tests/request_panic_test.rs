// ABOUTME: Runs an HTTP server under the production panic hook in a child process: a panicking
// ABOUTME: request gets a 500 while the process keeps serving, and other panics still exit

use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware,
    routing::get,
    Router,
};
use keycast_api::api::http::request_panics::contain_request_panics;
use keycast_core::metrics::METRICS;
use keycast_core::panic_scope;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tower_http::trace::TraceLayer;

/// Selects what the re-executed test binary does; the child tests are no-ops without it.
const CHILD_MODE: &str = "KEYCAST_PANIC_TEST_CHILD";
const LISTENING: &str = "panic-test-listening ";
const CHILD_TIMEOUT: Duration = Duration::from_secs(60);
/// The serve child stops on its own after this, in case its parent dies without killing it.
const CHILD_LIFETIME: Duration = Duration::from_secs(300);
const PANIC_PATHS: [&str; 3] = ["/panic", "/panic-in-blocking-work", "/panic-in-subtask"];

async fn panicking_handler() -> &'static str {
    panic!("handler failure")
}

async fn panicking_blocking_work() -> StatusCode {
    match panic_scope::spawn_blocking::<_, ()>(|| panic!("blocking work failure")).await {
        Ok(()) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

async fn panicking_subtask() -> StatusCode {
    let subtask = panic_scope::propagate(async { panic!("subtask failure") });
    match tokio::spawn(subtask).await {
        Ok(()) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn init_child() {
    tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stdout)
        .init();
    panic_scope::install_hook();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "child process started by request_panic_returns_500_and_the_server_keeps_serving"]
async fn child_serves_under_the_panic_hook() {
    if std::env::var(CHILD_MODE).as_deref() != Ok("serve") {
        return;
    }
    init_child();

    // Same layer order as production: the request span wraps panic containment.
    let app = Router::new()
        .route(PANIC_PATHS[0], get(panicking_handler))
        .route(PANIC_PATHS[1], get(panicking_blocking_work))
        .route(PANIC_PATHS[2], get(panicking_subtask))
        .route("/ok", get(|| async { "ok" }))
        .route("/metrics", get(|| async { METRICS.to_prometheus() }))
        .layer(middleware::from_fn(contain_request_panics))
        .layer(TraceLayer::new_for_http().make_span_with(
            |request: &Request<Body>| tracing::info_span!("request", path = %request.uri().path()),
        ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    println!("{LISTENING}{}", listener.local_addr().unwrap());
    let _ = tokio::time::timeout(CHILD_LIFETIME, axum::serve(listener, app)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "child process started by panic_outside_request_handling_exits_the_process"]
async fn child_panics_in_a_background_task() {
    if std::env::var(CHILD_MODE).as_deref() != Ok("background") {
        return;
    }
    init_child();

    // Without the hook's exit, the panic stays inside the task, this test
    // passes, and the child exits with status 0.
    let _ = tokio::spawn(async { panic!("background task failure") }).await;
}

struct ChildProcess {
    child: Child,
    lines: mpsc::UnboundedReceiver<String>,
    seen: Vec<String>,
}

impl ChildProcess {
    fn start(mode: &str, test_name: &str) -> Self {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                test_name,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_MODE, mode)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let (sender, lines) = mpsc::unbounded_channel();
        forward_lines(child.stdout.take().unwrap(), sender.clone());
        forward_lines(child.stderr.take().unwrap(), sender);
        Self {
            child,
            lines,
            seen: Vec::new(),
        }
    }

    /// Wait for `marker` and return the rest of its line. The marker can follow
    /// libtest's `test <name> ... ` on the same line.
    async fn wait_for_marker(&mut self, marker: &str) -> String {
        let found = tokio::time::timeout(CHILD_TIMEOUT, async {
            while let Some(line) = self.lines.recv().await {
                self.seen.push(line.clone());
                if let Some((_, rest)) = line.split_once(marker) {
                    return Some(rest.trim().to_string());
                }
            }
            None
        })
        .await;
        match found {
            Ok(Some(rest)) => rest,
            _ => panic!("child never printed {marker:?}:\n{}", self.output()),
        }
    }

    /// Everything the child has printed, once its output streams close.
    async fn finish_output(&mut self) -> String {
        while let Ok(Some(line)) = tokio::time::timeout(CHILD_TIMEOUT, self.lines.recv()).await {
            self.seen.push(line);
        }
        self.output()
    }

    /// Everything the child has printed so far.
    fn output(&mut self) -> String {
        while let Ok(line) = self.lines.try_recv() {
            self.seen.push(line);
        }
        self.seen.join("\n")
    }
}

fn forward_lines(
    stream: impl AsyncRead + Unpin + Send + 'static,
    sender: mpsc::UnboundedSender<String>,
) {
    tokio::spawn(async move {
        let mut lines = BufReader::new(stream).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if sender.send(line).is_err() {
                break;
            }
        }
    });
}

#[tokio::test]
async fn request_panic_returns_500_and_the_server_keeps_serving() {
    let mut server = ChildProcess::start("serve", "child_serves_under_the_panic_hook");
    let addr = server.wait_for_marker(LISTENING).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(CHILD_TIMEOUT)
        .build()
        .unwrap();

    for path in PANIC_PATHS {
        let response = client
            .get(format!("http://{addr}{path}"))
            .send()
            .await
            .unwrap_or_else(|error| panic!("{path}: {error}\n{}", server.output()));
        assert_eq!(response.status(), 500, "{path}\n{}", server.output());

        let response = client
            .get(format!("http://{addr}/ok"))
            .send()
            .await
            .unwrap_or_else(|error| panic!("after {path}: {error}\n{}", server.output()));
        assert_eq!(response.status(), 200, "after {path}\n{}", server.output());
        assert_eq!(response.text().await.unwrap(), "ok");
    }

    let metrics = client
        .get(format!("http://{addr}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        metrics.contains("keycast_http_request_panics_total 3"),
        "every contained panic is counted:\n{metrics}"
    );

    assert!(
        server.child.try_wait().unwrap().is_none(),
        "the server process exited:\n{}",
        server.output()
    );
    server.child.kill().await.unwrap();

    let output = server.finish_output().await;
    let request_panics: Vec<&str> = output
        .lines()
        .filter(|line| line.contains(r#""event":"request_panic""#))
        .collect();
    assert_eq!(request_panics.len(), 3, "each panic is logged:\n{output}");
    for path in PANIC_PATHS {
        let in_span = format!(r#""path":"{path}""#);
        assert!(
            request_panics.iter().any(|line| line.contains(&in_span)),
            "the panic on {path} is logged in its request span:\n{output}"
        );
    }
    assert!(!output.contains(r#""event":"fatal_panic""#), "{output}");
}

#[tokio::test]
async fn panic_outside_request_handling_exits_the_process() {
    let mut child = ChildProcess::start("background", "child_panics_in_a_background_task");
    let status = tokio::time::timeout(CHILD_TIMEOUT, child.child.wait())
        .await
        .expect("the child should exit")
        .unwrap();
    let output = child.finish_output().await;

    assert_eq!(status.code(), Some(1), "{output}");
    assert!(output.contains(r#""event":"fatal_panic""#), "{output}");
}
