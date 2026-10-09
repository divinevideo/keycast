// ABOUTME: Process panic policy: a panic in HTTP request work fails only that request,
// ABOUTME: while a panic anywhere else (signer, cluster coordination, background writers) exits

use crate::metrics::METRICS;
use std::future::Future;
use tracing::Instrument;

tokio::task_local! {
    static REQUEST: ();
}

/// Install the process-wide panic hook.
///
/// Every panic is logged. A panic in HTTP request work (see [`scope`]) is also
/// counted and then unwinds, failing only that request: the request middleware
/// answers a handler panic with a 500, and blocking work or a subtask hands it
/// to the awaiting request as a `JoinError`. A task a request starts and does
/// not wait for ends there, with no response left to fail. Any other panic
/// exits the process, so a failed background task restarts the instance
/// instead of leaving it running without that task.
///
/// The hook decides before unwinding starts, which is why the request case has
/// to be known here rather than at the layer that catches it.
pub fn install_hook() {
    // Initialise the registry now so the hook never runs its initialiser.
    once_cell::sync::Lazy::force(&METRICS);
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_hook(info);

        let location = info
            .location()
            .map(ToString::to_string)
            .unwrap_or_else(|| "unknown".to_string());
        let panic_message = info.payload_as_str().unwrap_or("non-string panic payload");

        if in_request() {
            METRICS.inc_http_request_panics();
            tracing::error!(
                event = "request_panic",
                location = %location,
                panic_message = %panic_message,
                "Panic in HTTP request work; failing that request and continuing"
            );
        } else {
            tracing::error!(
                event = "fatal_panic",
                location = %location,
                panic_message = %panic_message,
                "Panic outside HTTP request handling; exiting"
            );
            std::process::exit(1);
        }
    }));
}

/// Whether the current code runs as HTTP request work (see [`scope`]).
pub fn in_request() -> bool {
    REQUEST.try_with(|_| ()).is_ok()
}

/// Run `fut` as HTTP request work.
///
/// A panic inside `fut` no longer exits the process: it unwinds out of the
/// returned future, so the caller must catch it.
pub fn scope<F: Future>(fut: F) -> impl Future<Output = F::Output> {
    REQUEST.scope((), fut)
}

/// Carry the caller's request scope, and its tracing span, into a task
/// spawned on its behalf.
///
/// Tasks start without the scope, so a task spawned for a request would
/// otherwise exit the process on panic like a background task.
pub fn propagate<F: Future>(fut: F) -> impl Future<Output = F::Output> {
    let request_span = in_request().then(tracing::Span::current);
    async move {
        match request_span {
            Some(span) => REQUEST.scope((), fut.instrument(span)).await,
            None => fut.await,
        }
    }
}

/// [`tokio::task::spawn_blocking`] that keeps the caller's request scope and
/// tracing span.
///
/// A panic in the closure then reaches the awaiting request as a
/// `JoinError` when the caller is request work, and exits the process
/// otherwise.
pub fn spawn_blocking<F, R>(f: F) -> tokio::task::JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    if in_request() {
        let span = tracing::Span::current();
        tokio::task::spawn_blocking(move || REQUEST.sync_scope((), || span.in_scope(f)))
    } else {
        tokio::task::spawn_blocking(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn scope_marks_request_work() {
        assert!(!in_request());
        assert!(scope(async { in_request() }).await);
        assert!(!in_request());
    }

    #[tokio::test]
    async fn spawn_blocking_keeps_the_callers_scope() {
        assert!(scope(async { spawn_blocking(in_request).await.unwrap() }).await);
        assert!(!spawn_blocking(in_request).await.unwrap());
    }

    #[tokio::test]
    async fn blocking_work_that_reenters_the_runtime_keeps_the_scope() {
        let in_scope = scope(async {
            spawn_blocking(|| tokio::runtime::Handle::current().block_on(async { in_request() }))
                .await
                .unwrap()
        })
        .await;
        assert!(in_scope);
    }

    #[tokio::test]
    async fn propagate_keeps_the_callers_scope() {
        let (propagated, plain) = scope(async {
            let propagated = tokio::spawn(propagate(async { in_request() }))
                .await
                .unwrap();
            let plain = tokio::spawn(async { in_request() }).await.unwrap();
            (propagated, plain)
        })
        .await;
        assert!(propagated);
        assert!(!plain, "a plain spawn from request work is background work");
        assert!(!tokio::spawn(propagate(async { in_request() }))
            .await
            .unwrap());
    }

    /// Under the installed hook this panic unwinds (covered end to end in
    /// api/tests/request_panic_test.rs); tokio then hands it to the caller.
    #[tokio::test]
    async fn tokio_reports_a_blocking_work_panic_to_the_awaiting_caller() {
        let result =
            scope(async { spawn_blocking::<_, ()>(|| panic!("blocking work failed")).await }).await;
        assert!(result.unwrap_err().is_panic());
    }
}
