//! One log line for a request the server did not finish before it answered: its deadline
//! ran out (the operation deadline, or the idle and rate rules of the upload), or the
//! client went away. Such a request ends with a typed refusal the client may never read,
//! or with none, and nothing else says why. (A response stream cut after its head is
//! reported by `service::operations::streaming`.)
//!
//! The line is a stderr line and a `tracing` event (target `oncl::request_abort`), like
//! the one of an aborted stream; every field is a number or a closed name, never an item
//! id, a document, a key, a token, a URL, a path or the peer's address. A request is
//! reported once, whichever of the places below sees its end first.

use oncl_api::{error::ErrorCode, server::ResponseFuture};
use std::{
    error::Error,
    io::Write,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

/// Why a request ended without its answer being whole.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reason {
    /// The operation deadline, or the idle or minimum-rate rule of the upload, ended it.
    DeadlineExceeded,
    /// Its control was cancelled before it ended.
    Cancelled,
    /// The client closed or reset the connection while the request was being read.
    ClientDisconnected,
    /// The request was dropped before it produced a response: the connection went away,
    /// or the server was stopping.
    Abandoned,
}

impl Reason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Reason::DeadlineExceeded => "deadline_exceeded",
            Reason::Cancelled => "cancelled",
            Reason::ClientDisconnected => "client_disconnected",
            Reason::Abandoned => "abandoned",
        }
    }
}

/// The line: `oncl-server: request aborted: route=hash reason=deadline_exceeded elapsed_ms=1500`.
pub(crate) fn line(route: &str, reason: Reason, elapsed_ms: u64) -> String {
    format!(
        "oncl-server: request aborted: route={route} reason={} elapsed_ms={elapsed_ms}",
        reason.as_str()
    )
}

/// The request being served by this task.
struct Request {
    route: &'static str,
    started: Instant,
    reported: AtomicBool,
}

impl Request {
    fn report(&self, reason: Reason) {
        if self.reported.swap(true, Ordering::AcqRel) {
            return;
        }
        let elapsed_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        // A closed stderr must never panic a request: `eprintln!` would.
        let _ = writeln!(
            std::io::stderr().lock(),
            "{}",
            line(self.route, reason, elapsed_ms)
        );
        match reason {
            Reason::DeadlineExceeded => tracing::warn!(
                target: "oncl::request_abort",
                route = self.route,
                reason = reason.as_str(),
                elapsed_ms,
                "request aborted"
            ),
            _ => tracing::info!(
                target: "oncl::request_abort",
                route = self.route,
                reason = reason.as_str(),
                elapsed_ms,
                "request aborted"
            ),
        }
    }
}

tokio::task_local! {
    static CURRENT: Arc<Request>;
}

/// Reported when the request future is dropped before it ended.
struct Unfinished(Arc<Request>, bool);

impl Drop for Unfinished {
    fn drop(&mut self) {
        if !self.1 {
            self.0.report(Reason::Abandoned);
        }
    }
}

/// `future` as the request of `route`: it reports its own abort. The body readers reach
/// the request through [`body_failed`].
pub(crate) fn watch(route: &'static str, future: ResponseFuture) -> ResponseFuture {
    Box::pin(async move {
        let request = Arc::new(Request {
            route,
            started: Instant::now(),
            reported: AtomicBool::new(false),
        });
        let mut unfinished = Unfinished(request.clone(), false);
        let result = CURRENT.scope(request.clone(), future).await;
        unfinished.1 = true;
        match result.as_ref().err().map(|error| error.code) {
            Some(ErrorCode::DeadlineExceeded) => request.report(Reason::DeadlineExceeded),
            Some(ErrorCode::Cancelled) => request.report(Reason::Cancelled),
            _ => {}
        }
        result
    })
}

/// A body frame that failed to arrive: reported when the cause is the client going away.
pub(crate) fn body_failed(error: &axum::Error) {
    if client_gone(error) {
        let _ = CURRENT.try_with(|request| request.report(Reason::ClientDisconnected));
    }
}

/// Whether `error` (or one of its sources) is the peer closing or resetting the connection
/// in the middle of the message.
fn client_gone(error: &(dyn Error + 'static)) -> bool {
    let mut next: Option<&(dyn Error + 'static)> = Some(error);
    while let Some(error) = next {
        if let Some(hyper) = error.downcast_ref::<hyper::Error>()
            && (hyper.is_incomplete_message() || hyper.is_canceled() || hyper.is_closed())
        {
            return true;
        }
        if let Some(io) = error.downcast_ref::<std::io::Error>()
            && matches!(
                io.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof
            )
        {
            return true;
        }
        next = error.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_line_is_numbers_and_closed_names() {
        assert_eq!(
            line("batch", Reason::ClientDisconnected, 12),
            "oncl-server: request aborted: route=batch reason=client_disconnected elapsed_ms=12"
        );
    }

    #[test]
    fn a_reset_is_a_client_going_away_and_a_refusal_is_not() {
        let reset = axum::Error::new(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
        assert!(client_gone(&reset));
        let other = axum::Error::new(std::io::Error::other("nope"));
        assert!(!client_gone(&other));
    }
}
