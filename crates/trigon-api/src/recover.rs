//! Turning a bug into a sentence instead of a dropped connection.
//!
//! A panic in an axum handler unwinds out of the connection task. Hyper drops the socket, and the
//! browser reports **"NetworkError when attempting to fetch resource"** — which tells a reader
//! nothing, does not distinguish a bug from a server that is not running, and leaves no trace in
//! the page. That is the report this module exists because of.
//!
//! With this layer the same bug is a `500` carrying the panic's own message, logged with the route
//! that reached it. The front-end already renders a refusal's `detail`, so a reader sees *"the
//! server hit a bug reading that member"* and can say which member. That is the difference between
//! a report somebody can act on and one that says the network broke.
//!
//! **It does not make a panic acceptable.** A handler that panics has a defect and the log says so
//! at `error`. What it buys is that the defect is visible, attributable to one request, and does
//! not take the page down with it — and that the *next* bug of this kind arrives as a description
//! rather than as a transport error.

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use futures::FutureExt as _;
use std::panic::AssertUnwindSafe;

/// Run the rest of the stack, and answer even if it panics.
pub async fn catch_panics(req: Request, next: Next) -> Response {
    // Captured before the request is consumed, because the whole value of this is naming what
    // broke. A 500 that cannot say which route produced it is barely better than the dropped
    // connection it replaces.
    let method = req.method().clone();
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());

    // `AssertUnwindSafe` because `Next` is not `UnwindSafe` and cannot be: it owns the rest of the
    // stack. The assertion this makes is that observing a half-finished handler is acceptable, and
    // here it is — the handlers this wraps are readers. They hold no lock a caller can see across
    // an await, and the one piece of shared mutable state, the index, is a cache that
    // `index::read_or_recover` rebuilds rather than trusting.
    match AssertUnwindSafe(next.run(req)).catch_unwind().await {
        Ok(response) => response,
        Err(payload) => {
            // `&*payload`, not `&payload`. `payload` is a `Box<dyn Any + Send>`, and `&payload`
            // unsizes the *box itself* to `&dyn Any` — so the downcasts below look for a `String`
            // and find a `Box`, and every panic reports "no message". Caught by
            // `a_panicking_handler_answers_instead_of_dropping_the_connection`, which asserts on
            // the message rather than only on the status, and which is the reason to assert on
            // content at all: the status was right the whole time.
            let detail = message_of(&*payload);
            tracing::error!(%method, %path, panic = %detail, "a handler panicked");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({
                    "error": "server_bug",
                    "detail": format!(
                        "this request hit a bug in the server rather than a problem with the data: \
                         {detail}. Nothing is wrong with the run you were looking at; the rest of \
                         the site still works, and this is worth reporting with the address above."
                    ),
                })),
            )
                .into_response()
        }
    }
}

/// What a panic payload says, where it says anything.
///
/// `panic!("…")` gives a `String`, `panic!("literal")` a `&'static str`, and a panic from a library
/// that carried something else gives neither. The third case says so rather than rendering a type
/// name nobody can act on.
fn message_of(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else {
        "the panic carried no message".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape the real call site has: a `Box<dyn Any + Send>`, dereferenced.
    ///
    /// The unit test below passed while the handler reported "no message" for every panic, because
    /// it built `&*boxed` by hand and the caller wrote `&boxed`. A test that constructs its own
    /// argument differently from the code under test is a test of something else.
    #[test]
    fn a_boxed_payload_is_read_through_the_box_and_not_as_one() {
        let payload: Box<dyn std::any::Any + Send> = Box::new("index out of bounds".to_string());
        assert_eq!(message_of(&*payload), "index out of bounds");

        // And the mistake itself, written down: taking a reference to the box hands `dyn Any` a
        // `Box<dyn Any>`, whose downcast to `String` correctly fails.
        let as_box: &dyn std::any::Any = &payload;
        assert!(as_box.downcast_ref::<String>().is_none());
        assert!(
            as_box
                .downcast_ref::<Box<dyn std::any::Any + Send>>()
                .is_some()
        );
    }

    #[test]
    fn a_panic_message_survives_in_both_of_its_shapes() {
        let owned: Box<dyn std::any::Any + Send> = Box::new("index out of bounds".to_string());
        assert_eq!(message_of(&*owned), "index out of bounds");

        let literal: Box<dyn std::any::Any + Send> = Box::new("attempt to subtract with overflow");
        assert_eq!(message_of(&*literal), "attempt to subtract with overflow");

        // A payload that is neither says so, rather than reporting a type name.
        let other: Box<dyn std::any::Any + Send> = Box::new(42u32);
        assert!(message_of(&*other).contains("no message"));
    }
}
