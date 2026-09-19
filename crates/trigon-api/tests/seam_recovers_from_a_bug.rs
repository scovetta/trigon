//! A bug in one handler is one bad answer, not a dropped connection.
//!
//! The report that led here: *"Serve crashed — Not shown. NetworkError when attempting to fetch
//! resource"*. The first half is the front-end's catch block; the second is what a browser says
//! when a fetch fails at the transport level. A panicking handler and a server that is not running
//! are indistinguishable from the page, which makes the one report that matters — *what broke* —
//! impossible to give.

use std::sync::Arc;
use trigon_api::{Api, Index, Principal, Switches};
use trigon_store::Store;

async fn call(router: &mut axum::Router, path: &str) -> (u16, String) {
    use axum::body::Body;
    use axum::http::Request;
    use tower_service::Service as _;

    let res = router
        .call(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .expect("the stack answered at all");
    let status = res.status().as_u16();
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// A handler that panics. A named function with a concrete return type, because a closure
/// returning `!` gives axum nothing to infer a response from.
async fn boom() -> String {
    panic!("index out of bounds: the len is 3 but the index is 7")
}

fn api() -> Arc<Api> {
    Arc::new(Api {
        store: Arc::new(Store::in_memory()),
        queue: None,
        index: Index::new(),
        switches: Switches::default(),
        unauthenticated: Principal::Operator,
        member_reads: trigon_api::default_member_permits(),
    })
}

/// A handler that panics produces a 500 that names the panic.
#[tokio::test]
async fn a_panicking_handler_answers_instead_of_dropping_the_connection() {
    // The layer under test wraps whatever router it is given, so the fixture is a route that
    // definitely panics rather than a real handler that might.
    let mut router = axum::Router::new()
        .route("/boom", axum::routing::get(boom))
        .layer(axum::middleware::from_fn(trigon_api::recover::catch_panics));

    let (status, body) = call(&mut router, "/boom").await;
    assert_eq!(
        status, 500,
        "the connection was dropped rather than answered"
    );
    assert!(body.contains("server_bug"), "{body}");
    assert!(
        body.contains("index out of bounds: the len is 3 but the index is 7"),
        "the answer did not carry the panic's own message: {body}"
    );
    // And it says plainly that this is ours rather than a problem with the data, because the first
    // thing a reader wonders is whether the package they were looking at is broken.
    assert!(body.contains("bug in the server"), "{body}");
}

/// The server keeps serving afterwards.
///
/// The half of the report that says "crashed": one bad request must not take the process, or the
/// rest of the site, with it.
#[tokio::test]
async fn one_bug_does_not_take_the_site_down() {
    let mut router = axum::Router::new()
        .route("/boom", axum::routing::get(boom))
        .merge(trigon_api::router(api()))
        .layer(axum::middleware::from_fn(trigon_api::recover::catch_panics));

    let (first, _) = call(&mut router, "/v1/health").await;
    assert_eq!(first, 200);

    let (boom, _) = call(&mut router, "/boom").await;
    assert_eq!(boom, 500);

    let (after, body) = call(&mut router, "/v1/health").await;
    assert_eq!(
        after, 200,
        "the site stopped answering after one panic: {body}"
    );
    assert!(body.contains("\"ok\":true"), "{body}");
}
