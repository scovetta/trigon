//! `trigon serve` refusing to start, and saying why.
//!
//! A server that cannot open the queue it was given, cannot list its corpus, or cannot bind is a
//! failure to start. Each of those serving anyway would look to a reader like something else: no
//! queue looks like a corpus-only instance, an unlistable corpus looks like an empty one, and only
//! one of those is our fault.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use trigon_api::{
    Config, Principal, RepositorySwitch, RepositorySwitchReader, SwitchState, Switches,
};
use trigon_store::Store;

fn config(bind: &str) -> Config {
    Config {
        bind: bind.into(),
        queue: None,
        unauthenticated: Principal::Operator,
        switches: Switches::default(),
        refresh_seconds: 0,
        decompiler: None,
        repository_switch: None,
    }
}

#[tokio::test]
async fn a_server_whose_queue_cannot_be_opened_does_not_start_without_it() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("no-such-dir").join("q.db");
    let e = trigon_api::run(
        Store::in_memory(),
        Config {
            queue: Some(format!("sqlite://{}?mode=rwc", missing.display())),
            ..config("127.0.0.1:0")
        },
    )
    .await
    .expect_err("a server started without the queue it was given");
    assert!(e.starts_with("opening the queue"), "{e}");
}

#[tokio::test]
async fn a_corpus_that_cannot_be_listed_is_a_failure_to_start_and_not_an_empty_site() {
    // A directory that walks into itself: the listing fails, whoever runs this.
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("runs")).unwrap();
    std::os::unix::fs::symlink(dir.path().join("runs"), dir.path().join("runs/again")).unwrap();
    let store = Store::local(dir.path()).unwrap();
    assert!(
        store.list_runs().await.is_err(),
        "the fixture must be a corpus that cannot be listed"
    );

    let e = trigon_api::run(store, config("127.0.0.1:0"))
        .await
        .expect_err("a server started over a corpus it could not list");
    assert!(e.starts_with("listing runs"), "{e}");
}

#[tokio::test]
async fn a_server_that_cannot_bind_says_where_it_was_asked_to_and_does_not_start() {
    // A port this test holds, on loopback: taken, so the bind fails whatever else is running.
    let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let taken = held.local_addr().unwrap().to_string();

    // The evidence repository's switch is read once before anything is served, and not again by
    // a server that never started serving.
    let reads = Arc::new(AtomicUsize::new(0));
    let counted = reads.clone();
    let read: RepositorySwitchReader = Arc::new(move || {
        counted.fetch_add(1, Ordering::SeqCst);
        RepositorySwitch {
            state: SwitchState::Clear,
            repository: "/srv/evidence.git".into(),
            as_of: None,
            detail: "read for the test".into(),
        }
    });
    let e = trigon_api::run(
        Store::in_memory(),
        Config {
            refresh_seconds: 3600,
            repository_switch: Some(read),
            ..config(&taken)
        },
    )
    .await
    .expect_err("a server started on a port somebody else holds");
    assert!(e.starts_with(&format!("binding {taken}")), "{e}");
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    drop(held);
}
