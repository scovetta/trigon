//! Both kill-switches, reported side by side (`docs/19` §3): this server's own, which stops what
//! it shows, and the evidence repository's, which stops what `trigon publish` publishes. Each is
//! reported as what it is; neither is read as the other; and a repository switch nobody could read
//! is `unknown`, never clear.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use trigon_api::{
    Api, Index, Principal, RepositorySwitch, RepositorySwitchReader, SwitchState, Switches,
};
use trigon_store::Store;

fn api(stop: bool, who: Principal, switch: Option<RepositorySwitch>) -> Arc<Api> {
    api_reading(
        stop,
        who,
        switch.map(|s| {
            let read: RepositorySwitchReader = Arc::new(move || s.clone());
            read
        }),
    )
}

fn api_reading(stop: bool, who: Principal, read: Option<RepositorySwitchReader>) -> Arc<Api> {
    Arc::new(Api {
        store: Arc::new(Store::in_memory()),
        queue: None,
        index: Index::new(),
        switches: Switches {
            stop_divergences: stop,
            ..Switches::default()
        },
        unauthenticated: who,
        decompiler: None,
        member_reads: trigon_api::default_member_permits(),
        repository_switch: read,
    })
}

async fn get(api: Arc<Api>, uri: &str) -> Vec<u8> {
    use axum::body::Body;
    use axum::http::Request;
    use tower_service::Service as _;

    let mut router = trigon_api::router(api);
    let res = router
        .call(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 200);
    axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap()
        .to_vec()
}

async fn health(api: Arc<Api>) -> serde_json::Value {
    serde_json::from_slice(&get(api, "/v1/health").await).unwrap()
}

fn switch(state: SwitchState) -> RepositorySwitch {
    RepositorySwitch {
        state,
        repository: "/srv/trigon-evidence.git".into(),
        as_of: Some("2026-09-28T12:00:00Z".into()),
        detail: "read from the working clone /home/op/store/publish/ab/clone".into(),
    }
}

#[tokio::test]
async fn each_switch_is_reported_as_what_it_is_and_stops_only_what_it_says() {
    // The repository's set, this server's clear: the server still reports its own as running.
    let h = health(api(
        false,
        Principal::Operator,
        Some(switch(SwitchState::Set)),
    ))
    .await;
    assert_eq!(h["divergence_publication"], "running");
    let k = &h["kill_switches"];
    assert_eq!(k["serve"]["set"], false);
    assert_eq!(k["repository"]["state"], "set");
    assert_eq!(k["repository"]["as_of"], "2026-09-28T12:00:00Z");
    assert!(
        k["repository"]["stops"]
            .as_str()
            .unwrap()
            .contains("what `trigon publish` publishes")
    );
    assert!(
        k["serve"]["stops"]
            .as_str()
            .unwrap()
            .contains("what this server shows")
    );
    assert_eq!(k["repository"]["repository"], "/srv/trigon-evidence.git");

    // This server's set, the repository's clear: each is its own.
    let h = health(api(
        true,
        Principal::Operator,
        Some(switch(SwitchState::Clear)),
    ))
    .await;
    assert_eq!(h["divergence_publication"], "stopped");
    assert_eq!(h["kill_switches"]["serve"]["set"], true);
    assert_eq!(h["kill_switches"]["repository"]["state"], "clear");
}

#[tokio::test]
async fn a_switch_nobody_could_read_is_unknown_and_none_configured_is_absent() {
    let unread = RepositorySwitch {
        as_of: None,
        ..switch(SwitchState::Unknown)
    };
    let h = health(api(false, Principal::Operator, Some(unread))).await;
    assert_eq!(h["kill_switches"]["repository"]["state"], "unknown");
    assert!(h["kill_switches"]["repository"]["as_of"].is_null());
    // No publish repository configured: nothing to report, and nothing reported as off.
    let h = health(api(false, Principal::Operator, None)).await;
    assert!(h["kill_switches"]["repository"].is_null());
    assert_eq!(h["kill_switches"]["serve"]["set"], false);
}

/// Where the repository is, and the clone it was read from, name directories of the host's: an
/// anonymous reader is told the switch and when it was read, and nothing of where.
#[tokio::test]
async fn an_anonymous_reader_is_told_the_state_and_not_where_it_was_read() {
    let h = health(api(
        false,
        Principal::Anonymous,
        Some(switch(SwitchState::Set)),
    ))
    .await;
    let r = &h["kill_switches"]["repository"];
    assert_eq!(r["state"], "set");
    assert!(r.get("repository").is_none(), "{r}");
    assert!(r.get("detail").is_none(), "{r}");
    assert!(!h.to_string().contains("/home/op"), "{h}");
}

/// The reader `trigon serve` is handed runs `git`. Wrapped as `serve` wraps it, it is read once
/// before anything is served and then only on its timer: however many readers ask `/v1/health` or
/// load a page, no request reads it, forks anything, or waits on it.
#[tokio::test]
async fn no_request_reads_the_repository_switch_itself() {
    let reads = Arc::new(AtomicUsize::new(0));
    let counted = reads.clone();
    let read: RepositorySwitchReader = Arc::new(move || {
        counted.fetch_add(1, Ordering::SeqCst);
        switch(SwitchState::Set)
    });
    let cached = trigon_api::cached_switch(read, Duration::from_secs(3600)).await;
    assert_eq!(reads.load(Ordering::SeqCst), 1, "read once, before serving");
    let api = api_reading(false, Principal::Anonymous, Some(cached));
    for _ in 0..40 {
        let h = health(api.clone()).await;
        assert_eq!(h["kill_switches"]["repository"]["state"], "set");
        get(api.clone(), "/runs/anything").await;
    }
    assert_eq!(reads.load(Ordering::SeqCst), 1, "no request read it");
}

/// Read on its timer, the switch a page reports follows the repository's: a switch set after
/// `serve` started is reported set once the timer has read it again.
#[tokio::test]
async fn the_switch_is_read_again_on_its_timer() {
    let set = Arc::new(AtomicBool::new(false));
    let seen = set.clone();
    let read: RepositorySwitchReader = Arc::new(move || {
        switch(match seen.load(Ordering::SeqCst) {
            true => SwitchState::Set,
            false => SwitchState::Clear,
        })
    });
    let cached = trigon_api::cached_switch(read, Duration::from_millis(20)).await;
    let api = api_reading(false, Principal::Operator, Some(cached));
    assert_eq!(
        health(api.clone()).await["kill_switches"]["repository"]["state"],
        "clear"
    );
    set.store(true, Ordering::SeqCst);
    let mut state = serde_json::Value::Null;
    for _ in 0..200 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        state = health(api.clone()).await["kill_switches"]["repository"]["state"].clone();
        if state == "set" {
            break;
        }
    }
    assert_eq!(state, "set");
}
