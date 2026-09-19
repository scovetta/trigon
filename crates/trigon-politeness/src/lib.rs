//! What this process asks of an upstream host, and how fast it asks.
//!
//! # Why this is a crate and not a field
//!
//! It was two halves in two crates, and they disagreed about which traffic they were describing.
//!
//! `trigon-registry::Client` paced its requests and named itself with a contact URL, and its module
//! documentation opens by saying upstream reputation is what breaks first at scale. All true, and
//! on the route that carries almost none of the bytes: resolution metadata. Every byte a build
//! fetches at `--egress mirror-only` goes through `trigon-mirror`, which built bare
//! `reqwest::Client`s with a `trigon-mirror/0.0.0` User-Agent, no spacing, and no 429 path at all.
//! A 186-run npm sweep put **143,362 requests** through the unpaced route, which projects to 219
//! per second against `registry.npmjs.org` for five hours on the sweep M4 asks for
//! (`docs/20-m4-plan.md` §2). That is the shape of traffic a registry blocks.
//!
//! **And the paced half was not paced across a sweep either.** The spacing lived in a field on
//! `Client`, and a sweep builds a fresh `Client` per target — which the same struct's own doc
//! comment says, eight lines below that field, as the reason its *traffic counter* had to be a
//! process-global `static`. The counter was fixed and the limiter beside it was not, so the
//! declared 100 ms floor reset on every target and multiplied by every lane. A rate limit that
//! multiplies by concurrency is not one.
//!
//! So: **one map, holding the pacing and the counting together**, for the whole process. A host
//! that is counted here is paced here, and neither can drift from the other, because there is no
//! second place to put them.
//!
//! # Reserving rather than checking
//!
//! [`pace`] does not ask "was the last request long enough ago". Sixteen lanes asking that at once
//! all get the same answer and all fire at once. It **claims the next slot** and returns how long
//! to wait for it, so concurrent callers queue behind one another at the declared interval instead
//! of racing to read a timestamp none of them has written yet.
//!
//! That is also what makes [`throttled`] work: a 429 seen by one lane pushes the shared slot out,
//! so every other lane waits too. One worker learning that a host is unhappy is something all of
//! them need to know, and within a process this is how they find out. Across a fleet it needs the
//! queue, which is M4's Stage B.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// What this process has asked of one host, and what it said back.
///
/// A sweep that exhausts a rate limit does not slow down: it starts failing, each failure lands on
/// a different target, and the run reports a reproduction rate with infrastructure faults mixed
/// into it. Counting is what lets a sweep say "GitHub stopped answering after 60 requests" rather
/// than "140 packages have no strategy".
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HostTraffic {
    pub requests: u64,
    /// Times the host told us to slow down: a 429, or a 403 carrying an exhausted rate-limit
    /// header. Non-zero means the numbers from this run are about our politeness, not the packages.
    pub throttled: u64,
    /// Requests that failed after every retry.
    pub failed: u64,
}

/// One host's counters and its next free slot, together.
#[derive(Default)]
struct Host {
    traffic: HostTraffic,
    /// The instant this host may next be asked. `None` before the first request.
    ///
    /// Held beside the counters on purpose: the defect this crate exists for is that the traffic
    /// that was counted was not paced and the traffic that was paced was not counted.
    next: Option<Instant>,
}

/// `BTreeMap` so a report reads the same way twice.
static HOSTS: Mutex<BTreeMap<String, Host>> = Mutex::new(BTreeMap::new());

/// The minimum gap between two requests to the same host, in milliseconds.
static MIN_INTERVAL_MS: AtomicU64 = AtomicU64::new(100);

/// How long to wait after a 429 that carried no `Retry-After`.
///
/// Long enough to be a real pause and short enough that a sweep does not stall on one bad minute.
/// A server that told us what it wanted overrides this; guessing against one that did is how
/// throttling becomes a ban.
const BLIND_BACKOFF: Duration = Duration::from_secs(30);

/// The minimum gap between two requests to the same host.
pub fn min_interval() -> Duration {
    Duration::from_millis(MIN_INTERVAL_MS.load(Ordering::Relaxed))
}

/// Set the gap. Process-wide, and meant to be called once at startup.
pub fn set_min_interval(d: Duration) {
    MIN_INTERVAL_MS.store(d.as_millis() as u64, Ordering::Relaxed);
}

/// The User-Agent every outbound request carries, on every route.
///
/// **An anonymous crawler is the thing registries block first**, and the traffic that matters was
/// the traffic nobody could trace back to a person: the mirror sent `trigon-mirror/0.0.0` with no
/// contact URL while carrying every byte of a sweep. One string, so there is no route left that
/// declares itself differently.
pub fn user_agent() -> String {
    format!(
        "trigon/{} (+https://github.com/trigon-dev/trigon; rebuild verification)",
        env!("CARGO_PKG_VERSION")
    )
}

/// Wait until `host` may be asked again, and claim that slot.
pub async fn pace(host: &str) {
    let wait = reserve(host);
    if !wait.is_zero() {
        tokio::time::sleep(wait).await;
    }
}

/// Claim the next slot for `host`, and say how long it is until then.
///
/// Separated from the sleep so it can be tested without a clock, and so the lock is never held
/// across an await.
fn reserve(host: &str) -> Duration {
    let interval = min_interval();
    let now = Instant::now();
    let Ok(mut hosts) = HOSTS.lock() else {
        // A poisoned lock means another thread panicked while holding it. Pacing is not worth
        // taking the process down for, and the counters are not evidence of anything.
        return Duration::ZERO;
    };
    let host = hosts.entry(host.to_string()).or_default();
    let at = host.next.filter(|t| *t > now).unwrap_or(now);
    host.next = Some(at + interval);
    at.saturating_duration_since(now)
}

/// Record one request to a host.
///
/// **Git is egress too.** A sweep opens roughly two connections to a forge per target — an
/// `ls-remote` to resolve a tag and a `fetch` to get the commit — which at 400 targets is more
/// conversations with github.com than with either registry, and none of them go through an HTTP
/// client of ours. Counting them here means one table answers "what did we ask of whom", which is
/// the question a throttled run needs answered.
pub fn note_request(host: &str) {
    with(host, |h| h.traffic.requests += 1);
}

/// Record one request that failed after every retry.
pub fn note_failure(host: &str) {
    with(host, |h| h.traffic.failed += 1);
}

/// Record that a host told us to slow down, and hold every caller off until it is ready.
///
/// `retry_after` is what the server asked for. Honouring it is the difference between being
/// throttled and being banned.
pub fn throttled(host: &str, retry_after: Option<Duration>) {
    let until = Instant::now() + retry_after.unwrap_or(BLIND_BACKOFF);
    with(host, |h| {
        h.traffic.throttled += 1;
        // Never brought forward. A slot already further out was put there by a longer backoff or a
        // deeper queue, and moving it closer would undo somebody else's wait.
        if h.next.is_none_or(|t| t < until) {
            h.next = Some(until);
        }
    });
}

/// What this process has asked of each host so far.
pub fn traffic() -> BTreeMap<String, HostTraffic> {
    let Ok(hosts) = HOSTS.lock() else {
        return BTreeMap::new();
    };
    hosts
        .iter()
        .map(|(name, h)| (name.clone(), h.traffic.clone()))
        .collect()
}

/// What has been asked of each host since `before` was taken.
///
/// The table is process-wide, and a sweep runs hundreds of targets through it. A run that recorded
/// the raw table would claim every earlier target's traffic as its own, and the last target of a
/// sweep would look like the worst offender in it. Hosts that saw nothing in the interval are left
/// out rather than recorded as zeroes.
pub fn since(before: &BTreeMap<String, HostTraffic>) -> BTreeMap<String, HostTraffic> {
    traffic()
        .into_iter()
        .filter_map(|(host, now)| {
            let was = before.get(&host).cloned().unwrap_or_default();
            let delta = HostTraffic {
                requests: now.requests.saturating_sub(was.requests),
                throttled: now.throttled.saturating_sub(was.throttled),
                failed: now.failed.saturating_sub(was.failed),
            };
            (delta != HostTraffic::default()).then_some((host, delta))
        })
        .collect()
}

/// Add one table into another, host by host.
///
/// For a caller assembling a run's account from more than one source: this process's own requests
/// and, at an enforced tier, the mirror's — which run in a different process inside the build's
/// network namespace and cannot hand a counter back.
pub fn merge(into: &mut BTreeMap<String, HostTraffic>, other: BTreeMap<String, HostTraffic>) {
    for (host, t) in other {
        let e = into.entry(host).or_default();
        e.requests += t.requests;
        e.throttled += t.throttled;
        e.failed += t.failed;
    }
}

/// Forget everything. For tests, which share a process and would otherwise share a limiter.
pub fn reset() {
    if let Ok(mut hosts) = HOSTS.lock() {
        hosts.clear();
    }
    set_min_interval(Duration::from_millis(100));
}

fn with(host: &str, f: impl FnOnce(&mut Host)) {
    if let Ok(mut hosts) = HOSTS.lock() {
        f(hosts.entry(host.to_string()).or_default());
    }
}

/// The host part of a URL, for the table key.
///
/// A parse failure keys on the whole string rather than dropping the request from the count: an
/// unparseable URL is still a request somebody made, and a counter that silently omits what it
/// cannot classify under-reports exactly when something is wrong.
pub fn host_of(url: &str) -> String {
    url.split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url)
        .split(['/', '?', '#'])
        .next()
        .filter(|h| !h.is_empty())
        .map(|h| h.split('@').next_back().unwrap_or(h))
        .unwrap_or(url)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialized, because the thing under test is a process-global and a parallel test would be
    /// racing it rather than exercising it.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn guard() -> std::sync::MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn concurrent_callers_queue_instead_of_all_reading_the_same_timestamp() {
        // The bug this replaces: the old limiter asked "was the last request long enough ago",
        // which sixteen lanes all answer "yes" to at the same instant. Sixteen requests leave
        // together and the declared interval describes nothing. Reserving a slot means the tenth
        // caller waits nine intervals, which is what a rate limit is.
        let _g = guard();
        reset();
        set_min_interval(Duration::from_millis(50));

        let waits: Vec<Duration> = (0..4).map(|_| reserve("registry.npmjs.org")).collect();
        assert_eq!(
            waits[0],
            Duration::ZERO,
            "the first caller waits for nothing"
        );
        for (i, w) in waits.iter().enumerate().skip(1) {
            let expected = Duration::from_millis(50 * i as u64);
            // Reserving takes real time, so the claim is a floor rather than an equality.
            assert!(
                *w <= expected && *w + Duration::from_millis(10) >= expected,
                "caller {i} waited {w:?}, not about {expected:?}"
            );
        }
        // And another host is not behind this one's queue.
        assert_eq!(reserve("pypi.org"), Duration::ZERO);
    }

    #[test]
    fn the_limiter_does_not_reset_when_a_caller_does() {
        // A sweep builds a fresh registry client per target, which is why the traffic counter had
        // to be process-global. The limiter beside it kept resetting, so the floor restarted four
        // hundred times. There is no longer anything to construct.
        let _g = guard();
        reset();
        set_min_interval(Duration::from_millis(80));
        assert_eq!(reserve("example.test"), Duration::ZERO);
        let second = reserve("example.test");
        assert!(second > Duration::from_millis(60), "{second:?}");
    }

    #[test]
    fn a_host_that_says_slow_down_holds_off_every_caller_and_not_just_the_one_that_heard_it() {
        // One lane sees the 429. Every other lane is about to make the same request to the same
        // host, and within a process this is the only thing that can tell them.
        let _g = guard();
        reset();
        throttled("crates.io", Some(Duration::from_secs(5)));
        let wait = reserve("crates.io");
        assert!(wait > Duration::from_secs(4), "{wait:?}");
        assert_eq!(traffic()["crates.io"].throttled, 1);
    }

    #[test]
    fn a_longer_backoff_is_never_shortened_by_a_lighter_one() {
        // Two 429s in flight, the second carrying a smaller `Retry-After`. Taking the smaller
        // would undo the wait the first one bought, and the second server did not say "you may
        // now go faster" — it answered a request that was already in the air.
        let _g = guard();
        reset();
        throttled("slow.test", Some(Duration::from_secs(30)));
        throttled("slow.test", Some(Duration::from_secs(1)));
        assert!(reserve("slow.test") > Duration::from_secs(25));
    }

    #[test]
    fn the_user_agent_says_who_we_are_and_where_to_complain() {
        // An anonymous crawler is the thing registries block first, and the route carrying every
        // byte of a sweep was anonymous.
        let ua = user_agent();
        assert!(ua.starts_with("trigon/"), "{ua}");
        assert!(ua.contains("https://github.com/trigon-dev/trigon"), "{ua}");
    }

    #[test]
    fn counting_and_pacing_are_the_same_table() {
        // The defect in one line: a host that this process paced is a host it can report on.
        let _g = guard();
        reset();
        let _ = reserve("counted.test");
        note_request("counted.test");
        note_failure("counted.test");
        let t = &traffic()["counted.test"];
        assert_eq!((t.requests, t.failed, t.throttled), (1, 1, 0));
    }

    #[test]
    fn a_run_reports_its_own_traffic_and_not_the_sweep_before_it() {
        // The table is process-wide on purpose. A run that wrote the raw table into its record
        // would say the last target of a four-hundred-target sweep asked GitHub for everything.
        let _g = guard();
        reset();
        note_request("github.com");
        note_request("github.com");
        let before = traffic();

        note_request("github.com");
        note_failure("registry.npmjs.org");
        let mine = since(&before);

        assert_eq!(mine["github.com"].requests, 1, "two of those were not mine");
        assert_eq!(mine["registry.npmjs.org"].failed, 1);
        // A host that saw nothing in the interval is absent, not a row of zeroes.
        assert_eq!(mine.len(), 2);
        assert!(!since(&traffic()).contains_key("github.com"));
    }

    #[test]
    fn a_url_reduces_to_the_host_it_names() {
        assert_eq!(
            host_of("https://registry.npmjs.org/once"),
            "registry.npmjs.org"
        );
        assert_eq!(host_of("http://127.0.0.1:8099/x?y=1"), "127.0.0.1:8099");
        assert_eq!(host_of("https://user:pw@example.test/p"), "example.test");
        // Unparseable is still a request somebody made.
        assert_eq!(host_of("not a url"), "not a url");
    }
}
