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

/// What kind of thing a request is asking for.
///
/// **The routes are not alike and one floor for all of them was wrong.** The 100 ms came from
/// `trigon-registry::ClientConfig`, where it governs *metadata* — resolving a package, asking a
/// forge about a tag — and where it is plainly right: an index document is a decision, it is
/// assembled per request, and it is the thing a registry most wants asked for gently.
///
/// When the limiter moved to the mirror it started governing every artifact and toolchain fetch
/// too, because that is what the mirror proxies. A build installing eight hundred dependencies then
/// paid eighty seconds of pure spacing on tarballs alone — measured on the 125-target random sweep,
/// where it was the dominant cost and looked like a hang.
///
/// A `.tgz` at an immutable URL is a CDN object, served by infrastructure built for exactly this,
/// and the fetch cache already collapses 86.7% of the repeats. It does not want the same floor.
///
/// The numbers below are deliberately conservative rather than tuned: picking them by how fast they
/// make a sweep feel is how a rate limit becomes decorative. `Index` keeps the number the careful
/// client already used and nobody has complained about. `Bytes` is five times faster and still an
/// order of magnitude below what a CDN serves without noticing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    /// A document that decides something: a packument, a simple index, a registration, a sparse
    /// index line. Assembled per request and the expensive kind for a registry to serve.
    Index,
    /// Bytes at an immutable URL: an artifact, a toolchain tarball. A CDN object.
    Bytes,
}

/// The gap between two `Index` requests to one host.
static INDEX_INTERVAL_MS: AtomicU64 = AtomicU64::new(100);
/// The gap between two `Bytes` requests to one host.
static BYTES_INTERVAL_MS: AtomicU64 = AtomicU64::new(20);

/// How long to wait after a 429 that carried no `Retry-After`.
///
/// Long enough to be a real pause and short enough that a sweep does not stall on one bad minute.
/// A server that told us what it wanted overrides this; guessing against one that did is how
/// throttling becomes a ban.
const BLIND_BACKOFF: Duration = Duration::from_secs(30);

/// The gap between two requests of this kind to one host.
pub fn min_interval_for(route: Route) -> Duration {
    Duration::from_millis(match route {
        Route::Index => INDEX_INTERVAL_MS.load(Ordering::Relaxed),
        Route::Bytes => BYTES_INTERVAL_MS.load(Ordering::Relaxed),
    })
}

/// The index gap, which is the one the careful client has always declared.
pub fn min_interval() -> Duration {
    min_interval_for(Route::Index)
}

/// Set a gap. Process-wide, and meant to be called once at startup.
pub fn set_min_interval_for(route: Route, d: Duration) {
    let ms = d.as_millis() as u64;
    match route {
        Route::Index => INDEX_INTERVAL_MS.store(ms, Ordering::Relaxed),
        Route::Bytes => BYTES_INTERVAL_MS.store(ms, Ordering::Relaxed),
    }
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

/// Wait until `host` may be asked again for something of this kind, and claim that slot.
///
/// **One queue per host, whatever the route.** The two intervals say how far apart *this* request
/// pushes the next one, not that a host has two independent budgets — a registry counts requests,
/// not categories, and two queues would mean the declared rate is the sum of them.
pub async fn pace(host: &str, route: Route) {
    let wait = reserve(host, route);
    if !wait.is_zero() {
        tokio::time::sleep(wait).await;
    }
}

/// Claim the next slot for `host`, and say how long it is until then.
///
/// Separated from the sleep so it can be tested without a clock, and so the lock is never held
/// across an await.
fn reserve(host: &str, route: Route) -> Duration {
    let interval = min_interval_for(route);
    // Shared where a directory was named, so every process using it queues in one line. Falls
    // through to the in-memory queue when the file cannot be used, which is slower to notice but
    // never faster than no limit at all.
    if let Ok(g) = SHARED.lock()
        && let Some(dir) = g.as_ref()
        && let Some(wait) = reserve_shared(dir, host, interval)
    {
        return wait;
    }
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
    let wait = retry_after.unwrap_or(BLIND_BACKOFF);
    let until = Instant::now() + wait;
    with(host, |h| {
        h.traffic.throttled += 1;
        // Never brought forward. A slot already further out was put there by a longer backoff or a
        // deeper queue, and moving it closer would undo somebody else's wait.
        if h.next.is_none_or(|t| t < until) {
            h.next = Some(until);
        }
    });
    // **And the shared slot, where there is one.** `reserve` reads the file first and never
    // consults the map above while a directory is shared, so a backoff written only there held off
    // nobody: the mirror, which always shares its cache directory, waited out its declared interval
    // and asked again of a host that had just told it how long to wait.
    if let Ok(g) = SHARED.lock()
        && let Some(dir) = g.as_ref()
    {
        let _ = hold_shared(dir, host, now_micros() + wait.as_micros() as u64);
    }
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

/// Requests another of our processes made on our behalf, after the fact.
///
/// **A rate limit is about us, not about our process tree.** At an enforced tier the mirror runs
/// inside the build's network namespace, in its own process, and every byte a build fetches goes
/// through it — so a table that held only what *this* process asked for reported 3 requests for a
/// run that made 399. The mirror cannot hand a counter back across the island, but its transcript
/// names the upstream URL of every body that crossed, and its 429s come out through its log.
///
/// Counted, never paced: that traffic has already happened, and the process that made it did its
/// own pacing. Adding it here is what makes [`traffic`] the whole account, so a sweep's summary and
/// the number in the mail to a registry come from one place.
pub fn note_remote(host: &str, t: &HostTraffic) {
    with(host, |h| {
        h.traffic.requests += t.requests;
        h.traffic.throttled += t.throttled;
        h.traffic.failed += t.failed;
    });
}

/// Forget everything. For tests, which share a process and would otherwise share a limiter.
pub fn reset() {
    if let Ok(mut hosts) = HOSTS.lock() {
        hosts.clear();
    }
    if let Ok(mut g) = SHARED.lock() {
        *g = None;
    }
    set_min_interval_for(Route::Index, Duration::from_millis(100));
    set_min_interval_for(Route::Bytes, Duration::from_millis(20));
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

    pub(super) fn guard() -> std::sync::MutexGuard<'static, ()> {
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
        set_min_interval_for(Route::Index, Duration::from_millis(50));

        let waits: Vec<Duration> = (0..4)
            .map(|_| reserve("registry.npmjs.org", Route::Index))
            .collect();
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
        assert_eq!(reserve("pypi.org", Route::Index), Duration::ZERO);
    }

    #[test]
    fn the_limiter_does_not_reset_when_a_caller_does() {
        // A sweep builds a fresh registry client per target, which is why the traffic counter had
        // to be process-global. The limiter beside it kept resetting, so the floor restarted four
        // hundred times. There is no longer anything to construct.
        let _g = guard();
        reset();
        set_min_interval_for(Route::Index, Duration::from_millis(80));
        assert_eq!(reserve("example.test", Route::Index), Duration::ZERO);
        let second = reserve("example.test", Route::Index);
        assert!(second > Duration::from_millis(60), "{second:?}");
    }

    #[test]
    fn a_host_that_says_slow_down_holds_off_every_caller_and_not_just_the_one_that_heard_it() {
        // One lane sees the 429. Every other lane is about to make the same request to the same
        // host, and within a process this is the only thing that can tell them.
        let _g = guard();
        reset();
        throttled("crates.io", Some(Duration::from_secs(5)));
        let wait = reserve("crates.io", Route::Index);
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
        assert!(reserve("slow.test", Route::Index) > Duration::from_secs(25));
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
        let _ = reserve("counted.test", Route::Index);
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
    fn traffic_another_process_made_on_our_behalf_is_still_ours() {
        // The mirror runs inside the build's network namespace in its own process, and every byte
        // a build fetches goes through it. A table holding only this process's requests said 3 for
        // a run that made 399 — and a rate limit is about us, not about our process tree.
        let _g = guard();
        reset();
        note_request("registry.npmjs.org");
        note_remote(
            "registry.npmjs.org",
            &HostTraffic {
                requests: 395,
                throttled: 1,
                failed: 0,
            },
        );
        let t = &traffic()["registry.npmjs.org"];
        assert_eq!((t.requests, t.throttled), (396, 1));
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

#[cfg(test)]
mod routes_are_not_alike {
    use super::tests::guard;
    use super::*;

    #[test]
    fn a_tarball_does_not_wait_as_long_as_a_packument() {
        // The measurement behind this: on the 125-target random sweep the 100 ms floor governed
        // every artifact fetch as well as every index one, so a build installing hundreds of
        // dependencies paid the floor on each tarball. That was the dominant cost and it looked
        // like a hang.
        let _g = guard();
        reset();
        assert!(
            min_interval_for(Route::Bytes) < min_interval_for(Route::Index),
            "an immutable CDN object does not want a packument's floor"
        );
        // And neither is zero. A rate limit that stops applying to the bulk of the traffic is a
        // rate limit that has been turned off for the traffic that matters.
        assert!(min_interval_for(Route::Bytes) > Duration::ZERO);
    }

    #[test]
    fn one_host_has_one_queue_whatever_the_route() {
        // Two independent budgets would mean the declared rate is their sum, and a registry counts
        // requests rather than categories. The route decides how far *this* request pushes the
        // next one, not which queue it joins.
        let _g = guard();
        reset();
        set_min_interval_for(Route::Index, Duration::from_millis(100));
        set_min_interval_for(Route::Bytes, Duration::from_millis(10));

        assert_eq!(reserve("one.test", Route::Index), Duration::ZERO);
        // The next request waits behind the index one whatever kind it is.
        let after = reserve("one.test", Route::Bytes);
        assert!(after > Duration::from_millis(80), "{after:?}");
        // And having waited an index interval, the bytes request only pushes the next one 10ms.
        let third = reserve("one.test", Route::Index);
        assert!(
            third > after && third < after + Duration::from_millis(40),
            "{after:?} then {third:?}"
        );
    }

    #[test]
    fn a_host_told_us_to_slow_down_and_that_holds_for_both_routes() {
        // A 429 is about the host, not about what was asked of it.
        let _g = guard();
        reset();
        throttled("busy.test", Some(Duration::from_secs(5)));
        assert!(reserve("busy.test", Route::Bytes) > Duration::from_secs(4));
    }
}

// -------------------------------------------------------------------------------------------
// Sharing the queue between processes.
// -------------------------------------------------------------------------------------------

/// A directory the limiter keeps its slots in, so separate processes queue behind one another.
///
/// **The mirror is per-target, so process-global was never machine-global.** At an enforced tier
/// each target gets its own mirror container, which is its own process with its own copy of the map
/// above — so a sweep at four lanes declared one floor and kept four. A rate limit that multiplies
/// by concurrency is the thing this crate exists to stop, and it was still doing it one level up.
///
/// `None` keeps everything in memory, which is right for a single process and is what a
/// `trigon rebuild` on a laptop gets.
static SHARED: Mutex<Option<std::path::PathBuf>> = Mutex::new(None);

/// Queue against every other process using `dir`.
///
/// The mirror is handed the fetch cache's directory, which is already a mount shared by every
/// mirror container in a sweep. `flock` on a bind mount is the same lock in every container: one
/// kernel, one inode.
pub fn share_with(dir: std::path::PathBuf) {
    if std::fs::create_dir_all(dir.join("pace")).is_err() {
        tracing::warn!("cannot share the rate limiter through {}", dir.display());
        return;
    }
    if let Ok(mut g) = SHARED.lock() {
        *g = Some(dir);
    }
}

/// Wall-clock microseconds. Not `Instant`: that is process-local by construction and two processes
/// cannot compare theirs, which is the whole difficulty of sharing a slot.
fn now_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

/// One file per host, holding the microsecond at which it may next be asked.
///
/// Hashed rather than named, because a host is attacker-influenced in the sense that matters here:
/// it comes from a URL a package's metadata chose, and a path assembled from one is a traversal
/// waiting to happen.
fn slot_path(dir: &std::path::Path, host: &str) -> std::path::PathBuf {
    use sha2::Digest as _;
    dir.join("pace")
        .join(&format!("{:x}", sha2::Sha256::digest(host.as_bytes()))[..32])
}

/// Claim the next slot for `host` in the shared file, returning how long until it.
///
/// Returns `None` where the file cannot be used at all, and the caller falls back to the in-memory
/// queue — a limiter that failed open on a permissions problem would be a control that reports
/// success while doing nothing, which is the defect this repository keeps finding.
fn reserve_shared(dir: &std::path::Path, host: &str, interval: Duration) -> Option<Duration> {
    with_slot(dir, host, |stored, now| {
        let at = stored.max(now);
        (
            at + interval.as_micros() as u64,
            Duration::from_micros(at - now),
        )
    })
}

/// Push the shared slot for `host` out to `until`, in wall-clock microseconds.
///
/// Never brought forward, for the reason [`throttled`] gives about the in-memory one.
fn hold_shared(dir: &std::path::Path, host: &str, until: u64) -> Option<()> {
    with_slot(dir, host, |stored, _| (stored.max(until), ()))
}

/// Lock `host`'s slot file, hand `update` what it holds and the wall clock, and store the slot it
/// returns. `None` where the file cannot be used at all.
fn with_slot<R>(
    dir: &std::path::Path,
    host: &str,
    update: impl FnOnce(u64, u64) -> (u64, R),
) -> Option<R> {
    use std::io::{Read as _, Seek as _, Write as _};
    use std::os::unix::io::AsRawFd as _;

    let path = slot_path(dir, host);
    // Made on demand as well as by `share_with`. A directory that disappeared mid-sweep — a tmpfs
    // cleaner, a pruned cache — would otherwise silently drop every process back to its own
    // private queue, which is the multiplication this exists to stop, returning quietly.
    if let Some(parent) = path.parent()
        && std::fs::create_dir_all(parent).is_err()
    {
        return None;
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .ok()?;

    // Blocking, unlike the container store's lock: this is held for one read and one write of
    // eight bytes, so a waiter is waiting microseconds. The store's lock is held for a whole build,
    // which is why that one refuses to block.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return None;
    }
    let mut buf = [0u8; 8];
    let stored = match file.read_exact(&mut buf) {
        Ok(()) => u64::from_le_bytes(buf),
        // A fresh file, or a torn one. Either way the honest reading is "no slot claimed yet".
        Err(_) => 0,
    };
    let (next, answer) = update(stored, now_micros());
    let written = file
        .seek(std::io::SeekFrom::Start(0))
        .and_then(|_| file.write_all(&next.to_le_bytes()))
        .is_ok();
    let _ = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    if !written {
        return None;
    }
    Some(answer)
}

#[cfg(test)]
mod shared_across_processes {
    use super::*;
    // The same lock the other test modules take. Everything here drives process-global state, so
    // two locks would be two groups of tests racing rather than one group serialized.
    use super::tests::guard;

    /// A directory of this test's own, removed when the test is done with it.
    struct Dir(std::path::PathBuf);

    impl std::ops::Deref for Dir {
        type Target = std::path::PathBuf;
        fn deref(&self) -> &std::path::PathBuf {
            &self.0
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn dir(name: &str) -> Dir {
        let d = std::env::temp_dir().join(format!("trigon-pace-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Dir(d)
    }

    #[test]
    fn a_second_process_queues_behind_the_first_rather_than_beside_it() {
        // The bug this closes: at an enforced tier every target gets its own mirror container, so
        // the "process-global" limiter was one limiter per target. Four lanes declared one floor
        // and kept four. The file is the only thing two containers share.
        let _g = guard();
        reset();
        let d = dir("two-processes");

        // Two callers that share nothing but the directory — which is what two containers with the
        // same bind mount have.
        let first = reserve_shared(&d, "registry.npmjs.org", Duration::from_millis(100));
        let second = reserve_shared(&d, "registry.npmjs.org", Duration::from_millis(100));
        assert_eq!(first, Some(Duration::ZERO));
        let second = second.expect("the slot file is usable");
        assert!(
            second >= Duration::from_millis(90),
            "the second caller did not wait: {second:?}"
        );

        // A different host is a different queue, as it is in memory.
        assert_eq!(
            reserve_shared(&d, "pypi.org", Duration::from_millis(100)),
            Some(Duration::ZERO)
        );
    }

    #[test]
    fn the_slot_survives_the_process_that_wrote_it() {
        // The property the in-memory map cannot have: a mirror container exits after every target,
        // and the next one must not start from zero.
        let _g = guard();
        reset();
        let d = dir("survives");
        let _ = reserve_shared(&d, "a.test", Duration::from_secs(2));
        // Nothing of the first caller remains except the file.
        let again = reserve_shared(&d, "a.test", Duration::from_secs(2)).unwrap();
        assert!(again > Duration::from_millis(1500), "{again:?}");
    }

    #[test]
    fn a_host_from_a_package_cannot_choose_a_path() {
        // The host comes from a URL in registry metadata, which a package controls. A file named
        // after it would be a traversal; the name is a digest.
        let d = dir("traversal");
        let evil = slot_path(&d, "../../etc/passwd");
        assert!(evil.starts_with(d.join("pace")), "{evil:?}");
        assert!(
            evil.file_name()
                .unwrap()
                .to_string_lossy()
                .chars()
                .all(|c| c.is_ascii_hexdigit()),
            "{evil:?}"
        );
    }

    #[test]
    fn an_unusable_directory_falls_back_rather_than_failing_open() {
        // `reserve_shared` returning `None` sends the caller to the in-memory queue. What it must
        // never do is return `Some(ZERO)` on an error, which would be a limiter reporting success
        // while doing nothing.
        let missing = std::path::Path::new("/nonexistent-trigon-pace-dir");
        assert_eq!(
            reserve_shared(missing, "a.test", Duration::from_millis(100)),
            None
        );
    }

    #[test]
    fn a_shared_directory_is_where_this_processs_own_slots_are_claimed() {
        // `share_with` is how the mirror joins the line every other mirror in a sweep stands in.
        // A slot this process claims through `pace` has to land in the file, or the next container
        // starts from an empty queue.
        let _g = guard();
        reset();
        set_min_interval_for(Route::Index, Duration::from_millis(100));
        let d = dir("joined");
        share_with(d.clone());
        let first = reserve("joined.test", Route::Index);
        // Another process, which shares nothing with this one but the directory.
        let other = reserve_shared(&d, "joined.test", Duration::from_millis(100));
        reset();
        assert_eq!(first, Duration::ZERO);
        let other = other.expect("the slot file is usable");
        assert!(
            other >= Duration::from_millis(90),
            "the other process did not queue behind this one: {other:?}"
        );
    }

    #[test]
    fn a_directory_that_cannot_be_shared_leaves_the_in_memory_queue_in_force() {
        // A cache that is not a directory must not turn the limiter off: this process still paces
        // itself, which is slower to notice than a shared queue and never faster than no limit.
        let _g = guard();
        reset();
        set_min_interval_for(Route::Index, Duration::from_millis(100));
        let d = dir("not-a-directory");
        let file = d.join("file");
        std::fs::write(&file, b"").unwrap();
        share_with(file.join("cache"));
        let first = reserve("fallback.test", Route::Index);
        let second = reserve("fallback.test", Route::Index);
        reset();
        assert_eq!(first, Duration::ZERO);
        assert!(second > Duration::from_millis(60), "{second:?}");
        assert!(!file.join("cache").exists());
    }

    #[test]
    fn a_host_that_says_slow_down_holds_off_every_process_sharing_the_queue() {
        // The mirror always shares its cache directory, and `reserve` reads the file before the
        // map. A 429 recorded only in the map held off nobody: the mirror waited its declared 20ms
        // and asked again of a host that had just said how long to wait.
        let _g = guard();
        reset();
        let d = dir("throttled");
        share_with(d.clone());
        throttled("busy.test", Some(Duration::from_secs(5)));
        let here = reserve("busy.test", Route::Bytes);
        let other = reserve_shared(&d, "busy.test", Duration::from_millis(20));
        reset();
        assert!(here > Duration::from_secs(4), "this process: {here:?}");
        let other = other.expect("the slot file is usable");
        assert!(other > Duration::from_secs(4), "another process: {other:?}");
    }

    #[test]
    fn a_lighter_backoff_does_not_shorten_the_shared_one() {
        // The file keeps the rule the map keeps: a slot further out was put there by a longer wait
        // or a deeper queue, and a second, smaller `Retry-After` does not undo it.
        let _g = guard();
        reset();
        let d = dir("never-forward");
        share_with(d.clone());
        throttled("slow.test", Some(Duration::from_secs(30)));
        throttled("slow.test", Some(Duration::from_secs(1)));
        let wait = reserve_shared(&d, "slow.test", Duration::from_millis(20));
        reset();
        assert!(wait.unwrap() > Duration::from_secs(25), "{wait:?}");
    }
}
