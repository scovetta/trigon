//! A lock that cannot be taken must not read as an empty answer.
//!
//! This crate reaches for `.lock()` and then `.unwrap_or_default()` in the two places that decide
//! whether a run is evidence of anything:
//!
//! ```ignore
//! pub fn trips(&self) -> Vec<Trip> { self.trips.lock().map(|t| t.clone()).unwrap_or_default() }
//! fn record(&self, trip: Trip) { /* log */ if let Ok(mut t) = self.trips.lock() { t.push(trip) } }
//! ```
//!
//! Both directions fail **open**. A poisoned mutex loses the write silently and hands the reader an
//! empty `Vec`, and `main.rs` turns an empty `Vec` into "nothing tripped, carry on" — the exact
//! shape `docs/16-findings.md` §3.12 named: *a control that fails open, and reports success while
//! doing it.* It is the same mistake the sandbox already fixed on the tier above, where
//! `Island::guard_trips` returns a `Result` precisely because *"we could not look" and "nothing
//! tripped" are different answers, and only one of them means the run is evidence of anything*.
//!
//! Not panicking on a poisoned lock is right — a poisoned mutex should not take down a sweep
//! worker that is hours into its budget. But `Vec<Trip>` has no room to say "could not look", so
//! the guard's safety rests entirely on a property nothing states and nothing tested:
//! **the guard's locks can never be poisoned, because nothing that can unwind ever runs while one
//! is held.** That property is one edit away from being false in either direction — move the
//! `tracing::error!` inside the `if let Ok(..)` block, or add a `?`-free fallible step under the
//! lock — and the failure is invisible, because the guard goes on answering "clean".
//!
//! So these tests pin the property rather than the expression. `podman.rs` already writes the same
//! rule down for its event sink — *"the sink is called before the lock is taken ... a panicking one
//! takes only itself"* — and the guard obeys it without ever saying so.
//!
//! None of this touches the network: the URL refusal resolves before `send()`, so the end-to-end
//! test runs in CI rather than behind `TRIGON_LIVE=1`.

use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use sha2::{Digest as _, Sha256};
use trigon_core::Digest;
use trigon_mirror::{Guard, GuardManifest, GuardMatch, Mirror};

// ---------------------------------------------------------------------------------------------
// Poisoning: the one way the guard's fail-open branch can actually be reached.
// ---------------------------------------------------------------------------------------------

/// A subscriber that panics on every event, standing in for a logging layer that can fail.
///
/// Not a contrived adversary. `trigon mirror serve` runs inside a container whose stderr is a pipe
/// the parent reads, the fmt layer's writer is caller-supplied, and a writer that panics on a
/// closed pipe or a poisoned `MakeWriter` is an ordinary bug in someone else's crate. The point is
/// not that this *will* happen; it is that the guard's correctness currently depends on nothing
/// under the lock ever unwinding, and a subscriber is the only unwinding thing `record` calls.
struct PanicOnEvent;

impl tracing::Subscriber for PanicOnEvent {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, _: &tracing::Event<'_>) {
        panic!("the logging layer panicked while the guard was writing its trip line");
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// A panic in the trip's log line must not silence the guard for the rest of the run.
///
/// `Guard::record` logs first and locks second. That ordering is the whole reason
/// `trips().unwrap_or_default()` is survivable today: the only code in `record` that can unwind
/// runs before the `MutexGuard` exists, so the lock cannot be poisoned and the fail-open branch is
/// unreachable. Nothing in `guard.rs` says so, and the natural tidy-up — "don't log a trip we
/// failed to record", i.e. move the `tracing::error!` inside the `if let Ok(mut t)` block — inverts
/// it.
///
/// What that edit costs: one panicking log call poisons `trips`, every later `record` silently
/// drops its trip, `trips()` returns `[]` forever, and `main.rs` reads `!m.trips().is_empty()` as
/// false and lets the run stand. A build that downloaded its own published artifact is then
/// reported as a reproduction — and the byte-for-byte match that results is precisely what
/// `guard.rs` opens by saying the clean re-run cannot catch. The guard would not merely miss the
/// attack; it would certify it.
///
/// So: panic inside the log, then check the guard still answers. Today the first trip is lost
/// (it never reached the lock) and the second is recorded, which is the correct degradation — one
/// event lost, the control still live. If the lock were poisoned instead, the second assertion
/// finds an empty list.
#[test]
fn a_panic_in_the_trip_log_line_does_not_silence_the_guard_for_the_rest_of_the_run() {
    let g = Guard::new(refusing(
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
    ));

    // The panic is expected and is swallowed here; the harness only prints it if this test fails.
    let blew_up = std::panic::catch_unwind(AssertUnwindSafe(|| {
        tracing::subscriber::with_default(PanicOnEvent, || {
            g.record_refusal("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz");
        });
    }));
    assert!(
        blew_up.is_err(),
        "the premise of this test is a panic raised from inside the guard's log call; if \
         `record` stopped logging the trip at all, the tier that enforces `mirror-only` reads \
         that log and would see nothing"
    );

    // The run continues, as it must: a poisoned-mutex panic inside a sweep worker is exactly what
    // the `unwrap_or_default()` exists to avoid. What must *not* continue is the guard answering
    // "clean" from here on.
    g.record_refusal("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz");

    let trips = g.trips();
    assert_eq!(
        trips.len(),
        1,
        "a panic while logging one trip left the guard unable to record any later one. \
         `trips()` cannot distinguish a poisoned lock from a quiet run, so from here every \
         download the build makes — including its own published artifact — reads as clean and the \
         run is reported as a reproduction rather than `Void`."
    );
    assert_eq!(trips[0].matched, GuardMatch::RefusedUrl);

    // The other half of the guard's state has its own lock, and the panic must not have taken it
    // either: `undecomposed()` is how an operator learns the member check answered a narrower
    // question than it was asked.
    g.observe_oversized("http://cdn.example/huge.tgz", digest(b"not the artifact"));
    assert_eq!(
        g.undecomposed(),
        vec!["http://cdn.example/huge.tgz".to_string()],
        "the guard's second lock was taken down with the first, so a body it never opened now \
         reports identically to one it opened and cleared"
    );
}

// ---------------------------------------------------------------------------------------------
// Contention: the ordinary case, where the lock is fine and merely busy.
// ---------------------------------------------------------------------------------------------

/// Every trip recorded concurrently is in the answer the verdict is read from.
///
/// The mirror serves a whole build's downloads at once, so `record` is called from many tokio
/// worker threads and `trips()` is read once at the end by `main.rs`. `lock()` blocks, which is the
/// correct choice here and looks like a wart: a blocking lock inside an async handler is the sort
/// of thing a later cleanup replaces with `try_lock().ok()` to "avoid blocking the reactor". That
/// swap is silent and it is a security regression — a trip dropped for contention is a `Void` run
/// that reads as a pass, and contention is highest exactly when the build is downloading a lot,
/// which is when the guard matters most.
///
/// A counter would not do: the verdict quotes `trips[0].url` into the void reason an operator
/// reads, so the identities have to survive too.
#[test]
fn every_trip_recorded_concurrently_is_in_the_answer_the_verdict_is_read_from() {
    const THREADS: usize = 16;
    const EACH: usize = 32;

    let g = Arc::new(Guard::new(refusing(
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
    )));

    std::thread::scope(|s| {
        for t in 0..THREADS {
            let g = Arc::clone(&g);
            s.spawn(move || {
                for i in 0..EACH {
                    g.record_refusal(&format!("https://registry.npmjs.org/t{t}/n{i}.tgz"));
                }
            });
        }
    });

    let trips = g.trips();
    assert_eq!(
        trips.len(),
        THREADS * EACH,
        "{} of {} trips were dropped under contention. A dropped trip is a run that downloaded \
         its own artifact and is reported as a reproduction.",
        THREADS * EACH - trips.len(),
        THREADS * EACH
    );

    let urls: std::collections::BTreeSet<_> = trips.iter().map(|t| t.url.as_str()).collect();
    assert_eq!(
        urls.len(),
        THREADS * EACH,
        "the count survived but the identities did not, and the void reason `main.rs` prints is \
         built from `trips[0].url`"
    );
}

/// A reader of the trip list never watches it shrink to nothing.
///
/// The writer-side test above only inspects the final value, and the final read is uncontended —
/// so it would still pass if the *reader* were the lossy one. This is that direction. `trips()` is
/// read while the mirror is still serving in at least two places: `main.rs` breaks the repair loop
/// on `!m.trips().is_empty()` between attempts, with the mirror alive and the next build's
/// downloads in flight.
///
/// The invariant is monotonicity. Trips are only ever appended, so any read that returns fewer
/// than a read that preceded it did not read the list — it read a failure dressed as a list. A
/// `try_lock().ok().unwrap_or_default()` reader shows up here as a count that drops back to zero
/// while the writer is still pushing, which is the loop-exit condition inverted: the guard says
/// "clean" in the middle of a run it has already voided.
#[test]
fn a_reader_of_the_trip_list_never_watches_it_shrink() {
    const TOTAL: usize = 500;

    let g = Arc::new(Guard::new(refusing(
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
    )));
    let written = Arc::new(AtomicUsize::new(0));
    let partial_reads = Arc::new(AtomicUsize::new(0));
    // Both threads start together; without it the writer finishes first on a fast machine and the
    // reader asserts nothing. The first run of this test did exactly that, which is why the
    // vacuity check at the bottom exists.
    let start = std::sync::Barrier::new(2);

    std::thread::scope(|s| {
        {
            let (g, written, start) = (Arc::clone(&g), Arc::clone(&written), &start);
            s.spawn(move || {
                start.wait();
                for i in 0..TOTAL {
                    g.record_refusal(&format!("https://registry.npmjs.org/n{i}.tgz"));
                    written.fetch_add(1, Ordering::SeqCst);
                    // So the reader is genuinely racing the writer rather than reading a list that
                    // has already stopped changing.
                    std::thread::yield_now();
                }
            });
        }
        {
            let (g, written, partial_reads, start) = (
                Arc::clone(&g),
                Arc::clone(&written),
                Arc::clone(&partial_reads),
                &start,
            );
            s.spawn(move || {
                start.wait();
                let mut high_water = 0usize;
                while written.load(Ordering::SeqCst) < TOTAL {
                    let seen = g.trips().len();
                    assert!(
                        seen >= high_water,
                        "a read of the trip list returned {seen} after an earlier read returned \
                         {high_water}. Trips are append-only, so this read did not fail — it \
                         reported a clean run while the guard was already holding {high_water} \
                         reasons the run is void."
                    );
                    if seen > 0 && seen < TOTAL {
                        partial_reads.fetch_add(1, Ordering::SeqCst);
                    }
                    high_water = seen;
                }
            });
        }
    });

    assert!(
        partial_reads.load(Ordering::SeqCst) > 0,
        "the reader never saw the list part-way through, so nothing here was actually contended \
         and this test asserted nothing"
    );
    assert_eq!(g.trips().len(), TOTAL);
}

// ---------------------------------------------------------------------------------------------
// Lock order: the guard holds two mutexes, and one call touches both.
// ---------------------------------------------------------------------------------------------

/// The guard's two locks are never held at once, so its own two halves cannot wedge each other.
///
/// `Guard` carries `trips` and `undecomposed`, and `observe_oversized` is the one call that writes
/// both: it records the URL as unopened, drops that guard at the end of its `if let`, and only then
/// calls `observe`, which may take `trips`. Sequential, not nested — and nothing says so, which is
/// what makes it worth pinning. Widening that `if let` block to cover the `self.observe(..)` call
/// is a one-line edit with no visible effect, and it establishes a `undecomposed -> trips` order
/// that any future `trips -> undecomposed` path would deadlock against. A deadlocked mirror stalls
/// the build it is serving, and a build that times out is an `Error`, not a `Void`: the run is
/// filed as infrastructure trouble rather than as the guard tripping.
///
/// The premise is also an invariant in its own right: an oversized body that *is* the published
/// artifact still trips. The whole-artifact hash never needed the bytes, so the size limit that
/// suppresses the member check must not suppress it too — otherwise the cheapest way past the
/// guard would be to pad the artifact past 64 MiB.
///
/// Wall-clock timeout rather than a plain join: a deadlock has to fail this test, not hang the
/// suite.
#[test]
fn the_guards_two_locks_are_never_held_at_once_so_an_oversized_artifact_cannot_wedge_it() {
    const WRITERS: usize = 8;
    const READERS: usize = 4;
    const EACH: usize = 200;

    let published = digest(b"the published artifact, too large to decompose");
    let g = Arc::new(Guard::new(GuardManifest {
        artifact: Some(published),
        ..Default::default()
    }));

    // The premise, checked once before the storm: this call writes to both locks.
    g.observe_oversized("http://cdn.evil.example/first.tgz", published);
    assert_eq!(
        g.trips().len(),
        1,
        "an oversized body that is the artifact itself did not trip. The whole-artifact hash is \
         computed from the stream and never needed the bytes, so padding the artifact past \
         MAX_DECOMPOSE_BYTES must not be a way past the guard."
    );
    assert_eq!(
        g.undecomposed().len(),
        1,
        "and it is also recorded as unopened"
    );

    let (tx, rx) = std::sync::mpsc::channel::<()>();
    for w in 0..WRITERS {
        let (g, tx) = (Arc::clone(&g), tx.clone());
        std::thread::spawn(move || {
            for i in 0..EACH {
                g.observe_oversized(&format!("http://cdn.evil.example/w{w}/{i}.tgz"), published);
            }
            let _ = tx.send(());
        });
    }
    for _ in 0..READERS {
        let (g, tx) = (Arc::clone(&g), tx.clone());
        std::thread::spawn(move || {
            for _ in 0..EACH {
                // Both halves, read the way a caller reads them: the trip list decides the verdict
                // and the unopened list qualifies it.
                let _ = g.trips().len() + g.undecomposed().len();
            }
            let _ = tx.send(());
        });
    }
    drop(tx);

    for n in 0..(WRITERS + READERS) {
        rx.recv_timeout(Duration::from_secs(30)).unwrap_or_else(|e| {
            panic!(
                "only {n} of {} guard workers finished within 30s ({e}). The guard's two locks are \
                 being held at once somewhere, and a wedged mirror stalls the build it serves — \
                 which is filed as an infrastructure `Error`, not as the guard tripping.",
                WRITERS + READERS
            )
        });
    }

    assert_eq!(
        g.trips().len(),
        1 + WRITERS * EACH,
        "the two halves ran without deadlocking but lost records"
    );
    assert_eq!(g.undecomposed().len(), 1 + WRITERS * EACH);
}

// ---------------------------------------------------------------------------------------------
// The same question through the server, where the lock is taken inside an async handler.
// ---------------------------------------------------------------------------------------------

/// Every concurrent refusal reaches the trip list, on a runtime that really runs them at once.
///
/// The guard's mutexes are taken from inside axum handlers and from inside the body stream's
/// `unfold` future — a **`std::sync::Mutex`** in async code, which is the pattern that usually
/// deserves suspicion. Here it is safe, and safe for a reason worth writing down: axum's `Handler`
/// bound requires a `Send` future, and a `std::sync::MutexGuard` is `!Send`, so holding one across
/// an `.await` in this path does not deadlock at runtime — it fails to compile. Adding
/// `let _g = L.lock().unwrap(); tokio::task::yield_now().await;` to `proxy` produces
/// *"the trait `Handler<_, _>` is not implemented for fn item ... {handle}"*. The same bound covers
/// `guarded_stream`, whose stream is handed to `Body::from_stream`. That is the strongest form this
/// guarantee comes in, and it is why no test below has to hunt for a stall.
///
/// What is *not* enforced by a type is that a refusal served is a refusal recorded when several
/// arrive at once. This runs them on four worker threads, so `record_refusal` is genuinely
/// contended, and asserts the two numbers match: `main.rs` makes the run `Void` from `trips()`
/// being non-empty, so a 403 the build saw but the trip list did not keep is a control whose result
/// never arrives. A `try_lock` in `record` is invisible to every other end-to-end test in this
/// crate — they issue one request at a time — and shows up here.
///
/// It also runs in CI, which the guard's other end-to-end coverage does not: `tests/server.rs`
/// gates on `TRIGON_LIVE=1`, and the refusal resolves before `send()`, so no packet leaves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_concurrent_refusal_the_mirror_serves_is_a_refusal_the_verdict_can_see() {
    const CONCURRENT: usize = 96;

    let m = Mirror::new()
        .unwrap()
        .with_guard(refusing(
            "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        ))
        .serve(0)
        .await
        .unwrap();

    let url = format!(
        "http://{}/-artifact/npm/2018-04-09T01:10:46/registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        m.host()
    );
    let client = reqwest::Client::new();
    let all = futures::future::join_all((0..CONCURRENT).map(|_| {
        let (client, url) = (client.clone(), url.clone());
        tokio::spawn(async move { client.get(&url).send().await.map(|r| r.status().as_u16()) })
    }));

    let statuses = tokio::time::timeout(Duration::from_secs(60), all)
        .await
        .expect("the mirror stopped answering with requests in flight");

    for s in &statuses {
        assert_eq!(
            *s.as_ref()
                .expect("the request task lived")
                .as_ref()
                .expect("the mirror answered"),
            403,
            "a concurrent request for the run's own published artifact was served"
        );
    }
    assert_eq!(
        m.trips().len(),
        CONCURRENT,
        "the mirror refused every request but did not record every refusal. A refusal the verdict \
         cannot see is a control whose result never arrives: the build was told no, and the run is \
         still reported as a reproduction."
    );

    m.shutdown().await;
}

// ---------------------------------------------------------------------------------------------

fn digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(Sha256::digest(bytes).into())
}

fn refusing(url: &str) -> GuardManifest {
    GuardManifest {
        refuse_url: Some(url.to_string()),
        ..Default::default()
    }
}
