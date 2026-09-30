//! A panic in the guard's trip log line must not silence the guard: the poisoning half of
//! `seam_locks_fail_closed.rs`, which says why the guard's locks must never be poisoned.
//!
//! **Alone in its binary, and it has to stay alone.** The test installs a subscriber that panics
//! and relies on the guard's `tracing::warn!` reaching it. `tracing` caches, per log call site and
//! for the whole process, whether any subscriber wants that call, and works it out the first time
//! the call site is hit. While the test's subscriber is the only one registered, `tracing-core`
//! 0.1 works it out from the default subscriber of whichever thread hits the call site first. The
//! tests in `seam_locks_fail_closed.rs` that record refusals from threads of their own have no
//! subscriber there, so if one of them reaches the guard's `warn!` first, at any point between
//! this test installing its subscriber and its own first log call, the call site is cached as
//! wanted by nobody. The event never reaches the subscriber, nothing panics, and the test fails on
//! its premise. Run 32 at a time on 8 cores, the five tests in one binary failed this way 4 to 13
//! times in 1,000, and this test alone passed 5,000 of 5,000. A binary is a process, and with one
//! test in it no other thread can reach the call site first. Add a test here and the flake can
//! come back.

use std::panic::AssertUnwindSafe;

use sha2::{Digest as _, Sha256};
use trigon_core::Digest;
use trigon_mirror::{Guard, GuardManifest, GuardMatch};

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

fn digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(Sha256::digest(bytes).into())
}

fn refusing(url: &str) -> GuardManifest {
    GuardManifest {
        refuse_url: Some(url.to_string()),
        ..Default::default()
    }
}
