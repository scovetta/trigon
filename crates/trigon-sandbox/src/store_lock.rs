//! A lock over podman's shared image store.
//!
//! Podman's local image store is machine-global and this system reaches into it from three places:
//! the image build reads the layer store to decide what it can reuse, and two sweeps plus a per-run
//! `Drop` remove images from it. Run at the same time, the build fails with
//!
//! ```text
//! checking if cached image exists from a previous build: getting top layer info: layer not known
//! ```
//!
//! which arrives labelled as *our sandbox being broken* — or, through a sweep, as the package's
//! failure. A reproduction rate that contains infrastructure faults is not a rate, which is what
//! makes this a correctness problem rather than a tidiness one.
//!
//! **Shared for readers, exclusive for removals, on a file beside the store.** `flock` is held on
//! an open descriptor, so it is released when the process dies however it dies — no stale lock
//! survives a `kill -9`, which is the failure mode that makes lock *directories* unusable here.
//! Because it is a file lock rather than a process mutex it holds across two Trigon processes as
//! well as across lanes inside one, which was the half of `docs/17-backlog.md` B6 that no amount of
//! in-process care could reach.
//!
//! Readers block only while a removal is in flight, which is milliseconds. Removals never block at
//! all: they take the lock with `try`, and a removal that cannot have it is *skipped*, because a
//! stale image costs disk and a blocked one costs the run. The sweeps are best-effort by design and
//! collect it next time.
//!
//! The alternative the backlog also names — per-run storage — is a real option and a worse one: it
//! gives up layer sharing entirely and re-pulls a base image per target, which at 400 targets is
//! tens of gigabytes of registry traffic to avoid a lock.

use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::path::PathBuf;

/// Held for as long as the guard lives. Dropping it closes the descriptor, which releases the lock.
#[derive(Debug)]
pub struct StoreLock {
    _file: File,
}

/// Where the lock lives.
///
/// Per user, because podman's rootless store is per user: two people on one machine have separate
/// stores and must not wait on each other. In the temp directory rather than beside the store
/// itself, so that a store on a read-only or unusual mount still gets a lock.
///
/// There is deliberately no override. One existed briefly, justified as "for the tests", and the
/// justification was false the moment the tests took a path parameter instead — a knob nothing
/// exercises is the dead configuration `docs/16-findings.md` §3.15 is already about. Two processes
/// that must agree on this lock agree because they compute the same path, not because somebody
/// remembered to set the same variable in both.
fn path() -> PathBuf {
    // SAFETY: `getuid` is always safe; it reads a process property and cannot fail.
    let uid = unsafe { libc::getuid() };
    std::env::temp_dir().join(format!("trigon-image-store-{uid}.lock"))
}

fn open_at(at: &std::path::Path) -> Option<File> {
    OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(at)
        .ok()
}

fn lock(file: File, op: libc::c_int) -> Option<StoreLock> {
    // SAFETY: the descriptor is owned by `file` and outlives the call.
    let rc = unsafe { libc::flock(file.as_raw_fd(), op) };
    (rc == 0).then_some(StoreLock { _file: file })
}

impl StoreLock {
    /// How long a build will wait for a removal before giving up and building anyway.
    ///
    /// **Bounded, and that is the point.** A blocking `LOCK_SH` was the first version, and it is a
    /// worse bug than the race it fixes: a removal that hangs while holding the lock stops every
    /// build on the machine, for ever, with no diagnostic. Its own tests found it — three test
    /// binaries wedged against each other, reported as a hang.
    ///
    /// Removals here are one `podman rmi` and finish in well under a second, so a wait this long
    /// means the holder is stuck rather than busy. Giving up restores the behaviour that existed
    /// before this lock, which is a rare race; waiting restores nothing.
    const PATIENCE: std::time::Duration = std::time::Duration::from_secs(5);

    /// Take the lock as a reader, waiting out any removal in flight.
    ///
    /// `None` when the lock file cannot be opened, the call fails, or a removal held it past
    /// [`Self::PATIENCE`]. None of those is fatal: a machine where this cannot work is one where
    /// the previous behaviour applies, and refusing to build because a lock could not be taken
    /// trades a rare race for a certain failure. It is logged where it is taken.
    pub fn shared() -> Option<Self> {
        Self::shared_at(&path())
    }

    /// [`Self::shared`] on a named lock file.
    ///
    /// Exists because the tests must not contend with *each other*: the lock is real and
    /// process-wide, so two tests sharing one file deadlock or fail depending on thread order.
    /// A process-global override could not fix that — both tests are in the same process — which
    /// is why this is a parameter and not an environment variable.
    fn shared_at(at: &std::path::Path) -> Option<Self> {
        let file = open_at(at)?;
        let deadline = std::time::Instant::now() + Self::PATIENCE;
        loop {
            // SAFETY: the descriptor is owned by `file` and outlives the call.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } == 0 {
                return Some(StoreLock { _file: file });
            }
            if std::time::Instant::now() >= deadline {
                tracing::warn!(
                    "a removal has held podman's image store for {:?}; building without the lock",
                    Self::PATIENCE
                );
                return None;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }

    /// Take the lock for a removal, or report that a reader holds it.
    ///
    /// Never waits. A removal that cannot have the lock is skipped by its caller.
    pub fn try_exclusive() -> Option<Self> {
        Self::try_exclusive_at(&path())
    }

    /// [`Self::try_exclusive`] on a named lock file. See [`Self::shared_at`].
    fn try_exclusive_at(at: &std::path::Path) -> Option<Self> {
        lock(open_at(at)?, libc::LOCK_EX | libc::LOCK_NB)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Taken for writing by a test that asserts a lock is free once it is dropped, and for reading
    /// by every test in this crate that starts a process.
    ///
    /// `flock` belongs to the open file description, and a forked child holds a copy of every
    /// descriptor until it execs and the close-on-exec ones go. So a test on another thread that
    /// starts a process just as this one drops a lock keeps that lock held for the child's
    /// fork-to-exec window, and a removal asked for in that window is refused with both readers
    /// gone — `readers_share_and_a_removal_waits_for_all_of_them` failed that way in most runs of
    /// the whole suite once `network.rs` gained tests that start a stand-in runtime, and never on
    /// its own. The lock files are already per test; what they share is the process.
    ///
    /// Tokio's lock rather than the standard one, because the tests that start processes hold it
    /// across the awaits that start them.
    pub(crate) static SPAWNING: tokio::sync::RwLock<()> = tokio::sync::RwLock::const_new(());

    /// A lock file of this test's own.
    ///
    /// **Not a process-global override**, which was the first attempt and could not work: both
    /// tests live in one process, so they contended through it and the failure depended on thread
    /// order. It passed under `--test-threads=1` and failed in the real suite — verifying with the
    /// flag that suppresses the defect, which is the habit this file exists to break.
    fn mine(name: &str) -> PathBuf {
        let p =
            std::env::temp_dir().join(format!("trigon-lock-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn readers_share_and_a_removal_waits_for_all_of_them() {
        let _alone = SPAWNING.blocking_write();
        let at = mine("share");
        // Two readers coexist — concurrent builds must — and a removal cannot proceed while either
        // holds it, which is the property that stops `podman rmi` taking layers out from under
        // `podman build`.
        let a = StoreLock::shared_at(&at).expect("a reader can take the lock");
        let b = StoreLock::shared_at(&at).expect("readers do not exclude each other");
        assert!(
            StoreLock::try_exclusive_at(&at).is_none(),
            "a removal must not proceed while a build holds the store"
        );
        drop(a);
        assert!(
            StoreLock::try_exclusive_at(&at).is_none(),
            "nor while the second build still holds it"
        );
        drop(b);

        // And a removal excludes everything, including another removal.
        let held = StoreLock::try_exclusive_at(&at).expect("it proceeds once the readers are gone");
        assert!(StoreLock::try_exclusive_at(&at).is_none());
        drop(held);
        assert!(StoreLock::try_exclusive_at(&at).is_some());
    }

    #[test]
    fn a_build_gives_up_rather_than_waiting_forever_on_a_stuck_removal() {
        // The bug this closes was in the first version of this file: `shared()` blocked, so a
        // removal that never released stopped every build on the machine with no diagnostic. A
        // build that cannot have the lock proceeds without it, which is the behaviour that existed
        // before the lock — a rare race rather than a certain stall.
        let at = mine("stuck");
        let _held = StoreLock::try_exclusive_at(&at).expect("hold it as a removal would");
        let started = std::time::Instant::now();
        assert!(
            StoreLock::shared_at(&at).is_none(),
            "a build must give up, not wait"
        );
        assert!(
            started.elapsed() >= StoreLock::PATIENCE,
            "and it must actually have waited first: a removal is normally sub-second"
        );
    }
}
