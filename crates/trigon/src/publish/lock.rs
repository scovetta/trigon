//! One `trigon publish` at a time on a host, whatever store it runs from, and in a store (`docs/19`
//! §2.4, §10 phase 5).
//!
//! **Refused, not waited for.** A second publisher that waited would build on whatever the first
//! left and sign a checkpoint of its own a moment later; one that is refused says so, names the
//! holder, and can be run again. The lock is `flock` on an open descriptor, as podman's image store
//! lock is (`trigon-sandbox`'s `store_lock`), so it is released when its holder exits however it
//! exits: a publisher killed mid-step leaves no stale lock behind, only the file that names who
//! held it last.

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek as _, Write as _};
use std::os::fd::AsRawFd;
use std::path::Path;

use anyhow::{Context as _, Result, bail};

/// Held for as long as the guard lives. Dropping it closes the descriptor, which releases the lock.
#[derive(Debug)]
pub(crate) struct Lock {
    _file: File,
}

impl Lock {
    /// Take the lock at `path`, writing `holder` into it, or refuse with the holder the file names.
    pub(crate) fn take(path: &Path, holder: &str) -> Result<Lock> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)
            .with_context(|| format!("opening the lock {}", path.display()))?;
        // SAFETY: the descriptor is owned by `file` and outlives the call.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EWOULDBLOCK) {
                return Err(err).with_context(|| format!("locking {}", path.display()));
            }
            let mut held = String::new();
            let _ = file.read_to_string(&mut held);
            let held = held.trim();
            bail!(
                "another `trigon publish` holds {}: {}. One publish runs at a time on a host, and \
                 in a store, so that one writer builds on the log and signs its checkpoint; the \
                 lock is released when it exits, however it exits. Run this again once it has",
                path.display(),
                if held.is_empty() {
                    "it has not yet said who it is"
                } else {
                    held
                }
            );
        }
        file.set_len(0)?;
        file.rewind()?;
        writeln!(file, "{holder}").with_context(|| format!("writing {}", path.display()))?;
        Ok(Lock { _file: file })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_holder_is_refused_with_the_first_named_and_the_lock_goes_with_its_holder() {
        let dir = std::env::temp_dir().join(format!("trigon-publish-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("lock");
        let first = Lock::take(&path, "pid 1, publishing to /srv/evidence.git").unwrap();
        let e = Lock::take(&path, "pid 2").unwrap_err().to_string();
        assert!(e.contains("pid 1, publishing to /srv/evidence.git"), "{e}");
        assert!(e.contains("One publish runs at a time"), "{e}");
        drop(first);
        let _second = Lock::take(&path, "pid 2").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
