//! The evidence repository's kill-switch, as `trigon serve` reports it beside its own (`docs/19`
//! §3).
//!
//! **Read from the publisher's working clone, as of its last fetch that succeeded.** `serve` opens
//! no connection to the repository: what it reports is what `trigon publish`, run from the same
//! store, last fetched — the `kill-switch` file on the branch the clone tracks, at the commit that
//! fetch brought it to, and when that fetch was, which `publish` records in the clone's git
//! directory only once a fetch has succeeded ([`record_fetch`]). Not `FETCH_HEAD`: a fetch that
//! fails rewrites it too, and a switch read days ago would be stamped with the time of the failure.
//! A store with no working clone, one with no record of a fetch that succeeded, and a tree git
//! cannot read report `unknown`, never clear: a switch nobody has read is not a switch that is
//! off, and the switch is clear only where git lists nothing of its name. A working tree published
//! into in place is the repository itself, and is read as its branch is now.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use sha2::Digest as _;
use trigon_api::{RepositorySwitch, RepositorySwitchReader, SwitchState};
use trigon_attest::config::EvidenceConfig;
use trigon_attest::location::{Location, printable};

use super::git;

/// Where a working clone's git directory records its last fetch that succeeded: when it began, in
/// Unix seconds, and the commit it brought the branch to.
const FETCHED: &str = "trigon-fetched";

/// The reader `serve` asks, off the request path, where a publish repository is configured:
/// `[publish] repo`, or `TRIGON_PUBLISH_REPO` over it. `None` where none is.
pub(crate) fn reader(store: &Path, config: &EvidenceConfig) -> Option<RepositorySwitchReader> {
    let p = config.publish();
    let location = p.repo.clone()?;
    let branch = p.branch.clone();
    let clone = store
        .join("publish")
        .join(super::hex(&sha2::Sha256::digest(location.as_git_arg())))
        .join("clone");
    Some(Arc::new(move || read(&location, &branch, &clone)))
}

/// Record, in the working clone at `clone`, a fetch that began at `began` and succeeded, bringing
/// `tracking` to the commit it is at now. Written whole, over the one before, and only after the
/// fetch succeeded: a fetch that fails leaves the record of the last one that did.
pub(crate) fn record_fetch(clone: &Path, began: u64, tracking: &str) -> Result<()> {
    let commit = git::text(
        Some(clone),
        &["rev-parse", "--verify", &format!("{tracking}^{{commit}}")],
    )?;
    let dir = clone.join(".git");
    let part = dir.join(format!("{FETCHED}.part"));
    std::fs::write(&part, format!("{began} {commit}\n"))
        .and_then(|()| std::fs::rename(&part, dir.join(FETCHED)))
        .with_context(|| format!("recording the fetch in {}", dir.display()))
}

/// The switch of the repository at `location`, on `branch`, from the working clone at `clone`.
fn read(location: &Location, branch: &str, clone: &Path) -> RepositorySwitch {
    let repository = location.to_string();
    let unknown = |detail: String| RepositorySwitch {
        state: SwitchState::Unknown,
        repository: repository.clone(),
        as_of: None,
        detail,
    };
    // Published into in place: the tree is the repository, and its branch is read as it is now.
    if let Some(tree) = location.local_path()
        && matches!(git::kind_of(tree), Ok(Some(true)))
    {
        let head = format!("refs/heads/{branch}");
        if !git::succeeds(Some(tree), &["rev-parse", "--verify", "--quiet", &head]) {
            return unknown(format!("{} has no branch `{branch}`", tree.display()));
        }
        return match state(tree, &head) {
            Ok(state) => RepositorySwitch {
                state,
                repository: repository.clone(),
                as_of: Some(crate::now_rfc3339()),
                detail: format!(
                    "read from the working tree published into, {}, as its `{branch}` is now",
                    tree.display()
                ),
            },
            Err(why) => unknown(format!("{}: {why}", tree.display())),
        };
    }
    if !git::is_clone_at(clone) {
        return unknown(format!(
            "no working clone of the repository under this store ({}): `trigon publish` makes \
             one when it first runs from it, and the switch is read from that",
            clone.display()
        ));
    }
    let Some((began, commit)) = fetched(clone) else {
        return unknown(format!(
            "the working clone {} records no fetch of `{branch}` that succeeded: `trigon publish` \
             records one each time it fetches",
            clone.display()
        ));
    };
    match state(clone, &commit) {
        Ok(state) => RepositorySwitch {
            state,
            repository,
            as_of: Some(crate::rfc3339_from_unix(began)),
            detail: format!(
                "read from the working clone `trigon publish` keeps, {}, as its last fetch that \
                 succeeded found `{branch}`, at commit {}",
                clone.display(),
                &commit[..12]
            ),
        },
        Err(why) => unknown(format!("the working clone {}: {why}", clone.display())),
    }
}

/// Whether `rev` of the repository at `dir` has a `kill-switch`, as `git ls-tree` lists it: set
/// where it lists an entry of that name — a file, a link, a directory or a submodule, since
/// `publish` counts anything checked out there — and clear only where it lists none. Anything git
/// could not say is why the switch is unknown.
fn state(dir: &Path, rev: &str) -> Result<SwitchState, String> {
    let out = git::command(Some(dir))
        .args([
            "--literal-pathspecs",
            "ls-tree",
            "-z",
            rev,
            "--",
            "kill-switch",
        ])
        .output()
        .map_err(|e| format!("git could not be run to read it ({e})"))?;
    if !out.status.success() {
        return Err(format!(
            "git could not read the tree of {}: {}",
            printable(rev),
            git::scrub(String::from_utf8_lossy(&out.stderr).trim())
        ));
    }
    Ok(match out.stdout.is_empty() {
        true => SwitchState::Clear,
        false => SwitchState::Set,
    })
}

/// The working clone's last fetch that succeeded, as [`record_fetch`] recorded it: when it began,
/// and the commit it brought the branch to. `None` where there is no such record, or it is not one.
fn fetched(clone: &Path) -> Option<(u64, String)> {
    let text = std::fs::read_to_string(clone.join(".git").join(FETCHED)).ok()?;
    let (began, commit) = text.trim().split_once(' ')?;
    // Handed to git as a revision, so nothing but an object id is taken from the file.
    if !(matches!(commit.len(), 40 | 64) && commit.bytes().all(|b| b.is_ascii_hexdigit())) {
        return None;
    }
    Some((began.parse().ok()?, commit.to_string()))
}
