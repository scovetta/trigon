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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::process::Command;

    use super::*;

    /// A scratch directory for a test that runs `git`, removed when dropped.
    struct Dir(PathBuf);

    impl Dir {
        fn new(name: &str) -> Dir {
            let d =
                std::env::temp_dir().join(format!("trigon-switch-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            Dir(d)
        }

        /// `git` in `dir` under this directory, with no configuration of the host's.
        fn git(&self, dir: &str, args: &[&str]) -> String {
            let out = Command::new("git")
                .arg("-C")
                .arg(self.0.join(dir))
                .args(args)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }

        /// Commit `path` with `bytes` in the working tree `dir`.
        fn commit(&self, dir: &str, path: &str, bytes: &[u8]) {
            let p = self.0.join(dir).join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, bytes).unwrap();
            self.git(dir, &["add", "--all"]);
            self.git(dir, &["commit", "--quiet", "-m", path]);
        }

        fn location(&self, dir: &str) -> Location {
            Location::parse(self.0.join(dir).to_str().unwrap(), Path::new("/"), None).unwrap()
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A switch nobody has read is unknown, never clear: no working clone, a clone that records no
    /// fetch that succeeded, a record that is not one — anything but an object id is never handed
    /// to git as a revision — and a record of a commit the clone does not hold. Once a fetch is
    /// recorded, the switch is as that fetch found the branch, and as of when it began: a later
    /// fetch changes nothing until it is recorded as having succeeded.
    #[test]
    fn a_switch_nobody_has_read_is_unknown_and_never_clear() {
        let d = Dir::new("unread");
        d.git(".", &["init", "--quiet", "--bare", "-b", "main", "remote.git"]);
        d.git(".", &["init", "--quiet", "-b", "main", "writer"]);
        d.commit("writer", "README.md", b"evidence\n");
        d.git("writer", &["push", "--quiet", "../remote.git", "main"]);
        let location = d.location("remote.git");
        let clone = d.0.join("store/clone");
        let unknown = |why: &str| {
            let s = read(&location, "main", &clone);
            assert_eq!(s.state, SwitchState::Unknown, "{why}: {}", s.detail);
            assert_eq!(s.as_of, None, "{why}");
            assert!(s.detail.contains(why), "{why}: {}", s.detail);
            assert_eq!(s.repository, location.to_string());
        };

        unknown("no working clone of the repository under this store");
        std::fs::create_dir_all(d.0.join("store")).unwrap();
        d.git(".", &["clone", "--quiet", "remote.git", "store/clone"]);
        unknown("records no fetch of `main` that succeeded");

        let head = d.git("store/clone", &["rev-parse", "origin/main"]);
        let record = clone.join(".git").join(FETCHED);
        for bad in [
            "1700000000 HEAD".to_string(),
            "1700000000 --output=/tmp/x".to_string(),
            format!("1700000000 {}", &head[..39]),
            format!("1700000000 {head}0"),
            format!("soon {head}"),
            format!("-1 {head}"),
            head.clone(),
            String::new(),
        ] {
            std::fs::write(&record, format!("{bad}\n")).unwrap();
            unknown("records no fetch of `main` that succeeded");
        }
        // Well formed, and of a commit the clone does not hold: git cannot say.
        std::fs::write(&record, format!("1700000000 {}\n", "5".repeat(40))).unwrap();
        unknown("git could not read the tree");

        record_fetch(&clone, 1_700_000_000, "origin/main").unwrap();
        let s = read(&location, "main", &clone);
        assert_eq!(s.state, SwitchState::Clear, "{}", s.detail);
        assert_eq!(s.as_of.as_deref(), Some("2023-11-14T22:13:20Z"));
        assert!(s.detail.contains(&head[..12]), "{}", s.detail);
        assert!(!clone.join(".git").join(format!("{FETCHED}.part")).exists());

        // Set on the remote and fetched, but the fetch not recorded: as the last recorded one said.
        d.commit("writer", "kill-switch", b"stopped\n");
        d.git("writer", &["push", "--quiet", "../remote.git", "main"]);
        d.git("store/clone", &["fetch", "--quiet", "origin"]);
        assert_eq!(read(&location, "main", &clone).state, SwitchState::Clear);
        record_fetch(&clone, 1_700_000_060, "origin/main").unwrap();
        let s = read(&location, "main", &clone);
        assert_eq!(s.state, SwitchState::Set, "{}", s.detail);
        assert_eq!(s.as_of.as_deref(), Some("2023-11-14T22:14:20Z"));

        // A fetch of a branch the clone does not track is never recorded as one that succeeded.
        assert!(record_fetch(&clone, 1_700_000_120, "origin/elsewhere").is_err());
        assert_eq!(
            read(&location, "main", &clone).as_of.as_deref(),
            Some("2023-11-14T22:14:20Z")
        );
    }

    /// `serve` asks about the repository `[publish] repo` names, and about none where none is
    /// named; and it reads the working clone `publish` keeps for that location under the store —
    /// the directory named by the location's digest — and no other.
    #[test]
    fn the_reader_reads_the_clone_publish_keeps_for_the_repository_configured() {
        use sha2::Digest as _;
        let d = Dir::new("reader");
        d.git(".", &["init", "--quiet", "--bare", "-b", "main", "remote.git"]);
        d.git(".", &["init", "--quiet", "-b", "main", "writer"]);
        d.commit("writer", "README.md", b"evidence\n");
        d.git("writer", &["push", "--quiet", "../remote.git", "main"]);
        let config = |text: &str| {
            let file = d.0.join("evidence.toml");
            std::fs::write(&file, text).unwrap();
            let env = trigon_attest::config::Env {
                cwd: d.0.clone(),
                home: Some(d.0.join("home")),
                evidence_config: Some(file),
                evidence_cache: Some(d.0.join("cache")),
                evidence_state: Some(d.0.join("state")),
                ..Default::default()
            };
            EvidenceConfig::load(&env).unwrap()
        };
        let store = d.0.join("store");
        assert!(reader(&store, &config("[publish]\n")).is_none());

        let location = d.location("remote.git");
        let read = reader(
            &store,
            &config(&format!("[publish]\nrepo = \"{location}\"\n")),
        )
        .expect("a repository is configured");
        let s = read();
        assert_eq!(s.state, SwitchState::Unknown, "{}", s.detail);
        assert_eq!(s.repository, location.to_string());
        // The clone `publish` makes for the location, fetched and recorded as it records one.
        let clone = store
            .join("publish")
            .join(super::super::hex(&sha2::Sha256::digest(location.as_git_arg())))
            .join("clone");
        std::fs::create_dir_all(clone.parent().unwrap()).unwrap();
        d.git(
            ".",
            &["clone", "--quiet", "remote.git", clone.to_str().unwrap()],
        );
        record_fetch(&clone, 1_700_000_000, "origin/main").unwrap();
        let s = read();
        assert_eq!(s.state, SwitchState::Clear, "{}", s.detail);
        assert!(s.detail.contains(&clone.display().to_string()), "{}", s.detail);
    }

    /// A working tree published into in place is the repository itself: its branch is read as it
    /// is now, set where git lists anything named `kill-switch` — a directory as much as a file —
    /// and unknown where it has no such branch. The store's working clone plays no part.
    #[test]
    fn a_working_tree_published_into_is_read_as_its_branch_is_now() {
        let d = Dir::new("in-place");
        d.git(".", &["init", "--quiet", "-b", "main", "tree"]);
        d.commit("tree", "README.md", b"evidence\n");
        let location = d.location("tree");
        let clone = d.0.join("no-clone");
        let s = read(&location, "main", &clone);
        assert_eq!(s.state, SwitchState::Clear, "{}", s.detail);
        assert!(s.as_of.is_some());
        assert!(
            s.detail.contains("read from the working tree published into"),
            "{}",
            s.detail
        );
        assert!(s.detail.contains("as its `main` is now"), "{}", s.detail);

        d.commit("tree", "kill-switch/why", b"stopped\n");
        let s = read(&location, "main", &clone);
        assert_eq!(s.state, SwitchState::Set, "{}", s.detail);

        let s = read(&location, "other", &clone);
        assert_eq!(s.state, SwitchState::Unknown, "{}", s.detail);
        assert!(s.detail.contains("has no branch `other`"), "{}", s.detail);
        assert_eq!(s.as_of, None);
    }
}
