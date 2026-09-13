//! A pinned checkout on local disk, for the rungs that have to read the repository.
//!
//! The heuristic rungs answer from registry metadata alone, which is why they cost one request and
//! no disk. The Builder cannot: `docs/07-ai.md` §4 has it answering from the repository's file list
//! and its manifests, and neither exists anywhere on the host — the build container clones the
//! source and then takes it away with it.
//!
//! Shelling out to `git` rather than driving a library, which is [`17`](../docs/17-crates.md)'s
//! call and holds here for a smaller reason too: what this fetches is one commit, and `git` is the
//! only client that gets partial fetch, redirects and the rest of it right for every forge.
//!
//! **This runs on the host, over a URL a package told us about.** The sandbox has been doing the
//! same clone all along, but inside an island with nothing to reach; here there is no boundary, so
//! the URL and the commit are validated before either reaches a command line, and git is invoked
//! with the ambient configuration switched off. A repository is still data: nothing in it is
//! executed, and the checkout is read, never built.

use std::path::{Path, PathBuf};

use crate::error::RegistryError;

/// Checkouts, keyed by what they are.
///
/// Immutable content under an immutable key, which is the only kind of thing that is safe to cache
/// across runs (`docs/12-security.md` §9): a commit is a commit.
pub struct SourceCache {
    root: PathBuf,
    local: bool,
}

/// One pinned tree on disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkout {
    pub repo: String,
    pub commit: String,
    pub path: PathBuf,
}

impl SourceCache {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        SourceCache {
            root: root.into(),
            local: false,
        }
    }

    /// Also fetch from a path on this machine.
    ///
    /// For a repository **the operator named** — `--source ./repo@<commit>` — and never one a
    /// package named. The distinction is the whole of the URL check: `file://` is not dangerous,
    /// `file://` chosen by the thing under test is. Encoded as a constructor so the trusted case is
    /// something a caller opts into rather than something the check has to guess at.
    pub fn trusting_local_paths(mut self) -> Self {
        self.local = true;
        self
    }

    /// The default location, under the user's cache directory.
    pub fn default_root() -> PathBuf {
        std::env::var_os("TRIGON_SOURCE_CACHE")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("XDG_CACHE_HOME").map(|c| PathBuf::from(c).join("trigon")))
            .or_else(|| {
                std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache").join("trigon"))
            })
            .unwrap_or_else(std::env::temp_dir)
            .join("sources")
    }

    /// Fetch one commit, or return the checkout already here.
    ///
    /// Depth 1 against the commit itself: history is not what any rung reads, and a full clone of a
    /// large repository is the memory-and-bandwidth bomb `docs/10-scale.md` §1 names as the sleeper
    /// cost of a sweep.
    pub fn checkout(&self, repo: &str, commit: &str) -> Result<Checkout, RegistryError> {
        let repo = check_repo(repo, self.local)?;
        let commit = check_commit(commit)?;
        let path = self.root.join(key(&repo, &commit));

        // `.git` rather than the directory: an interrupted fetch leaves a directory behind, and
        // reusing it would serve a half-checkout that looks exactly like a repository missing files.
        if path.join(".git").join("HEAD").is_file() && marker(&path).is_file() {
            return Ok(Checkout { repo, commit, path });
        }
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).map_err(|e| RegistryError::Source {
            repo: repo.clone(),
            detail: format!("creating {}: {e}", path.display()),
        })?;

        git(&path, &["init", "--quiet"], &repo, self.local)?;
        git(
            &path,
            &["remote", "add", "origin", &repo],
            &repo,
            self.local,
        )?;
        git(
            &path,
            &["fetch", "--quiet", "--depth", "1", "origin", &commit],
            &repo,
            self.local,
        )?;
        git(
            &path,
            &["checkout", "--quiet", "--detach", "FETCH_HEAD"],
            &repo,
            self.local,
        )?;

        // Written last, so it is only ever present on a checkout that completed.
        std::fs::write(marker(&path), format!("{repo}\n{commit}\n")).map_err(|e| {
            RegistryError::Source {
                repo: repo.clone(),
                detail: format!("writing the completion marker: {e}"),
            }
        })?;
        Ok(Checkout { repo, commit, path })
    }
}

impl Checkout {
    /// Every tracked path, relative and sorted, up to `limit`.
    ///
    /// From `git ls-files` rather than a directory walk: it is already the answer to "what is in
    /// this repository", it skips `.git` without a special case, and it cannot be led anywhere by a
    /// symlink. A truncated list is returned rather than refused — a prompt gets a prefix of the
    /// tree, which is worth more than nothing and is why the cap is the caller's to choose.
    pub fn files(&self, limit: usize) -> Result<Vec<String>, RegistryError> {
        // Reading a checkout that is already here touches no transport, so the protocol list is
        // irrelevant and the stricter one is what this asks for.
        let out = git_output(&self.path, &["ls-files", "-z"], &self.repo, false)?;
        let mut files: Vec<String> = out
            .split(|b| *b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();
        files.sort();
        files.truncate(limit);
        Ok(files)
    }

    /// Read the named files, skipping what is absent or too large.
    ///
    /// Absence is not an error: the caller names every manifest any ecosystem might have, and a
    /// repository has a handful of them. The size cap is what stops a generated lockfile from
    /// becoming most of a prompt.
    pub fn read(&self, names: &[&str], max_bytes: usize) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for name in names {
            // Only within the checkout. A name with `..` in it would otherwise read the host.
            if name.contains("..") || Path::new(name).is_absolute() {
                continue;
            }
            let p = self.path.join(name);
            let Ok(meta) = std::fs::metadata(&p) else {
                continue;
            };
            if !meta.is_file() || meta.len() as usize > max_bytes {
                continue;
            }
            if let Ok(text) = std::fs::read_to_string(&p) {
                out.push(((*name).to_string(), text));
            }
        }
        out
    }
}

fn marker(path: &Path) -> PathBuf {
    path.join(".git").join("trigon-complete")
}

/// The cache key: the repository and the commit, hashed so the path is a fixed shape.
fn key(repo: &str, commit: &str) -> String {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(repo.as_bytes());
    h.update([0]);
    h.update(commit.as_bytes());
    format!("{:x}", h.finalize())[..32].to_string()
}

/// A repository URL we are willing to hand to `git`.
///
/// `https` only, and no leading `-`. The second is the one that matters: git reads a leading dash
/// as an option wherever it appears, so `--upload-pack=…` in a field a package controls is remote
/// command execution on the host. `https` only because the alternatives (`ssh`, `file`, `ext`) each
/// reach something we do not want a package choosing — a credential agent, the local filesystem, an
/// arbitrary command.
fn check_repo(repo: &str, local: bool) -> Result<String, RegistryError> {
    let repo = repo.trim();
    // A leading dash is refused whatever the source of the URL: it is the argument-injection case,
    // and an operator pointing at a local repository has no reason to write one.
    let shape = !repo.starts_with('-')
        && repo.len() < 512
        && !repo.contains(char::is_whitespace)
        && !repo.contains('\0');
    let scheme = repo.starts_with("https://")
        || (local && (repo.starts_with("file://") || repo.starts_with('/')));
    if !(shape && scheme) {
        return Err(RegistryError::SourceRefused {
            repo: repo.to_string(),
            detail: "not an https URL. A repository URL comes from package metadata, so it is \
                     checked before it reaches a command line; a local path is fetched only for a \
                     repository the operator named."
                .into(),
        });
    }
    Ok(repo.to_string())
}

/// A full commit id, and nothing else.
///
/// Not a ref, not an abbreviation. A branch or a tag is mutable, and a rung that reads "the
/// repository at `main`" is reading whatever `main` says today rather than what the package was
/// built from.
fn check_commit(commit: &str) -> Result<String, RegistryError> {
    let c = commit.trim();
    if c.len() == 40 && c.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(c.to_ascii_lowercase());
    }
    Err(RegistryError::SourceRefused {
        repo: c.to_string(),
        detail: "not a full commit id. A rung that reads a repository must read the commit the \
                 package was built from; a branch or a tag is whatever it points at today."
            .into(),
    })
}

/// Run git with the ambient configuration switched off.
///
/// The environment this inherits belongs to whoever ran `trigon`, and a fetch of a repository we
/// were told about by a package should not be able to use their credentials, prompt them, or pick
/// up a system-wide `insteadOf` that sends it somewhere else.
fn command(dir: &Path, local: bool) -> std::process::Command {
    let mut c = std::process::Command::new("git");
    c.current_dir(dir)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        // The belt to the URL check's braces, and it holds where the check cannot see: a redirect,
        // a submodule, an `insteadOf` we did not manage to suppress. `file` is added only for the
        // operator's own local path, which is also what makes this list load-bearing rather than
        // decorative — it refused the test fixture until the trusted case said so.
        .env(
            "GIT_ALLOW_PROTOCOL",
            if local { "https:file" } else { "https" },
        )
        .env("GIT_LFS_SKIP_SMUDGE", "1");
    c
}

fn git(dir: &Path, args: &[&str], repo: &str, local: bool) -> Result<(), RegistryError> {
    let out = command(dir, local)
        .args(args)
        .output()
        .map_err(|e| RegistryError::Source {
            repo: repo.to_string(),
            detail: format!("running git: {e}"),
        })?;
    if !out.status.success() {
        return Err(RegistryError::Source {
            repo: repo.to_string(),
            detail: format!(
                "git {} failed: {}",
                args[0],
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        });
    }
    Ok(())
}

fn git_output(
    dir: &Path,
    args: &[&str],
    repo: &str,
    local: bool,
) -> Result<Vec<u8>, RegistryError> {
    let out = command(dir, local)
        .args(args)
        .output()
        .map_err(|e| RegistryError::Source {
            repo: repo.to_string(),
            detail: format!("running git: {e}"),
        })?;
    if !out.status.success() {
        return Err(RegistryError::Source {
            repo: repo.to_string(),
            detail: format!(
                "git {} failed: {}",
                args[0],
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        });
    }
    Ok(out.stdout)
}
