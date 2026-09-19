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

use std::collections::BTreeMap;
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
    /// Tags that point at this exact commit, as fetched.
    ///
    /// Empty means no tag names this commit — or that the remote could not be asked. Either way a
    /// build whose version comes from `git describe` will produce a development version rather than
    /// the release, which is a divergence about how we cloned rather than about the package. The
    /// caller is owed the difference; see [`SourceCache::checkout`].
    pub tags: Vec<String>,
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
            // A cached checkout is reused, and one made before tags were fetched has none — so
            // reading them is not enough, or the fix would apply only to repositories nobody had
            // built yet. Backfilled once and then found by the read on every later hit.
            let mut tags = tags_present(&path, &repo, self.local);
            if tags.is_empty() {
                tags = fetch_tags_for(&path, &repo, &commit, self.local);
            }
            return Ok(Checkout {
                repo,
                commit,
                path,
                tags,
            });
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

        // **The tags that name this commit, and only those.**
        //
        // A `--depth 1` fetch of one commit carries no tags, so `git describe` has nothing to
        // describe from — and `hatch-vcs`, `setuptools-scm` and every sibling derive the package
        // version from exactly that. `chardet 7.4.3` rebuilt as `chardet-0.1.dev1+g8f404a5a9`:
        // twenty-nine of thirty-five members byte-identical, and a `divergent` verdict published
        // about a package whose only fault was how we cloned it.
        //
        // It is also the second tier-dependent divergence found in a day. At `--egress open` the
        // source phase runs `git clone` inside the container, which fetches every tag, so the
        // version came out right; at an enforced tier the host does this shallow fetch instead and
        // it did not. Same recipe, same commit, two artifacts.
        //
        // Only the matching tags, rather than `--tags`: chardet has seventy-three and one of them
        // is the answer. `ls-remote` is a single round trip that transfers no objects, so asking
        // which costs less than fetching the rest.
        let tags = fetch_tags_for(&path, &repo, &commit, self.local);

        // Written last, so it is only ever present on a checkout that completed.
        std::fs::write(marker(&path), format!("{repo}\n{commit}\n")).map_err(|e| {
            RegistryError::Source {
                repo: repo.clone(),
                detail: format!("writing the completion marker: {e}"),
            }
        })?;
        Ok(Checkout {
            repo,
            commit,
            path,
            tags,
        })
    }
}

/// Tag refs already in a cached checkout that point at its commit.
fn tags_present(path: &Path, repo: &str, local: bool) -> Vec<String> {
    git_output(path, &["tag", "--points-at", "HEAD"], repo, local)
        .ok()
        .map(|out| {
            String::from_utf8_lossy(&out)
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Ask the remote which tags name this commit, then fetch just those.
///
/// Best effort by design. A commit that no tag names is ordinary — most commits are not releases —
/// and a remote that will not answer is a network problem, not a reason to fail a checkout that has
/// already succeeded. What must not happen is either being silent: the empty list travels on
/// [`Checkout::tags`] so the caller can say which it was.
/// Every tag a repository advertises, and the commit each ultimately names.
///
/// **Git protocol, not the GitHub API, and that is the point.** Resolving a version to a tag used
/// to cost one `api.github.com` request per spelling tried — measured at two per PyPI target, so a
/// 200-target corpus needs about 400 against an unauthenticated allowance of 60 an hour. The run
/// would exhaust its budget in the first few minutes and report the rest as `no-strategy`, which is
/// a statement about our request budget wearing the costume of a finding about packages.
///
/// `ls-remote` answers the same question in one request, on a transport that is not subject to that
/// limit, and answers it *better*: it returns every tag, so a spelling nobody thought to try is
/// still visible rather than costing another round trip.
///
/// Annotated tags list twice — the tag object under its own name, and the commit it points at under
/// `^{}`. The peeled line wins where both are present, because the commit is what a checkout needs.
pub fn remote_tags(repo: &str, local: bool) -> Result<BTreeMap<String, String>, RegistryError> {
    let repo = check_repo(repo, local)?;
    // `ls-remote` needs no local repository; the current directory only has to exist.
    let here = std::env::temp_dir();
    let listing = git_output(&here, &["ls-remote", "--tags", &repo], &repo, local)?;
    let listing = String::from_utf8_lossy(&listing);
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for line in listing.lines() {
        let Some((sha, name)) = line.split_once('\t') else {
            continue;
        };
        let (sha, name) = (sha.trim(), name.trim());
        let Some(tag) = name.strip_prefix("refs/tags/") else {
            continue;
        };
        match tag.strip_suffix("^{}") {
            // The peeled form is authoritative and overwrites whatever the tag object said.
            Some(bare) => {
                out.insert(bare.to_string(), sha.to_string());
            }
            None => {
                out.entry(tag.to_string())
                    .or_insert_with(|| sha.to_string());
            }
        }
    }
    Ok(out)
}

fn fetch_tags_for(path: &Path, repo: &str, commit: &str, local: bool) -> Vec<String> {
    let Ok(listing) = git_output(path, &["ls-remote", "--tags", "origin"], repo, local) else {
        return Vec::new();
    };
    let listing = String::from_utf8_lossy(&listing);
    let mut wanted: Vec<String> = Vec::new();
    for line in listing.lines() {
        let Some((sha, name)) = line.split_once('\t') else {
            continue;
        };
        if sha.trim() != commit {
            continue;
        }
        // An annotated tag lists twice: the tag object under its own name, and the commit it points
        // at under `^{}`. The commit line is the one that matches here, and the ref to fetch is its
        // name without the suffix.
        let name = name.trim().trim_end_matches("^{}");
        if name.starts_with("refs/tags/") && !wanted.iter().any(|w| w == name) {
            wanted.push(name.to_string());
        }
    }
    if wanted.is_empty() {
        return Vec::new();
    }
    let mut args: Vec<String> = ["fetch", "--quiet", "--depth", "1", "origin"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    for w in &wanted {
        args.push(format!("{w}:{w}"));
    }
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    if git(path, &argv, repo, local).is_err() {
        return Vec::new();
    }
    wanted
        .iter()
        .map(|w| w.trim_start_matches("refs/tags/").to_string())
        .collect()
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
        // Resolved once, because the containment check below compares against it and the checkout
        // may itself sit under a symlink — `/tmp` is one on several systems, and comparing a
        // resolved path against an unresolved root would reject everything.
        let Ok(root) = self.path.canonicalize() else {
            return Vec::new();
        };

        let mut out = Vec::new();
        for name in names {
            // Only within the checkout. A name with `..` in it would otherwise read the host.
            if name.contains("..") || Path::new(name).is_absolute() {
                continue;
            }

            // **Containment, not spelling.** The check above is about the *name*, and the name is
            // ours — `MANIFESTS` is a fixed list. What an attacker controls is the repository, and
            // git stores symlinks and checks them out as symlinks. A repo containing
            // `package.json -> /etc/passwd` has a name with no `..` in it that is nonetheless the
            // host's file, and `std::fs::metadata` follows links, so it read as a perfectly
            // ordinary manifest — into a model prompt, which leaves the machine.
            //
            // `canonicalize` resolves every component, so this also covers a symlinked *directory*
            // in the middle of the path, which no examination of the final name could catch.
            let Ok(real) = self.path.join(name).canonicalize() else {
                continue;
            };
            if !real.starts_with(&root) {
                continue;
            }

            let Ok(meta) = std::fs::metadata(&real) else {
                continue;
            };
            if !meta.is_file() || meta.len() as usize > max_bytes {
                continue;
            }
            if let Ok(text) = std::fs::read_to_string(&real) {
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
    // Only the subcommands that open a connection. `init`, `checkout` and the rest are local and
    // counting them would report traffic that never left the machine.
    if let Some(host) = args
        .first()
        .filter(|a| matches!(**a, "ls-remote" | "fetch" | "clone"))
        .and_then(|_| forge_of(repo))
    {
        crate::client::note_request(&host);
    }
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

/// The host a repository URL names, for the traffic table.
fn forge_of(repo: &str) -> Option<String> {
    repo.strip_prefix("https://")
        .and_then(|r| r.split('/').next())
        .filter(|h| !h.is_empty())
        .map(str::to_string)
}

fn git_output(
    dir: &Path,
    args: &[&str],
    repo: &str,
    local: bool,
) -> Result<Vec<u8>, RegistryError> {
    // Only the subcommands that open a connection. `init`, `checkout` and the rest are local and
    // counting them would report traffic that never left the machine.
    if let Some(host) = args
        .first()
        .filter(|a| matches!(**a, "ls-remote" | "fetch" | "clone"))
        .and_then(|_| forge_of(repo))
    {
        crate::client::note_request(&host);
    }
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
