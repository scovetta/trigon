//! Which of an artifact's members came out of the commit, and which the build made.
//!
//! # The join, and the one way to get it wrong
//!
//! A verdict is a claim about a published artifact **and a source**, and until now the source half
//! reached a page as a repository URL and a commit. This answers the question a reader actually
//! has: *of the forty-two files in this wheel, how many are the maintainer's bytes unchanged?*
//!
//! **It must not join on the comparison blob's digests.** `FileDiff.upstream_digest` looks like the
//! right key and is not: `summarize` applies the stabilizer set and *then* returns the archive that
//! `diff::index` hashes, so those digests are post-stabilization. Joining on them, Newtonsoft.Json
//! carries 1 of 23 members from its commit. Joining on raw bytes it carries **0 of 24** — the single
//! hit is `LICENSE.md`, and it matches only because `nupkg-text-eol` rewrote CRLF to LF first. A
//! page reporting the first number would be making a claim the bytes do not support.
//!
//! So this reads the artifact on disk and hashes members **before** any pass runs.
//!
//! # Four states, and they are never summed
//!
//! - [`Origin::Verbatim`] — the member's bytes are a file in the commit, unchanged.
//! - [`Origin::Normalized`] — they are a file in the commit *after* a named pass, and the name is
//!   carried so the sentence can say which one made it true.
//! - [`Origin::Built`] — no file under the scope has those bytes. Never phrased as "not in the
//!   commit": it is wrong when the checkout was pruned, when `subdir` was too narrow, and when the
//!   file is generated from a template that *is* in the commit. The page says what was searched.
//! - [`Origin::Unknown`] — the checkout is not on this machine, so nothing was searched at all.
//!
//! Reporting `Verbatim + Normalized` as one number is the mistake the module exists to avoid, so
//! there is no method that adds them.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Where one member of an artifact came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Origin {
    Verbatim,
    /// The pass that explains it, by name.
    Normalized(&'static str),
    Built,
    Unknown,
}

impl Origin {
    pub fn label(&self) -> String {
        match self {
            Origin::Verbatim => "carried verbatim".into(),
            Origin::Normalized(pass) => format!("carried after `{pass}`"),
            Origin::Built => "the build made this".into(),
            Origin::Unknown => "unknown — no checkout".into(),
        }
    }

    /// The colour, from the same palette the verdict tags use.
    pub fn colour(&self) -> &'static str {
        match self {
            Origin::Verbatim => "#137333",
            Origin::Normalized(_) => "#4b7f52",
            Origin::Built => "#3b5d8f",
            Origin::Unknown => "#6b6b66",
        }
    }
}

/// One member, and where it came from.
#[derive(Clone, Debug)]
pub struct Member {
    pub path: String,
    pub bytes: u64,
    pub origin: Origin,
    /// The file in the checkout that explains it, where one does.
    pub source_path: Option<String>,
}

/// What a join looked at, so a sentence can say it rather than assert a negative.
#[derive(Clone, Debug)]
pub struct Scope {
    pub commit: String,
    /// The subdirectory the strategy built from, when it named one.
    pub subdir: Option<String>,
    /// Files hashed under that scope. `0` with `searched == false` means the checkout is absent.
    pub files: usize,
    pub searched: bool,
}

impl Scope {
    /// "none of the 412 files at d32e9734 has those bytes" — what was searched, never a negative
    /// about the commit.
    pub fn where_we_looked(&self) -> String {
        if !self.searched {
            return "the checkout for this commit is not on this machine, so nothing was searched"
                .to_string();
        }
        let short = &self.commit[..8.min(self.commit.len())];
        match &self.subdir {
            // The subtree is context, not a filter: the whole checkout is searched, and saying
            // which part the build ran in is what lets a reader read a hit outside it correctly.
            Some(d) => format!(
                "{} file(s) at {short}, of which the build ran in `{d}`",
                self.files
            ),
            None => format!("{} file(s) at {short}", self.files),
        }
    }
}

/// Where a checkout for this commit would be, under the cache the rungs use.
///
/// The same `sha256(repo\0commit)[..32]` key `SourceCache` writes, computed here rather than
/// exported from there, because this reads a directory and must not be able to create one: the
/// cache's own constructor makes the directory it is given, and a page is read-only.
pub fn checkout_dir(root: &Path, repo: &str, commit: &str) -> PathBuf {
    use sha2::Digest as _;
    // Spelled as the cache spells them before it hashes: the URL trimmed, the commit trimmed and
    // lower-cased. A record that carries a commit in capitals names the checkout the cache wrote
    // under the lower-case key, and hashing it as given looked in a directory nobody made.
    let commit = commit.trim().to_ascii_lowercase();
    let mut h = sha2::Sha256::new();
    h.update(repo.trim().as_bytes());
    h.update([0]);
    h.update(commit.as_bytes());
    root.join(&format!("{:x}", h.finalize())[..32])
}

/// A checkout's files, by content digest, in two forms kept apart.
#[derive(Clone, Debug, Default)]
struct Index {
    /// The bytes as they are in the commit.
    raw: BTreeMap<String, Vec<String>>,
    /// The bytes as they would be with CRLF line endings. A hit here is `Normalized`, never
    /// `Verbatim` — see `index_checkout` for why they are two maps.
    eol: BTreeMap<String, Vec<String>>,
}

/// How many files a single walk will hash before it gives up.
///
/// A bound rather than a timeout: the same checkout must produce the same answer twice. The largest
/// checkout in this machine's cache is 52k files and takes 19 seconds cold, which is already too
/// long for a request — hence the memo below — and a repository ten times that size should degrade
/// to "we did not finish looking" rather than to a page that never loads.
const MAX_FILES: usize = 200_000;

/// Content digest to the paths carrying it, for the **whole** checkout.
///
/// **Digest to *paths*, plural.** A repository with the same licence text in four places is
/// ordinary, and a map that kept one would make the member table's "from" column a coin flip.
///
/// **The whole checkout, not the build subdirectory.** Scoping the search to `subdir` was the first
/// version and it under-reports: `Newtonsoft.Json` builds from `Src/Newtonsoft.Json` and ships the
/// repository's root `LICENSE.md`, so a scoped search calls a file anybody can read in the commit
/// "the build made this". Searching everything cannot overstate — the bytes really are in the
/// commit — and the member table prints the path it matched, so a reader sees for themselves
/// whether a hit came from the built subtree or from somewhere else in the repository.
fn index_checkout(dir: &Path) -> (Index, usize) {
    use sha2::Digest as _;
    let root = dir.to_path_buf();
    let mut out = Index::default();
    let mut seen = 0usize;
    let mut stack = vec![root.clone()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                // `.git` is the repository, not the source. Hashing it would put pack files in the
                // table and make the file count meaningless.
                if p.file_name().is_some_and(|n| n == ".git") {
                    continue;
                }
                stack.push(p);
                continue;
            }
            if seen >= MAX_FILES {
                return (out, seen);
            }
            seen += 1;
            let Ok(bytes) = std::fs::read(&p) else {
                continue;
            };
            let rel = p
                .strip_prefix(&root)
                .unwrap_or(&p)
                .to_string_lossy()
                .into_owned();
            out.raw
                .entry(format!("{:x}", sha2::Sha256::digest(&bytes)))
                .or_default()
                .push(rel.clone());
            // **A separate map, and that separation is the whole point.** These are the digests the
            // file would have with CRLF line endings — the form `nupkg-text-eol` rewrites away, and
            // the only reason `Newtonsoft.Json`'s root `LICENSE.md` matches anything at all: it is
            // CRLF in the artifact and LF in the commit.
            //
            // Folding them into `raw` was the first version, and it reported that member as
            // "carried verbatim". It is not: its bytes are not the commit's bytes, they are the
            // commit's bytes after a pass. Counting normalization as carriage is exactly the
            // mistake this module's documentation says it exists to avoid, committed in the lookup
            // rather than in the join.
            //
            // One pass, one direction. A general rewrite-rule detector that tried transformations
            // until something matched would find coincidences, and a coincidence presented as
            // provenance is worse than "the build made this".
            if let Some(crlf) = to_crlf(&bytes) {
                out.eol
                    .entry(format!("{:x}", sha2::Sha256::digest(&crlf)))
                    .or_default()
                    .push(rel);
            }
        }
    }
    (out, seen)
}

/// `\n` to `\r\n`, or `None` where the bytes are not text or already carry a `\r`.
fn to_crlf(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() > 1_000_000 || bytes.contains(&0) || bytes.contains(&b'\r') {
        return None;
    }
    if !bytes.contains(&b'\n') {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() + 16);
    for b in bytes {
        if *b == b'\n' {
            out.push(b'\r');
        }
        out.push(*b);
    }
    Some(out)
}

/// The join: every member, and where it came from.
///
/// `members` is `(path, raw content digest, bytes)` taken from the artifact **before** any pass.
pub fn join(
    members: &[(String, String, u64)],
    checkout: Option<&Path>,
    subdir: Option<&str>,
    commit: &str,
) -> (Vec<Member>, Scope) {
    let Some(dir) = checkout.filter(|d| d.is_dir()) else {
        let scope = Scope {
            commit: commit.to_string(),
            subdir: subdir.map(str::to_string),
            files: 0,
            searched: false,
        };
        let out = members
            .iter()
            .map(|(path, _, bytes)| Member {
                path: path.clone(),
                bytes: *bytes,
                origin: Origin::Unknown,
                source_path: None,
            })
            .collect();
        return (out, scope);
    };

    let (index, files) = memo(dir);
    let scope = Scope {
        commit: commit.to_string(),
        subdir: subdir.map(str::to_string),
        files,
        searched: true,
    };

    let out = members
        .iter()
        .map(|(path, digest, bytes)| {
            // Raw first, always. A file that is byte-identical to the commit must never be
            // reported as one a pass explains, and a file a pass explains must never be reported
            // as byte-identical.
            let (origin, source_path) = match index.raw.get(digest) {
                Some(paths) => (Origin::Verbatim, paths.first().cloned()),
                None => match index.eol.get(digest) {
                    Some(paths) => (Origin::Normalized("nupkg-text-eol"), paths.first().cloned()),
                    None => (Origin::Built, None),
                },
            };
            Member {
                path: path.clone(),
                bytes: *bytes,
                origin,
                source_path,
            }
        })
        .collect();
    (out, scope)
}

/// The index for one checkout, computed once per `(dir, mtime, subdir)`.
///
/// **Not an optimisation.** The largest checkout in this machine's cache takes 19 seconds to hash
/// cold, and a page that did that per request would be a page nobody opens twice. Keyed on the
/// directory's mtime as well as its path so a re-fetched checkout is re-read rather than served
/// from a stale index.
fn memo(dir: &Path) -> (Index, usize) {
    use std::sync::Mutex;
    type Key = (PathBuf, u64);
    static CACHE: Mutex<Option<BTreeMap<Key, (Index, usize)>>> = Mutex::new(None);

    let stamp = std::fs::metadata(dir)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let key: Key = (dir.to_path_buf(), stamp);

    if let Ok(guard) = CACHE.lock()
        && let Some(map) = guard.as_ref()
        && let Some(hit) = map.get(&key)
    {
        return hit.clone();
    }
    let built = index_checkout(dir);
    if let Ok(mut guard) = CACHE.lock() {
        guard
            .get_or_insert_with(BTreeMap::new)
            .insert(key, built.clone());
    }
    built
}

/// How many members fell into each origin, in the order a bar draws them.
///
/// Returned as a list rather than a struct with a `total` method, because the one thing a caller
/// must not do is add the first two together.
pub fn tally(members: &[Member]) -> Vec<(Origin, usize)> {
    let mut verbatim = 0;
    let mut normalized = 0;
    let mut built = 0;
    let mut unknown = 0;
    let mut pass = "";
    for m in members {
        match &m.origin {
            Origin::Verbatim => verbatim += 1,
            Origin::Normalized(p) => {
                normalized += 1;
                pass = p;
            }
            Origin::Built => built += 1,
            Origin::Unknown => unknown += 1,
        }
    }
    vec![
        (Origin::Verbatim, verbatim),
        (Origin::Normalized(pass), normalized),
        (Origin::Built, built),
        (Origin::Unknown, unknown),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(name: &str, files: &[(&str, &[u8])]) -> PathBuf {
        let d = std::env::temp_dir()
            .join(format!("trigon-prov-{}", std::process::id()))
            .join(name);
        let _ = std::fs::remove_dir_all(&d);
        for (p, b) in files {
            let full = d.join(p);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, b).unwrap();
        }
        d
    }

    fn sha(b: &[u8]) -> String {
        use sha2::Digest as _;
        format!("{:x}", sha2::Sha256::digest(b))
    }

    #[test]
    fn a_member_whose_bytes_are_in_the_commit_is_carried_and_says_from_where() {
        let dir = tree("verbatim", &[("src/lib.rs", b"fn main() {}\n")]);
        let members = vec![("package/lib.rs".to_string(), sha(b"fn main() {}\n"), 13u64)];
        let (out, scope) = join(&members, Some(&dir), None, "d50b912e9948");
        assert_eq!(out[0].origin, Origin::Verbatim);
        assert_eq!(out[0].source_path.as_deref(), Some("src/lib.rs"));
        assert!(scope.searched);
        assert_eq!(scope.files, 1);
    }

    #[test]
    fn a_member_nothing_in_the_commit_explains_is_built_and_the_scope_is_stated() {
        // Never "not in the commit": the page has to say what it searched, because the answer is
        // wrong when the checkout was pruned, when `subdir` was too narrow, and when the file is
        // generated from a template that *is* in the commit.
        let dir = tree("built", &[("src/lib.rs", b"fn main() {}\n")]);
        let members = vec![("package/compiled.so".to_string(), sha(b"\x7fELF..."), 7u64)];
        let (out, scope) = join(&members, Some(&dir), None, "d50b912e9948");
        assert_eq!(out[0].origin, Origin::Built);
        let said = scope.where_we_looked();
        assert!(said.contains("1 file(s) at d50b912e"), "{said}");
        assert!(!said.contains("not in the commit"), "{said}");
    }

    #[test]
    fn a_file_from_outside_the_build_subtree_is_still_in_the_commit() {
        // `Newtonsoft.Json` builds from `Src/Newtonsoft.Json` and ships the repository's root
        // `LICENSE.md`. Scoping the search to the build subtree — which the first version did —
        // reports a file anybody can read in the commit as "the build made this". Searching
        // everything cannot overstate, and the matched path is printed so a reader can tell the
        // two apart for themselves.
        let dir = tree(
            "whole",
            &[
                ("Src/Newtonsoft.Json/x.cs", b"inside\n"),
                ("LICENSE.md", b"MIT\n"),
            ],
        );
        let members = vec![
            ("lib/x.cs".to_string(), sha(b"inside\n"), 7),
            ("LICENSE.md".to_string(), sha(b"MIT\n"), 4),
        ];
        let (out, scope) = join(
            &members,
            Some(&dir),
            Some("Src/Newtonsoft.Json"),
            "d50b912e",
        );
        assert_eq!(out[0].origin, Origin::Verbatim);
        assert_eq!(
            out[1].origin,
            Origin::Verbatim,
            "the root licence is in the commit"
        );
        assert_eq!(out[1].source_path.as_deref(), Some("LICENSE.md"));
        // And the sentence still says where the build ran, because that is how a reader reads a
        // hit from outside it.
        let said = scope.where_we_looked();
        assert!(said.contains("Src/Newtonsoft.Json"), "{said}");
        assert!(said.contains("2 file(s)"), "{said}");
    }

    #[test]
    fn a_missing_checkout_is_unknown_rather_than_built() {
        // The difference the whole page turns on. "We looked and found nothing" and "we could not
        // look" are opposite claims, and only one of them says anything about the package.
        let members = vec![("a".to_string(), sha(b"x"), 1)];
        let (out, scope) = join(&members, None, None, "d50b912e");
        assert_eq!(out[0].origin, Origin::Unknown);
        assert!(!scope.searched);
        assert!(scope.where_we_looked().contains("not on this machine"));
    }

    #[test]
    fn a_line_ending_rewrite_is_named_as_one_rather_than_called_verbatim() {
        // `Newtonsoft.Json`'s LICENSE.md: CRLF in the artifact, LF in the commit. A raw join finds
        // it only because the index also carries the CRLF form. The tally must not present this as
        // the same thing as an untouched file — which is why `tally` returns a list and has no
        // method that adds the two.
        let dir = tree("eol", &[("LICENSE.md", b"MIT\nfree\n")]);
        let members = vec![("LICENSE.md".to_string(), sha(b"MIT\r\nfree\r\n"), 10)];
        let (out, _) = join(&members, Some(&dir), None, "d50b912e");
        assert_eq!(
            out[0].origin,
            Origin::Normalized("nupkg-text-eol"),
            "a member whose bytes are the commit's only after a pass is not verbatim"
        );
        assert_eq!(out[0].source_path.as_deref(), Some("LICENSE.md"));

        // And a file that really is byte-identical stays verbatim, so the two are not merely
        // labelled differently — the lookup order decides, raw first.
        let plain = vec![("PLAIN.md".to_string(), sha(b"MIT\nfree\n"), 9)];
        let (out, _) = join(&plain, Some(&dir), None, "d50b912e");
        assert_eq!(out[0].origin, Origin::Verbatim);
    }

    #[test]
    fn the_tally_has_no_way_to_add_carried_to_normalized() {
        let members = vec![
            Member {
                path: "a".into(),
                bytes: 1,
                origin: Origin::Verbatim,
                source_path: None,
            },
            Member {
                path: "b".into(),
                bytes: 1,
                origin: Origin::Built,
                source_path: None,
            },
            Member {
                path: "c".into(),
                bytes: 1,
                origin: Origin::Built,
                source_path: None,
            },
        ];
        let t = tally(&members);
        assert_eq!(t[0].1, 1);
        assert_eq!(t[2].1, 2);
        // Every state is present even at zero, so a reader is never left to infer one.
        assert_eq!(t.len(), 4);
    }

    fn git(dir: &Path, args: &[&str]) -> String {
        let out = std::process::Command::new("git")
            .current_dir(dir)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// The directory this reads is the one the rungs' cache wrote, for the commit as a record
    /// spells it: a page that computed another key would say "not on this machine" about a
    /// checkout that is.
    #[test]
    fn the_checkout_it_looks_for_is_the_one_the_source_cache_wrote() {
        let origin = tree("origin", &[("LICENSE.md", b"MIT\n")]);
        git(&origin, &["init", "--quiet", "-b", "main"]);
        git(&origin, &["add", "-A"]);
        git(&origin, &["commit", "--quiet", "-m", "one"]);
        let commit = git(&origin, &["rev-parse", "HEAD"]);
        let repo = origin.to_string_lossy().into_owned();
        let root = std::env::temp_dir()
            .join(format!("trigon-prov-{}", std::process::id()))
            .join("sources");
        let _ = std::fs::remove_dir_all(&root);

        let fetched = trigon_registry::SourceCache::new(&root)
            .trusting_local_paths()
            .checkout(&repo, &commit.to_ascii_uppercase())
            .unwrap();
        // Every spelling the cache accepts for this repository and commit names the checkout it
        // wrote: the cache trims both and lower-cases the commit before it hashes them.
        let padded = format!(" {repo}\n");
        let upper = commit.to_ascii_uppercase();
        let upper_padded = format!(" {upper}\n");
        let again = trigon_registry::SourceCache::new(&root)
            .trusting_local_paths()
            .checkout(&padded, &upper_padded)
            .unwrap();
        assert_eq!(
            again.path, fetched.path,
            "the cache's own reading of that spelling"
        );
        for (repo, spelled) in [
            (&repo, &commit),
            (&repo, &upper),
            (&repo, &upper_padded),
            (&padded, &commit),
            (&padded, &upper_padded),
        ] {
            assert_eq!(
                checkout_dir(&root, repo, spelled),
                fetched.path,
                "{repo:?} {spelled:?}"
            );
        }
        // And what is found there is the commit's.
        let members = vec![("LICENSE.md".to_string(), sha(b"MIT\n"), 4)];
        let (out, scope) = join(
            &members,
            Some(&checkout_dir(&root, &repo, &commit)),
            None,
            &commit,
        );
        assert!(scope.searched);
        assert_eq!(out[0].origin, Origin::Verbatim);
    }

    /// Four states, four sentences and four colours, and the normalized one names its pass.
    #[test]
    fn each_origin_says_what_it_is_and_the_normalized_one_names_its_pass() {
        let all = [
            Origin::Verbatim,
            Origin::Normalized("nupkg-text-eol"),
            Origin::Built,
            Origin::Unknown,
        ];
        assert_eq!(all[0].label(), "carried verbatim");
        assert_eq!(all[1].label(), "carried after `nupkg-text-eol`");
        assert_eq!(all[2].label(), "the build made this");
        assert_eq!(all[3].label(), "unknown — no checkout");
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a.label(), b.label());
                assert_ne!(a.colour(), b.colour(), "{a:?} and {b:?} look alike");
            }
        }
    }

    /// Normalized members are counted apart from verbatim ones, under the pass that explains them.
    #[test]
    fn the_tally_counts_normalized_members_apart_and_names_their_pass() {
        let dir = tree("tally", &[("a.txt", b"one\n"), ("b.txt", b"two\n")]);
        let members = vec![
            ("a.txt".to_string(), sha(b"one\n"), 4),
            ("b.txt".to_string(), sha(b"two\r\n"), 5),
            ("c.bin".to_string(), sha(b"\x00built"), 6),
        ];
        let (out, _) = join(&members, Some(&dir), None, "d50b912e");
        let t = tally(&out);
        assert_eq!(
            t,
            vec![
                (Origin::Verbatim, 1),
                (Origin::Normalized("nupkg-text-eol"), 1),
                (Origin::Built, 1),
                (Origin::Unknown, 0),
            ]
        );
    }

    /// Only text gets a CRLF form: bytes with a NUL are not text, bytes already carrying a `\r` are
    /// not LF text, and bytes with no line to end have no other form. None of them may match as
    /// "carried after a pass" on the strength of a rewrite that pass would never make.
    #[test]
    fn only_lf_text_is_given_a_line_ending_form() {
        let dir = tree(
            "crlf",
            &[
                ("binary.dat", b"a\nb\x00\n"),
                ("mixed.txt", b"a\r\nb\n"),
                ("oneline.txt", b"no newline"),
            ],
        );
        let members = vec![
            ("binary.dat".to_string(), sha(b"a\r\nb\x00\r\n"), 7),
            ("mixed.txt".to_string(), sha(b"a\r\r\nb\r\n"), 8),
            ("oneline.txt".to_string(), sha(b"no newline"), 10),
        ];
        let (out, _) = join(&members, Some(&dir), None, "d50b912e");
        assert_eq!(out[0].origin, Origin::Built);
        assert_eq!(out[1].origin, Origin::Built);
        // Its bytes are the commit's as they stand.
        assert_eq!(out[2].origin, Origin::Verbatim);
        assert_eq!(to_crlf(b"no newline"), None);
        assert_eq!(to_crlf(b"a\nb\n").as_deref(), Some(&b"a\r\nb\r\n"[..]));
    }

    /// A checkout fetched again is read again: the index is keyed on the directory's mtime as well
    /// as its path, so a changed tree is not answered from the index of the old one.
    #[test]
    fn a_checkout_that_changed_is_read_again() {
        let dir = tree("refetched", &[("old.txt", b"old\n")]);
        let members = vec![("new.txt".to_string(), sha(b"new\n"), 4)];
        let (out, _) = join(&members, Some(&dir), None, "d50b912e");
        assert_eq!(out[0].origin, Origin::Built);

        std::fs::write(dir.join("new.txt"), b"new\n").unwrap();
        // A fetch a second later: the directory's time moves on, whatever the clock's resolution.
        let later = std::fs::metadata(&dir).unwrap().modified().unwrap()
            + std::time::Duration::from_secs(5);
        std::fs::File::open(&dir).unwrap().set_modified(later).unwrap();
        let (out, scope) = join(&members, Some(&dir), None, "d50b912e");
        assert_eq!(out[0].origin, Origin::Verbatim);
        assert_eq!(scope.files, 2);
    }

    /// A directory or a file the walk cannot read is passed over, and the rest of the checkout is
    /// still searched: one unreadable corner does not turn every member into "the build made this".
    #[test]
    fn what_cannot_be_read_is_passed_over_and_the_rest_is_still_searched() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tree(
            "unreadable",
            &[
                ("open/a.txt", b"readable\n"),
                ("sealed/b.txt", b"sealed\n"),
                ("locked.txt", b"locked\n"),
            ],
        );
        let set = |p: &Path, mode: u32| {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        set(&dir.join("sealed"), 0o000);
        set(&dir.join("locked.txt"), 0o000);
        // A user the permissions do not stop (root) reads everything, and there is nothing to test.
        let stopped = std::fs::read_dir(dir.join("sealed")).is_err()
            && std::fs::read(dir.join("locked.txt")).is_err();
        let members = vec![
            ("a.txt".to_string(), sha(b"readable\n"), 9),
            ("b.txt".to_string(), sha(b"sealed\n"), 7),
            ("locked.txt".to_string(), sha(b"locked\n"), 7),
        ];
        let (out, scope) = join(&members, Some(&dir), None, "d50b912e");
        set(&dir.join("sealed"), 0o755);
        set(&dir.join("locked.txt"), 0o644);
        assert!(scope.searched);
        assert_eq!(out[0].origin, Origin::Verbatim, "the readable part was not searched");
        if stopped {
            assert_eq!(out[1].origin, Origin::Built);
            assert_eq!(out[2].origin, Origin::Built);
        }
    }

    /// A commit shorter than the eight characters a sentence shows is shown whole.
    #[test]
    fn a_short_commit_is_shown_whole() {
        let dir = tree("short", &[("a", b"a")]);
        let (_, scope) = join(&[], Some(&dir), None, "abc");
        assert_eq!(scope.where_we_looked(), "1 file(s) at abc");
    }

    #[test]
    fn the_git_directory_is_not_the_source() {
        let dir = tree(
            "gitdir",
            &[
                (".git/objects/pack/x.pack", b"packdata"),
                ("a.rs", b"code\n"),
            ],
        );
        let (_, scope) = join(&[], Some(&dir), None, "abc");
        assert_eq!(scope.files, 1, "the pack file was hashed as source");
    }
}
