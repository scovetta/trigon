//! The pinned checkout the Builder reads from.
//!
//! Everything here runs against a repository made on the spot, so the suite needs no network: what
//! is being tested is the fetch-and-read machinery and the refusals, not GitHub.

use std::path::{Path, PathBuf};
use std::process::Command;

use trigon_registry::SourceCache;

fn tmpdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("trigon-source-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
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
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A repository with a manifest, a source file and a second commit, and the first commit's id.
fn fixture(root: &Path) -> (PathBuf, String) {
    let repo = root.join("origin");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::write(
        repo.join("package.json"),
        "{\"name\":\"a\",\"version\":\"1.0.0\"}\n",
    )
    .unwrap();
    std::fs::write(repo.join("src").join("index.js"), "module.exports = 1;\n").unwrap();
    git(&repo, &["init", "--quiet", "-b", "main"]);
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "--quiet", "-m", "one"]);
    let out = Command::new("git")
        .current_dir(&repo)
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    let first = String::from_utf8_lossy(&out.stdout).trim().to_string();

    // A later commit that removes a file, so "the checkout is at the pinned commit" is a claim with
    // something behind it rather than a tautology about a one-commit repository.
    std::fs::write(repo.join("LATER.md"), "not in the first commit\n").unwrap();
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "--quiet", "-m", "two"]);
    (repo, first)
}

#[test]
fn a_checkout_is_the_commit_that_was_asked_for_and_not_the_branch() {
    // The whole reason a rung reads the repository at a commit: `main` today is not what the
    // package was built from, and a file that arrived afterwards would be read as evidence.
    let d = tmpdir("pinned");
    let (repo, first) = fixture(&d);
    let cache = SourceCache::new(d.join("cache")).trusting_local_paths();

    let c = cache.checkout(repo.to_str().unwrap(), &first).unwrap();
    assert_eq!(c.commit, first);
    let files = c.files(100).unwrap();
    assert_eq!(files, vec!["package.json", "src/index.js"]);
    assert!(
        !files.iter().any(|f| f.contains("LATER")),
        "the branch has moved on and this checkout followed it"
    );

    // Asked for again, it is the same directory and no second fetch: a commit is a commit, which
    // is the only kind of thing safe to cache across runs.
    let again = cache.checkout(repo.to_str().unwrap(), &first).unwrap();
    assert_eq!(again.path, c.path);
    assert!(again.path.join(".git").join("trigon-complete").is_file());

    // And an operator's local path is the only way in: the same URL from package metadata is not.
    let e = SourceCache::new(d.join("cache2"))
        .checkout(&format!("file://{}", repo.display()), &first)
        .unwrap_err()
        .to_string();
    assert!(e.contains("https URL"), "{e}");
    assert!(e.contains("operator named"), "{e}");
}

#[test]
fn a_ref_that_is_not_a_commit_is_refused_rather_than_resolved() {
    let d = tmpdir("ref");
    let cache = SourceCache::new(d.join("cache"));
    for r in ["main", "v1.0.0", "ff8e7ba", ""] {
        let e = cache
            .checkout("https://github.com/stevemao/left-pad", r)
            .unwrap_err();
        assert!(
            e.to_string().contains("full commit id"),
            "`{r}` was not refused: {e}"
        );
        assert!(!trigon_core::Classify::is_retryable(&e), "`{r}`");
    }
}

#[test]
fn a_url_that_could_be_an_argument_is_refused() {
    // A repository URL comes from package metadata. git reads a leading dash as an option wherever
    // it appears, so `--upload-pack=…` in a field a package controls is a command on this host.
    let d = tmpdir("argv");
    let cache = SourceCache::new(d.join("cache"));
    let commit = "0".repeat(40);
    for url in [
        "--upload-pack=touch /tmp/pwned",
        "-u ./evil",
        "ssh://git@github.com/a/b",
        "file:///etc",
        "ext::sh -c whoami",
        "https://example.invalid/a b",
    ] {
        let e = cache.checkout(url, &commit).unwrap_err();
        assert!(
            e.to_string().contains("https URL"),
            "`{url}` was not refused: {e}"
        );
    }
}

#[test]
fn the_reader_lists_tracked_files_and_reads_the_manifests_it_knows() {
    let d = tmpdir("read");
    let (repo, first) = fixture(&d);
    let c = SourceCache::new(d.join("cache"))
        .trusting_local_paths()
        .checkout(repo.to_str().unwrap(), &first)
        .unwrap();

    // A truncated list is a prefix of the tree, not a refusal: a prompt with some of the repository
    // in it is worth more than one with none.
    assert_eq!(c.files(1).unwrap(), vec!["package.json"]);

    let manifests = c.read(&["package.json", "pyproject.toml"], 64 * 1024);
    assert_eq!(manifests.len(), 1, "an absent manifest is not an error");
    assert_eq!(manifests[0].0, "package.json");
    assert!(manifests[0].1.contains("\"name\":\"a\""));

    // The cap is what stops a generated lockfile from becoming most of a prompt.
    assert!(c.read(&["package.json"], 4).is_empty());

    // And nothing outside the checkout, whatever the caller asks for.
    assert!(
        c.read(&["../../etc/passwd", "/etc/passwd"], 64 * 1024)
            .is_empty()
    );
}

#[test]
fn a_checkout_carries_the_tag_that_names_its_commit() {
    // `hatch-vcs`, `setuptools-scm` and every sibling take the package version from `git describe`.
    // A `--depth 1` fetch of one commit carries no tags, so `describe` had nothing to describe from
    // and `chardet 7.4.3` rebuilt as `chardet-0.1.dev1+g8f404a5a9` — twenty-nine of thirty-five
    // members byte-identical, and a `divergent` verdict published about a package whose only fault
    // was how we cloned it.
    //
    // It was also tier-dependent, which is what made it invisible: at `--egress open` the source
    // phase runs `git clone` inside the container and gets every tag, so the version came out
    // right. Only an enforced tier, where the host does this shallow fetch instead, was wrong.
    let root = tmpdir("tagged");
    let (repo, first) = fixture(&root);
    // An *annotated* tag, which is what a release usually is and which lists twice in `ls-remote`:
    // once as the tag object and once as the commit it dereferences to. Matching the wrong line
    // fetches nothing.
    git(&repo, &["tag", "-a", "v1.0.0", "-m", "release", &first]);
    // And a second tag on the other commit, which must not be fetched: a repository with seventy
    // tags should cost one.
    git(&repo, &["tag", "-a", "v2.0.0", "-m", "later", "HEAD"]);

    let cache = SourceCache::new(root.join("cache")).trusting_local_paths();
    let out = cache.checkout(repo.to_str().unwrap(), &first).unwrap();
    assert_eq!(
        out.tags,
        vec!["v1.0.0".to_string()],
        "only the matching tag"
    );

    let described = Command::new("git")
        .current_dir(&out.path)
        .args(["describe", "--tags"])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&described.stdout).trim(),
        "v1.0.0",
        "the version a VCS-derived build would compute"
    );
}

#[test]
fn a_checkout_cached_before_tags_were_fetched_gets_them_on_the_next_hit() {
    // The fix would otherwise apply only to repositories nobody had built yet: a cached checkout is
    // reused, and one made before this existed has no tags and would never acquire any. Found by
    // the fix not working on the package it was written for.
    let root = tmpdir("tag-backfill");
    let (repo, first) = fixture(&root);
    let cache = SourceCache::new(root.join("cache")).trusting_local_paths();

    // The first checkout happens before the tag exists, so it legitimately has none.
    let cold = cache.checkout(repo.to_str().unwrap(), &first).unwrap();
    assert!(cold.tags.is_empty());

    git(&repo, &["tag", "-a", "v1.0.0", "-m", "release", &first]);
    let warm = cache.checkout(repo.to_str().unwrap(), &first).unwrap();
    assert_eq!(warm.path, cold.path, "the same cached checkout, reused");
    assert_eq!(warm.tags, vec!["v1.0.0".to_string()], "and backfilled");
}

#[test]
fn a_commit_no_tag_names_reports_no_tags_rather_than_failing() {
    // Most commits are not releases. An untagged one is ordinary, so this is a note the caller can
    // act on and not a refusal — but it must be reported, because a VCS-versioned build will
    // silently produce a development version from it.
    let root = tmpdir("untagged");
    let (repo, first) = fixture(&root);
    git(&repo, &["tag", "-a", "v2.0.0", "-m", "later", "HEAD"]);

    let cache = SourceCache::new(root.join("cache")).trusting_local_paths();
    let out = cache.checkout(repo.to_str().unwrap(), &first).unwrap();
    assert!(
        out.tags.is_empty(),
        "no tag names this commit: {:?}",
        out.tags
    );
    assert!(
        out.path.join(".git").is_dir(),
        "and the checkout still works"
    );
}

/// A manifest that is a symlink out of the checkout reads nothing.
///
/// **The vector the `..` guard does not cover.** `Checkout::read` rejects a *caller-supplied* name
/// containing `..` or an absolute path, and the test above asserts that. The name it is handed is
/// not the attacker's input — `MANIFESTS` is a fixed list — so that guard was never the interesting
/// one. What an attacker controls is the *repository*, and git stores symlinks (mode 120000) and
/// checks them out as symlinks.
///
/// So a package whose source repo contains `package.json -> /etc/passwd` passes the guard (the name
/// has no `..` and is relative), and `std::fs::metadata` follows the link, so `is_file()` is true
/// of the target and `read_to_string` reads it. From `trigon/src/inferrer.rs` those manifests go
/// straight into the model prompt, which leaves the machine.
///
/// The fix is containment rather than another spelling check: canonicalize and require the result
/// to be inside the checkout, which also covers a symlinked *directory* component that no
/// examination of the final name could catch.
#[test]
#[cfg(unix)]
fn a_manifest_that_is_a_symlink_out_of_the_checkout_is_not_read() {
    let d = tmpdir("symlink");
    let repo = d.join("origin");
    std::fs::create_dir_all(repo.join("sub")).unwrap();

    // A file outside the repository, standing in for anything the build user can read.
    let secret = d.join("host-secret.txt");
    std::fs::write(&secret, "PRIVATE KEY MATERIAL\n").unwrap();

    // The attack, committed the way git really stores it.
    std::os::unix::fs::symlink(&secret, repo.join("package.json")).unwrap();
    // And the same through a symlinked directory component, which inspecting the final name
    // cannot catch.
    std::os::unix::fs::symlink(d.join(""), repo.join("sub").join("up")).unwrap();
    std::fs::write(repo.join("pyproject.toml"), "[project]\nname='real'\n").unwrap();

    git(&repo, &["init", "--quiet", "-b", "main"]);
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "--quiet", "-m", "one"]);
    let out = Command::new("git")
        .current_dir(&repo)
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    let head = String::from_utf8_lossy(&out.stdout).trim().to_string();

    let c = SourceCache::new(d.join("cache"))
        .trusting_local_paths()
        .checkout(repo.to_str().unwrap(), &head)
        .unwrap();

    // Sanity: git really did check the symlink out as a symlink, or this test proves nothing.
    let link = c.path.join("package.json");
    assert!(
        std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink(),
        "the fixture is not exercising a symlink; git checked out a regular file"
    );

    let got = c.read(&["package.json", "sub/up/host-secret.txt", "pyproject.toml"], 1 << 20);
    let names: Vec<&str> = got.iter().map(|(n, _)| n.as_str()).collect();

    assert!(
        !got.iter().any(|(_, body)| body.contains("PRIVATE KEY MATERIAL")),
        "a file outside the checkout was read into what becomes a model prompt: {names:?}"
    );
    assert!(
        !names.contains(&"package.json"),
        "the symlinked manifest should be skipped entirely, not read as empty"
    );

    // And the real file beside it is still read, so the fix is containment and not a refusal to
    // read anything at all.
    assert!(
        names.contains(&"pyproject.toml"),
        "the ordinary manifest stopped being read: {names:?}"
    );
}
