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
