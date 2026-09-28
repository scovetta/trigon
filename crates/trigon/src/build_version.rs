// The version a build of Trigon identifies itself by.
//
// This file is `include!`d by `build.rs` *and* by the binary's tests, so it carries no inner doc
// comments and no `use` statements that either side might already have.

/// The crate version and the git revision `root` is checked out at: `0.0.0+git.<40 hex>`, with
/// `.dirty` after it when the tree has changes the commit does not, and `0.0.0+git.unknown` when
/// `root` is not the top of a git checkout or `git` cannot be run. Never an empty revision.
///
/// **The crate version alone identifies nothing**: every build of this workspace is `0.0.0`, so a
/// run record that said which Trigon built it said nothing a reader could use (`docs/19` §4.2 item
/// 3). The form is semver build metadata, so a tool that orders versions ignores it and one that
/// compares them sees two builds as different.
///
/// `root` must be the checkout's own top level, not merely inside one: a source tree unpacked
/// inside somebody else's repository would otherwise be stamped with that repository's commit.
///
/// Returns, beside the version, the files whose change moves `HEAD` — the `HEAD` file, the branch
/// it names, `packed-refs` and the index — for `cargo:rerun-if-changed`. A working-tree edit moves
/// none of them, so the dirty flag is as of the last time the build script ran.
pub fn build_version(version: &str, root: &std::path::Path) -> (String, Vec<std::path::PathBuf>) {
    let git = |args: &[&str]| -> Option<String> {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            // A build run from inside a git hook inherits these, and they would point every
            // question below at the hook's repository instead of `root`.
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            // Ask without writing. `git status` otherwise refreshes the index and writes it back
            // under `index.lock`, and this runs on every build — every background `cargo check`
            // an editor starts — so a `git add` or `git commit` at the same moment would fail on
            // the lock. It would also rewrite the index the script watches, and run itself again.
            .env("GIT_OPTIONAL_LOCKS", "0")
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    let unknown = (format!("{version}+git.unknown"), Vec::new());

    let Some(top) = git(&["rev-parse", "--show-toplevel"]) else {
        return unknown;
    };
    let same = match (std::fs::canonicalize(&top), std::fs::canonicalize(root)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    };
    if !same {
        return unknown;
    }
    let Some(rev) = git(&["rev-parse", "HEAD"])
        .filter(|r| r.len() == 40 && r.bytes().all(|b| b.is_ascii_hexdigit()))
    else {
        // A repository with no commit yet, or a hash this does not recognise.
        return unknown;
    };
    let dirty = match git(&["status", "--porcelain"]) {
        Some(s) => !s.is_empty(),
        // Unable to tell is not clean.
        None => true,
    };

    let mut watch = Vec::new();
    let mut git_path = |name: &str| {
        if let Some(p) = git(&["rev-parse", "--git-path", name]) {
            watch.push(root.join(p));
        }
    };
    git_path("HEAD");
    git_path("packed-refs");
    git_path("index");
    if let Some(branch) = git(&["symbolic-ref", "-q", "HEAD"]) {
        git_path(&branch);
    }

    let suffix = if dirty { ".dirty" } else { "" };
    (format!("{version}+git.{rev}{suffix}"), watch)
}
