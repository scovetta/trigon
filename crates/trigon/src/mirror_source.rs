// The digest of the source the time-warp mirror is built from.
//
// This file is `include!`d by `build.rs` *and* by the binary, so it carries no inner doc comments
// and no `use` statements that either side might already have.

/// Hash `crates/trigon-mirror`'s manifest and sources, as sixteen hex characters.
///
/// **One function, two callers that must agree.** `build.rs` bakes the result into the binary for
/// the staleness check; `trigon mirror-image` stamps it on the image it builds. Two copies of a
/// hashing rule would be invisible when wrong: they would either never match, warning on every run,
/// or match by luck and never warn.
///
/// Scoped to `trigon-mirror` alone, not the workspace and not its dependencies. A digest over
/// everything would be correct and useless — it changes when a stabilizer or a failure rule
/// changes, and a warning that fires on every commit is one people learn to ignore. The routes, the
/// time filter and the guard all live in that one crate, so it is where staleness that changes what
/// a build sees comes from.
///
/// `Err` only when the source tree is not there to read, which for the binary means it was built
/// somewhere other than its own checkout.
pub fn mirror_source_digest(root: &std::path::Path) -> std::io::Result<String> {
    use sha2::Digest as _;
    let mut files = Vec::new();
    let dir = root.join("crates").join("trigon-mirror");
    files.push(dir.join("Cargo.toml"));
    let mut stack = vec![dir.join("src")];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d)?.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                files.push(p);
            }
        }
    }
    // Sorted, because a directory listing comes back in whatever order the filesystem feels like
    // and a digest that depends on that is a digest that changes for no reason.
    files.sort();
    let mut h = sha2::Sha256::new();
    for f in &files {
        h.update(
            f.strip_prefix(root)
                .unwrap_or(f)
                .to_string_lossy()
                .as_bytes(),
        );
        h.update([0]);
        h.update(std::fs::read(f)?);
        h.update([0]);
    }
    Ok(format!("{:x}", h.finalize())[..16].to_string())
}
