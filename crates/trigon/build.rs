//! Bake the mirror's source digest into the binary.
//!
//! `warn_if_stale` used to compute this at run time by walking up from the current directory to
//! find the workspace — and returned silently when it could not. So the check worked from inside
//! the checkout and did nothing at all from anywhere else, which is where an installed Trigon is
//! always run from. A control that fails open, and reports nothing while doing it.
//!
//! Compile time is also the honest question. The check asks "is the mirror image older than the
//! mirror code *this binary* speaks", and that is a fact about the binary, not about whatever source
//! happens to be on the disk it is run from.

include!("src/mirror_source.rs");

fn main() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("crates/trigon has a workspace root two levels up")
        .to_path_buf();

    // Re-run when the mirror's sources change, or the digest goes stale itself and the check
    // becomes a different flavour of the bug it exists to prevent.
    println!("cargo:rerun-if-changed=crates/trigon-mirror");
    println!("cargo:rerun-if-changed=crates/trigon/src/mirror_source.rs");

    let digest = mirror_source_digest(&root).unwrap_or_else(|e| {
        // A published crate built outside the workspace has no mirror sources to hash. Say so in
        // the value rather than failing the build: the check then reports that it could not look,
        // which is the answer, instead of silently passing.
        println!("cargo:warning=could not digest trigon-mirror's source: {e}");
        "unknown".to_string()
    });
    println!("cargo:rustc-env=TRIGON_MIRROR_SOURCE={digest}");
}
