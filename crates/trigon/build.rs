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
include!("src/build_version.rs");

fn main() {
    // Read when the script runs, not baked in when it was compiled. Cargo reuses a compiled build
    // script across a tree that has moved — its hash for a path package is relative to the
    // workspace — and `env!` would then point it at wherever the tree was when it was compiled:
    // a copy without `.git` was stamped with the original checkout's commit.
    let manifest = std::path::PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"),
    );
    let root = manifest
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

    // Which Trigon this is, for every run it records and every statement it signs. A checkout's
    // revision, or `+git.unknown` where there is no checkout, which is a build from a source
    // archive and must still compile.
    let (version, watch) = build_version(env!("CARGO_PKG_VERSION"), &root);
    for p in watch {
        println!("cargo:rerun-if-changed={}", p.display());
    }
    println!("cargo:rustc-env=TRIGON_BUILD_VERSION={version}");
}
