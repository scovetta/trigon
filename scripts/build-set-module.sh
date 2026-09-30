#!/usr/bin/env bash
#
# Build the stabilizer-set module: the stabilizers this checkout compiles in, as the WebAssembly
# module a verifier runs when its own binary no longer carries the set a verdict names
# (docs/09-attestations.md §7.1). `trigon attest` names it in every verdict, and `trigon publish`
# refuses a verdict that names none.
#
#   scripts/build-set-module.sh
#
# Prints the module's path, its sha256 and the commit it names. Point `[publish] stabilizer_module`
# in evidence.toml at the path, or pass it as `trigon attest --stabilizer-module <path>`.
#
# **Reproducible.** Two builds of one commit give the same bytes, wherever the checkout is and
# whoever builds it, so a verifier who would rather not run the module a record carries can build
# it from the source it names and compare the sha256 with the one the verdict signs. Three things
# would otherwise leak into it:
#
#   - the path of the checkout and of cargo's registry, through the source locations the compiler
#     embeds for panic messages. `--remap-path-prefix` rewrites both, to /trigon and /cargo;
#   - the same paths through debug information, which the release profile keeps (`debug = 1`) and
#     which is most of the module's size. Built here without it, and stripped;
#   - flags from the environment or a cargo configuration: CARGO_ENCODED_RUSTFLAGS is set here
#     outright, which takes precedence over RUSTFLAGS and any configured `rustflags`. Encoded, one
#     flag per 0x1f-separated field, because cargo splits RUSTFLAGS on whitespace, and a checkout
#     or a CARGO_HOME whose path has a space in it would come apart into two flags that name
#     neither path.
#
# **It names the commit it was built from** (`trigon_source_commit`), so a verifier knows which
# commit to rebuild it from: `git rev-parse HEAD`, with `.dirty` after it when the tree has changes
# the commit does not, as the binary's own version does (crates/trigon/src/build_version.rs). A
# dirty module cannot be rebuilt from a commit, and `trigon attest` says so. Outside a git
# checkout it names none. Two builds of one commit name the same one, so this costs nothing in
# reproducibility.
#
# The toolchain is the one rust-toolchain.toml pins, and the dependencies are Cargo.lock's
# (`--locked`). Everything else about the build is the release profile in Cargo.toml, whose
# `overflow-checks = true` the module keeps: a stabilizer must trap where the native build would.
#
# Needs the target: rustup target add wasm32-unknown-unknown

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
HOME_OF_CARGO="${CARGO_HOME:-$HOME/.cargo}"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

# Each path as cargo will spell it, and as the filesystem resolves it, where the two differ: one
# flag per field, a path with a space in it included.
SEP=$'\x1f'
flags="--remap-path-prefix=$ROOT=/trigon$SEP--remap-path-prefix=$HOME_OF_CARGO=/cargo"
if [ -d "$HOME_OF_CARGO" ]; then
    physical="$(cd "$HOME_OF_CARGO" && pwd -P)"
    [ "$physical" = "$HOME_OF_CARGO" ] || flags="$flags$SEP--remap-path-prefix=$physical=/cargo"
fi

# The commit, where ROOT is the top of a git checkout: a tree unpacked inside somebody else's
# repository is not that repository's commit. Unable to tell whether the tree is clean is not clean.
git_here() {
    env -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE GIT_OPTIONAL_LOCKS=0 git -C "$ROOT" "$@"
}
commit=""
if top="$(git_here rev-parse --show-toplevel 2>/dev/null)" \
    && [ "$(cd "$top" && pwd -P)" = "$ROOT" ] \
    && head="$(git_here rev-parse HEAD 2>/dev/null)" \
    && [[ "$head" =~ ^[0-9a-f]{40}$ ]]; then
    commit="$head"
    if ! status="$(git_here status --porcelain 2>/dev/null)" || [ -n "$status" ]; then
        commit="$commit.dirty"
    fi
fi

cd "$ROOT"
env -u RUSTFLAGS \
    CARGO_ENCODED_RUSTFLAGS="$flags" \
    TRIGON_SET_MODULE_COMMIT="$commit" \
    CARGO_PROFILE_RELEASE_DEBUG=0 \
    CARGO_PROFILE_RELEASE_STRIP=debuginfo \
    cargo build --locked -p trigon-stabilize-wasm --target wasm32-unknown-unknown --release >&2

MODULE="$TARGET_DIR/wasm32-unknown-unknown/release/trigon_stabilize_wasm.wasm"
[ -f "$MODULE" ] || { echo "cargo built no module at $MODULE" >&2; exit 1; }
echo "module  $MODULE"
echo "sha256  $(sha256sum "$MODULE" | cut -d' ' -f1)"
echo "commit  ${commit:-none: $ROOT is not the top of a git checkout}"
