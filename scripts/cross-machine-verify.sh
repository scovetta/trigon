#!/usr/bin/env bash
#
# The M2 exit criterion, as a script: an attestation produced here is checkable from a checkout that
# shares no state with the producer.
#
# This is the claim the whole design rests on, so it is worth running rather than asserting. The
# verifier gets a fresh `git clone`, its own target directory, and a `--no-default-features` build
# that links no async runtime and no network client. It is then handed four files — a bundle, two
# artifacts, and a public key — and nothing else, with the network taken away where the kernel
# allows it.
#
#   scripts/cross-machine-verify.sh [workdir]
#
# Exits non-zero if any step fails, so it drops into CI without a wrapper.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${1:-$(mktemp -d)}"
mkdir -p "$WORK"
cd "$WORK"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
say "The producer builds the artifacts and signs a statement"

mkdir -p producer/package/lib && cd producer
printf '{\n  "name": "demo",\n  "version": "1.4.2"\n}\n' > package/package.json
printf 'module.exports = function demo(x) { return x + 1 }\n' > package/lib/index.js
printf '# demo\n' > package/README.md

# Two tarballs holding identical members, packed by different machines. This is the ordinary case a
# stabilizer set exists for, not a contrived one.
tar --format=ustar --sort=name --mtime=@1700000000 --owner=0   --group=0  -cf - package | gzip -9 -n > upstream.tgz
tar --format=ustar --sort=name --mtime=@1725000000 --owner=501 --group=20 -cf - package | gzip -6 -n > rebuild.tgz
head -c 32 /dev/urandom > signing-key.bin

cargo run -q --manifest-path "$REPO/Cargo.toml" -p trigon -- \
    verify upstream.tgz rebuild.tgz \
    --attest bundle.json --key signing-key.bin --subject demo-1.4.2.tgz > /dev/null 2> produce.log
grep -q '^public key' produce.log || fail "the producer printed no public key"
cd "$WORK"

# ---------------------------------------------------------------------------
say "The verifier builds from a clone that shares nothing with the producer"

git clone -q --depth 1 "file://$REPO" verifier-src
CARGO_TARGET_DIR="$WORK/verifier-target" cargo build -q --release \
    --manifest-path verifier-src/Cargo.toml -p trigon --no-default-features
V="$WORK/verifier-target/release/trigon"
[ -x "$V" ] || fail "the verifier did not build"

# The claim is about a dependency tree, so check the tree rather than the diagram.
( cd verifier-src && cargo tree -p trigon --no-default-features -e normal --prefix none ) \
    | awk '{print $1}' | sort -u > deps.txt
if grep -Ex "tokio|reqwest|hyper|rustls|h2|axum|trigon-registry|trigon-sandbox|trigon-mirror|trigon-ai" deps.txt; then
    fail "the verifier links a runtime, a network client, or a sandbox"
fi
printf '  %s crates, none of them a runtime or a network client\n' "$(wc -l < deps.txt)"

# ---------------------------------------------------------------------------
say "The courier carries four files"

mkdir -p courier
cp producer/bundle.json producer/upstream.tgz producer/rebuild.tgz courier/
grep '^public key' producer/produce.log | cut -d' ' -f3 > courier/publisher.pub
cd courier && ls

# Under a network namespace with no interfaces where the kernel allows one. Not decoration: it is
# the difference between "does not use the network" and "did not happen to use it this time".
iso=()
if unshare -rn true 2>/dev/null; then iso=(unshare -rn); else echo "  (no unprivileged netns here; running without it)"; fi

say "The claim holds"
"${iso[@]}" "$V" verify-attestation bundle.json --rerun-comparison \
    --upstream upstream.tgz --rebuild rebuild.tgz --public-key "$(cat courier/publisher.pub 2>/dev/null || cat publisher.pub)" \
    || fail "a statement we produced did not re-derive"

# ---------------------------------------------------------------------------
# The positive result alone proves little: a verifier that printed "the claim holds" unconditionally
# would pass it. Each of these has to fail, and fail for its own reason.

say "And the lies do not"

python3 - <<'PY'
import json, base64
e = json.load(open('bundle.json'))
p = json.loads(base64.b64decode(e['payload']))
p['predicate']['outcome'] = 'exact'
e['payload'] = base64.b64encode(json.dumps(p, separators=(',', ':'), sort_keys=True).encode()).decode()
json.dump(e, open('lie.json', 'w'))
PY

if "$V" verify-attestation lie.json --rerun-comparison --upstream upstream.tgz --rebuild rebuild.tgz >/dev/null 2>&1; then
    fail "an overstated outcome was accepted"
fi
echo "  overstated outcome      refuted by the bytes, with no signature checked"

if "$V" verify-attestation lie.json --public-key "$(cat publisher.pub)" >/dev/null 2>&1; then
    fail "an edited payload verified against the publisher's key"
fi
echo "  edited payload          rejected by the signature"

# A different artifact that stabilizes to the same form: the case the stabilized digests alone
# cannot catch, which is why re-derivation checks the raw digests first.
tar --format=ustar --sort=name --mtime=@1700000000 --owner=7 --group=0 -cf - -C ../producer package | gzip -9 -n > other.tgz
if "$V" verify-attestation bundle.json --rerun-comparison --upstream other.tgz --rebuild rebuild.tgz >/dev/null 2>&1; then
    fail "a substituted artifact was accepted as the subject"
fi
echo "  substituted artifact    rejected as not the one the statement is about"

printf '\n\033[32mok — a statement produced here re-derives from a checkout sharing no state with it\033[0m\n'
printf 'workdir: %s\n' "$WORK"
