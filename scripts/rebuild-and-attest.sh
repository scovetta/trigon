#!/usr/bin/env bash
#
# Rebuild one package and sign what the run says, with the attestor as a separate process.
#
#   scripts/rebuild-and-attest.sh pkg:pypi/chardet@7.4.3
#   scripts/rebuild-and-attest.sh pkg:npm/left-pad@1.3.0 --key ~/.trigon/signing.key
#
# Two steps, deliberately not one. `trigon rebuild --attest <path>` exists and signs in the same
# process that ran the build; `trigon attest` reads the stored blobs back by hash, re-derives the
# claim from the artifact bytes, and only then signs. The second is the one worth running: a
# process that signs what it was told would launder a forged outcome into a signature.
#
# Exits 0 only when a statement was written.

set -euo pipefail

usage() {
    cat >&2 <<'USAGE'
usage: rebuild-and-attest.sh <purl> [options]

  --key <file>      ed25519 key to sign with. Without one the statements are written unsigned,
                    which is still a checkable document, just not an attributable one.
  --store <dir>     where runs and blobs go          (default: ./trigon-store)
  --work <dir>      where this run's artifacts go    (default: ./work/<purl-slug>)
  --egress <tier>   deny-all | mirror-only | open    (default: mirror-only)
  --image <ref>     base image. Resolved from the local store when omitted.
  --prune           drop the rebuilt bytes after attesting, keeping the digests
USAGE
    exit 2
}

[ $# -ge 1 ] || usage
case "$1" in -*|'') usage ;; esac

PURL="$1"; shift
KEY=""
STORE="./trigon-store"
WORK=""
EGRESS="mirror-only"
IMAGE=""
PRUNE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --key)    KEY="$2";    shift 2 ;;
        --store)  STORE="$2";  shift 2 ;;
        --work)   WORK="$2";   shift 2 ;;
        --egress) EGRESS="$2"; shift 2 ;;
        --image)  IMAGE="$2";  shift 2 ;;
        --prune)  PRUNE=1;     shift ;;
        -h|--help) usage ;;
        *) echo "unknown option: $1" >&2; usage ;;
    esac
done

# Prefer a built binary over whatever is on PATH, so a checkout tests itself.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TRIGON="${TRIGON:-$ROOT/target/debug/trigon}"
[ -x "$TRIGON" ] || TRIGON="$(command -v trigon || true)"
[ -n "$TRIGON" ] || { echo "no trigon binary: build one with \`cargo build -p trigon\`" >&2; exit 1; }

if [ -z "$WORK" ]; then
    WORK="./work/$(printf '%s' "$PURL" | tr -c 'A-Za-z0-9._@-' '-')"
fi

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

# ---------------------------------------------------------------------------------------------
# The images. This is the step that is worth scripting: a stale `--image` digest is reported as a
# missing image now, but the cure is still to look the current one up rather than paste one.
# ---------------------------------------------------------------------------------------------

# No `exit` in the awk: leaving the pipe early sends podman SIGPIPE, and under `pipefail` that is
# a non-zero status for a lookup that in fact succeeded. Reading the whole listing costs nothing.
image_id() {
    podman images --no-trunc --format '{{.Repository}}:{{.Tag}} {{.ID}}' 2>/dev/null \
        | awk -v want="$1" '$1 == want { found = $2 } END { print found }'
}

if [ -z "$IMAGE" ]; then
    IMAGE="$(image_id localhost/trigon-base:latest)"
    if [ -z "$IMAGE" ]; then
        say "no base image; building one"
        "$TRIGON" base-image --from docker.io/library/debian:bookworm-slim
        IMAGE="$(image_id localhost/trigon-base:latest)"
        [ -n "$IMAGE" ] || { echo "base image still missing after building it" >&2; exit 1; }
    fi
fi

# `--egress mirror-only` runs the mirror inside the build's network island, and that needs its
# image. Building it is idempotent and cheap when the layers are warm.
if [ "$EGRESS" = "mirror-only" ] && [ -z "$(image_id localhost/trigon-mirror:latest)" ]; then
    say "no mirror image; building one"
    "$TRIGON" mirror-image
fi

# ---------------------------------------------------------------------------------------------
# The rebuild. `--store` is what makes the run attestable at all: the record and the blobs the
# attestor reads back are written there, and a run without it leaves the attestor nothing.
# ---------------------------------------------------------------------------------------------

say "rebuilding $PURL"
printf '  image   %s\n  egress  %s\n  store   %s\n  work    %s\n' \
    "$IMAGE" "$EGRESS" "$STORE" "$WORK"

rm -rf "$WORK"
set +e
"$TRIGON" rebuild "$PURL" \
    --image "$IMAGE" \
    --egress "$EGRESS" \
    --timewarp auto \
    --work "$WORK" \
    --store "$STORE"
REBUILD_STATUS=$?
set -e

# A non-zero rebuild is not automatically a reason to stop. `record_run` sits past the point where
# the comparison is unwrapped, so a build failure, a void, a `no-strategy` and an error of ours
# write no record at all — and a divergence writes one and exits non-zero. The store is what says
# whether there is anything to attest, so ask it rather than the exit code.
LATEST="$("$TRIGON" runs --store "$STORE" 2>/dev/null | awk 'NR == 1 { print $1 }')"

if [ "$LATEST" = "no" ] || [ -z "$LATEST" ]; then
    say "nothing to attest"
    cat >&2 <<'WHY'
The run wrote no store record, which means it did not reach a comparison: a build failure, a
`no-strategy`, a void, or an error of ours. Nothing may be signed about a run that is evidence of
nothing, so this is the system working rather than a missing step.

  <work>/run.json      what happened, and why — `declines` names the rung that said no
  <work>/rebuild/      the container's own log and its network transcript
WHY
    # Never 0. `trigon rebuild` returns 0 for a `no-strategy` — it did what it was asked and had
    # nothing to say — but this script promises a statement, so "no statement" is a failure of the
    # script's own contract whatever the rebuild thought.
    [ "$REBUILD_STATUS" -ne 0 ] && exit "$REBUILD_STATUS"
    exit 1
fi

# ---------------------------------------------------------------------------------------------
# The attestation. A separate invocation on purpose: it reads the blobs back by hash, checks each
# against the hash it asked for, recomputes the equivalence claim from the artifact bytes, and
# refuses if the record disagrees with its own evidence or if the guard tripped.
# ---------------------------------------------------------------------------------------------

say "attesting $LATEST"
ATTEST_ARGS=(attest "$LATEST" --store "$STORE")
[ -n "$KEY" ] && ATTEST_ARGS+=(--key "$KEY")
[ -n "$PRUNE" ] && ATTEST_ARGS+=(--prune)

if ! "$TRIGON" "${ATTEST_ARGS[@]}"; then
    cat >&2 <<'WHY'

The attestor refused, and its message above says which gate. All four are deliberate:

  the guard tripped        the artifact reached the build over the network, so a match proves
                           only that the build downloaded it
  artifacts pruned         the claim cannot be re-derived, so it will not be re-signed
  record disagrees         the record claims something its own comparison does not say
  re-derivation failed     the bytes give a different answer from the one recorded

WHY
    exit 1
fi

if [ -z "$KEY" ]; then
    printf '\n  note: written unsigned. Pass --key for an attributable statement.\n'
fi

say "done"
"$TRIGON" runs --store "$STORE" | awk 'NR == 1' 
printf '\n  statements  %s/attestations/\n' "$STORE"
printf '  verify      %s verify-attestation \\\n' "$TRIGON"
printf '                %s/attestations/.../equivalence.intoto.json \\\n' "$STORE"
printf '                --rerun-comparison --upstream <published> --rebuild <rebuilt>\n'
