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
                    Make one with: trigon keygen --out ~/.trigon/signing.key
  --store <dir>     where runs and blobs go          (default: ./trigon-store)
  --work <dir>      where this run's artifacts go    (default: ./work/<purl-slug>)
  --egress <tier>   deny-all | mirror-only | open    (default: mirror-only)
  --image <ref>     base image. Resolved from the local store when omitted.
  --model <spec>    ask a model for a strategy when nothing deterministic produced one. Off by
                    default: a run that silently calls a model is a run whose cost and derivation
                    are a surprise. `replay:<transcript.json>` answers from a recording and opens
                    no socket, which is the form to use in a test.
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
MODEL=""
PRUNE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --key)    KEY="$2";    shift 2 ;;
        --store)  STORE="$2";  shift 2 ;;
        --work)   WORK="$2";   shift 2 ;;
        --egress) EGRESS="$2"; shift 2 ;;
        --image)  IMAGE="$2";  shift 2 ;;
        --model)  MODEL="$2";  shift 2 ;;
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

# Bold headings, but only where the binary would colour too: stdout is a terminal and NO_COLOR is
# unset. This mirrors `style::enabled()` so the script and `trigon`'s own output agree about colour.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then B='\033[1;97m'; R='\033[0m'; else B=''; R=''; fi
say() { printf '\n%b%s%b\n' "$B" "$*" "$R"; }

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

# Which runs the store already held. The run to attest is the one *this* invocation produced, and
# the only way to know which that is, is to know which were there before.
RUNS_BEFORE="$("$TRIGON" runs --store "$STORE" 2>/dev/null | awk '$1 != "no" { print $1 }' | sort)"

# The invocation banner — image, egress, store, work — is printed by `trigon rebuild` itself now,
# styled and in the tool-wide column, so a direct run shows it too and there is one place that owns
# the colour. Nothing to echo here.

rm -rf "$WORK"
set +e
REBUILD_ARGS=(rebuild "$PURL"
    --image "$IMAGE"
    --egress "$EGRESS"
    --timewarp auto
    --work "$WORK"
    --store "$STORE")
# Appended rather than passed empty. `--model ""` is not "no model": clap takes the empty string as
# the value, and the ladder then reports a model rung that cannot answer instead of one that was
# never asked.
[ -n "$MODEL" ] && REBUILD_ARGS+=(--model "$MODEL")
"$TRIGON" "${REBUILD_ARGS[@]}"
REBUILD_STATUS=$?
set -e

# A non-zero rebuild is not automatically a reason to stop. `record_run` sits past the point where
# the comparison is unwrapped, so a build failure, a void, a `no-strategy` and an error of ours
# write no record at all — and a divergence writes one and exits non-zero. The store is what says
# whether there is anything to attest, so ask it rather than the exit code.
# **The run this invocation made, not the newest run in the store.** Those are the same thing only
# when the store starts empty, and taking the newest meant that a target which produced no record —
# a `no-strategy`, a build failure — silently attested and signed whatever ran last. Asked for a
# NuGet package, this script signed a statement about a left-pad run from an hour earlier. Nothing
# in the statement was false, which is what made it dangerous: the operator asked about one package
# and was handed a signed claim about another.
RUNS_AFTER="$("$TRIGON" runs --store "$STORE" 2>/dev/null | awk '$1 != "no" { print $1 }' | sort)"
LATEST="$(comm -13 <(printf '%s\n' "$RUNS_BEFORE") <(printf '%s\n' "$RUNS_AFTER") | awk 'NF' | tail -1)"

# And, independently, that it is about the package that was asked for. Two checks rather than one
# because they fail differently: the first catches a run that produced nothing, the second catches
# a store being written by something else at the same time.
if [ -n "$LATEST" ]; then
    RAN_TARGET="$("$TRIGON" runs --store "$STORE" 2>/dev/null |
                  awk -v id="$LATEST" '$1 == id { print $2 }')"
    if [ "$RAN_TARGET" != "$PURL" ]; then
        say "refusing to attest"
        printf 'The new run in the store is for `%s`, and this invocation asked for `%s`.\n' \
               "$RAN_TARGET" "$PURL" >&2
        printf 'Refusing to sign a statement about a package nobody asked about.\n' >&2
        exit 1
    fi
fi

if [ "$LATEST" = "no" ] || [ -z "$LATEST" ]; then
    say "nothing to attest"
    cat >&2 <<'WHY'
This run wrote no store record, which means it did not reach a comparison: a build failure, a
`no-strategy`, a void, or an error of ours. Nothing may be signed about a run that is evidence of
nothing, so this is the system working rather than a missing step.

The store may well hold other runs, including successful ones. None of them is this run, and none
of them is what you asked about.

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
# The two artifact paths, filled in rather than left as <published> and <rebuilt>. This script knows
# both — the published one sits at the top of the work directory and the rebuilt one under
# `rebuild/<strategy>-<pid>/` — and printing placeholders for values it holds is how a verify line
# ends up retyped wrong or not run at all.
# Found structurally rather than by parsing a record: the published artifact is the file at the top
# of the work directory whose name also appears under `rebuild/<strategy>-<pid>/`. That pairing is
# the definition of the two files `--rerun-comparison` wants, it holds for every ecosystem's
# extension, and it needs no jq. Requiring both halves is what keeps a half-answer out of the line.
UPSTREAM=""; REBUILT=""
for candidate in "$WORK"/*; do
    [ -f "$candidate" ] || continue
    # **Case-insensitively.** NuGet ids are case-insensitive and the feed serves the filename
    # folded, so the published artifact arrives as `polly.8.2.0.nupkg` while `dotnet pack` writes
    # `Polly.8.2.0.nupkg`. An exact match found neither and printed placeholders for a run that had
    # both files sitting in the work directory. Other ecosystems are unaffected: their two names
    # already agree, so folding changes nothing for them.
    base="${candidate##*/}"
    set -- $(find "$WORK"/rebuild -maxdepth 2 -type f -iname "$base" 2>/dev/null)
    # Exactly one match, or none: rebuild directories accumulate across runs of the same target,
    # and a verify line naming the wrong one is worse than naming none at all.
    if [ $# -eq 1 ] && [ -f "$1" ]; then
        if [ -n "$UPSTREAM" ]; then
            # Two candidates means the guess is not a guess worth printing.
            UPSTREAM=""; REBUILT=""
            break
        fi
        UPSTREAM="$candidate"; REBUILT="$1"
    fi
done

# The claim's path, from the record the attestor just wrote rather than from a glob over the
# glob over the store: a store accumulates runs, and the bundle this line should name is the one
# this run produced. Read with sed because the record puts one path per line, so the script needs
# no jq.
# **`equivalence` OR `divergence`.** A run that reproduces writes the first and a run that does not
# writes the second, and this matched only the first — so every divergent run, which is exactly the
# run someone most wants to check by hand, printed a placeholder for a bundle sitting in the store
# under the other name. The other two statements a run writes, `rebuild` and `buildobservation`,
# describe how the artifact was produced rather than how it compared, and `--rerun-comparison` has
# nothing to re-derive from either.
BUNDLE=""
INCOMPLETE=""
if [ -f "$STORE/runs/$LATEST.json" ]; then
    # `#` as the delimiter, not `|`. With `|` delimiting the s-command, the `\|` below reads as an
    # escaped delimiter rather than an alternation, so the expression matched nothing at all and
    # every run printed a placeholder — including the ones that did reproduce.
    REL="$(sed -n 's#.*"\(attestations/[^"]*/\(equivalence\|divergence\)\.intoto\.json\)".*#\1#p' \
           "$STORE/runs/$LATEST.json" | head -1)"
    [ -n "$REL" ] && [ -f "$STORE/$REL" ] && BUNDLE="$STORE/$REL"
fi

printf '\n  statements  %s/attestations/\n' "$STORE"
printf '  verify      %s verify-attestation \\\n' "$TRIGON"
if [ -n "$BUNDLE" ]; then
    printf '                "%s" \\\n' "$BUNDLE"
else
    printf '                %s/attestations/.../{equivalence,divergence}.intoto.json \\\n' "$STORE"
    INCOMPLETE=1
fi
if [ -n "$UPSTREAM" ] && [ -n "$REBUILT" ]; then
    printf '                --rerun-comparison \\\n'
    printf '                --upstream "%s" \\\n' "$UPSTREAM"
    printf '                --rebuild "%s"' "$REBUILT"
else
    printf '                --rerun-comparison --upstream <published> --rebuild <rebuilt>'
    INCOMPLETE=1
fi
[ -n "$KEY" ] && printf ' \\\n                --public-key $(%s public-key %s)' "$TRIGON" "$KEY"
printf '\n'
if [ -n "$INCOMPLETE" ]; then
    # A placeholder in that line is a command nobody can paste, which is the whole reason the rest
    # is filled in. Say which part could not be resolved rather than let it be found by trying.
    printf '\n  note: the <angle-bracketed> parts above could not be filled in from this run.\n'
    printf '        The two artifacts are the file at the top of %s and its\n' "$WORK"
    printf '        namesake under %s/rebuild/<strategy>/.\n' "$WORK"
fi
