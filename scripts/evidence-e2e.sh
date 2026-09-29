#!/usr/bin/env bash
# End to end, on this machine, through the evidence store of docs/19:
#
#   (a) keys and a local evidence repository: an attestation key, a log key, a bare git repository,
#       evidence.toml, and `trigon log init`;
#   (b) a rebuild of one package. In `void` mode (the default) it runs at open egress, which the
#       publication gate calls void: a void publishes on one attempt, as a `void/v1` record. In
#       `verdict` mode it runs at mirror-only egress and is confirmed by a second, cold attempt,
#       because a verdict never publishes on one (ADR-0010 safeguard 1);
#   (c) `trigon attest` and `trigon publish` into the repository;
#   (d) the consumer's side: `evidence add` and `sync`, `lookup` by purl and by file, `check` over a
#       lockfile, the record's own falsifying command, the network-free record check, and two
#       checks that must fail (a record with one byte changed, a package never published).
#
# Usage: scripts/evidence-e2e.sh [PURL] [--mode void|verdict] [--dir DIR]
#   PURL      default pkg:npm/wrappy@1.0.2 (small, and reproduces at mirror-only)
#   --mode    void (default) or verdict. On one machine a verdict publishes only if the confirming
#             attempt could pull its base image again by a registry digest; a locally built base
#             image (trigon base-image, --image auto) has none, and the gate withholds the pair.
#   --dir     the work directory; default a new one under /tmp, kept afterwards either way
#
# Nothing outside the work directory is read or written: XDG config, cache and state, the
# evidence configuration and the store all live under it. The rebuilds need podman and the
# network (the mirror fetches what the build asks for); nothing else does.

set -euo pipefail

PURL="pkg:npm/wrappy@1.0.2"
DIR=""
MODE="void"
while [ $# -gt 0 ]; do
    case "$1" in
        --dir) DIR="$2"; shift 2 ;;
        --mode) MODE="$2"; shift 2 ;;
        -h|--help) sed -n '2,27p' "$0"; exit 0 ;;
        pkg:*) PURL="$1"; shift ;;
        *) echo "unknown argument: $1" >&2; exit 64 ;;
    esac
done

case "$MODE" in void|verdict) ;; *) echo "--mode is void or verdict" >&2; exit 64 ;; esac
# What every consumer-side answer must be: 0 for a verdict at or above normalized_with_caveats, 3
# for a void (docs/19 §6).
if [ "$MODE" = verdict ]; then OK=0; else OK=3; fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TRIGON="${TRIGON:-$ROOT/target/debug/trigon}"
[ -x "$TRIGON" ] || { echo "no trigon at $TRIGON: run \`cargo build -p trigon\` first" >&2; exit 1; }
W="${DIR:-$(mktemp -d /tmp/trigon-e2e.XXXXXX)}"
mkdir -p "$W"
W="$(cd "$W" && pwd)"
ORIGIN="example.org/trigon-e2e-evidence"

# Everything this run configures, caches or remembers stays in $W.
export XDG_CONFIG_HOME="$W/xdg/config" XDG_CACHE_HOME="$W/xdg/cache" XDG_STATE_HOME="$W/xdg/state"
export TRIGON_EVIDENCE_CONFIG="$W/evidence.toml"
unset TRIGON_PUBLISH_REPO TRIGON_EVIDENCE_REPO TRIGON_EVIDENCE_LOG_KEY \
      TRIGON_EVIDENCE_ATTESTATION_KEY TRIGON_EVIDENCE_CHECKPOINT TRIGON_EVIDENCE_TOFU \
      TRIGON_EVIDENCE_CACHE TRIGON_EVIDENCE_STATE
cd "$W"   # so no `.trigon/evidence.toml` of some project is picked up

t() { "$TRIGON" --theme textnocolor "$@"; }
PASSED=()
FAILED=()
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
show() { printf '$ trigon %s\n' "$*"; }
# expect CODE CMD...: run a trigon command, and record whether it exited as it should.
expect() {
    local want="$1"; shift
    show "$*"
    set +e; t "$@"; local got=$?; set -e
    if [ "$got" -eq "$want" ]; then PASSED+=("exit $got: trigon $*")
    else FAILED+=("exit $got, wanted $want: trigon $*"); printf '\033[31m!! exit %s, wanted %s\033[0m\n' "$got" "$want"; fi
}
json_field() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); v=d
for k in sys.argv[2].split("."): v=v.get(k) if isinstance(v,dict) else None
print(v if v is not None else "")' "$1" "$2"; }

echo "work directory: $W"
echo "package:        $PURL"
echo "mode:           $MODE"
echo "trigon:         $(t --version)"

# ------------------------------------------------------------------------------------------------
step "(a) keys, a local evidence repository, and its configuration"
# ------------------------------------------------------------------------------------------------
mkdir -p "$W/keys"
[ -f "$W/keys/attestation.key" ] || t keygen --out "$W/keys/attestation.key" >/dev/null
[ -f "$W/keys/log.key" ] || t log keygen --origin "$ORIGIN" --out "$W/keys/log.key" >/dev/null
ATT_HEX="$(t public-key "$W/keys/attestation.key")"
LOG_VKEY="$(t log public-key "$W/keys/log.key")"
echo "attestation key  $ATT_HEX"
echo "log key          $LOG_VKEY"

[ -d "$W/evidence.git" ] || git init -q --bare -b main "$W/evidence.git"

cat > "$W/evidence.toml" <<EOF
# Written by scripts/evidence-e2e.sh. The publisher's half:
[publish]
repo = "$W/evidence.git"
branch = "main"
origin = "$ORIGIN"
disputes = "https://$ORIGIN/issues"
log_key = "$W/keys/log.key"
# One machine, so the confirming attempt runs here: cold, its image re-pulled (docs/19 D8).
same_host_confirmation = true
confirmation_interval = "1s"
EOF
echo "wrote $W/evidence.toml"

if [ -z "$(git -C "$W/evidence.git" rev-parse --verify -q refs/heads/main)" ]; then
    show "log init --origin $ORIGIN --repo $W/evidence.git …"
    t log init --origin "$ORIGIN" --repo "$W/evidence.git" --attestation-key "$ATT_HEX"
else
    echo "the repository already has a log; keeping it"
fi

# ------------------------------------------------------------------------------------------------
step "(b) rebuild $PURL ($MODE)"
# ------------------------------------------------------------------------------------------------
STORE="$W/store"
runs() { t runs --store "$STORE" 2>/dev/null | awk '$1 != "no" && $1 ~ /^[0-9]+-/ { print $1 }' | sort; }
if [ "$MODE" = verdict ]; then EGRESS=mirror-only; else EGRESS=open; fi
BEFORE="$(runs)"
show "rebuild $PURL --image auto --egress $EGRESS --timewarp auto --store $STORE"
set +e
t rebuild "$PURL" --image auto --egress "$EGRESS" --timewarp auto --work "$W/work" --store "$STORE"
rc=$?
set -e
RUN="$(comm -13 <(echo "$BEFORE") <(runs) | tail -1)"
[ -n "$RUN" ] || { echo "the rebuild recorded no run (exit $rc)" >&2; exit 1; }
OUTCOME="$(json_field "$STORE/runs/$RUN.json" outcome)"
echo "run: $RUN (rebuild exited $rc, outcome ${OUTCOME:-none})"
case "$OUTCOME" in
    exact|normalized|normalized_with_caveats|divergent) ;;
    *) echo "the rebuild reached no outcome to publish; try another package" >&2; exit 1 ;;
esac

if [ "$MODE" = verdict ]; then
    BEFORE="$(runs)"
    show "rebuild --confirm $RUN --store $STORE"
    t rebuild --confirm "$RUN" --work "$W/work-confirm" --store "$STORE" || true
    CONFIRM="$(comm -13 <(echo "$BEFORE") <(runs) | tail -1)"
    [ -n "$CONFIRM" ] || { echo "the confirming attempt recorded no run" >&2; exit 1; }
    echo "confirming run: $CONFIRM (outcome: $(json_field "$STORE/runs/$CONFIRM.json" outcome))"
else
    echo "open egress: the gate calls this run void, so it publishes as a void/v1 record on one attempt"
fi

# ------------------------------------------------------------------------------------------------
step "(c) attest, and publish into the evidence repository"
# ------------------------------------------------------------------------------------------------
expect 0 attest "$RUN" --store "$STORE" --key "$W/keys/attestation.key"
expect 0 publish "$RUN" --store "$STORE"
if [ ${#FAILED[@]} -gt 0 ]; then
    echo
    echo "publish refused, so there is nothing for a consumer to find: stopping here."
    echo "In verdict mode on one machine this is the gate's rule, not a failure of the store:"
    echo "the confirming attempt must pull its base image again by a registry digest."
    echo "Run with --mode void to exercise the rest, or confirm on a second machine."
    exit 1
fi
echo
git -C "$W/evidence.git" log --oneline main
echo
git -C "$W/evidence.git" ls-tree -r --name-only main | sed 's/^/  /' | head -40

# ------------------------------------------------------------------------------------------------
step "(d) validate, as a consumer would"
# ------------------------------------------------------------------------------------------------
expect 0 evidence add e2e "$W/evidence.git" --log-key "$LOG_VKEY" --attestation-key "$ATT_HEX" --required
expect 0 evidence sync
expect 0 evidence list

# The artifacts, from the store: what the registry published, and what the rebuild produced.
blob() { local h="$1"; echo "$STORE/blobs/sha256/${h:0:2}/$h"; }
UP_SHA="$(json_field "$STORE/runs/$RUN.json" upstream.sha256)"
RB_SHA="$(json_field "$STORE/runs/$RUN.json" rebuild.sha256)"
UP_NAME="$(json_field "$STORE/runs/$RUN.json" upstream.name)"
mkdir -p "$W/artifacts"
cp "$(blob "$UP_SHA")" "$W/artifacts/$UP_NAME"
REBUILD_ARGS=()
if [ -n "$RB_SHA" ] && [ -f "$(blob "$RB_SHA")" ] && [ "$RB_SHA" != "$UP_SHA" ]; then
    cp "$(blob "$RB_SHA")" "$W/artifacts/rebuilt-$UP_NAME"
    REBUILD_ARGS=(--rebuild "$W/artifacts/rebuilt-$UP_NAME")
fi

expect "$OK" lookup "$PURL"
expect "$OK" lookup "$W/artifacts/$UP_NAME"

# A lockfile naming the package, with the digest its ecosystem declares.
case "$PURL" in
    pkg:npm/*)
        spec="${PURL#pkg:npm/}"; name="${spec%@*}"; name="${name//%40/@}"; ver="${spec##*@}"
        integrity="sha512-$(openssl dgst -sha512 -binary "$W/artifacts/$UP_NAME" | base64 -w0)"
        cat > "$W/package-lock.json" <<EOF
{
  "name": "e2e", "lockfileVersion": 3, "requires": true,
  "packages": {
    "": { "name": "e2e", "dependencies": { "$name": "$ver" } },
    "node_modules/$name": { "version": "$ver",
      "resolved": "https://registry.npmjs.org/$name/-/${name##*/}-$ver.tgz",
      "integrity": "$integrity" }
  }
}
EOF
        LOCKFILE="$W/package-lock.json" ;;
    pkg:pypi/*)
        spec="${PURL#pkg:pypi/}"
        echo "${spec%@*}==${spec##*@} --hash=sha256:$UP_SHA" > "$W/requirements.txt"
        LOCKFILE="$W/requirements.txt" ;;
    *) LOCKFILE="" ;;
esac
if [ -n "$LOCKFILE" ]; then expect "$OK" check "$LOCKFILE"
else echo "(no lockfile form for this ecosystem here; check skipped)"; fi

# The record's own falsifying command, as it is signed into the record.
expect "$OK" verify-attestation --lookup "sha256:$UP_SHA" --origin "$ORIGIN" \
    --rerun-comparison --upstream "$W/artifacts/$UP_NAME" "${REBUILD_ARGS[@]}"

# The network-free check of the record file itself, from the synced clone.
RECORD_REL="$(git -C "$W/evidence.git" ls-tree -r --name-only main | grep '^records/' | head -1)"
git -C "$W/evidence.git" show "main:$RECORD_REL" > "$W/record.json"
expect "$OK" verify-attestation --record "$W/record.json" --source e2e

# Two that must fail.
python3 - "$W/record.json" "$W/record-tampered.json" <<'EOF'
import sys
b = bytearray(open(sys.argv[1], 'rb').read())
i = b.index(b'"payload"') + 20          # inside the signed payload
b[i] = ord('A') if b[i] != ord('A') else ord('B')
open(sys.argv[2], 'wb').write(bytes(b))
EOF
expect 4 verify-attestation --record "$W/record-tampered.json" --source e2e
expect 2 lookup "pkg:npm/this-package-was-never-published@0.0.1"

# ------------------------------------------------------------------------------------------------
step "result"
# ------------------------------------------------------------------------------------------------
for p in "${PASSED[@]}"; do printf '  \033[32mok\033[0m    %s\n' "$p"; done
for f in "${FAILED[@]}"; do printf '  \033[31mFAIL\033[0m  %s\n' "$f"; done
echo
echo "work directory kept: $W"
echo "  evidence repository   $W/evidence.git   (git -C $W/evidence.git log --stat)"
echo "  store                 $STORE            ($TRIGON runs --store $STORE)"
echo "  configuration         $W/evidence.toml"
[ ${#FAILED[@]} -eq 0 ] && { echo "all ${#PASSED[@]} checks passed"; exit 0; }
echo "${#FAILED[@]} of $(( ${#PASSED[@]} + ${#FAILED[@]} )) checks failed"; exit 1
