#!/usr/bin/env bash
# End to end, on this machine, through the evidence store of docs/19:
#
#   (a) keys and a local evidence repository: an attestation key, a log key, a bare git repository,
#       evidence.toml, and `trigon log init`;
#   (b) a rebuild of one package behind the mirror's egress filter (`--egress mirror-only`: the
#       build's only route out is the mirror, pinned to the moment the package was published), and
#       a second, cold attempt to confirm it, because a verdict never publishes on one attempt
#       (ADR-0010 safeguard 1);
#   (c) `trigon attest` and `trigon publish` into the repository;
#   (d) the consumer's side: `evidence add` and `sync`, `lookup` by purl and by file, `check` over a
#       lockfile, the record's own falsifying command, the network-free record check, and two
#       checks that must fail (a record with one byte changed, a package never published).
#
# Usage: scripts/evidence-e2e.sh [PURL] [--egress mirror-only|deny-all|open] [--dir DIR]
#   PURL      default pkg:npm/wrappy@1.0.2 (small, and reproduces behind the mirror)
#   --egress  default mirror-only, the mirror's egress filter. `deny-all` gives the build no network
#             at all, so only a package whose build fetches nothing reaches an outcome. `open`
#             gives the gate a void, which publishes on one attempt. These are the tiers the podman
#             runner enforces; `git-and-mirror` is not among them yet.
#   --dir     default work/evidence-e2e in this repository (gitignored). A directory left by an
#             earlier run is moved aside with a timestamp, never deleted.
#
# Everything is kept for inspection: the bare repository, a checkout of it, the store, the keys and
# the configuration. `source <dir>/env.sh` points trigon at them from any shell. Nothing outside the
# directory is read or written (XDG config, cache and state included). The rebuilds need podman and
# the network, which the mirror fetches through; nothing else does.
#
# On one machine the confirming attempt runs here, cold. A locally built base image (`trigon
# base-image`, `--image auto`) has no registry digest to pull it again by, so the configuration
# turns on `same_host_local_images` for this repository (docs/19 D8) and says so.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PURL="pkg:npm/wrappy@1.0.2"
EGRESS="mirror-only"
DIR="$ROOT/work/evidence-e2e"
while [ $# -gt 0 ]; do
    case "$1" in
        --egress) EGRESS="$2"; shift 2 ;;
        --dir) DIR="$2"; shift 2 ;;
        -h|--help) sed -n '2,/^$/p' "$0"; exit 0 ;;
        pkg:*) PURL="$1"; shift ;;
        *) echo "unknown argument: $1" >&2; exit 64 ;;
    esac
done
# Only a tier trigon parses and the podman runner enforces: any other fails at the rebuild, after
# the mirror image is built, and would be reported below as a package that reached no outcome.
case "$EGRESS" in
    mirror-only|deny-all|open) ;;
    *) echo "--egress is mirror-only (the mirror's egress filter), deny-all or open" >&2; exit 64 ;;
esac
# What every consumer-side answer must be: 0 for a verdict at or above normalized_with_caveats, 3
# for a void (docs/19 §6). Open egress is void by the gate's rule.
if [ "$EGRESS" = open ]; then OK=3; else OK=0; fi

TRIGON="${TRIGON:-$ROOT/target/debug/trigon}"
[ -x "$TRIGON" ] || { echo "no trigon at $TRIGON: run \`cargo build -p trigon\` first" >&2; exit 1; }

# Never delete an earlier run: move it aside.
if [ -e "$DIR" ]; then
    aside="$DIR.$(date +%Y%m%d-%H%M%S)"
    mv "$DIR" "$aside"
    echo "moved the earlier run aside: $aside"
fi
mkdir -p "$DIR"
W="$(cd "$DIR" && pwd)"
ORIGIN="example.org/trigon-e2e-evidence"

# Everything this run configures, caches or remembers stays in $W, and env.sh says how to reach it.
export XDG_CONFIG_HOME="$W/xdg/config" XDG_CACHE_HOME="$W/xdg/cache" XDG_STATE_HOME="$W/xdg/state"
export TRIGON_EVIDENCE_CONFIG="$W/evidence.toml"
unset TRIGON_PUBLISH_REPO TRIGON_EVIDENCE_REPO TRIGON_EVIDENCE_LOG_KEY \
      TRIGON_EVIDENCE_ATTESTATION_KEY TRIGON_EVIDENCE_CHECKPOINT TRIGON_EVIDENCE_TOFU \
      TRIGON_EVIDENCE_CACHE TRIGON_EVIDENCE_STATE
cat > "$W/env.sh" <<EOF
# source this to run trigon against the evidence-e2e setup in $W
export XDG_CONFIG_HOME="$W/xdg/config" XDG_CACHE_HOME="$W/xdg/cache" XDG_STATE_HOME="$W/xdg/state"
export TRIGON_EVIDENCE_CONFIG="$W/evidence.toml"
alias trigon="$TRIGON"
echo "trigon now reads $W/evidence.toml; the store is $W/store"
EOF
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
image_id() {
    podman images --no-trunc --format '{{.Repository}}:{{.Tag}} {{.ID}}' 2>/dev/null \
        | awk -v want="$1" '$1 == want { found = $2 } END { print found }'
}

echo "work directory: $W"
echo "package:        $PURL"
echo "egress:         $EGRESS"
echo "trigon:         $(t --version)"

# ------------------------------------------------------------------------------------------------
step "(a) keys, a local evidence repository, and its configuration"
# ------------------------------------------------------------------------------------------------
mkdir -p "$W/keys"
t keygen --out "$W/keys/attestation.key" >/dev/null
t log keygen --origin "$ORIGIN" --out "$W/keys/log.key" >/dev/null
ATT_HEX="$(t public-key "$W/keys/attestation.key")"
LOG_VKEY="$(t log public-key "$W/keys/log.key")"
echo "attestation key  $ATT_HEX"
echo "log key          $LOG_VKEY"

git init -q --bare -b main "$W/evidence.git"

cat > "$W/evidence.toml" <<EOF
# Written by scripts/evidence-e2e.sh. The publisher's half:
[publish]
repo = "$W/evidence.git"
branch = "main"
origin = "$ORIGIN"
disputes = "https://$ORIGIN/issues"
log_key = "$W/keys/log.key"
# One machine, so the confirming attempt runs here, cold (docs/19 D8). Its base image was built
# locally and has no registry digest to pull it again by; same_host_local_images accepts it.
same_host_confirmation = true
same_host_local_images = true
confirmation_interval = "1s"
EOF
echo "wrote $W/evidence.toml"

show "log init --origin $ORIGIN --repo $W/evidence.git --attestation-key …"
# Its output ends with the GitHub ruleset call to protect the branch, kept in log-init.txt.
t log init --origin "$ORIGIN" --repo "$W/evidence.git" --attestation-key "$ATT_HEX" \
    > "$W/log-init.txt"
sed -n '1,/^$/p' "$W/log-init.txt"

# The mirror runs from its own image, inside the build's network island; only `mirror-only` has one.
if [ "$EGRESS" = mirror-only ] && [ -z "$(image_id localhost/trigon-mirror:latest)" ]; then
    echo "no mirror image; building one"
    t mirror-image
fi

# ------------------------------------------------------------------------------------------------
step "(b) rebuild $PURL behind the egress filter ($EGRESS)"
# ------------------------------------------------------------------------------------------------
STORE="$W/store"
runs() { t runs --store "$STORE" 2>/dev/null | awk '$1 != "no" && $1 ~ /^[0-9]+-/ { print $1 }' | sort; }
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

if [ "$EGRESS" != open ]; then
    BEFORE="$(runs)"
    show "rebuild --confirm $RUN --store $STORE"
    t rebuild --confirm "$RUN" --work "$W/work-confirm" --store "$STORE" || true
    CONFIRM="$(comm -13 <(echo "$BEFORE") <(runs) | tail -1)"
    [ -n "$CONFIRM" ] || { echo "the confirming attempt recorded no run" >&2; exit 1; }
    echo "confirming run: $CONFIRM (outcome: $(json_field "$STORE/runs/$CONFIRM.json" outcome))"
    # What the gate reads of it on one machine: whether anything warm could supply it, and how its
    # base image was pinned and whether it was pulled again.
    echo "  warm: $(json_field "$STORE/runs/$CONFIRM.json" cache.warm)," \
        "image_pin: $(json_field "$STORE/runs/$CONFIRM.json" cache.image_pin)," \
        "image_repulled: $(json_field "$STORE/runs/$CONFIRM.json" cache.image_repulled)"
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
    echo "publish refused, so there is nothing for a consumer to find: stopping here. The gate's"
    echo "reason is above. Everything so far is kept in $W."
    exit 1
fi
git clone -q "$W/evidence.git" "$W/evidence-checkout"
echo
git -C "$W/evidence-checkout" log --oneline
echo
(cd "$W/evidence-checkout" && find . -path ./.git -prune -o -type f -print | sort | sed 's|^\./|  |')

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
RECORD_REL="$(cd "$W/evidence-checkout" && ls records/*/*/*.json | head -1)"
cp "$W/evidence-checkout/$RECORD_REL" "$W/record.json"
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
cat <<EOF

Kept for inspection, in $W:
  evidence.git        the evidence repository (bare), as a consumer clones it
  evidence-checkout/  a checkout of it:      git -C $W/evidence-checkout log --stat
  record.json         the published record:  python3 -m json.tool $W/record.json
  store/              the runs:              $TRIGON runs --store $W/store
  evidence.toml       publisher and consumer configuration
  keys/               attestation and log keys
  source $W/env.sh    then run trigon lookup / check / evidence list against this setup
EOF
[ ${#FAILED[@]} -eq 0 ] && { echo; echo "all ${#PASSED[@]} checks passed"; exit 0; }
echo; echo "${#FAILED[@]} of $(( ${#PASSED[@]} + ${#FAILED[@]} )) checks failed"; exit 1
