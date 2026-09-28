#!/usr/bin/env bash
#
# The phase 5 spike of docs/19 §10: what an evidence repository costs on GitHub at scale.
#
#   TRIGON_LIVE=1 GITHUB_TOKEN=… scripts/evidence-spike.sh <owner>/<scratch-repo> [options]
#
# Measures, against a scratch repository the person running it names and nothing else:
#
#   1. clone time for the consumer's default clone — `git clone --depth 1 --filter=blob:none
#      --sparse`, then `git sparse-checkout set keys log records` (docs/19 §6) — at each size in
#      --records (10^4 and 10^5 synthetic records by default), unauthenticated, as a consumer
#      clones;
#   2. fetch time for that clone, at each of those sizes, after one publication-sized commit —
#      `git fetch --depth 1` and `git reset --hard FETCH_HEAD`, never a pull;
#   3. push time for a commit of a few hundred files (--commit-files, 300 by default), several
#      times, paced under GitHub's advice of at most 6 pushes a minute to one repository, and for
#      each growth batch as the repository grows by thousands of files at a time;
#   4. GitHub's behaviour for unauthenticated git reads above its advice of about 15 a second:
#      --git-reads `git ls-remote`s and shallow fetches of the public URL, started --git-rate a
#      second, with no credential, and what each answered;
#   5. the practical limits on release assets: upload time for many small assets and one large
#      one, the time to list a release's assets, and, with --probe-asset-limit, what GitHub says
#      to the 1,001st asset of one release;
#   6. the repository's size as GitHub reports it after each step, and the API's rate limits.
#
# **Synthetic records**, shaped as docs/19 §7 sizes them — a record file of ~10 KB under
# records/<aa>/<bb>/, five index files per record, and a leaf of ~600 bytes in 256-leaf entry
# bundles with hash tiles beside them — so that transfer and object counts are realistic. None of
# it is signed and none of it verifies: this measures GitHub, not Trigon's checks.
#
# **It writes only into a repository that holds nothing but what this script writes.** Before
# anything is pushed it refuses a --push-url or --clone-url that does not name <owner>/<repo>; a
# repository with a branch other than `main`, or a release whose tag this script did not make; and
# a `main` whose files are anything but its own — SPIKE.md, saying it was written by this script,
# and keys/, log/, records/ and index/. It never force-pushes and never deletes. It needs `git`,
# `curl` and `python3`, a push credential
# for the repository in git's own configuration (an SSH key for --push-url, by default), and
# GITHUB_TOKEN or GH_TOKEN with contents-write on it for the release steps, read from the
# environment and never printed. Results go to --out (./spike-<date>/results.md), for
# docs/16-findings.md.
#
# Not run in CI, and never by a test: TRIGON_LIVE=1 is required.

set -euo pipefail

usage() {
    cat >&2 <<'USAGE'
usage: TRIGON_LIVE=1 evidence-spike.sh <owner>/<repo> [options]

  --records "<n> <n>…"    sizes to measure the consumer clone at   (default: "10000 100000")
  --commit-files <n>      files in one publication-sized commit     (default: 300)
  --pushes <n>            publication-sized pushes to time          (default: 5)
  --batch <n>             records per growth commit                 (default: 5000)
  --git-reads <n>         unauthenticated git reads to make          (default: 60)
  --git-rate <n>          of them started a second                   (default: 20)
  --assets <n>            small release assets to upload and time   (default: 50)
  --large-mib <n>         size of the one large asset, MiB          (default: 100)
  --probe-asset-limit     fill one release to 1,000 assets and try a 1,001st
  --push-url <url>        where to push   (default: git@github.com:<owner>/<repo>.git)
  --clone-url <url>       where to clone  (default: https://github.com/<owner>/<repo>.git)
  --out <dir>             results directory (default: ./spike-<UTC date>)
USAGE
    exit 2
}

if [ "${TRIGON_LIVE:-}" != "1" ]; then
    echo "refusing: this pushes to GitHub. Set TRIGON_LIVE=1 to run it against a scratch" \
         "repository you name." >&2
    exit 2
fi
[ $# -ge 1 ] || usage
case "$1" in -*|'') usage ;; esac
REPO="$1"; shift
case "$REPO" in
    */*) ;;
    *) echo "refusing: '$REPO' is not <owner>/<repo>" >&2; exit 2 ;;
esac

RECORDS="10000 100000"
COMMIT_FILES=300
PUSHES=5
BATCH=5000
GIT_READS=60
GIT_RATE=20
ASSETS=50
LARGE_MIB=100
PROBE=0
PUSH_URL="git@github.com:${REPO}.git"
CLONE_URL="https://github.com/${REPO}.git"
OUT="./spike-$(date -u +%Y%m%d)"
while [ $# -gt 0 ]; do
    case "$1" in
        --records) RECORDS="$2"; shift 2 ;;
        --commit-files) COMMIT_FILES="$2"; shift 2 ;;
        --pushes) PUSHES="$2"; shift 2 ;;
        --batch) BATCH="$2"; shift 2 ;;
        --git-reads) GIT_READS="$2"; shift 2 ;;
        --git-rate) GIT_RATE="$2"; shift 2 ;;
        --assets) ASSETS="$2"; shift 2 ;;
        --large-mib) LARGE_MIB="$2"; shift 2 ;;
        --probe-asset-limit) PROBE=1; shift ;;
        --push-url) PUSH_URL="$2"; shift 2 ;;
        --clone-url) CLONE_URL="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        *) usage ;;
    esac
done
TOKEN="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
if [ -z "$TOKEN" ]; then
    echo "refusing: the release steps need GITHUB_TOKEN or GH_TOKEN with contents-write on" \
         "$REPO" >&2
    exit 2
fi
for tool in git curl python3; do
    command -v "$tool" >/dev/null || { echo "refusing: $tool is not on PATH" >&2; exit 2; }
done

mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
WORK="$OUT/work"
RESULTS="$OUT/results.md"
mkdir -p "$WORK"

now() { date +%s.%N; }
since() { python3 -c "import sys; print(f'{float(sys.argv[2]) - float(sys.argv[1]):.2f}')" "$1" "$(now)"; }
say() { echo "$*" | tee -a "$RESULTS"; }

# The token goes in a header read from a file descriptor, so it is on no command line and in no
# process listing.
api() {
    local method="$1" path="$2"; shift 2
    curl -sS -X "$method" -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" -H @<(printf 'Authorization: Bearer %s\n' "$TOKEN") \
        "$@" "https://api.github.com$path"
}
repo_kb() { api GET "/repos/$REPO" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("size","?"))'; }

# ---- the repository: empty, or this script's own --------------------------------------------

refuse() { echo "refusing: $*; name a scratch repository that holds nothing else" >&2; exit 2; }

# Both URLs name <owner>/<repo> itself, so the repository the guard reads is the one written to,
# and the one the release steps write to through the API.
lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
names_repo() {
    local u r
    u="$(lower "$1")"; u="${u%.git}"; r="$(lower "$REPO")"
    case "$u" in
        "https://github.com/$r"|"git@github.com:$r"|"ssh://git@github.com/$r") return 0 ;;
    esac
    return 1
}
names_repo "$PUSH_URL" || refuse "--push-url $PUSH_URL is not $REPO on github.com"
names_repo "$CLONE_URL" || refuse "--clone-url $CLONE_URL is not $REPO on github.com"

# No branch but `main`, and no release this script did not make.
heads=$(git ls-remote --heads "$PUSH_URL" | awk '{print $2}')
for h in $heads; do
    [ "$h" = "refs/heads/main" ] || refuse "$REPO has the branch ${h#refs/heads/}"
done
page=1
while :; do
    # `<count> <tags this script did not make>`, or `?<why>` where the page could not be read.
    got=$(api GET "/repos/$REPO/releases?per_page=100&page=$page" | python3 -c '
import json, sys
r = json.load(sys.stdin)
if not isinstance(r, list):
    print("?" + str(r.get("message", "an answer that is not a list")))
else:
    print(len(r), " ".join(x["tag_name"] for x in r if not x["tag_name"].startswith("spike-")))
')
    case "$got" in
        '?'*) refuse "the releases of $REPO could not be listed: ${got#?}" ;;
    esac
    others="${got#* }"
    [ -z "${others// /}" ] || refuse "$REPO has releases this script did not make: $others"
    [ "${got%% *}" -lt 100 ] && break
    page=$(( page + 1 ))
done

SPIKE_LINE="Synthetic records written by scripts/evidence-spike.sh. Nothing here is signed."
PUSHER="$WORK/pusher"
rm -rf "$PUSHER"
git clone --quiet "$PUSH_URL" "$PUSHER"
git -C "$PUSHER" config user.name "trigon spike"
git -C "$PUSHER" config user.email "spike@trigon.invalid"
git -C "$PUSHER" config commit.gpgSign false
if git -C "$PUSHER" rev-parse --verify --quiet HEAD >/dev/null; then
    [ "$(git -C "$PUSHER" rev-parse --abbrev-ref HEAD)" = main ] \
        || refuse "$REPO's default branch is not main"
    [ "$(head -n 1 "$PUSHER/SPIKE.md" 2>/dev/null)" = "$SPIKE_LINE" ] \
        || refuse "$REPO is not empty, and holds no SPIKE.md from an earlier run of this script"
    stray=$(git -C "$PUSHER" ls-files | cut -d/ -f1 | sort -u \
        | grep -vxE 'SPIKE\.md|keys|log|records|index' || true)
    [ -z "$stray" ] || refuse "$REPO holds files this script does not write: $(echo $stray)"
else
    git -C "$PUSHER" switch --quiet --orphan main
fi

{
    echo "# Evidence repository spike, $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo
    echo "- repository: $REPO; pushed over $PUSH_URL, cloned from $CLONE_URL"
    echo "- git $(git --version | cut -d' ' -f3); $(uname -sr)"
    echo "- records: $RECORDS; publication-sized commit: $COMMIT_FILES files; growth batch: $BATCH records"
    echo
} >> "$RESULTS"

# Synthetic files: records `from`..`to`-1, each a record file, five index files, and its leaf in
# the entry bundles and hash tiles the log would have.
generate() {
    python3 - "$PUSHER" "$1" "$2" <<'PY'
import base64, hashlib, json, os, sys
root, start, end = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
def put(path, data):
    full = os.path.join(root, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "wb") as f:
        f.write(data)
def fan(hexd):
    return f"{hexd[:2]}/{hexd[2:4]}/{hexd}"
leaves = {}
for n in range(start, end):
    subject = hashlib.sha256(f"artifact {n}".encode()).hexdigest()
    body = json.dumps({"_type": "https://in-toto.io/Statement/v1",
                       "subject": [{"name": f"pkg-{n}.tgz", "digest": {"sha256": subject}}],
                       "predicateType": "https://trigon.dev/equivalence/v2",
                       "predicate": {"purl": f"pkg:npm/spike-{n}@1.0.0", "outcome": "normalized",
                                     "notes": ["synthetic"] * 120}}).encode()
    envelope = {"payloadType": "application/vnd.in-toto+json",
                "payload": base64.b64encode(body).decode(),
                "signatures": [{"keyid": "0" * 16, "sig": base64.b64encode(os.urandom(64)).decode()}]}
    record = json.dumps({"schema": "trigon.record/v1", "statements": [envelope] * 3}).encode()
    digest = hashlib.sha256(record).hexdigest()
    put(f"records/{fan(digest)}.json", record)
    for kind, key in (("sha256", subject), ("sha512", hashlib.sha512(body).hexdigest()),
                      ("sha1", hashlib.sha1(body).hexdigest()),
                      ("purl1", hashlib.sha256(f"pkg:npm/spike-{n}@1.0.0".encode()).hexdigest()),
                      ("pkg1", hashlib.sha256(f"pkg:npm/spike-{n}".encode()).hexdigest())):
        put(f"index/{kind}/{fan(key)}.json",
            json.dumps({"key": f"{kind}:{key}", "records": [{"record": f"sha256:{digest}", "leaf": n}]}).encode())
    leaf = json.dumps({"kind": "record", "time": 1790467200 + n, "record": f"sha256:{digest}",
                       "subject": {"sha256": subject}, "purl": f"pkg:npm/spike-{n}@1.0.0",
                       "pad": "x" * 380}, separators=(",", ":")).encode()
    leaves[n] = leaf
# Whole bundles and tiles for every 256 leaves this batch completes; a batch is a multiple of 256.
for first in range(start - start % 256, end, 256):
    if first + 256 > end:
        break
    bundle = b"".join(len(leaves.get(i, b"x")).to_bytes(2, "big") + leaves.get(i, b"x")
                      for i in range(first, first + 256))
    # tlog-tiles' path encoding: three-digit groups, every one but the last prefixed `x`.
    t, groups = first // 256, []
    while True:
        groups.insert(0, f"{t % 1000:03d}")
        t //= 1000
        if t == 0:
            break
    name = "/".join(["x" + g for g in groups[:-1]] + [groups[-1]])
    put(f"log/tile/entries/{name}", bundle)
    put(f"log/tile/0/{name}", b"".join(hashlib.sha256(b"\0" + leaves.get(i, b"x")).digest()
                                       for i in range(first, first + 256)))
put("log/checkpoint", f"spike\n{end}\n{base64.b64encode(os.urandom(32)).decode()}\n".encode())
PY
}

commit_and_push() {
    local message="$1" t
    git -C "$PUSHER" add --all
    git -C "$PUSHER" commit --quiet -m "$message"
    t=$(now)
    git -C "$PUSHER" push --quiet origin main
    since "$t"
}

if [ ! -f "$PUSHER/SPIKE.md" ]; then
    mkdir -p "$PUSHER/keys"
    printf 'spike+00000000+%s\n' "$(head -c 33 /dev/urandom | base64)" > "$PUSHER/keys/log.vkey"
    printf '%s\n' "$SPIKE_LINE" > "$PUSHER/SPIKE.md"
    commit_and_push "spike: begin" >/dev/null
fi
have=$(git -C "$PUSHER" ls-files records | wc -l | tr -d ' ')

# A publication-sized commit of --commit-files record files, pushed: how long the push took.
publication() {
    python3 - "$PUSHER" "$COMMIT_FILES" "$1" <<'PY'
import os, sys, hashlib
root, n, label = sys.argv[1], int(sys.argv[2]), sys.argv[3]
for k in range(n):
    h = hashlib.sha256(f"publication {label} file {k}".encode()).hexdigest()
    path = os.path.join(root, "records", h[:2], h[2:4], h + ".json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write('{"synthetic": true, "pad": "' + "x" * 9000 + '"}')
PY
    commit_and_push "spike: publication $1, $COMMIT_FILES files"
}

# The consumer's update of the clone at $1, as docs/19 §6 has it: never a pull.
fetch_into() {
    local t
    t=$(now)
    git -C "$1" fetch --quiet --depth 1 origin main
    git -C "$1" reset --quiet --hard FETCH_HEAD
    since "$t"
}

# ---- growth, and the consumer clone at each size ---------------------------------------------

say "## Growth, and the consumer's clone and fetch at each size"
say
say "| records | batch push (s) | files in batch | clone (s) | clone on disk | publication push (s) | fetch + reset (s) | repository size (KB) |"
say "|---|---|---|---|---|---|---|---|"
for target in $RECORDS; do
    while [ "$have" -lt "$target" ]; do
        step=$(( target - have < BATCH ? target - have : BATCH ))
        step=$(( (step + 255) / 256 * 256 ))
        generate "$have" "$(( have + step ))"
        files=$(git -C "$PUSHER" status --porcelain --untracked-files=all | wc -l | tr -d ' ')
        pushed=$(commit_and_push "spike: records $have..$(( have + step ))")
        have=$(( have + step ))
        echo "  pushed $step records ($files files) in ${pushed}s" >&2
        last_push="$pushed"; last_files="$files"
        sleep 11
    done
    clone="$WORK/clone-$target"
    rm -rf "$clone"
    t=$(now)
    git clone --quiet --depth 1 --filter=blob:none --sparse "$CLONE_URL" "$clone"
    git -C "$clone" sparse-checkout set keys log records
    took=$(since "$t")
    disk=$(du -sh "$clone" | cut -f1)
    # One publication at this size, and the fetch that brings this size's clone up to it.
    sleep 11
    pushed=$(publication "at-$have")
    fetched=$(fetch_into "$clone")
    say "| $have | ${last_push:-} | ${last_files:-} | $took | $disk | $pushed | $fetched | $(repo_kb) |"
    sleep 11
done
say

# ---- publication-sized commits: push, then the consumer's fetch ------------------------------

say "## Publication-sized commits in a row: push, and the largest clone's fetch"
say
say "| push | files | push (s) | fetch + reset (s) |"
say "|---|---|---|---|"
clone="$WORK/clone-$(echo "$RECORDS" | awk '{print $NF}')"
for i in $(seq 1 "$PUSHES"); do
    pushed=$(publication "$i")
    fetched=$(fetch_into "$clone")
    say "| $i | $COMMIT_FILES | $pushed | $fetched |"
    # GitHub advises at most 6 pushes a minute to one repository.
    sleep 11
done
say

# ---- unauthenticated git reads ---------------------------------------------------------------

say "## Unauthenticated git reads, above GitHub's advice of about 15 a second"
say
# No credential: no helper, no askpass and no prompt, so GitHub sees an anonymous reader. Every
# fourth read is a shallow, blobless fetch into an empty repository of its own — a consumer's
# first clone — and the rest are `ls-remote`, the read every fetch begins with.
anon() {
    GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=true git -c credential.helper= -c core.askPass=true "$@"
}
reads="$WORK/reads"
rm -rf "$reads"
mkdir -p "$reads"
interval=$(python3 -c "print(1 / $GIT_RATE)")
t=$(now)
for i in $(seq 1 "$GIT_READS"); do
    if [ $(( i % 4 )) -eq 0 ]; then
        (
            git init --quiet --bare "$reads/f$i.git"
            anon -C "$reads/f$i.git" fetch --quiet --depth 1 --filter=blob:none "$CLONE_URL" \
                main 2>"$reads/$i.err"
            echo $? > "$reads/$i.rc"
        ) &
    else
        (
            anon ls-remote "$CLONE_URL" refs/heads/main >/dev/null 2>"$reads/$i.err"
            echo $? > "$reads/$i.rc"
        ) &
    fi
    sleep "$interval"
done
wait
elapsed=$(since "$t")
answered=$(grep -lx 0 "$reads"/*.rc 2>/dev/null | wc -l | tr -d ' ')
say "- $GIT_READS reads of $CLONE_URL, started $GIT_RATE a second, over ${elapsed}s: $answered answered, $(( GIT_READS - answered )) did not"
if [ "$answered" -lt "$GIT_READS" ]; then
    say "- what those that did not answer said, most often first: $(cat "$reads"/*.err | sort | uniq -c | sort -rn | head -5 | tr -s ' \n' ' ')"
fi
say

# ---- release assets --------------------------------------------------------------------------

say "## Release assets"
say
tag="spike-$(date -u +%Y%m%d%H%M%S)"
release=$(api POST "/repos/$REPO/releases" -d "{\"tag_name\":\"$tag\",\"name\":\"$tag\",\"draft\":false,\"prerelease\":true,\"make_latest\":\"false\"}")
release_id=$(printf '%s' "$release" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
upload() {
    local name="$1" file="$2"
    curl -sS -o /dev/null -w '%{http_code} %{time_total}' -X POST \
        -H "Content-Type: application/octet-stream" \
        -H @<(printf 'Authorization: Bearer %s\n' "$TOKEN") \
        --data-binary "@$file" \
        "https://uploads.github.com/repos/$REPO/releases/$release_id/assets?name=$name"
}
small="$WORK/small.bin"; head -c 65536 /dev/urandom > "$small"
total=0; worst=0; codes=""
for i in $(seq 1 "$ASSETS"); do
    read -r code secs < <(upload "sha256-$(printf '%064x' "$i")" "$small")
    codes="$codes $code"
    total=$(python3 -c "print($total + $secs)")
    worst=$(python3 -c "print(max($worst, $secs))")
done
say "- $ASSETS assets of 64 KiB: $(python3 -c "print(f'{$total / $ASSETS:.2f}')")s each on average, ${worst}s at worst; status codes:$(printf '%s\n' $codes | sort | uniq -c | tr '\n' ' ')"
large="$WORK/large.bin"; head -c $(( LARGE_MIB * 1048576 )) /dev/urandom > "$large"
read -r code secs < <(upload "sha256-large" "$large")
say "- one asset of $LARGE_MIB MiB: HTTP $code in ${secs}s"
t=$(now)
listed=0; page=1
while :; do
    n=$(api GET "/repos/$REPO/releases/$release_id/assets?per_page=100&page=$page" \
        | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')
    listed=$(( listed + n ))
    [ "$n" -lt 100 ] && break
    page=$(( page + 1 ))
done
say "- listing $listed assets: $(since "$t")s"
if [ "$PROBE" = 1 ]; then
    for i in $(seq "$(( ASSETS + 2 ))" 1000); do
        upload "sha256-$(printf '%064x' "$i")" "$small" >/dev/null
    done
    read -r code secs < <(upload "sha256-$(printf '%064x' 1001)" "$small")
    say "- the 1,001st asset of one release: HTTP $code"
fi
say

# ---- limits ----------------------------------------------------------------------------------

say "## Rate limits after the run"
say
api GET "/rate_limit" | python3 -c '
import json, sys
r = json.load(sys.stdin)["resources"]
for k in ("core", "search", "graphql"):
    v = r.get(k, {})
    print(f"- {k}: {v.get(\"remaining\")} of {v.get(\"limit\")} remaining")
' | tee -a "$RESULTS"
say
say "Repository size at the end: $(repo_kb) KB, as GitHub reports it."
echo "results: $RESULTS" >&2
