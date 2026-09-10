# Fuzzing

Three targets, all over attacker-controlled bytes. `parse` is the one that matters most: every
artifact we handle arrives from a registry and none of it is trusted.

| Target | Property |
|---|---|
| `parse` | Parsing does not panic, and respects its limits. |
| `roundtrip` | `write(parse(write(a))) == write(a)`. A counterexample is a case where a signed digest is a coin flip. |
| `stabilize` | Stabilizers are total and idempotent, and a second pass over stabilized bytes reports no work. |

## Running

Needs nightly and `cargo-fuzz`:

```
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked
```

Seed from real artifacts before running. A fuzzer starting from random bytes spends its budget
learning what a tar header looks like; one starting from valid archives reaches the interesting code
in seconds. The M0 corpus cache is the seed source:

```
xtask corpus fetch --manifest corpora/m0.toml
mkdir -p fuzz/corpus/parse
find ~/.cache/trigon/corpora/m0 -size -400k -type f -exec cp {} fuzz/corpus/parse/ \;
cp fuzz/corpus/parse/* fuzz/corpus/roundtrip/
cp fuzz/corpus/parse/* fuzz/corpus/stabilize/

cargo +nightly fuzz run parse -- -max_total_time=300 -rss_limit_mb=4096
```

`fuzz/corpus` is not committed. It is derived from the pinned corpus by the commands above, and
checking in a megabyte of registry artifacts to reproduce something reproducible is not worth it.
A crashing input found by a run **is** committed, as a unit test in the crate it breaks rather than
as an opaque blob under `fuzz/artifacts`.

## Where it stands

Five minutes per target, seeded as above, on the 58-artifact M0 corpus: about 62,000 runs across the
three, no crashes and no property violations. That is an exit criterion met, not a claim that the
parser is safe; the useful version of this runs for hours in CI on a schedule.
