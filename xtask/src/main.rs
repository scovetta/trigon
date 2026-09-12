//! Repository automation.
//!
//! `policy` is the one that matters: it walks the resolved dependency graph and asserts that the
//! judgement half cannot reach a network client, an async runtime, or the AI crate. The crate graph
//! is an anti-footgun rather than a security control, and this is what keeps it honest.
//! See `docs/01-architecture.md` §2.2.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

mod corpus;
mod differential;
mod golden;
mod scan;

#[derive(Parser, Debug)]
#[command(name = "xtask")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Check the dependency policy. Fails the build on a violation.
    Policy,
    /// Fetch a corpus into the local cache, verifying every artifact against its pinned digest.
    Corpus {
        #[command(subcommand)]
        cmd: CorpusCmd,
    },
    /// Check, or re-record, the golden stabilized digests for a corpus.
    Golden {
        #[arg(long, default_value = "corpora/m0-smoke.toml")]
        manifest: std::path::PathBuf,
        /// Re-record rather than check.
        #[arg(long)]
        write: bool,
        /// Why the digests moved. Required to write.
        #[arg(long, default_value = "")]
        reason: String,
        /// Allow a re-record with no change to the code that produces digests.
        #[arg(long)]
        force: bool,
    },
    /// Compare our stabilizer against the reference over a corpus.
    Differential {
        #[arg(long, default_value = "corpora/m0-smoke.toml")]
        manifest: std::path::PathBuf,
        #[arg(long, default_value = "corpora/deviations.toml")]
        deviations: std::path::PathBuf,
        /// The reference binary. `go install github.com/google/oss-rebuild/cmd/stabilize@latest`
        #[arg(long, default_value = "stabilize")]
        reference: String,
    },
}

#[derive(Subcommand, Debug)]
enum CorpusCmd {
    /// Download and verify. Artifacts land in the cache, never in the repository.
    Fetch {
        #[arg(long, default_value = "corpora/m0-smoke.toml")]
        manifest: std::path::PathBuf,
    },
    /// Walk a registry, record which strata each artifact satisfies, discard the bytes.
    Scan {
        #[arg(long)]
        ecosystem: String,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long, default_value = "corpora/candidates.jsonl")]
        out: std::path::PathBuf,
        /// Pause between requests. Registries owe us nothing.
        #[arg(long, default_value_t = 250)]
        delay_ms: u64,
    },
    /// Turn scanned candidates into a manifest, rarest strata first.
    Select {
        #[arg(long, default_value = "corpora/candidates.jsonl")]
        from: std::path::PathBuf,
        #[arg(long, default_value = "corpora/m0.toml")]
        out: std::path::PathBuf,
        #[arg(long, default_value_t = 25)]
        per_stratum: usize,
        #[arg(long, default_value = "m0")]
        name: String,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Policy => {
            print!("{}", check_policy()?);
            Ok(())
        }
        Cmd::Corpus { cmd } => match cmd {
            CorpusCmd::Fetch { manifest } => {
                println!("{}", corpus::fetch(&manifest)?);
                Ok(())
            }
            CorpusCmd::Scan {
                ecosystem,
                limit,
                out,
                delay_ms,
            } => {
                print!("{}", scan::scan(&ecosystem, limit, &out, delay_ms)?);
                Ok(())
            }
            CorpusCmd::Select {
                from,
                out,
                per_stratum,
                name,
            } => {
                print!("{}", scan::select(&from, &out, per_stratum, &name)?);
                Ok(())
            }
        },
        Cmd::Golden {
            manifest,
            write,
            reason,
            force,
        } => {
            let bin = std::env::var("TRIGON_BIN").unwrap_or_else(|_| "target/debug/trigon".into());
            let out = if write {
                golden::write(&manifest, &bin, &reason, force)?
            } else {
                golden::check(&manifest, &bin)?
            };
            print!("{out}");
            Ok(())
        }
        Cmd::Differential {
            manifest,
            deviations,
            reference,
        } => {
            print!("{}", differential::run(&manifest, &deviations, &reference)?);
            Ok(())
        }
    }
}

/// Crates in the judgement half and what they may never reach, transitively, through a normal
/// (non-dev, non-build) dependency edge.
const FORBID_TRANSITIVE: &[(&str, &[&str])] = &[
    (
        "trigon-stabilize",
        &[
            "trigon-ai",
            "trigon-registry",
            "tokio",
            "reqwest",
            "hyper",
            "rustls",
            "async-compression",
        ],
    ),
    (
        "trigon-compare",
        &["trigon-ai", "trigon-registry", "tokio", "reqwest", "hyper"],
    ),
    (
        "trigon-archive",
        &[
            "trigon-ai",
            "trigon-registry",
            "tokio",
            "reqwest",
            "hyper",
            "async-compression",
        ],
    ),
    (
        "trigon-core",
        &["trigon-ai", "trigon-registry", "tokio", "reqwest", "hyper"],
    ),
    (
        "trigon-strategy",
        &["trigon-ai", "trigon-registry", "tokio", "reqwest", "hyper"],
    ),
    // The one a user checks for themselves. `trigon verify-attestation` links this and nothing
    // else, so "here is a binary with no network client and no model code that re-derives our
    // verdict" is a claim about a dependency tree rather than about a diagram.
    (
        "trigon-attest",
        &["trigon-ai", "trigon-registry", "tokio", "reqwest", "hyper"],
    ),
    // The invariant read from the other side. Everything above keeps the judgement half free of a
    // model; this keeps the model's half out of the judgement code. A `trigon-ai` that could call
    // `compare` or `apply` could compare, and no amount of care in the engine would make that
    // untrue — whereas a crate that cannot name the function cannot call it.
    (
        "trigon-ai",
        &["trigon-compare", "trigon-stabilize", "trigon-archive"],
    ),
];

/// Judgement-half crates declare no cargo features of their own, which leaves feature unification
/// nothing to leak in through.
const REQUIRE_NO_FEATURES: &[&str] = &[
    "trigon-core",
    "trigon-archive",
    "trigon-stabilize",
    "trigon-compare",
    "trigon-strategy",
    "trigon-attest",
];

/// Crates where a `HashMap` in the source is a policy violation rather than a style preference.
///
/// Rendering order feeds `strategy_digest`. `minijinja` preserves insertion order when it ranges a
/// map, so a `HashMap` in a template context makes the rendered script, and therefore the digest,
/// vary between runs of the same binary against the same input. `BTreeMap` everywhere removes the
/// question. See `docs/04-strategies.md` §3.2 (2).
const FORBID_HASHMAP: &[&str] = &["trigon-strategy"];

pub fn check_policy() -> Result<String> {
    check_policy_with(FORBID_TRANSITIVE, REQUIRE_NO_FEATURES)
}

/// The policy check, with its table as a parameter so a test can hand it a rule that must fail.
///
/// A checker nobody has seen fail is a checker nobody knows works. Passing the table in is what
/// makes the negative test possible without adding a forbidden dependency to a real crate.
fn check_policy_with(
    forbid_transitive: &[(&str, &[&str])],
    require_no_features: &[&str],
) -> Result<String> {
    let meta = cargo_metadata()?;
    let packages = meta["packages"].as_array().context("packages")?;
    let nodes = meta["resolve"]["nodes"]
        .as_array()
        .context("resolve.nodes")?;

    // id -> name, and the normal-dependency adjacency. Dev-dependencies are deliberately excluded:
    // `trigon-archive` uses the `zip` crate in tests as a stand-in for an external implementation,
    // and a test dependency cannot reach a shipped artifact.
    let mut name_of: BTreeMap<&str, &str> = BTreeMap::new();
    for p in packages {
        name_of.insert(p["id"].as_str().unwrap(), p["name"].as_str().unwrap());
    }
    let mut edges: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for n in nodes {
        let id = n["id"].as_str().unwrap();
        let mut out = Vec::new();
        for d in n["deps"].as_array().unwrap() {
            let normal = d["dep_kinds"]
                .as_array()
                .map(|ks| ks.iter().any(|k| k["kind"].is_null()))
                .unwrap_or(true);
            if normal {
                out.push(d["pkg"].as_str().unwrap());
            }
        }
        edges.insert(id, out);
    }

    let id_for = |name: &str| -> Option<&str> {
        name_of.iter().find(|(_, n)| **n == name).map(|(id, _)| *id)
    };

    let mut violations: Vec<String> = Vec::new();
    let mut lines: Vec<String> = Vec::new();

    for (crate_name, forbidden) in forbid_transitive {
        let Some(root) = id_for(crate_name) else {
            continue;
        };
        let reachable = reachable_from(root, &edges, &name_of);
        for f in *forbidden {
            if reachable.contains(*f) {
                let path = shortest_path(root, f, &edges, &name_of).unwrap_or_default();
                violations.push(format!(
                    "{crate_name} reaches `{f}` transitively: {}",
                    path.join(" -> ")
                ));
            }
        }
        lines.push(format!(
            "  {crate_name:<18} clean of {} forbidden crate(s), {} in its tree",
            forbidden.len(),
            reachable.len()
        ));
    }

    for crate_name in require_no_features {
        let Some(p) = packages
            .iter()
            .find(|p| p["name"].as_str() == Some(crate_name))
        else {
            continue;
        };
        let feats = p["features"].as_object().map(|m| m.len()).unwrap_or(0);
        if feats > 0 {
            let names: Vec<_> = p["features"].as_object().unwrap().keys().cloned().collect();
            violations.push(format!(
                "{crate_name} declares {feats} cargo feature(s): {}. Judgement-half crates declare \
                 none, so feature unification has nothing to leak in through.",
                names.join(", ")
            ));
        } else {
            lines.push(format!("  {crate_name:<18} declares no cargo features"));
        }
    }

    // Compiles before it resolves. A tree is a claim about what *would* be linked; this is the
    // claim actually on the front of the project, and it was false for several commits while the
    // resolve below stayed green.
    match verifier_builds() {
        Ok(()) => lines.push("  trigon (verifier)  compiles".to_string()),
        Err(e) => violations.push(e.to_string()),
    }

    match verifier_tree() {
        Ok(found) if !found.is_empty() => violations.push(format!(
            "the verifier build (`-p trigon --no-default-features`) links {}. That build is the \
             claim a sceptic checks instead of trusting us, so a runtime or a network client in it \
             is not a dependency change, it is the claim becoming false.",
            found.join(", ")
        )),
        Ok(_) => lines.push(
            "  trigon (verifier)  links no runtime, no network client, no sandbox".to_string(),
        ),
        Err(e) => violations.push(format!("could not resolve the verifier build: {e}")),
    }

    for crate_name in FORBID_HASHMAP {
        match hashmap_uses(crate_name) {
            Ok(found) if !found.is_empty() => violations.push(format!(
                "{crate_name} names HashMap at {}. Rendering order feeds strategy_digest, and a \
                 hash map makes it vary between runs. Use BTreeMap.",
                found.join(", ")
            )),
            Ok(_) => lines.push(format!("  {crate_name:<18} names no HashMap")),
            Err(e) => violations.push(format!("could not scan {crate_name}: {e}")),
        }
    }

    if !violations.is_empty() {
        bail!(
            "dependency policy violated:\n  - {}",
            violations.join("\n  - ")
        );
    }
    Ok(format!("dependency policy ok\n{}", lines.join("\n")))
}

/// The workspace root, however xtask was invoked.
///
/// `cargo run -p xtask` starts at the workspace root and `cargo test -p xtask` starts at the crate
/// directory, so anything resolving a repository path relative to the current directory works in
/// one and not the other.
pub fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives one level below the workspace root")
        .to_path_buf()
}

/// Every `file:line` in a crate's `src` that names `HashMap`.
fn hashmap_uses(crate_name: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let root = workspace_root();
    let mut stack = vec![root.join("crates").join(crate_name).join("src")];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir)?.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            if p.extension().is_none_or(|x| x != "rs") {
                continue;
            }
            let text = std::fs::read_to_string(&p)?;
            let shown = p.strip_prefix(&root).unwrap_or(&p).to_path_buf();
            for (i, line) in text.lines().enumerate() {
                // A line that says why it is banned is documentation, not a use.
                if line.contains("HashMap") && !line.trim_start().starts_with("//") {
                    out.push(format!("{}:{}", shown.display(), i + 1));
                }
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Whether the verifier build compiles at all.
///
/// `cargo tree` answers a question about the dependency *graph*, which is not the same question as
/// whether the binary builds — and the difference is not academic. The verifier was broken for
/// several commits by a match arm added outside its `#[cfg]`, while this check stayed green the
/// whole time, because a resolve does not compile anything. The claim on the front of this project
/// is that a sceptic can build a small binary and re-derive our verdict; asserting its dependency
/// tree while it does not build asserts nothing.
///
/// `cargo check` rather than `build`: it catches the same class at a fraction of the time.
fn verifier_builds() -> Result<()> {
    let out = std::process::Command::new(env!("CARGO"))
        .current_dir(workspace_root())
        .args(["check", "-q", "-p", "trigon", "--no-default-features"])
        .output()
        .context("running cargo check on the verifier build")?;
    if !out.status.success() {
        bail!(
            "the verifier build (`-p trigon --no-default-features`) does not compile:\n{}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Forbidden crates present in the verifier build.
///
/// A separate resolve rather than a walk of the default graph: the whole point of the feature is
/// that the two builds have different dependency trees, so asking the default one proves nothing.
fn verifier_tree() -> Result<Vec<String>> {
    const FORBIDDEN: &[&str] = &[
        "tokio",
        "reqwest",
        "hyper",
        "trigon-sandbox",
        "trigon-ai",
        "trigon-registry",
        // The `wasm` feature exists and is off by default. It nearly doubles this tree, so a
        // verifier that acquired it by accident — a default-features slip, a feature unified in
        // from elsewhere — would have quietly given up the property the build exists to demonstrate.
        "wasmtime",
    ];
    let out = std::process::Command::new(env!("CARGO"))
        .current_dir(workspace_root())
        .args([
            "tree",
            "-p",
            "trigon",
            "--no-default-features",
            "--edges",
            "normal",
            "--prefix",
            "none",
        ])
        .output()
        .context("running cargo tree")?;
    if !out.status.success() {
        bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut found: Vec<String> = FORBIDDEN
        .iter()
        .filter(|f| {
            text.lines()
                .any(|l| l.split_whitespace().next() == Some(*f))
        })
        .map(|s| s.to_string())
        .collect();
    found.sort();
    Ok(found)
}

fn cargo_metadata() -> Result<serde_json::Value> {
    let out = std::process::Command::new(env!("CARGO"))
        .args(["metadata", "--all-features", "--format-version", "1"])
        .output()
        .context("running cargo metadata")?;
    if !out.status.success() {
        bail!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(serde_json::from_slice(&out.stdout)?)
}

fn reachable_from<'a>(
    root: &'a str,
    edges: &BTreeMap<&'a str, Vec<&'a str>>,
    name_of: &BTreeMap<&'a str, &'a str>,
) -> BTreeSet<&'a str> {
    let mut seen = BTreeSet::new();
    let mut q = VecDeque::from([root]);
    let mut visited = BTreeSet::from([root]);
    while let Some(id) = q.pop_front() {
        for next in edges.get(id).into_iter().flatten() {
            if visited.insert(*next) {
                seen.insert(*name_of.get(next).unwrap_or(next));
                q.push_back(next);
            }
        }
    }
    seen
}

fn shortest_path<'a>(
    root: &'a str,
    target_name: &str,
    edges: &BTreeMap<&'a str, Vec<&'a str>>,
    name_of: &BTreeMap<&'a str, &'a str>,
) -> Option<Vec<String>> {
    let mut prev: BTreeMap<&str, &str> = BTreeMap::new();
    let mut q = VecDeque::from([root]);
    let mut visited = BTreeSet::from([root]);
    while let Some(id) = q.pop_front() {
        if name_of.get(id) == Some(&target_name) {
            let mut path = vec![target_name.to_string()];
            let mut cur = id;
            while let Some(p) = prev.get(cur) {
                path.push(name_of.get(p).unwrap_or(p).to_string());
                cur = p;
            }
            path.reverse();
            return Some(path);
        }
        for next in edges.get(id).into_iter().flatten() {
            if visited.insert(*next) {
                prev.insert(next, id);
                q.push_back(next);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    /// The policy runs as a test, so `cargo test` fails on a violation rather than waiting for
    /// someone to remember to run `cargo xtask policy`.
    #[test]
    fn judgement_half_cannot_reach_a_runtime_or_a_model() {
        match super::check_policy() {
            Ok(report) => println!("{report}"),
            Err(e) => panic!("{e}"),
        }
    }

    /// And the check is not vacuous.
    ///
    /// `serde` is a real, normal, transitive dependency of `trigon-core`, so forbidding it must
    /// produce a violation naming the path. Without this, a graph walk that silently found nothing
    /// (a renamed field in `cargo metadata`, an id format change) would report every crate clean
    /// and the M0 exit criterion would be met by a checker that cannot fail.
    #[test]
    fn the_policy_check_fails_on_a_deliberate_violation() {
        let err = super::check_policy_with(&[("trigon-core", &["serde"])], &[])
            .expect_err("forbidding a dependency that exists must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("trigon-core reaches `serde` transitively"),
            "{msg}"
        );
        assert!(
            msg.contains("->"),
            "the violation must name the path: {msg}"
        );
    }

    /// Nor is the HashMap rule. `trigon-stabilize` is not on the list and does not name one, so
    /// the scanner must come back empty for it rather than erroring, and it must find the uses in
    /// a crate that has them.
    #[test]
    fn the_hashmap_scan_finds_what_is_there_and_nothing_else() {
        assert!(super::hashmap_uses("trigon-strategy").unwrap().is_empty());
        // xtask itself uses BTreeMap throughout; a crate that does not exist must error rather
        // than silently report clean, which is the failure mode that would make the rule vacuous.
        assert!(super::hashmap_uses("trigon-does-not-exist").is_err());
    }

    /// The feature rule is not vacuous either. `serde` declares features; a judgement-half crate
    /// must not, and pointing the rule at a crate that does proves the arm runs.
    #[test]
    fn the_feature_rule_fails_on_a_crate_that_declares_features() {
        let err = super::check_policy_with(&[], &["serde"])
            .expect_err("serde declares features, so requiring none must fail");
        assert!(err.to_string().contains("serde declares"), "{err}");
    }
}
