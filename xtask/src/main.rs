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
mod signature;

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
            "tokio",
            "reqwest",
            "hyper",
            "rustls",
            "async-compression",
        ],
    ),
    (
        "trigon-compare",
        &["trigon-ai", "tokio", "reqwest", "hyper"],
    ),
    (
        "trigon-archive",
        &[
            "trigon-ai",
            "tokio",
            "reqwest",
            "hyper",
            "async-compression",
        ],
    ),
    ("trigon-core", &["trigon-ai", "tokio", "reqwest", "hyper"]),
];

/// Judgement-half crates declare no cargo features of their own, which leaves feature unification
/// nothing to leak in through.
const REQUIRE_NO_FEATURES: &[&str] = &[
    "trigon-core",
    "trigon-archive",
    "trigon-stabilize",
    "trigon-compare",
];

pub fn check_policy() -> Result<String> {
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

    for (crate_name, forbidden) in FORBID_TRANSITIVE {
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

    for crate_name in REQUIRE_NO_FEATURES {
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

    if !violations.is_empty() {
        bail!(
            "dependency policy violated:\n  - {}",
            violations.join("\n  - ")
        );
    }
    Ok(format!("dependency policy ok\n{}", lines.join("\n")))
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
}
