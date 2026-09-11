//! Naming a build failure in a way that generalizes across the packages that share it.
//!
//! Three things in the design need this one value, which is why it is a type rather than a helper
//! buried in the agent:
//!
//! 1. **The repair cache key** (`docs/07-ai.md` §4.1). "setuptools omits the PKG-INFO trailing
//!    newline before version X" is *one* repair covering thousands of packages. Key the cache on
//!    the target and every sibling misses; key it on the signature and the first repair pays for
//!    all of them. This is the difference between a $4,000 sweep and a $168,000 one.
//! 2. **Admission control** (§4.3). We enter the repair loop only when the signature is *novel*. A
//!    signature already known unfixable short-circuits to a verdict at zero model spend, and a
//!    repeated signature within one run is the stop rule — cheaper and better than counting
//!    iterations.
//! 3. **The failure-cluster view** (`docs/11-interfaces.md` §4). What turns 500 red rows into 12
//!    tickets, which is the operator need that outranks everything else in the UI.
//!
//! So the whole value is in *generalizing*. A signature carrying the package name, the version, a
//! temp path or a hash is a signature that matches one run, and all three uses above collapse. The
//! rules below therefore capture only the part of a message that is a property of the **failure
//! class**, never of the target: the missing header, not the package that needed it.
//!
//! Deterministic, and it stays that way. A model reads the compressed log this module produces; it
//! does not get to decide what the failure was, because the answer keys a cache and gates spend.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::Fault;

/// A build failure, named so that every run sharing the cause shares the name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureSignature {
    /// Stable, `ecosystem/what-happened`. Appears in cache keys, cluster ids and tickets, so it is
    /// treated as a wire value: renaming one splits its cluster in two and orphans its repairs.
    pub code: &'static str,
    /// The part of the message that generalizes, normalized. `Some("Python.h")` for a missing
    /// header — the repair is the same for every package that needs it. Never a package name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub fault: Fault,
    /// Whether running this again unchanged could reach a different answer.
    pub retryable: bool,
    /// Whether a repair attempt has any prospect at all.
    ///
    /// `false` is the admission-control short circuit: a build killed for running out of memory is
    /// not a strategy problem, and a model iterating on it spends money to reach the same place.
    pub repairable: bool,
    /// The line that produced the classification, verbatim and bounded. For a human reading a
    /// cluster, not part of the key.
    pub evidence: String,
}

impl FailureSignature {
    /// The cache and cluster key. Everything that varies per target is already out.
    pub fn key(&self) -> String {
        match &self.subject {
            Some(s) => format!("{}:{s}", self.code),
            None => self.code.to_string(),
        }
    }

    /// The failure we could not name.
    ///
    /// Deliberately one bucket rather than a per-message hash. An unrecognised failure is a gap in
    /// the rule table, and it should show up as one large cluster somebody fixes, not as five
    /// hundred singleton clusters that look like five hundred unrelated problems.
    pub fn unknown(evidence: impl Into<String>) -> Self {
        FailureSignature {
            code: "unknown",
            subject: None,
            fault: Fault::Build,
            retryable: false,
            repairable: true,
            evidence: clip(&evidence.into()),
        }
    }

    pub fn is_unknown(&self) -> bool {
        self.code == "unknown"
    }
}

impl fmt::Display for FailureSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.key())
    }
}

/// How a rule pulls the generalizing part out of a matched line.
#[derive(Clone, Copy, Debug)]
enum Capture {
    /// Nothing varies within this class that is worth keying on.
    None,
    /// The text between the first `open` after the needle and the next `close`.
    Between(&'static str, &'static str),
    /// The word following `after`, with trailing punctuation trimmed.
    WordAfter(&'static str),
    /// The token immediately preceding `marker`.
    ///
    /// For messages that name the thing last: a shell says `run.sh: line 3: yarn: command not
    /// found`, where every candidate delimiter before the tool name is also a delimiter inside the
    /// shell's own preamble. Reading backwards from the marker is the only stable anchor.
    WordBefore(&'static str),
}

struct Rule {
    code: &'static str,
    /// Every needle must appear in the same line. Substrings, not patterns: a regex table is a
    /// dependency and a performance cliff on logs this size, and nothing here needs one.
    needles: &'static [&'static str],
    fault: Fault,
    retryable: bool,
    repairable: bool,
    capture: Capture,
}

/// The taxonomy.
///
/// Ordered, first match wins, so the specific rules come before the general ones. Several of these
/// are here because they actually happened while building this system, which is the only reason to
/// trust a taxonomy at all: `node:path` was a Node too old for the strategy, `python3-venv` was a
/// Debian package split, `wheel` was pip running without build isolation.
const RULES: &[Rule] = &[
    // ---- our own environment, not the package's fault -----------------------------------------
    Rule {
        code: "env/missing-tool",
        needles: &["command not found"],
        fault: Fault::Bug,
        retryable: false,
        repairable: true,
        capture: Capture::WordBefore(": command not found"),
    },
    Rule {
        code: "env/node-too-old",
        needles: &["Cannot find module 'node:"],
        fault: Fault::Bug,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        code: "env/missing-venv",
        needles: &["ensurepip is not available"],
        fault: Fault::Bug,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        code: "env/no-ca-certificates",
        needles: &["server certificate verification failed"],
        fault: Fault::Bug,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        code: "env/out-of-memory",
        needles: &["Killed"],
        fault: Fault::Infra,
        retryable: true,
        // Not a strategy problem. A model iterating here spends money to reach the same place.
        repairable: false,
        capture: Capture::None,
    },
    Rule {
        code: "env/out-of-memory",
        needles: &["JavaScript heap out of memory"],
        fault: Fault::Infra,
        retryable: true,
        repairable: false,
        capture: Capture::None,
    },
    Rule {
        code: "env/no-space",
        needles: &["No space left on device"],
        fault: Fault::Infra,
        retryable: true,
        repairable: false,
        capture: Capture::None,
    },
    // ---- the network, and what a denied egress tier looks like from inside ---------------------
    Rule {
        code: "net/unreachable",
        needles: &["Temporary failure in name resolution"],
        fault: Fault::Policy,
        retryable: false,
        // Under `--egress mirror-only` this is the enforcement working, not a fault to repair. The
        // strategy asked for something the tier does not grant, and the fix is the strategy.
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        code: "net/unreachable",
        needles: &["Could not resolve host"],
        fault: Fault::Policy,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        code: "net/unreachable",
        needles: &["Network is unreachable"],
        fault: Fault::Policy,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        code: "net/registry-5xx",
        needles: &["503 Service Unavailable"],
        fault: Fault::Upstream,
        retryable: true,
        repairable: false,
        capture: Capture::None,
    },
    Rule {
        code: "net/rate-limited",
        needles: &["429 Too Many Requests"],
        fault: Fault::Upstream,
        retryable: true,
        repairable: false,
        capture: Capture::None,
    },
    // ---- npm -----------------------------------------------------------------------------------
    Rule {
        code: "npm/peer-conflict",
        needles: &["ERESOLVE"],
        fault: Fault::Build,
        retryable: false,
        repairable: true,
        // Deliberately uncaptured. Which two packages conflict is a property of the target, and
        // keying on it would give every target its own cluster of one.
        capture: Capture::None,
    },
    Rule {
        code: "npm/version-gone",
        needles: &["notarget No matching version found"],
        fault: Fault::Upstream,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        code: "npm/lifecycle-script",
        needles: &["Failed at the", "script"],
        fault: Fault::Build,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        code: "npm/node-gyp",
        needles: &["gyp ERR!"],
        fault: Fault::Build,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        code: "npm/engine-mismatch",
        needles: &["EBADENGINE"],
        fault: Fault::Build,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    // ---- Python ---------------------------------------------------------------------------------
    Rule {
        code: "pip/no-matching-distribution",
        needles: &["No matching distribution found for"],
        fault: Fault::Upstream,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        code: "pip/unmet-build-dependency",
        needles: &["Unmet dependencies"],
        fault: Fault::Build,
        retryable: false,
        repairable: true,
        capture: Capture::WordAfter("Unmet dependencies:"),
    },
    Rule {
        code: "pip/metadata-generation-failed",
        needles: &["metadata-generation-failed"],
        fault: Fault::Build,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        code: "pip/missing-build-backend",
        needles: &["Cannot import 'setuptools.build_meta'"],
        fault: Fault::Build,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        code: "py/missing-module",
        needles: &["ModuleNotFoundError: No module named"],
        fault: Fault::Build,
        retryable: false,
        repairable: true,
        // Which module *is* the repair, and it is shared: every package needing `cython` needs the
        // same fix.
        capture: Capture::Between("named '", "'"),
    },
    Rule {
        code: "py/syntax-error",
        needles: &["SyntaxError:"],
        fault: Fault::Build,
        retryable: false,
        // Nearly always an interpreter too new or too old for the source, which is a toolchain
        // window the evidence should have pinned.
        repairable: true,
        capture: Capture::None,
    },
    // ---- native toolchains ------------------------------------------------------------------------
    Rule {
        code: "cc/missing-header",
        needles: &["fatal error:", "No such file or directory"],
        fault: Fault::Build,
        retryable: false,
        repairable: true,
        capture: Capture::Between("fatal error: ", ":"),
    },
    Rule {
        code: "cc/missing-compiler",
        needles: &["unable to execute 'cc'"],
        fault: Fault::Bug,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        code: "ld/undefined-symbol",
        needles: &["undefined reference to"],
        fault: Fault::Build,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    // ---- git ---------------------------------------------------------------------------------------
    Rule {
        code: "git/no-such-ref",
        needles: &["did not match any file(s) known to git"],
        fault: Fault::Upstream,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        code: "git/no-such-ref",
        needles: &["Remote branch", "not found in upstream"],
        fault: Fault::Upstream,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
    Rule {
        code: "git/repository-gone",
        needles: &["Repository not found"],
        fault: Fault::Upstream,
        retryable: false,
        repairable: false,
        capture: Capture::None,
    },
    // ---- ours ---------------------------------------------------------------------------------------
    Rule {
        code: "trigon/no-output",
        needles: &["no file matched the output path"],
        fault: Fault::Bug,
        retryable: false,
        repairable: true,
        capture: Capture::None,
    },
];

/// Name the failure in a build log.
///
/// Scans from the end. The last error is almost always the one that stopped the build, and the
/// first is often a tolerated warning from a phase that went on to succeed — the opposite of how a
/// human skims, and right more often.
pub fn classify(log: &str) -> FailureSignature {
    let lines: Vec<&str> = log.lines().collect();
    for line in lines.iter().rev() {
        if let Some(sig) = classify_line(line) {
            return sig;
        }
    }
    FailureSignature::unknown(last_interesting(&lines))
}

fn classify_line(line: &str) -> Option<FailureSignature> {
    let rule = RULES
        .iter()
        .find(|r| r.needles.iter().all(|n| line.contains(n)))?;
    Some(FailureSignature {
        code: rule.code,
        subject: capture(line, rule.capture).map(|s| normalize_subject(&s)),
        fault: rule.fault,
        retryable: rule.retryable,
        repairable: rule.repairable,
        evidence: clip(line.trim()),
    })
}

fn capture(line: &str, how: Capture) -> Option<String> {
    match how {
        Capture::None => None,
        Capture::Between(open, close) => {
            let rest = line.split_once(open)?.1;
            let end = rest.find(close)?;
            Some(rest[..end].to_string())
        }
        Capture::WordBefore(marker) => {
            let head = line.split(marker).next()?;
            head.rsplit([' ', ':'])
                .find(|t| !t.is_empty())
                .map(str::to_string)
        }
        Capture::WordAfter(marker) => {
            line.split_once(marker)?
                .1
                .split_whitespace()
                .next()
                .map(|w| {
                    w.trim_matches(|c: char| !c.is_alphanumeric() && c != '.')
                        .to_string()
                })
        }
    }
}

/// Strip what makes one occurrence different from the next.
///
/// A subject carrying a version, a build id or an absolute path defeats the whole point: the
/// cluster becomes a cluster of one. Paths keep only their last component, and a trailing version
/// goes, because `Python.h` and `libssl-dev` are repairs while `/tmp/pip-build-9k2/Python.h` is a
/// run.
fn normalize_subject(s: &str) -> String {
    let s = s.trim().trim_matches('\'').trim_matches('"');
    let s = s.rsplit('/').next().unwrap_or(s);
    let s = s.split_once("==").map(|(a, _)| a).unwrap_or(s);
    s.trim().to_lowercase()
}

/// The last line that looks like it says something, for a failure we could not name.
///
/// Bounded and stripped of control characters. A build script can print anything, including text
/// shaped like our own output, and this string reaches a model.
fn last_interesting(lines: &[&str]) -> String {
    lines
        .iter()
        .rev()
        .map(|l| l.trim())
        .find(|l| !l.is_empty() && l.len() > 8)
        .unwrap_or("")
        .to_string()
}

fn clip(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_control() || *c == '\t')
        .take(300)
        .collect();
    cleaned.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_generalizes_across_packages_that_share_a_cause() {
        // The property the whole module exists for. Two different packages, one repair.
        let a = classify("gcc: fatal error: Python.h: No such file or directory\ncc failed");
        let b =
            classify("building 'lxml' extension\nfatal error: Python.h: No such file or directory");
        assert_eq!(a.key(), b.key());
        assert_eq!(a.key(), "cc/missing-header:python.h");
    }

    #[test]
    fn a_missing_tool_is_named_by_the_tool_not_by_the_shell_preamble() {
        // A shell prefixes the message with its own script and line number, and every delimiter
        // before the tool name appears in that preamble too. Reading forwards captured `line 3`,
        // which clusters by where the script happened to break rather than by what is missing.
        for line in [
            "/build/run.sh: line 3: yarn: command not found",
            "sh: 1: yarn: command not found",
            "bash: yarn: command not found",
        ] {
            assert_eq!(classify(line).key(), "env/missing-tool:yarn", "{line}");
        }
    }

    #[test]
    fn a_subject_that_is_a_path_keeps_only_what_repairs_are_shared_by() {
        let s = classify(
            "fatal error: /usr/include/x86_64-linux-gnu/openssl/ssl.h: No such file or directory",
        );
        assert_eq!(s.subject.as_deref(), Some("ssl.h"));
    }

    #[test]
    fn a_class_whose_detail_is_per_target_captures_nothing() {
        // Which two packages conflict is a fact about the target. Keying on it would give every
        // target a cluster of one and make the repair cache useless.
        let a = classify("npm ERR! code ERESOLVE\nnpm ERR! while resolving: left-pad@1.3.0");
        let b = classify("npm ERR! code ERESOLVE\nnpm ERR! while resolving: request@2.88.0");
        assert_eq!(a.key(), b.key());
        assert_eq!(a.key(), "npm/peer-conflict");
    }

    #[test]
    fn the_last_error_wins_not_the_first() {
        // A warning early in a phase that went on to succeed is not why the build stopped.
        let log = "npm WARN EBADENGINE unsupported engine\nrunning build\nfatal error: ffi.h: No such file or directory";
        assert_eq!(classify(log).code, "cc/missing-header");
    }

    #[test]
    fn an_unrecognised_failure_is_one_cluster_not_five_hundred() {
        // A per-message hash would scatter a single missing rule across the whole corpus and make
        // it invisible. One bucket is a gap somebody fixes.
        let a = classify("error: the frobnicator declined, code 7");
        let b = classify("error: the frobnicator declined, code 9");
        assert!(a.is_unknown() && b.is_unknown());
        assert_eq!(a.key(), b.key());
        // The differing detail is still there for a human, just not in the key.
        assert_ne!(a.evidence, b.evidence);
    }

    #[test]
    fn a_failure_no_strategy_change_can_fix_is_marked_unrepairable() {
        // Admission control. A model iterating on an OOM spends money to reach the same place.
        let s = classify("/build/run.sh: line 4: 1213 Killed  npm run build");
        assert_eq!(s.code, "env/out-of-memory");
        assert!(!s.repairable);
        assert!(s.retryable, "a bigger worker could get further");
    }

    #[test]
    fn denied_egress_reads_as_policy_not_as_a_broken_package() {
        // Under mirror-only this is the enforcement working. Counting it against the package would
        // make the reproduction rate a measure of our own network policy.
        let s = classify(
            "npm ERR! request to https://registry.npmjs.org failed, reason: getaddrinfo EAI_AGAIN\nTemporary failure in name resolution",
        );
        assert_eq!(s.code, "net/unreachable");
        assert_eq!(s.fault, Fault::Policy);
    }

    #[test]
    fn the_failures_we_actually_hit_are_named() {
        // Every one of these stopped a real build while this system was being written. A taxonomy
        // built only from documentation would have missed all of them.
        for (log, code) in [
            ("Error: Cannot find module 'node:path'", "env/node-too-old"),
            (
                "The virtual environment was not created successfully because ensurepip is not available",
                "env/missing-venv",
            ),
            (
                "error: Unmet dependencies: wheel",
                "pip/unmet-build-dependency",
            ),
            (
                "fatal: unable to access 'https://github.com/x/y.git/': server certificate verification failed",
                "env/no-ca-certificates",
            ),
        ] {
            assert_eq!(classify(log).code, code, "log: {log}");
        }
    }

    #[test]
    fn evidence_is_bounded_and_carries_no_control_characters() {
        // This string reaches a model, and the build script that produced it chose every byte.
        let log = format!(
            "fatal error: x.h: No such file or directory {}",
            "A\u{1b}[2J".repeat(400)
        );
        let s = classify(&log);
        assert!(s.evidence.len() <= 300, "{}", s.evidence.len());
        assert!(!s.evidence.contains('\u{1b}'));
    }

    #[test]
    fn a_retryable_failure_is_told_apart_from_a_permanent_one() {
        assert!(classify("npm ERR! 503 Service Unavailable").retryable);
        assert!(
            !classify("npm ERR! notarget No matching version found for left-pad@9.9.9").retryable
        );
    }

    #[test]
    fn every_code_is_shaped_for_a_cluster_id() {
        for r in RULES {
            assert!(
                r.code == "unknown" || r.code.contains('/'),
                "`{}` should read `area/what-happened`",
                r.code
            );
            assert!(
                r.code
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "/-".contains(c)),
                "`{}` is not safe as a cluster id",
                r.code
            );
        }
    }
}
