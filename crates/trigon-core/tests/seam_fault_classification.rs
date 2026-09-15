//! Whose fault it was, and whether anything checks.
//!
//! [`trigon_core::Fault`] exists for one reason, stated in its own doc comment and in
//! `docs/02-domain-model.md` §4: **a benchmark denominator that counts our infrastructure faults as
//! unreproducible packages measures our reliability wearing a reproduction rate's costume.** Every
//! error type in the workspace implements [`Classify`] to keep the two apart, and the classification
//! is worth exactly as much as the care taken over each arm — which, until this file existed, nothing
//! asserted.
//!
//! The asymmetry is the whole point and it cuts both ways:
//!
//! - An error that describes **our** environment, classified as `Build` or `Upstream`, blames the
//!   package. It lands in the numerator of the unreproducible rate and the published number is wrong
//!   in the direction that makes the ecosystem look worse than it is.
//! - An error that describes the **package**, classified as `Bug` or `Infra`, inflates our own error
//!   rate and hides a real reproducibility failure behind a page that says "please report it".
//!
//! Neither is loud. Both survive code review, because each individual arm reads plausibly on its
//! own; what goes wrong is a *new* arm inheriting someone else's decision. So the tests here are
//! written to be exhaustive over the things that grow — the variants of each error enum, and the
//! rules in the failure taxonomy — so that a variant added tomorrow with no deliberate
//! classification fails on the day it is added rather than on the day someone reads a rate.
//!
//! ## Why some tests read source text
//!
//! `trigon-core` is the bottom of the dependency graph: every crate that defines a [`Classify`]
//! implementation depends on *it*, so a test living here cannot link `RegistryError`,
//! `SandboxError`, `LlmError` or any of their siblings, and the crate declares no dev-dependencies
//! that could be pressed into service. The seam still crosses those boundaries, so the tests that
//! cross with it read the files, exactly as `seam_enumerations.rs` does and for the same reason.
//!
//! These are not greps for a forbidden string. Each one parses the real list out of the real file —
//! the variants of an enum, the arms of a `match`, the rows of the rule table, the types the CLI
//! downcasts — and compares two sets. Every reader asserts loudly that it found something before it
//! asserts anything about what it found, because the failure mode of a source-reading test is not a
//! false alarm, it is a test that quietly passes by matching nothing.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use trigon_core::{Classify, Fault, classify};

// ---------------------------------------------------------------------------------------------
// Reading the workspace
// ---------------------------------------------------------------------------------------------

fn workspace_root() -> PathBuf {
    // `crates/trigon-core` -> the workspace. Asserted rather than assumed: a crate moved one level
    // deeper would otherwise make every source-reading test below silently vacuous.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("trigon-core should sit two levels under the workspace root")
        .to_path_buf();
    assert!(
        root.join("Cargo.toml").is_file() && root.join("crates").is_dir(),
        "expected a workspace root at {}; the layout this file reads has moved",
        root.display()
    );
    root
}

fn read(rel: &str) -> String {
    let path = workspace_root().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {} ({e}). This test compares a classification in that file against one \
             elsewhere; if the file moved, move this test with it rather than deleting it.",
            path.display()
        )
    })
}

/// Every `.rs` file under `crates/*/src`, in a stable order.
///
/// `src` only. The test trees mention `Classify` too, and a test's opinion about a fault is not the
/// thing under examination here.
fn crate_sources() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("cannot list {} ({e})", dir.display()));
        for entry in entries {
            let path = entry.expect("a readable directory entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    let crates = workspace_root().join("crates");
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&crates).expect("crates/ should be listable") {
        let src = entry
            .expect("a readable directory entry")
            .path()
            .join("src");
        if src.is_dir() {
            walk(&src, &mut files);
        }
    }
    files.sort();
    assert!(
        files.len() > 50,
        "found only {} source files under crates/*/src; the walk is not reaching the workspace",
        files.len()
    );
    files
}

/// Source with `//` comments removed, so that a variant named only in a comment cannot pass for a
/// variant that was actually classified.
///
/// Safe on the narrow slices it is used for — `Classify` implementations and the rule table carry no
/// string literals containing `//`, which is the one case this would mangle.
fn without_comments(src: &str) -> String {
    src.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The identifiers in a fragment of source, as a set.
fn identifiers(src: &str) -> BTreeSet<String> {
    src.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect()
}

/// The variant names declared by one `enum`, in declaration order.
///
/// Indentation-driven rather than brace-matching, because `thiserror`'s `#[error("...{field}...")]`
/// attributes put unbalanced braces inside string literals on nearly every variant of every error
/// type in this workspace. The workspace is rustfmt-formatted (there is a CI gate and a commit that
/// did it), so "four spaces, then a capital letter" identifies a variant line and nothing else: field
/// names are lower-case and one level deeper, attributes start with `#`, doc comments with `/`, and
/// the continuation lines of a wrapped error string are indented past four.
fn variants_of(src: &str, enum_name: &str) -> Vec<String> {
    let needle = format!("enum {enum_name} {{");
    let start = src
        .find(&needle)
        .unwrap_or_else(|| panic!("no `enum {enum_name}` in the source read for this test"));

    let mut names = Vec::new();
    for line in src[start..].lines().skip(1) {
        // Every top-level item in a formatted file ends with a `}` in column zero.
        if line == "}" {
            break;
        }
        let Some(rest) = line.strip_prefix("    ") else {
            continue;
        };
        if !rest.starts_with(|c: char| c.is_ascii_uppercase()) {
            continue;
        }
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        names.push(name);
    }

    assert!(
        names.len() >= 2,
        "read {} variants out of `enum {enum_name}`; the shape this parser assumes has changed",
        names.len()
    );
    names
}

/// One `impl Classify for ...` block, split into the methods it overrides.
#[derive(Debug)]
struct ClassifyImpl {
    ty: String,
    file: PathBuf,
    /// Method name -> that method's body, comments stripped.
    methods: BTreeMap<String, String>,
}

/// Every `Classify` implementation in the workspace's shipped source.
fn classify_impls() -> Vec<ClassifyImpl> {
    let mut impls = Vec::new();
    for file in crate_sources() {
        let src = std::fs::read_to_string(&file).expect("a readable source file");
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let Some(after) = line.split_once("Classify for ") else {
                continue;
            };
            let ty: String = after
                .1
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();

            // The block runs to the first `}` in column zero, which in formatted source is the end
            // of the item and cannot be anything else.
            let end = lines[i + 1..]
                .iter()
                .position(|l| *l == "}")
                .map(|n| i + 1 + n)
                .unwrap_or_else(|| {
                    panic!(
                        "`impl Classify for {ty}` in {} never closes",
                        file.display()
                    )
                });

            let mut methods: BTreeMap<String, String> = BTreeMap::new();
            let mut current: Option<String> = None;
            for l in &lines[i + 1..end] {
                if let Some(rest) = l.strip_prefix("    fn ") {
                    let name: String = rest
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect();
                    current = Some(name.clone());
                    methods.insert(name, String::new());
                }
                if let Some(name) = &current {
                    let body = methods.get_mut(name).expect("just inserted");
                    body.push_str(l);
                    body.push('\n');
                }
            }
            assert!(
                methods.contains_key("fault"),
                "`impl Classify for {ty}` in {} declares no `fault`; the parser has drifted",
                file.display()
            );
            impls.push(ClassifyImpl {
                ty,
                file: file.clone(),
                methods: methods
                    .into_iter()
                    .map(|(k, v)| (k, without_comments(&v)))
                    .collect(),
            });
        }
    }

    // Nine as of writing. A floor rather than an equality so that adding a tenth error type is not
    // a test failure, but losing the ability to see them is.
    assert!(
        impls.len() >= 9,
        "found {} `Classify` implementations; expected at least the nine that exist. The scan is \
         not finding them, and every assertion built on it is vacuous.",
        impls.len()
    );
    impls
}

// ---------------------------------------------------------------------------------------------
// The classes themselves
// ---------------------------------------------------------------------------------------------

/// Every fault class, pinned by a `match` that stops compiling when a sixth is added.
const ALL_FAULTS: [Fault; 5] = [
    Fault::Infra,
    Fault::Upstream,
    Fault::Build,
    Fault::Policy,
    Fault::Bug,
];

/// Exists so that adding a variant to [`Fault`] fails to compile *here*, which is the only way a new
/// class gets a deliberate answer to the two questions below rather than whatever the array happened
/// to hold.
fn whose(f: Fault) -> &'static str {
    match f {
        Fault::Infra => "ours: infrastructure",
        Fault::Upstream => "the registry's, or the network's",
        Fault::Build => "the package's own build",
        Fault::Policy => "a policy this run is enforcing",
        Fault::Bug => "ours, and someone should look now",
    }
}

#[test]
fn only_a_build_failure_is_a_fact_about_the_package_and_the_denominator_depends_on_it() {
    // `is_about_the_package` is what separates the reproduction rate's numerator from a count of our
    // own bad days. If `Infra` ever answered true, every OOM-killed worker would be published as a
    // package that cannot be rebuilt; if `Build` ever answered false, the rate would have no
    // numerator at all. One line of code, and the number the whole project exists to publish is
    // downstream of it.
    for f in ALL_FAULTS {
        assert_eq!(
            f.is_about_the_package(),
            f == Fault::Build,
            "{f:?} ({}) disagrees about whether it says anything about the package",
            whose(f)
        );
    }

    // The array above is hand-written and `whose` is what forces it to be revisited, so check it
    // really does hold every variant the type declares.
    let declared = variants_of(&read("crates/trigon-core/src/fault.rs"), "Fault");
    let covered: BTreeSet<String> = ALL_FAULTS.iter().map(|f| format!("{f:?}")).collect();
    assert_eq!(
        declared.iter().cloned().collect::<BTreeSet<_>>(),
        covered,
        "ALL_FAULTS has fallen behind `enum Fault`, so every test in this file that sweeps the \
         classes is sweeping a subset of them"
    );
}

/// A local error whose only job is to exercise the trait's default, one variant per class.
#[derive(Debug)]
enum Inheriting {
    Infra,
    Upstream,
    Build,
    Policy,
    Bug,
}

impl Classify for Inheriting {
    fn fault(&self) -> Fault {
        match self {
            Inheriting::Infra => Fault::Infra,
            Inheriting::Upstream => Fault::Upstream,
            Inheriting::Build => Fault::Build,
            Inheriting::Policy => Fault::Policy,
            Inheriting::Bug => Fault::Bug,
        }
    }
}

#[test]
fn an_error_that_does_not_override_retryability_inherits_exactly_what_its_fault_class_implies() {
    // Four of the workspace's nine classified error types — `SandboxError`, `StrategyError`,
    // `MirrorError` and `AttestError` — declare no `is_retryable` and take this default whole. So
    // this is not a test of `matches!`; it is a test of what a fleet does with four error types that
    // never say anything about retrying.
    //
    // Both directions cost real money. `Build` turning retryable would put every package that does
    // not compile back on the queue forever, because a build that failed deterministically fails
    // deterministically again — which is precisely what `SandboxError::Failed` is. `Policy` turning
    // retryable would do the same for every refusal we issued on purpose. `Infra` turning
    // un-retryable would strand a run that lost a container or a disk, and charge the loss to
    // nobody, on a class whose entire purpose is that it can be swept up later.
    for (e, want, why) in [
        (
            Inheriting::Infra,
            true,
            "a lost container or a full disk can come back",
        ),
        (
            Inheriting::Upstream,
            true,
            "a registry that was briefly down answers on the next sweep",
        ),
        (
            Inheriting::Build,
            false,
            "a build that failed deterministically fails deterministically again",
        ),
        (
            Inheriting::Policy,
            false,
            "we refused on purpose, and we will refuse again",
        ),
        (
            Inheriting::Bug,
            false,
            "retrying our own bug reaches our own bug",
        ),
    ] {
        assert_eq!(
            e.is_retryable(),
            want,
            "{e:?} inherits the wrong retryability from {:?}: {why}",
            e.fault()
        );
        // And the default really is a delegation. An `is_retryable` on the trait that stopped
        // consulting `fault()` would silently give every non-overriding type the same answer.
        assert_eq!(e.is_retryable(), e.fault().is_retryable());
    }
}

// ---------------------------------------------------------------------------------------------
// The error types
// ---------------------------------------------------------------------------------------------

#[test]
fn every_classified_error_names_every_one_of_its_variants_rather_than_leaving_new_ones_to_a_wildcard()
 {
    // The compiler already enforces this for `fault()` — as long as nobody writes `_ =>`. The moment
    // somebody does, or writes the same thing as a `matches!` over a couple of variants, the
    // enforcement is gone and every variant added afterwards inherits a bucket nobody chose for it.
    //
    // That is not hypothetical for retryability. `trigon-ai`'s retry loop asks the error itself
    // (`crates/trigon-ai/src/http.rs`, `if !Classify::is_retryable(&last) { break }`), so an
    // `LlmError` variant added for a transient condition — an overload, a timeout, a dropped
    // stream — falls into a wildcard that says `false` and stops being retried, with nothing said
    // anywhere. The reverse shape is just as quiet: a wildcard returning `true` would retry a
    // refusal on every sweep forever.
    //
    // So: every method of every `Classify` implementation must mention every variant of its error by
    // name. That is a spelling of "no catch-all" that a `matches!` cannot slip past.
    let mut offences = Vec::new();

    for imp in classify_impls() {
        // The enum is declared in the same crate; find the file that declares it.
        let crate_dir = imp
            .file
            .ancestors()
            .find(|p| p.join("Cargo.toml").is_file())
            .unwrap_or_else(|| panic!("{} sits in no crate", imp.file.display()));
        let declaring = std::fs::read_to_string(&imp.file).expect("a readable source file");
        let declaring = if declaring.contains(&format!("enum {} {{", imp.ty)) {
            declaring
        } else {
            let mut found = None;
            for f in crate_sources() {
                if !f.starts_with(crate_dir) {
                    continue;
                }
                let s = std::fs::read_to_string(&f).expect("a readable source file");
                if s.contains(&format!("enum {} {{", imp.ty)) {
                    found = Some(s);
                    break;
                }
            }
            found.unwrap_or_else(|| panic!("no `enum {}` anywhere in its own crate", imp.ty))
        };

        let variants = variants_of(&declaring, &imp.ty);
        for (method, body) in &imp.methods {
            let mentioned = identifiers(body);
            let missing: Vec<&String> = variants
                .iter()
                .filter(|v| !mentioned.contains(*v))
                .collect();
            if !missing.is_empty() {
                offences.push(format!(
                    "{}: `{}::{method}` decides for {} of {} variants and leaves {} to whatever the \
                     catch-all says: {}",
                    imp.file.display(),
                    imp.ty,
                    variants.len() - missing.len(),
                    variants.len(),
                    missing.len(),
                    missing
                        .iter()
                        .map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
    }

    assert!(
        offences.is_empty(),
        "a classification with a catch-all is a classification that stops being read the day \
         somebody adds a variant:\n  {}",
        offences.join("\n  ")
    );
}

#[test]
fn every_error_the_cli_can_exit_with_reports_the_fault_it_already_knows() {
    // `report_fault` in `crates/trigon/src/main.rs` exists because the classification "was
    // implemented and never used, which made it documentation rather than a control" — its own words.
    // It is still documentation for four of the nine types, because it reaches them by downcasting a
    // hand-written list of concrete error types and four are not on the list.
    //
    // Confirmed against the built binary rather than inferred from the source. A malformed artifact
    // says whose fault it was:
    //
    //     $ trigon stabilize --infile junk.tgz --outfile out.tgz --format tgz
    //     ERROR the published artifact's fault=Upstream retryable=false
    //     Error: malformed gzip: not a gzip member
    //
    // while an attestation whose subject is the wrong file, a run that is not in the store, and a
    // mirror that cannot bind its port each print their message and nothing else:
    //
    //     $ trigon verify-attestation att.json --rerun-comparison --upstream c.tgz --rebuild b.tgz
    //     Error: the upstream artifact given is not the one this statement is about: ...
    //     $ trigon attest nosuchrun --store emptystore
    //     Error: no run `nosuchrun` in this store
    //     $ trigon mirror --port 1
    //     Error: could not listen on port 1: Permission denied (os error 13)
    //
    // All three classify deliberately — `AttestError::WrongArtifact` is `Upstream` precisely so a
    // mistake is not reported as a signed lie, `StoreError::NoSuchRun` is `Bug`, `MirrorError::Bind`
    // is `Infra` and retryable — and all three exit with the class unread. The one that matters most
    // is the one nobody has hit yet: `AttestError::ClaimRefuted` is `Fault::Bug`, "ours, and someone
    // should look now", which is the loudest thing this system can say, and today it exits as quietly
    // as a typo'd path.
    let main = read("crates/trigon/src/main.rs");

    // Both halves of the reporting path: the class, and the retryability the class only defaults.
    let mut consulted = BTreeSet::new();
    for f in ["fn report_fault(", "fn retryable_of("] {
        let start = main
            .find(f)
            .unwrap_or_else(|| panic!("no `{f}` in main.rs; the CLI's fault reporting has moved"));
        let body: String = main[start..]
            .lines()
            .skip(1)
            .take_while(|l| *l != "}")
            .collect::<Vec<_>>()
            .join("\n");
        for frag in body.split("downcast_ref::<").skip(1) {
            let ty = frag
                .split('>')
                .next()
                .unwrap_or_default()
                .rsplit("::")
                .next()
                .unwrap_or_default()
                .trim()
                .to_string();
            consulted.insert(ty);
        }
    }
    assert!(
        consulted.contains("ArchiveError"),
        "read {consulted:?} out of the CLI's fault reporting, which does not look like the list it \
         keeps; this test is not reading what it thinks it is"
    );

    let classified: BTreeSet<String> = classify_impls().into_iter().map(|i| i.ty).collect();
    let unread: Vec<&String> = classified.difference(&consulted).collect();
    assert!(
        unread.is_empty(),
        "{} error types classify every variant deliberately and the CLI never asks: {}. \
         A fault nobody reads is a comment.",
        unread.len(),
        unread
            .iter()
            .map(|t| t.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
}

// ---------------------------------------------------------------------------------------------
// The failure taxonomy
// ---------------------------------------------------------------------------------------------

/// One row of `RULES` in `crates/trigon-core/src/failure.rs`.
#[derive(Debug)]
struct RuleRow {
    code: String,
    fault: Fault,
    retryable: bool,
}

/// The rule table, read out of its own source.
///
/// `RULES` is private and there is no accessor, which is right — nothing in production needs to
/// enumerate it. But a test that samples it is a test that says nothing about the rule somebody adds
/// next month, and a taxonomy grows by exactly that. It is thirty-eight rows today and every one of
/// them assigns a fault.
fn failure_rules() -> Vec<RuleRow> {
    let src = read("crates/trigon-core/src/failure.rs");
    let start = src
        .find("const RULES: &[Rule] = &[")
        .expect("no `const RULES` in failure.rs; the taxonomy has moved");
    let body: String = src[start..]
        .lines()
        .skip(1)
        .take_while(|l| *l != "];")
        .collect::<Vec<_>>()
        .join("\n");
    let body = without_comments(&body);

    let mut rows = Vec::new();
    let (mut code, mut fault, mut retryable) = (None, None, None);
    for line in body.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("code: ") {
            code = Some(rest.trim().trim_matches(',').trim_matches('"').to_string());
        } else if let Some(rest) = t.strip_prefix("fault: Fault::") {
            let name = rest.trim().trim_matches(',');
            fault = Some(match name {
                "Infra" => Fault::Infra,
                "Upstream" => Fault::Upstream,
                "Build" => Fault::Build,
                "Policy" => Fault::Policy,
                "Bug" => Fault::Bug,
                other => panic!(
                    "rule table names a fault `{other}` this test does not know. A new class needs \
                     a deliberate answer here, not a silent skip."
                ),
            });
        } else if let Some(rest) = t.strip_prefix("retryable: ") {
            retryable = Some(rest.trim().trim_matches(',') == "true");
        } else if t == "}," {
            // End of a `Rule { ... }`. All three fields are mandatory in the struct, so any row that
            // reaches here without them means the parse, not the table, is wrong.
            let (c, f, r) = (code.take(), fault.take(), retryable.take());
            match (c, f, r) {
                (Some(code), Some(fault), Some(retryable)) => rows.push(RuleRow {
                    code,
                    fault,
                    retryable,
                }),
                other => panic!("a rule row parsed as {other:?}; the table's shape has changed"),
            }
        }
    }

    assert!(
        rows.len() >= 30,
        "read {} rules out of the taxonomy; it has around thirty-eight and a parse that finds a \
         handful would let this file pass while checking almost nothing",
        rows.len()
    );
    rows
}

#[test]
fn no_failure_rule_that_names_our_own_environment_is_charged_to_the_package() {
    // The rule table is where the asymmetry actually bites, because it is the thing that grows: a
    // sweep turns up an unnamed cluster, somebody writes a rule for it, and the fault is the field
    // most easily copied from the row above. Eleven of the thirty-eight rules say `Fault::Build`, so
    // `Build` is what a copied row says by default.
    //
    // Two areas may never say it. `env/...` names something missing or broken in the image *we*
    // built — a missing `yarn`, a missing `libatomic`, an OOM kill — and `trigon/...` names our own
    // code: the mirror handing a build a corrupt body is the founding example, because a corrupt
    // tarball reads exactly like a broken package and would otherwise be counted as one. A rule in
    // either area that says `Build` publishes our bug as an unreproducible package; one that says
    // `Upstream` blames the registry for it instead. Both are the failure this taxonomy exists to
    // prevent, and both are one careless line.
    let rules = failure_rules();

    let ours: Vec<&RuleRow> = rules
        .iter()
        .filter(|r| r.code.starts_with("env/") || r.code.starts_with("trigon/"))
        .collect();
    assert!(
        ours.len() >= 10,
        "only {} rules in the `env/` and `trigon/` areas; there are a dozen, so this test is \
         checking almost nothing",
        ours.len()
    );

    for r in ours {
        assert!(
            !r.fault.is_about_the_package(),
            "`{}` is {:?} — {} — and it describes our own environment. It will be counted against \
             the package in every rate we publish.",
            r.code,
            r.fault,
            whose(r.fault)
        );
        assert_ne!(
            r.fault,
            Fault::Upstream,
            "`{}` describes our own environment and blames the registry for it",
            r.code
        );
    }
}

#[test]
fn no_failure_rule_classified_as_a_policy_refusal_asks_to_be_retried_forever() {
    // `retryable` is a separate field from `fault` in the rule table, which is right — a registry
    // that was briefly down and an artifact that will never parse are both `Upstream` and only one is
    // worth another go. The cost of separating them is that the two can disagree, and one disagreement
    // is never defensible: a refusal we issued on purpose answers the same way every time it is
    // asked. `net/unreachable` under `--egress mirror-only` is the enforcement working; re-running it
    // burns a worker slot to watch the enforcement work again, on every sweep, for as long as the
    // sweep exists.
    let rules = failure_rules();

    let policy: Vec<&RuleRow> = rules.iter().filter(|r| r.fault == Fault::Policy).collect();
    assert!(
        policy.len() >= 3,
        "only {} policy rules found; the taxonomy has several and this test is checking almost \
         nothing",
        policy.len()
    );
    for r in policy {
        assert!(
            !r.retryable,
            "`{}` is a refusal of ours and asks to be retried. The answer will not change.",
            r.code
        );
    }

    // And the class the rules are copying from agrees, which is what makes the rows above readable
    // as deliberate rather than coincidental.
    assert!(!Fault::Policy.is_retryable());
}

#[test]
fn a_failure_we_have_no_rule_for_is_charged_to_the_package_and_says_so() {
    // The residue bucket, pinned deliberately because it is the largest one in any sweep of a new
    // ecosystem and because it is *not* obviously right. `classify` only ever runs on a build log, so
    // a build did run and did fail, and charging the residue to the package is the defensible reading.
    // But this module's own history says what actually lands here: a mirror answering 400 to a
    // toolchain fetch, a missing `npx` under dash, three npm-corpus failures that were all ours.
    // Every one of those was `Fault::Build` — counted against a package — for as long as it took
    // somebody to notice the cluster and write a rule.
    //
    // So this test is a tripwire on a known asymmetry rather than a statement that it is fine: if
    // somebody changes what an unnamed failure costs a package, they change it here, on purpose, with
    // this comment in front of them.
    //
    // **Two things have changed under it since, both narrowing what lands here.** The container
    // runtime's own refusals — an image absent from the store, a registry it cannot reach — used to
    // arrive as a build log and match no rule; they now return `SandboxError::RuntimeRefused` and
    // never reach `classify` at all. And the table has rules for the runtime failures that *do*
    // produce a log (`env/image-unavailable`, `env/runtime-refused`, and the lowercase spellings of
    // out-of-memory, no-space and permission-denied that only the container forms emit).
    //
    // So the premise above — a build ran and did fail — is truer than it was. It is still not
    // certain, and the question of whether the residue should cost a package anything stays open in
    // `docs/17-backlog.md`. The next person to stand here has better information than the last.
    let s = classify("error: the frobnicator declined, code 7");
    assert!(s.is_unknown());
    assert_eq!(
        s.fault,
        Fault::Build,
        "an unnamed failure is charged to the package"
    );
    assert!(
        s.fault.is_about_the_package(),
        "and therefore lands in the numerator of the published reproduction rate"
    );
    assert!(
        !s.retryable,
        "we do not know what it was, so we have no reason to think a second run differs"
    );
    assert!(
        s.repairable,
        "but a strategy change might still fix it, so the repair loop is allowed to try"
    );

    // A named failure of ours is the contrast that makes the above a choice rather than an accident:
    // the same log, once a rule exists for it, stops costing the package anything.
    let named = classify("npm ERR! code Z_DATA_ERROR\nnpm ERR! zlib: invalid stored block lengths");
    assert!(!named.is_unknown());
    assert!(
        !named.fault.is_about_the_package(),
        "a rule exists for this one, and it says the corruption was our mirror's"
    );
}

#[test]
fn the_container_runtimes_own_refusals_are_named_rather_than_charged_to_the_package() {
    // The rule table had no rule for any container-runtime, registry or image failure, so every one
    // of them fell to the residue bucket above and was counted against a package. An operator who
    // passed `--image` a digest that was not in the local store was told "the build failed in deps:
    // unknown" — the wrong phase, the wrong fault, and none of podman's own message, which had
    // named the cause exactly.
    for log in [
        "Error: creating build container: initializing source docker://localhost/trigon-base@sha256:7cddd: \
         pinging container registry localhost: Get \"https://localhost/v2/\": dial tcp [::1]:443: \
         connect: connection refused",
        "Error: 7cdddce4868e731b4e441d8d5f836b97f1e653e8f3cae212a24bb305cf2deec2: image not known",
        "Error: error creating container storage: the container name is already in use",
    ] {
        let s = classify(log);
        assert!(!s.is_unknown(), "no rule claimed: {log}");
        assert!(
            !s.fault.is_about_the_package(),
            "the runtime declining to start is not the package failing to build: {log} -> {:?}",
            s.fault
        );
        assert!(
            !s.repairable,
            "nothing a model writes into a strategy reaches an unreachable registry: {log}"
        );
    }
}

#[test]
fn the_container_forms_of_the_environment_failures_match_too() {
    // The table matched the C library's capitalised spellings and not the lowercase ones the
    // runtime and Go tooling emit, so a build the kernel killed inside podman, or one that filled
    // the disk, matched no rule and was charged to the package.
    for (log, code) in [
        ("write /out/wheel: no space left on device", "env/no-space"),
        ("OCI runtime error: signal: killed", "env/out-of-memory"),
        ("runtime: cannot allocate memory", "env/out-of-memory"),
    ] {
        let s = classify(log);
        assert_eq!(s.code, code, "{log}");
        assert!(!s.fault.is_about_the_package(), "{log}");
    }

    // And the two spellings of one failure key into one cluster rather than two. The cluster id is
    // also the repair-cache key and the admission prior, so a failure keying two ways means the
    // flywheel never recognises what it has already solved.
    let upper = classify("IOError: [Errno 13] Permission denied: '/deps'");
    let lower = classify("open /deps/bin/python: permission denied");
    assert_eq!(upper.code, lower.code);
    assert_eq!(upper.fault, lower.fault);
}
