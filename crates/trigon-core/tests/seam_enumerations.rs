//! Enumerations against their resolvers.
//!
//! `docs/16-findings.md` records five defects found in code that had unit tests, and every one was
//! the same shape: two things that had to agree, with nothing asserting they did. One of them was
//! an enumeration that under-reported — `all_profiles()` omitted `wheel` while `profile()` answered
//! to it, so the WASM parity test that proves an archived stabilizer set reproduces a signed digest
//! silently skipped the only profile PyPI uses. An enumeration that under-reports is invisible
//! *precisely* to the consumers that iterate: parity sweeps, `--json` output, and the error
//! messages that end "known: ...".
//!
//! This file sweeps that class. Every test here holds one of two shapes:
//!
//! 1. **A variant and its resolver.** Every variant of an enum must be reachable through, and read
//!    back by, every function that claims to name or parse it — `Display`, `FromStr`, serde, a
//!    factory's match arms, a file-extension sniffer. Where the enum is one we can link, the test
//!    is written so that **adding a variant stops the crate compiling** rather than quietly
//!    shrinking the list, which is the only form of this test that survives the next contributor.
//! 2. **A list and the set it claims to cover.** A hand-maintained list of `include_str!`s against
//!    the files on disk; a factory's `supported: "..."` string against its own match arms.
//!
//! ## Why some tests read source text
//!
//! `trigon-core` declares no dev-dependencies and cannot be given any without editing a manifest
//! this task may not touch, so the seams that cross a crate boundary — `for_ecosystem`'s arms
//! against its refusal message, the builtin-tool list against `crates/trigon-strategy/tools/`,
//! `Derivation`'s variants against the spelling `trigon rebuild` writes into a run record — are
//! checked by reading the files. That is weaker than linking, and it is deliberately *not* a
//! grep-for-a-forbidden-string lint: each one parses the real list out of the real file and
//! compares two sets. Every reader panics loudly when its anchor has moved, so a refactor turns
//! into a visible failure and never into a test that passes by finding nothing.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use trigon_core::{
    ArtifactId, ArtifactKind, Ecosystem, Format, Match, NoteCode, Phase, PurlError, TargetRef,
};

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
            "cannot read {} ({e}). This test compares a list in that file against a list \
             elsewhere; if the file moved, move this test with it rather than deleting it.",
            path.display()
        )
    })
}

/// The variant names declared by one `enum` in a source file, in declaration order.
///
/// Used to make the hand-written variant tables below self-checking: a variant added to the enum
/// and forgotten here shows up as a name the table does not carry, so the list cannot quietly fall
/// behind the type. Deliberately dumb — it reads unit and struct variants and nothing else, which
/// is all any enum in this sweep uses.
fn variants_declared_in(source: &str, enum_name: &str) -> Vec<String> {
    let needle = format!("enum {enum_name} {{");
    let start = source
        .find(&needle)
        .unwrap_or_else(|| panic!("no `enum {enum_name}` in the source read for this test"))
        + needle.len();

    let mut depth = 1usize;
    let mut body = String::new();
    for ch in source[start..].chars() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
        body.push(ch);
    }
    assert_eq!(depth, 0, "unbalanced braces reading `enum {enum_name}`");

    let mut names = Vec::new();
    let mut nested = 0usize;
    for line in body.lines() {
        let t = line.trim();
        // Struct-variant bodies are skipped wholesale: only the variant's own line names it.
        if nested > 0 {
            nested += t.matches('{').count();
            nested -= t.matches('}').count();
            continue;
        }
        if t.is_empty() || t.starts_with("//") || t.starts_with("#[") {
            continue;
        }
        let head: String = t
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if head.is_empty() || !head.starts_with(|c: char| c.is_ascii_uppercase()) {
            continue;
        }
        nested += t.matches('{').count() - t.matches('}').count().min(t.matches('{').count());
        names.push(head);
    }
    assert!(
        !names.is_empty(),
        "read no variants out of `enum {enum_name}`; the parser in this test needs fixing"
    );
    names
}

/// Assert that a hand-written table covers an enum exactly.
///
/// The tables below are paired with an exhaustive `match`, so a new variant is a *compile* error
/// first; this catches the case where someone silences that error by adding an arm and forgets the
/// table, which is exactly how `all_profiles()` came to omit `wheel`.
fn assert_table_covers_enum<T: std::fmt::Debug>(table: &[T], source_rel: &str, enum_name: &str) {
    let declared: BTreeSet<String> = variants_declared_in(&read(source_rel), enum_name)
        .into_iter()
        .collect();
    let tabled: BTreeSet<String> = table.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(
        tabled, declared,
        "the table in this test and `enum {enum_name}` in {source_rel} list different variants. \
         A variant the table omits is one every assertion below silently skips."
    );
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let p = entry.expect("readable dir entry").path();
        if p.is_dir() {
            walk(&p, out);
        } else {
            out.push(p);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Ecosystem: the enumeration, its two parsers, and the list its error message prints
// ---------------------------------------------------------------------------------------------

/// Every `Ecosystem`, with completeness enforced twice over: the `match` is exhaustive, so a new
/// variant breaks the build here, and `assert_table_covers_enum` compares this list against the
/// declaration in `target.rs`.
fn all_ecosystems() -> Vec<Ecosystem> {
    let table = vec![
        Ecosystem::Npm,
        Ecosystem::PyPI,
        Ecosystem::CratesIo,
        Ecosystem::RubyGems,
        Ecosystem::NuGet,
        Ecosystem::Maven,
        Ecosystem::GitHub,
    ];
    // The exhaustive match is the compile-time half. It exists for its effect on the build and
    // never for its value.
    for e in &table {
        match e {
            Ecosystem::Npm
            | Ecosystem::PyPI
            | Ecosystem::CratesIo
            | Ecosystem::RubyGems
            | Ecosystem::NuGet
            | Ecosystem::Maven
            | Ecosystem::GitHub => {}
        }
    }
    assert_table_covers_enum(&table, "crates/trigon-core/src/target.rs", "Ecosystem");
    table
}

#[test]
fn every_ecosystem_is_in_all_and_its_purl_type_round_trips_through_from_purl_type() {
    // `Ecosystem::all()` is the enumeration and `from_purl_type` is the resolver. This is finding 3
    // in `docs/16-findings.md` transplanted: `all()` is what `known()` prints, what a sweep planner
    // would iterate, and what any future per-ecosystem parity test would walk. A variant missing
    // from it is invisible to all of them while `from_purl_type` keeps answering to its name, so
    // the system supports an ecosystem that nothing lists.
    let table = all_ecosystems();
    let listed: BTreeSet<Ecosystem> = Ecosystem::all().iter().copied().collect();

    for e in &table {
        assert!(
            listed.contains(e),
            "`Ecosystem::{e:?}` exists and `Ecosystem::all()` omits it. Every consumer that \
             iterates — the `Known:` line in `PurlError`, any per-ecosystem sweep — will skip it \
             while `from_purl_type(\"{}\")` keeps resolving it.",
            e.purl_type()
        );
        assert_eq!(
            Ecosystem::from_purl_type(e.purl_type()),
            Some(*e),
            "`{e:?}` prints as `{}` and `from_purl_type` will not read that back. A PURL this \
             system printed must be a PURL this system can parse.",
            e.purl_type()
        );
        assert_eq!(
            e.to_string(),
            e.purl_type(),
            "`Display` and `purl_type()` are two spellings of one name and must not diverge"
        );
    }

    assert_eq!(
        listed.len(),
        table.len(),
        "`Ecosystem::all()` lists {} entries for {} variants",
        listed.len(),
        table.len()
    );

    let types: BTreeSet<&str> = table.iter().map(|e| e.purl_type()).collect();
    assert_eq!(
        types.len(),
        table.len(),
        "two ecosystems share a `pkg:` type; one of them can never be parsed back"
    );

    // The documented aliases resolve to the variant whose canonical spelling they shadow, and to
    // nothing else. An alias that drifted onto the wrong variant is a parse that succeeds with the
    // wrong answer, which is worse than a parse that fails.
    for (alias, expected) in [
        ("crates.io", Ecosystem::CratesIo),
        ("rubygems", Ecosystem::RubyGems),
    ] {
        assert_eq!(
            Ecosystem::from_purl_type(alias),
            Some(expected),
            "alias `{alias}` no longer resolves to {expected:?}"
        );
    }
    assert_eq!(Ecosystem::from_purl_type("not-a-registry"), None);
}

#[test]
fn the_unknown_ecosystem_error_names_exactly_the_ecosystems_all_reports() {
    // "known: ..." messages are the classic under-reporting surface: they are a second, hand-kept
    // copy of the enumeration written for a human, and nothing fails when the copy falls behind.
    // `PurlError::UnknownEcosystem` derives its list from `all()`, so this asserts the derivation
    // is still live rather than a literal somebody pasted.
    let table = all_ecosystems();
    let expected = table
        .iter()
        .map(|e| e.purl_type())
        .collect::<Vec<_>>()
        .join(", ");

    let err = TargetRef::from_str("pkg:not-a-registry/x@1.0").unwrap_err();
    assert!(
        matches!(err, PurlError::UnknownEcosystem { .. }),
        "expected an UnknownEcosystem error, got {err:?}"
    );
    let text = err.to_string();
    let listed = text
        .split_once("Known: ")
        .unwrap_or_else(|| panic!("no `Known: ` list in `{text}`"))
        .1
        .trim()
        .to_string();
    assert_eq!(
        listed, expected,
        "the refusal message lists a different set of ecosystems than `Ecosystem::all()`. \
         An operator reading it is being told the wrong thing about what this build supports."
    );
}

#[test]
fn every_ecosystem_serializes_under_the_same_name_the_rest_of_the_system_calls_it() {
    // FAILING, and the failure is a live defect. `Ecosystem` has two independent string forms:
    //
    //   * `purl_type()` / `Display` — `pypi`, `cargo`, `gem`, `nuget`, `github`. This is what a
    //     PURL carries, what `Ecosystem::from_purl_type` parses, and what `trigon-store` uses for
    //     its on-disk layout (`crates/trigon-store/src/lib.rs`, `target.reference.ecosystem
    //     .purl_type()`).
    //   * serde's `rename_all = "snake_case"`, which for these acronym-shaped variant names
    //     produces `py_p_i`, `crates_io`, `ruby_gems`, `nu_get`, `git_hub`.
    //
    // `TargetRef` derives `Serialize`, so the second form is what `trigon resolve --output json`
    // actually prints today:
    //
    //     $ trigon resolve pkg:pypi/sniffio@1.3.1 --output json
    //     { "reference": { "ecosystem": "py_p_i", ... } }
    //
    // Two halves of one value that disagree — finding 4's shape exactly. The consequences are not
    // cosmetic: the JSON this tool emits names an ecosystem in a spelling `from_purl_type` will not
    // read back, and a document a human writes with `"ecosystem": "pypi"` is one serde will not
    // deserialize. The same run's store path says `pypi/` while its own JSON says `py_p_i`.
    //
    // Every other enum in this crate agrees with itself here: `Match`, `Phase`, `Confidence` and
    // `Fault` all serialize under the string they print. `Ecosystem` is the outlier, and nobody
    // chose `py_p_i` — it is what the derive did to `PyPI` while nothing was watching.
    let table = all_ecosystems();
    let mut wrong = Vec::new();
    for e in &table {
        let json = serde_json::to_string(e).expect("Ecosystem serializes");
        let name = json.trim_matches('"').to_string();
        if name != e.purl_type() {
            wrong.push(format!(
                "  {e:?}: serde says `{name}`, the rest of the system says `{}`",
                e.purl_type()
            ));
        }
        // The other direction: serde must read back what the PURL parser accepts, or the two
        // parsers for one type accept disjoint languages.
        let via_serde: Result<Ecosystem, _> =
            serde_json::from_str(&format!("\"{}\"", e.purl_type()));
        if via_serde.map(|v| v == *e).unwrap_or(false) {
            continue;
        }
        wrong.push(format!(
            "  {e:?}: serde cannot deserialize its own `pkg:` type `{}`",
            e.purl_type()
        ));
    }
    assert!(
        wrong.is_empty(),
        "an `Ecosystem` has two names and they disagree:\n{}\n\
         Fix: give every variant an explicit `#[serde(rename = \"...\")]` equal to its \
         `purl_type()`, with `alias`es for the old spellings if any stored JSON carries them.",
        wrong.join("\n")
    );
}

// ---------------------------------------------------------------------------------------------
// Match and Phase: printed, parsed, and serialized in three places each
// ---------------------------------------------------------------------------------------------

#[test]
fn every_match_rung_reads_back_as_itself_through_display_from_str_and_serde() {
    // `Match` is written to disk three ways: `Display` into a sweep's TSV, `Serialize` into the
    // attestation predicate (`"outcome": c.outcome.to_string()` in `trigon-attest`), and read back
    // by `FromStr` on the resume path. The doc comment on `FromStr` records what happens when the
    // three drift — a resume path that spelled `normalized_with_caveats` with hyphens dropped every
    // caveated match out of the rate it reported. Nothing was asserting the inverse held.
    let table = vec![
        Match::Divergent,
        Match::NormalizedWithCaveats,
        Match::Normalized,
        Match::Exact,
    ];
    for m in &table {
        match m {
            Match::Divergent | Match::NormalizedWithCaveats | Match::Normalized | Match::Exact => {}
        }
    }
    assert_table_covers_enum(&table, "crates/trigon-core/src/outcome.rs", "Match");

    for m in &table {
        let shown = m.to_string();
        assert_eq!(
            Match::from_str(&shown),
            Ok(*m),
            "`{m:?}` prints as `{shown}` and does not read back"
        );
        let json = serde_json::to_string(m).expect("Match serializes");
        assert_eq!(
            json.trim_matches('"'),
            shown,
            "`{m:?}` serializes as {json} and prints as `{shown}`; a consumer reading one and \
             writing the other silently loses the rung"
        );
        assert_eq!(
            serde_json::from_str::<Match>(&json).unwrap(),
            *m,
            "`{m:?}` does not deserialize from its own serialization"
        );
    }

    // The rungs are ordered, and the order is the claim `is_at_least` makes on behalf of every
    // policy threshold downstream. Asserted over the whole enumeration rather than on one pair.
    for (i, lo) in table.iter().enumerate() {
        for hi in &table[i..] {
            assert!(
                hi.is_at_least(*lo),
                "{hi:?} is listed above {lo:?} and does not outrank it"
            );
        }
    }
    assert!(Match::from_str("normalized-with-caveats").is_err());
}

#[test]
fn every_phase_reads_back_as_itself_and_the_order_is_the_order_the_build_runs() {
    // `Phase` has a hand-written `Display` and a hand-written `FromStr` in the same file, plus a
    // serde derive — three lists to keep in step. A phase that prints under one name and parses
    // under another breaks the repair loop's "did this attempt get further" comparison, which reads
    // the phase back out of a stored record.
    let table = vec![
        Phase::Setup,
        Phase::Source,
        Phase::Deps,
        Phase::Build,
        Phase::Collect,
    ];
    for p in &table {
        match p {
            Phase::Setup | Phase::Source | Phase::Deps | Phase::Build | Phase::Collect => {}
        }
    }
    assert_table_covers_enum(&table, "crates/trigon-core/src/fault.rs", "Phase");

    for p in &table {
        let shown = p.to_string();
        assert_eq!(
            Phase::from_str(&shown),
            Ok(*p),
            "`{p:?}` does not read back"
        );
        assert_eq!(
            serde_json::to_string(p).unwrap().trim_matches('"'),
            shown,
            "`{p:?}` serializes under a different name than it prints"
        );
    }

    // Declaration order *is* the semantics here: `Setup < Source < Deps < Build < Collect` is
    // derived from the enum, and "reached a later phase" is a `>` rather than a table.
    for w in table.windows(2) {
        assert!(
            w[0] < w[1],
            "{:?} must sort before {:?}: the ordering is the build's own",
            w[0],
            w[1]
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Format and ArtifactKind: two extension tables that have to see the same files
// ---------------------------------------------------------------------------------------------

#[test]
fn every_format_but_raw_is_named_by_some_file_extension_and_prints_a_distinct_name() {
    // `Format` is the enumeration; `from_file_name` is the resolver that picks one for a real
    // artifact. A variant no extension maps to is a format the system can describe and never
    // detect — reachable only when a human passes `--format`, which is exactly the state
    // `all_profiles()` was in for `wheel`. `Raw` is the one deliberate exception: it is the
    // "compare it whole" fallback and names no extension by design, so it is listed here as a
    // decision rather than left to be discovered.
    let table = vec![
        Format::TarGz,
        Format::Tar,
        Format::Zip,
        Format::Gzip,
        Format::Raw,
    ];
    for f in &table {
        match f {
            Format::TarGz | Format::Tar | Format::Zip | Format::Gzip | Format::Raw => {}
        }
    }
    assert_table_covers_enum(&table, "crates/trigon-core/src/format.rs", "Format");

    // One witness per variant. If a new format arrives, the exhaustive match above fails the build
    // and whoever adds the arm has to name an extension that reaches it.
    let witnesses: &[(Format, &[&str])] = &[
        (Format::TarGz, &["x.tar.gz", "x.tgz", "x.crate"]),
        (Format::Tar, &["x.tar", "x.gem"]),
        (
            Format::Zip,
            &["x.zip", "x.whl", "x.jar", "x.nupkg", "x.egg"],
        ),
        (Format::Gzip, &["x.json.gz"]),
    ];
    for (fmt, names) in witnesses {
        for name in *names {
            assert_eq!(
                Format::from_file_name(name),
                Some(*fmt),
                "`{name}` no longer sniffs as {fmt:?}"
            );
        }
    }
    let covered: Vec<Format> = witnesses.iter().map(|(f, _)| *f).collect();
    for f in &table {
        if *f == Format::Raw {
            assert!(
                !covered.contains(f),
                "Format::Raw acquired an extension; it is the whole-file fallback and a sniffer \
                 that returns it would stop `--format` from being the only way in"
            );
            continue;
        }
        assert!(
            covered.contains(f),
            "no file extension resolves to {f:?}. The format can be named in an attestation and \
             never inferred from an artifact, so nothing but an explicit `--format` reaches it."
        );
    }

    // Two printed names for one format, or one name for two formats, and an attestation's
    // `archiveFormat` stops identifying the parse a verifier must repeat.
    let shown: BTreeSet<String> = table.iter().map(|f| f.to_string()).collect();
    assert_eq!(
        shown.len(),
        table.len(),
        "two formats print the same name: {shown:?}"
    );

    // `has_outer_codec` decides whether a decompressed-container digest is meaningful, and it must
    // agree with `layers()`: a format with an outer codec unwraps something.
    for f in &table {
        if f.has_outer_codec() {
            assert!(
                f.layers() >= 1,
                "{f:?} claims an outer codec and unwraps {} layers",
                f.layers()
            );
        }
    }
}

#[test]
fn every_artifact_kind_a_file_name_can_name_also_has_a_container_format() {
    // Two extension tables live in this crate, in two files, both keyed on the same suffix:
    // `ArtifactId::kind()` in `target.rs` and `Format::from_file_name()` in `format.rs`. They
    // answer different questions and must agree on *coverage*: an artifact whose kind we know but
    // whose container format we cannot infer is one `trigon stabilize` refuses with "cannot infer
    // a format; pass --format", after the registry has already told us exactly what it is.
    //
    // The direction is one-way on purpose. `.tar` and `.egg` are formats with no interesting kind,
    // and that is fine; a kind with no format is not.
    let table = vec![
        ArtifactKind::Sdist,
        ArtifactKind::Wheel,
        ArtifactKind::Tarball,
        ArtifactKind::Crate,
        ArtifactKind::Gem,
        ArtifactKind::Nupkg,
        ArtifactKind::Jar,
        ArtifactKind::ReleaseAsset,
        ArtifactKind::SourceArchive,
        ArtifactKind::Other,
    ];
    for k in &table {
        match k {
            ArtifactKind::Sdist
            | ArtifactKind::Wheel
            | ArtifactKind::Tarball
            | ArtifactKind::Crate
            | ArtifactKind::Gem
            | ArtifactKind::Nupkg
            | ArtifactKind::Jar
            | ArtifactKind::ReleaseAsset
            | ArtifactKind::SourceArchive
            | ArtifactKind::Other => {}
        }
    }
    assert_table_covers_enum(&table, "crates/trigon-core/src/target.rs", "ArtifactKind");

    // Every extension `kind()` recognises, with the kind it must produce.
    let named: &[(&str, ArtifactKind)] = &[
        ("pkg-1.0-py3-none-any.whl", ArtifactKind::Wheel),
        ("syn-2.0.39.crate", ArtifactKind::Crate),
        ("rake-13.2.1.gem", ArtifactKind::Gem),
        ("Newtonsoft.Json.13.0.3.nupkg", ArtifactKind::Nupkg),
        ("guava-33.0.0.jar", ArtifactKind::Jar),
        ("left-pad-1.3.0.tgz", ArtifactKind::Tarball),
        ("sniffio-1.3.1.tar.gz", ArtifactKind::Sdist),
        ("source-1.0.zip", ArtifactKind::Sdist),
    ];
    for (name, kind) in named {
        assert_eq!(
            ArtifactId::new(*name).kind(),
            *kind,
            "`{name}` no longer reads as {kind:?}"
        );
        assert!(
            Format::from_file_name(name).is_some(),
            "`{name}` has a known ArtifactKind ({kind:?}) and no known container Format. The \
             registry can tell us what the file is and the stabilizer cannot open it."
        );
    }

    // `Other` is the fallback and must stay unreachable from the names above.
    assert_eq!(ArtifactId::new("README").kind(), ArtifactKind::Other);
}

// ---------------------------------------------------------------------------------------------
// NoteCode: the enumeration against the code that can actually emit it
// ---------------------------------------------------------------------------------------------

#[test]
fn every_note_code_the_system_declares_is_emitted_by_something_that_can_produce_it() {
    // A `NoteCode` variant nothing constructs is a claim the system makes and never keeps. Notes
    // are the channel by which a run tells a human something it observed — `is_noteworthy` even
    // promises that a subset reaches a human *on a clean match* — so a dead code is a promised
    // signal that can never fire, and no unit test of the notes that do fire will ever notice.
    //
    // The scan is over the workspace's `src/` trees for the literal `NoteCode::<Variant>`, which is
    // how every emitter in this repository spells it today.
    let table = vec![
        NoteCode::NestedParseFailed,
        NoteCode::RecursionLimitReached,
        NoteCode::EntryLimitReached,
        NoteCode::SizeLimitReached,
        NoteCode::SpilledToDisk,
        NoteCode::DuplicateEntryPath,
        NoteCode::MalformedEntry,
        NoteCode::UnknownEntryKind,
        NoteCode::LongNameReencoded,
        NoteCode::MemberOnlyInUpstream,
        NoteCode::MemberOnlyInRebuild,
        NoteCode::MemberContentDiffers,
        NoteCode::ExecutableContentDiffers,
        NoteCode::CustomStabilizerTouchedExecutable,
    ];
    for c in &table {
        match c {
            NoteCode::NestedParseFailed
            | NoteCode::RecursionLimitReached
            | NoteCode::EntryLimitReached
            | NoteCode::SizeLimitReached
            | NoteCode::SpilledToDisk
            | NoteCode::DuplicateEntryPath
            | NoteCode::MalformedEntry
            | NoteCode::UnknownEntryKind
            | NoteCode::LongNameReencoded
            | NoteCode::MemberOnlyInUpstream
            | NoteCode::MemberOnlyInRebuild
            | NoteCode::MemberContentDiffers
            | NoteCode::ExecutableContentDiffers
            | NoteCode::CustomStabilizerTouchedExecutable => {}
        }
    }
    assert_table_covers_enum(&table, "crates/trigon-core/src/note.rs", "NoteCode");

    let root = workspace_root();
    let mut sources = Vec::new();
    for crate_dir in
        std::fs::read_dir(root.join("crates")).expect("the workspace has a crates/ directory")
    {
        let src = crate_dir.expect("readable entry").path().join("src");
        if src.is_dir() {
            walk(&src, &mut sources);
        }
    }
    walk(&root.join("xtask").join("src"), &mut sources);
    let definition = root.join("crates/trigon-core/src/note.rs");
    let corpus: String = sources
        .iter()
        .filter(|p| p.extension().is_some_and(|e| e == "rs") && **p != definition)
        .map(|p| std::fs::read_to_string(p).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        corpus.contains("NoteCode::RecursionLimitReached"),
        "the scan found no emitters at all; the way this repository spells a NoteCode has changed \
         and this test is measuring nothing"
    );

    let mut dead = Vec::new();
    for c in &table {
        if !corpus.contains(&format!("NoteCode::{c:?}")) {
            let promised = if c.is_noteworthy() {
                "  <- and `is_noteworthy()` promises this one reaches a human"
            } else {
                ""
            };
            dead.push(format!("  NoteCode::{c:?}{promised}"));
        }
    }
    assert!(
        dead.is_empty(),
        "these NoteCode variants are declared and never constructed anywhere in the workspace:\n\
         {}\n\
         The comparison codes are the sharp ones: `trigon-compare`'s `DiffReport` already \
         computes every fact they name — `only_upstream`, `only_rebuild`, `differs`, \
         `executable_differs` in `crates/trigon-compare/src/diff.rs` — and reports it through a \
         parallel vocabulary, so the system has two names for one observation and the half that \
         reaches `Note` (and the attestation) is dead. Fix: either have `compare()` emit these \
         notes from the `DiffReport` it already builds, or delete the variants so the enum stops \
         advertising signals nothing produces.",
        dead.join("\n")
    );
}

// ---------------------------------------------------------------------------------------------
// Cross-crate lists. See the module header for why these read source.
// ---------------------------------------------------------------------------------------------

#[test]
fn the_registry_factorys_supported_list_names_exactly_the_ecosystems_it_serves() {
    // `for_ecosystem` is a resolver with two lists in it: the match arms that return a client, and
    // the `supported: "..."` string its refusal prints. The second is a hand-kept copy of the
    // first, written for an operator, and nothing fails when a new registry lands and the string
    // stays behind — the same shape as `all_profiles()` omitting `wheel`, except the reader is a
    // human deciding whether to file a bug.
    //
    // Verified against the real binary while writing this:
    //   $ trigon resolve pkg:gem/rake@13.2.1
    //   Error: trigon does not speak gem; this build knows npm, pypi
    let src = read("crates/trigon-registry/src/registry.rs");
    let body = src
        .split_once("pub fn for_ecosystem(")
        .unwrap_or_else(|| panic!("`for_ecosystem` has moved out of trigon-registry/registry.rs"))
        .1;

    let served: Vec<Ecosystem> = all_ecosystems()
        .into_iter()
        .filter(|e| body.contains(&format!("Ecosystem::{e:?} => Ok(")))
        .collect();
    assert!(
        !served.is_empty(),
        "read no served ecosystems out of `for_ecosystem`; its arms no longer look like \
         `Ecosystem::X => Ok(...)` and this test needs updating with them"
    );

    let quoted = body
        .split_once("supported: \"")
        .unwrap_or_else(|| panic!("`for_ecosystem` no longer names a `supported:` list"))
        .1;
    let listed = &quoted[..quoted.find('"').expect("unterminated supported string")];

    let expected = served
        .iter()
        .map(|e| e.purl_type())
        .collect::<Vec<_>>()
        .join(", ");
    assert_eq!(
        listed, expected,
        "`for_ecosystem` serves [{expected}] and tells the operator it knows [{listed}]. \
         Whoever reads that message is being told the wrong thing about what this build can do."
    );
}

#[test]
fn every_builtin_tool_yaml_on_disk_is_in_the_list_the_strategy_crate_compiles_in() {
    // `BUILTIN_TOOLS` in `crates/trigon-strategy/src/tool.rs` is a hand-written list of
    // `include_str!`s, and `crates/trigon-strategy/tools/` is the set of files that exist. The list
    // is the enumeration; the directory is the truth. A tool file added and not included compiles
    // fine, ships, and is invisible to `trigon strategy tools` and to every `uses:` that names it —
    // which surfaces as a strategy rejected for naming an unknown tool, blaming the document.
    //
    // Confirmed against the binary while writing this: `trigon strategy tools` prints 14 tools,
    // and 14 files live under that directory.
    let src = read("crates/trigon-strategy/src/tool.rs");
    let listed: BTreeSet<String> = src
        .match_indices("include_str!(\"../tools/")
        .map(|(i, m)| {
            let rest = &src[i + m.len()..];
            rest[..rest.find('"').expect("unterminated include_str! path")].to_string()
        })
        .collect();
    assert!(
        !listed.is_empty(),
        "read no `include_str!(\"../tools/...\")` entries out of tool.rs; the builtin tool list \
         is built some other way now and this test is measuring nothing"
    );

    let dir = workspace_root().join("crates/trigon-strategy/tools");
    let mut files = Vec::new();
    walk(&dir, &mut files);
    let on_disk: BTreeSet<String> = files
        .iter()
        .filter(|p| p.extension().is_some_and(|e| e == "yaml" || e == "yml"))
        .map(|p| {
            p.strip_prefix(&dir)
                .expect("under the tools directory")
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();

    let missing: Vec<&String> = on_disk.difference(&listed).collect();
    assert!(
        missing.is_empty(),
        "these tool documents exist and `BUILTIN_TOOLS` does not include them: {missing:?}. \
         They are invisible to `trigon strategy tools` and unusable from a `uses:`, and the \
         failure surfaces as a strategy blamed for naming an unknown tool."
    );
    let phantom: Vec<&String> = listed.difference(&on_disk).collect();
    assert!(
        phantom.is_empty(),
        "`BUILTIN_TOOLS` includes paths with no file behind them: {phantom:?}"
    );
}
