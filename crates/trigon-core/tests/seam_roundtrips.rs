//! Everything that crosses a boundary, and whether it comes back the same.
//!
//! A type that is written by one half of the system and read by the other is a seam, and a seam is
//! two things that have to agree with nothing making them. `Match` already carries the lesson in
//! its own source: `FromStr` is documented as the exact inverse of `Display` because a sweep's
//! resume path once spelled `normalized_with_caveats` with hyphens and silently dropped every
//! caveated match from the rate it reported. Nobody had asserted that the writer and the reader
//! used the same alphabet.
//!
//! This file asserts it, for every type in this crate that reaches a file, a wire, or a signature,
//! and for **every variant** rather than a sample. The sampling is the failure mode: the WASM
//! parity test covered every profile `all_profiles()` listed, `all_profiles()` omitted `wheel`, and
//! so the one profile PyPI actually uses went unchecked for a dozen commits. An inventory that a
//! new variant does not have to be added to is an inventory that will be wrong.
//!
//! So the inventories below are built by a `match` with **no wildcard arm**. Adding a variant to
//! any of these enums makes this file stop compiling until the variant is listed here too. That is
//! the point, and it is why the arms are spelled out rather than collapsed into `_ => {}`.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::str::FromStr;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::json;
use trigon_core::{
    ArtifactId, ArtifactKind, Claim, Compressed, Confidence, Digest, Ecosystem, EntryPath,
    Evidence, FailureSignature, Fault, Format, Intrinsics, Match, MultiDigest, Note, NoteCode,
    Phase, ProfileId, Provenance, RegistryMoment, RiskTier, Sha512, SourceDiscovery,
    SourceProvenance, StabilizerId, Target, TargetRef, ToolchainResolution, classify, jcs,
};

// ---------------------------------------------------------------------------------------------
// Inventories. Exhaustive by construction: each `match` has no wildcard, so a new variant is a
// compile error here first, and the fix is to add it to the `vec!` above the match as well.
// ---------------------------------------------------------------------------------------------

fn every_match() -> Vec<Match> {
    let all = vec![
        Match::Divergent,
        Match::NormalizedWithCaveats,
        Match::Normalized,
        Match::Exact,
    ];
    for m in &all {
        match m {
            Match::Divergent => {}
            Match::NormalizedWithCaveats => {}
            Match::Normalized => {}
            Match::Exact => {}
        }
    }
    all
}

fn every_phase() -> Vec<Phase> {
    let all = vec![
        Phase::Setup,
        Phase::Source,
        Phase::Deps,
        Phase::Build,
        Phase::Collect,
    ];
    for p in &all {
        match p {
            Phase::Setup => {}
            Phase::Source => {}
            Phase::Deps => {}
            Phase::Build => {}
            Phase::Collect => {}
        }
    }
    all
}

fn every_risk_tier() -> Vec<RiskTier> {
    let all = vec![
        RiskTier::Structural,
        RiskTier::Metadata,
        RiskTier::Content,
        RiskTier::Lossy,
    ];
    for r in &all {
        match r {
            RiskTier::Structural => {}
            RiskTier::Metadata => {}
            RiskTier::Content => {}
            RiskTier::Lossy => {}
        }
    }
    all
}

fn every_fault() -> Vec<Fault> {
    let all = vec![
        Fault::Infra,
        Fault::Upstream,
        Fault::Build,
        Fault::Policy,
        Fault::Bug,
    ];
    for f in &all {
        match f {
            Fault::Infra => {}
            Fault::Upstream => {}
            Fault::Build => {}
            Fault::Policy => {}
            Fault::Bug => {}
        }
    }
    all
}

fn every_confidence() -> Vec<Confidence> {
    let all = vec![Confidence::Certain, Confidence::Strong, Confidence::Weak];
    for c in &all {
        match c {
            Confidence::Certain => {}
            Confidence::Strong => {}
            Confidence::Weak => {}
        }
    }
    all
}

fn every_format() -> Vec<Format> {
    let all = vec![
        Format::TarGz,
        Format::Tar,
        Format::Zip,
        Format::Gzip,
        Format::Raw,
    ];
    for f in &all {
        match f {
            Format::TarGz => {}
            Format::Tar => {}
            Format::Zip => {}
            Format::Gzip => {}
            Format::Raw => {}
        }
    }
    all
}

fn every_ecosystem() -> Vec<Ecosystem> {
    let all = vec![
        Ecosystem::Npm,
        Ecosystem::PyPI,
        Ecosystem::CratesIo,
        Ecosystem::RubyGems,
        Ecosystem::NuGet,
        Ecosystem::Maven,
        Ecosystem::GitHub,
    ];
    for e in &all {
        match e {
            Ecosystem::Npm => {}
            Ecosystem::PyPI => {}
            Ecosystem::CratesIo => {}
            Ecosystem::RubyGems => {}
            Ecosystem::NuGet => {}
            Ecosystem::Maven => {}
            Ecosystem::GitHub => {}
        }
    }
    all
}

fn every_provenance() -> Vec<Provenance> {
    let all = vec![
        Provenance::Builtin,
        Provenance::Human {
            reviewer: "a-reviewer".into(),
        },
        Provenance::Model {
            model_id: "some-model".into(),
            run_id: "run-7".into(),
        },
    ];
    for p in &all {
        match p {
            Provenance::Builtin => {}
            Provenance::Human { .. } => {}
            Provenance::Model { .. } => {}
        }
    }
    all
}

fn every_note_code() -> Vec<NoteCode> {
    let all = vec![
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
    for c in &all {
        match c {
            NoteCode::NestedParseFailed => {}
            NoteCode::RecursionLimitReached => {}
            NoteCode::EntryLimitReached => {}
            NoteCode::SizeLimitReached => {}
            NoteCode::SpilledToDisk => {}
            NoteCode::DuplicateEntryPath => {}
            NoteCode::MalformedEntry => {}
            NoteCode::UnknownEntryKind => {}
            NoteCode::LongNameReencoded => {}
            NoteCode::MemberOnlyInUpstream => {}
            NoteCode::MemberOnlyInRebuild => {}
            NoteCode::MemberContentDiffers => {}
            NoteCode::ExecutableContentDiffers => {}
            NoteCode::CustomStabilizerTouchedExecutable => {}
        }
    }
    all
}

fn every_artifact_kind() -> Vec<ArtifactKind> {
    let all = vec![
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
    for k in &all {
        match k {
            ArtifactKind::Sdist => {}
            ArtifactKind::Wheel => {}
            ArtifactKind::Tarball => {}
            ArtifactKind::Crate => {}
            ArtifactKind::Gem => {}
            ArtifactKind::Nupkg => {}
            ArtifactKind::Jar => {}
            ArtifactKind::ReleaseAsset => {}
            ArtifactKind::SourceArchive => {}
            ArtifactKind::Other => {}
        }
    }
    all
}

fn every_source_discovery() -> Vec<SourceDiscovery> {
    let all = vec![
        SourceDiscovery::RegistryCommit,
        SourceDiscovery::PublishedProvenance,
        SourceDiscovery::RegistryMetadata,
        SourceDiscovery::ExactTag,
        SourceDiscovery::PrefixedTag,
        SourceDiscovery::FuzzyTag,
        SourceDiscovery::ManifestHistory,
        SourceDiscovery::TreeHashMatch,
        SourceDiscovery::Definition,
        SourceDiscovery::ModelAssisted,
    ];
    for d in &all {
        match d {
            SourceDiscovery::RegistryCommit => {}
            SourceDiscovery::PublishedProvenance => {}
            SourceDiscovery::RegistryMetadata => {}
            SourceDiscovery::ExactTag => {}
            SourceDiscovery::PrefixedTag => {}
            SourceDiscovery::FuzzyTag => {}
            SourceDiscovery::ManifestHistory => {}
            SourceDiscovery::TreeHashMatch => {}
            SourceDiscovery::Definition => {}
            SourceDiscovery::ModelAssisted => {}
        }
    }
    all
}

// ---------------------------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------------------------

/// Serialize, read back, and insist on equality *and* on a byte-identical second serialization.
///
/// The second serialization is not redundant. A value that survives one trip but re-renders
/// differently — a `skip_serializing_if` that no longer fires, an `Option` that came back as
/// `Some("")` instead of `None` — produces a different digest for the same fact, and digests are
/// what this system signs.
fn survives_json<T>(label: &str, v: &T)
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    let once =
        serde_json::to_string(v).unwrap_or_else(|e| panic!("{label} would not serialize: {e}"));
    let back: T = serde_json::from_str(&once)
        .unwrap_or_else(|e| panic!("{label} did not read back from `{once}`: {e}"));
    assert_eq!(&back, v, "{label} changed across the wire: `{once}`");
    let twice = serde_json::to_string(&back).unwrap();
    assert_eq!(
        once, twice,
        "{label} re-renders differently after a round trip"
    );
}

/// The string a serde-serialized enum variant lands on, without the JSON quotes.
fn serde_word<T: Serialize + Debug>(v: &T) -> String {
    let s = serde_json::to_string(v).unwrap();
    s.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or_else(|| panic!("{v:?} does not serialize as a bare string: {s}"))
        .to_string()
}

// ---------------------------------------------------------------------------------------------
// Verdicts and their alphabets.
// ---------------------------------------------------------------------------------------------

#[test]
fn every_match_variant_spells_itself_the_same_way_through_display_fromstr_and_serde() {
    // `Match` crosses the boundary through *two* independent channels, and they have to agree or a
    // reader joining one to the other sees two different verdicts for one run:
    //
    //   - as a bare string, `RunRecord::outcome` in `crates/trigon-store/src/record.rs`, whose doc
    //     comment names the four spellings, and `"outcome"` in the signed equivalence predicate in
    //     `crates/trigon-attest/src/statement.rs`, both written with `Display`;
    //   - as a serde field, `Comparison::outcome`, which `trigon attest` reads back out of the blob
    //     store before it re-derives and signs the claim.
    //
    // Display, FromStr and serde are therefore one alphabet with three implementations. Nothing but
    // this test makes them the same alphabet.
    for m in every_match() {
        let shown = m.to_string();
        assert_eq!(
            Match::from_str(&shown),
            Ok(m),
            "`{shown}` is what Display writes and FromStr would not read it back"
        );
        assert_eq!(
            serde_word(&m),
            shown,
            "{m:?} goes into a record as `{shown}` and into a Comparison as `{}`",
            serde_word(&m)
        );
    }

    // The reader must stay narrow. Widening it to be forgiving is how a typo stops being an error
    // and starts being a silently different verdict.
    for wrong in [
        "normalized-with-caveats",
        "NormalizedWithCaveats",
        "Exact",
        "3",
        "",
    ] {
        assert!(
            Match::from_str(wrong).is_err(),
            "`{wrong}` is not one of the four spellings and must not parse"
        );
    }
}

#[test]
fn the_match_ladder_keeps_its_order_across_the_wire() {
    // `is_at_least` is a policy gate — "accept `normalized` or better" — and it is derived from
    // declaration order. Serializing as a string is what lets a rung be inserted later, but only if
    // the order survives the trip: a value that came back as a different variant would compare
    // differently and quietly change what a policy admits.
    for m in every_match() {
        let back: Match = serde_json::from_str(&serde_json::to_string(&m).unwrap()).unwrap();
        assert_eq!(
            back.is_at_least(Match::Normalized),
            m.is_at_least(Match::Normalized)
        );
        assert_eq!(back.is_reproduced(), m.is_reproduced());
    }
    assert!(Match::Exact > Match::Normalized);
    assert!(Match::Normalized > Match::NormalizedWithCaveats);
    assert!(Match::NormalizedWithCaveats > Match::Divergent);
}

#[test]
fn every_phase_agrees_across_display_fromstr_serde_and_the_debug_rendering_callers_use() {
    // Four spellings of one value, three of them written by hand:
    //
    //   - `Display`/`FromStr`, the pair `RunRecord::timings` keys on;
    //   - serde, wherever a `Phase` rides inside a struct;
    //   - `format!("{p:?}").to_lowercase()`, which `crates/trigon/src/main.rs` uses to fill
    //     `BuildFailure::phase` rather than calling the `Display` that already exists.
    //
    // They agree today only because every variant happens to be one word. A `PostBuild` would make
    // the hand-rolled rendering say `postbuild` while serde said `post_build`, and the repair
    // loop's "did this attempt get *further*" comparison would be reading a phase name that no
    // longer parses.
    for p in every_phase() {
        let shown = p.to_string();
        assert_eq!(
            Phase::from_str(&shown),
            Ok(p),
            "Display/FromStr disagree on {p:?}"
        );
        assert_eq!(serde_word(&p), shown, "serde and Display disagree on {p:?}");
        assert_eq!(
            format!("{p:?}").to_lowercase(),
            shown,
            "the Debug-lowercase rendering in crates/trigon/src/main.rs disagrees on {p:?}"
        );
    }
    assert!(
        Phase::from_str("Build").is_err(),
        "the spelling is lowercase"
    );
}

#[test]
fn every_tier_fault_and_confidence_serializes_under_the_debug_lowercase_name_its_writers_use() {
    // `RiskTier` reaches a **signed** document through a hand-rolled rendering:
    // `"risk": format!("{:?}", a.risk).to_lowercase()` in
    // `crates/trigon-attest/src/statement.rs`, repeated in two places in the CLI. The same tier
    // reaches the stored `Comparison` through serde. `docs/threat-model.md` §1.13 tells a consumer
    // to read `applied[].risk` and reject a normalization they do not accept, so the two renderings
    // naming one tier differently is the same failure as finding 4: a signed statement that
    // disagrees with the comparison it was derived from.
    //
    // Single-word variants make these coincide. `SemiLossy` would not: `semilossy` against
    // `semi_lossy`. This is the assertion that catches it on the day it is added.
    for r in every_risk_tier() {
        assert_eq!(
            format!("{r:?}").to_lowercase(),
            serde_word(&r),
            "the attestation writes {r:?} one way and serde another"
        );
    }
    for f in every_fault() {
        assert_eq!(format!("{f:?}").to_lowercase(), serde_word(&f), "{f:?}");
    }
    for c in every_confidence() {
        assert_eq!(format!("{c:?}").to_lowercase(), serde_word(&c), "{c:?}");
    }
}

#[test]
fn every_provenance_variant_tags_itself_with_the_name_the_attestation_writes() {
    // The provenance cap is the invariant the whole design rests on: `Match::Normalized` is
    // unreachable when anything other than `Builtin` fired. A consumer checks it by reading
    // `applied[].provenance`, which `provenance_name` in `crates/trigon-attest/src/statement.rs`
    // writes as one of exactly these three words, and by reading `kind` off a serde-serialized
    // `Provenance`. A fourth variant whose tag did not match its `provenance_name` arm would be
    // invisible to a consumer filtering on the three they know.
    let expected = ["builtin", "human", "model"];
    for (p, want) in every_provenance().iter().zip(expected) {
        let v = serde_json::to_value(p).unwrap();
        assert_eq!(
            v.get("kind").and_then(|k| k.as_str()),
            Some(want),
            "{p:?} does not tag itself `{want}`"
        );
        survives_json("Provenance", p);
    }
    assert_eq!(
        every_provenance().len(),
        expected.len(),
        "a provenance variant exists that `provenance_name` in trigon-attest does not name"
    );
}

// ---------------------------------------------------------------------------------------------
// Container format: one type, two names.
// ---------------------------------------------------------------------------------------------

#[test]
fn every_format_variant_names_itself_the_same_way_through_display_and_serde() {
    // `Format` is the one value a verifier cannot re-derive: holding an attestation and two files
    // it has no ecosystem to ask, and guessing reads a `.gem` as a plain tar and computes a
    // different digest for a correct artifact. So the name is written down — and it is written
    // down twice, in two different alphabets, by code that does not know about the other:
    //
    //   - `Display`, which `statement.rs` puts in the signed `archiveFormat` field and which
    //     `xtask corpus scan` writes into `corpora/*.toml` as `format = "tar+gzip"`;
    //   - serde, which renders `TarGz` as `tar-gz` inside every stored `Summary`.
    //
    // There is no `FromStr`, so three readers parse the string by hand and none of them agrees
    // with the others about which spellings exist:
    //
    //   - `resolve_format`  (crates/trigon/src/main.rs)      tar+gzip | tar.gz | tgz | tar | zip | gzip | gz | raw
    //   - `parse_format`    (crates/trigon-attest/src/verify.rs) tar+gzip | tar-gz | tar | zip | gzip | raw
    //   - `codes_for`       (xtask/src/differential.rs)         tar+gzip | tar | zip | gzip
    //
    // That `parse_format` already accepts both spellings is the drift having happened once and
    // been patched at the reader. This asserts the property that would have made the patch
    // unnecessary: one format, one name.
    for f in every_format() {
        assert_eq!(
            serde_word(&f),
            f.to_string(),
            "{f:?} is `{}` to serde and `{}` to Display, and `trigon stabilize --format {}` \
             rejects the former: `error: unknown format `{}``",
            serde_word(&f),
            f,
            serde_word(&f),
            serde_word(&f)
        );
    }
}

#[test]
fn every_format_variant_survives_serde_and_keeps_its_layer_arithmetic() {
    // The round trip proper, independent of the spelling above. `layers()` and `has_outer_codec()`
    // decide whether a container digest is computed at all, so a format that came back as a
    // different variant would silently change which of the three digests a comparison holds.
    for f in every_format() {
        survives_json("Format", &f);
        let back: Format = serde_json::from_str(&serde_json::to_string(&f).unwrap()).unwrap();
        assert_eq!(back.layers(), f.layers());
        assert_eq!(back.has_outer_codec(), f.has_outer_codec());
    }
}

// ---------------------------------------------------------------------------------------------
// Identity: package URLs, both directions.
// ---------------------------------------------------------------------------------------------

#[test]
fn every_ecosystem_round_trips_through_its_purl_type_and_is_listed_in_all() {
    // `Ecosystem::all()` is a hand-maintained list, and a hand-maintained enumeration that nothing
    // checks is exactly what omitted `wheel` from `all_profiles()` and left the one profile PyPI
    // uses out of the WASM parity test. `all()` feeds the error message that tells a user which
    // ecosystems exist, so a missing entry is a package type the tool supports and denies having.
    for e in every_ecosystem() {
        assert_eq!(
            Ecosystem::from_purl_type(e.purl_type()),
            Some(e),
            "{e:?} renders as `{}` and its own parser does not accept that",
            e.purl_type()
        );
        assert_eq!(
            e.to_string(),
            e.purl_type(),
            "Display and purl_type disagree on {e:?}"
        );
        assert!(
            Ecosystem::all().contains(&e),
            "{e:?} is not in Ecosystem::all(), so it is missing from the `Known:` list a user sees"
        );
    }
    assert_eq!(
        Ecosystem::all().len(),
        every_ecosystem().len(),
        "Ecosystem::all() and the variant list have drifted apart"
    );
}

#[test]
fn every_ecosystem_serializes_under_a_name_its_own_parser_accepts() {
    // The same identity leaves this system through two doors. `trigon resolve --output text`
    // prints the PURL, built from `purl_type()`. `trigon resolve --output json` prints a
    // serde-serialized `ResolvedTarget`, whose `ecosystem` field is the derived `snake_case`
    // rendering of the Rust variant name. For five of the seven variants those are different
    // strings, and the JSON one is not a PURL type at all:
    //
    //     $ trigon resolve pkg:pypi/sniffio@1.3.1 --output text
    //     pkg:pypi/sniffio@1.3.1
    //     $ trigon resolve pkg:pypi/sniffio@1.3.1 --output json
    //     { "reference": { "ecosystem": "py_p_i", ... } }
    //
    // `Ecosystem::from_purl_type("py_p_i")` is `None`, so the JSON document this tool prints
    // cannot be fed back into the tool, and a consumer joining the JSON output to anything keyed
    // on a PURL type finds nothing. One value must have one name.
    for e in every_ecosystem() {
        let word = serde_word(&e);
        assert_eq!(
            Ecosystem::from_purl_type(&word),
            Some(e),
            "{e:?} serializes as `{word}`, which its own parser rejects; the PURL type is `{}`",
            e.purl_type()
        );
    }
}

/// PURLs that occur, plus the ones whose parsing rules are load-bearing.
fn purls_that_must_round_trip() -> Vec<&'static str> {
    vec![
        // One per ecosystem, so a new ecosystem with a broken `purl_type` shows up here.
        "pkg:npm/left-pad@1.3.0",
        "pkg:pypi/sniffio@1.3.1",
        "pkg:cargo/serde@1.0.197",
        "pkg:gem/rake@13.2.1",
        "pkg:nuget/Newtonsoft.Json@13.0.3",
        "pkg:maven/org.apache.commons/commons-lang3@3.14.0",
        "pkg:github/stevemao/left-pad@v1.3.0",
        // A scoped npm name. The parser takes the version after the LAST `@` precisely so this
        // does not become a package called `babel/core@7.24.0`, which exists nowhere.
        "pkg:npm/@babel/core@7.24.0",
        // Versions with the characters real registries publish: semver prerelease and build
        // metadata, a PEP 440 epoch and post-release, and a `v` prefix on a GitHub tag.
        "pkg:npm/thing@2.0.0-rc.1+sha.5114f85",
        "pkg:pypi/thing@1!2.0.post1",
        "pkg:pypi/thing@1.0.0.dev20240101",
        "pkg:cargo/thing@0.1.0-alpha.1",
        // Qualifiers, which a wheel needs: a version is a dozen files and they do not reproduce
        // alike. Rendered from a BTreeMap, so the order is the sorted one whatever arrived.
        "pkg:pypi/cryptography@42.0.5?abi=cp39&arch=x86_64",
        "pkg:pypi/thing@1.0?empty=",
        // A multi-segment namespace, which is what makes a maven group work.
        "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.17.0",
    ]
}

#[test]
fn every_purl_shape_we_accept_survives_display_and_a_second_parse() {
    // Parse -> render -> parse. The store keys a run on `RunRecord::target`, a bare PURL string,
    // and the definitions tree and the attestation layout are directories built from the parsed
    // pieces. A coordinate that does not survive the trip is a run filed under a package that does
    // not exist.
    for s in purls_that_must_round_trip() {
        let once = TargetRef::from_str(s).unwrap_or_else(|e| panic!("`{s}` did not parse: {e}"));
        let rendered = once.to_string();
        assert_eq!(rendered, s, "`{s}` does not render as itself");
        let twice = TargetRef::from_str(&rendered)
            .unwrap_or_else(|e| panic!("`{rendered}`, our own output, did not parse: {e}"));
        assert_eq!(
            twice, once,
            "`{s}` is not the same coordinate after a round trip"
        );

        // And through the other door. A `TargetRef` is persisted as a PURL string in a run record
        // and as a serde struct inside every `ResolvedTarget`; both have to name one package.
        survives_json("TargetRef", &once);
        let as_json: TargetRef =
            serde_json::from_str(&serde_json::to_string(&once).unwrap()).unwrap();
        assert_eq!(
            as_json.to_string(),
            rendered,
            "`{s}` names a different package after going through serde"
        );
    }
}

#[test]
fn a_target_ref_built_by_hand_survives_the_purl_round_trip_for_every_ecosystem() {
    // The other direction. Everything above starts from a string; a resolver starts from a value,
    // and `registry_name()` is what it asks the registry for. npm rejoins the scope with a slash
    // and maven with a colon, and asking npm for `core` rather than `@babel/core` finds a
    // different package that exists and is unrelated.
    for e in every_ecosystem() {
        let plain = TargetRef::new(e, "thing", "1.0.0");
        let back = TargetRef::from_str(&plain.to_string()).unwrap();
        assert_eq!(back, plain, "{e:?} loses something with no namespace");
        assert_eq!(back.registry_name(), plain.registry_name());

        let scoped = TargetRef::new(e, "thing", "1.0.0").with_namespace("scope");
        let back = TargetRef::from_str(&scoped.to_string()).unwrap();
        assert_eq!(back, scoped, "{e:?} loses its namespace: `{}`", scoped);
        assert_eq!(
            back.registry_name(),
            scoped.registry_name(),
            "{e:?} asks the registry for a different name after a round trip"
        );

        let mut qualified = TargetRef::new(e, "thing", "1.0.0");
        qualified.qualifiers = BTreeMap::from([
            ("arch".to_string(), "x86_64".to_string()),
            ("abi".to_string(), "cp39".to_string()),
        ]);
        let back = TargetRef::from_str(&qualified.to_string()).unwrap();
        assert_eq!(back, qualified, "{e:?} loses its qualifiers");
    }
}

#[test]
fn an_alias_purl_type_normalizes_to_the_canonical_spelling_and_then_stops_moving() {
    // `from_purl_type` accepts `crates.io` and `rubygems` as well as the canonical `cargo` and
    // `gem`, because both spellings occur in the wild. The round trip is therefore not the
    // identity on the first pass — it is a *normalization*, and what matters is that it converges:
    // the second pass must be a fixed point, or the same package produces two store keys and two
    // attestation paths depending on how someone typed it.
    for (alias, canonical) in [
        ("pkg:crates.io/serde@1.0.197", "pkg:cargo/serde@1.0.197"),
        ("pkg:rubygems/rake@13.2.1", "pkg:gem/rake@13.2.1"),
    ] {
        let once = TargetRef::from_str(alias).unwrap();
        assert_eq!(once.to_string(), canonical, "`{alias}` did not normalize");
        let twice = TargetRef::from_str(&once.to_string()).unwrap();
        assert_eq!(twice, once, "`{canonical}` is not a fixed point");
        assert_eq!(twice.to_string(), canonical);
    }
}

#[test]
fn the_version_is_still_taken_after_the_last_at_sign_when_a_purl_is_rendered_back() {
    // The rule is commented in the parser and tested there on the way in. This is the way out: a
    // value carrying an unencoded `@` in its version renders a string that re-parses as a
    // *different* coordinate, and the split is what makes scoped npm names work, so this is a
    // stated limit of the subset rather than a case to guess at. Pinned so that "fixing" the
    // split to the first `@` — which would make this assertion pass — cannot happen without
    // breaking `pkg:npm/@babel/core@7.24.0` in the test above, loudly.
    let awkward = TargetRef::new(Ecosystem::Npm, "thing", "1.0.0+build@2");
    let back = TargetRef::from_str(&awkward.to_string()).unwrap();
    assert_ne!(
        back, awkward,
        "an unencoded `@` in a version is a documented limit; if this now round trips, the parser \
         changed and the scoped-name case needs re-checking"
    );
    assert_eq!(back.version, "2");
    assert_eq!(back.name, "thing@1.0.0+build");
}

#[test]
fn an_artifact_id_keeps_the_kind_its_filename_implies_across_the_wire() {
    // The filename is the identity: a version ships an sdist and eleven platform wheels built on
    // eleven machines, and a verdict about "cryptography 42.0.5" is not a claim anybody can check.
    // `kind()` is derived from the stored string, so the string has to come back byte-identical.
    for (name, kind) in [
        ("left-pad-1.3.0.tgz", ArtifactKind::Tarball),
        (
            "cryptography-42.0.5-cp39-abi3-manylinux_2_28_x86_64.whl",
            ArtifactKind::Wheel,
        ),
        ("sniffio-1.3.1.tar.gz", ArtifactKind::Sdist),
        ("serde-1.0.197.crate", ArtifactKind::Crate),
        ("rake-13.2.1.gem", ArtifactKind::Gem),
        ("Newtonsoft.Json.13.0.3.nupkg", ArtifactKind::Nupkg),
        ("weird name with spaces.bin", ArtifactKind::Other),
    ] {
        let id = ArtifactId::new(name);
        survives_json("ArtifactId", &id);
        let back: ArtifactId = serde_json::from_str(&serde_json::to_string(&id).unwrap()).unwrap();
        assert_eq!(back.kind(), kind, "{name} changed kind across the wire");
        assert_eq!(back.to_string(), name);
    }
    for k in every_artifact_kind() {
        survives_json("ArtifactKind", &k);
    }
}

// ---------------------------------------------------------------------------------------------
// Digests, which are the values a signature is about.
// ---------------------------------------------------------------------------------------------

#[test]
fn every_digest_form_round_trips_and_renders_exactly_one_canonical_spelling() {
    let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let d = Digest::from_hex(empty).unwrap();

    // Display, serde and `to_hex` are three renderings of one value; a digest quoted in a log and
    // a digest in a statement have to be comparable by eye and by `grep`.
    assert_eq!(d.to_string(), d.to_hex());
    assert_eq!(serde_word(&d), d.to_hex());
    survives_json("Digest", &d);

    // Parsing is case-insensitive; rendering is not. A registry that publishes uppercase hex
    // therefore normalizes on the way in, which is the only reason two digests for the same bytes
    // compare equal after coming from two sources.
    let upper = Digest::from_hex(&empty.to_uppercase()).unwrap();
    assert_eq!(upper, d);
    assert_eq!(
        upper.to_hex(),
        empty,
        "rendering must be lowercase, whatever was parsed"
    );

    // Every byte position, so a from_hex that dropped or transposed a nibble cannot hide behind a
    // uniform test vector.
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(3);
    }
    let d = Digest::from_bytes(bytes);
    assert_eq!(Digest::from_hex(&d.to_hex()).unwrap(), d);
    assert_eq!(d.as_bytes(), &bytes);
    survives_json("Digest", &d);

    // SHA-512 rides along on raw artifact digests only, because that is what a third party
    // cross-checks against a registry.
    let mut long = [0u8; 64];
    for (i, b) in long.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(11).wrapping_add(1);
    }
    let s = Sha512(long);
    assert_eq!(Sha512::from_hex(&s.to_hex()).unwrap(), s);
    survives_json("Sha512", &s);

    // And the pair, in both shapes. `sha512` is skipped when absent and defaulted when missing,
    // which is a two-sided contract: skip without default would make our own output unreadable.
    let only = MultiDigest::sha256_only(d);
    assert_eq!(
        serde_json::to_string(&only).unwrap(),
        format!("{{\"sha256\":\"{}\"}}", d.to_hex()),
        "an absent sha512 must be absent, not null"
    );
    survives_json("MultiDigest (sha256 only)", &only);
    survives_json(
        "MultiDigest (both)",
        &MultiDigest {
            sha256: d,
            sha512: Some(s),
        },
    );
}

#[test]
fn a_digest_nested_in_an_internally_tagged_enum_still_reads_back() {
    // `RegistryMoment::Lockfile` puts a `Digest` — a `transparent` newtype with a custom hex
    // `with` module — inside an internally tagged enum, which serde deserializes by buffering the
    // whole value first. That combination is the one that breaks quietly: the outer enum decides
    // it matched, the inner field fails, and what comes back is an error at a path nobody reads.
    // A lockfile digest is the strongest form of registry-moment evidence, so losing it silently
    // downgrades a build that resolves nothing to one that resolves against a timestamp.
    let d = Digest::from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        .unwrap();
    for m in [
        RegistryMoment::Lockfile { digest: d },
        RegistryMoment::Timestamp {
            rfc3339: "2024-02-25T23:20:01.196159Z".into(),
        },
        RegistryMoment::GitCommit {
            oid: "ae020e13b98d276a6558ffc25e82509fd4c288f0".into(),
        },
    ] {
        survives_json("RegistryMoment", &m);
    }
    let json = serde_json::to_value(RegistryMoment::Lockfile { digest: d }).unwrap();
    assert_eq!(json["kind"], "lockfile");
    assert_eq!(
        json["digest"],
        d.to_hex(),
        "the digest must stay a hex string, not become bytes"
    );
}

#[test]
fn an_entry_path_survives_json_with_its_non_utf8_bytes_intact() {
    // Held as bytes on purpose: real npm tarballs contain non-UTF-8 member paths and zip carries an
    // explicit non-UTF-8 flag. Ordering is over raw bytes, and the stabilized digest is computed
    // over members in that order, so a path that came back through a lossy conversion would sort
    // differently and change a signed digest for an artifact nobody touched.
    let nasty = EntryPath::new(vec![
        b'p', b'k', b'g', b'/', 0xff, 0xfe, b'/', 0xc3, b'n', b'a', b'm', b'e',
    ]);
    survives_json("EntryPath", &nasty);
    let back: EntryPath = serde_json::from_str(&serde_json::to_string(&nasty).unwrap()).unwrap();
    assert_eq!(
        back.as_bytes(),
        nasty.as_bytes(),
        "a byte was lost or replaced"
    );
    assert_eq!(back.file_name(), nasty.file_name());
    assert!(
        back.to_lossy().contains('\u{fffd}'),
        "the lossy view is for display only; the bytes above prove nothing was actually replaced"
    );

    // Ordering has to survive too, since it is what the digest depends on.
    let mut before = vec![
        EntryPath::from("a/b"),
        EntryPath::from("a.b"),
        EntryPath::from("a"),
    ];
    let mut after: Vec<EntryPath> = before
        .iter()
        .map(|p| serde_json::from_str(&serde_json::to_string(p).unwrap()).unwrap())
        .collect();
    before.sort();
    after.sort();
    assert_eq!(before, after);
}

// ---------------------------------------------------------------------------------------------
// Everything else that is written down.
// ---------------------------------------------------------------------------------------------

#[test]
fn every_persisted_core_value_survives_a_json_round_trip() {
    // One table rather than one test each, because the property is the same for all of them and a
    // type added to the crate without a line here is the gap this file exists to close.
    let d = Digest::from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        .unwrap();

    for c in every_note_code() {
        survives_json("NoteCode", &c);
        let back: NoteCode = serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
        assert_eq!(
            back.is_noteworthy(),
            c.is_noteworthy(),
            "{c:?} changed whether it reaches a human"
        );
        survives_json("Note", &Note::new(c, "a detail"));
        survives_json(
            "Note with a path",
            &Note::at(c, EntryPath::new(vec![0xff, b'/', b'x']), "a detail"),
        );
    }

    for s in every_source_discovery() {
        survives_json("SourceDiscovery", &s);
        survives_json(
            "SourceProvenance",
            &SourceProvenance {
                repo_url: "https://github.com/python-trio/sniffio".into(),
                // What the package said, before the trim that produced `repo_url`. A round trip
                // that never carried it would not notice it going missing.
                declared_url: Some("https://github.com/python-trio/sniffio/issues".into()),
                commit: "ae020e13b98d276a6558ffc25e82509fd4c288f0".into(),
                ref_name: Some("v1.3.1".into()),
                subdir: Some("packages/sniffio".into()),
                how: s,
            },
        );
    }

    // Every `Claim` shape, including the two with `Option` fields — an internally tagged enum plus
    // `Option` is the combination where a missing field and a null one stop meaning the same thing.
    let claims = vec![
        Claim::ToolchainRange {
            tool: "cargo".into(),
            lo: Some("1.60.0".into()),
            hi: None,
        },
        Claim::ToolchainRange {
            tool: "cargo".into(),
            lo: None,
            hi: None,
        },
        Claim::ToolchainExact {
            tool: "cargo".into(),
            version: "1.75.0".into(),
        },
        Claim::BuildBackend {
            backend: "setuptools".into(),
        },
        Claim::RegistryMomentIs {
            moment: RegistryMoment::Lockfile { digest: d },
        },
        Claim::RepoIs {
            url: "https://github.com/x/y".into(),
        },
        Claim::SubdirIs {
            path: "packages/core".into(),
        },
        Claim::PlatformIs {
            platform: "manylinux_2_28_x86_64".into(),
        },
        Claim::RequiresNetwork { required: false },
        Claim::UnrunScript {
            name: "build".into(),
            command: "tsc -p .".into(),
        },
    ];
    for c in &claims {
        match c {
            Claim::ToolchainRange { .. } => {}
            Claim::ToolchainExact { .. } => {}
            Claim::BuildBackend { .. } => {}
            Claim::RegistryMomentIs { .. } => {}
            Claim::RepoIs { .. } => {}
            Claim::SubdirIs { .. } => {}
            Claim::PlatformIs { .. } => {}
            Claim::RequiresNetwork { .. } => {}
            Claim::UnrunScript { .. } => {}
        }
        survives_json("Claim", c);
        survives_json(
            "Evidence",
            &Evidence::new(c.clone(), Confidence::Strong, "registry-metadata"),
        );
    }

    // The two outcomes that mean "escalate" are the ones worth carrying across a boundary intact:
    // an empty intersection and an unconstrained one are what a model is called for, and a
    // `Contradiction` that came back as a `Window` would send a build off with an invented answer.
    let evidence = vec![Evidence::new(
        Claim::ToolchainExact {
            tool: "cargo".into(),
            version: "1.75.0".into(),
        },
        Confidence::Certain,
        "manifest-fingerprint",
    )];
    for r in [
        ToolchainResolution::Pinned {
            version: "1.75.0".into(),
        },
        ToolchainResolution::Window {
            lo: Some("1.60.0".into()),
            hi: None,
        },
        ToolchainResolution::Window { lo: None, hi: None },
        ToolchainResolution::Contradiction {
            conflicting: evidence.clone(),
        },
        ToolchainResolution::Unconstrained,
    ] {
        match &r {
            ToolchainResolution::Pinned { .. } => {}
            ToolchainResolution::Window { .. } => {}
            ToolchainResolution::Contradiction { .. } => {}
            ToolchainResolution::Unconstrained => {}
        }
        let needs_help = r.needs_help();
        survives_json("ToolchainResolution", &r);
        let back: ToolchainResolution =
            serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(
            back.needs_help(),
            needs_help,
            "{r:?} changed whether it escalates"
        );
    }

    // `Intrinsics` is almost entirely `skip_serializing_if`. An empty one must render as `{}` and
    // read back as an empty one, or every target with no registry metadata becomes unreadable.
    let empty = Intrinsics::default();
    assert_eq!(serde_json::to_string(&empty).unwrap(), "{}");
    survives_json("Intrinsics (empty)", &empty);
    survives_json(
        "Intrinsics (full)",
        &Intrinsics {
            publish_time: Some("2024-02-25T23:20:01.196159Z".into()),
            declared_repo: Some("https://github.com/python-trio/sniffio".into()),
            registry_moment: Some(RegistryMoment::Timestamp {
                rfc3339: "2024-02-25T23:20:01.196159Z".into(),
            }),
            evidence: vec![Evidence::new(
                Claim::BuildBackend {
                    backend: "setuptools".into(),
                },
                Confidence::Certain,
                "pkg-info",
            )],
        },
    );

    survives_json(
        "Target",
        &Target::new(
            TargetRef::from_str("pkg:npm/@babel/core@7.24.0").unwrap(),
            ArtifactId::new("core-7.24.0.tgz"),
        ),
    );
    survives_json("ProfileId", &ProfileId::new("npm-tarball"));
    survives_json("StabilizerId", &StabilizerId::new("wheel-record"));
    survives_json(
        "Compressed",
        &Compressed {
            text: "error: no\n... 40 lines elided (progress)\n".into(),
            original_lines: 60_000,
            kept_lines: 42,
            original_bytes: 1_234_567,
        },
    );
}

#[test]
fn a_failure_signature_from_the_static_rule_table_reads_back_equal_and_keeps_its_key() {
    // `code` is a `Cow<'static, str>` for exactly this reason, stated in its own doc comment: serde
    // can only deserialize a `&'static str` from input that is itself `'static`, so the derive on
    // any struct containing one does not compile, and a signature that cannot be read back is no
    // use in a run record — which is where it has to end up. Construction from the table stays
    // allocation-free (`Cow::Borrowed`); only a value read back from JSON owns its bytes. The two
    // have to compare equal, because `key()` is the repair-cache key and the failure-cluster id,
    // and a borrowed key that did not match its own deserialized form would make every repair miss
    // its own cache on the second run.
    let lines = [
        "run.sh: line 3: yarn: command not found",
        "fatal error: Python.h: No such file or directory",
        "npm ERR! 503 Service Unavailable",
        "Killed",
        "something nobody has a rule for yet",
    ];
    let mut saw_a_borrowed_code = false;
    for line in lines {
        let sig = classify(line);
        if matches!(sig.code, Cow::Borrowed(_)) {
            saw_a_borrowed_code = true;
        }
        let key = sig.key();
        survives_json("FailureSignature", &sig);
        let back: FailureSignature =
            serde_json::from_str(&serde_json::to_string(&sig).unwrap()).unwrap();
        assert_eq!(back.key(), key, "the cache key changed for `{line}`");
        assert_eq!(
            back.code, sig.code,
            "a borrowed code does not equal its owned form"
        );
        assert_eq!(back.fault, sig.fault);
        assert_eq!(
            back.retryable, sig.retryable,
            "admission control reads this"
        );
        assert_eq!(
            back.repairable, sig.repairable,
            "admission control reads this"
        );
        assert_eq!(back.to_string(), key, "Display is the key");
    }
    assert!(
        saw_a_borrowed_code,
        "no rule fired, so the Cow::Borrowed path this test exists for was never exercised"
    );
}

// ---------------------------------------------------------------------------------------------
// Canonical JSON, which is what a signature actually covers.
// ---------------------------------------------------------------------------------------------

#[test]
fn everything_that_can_reach_a_signed_document_canonicalizes() {
    // The canonicalizer refuses floats and non-ASCII keys by design, and those refusals are the
    // right behaviour — but only as long as nothing we sign contains one. This is the assertion
    // that ties the two halves together: the day someone adds an `f64` field to a type that rides
    // into a statement, signing stops working, and it stops working at the point of signing rather
    // than here unless something checks.
    let d = Digest::from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        .unwrap();
    let values: Vec<(&str, serde_json::Value)> = vec![
        (
            "Match",
            serde_json::to_value(Match::NormalizedWithCaveats).unwrap(),
        ),
        ("RiskTier", serde_json::to_value(RiskTier::Content).unwrap()),
        (
            "Provenance",
            serde_json::to_value(Provenance::Builtin).unwrap(),
        ),
        ("Format", serde_json::to_value(Format::TarGz).unwrap()),
        (
            "MultiDigest",
            serde_json::to_value(MultiDigest::sha256_only(d)).unwrap(),
        ),
        (
            "EntryPath",
            serde_json::to_value(EntryPath::new(vec![0xff, b'/', b'x'])).unwrap(),
        ),
        (
            "Note",
            serde_json::to_value(Note::at(
                NoteCode::MemberContentDiffers,
                EntryPath::from("lib/index.js"),
                "differs",
            ))
            .unwrap(),
        ),
        (
            "Target",
            serde_json::to_value(Target::new(
                TargetRef::from_str("pkg:npm/@babel/core@7.24.0").unwrap(),
                ArtifactId::new("core-7.24.0.tgz"),
            ))
            .unwrap(),
        ),
        (
            "Compressed",
            serde_json::to_value(Compressed {
                text: "e\n".into(),
                original_lines: 3,
                kept_lines: 1,
                original_bytes: 9,
            })
            .unwrap(),
        ),
        (
            "FailureSignature",
            serde_json::to_value(classify("Killed")).unwrap(),
        ),
        (
            "Intrinsics",
            serde_json::to_value(Intrinsics {
                publish_time: Some("2024-02-25T23:20:01.196159Z".into()),
                declared_repo: None,
                registry_moment: Some(RegistryMoment::Lockfile { digest: d }),
                evidence: vec![Evidence::new(
                    Claim::RequiresNetwork { required: false },
                    Confidence::Certain,
                    "lockfile",
                )],
            })
            .unwrap(),
        ),
    ];
    for (label, v) in &values {
        let canon = jcs::canonicalize(v).unwrap_or_else(|e| {
            panic!("{label} cannot be canonicalized, so it cannot be signed: {e}")
        });
        // And the canonical bytes must survive being parsed and re-canonicalized, which is what a
        // verifier does before checking the signature.
        let reparsed: serde_json::Value = serde_json::from_str(&canon).unwrap();
        assert_eq!(
            jcs::canonicalize(&reparsed).unwrap(),
            canon,
            "{label} is not a fixed point"
        );
    }

    // `Compressed::ratio()` is the one `f64` in this crate. It is a method rather than a field,
    // which is why `Compressed` above canonicalizes at all; storing the ratio instead of computing
    // it would make every log record unsignable.
    assert!(
        jcs::canonicalize(&json!({"ratio": 7.5})).is_err(),
        "a float must still be refused, or the guard above proves nothing"
    );
}

#[test]
fn canonical_json_is_byte_stable_for_the_same_value_built_three_ways() {
    // A signature covers the canonical bytes. Two writers that build the same document differently
    // — one from a literal, one field by field, one by parsing text a third party sent — must
    // produce the same bytes, or a statement signed by one does not verify for the other.
    let literal = json!({
        "outcome": "normalized",
        "archiveFormat": "tar+gzip",
        "applied": [{"id": "tar-mode", "risk": "structural"}],
        "provenanceCap": {"allBuiltin": true, "maxRiskApplied": "structural"},
    });

    let mut cap = serde_json::Map::new();
    cap.insert("maxRiskApplied".into(), json!("structural"));
    cap.insert("allBuiltin".into(), json!(true));
    let mut built = serde_json::Map::new();
    built.insert("provenanceCap".into(), serde_json::Value::Object(cap));
    built.insert(
        "applied".into(),
        json!([{"risk": "structural", "id": "tar-mode"}]),
    );
    built.insert("archiveFormat".into(), json!("tar+gzip"));
    built.insert("outcome".into(), json!("normalized"));
    let built = serde_json::Value::Object(built);

    let from_text: serde_json::Value = serde_json::from_str(
        r#"{ "provenanceCap" : { "allBuiltin" : true , "maxRiskApplied" : "structural" } ,
             "applied" : [ { "id" : "tar-mode" , "risk" : "structural" } ] ,
             "archiveFormat" : "tar+gzip" , "outcome" : "normalized" }"#,
    )
    .unwrap();

    let a = jcs::canonicalize(&literal).unwrap();
    let b = jcs::canonicalize(&built).unwrap();
    let c = jcs::canonicalize(&from_text).unwrap();
    assert_eq!(a, b, "insertion order reached the canonical form");
    assert_eq!(a, c, "whitespace in the source reached the canonical form");

    // Array order is meaning, not spelling, and must not be normalized away.
    let reordered = json!({"applied": [{"id": "b"}, {"id": "a"}]});
    assert_ne!(
        jcs::canonicalize(&reordered).unwrap(),
        jcs::canonicalize(&json!({"applied": [{"id": "a"}, {"id": "b"}]})).unwrap(),
        "sorting an array would change what the document says"
    );
}

#[test]
fn a_non_ascii_qualifier_key_is_refused_by_the_canonicalizer_rather_than_ordered_by_guess() {
    // The one path by which attacker-influenced text becomes an object *key* in a document we
    // sign: PURL qualifiers are parsed from a string and land in a `BTreeMap`. `BTreeMap` orders by
    // UTF-8 bytes; JCS orders by UTF-16 code unit; the two disagree above the BMP. The
    // canonicalizer refuses rather than implementing half of that ordering, and this pins that the
    // refusal actually covers the qualifier path rather than only hand-built maps.
    let mut t = TargetRef::new(Ecosystem::PyPI, "thing", "1.0");
    t.qualifiers.insert("plataforma\u{e9}".into(), "x".into());
    let v = serde_json::to_value(&t).unwrap();
    let e = jcs::canonicalize(&v).unwrap_err();
    assert!(
        matches!(e, jcs::CanonError::NonAsciiKey(_)),
        "a non-ASCII qualifier key must be refused, not ordered by guess: {e:?}"
    );
    assert!(
        e.to_string().contains("UTF-16"),
        "the error should say why: {e}"
    );

    // An ASCII key with a non-ASCII *value* is fine: JCS escapes nothing above 0x1f in strings.
    let mut ok = TargetRef::new(Ecosystem::PyPI, "thing", "1.0");
    ok.qualifiers.insert("note".into(), "caf\u{e9}".into());
    let canon = jcs::canonicalize(&serde_json::to_value(&ok).unwrap()).unwrap();
    assert!(
        canon.contains("caf\u{e9}"),
        "a non-ASCII value must pass through unescaped: {canon}"
    );
}
