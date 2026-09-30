//! A record signed before a pass was renamed is re-derived under the set it was signed with.
//!
//! The set digest covers each pass's id, stage, risk and provenance, and not its code
//! (`docs/19-distribution-and-lookup.md` §11, open question 1). So a pass whose observable
//! behaviour changes has to change its id, or a record signed under the old behaviour is re-derived
//! under the new one with the digest it was signed with, and an honest record reads as refuted.
//!
//! `wheel-record` is the case. Its RECORD was always the same bytes; what changed in 62781a8 is
//! that an archive pass that rewrites a member's body is now attributed, so a wheel comparison's
//! field edits name RECORD's `body` as rewritten by it, and a comparison report published before
//! that does not carry the edit. The pass became `wheel-record-v2`, which moved the `wheel` set's
//! digest, so an old record is refused by today's set and re-derived through its archived one.
//!
//! Two of the set's passes have been renamed since, for changes of their own
//! (`docs/16-findings.md` §3.106): the RECORD pass is `wheel-record-v3` and `pyc-header` is
//! `pyc-header-v2`. The published set is rebuilt here from today's by giving both their old ids.

use std::io::Write as _;
use std::sync::Arc;

use trigon_archive::{Archive, Entry, Limits};
use trigon_attest::{ArchivedStabilizer, AttestError, Statement, rederive, rederive_with};
use trigon_compare::compare_bytes;
use trigon_core::{Digest, Format, Match, Provenance, RiskTier, StabilizerId};
use trigon_stabilize::{Cx, Stabilizer, StabilizerSet, profile};

/// The `wheel` set's digest before 62781a8, which every wheel record signed until then names.
const PUBLISHED: &str = "58632c3c627d30f9ddd01c3b2f8ae292e89af5e2b6f0893fc4cfba4e5a7d425d";

/// Today's pass under the id it was published with. On the wheels this file builds, which ship
/// no `.pyc` and one `.dist-info`, each writes what it wrote then.
#[derive(Debug)]
struct AsPublished(&'static str, Arc<dyn Stabilizer>);

impl Stabilizer for AsPublished {
    fn id(&self) -> StabilizerId {
        StabilizerId::new(self.0)
    }
    fn stage(&self) -> trigon_stabilize::Stage {
        self.1.stage()
    }
    fn risk(&self) -> RiskTier {
        self.1.risk()
    }
    fn provenance(&self) -> Provenance {
        self.1.provenance()
    }
    fn applies(&self, cx: &Cx) -> bool {
        self.1.applies(cx)
    }
    fn on_archive(&self, a: &mut Archive, cx: &Cx) -> trigon_stabilize::Touched {
        self.1.on_archive(a, cx)
    }
    fn on_entry(&self, e: &mut Entry, cx: &Cx) -> trigon_stabilize::Touched {
        self.1.on_entry(e, cx)
    }
}

/// The `wheel` set as it was published: today's, with the renamed passes under their old ids.
fn as_published() -> StabilizerSet {
    let members = profile("wheel")
        .unwrap()
        .members
        .into_iter()
        .map(|m| match m.id().as_str() {
            "wheel-record-v3" => Arc::new(AsPublished("wheel-record", m)) as Arc<dyn Stabilizer>,
            "pyc-header-v2" => Arc::new(AsPublished("pyc-header", m)) as Arc<dyn Stabilizer>,
            _ => m,
        })
        .collect();
    StabilizerSet::new("wheel", members)
}

/// The module a verifier would load for the published set: stabilized bytes, and no report.
struct Archived;

impl ArchivedStabilizer for Archived {
    fn digest(&mut self, profile_id: &str) -> Result<Digest, String> {
        match profile_id {
            "wheel" => Ok(as_published().digest()),
            other => Err(format!("this module carries `wheel`, not `{other}`")),
        }
    }

    fn stabilize(&mut self, _: &str, format: Format, bytes: &[u8]) -> Result<Vec<u8>, String> {
        let (_, archive) =
            trigon_compare::summarize(bytes.to_vec(), format, &as_published(), &Limits::default())
                .map_err(|e| e.to_string())?;
        trigon_archive::serialize(&archive, true).map_err(|e| e.to_string())
    }
}

/// A wheel whose RECORD its builder wrote in an order of its own, so the RECORD pass rewrites it.
fn wheel(method: zip::CompressionMethod, year: u16, record: &str) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default()
        .compression_method(method)
        .last_modified_time(zip::DateTime::from_date_and_time(year, 1, 1, 0, 0, 0).unwrap());
    for (name, body) in [
        ("pkg/__init__.py", "x = 1\n"),
        (
            "pkg-1.0.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: pkg\nVersion: 1.0\n",
        ),
        (
            "pkg-1.0.dist-info/WHEEL",
            "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        ),
        ("pkg-1.0.dist-info/RECORD", record),
    ] {
        w.start_file(name, opts).unwrap();
        w.write_all(body.as_bytes()).unwrap();
    }
    w.finish().unwrap().into_inner()
}

fn pair() -> (Vec<u8>, Vec<u8>) {
    (
        wheel(
            zip::CompressionMethod::Stored,
            2021,
            "pkg/__init__.py,,\npkg-1.0.dist-info/RECORD,,\n",
        ),
        wheel(
            zip::CompressionMethod::Deflated,
            2024,
            "pkg-1.0.dist-info/RECORD,,\npkg/__init__.py,sha256=stale,6\n",
        ),
    )
}

/// A comparison report as the code before 62781a8 wrote it: every field edit but the one an
/// archive pass made to a body, which nothing then attributed.
fn written_before_attribution(c: &trigon_compare::Comparison) -> Vec<u8> {
    let mut report = serde_json::to_value(c).unwrap();
    let edits = report["diff"]["field_edits"].as_array_mut().unwrap();
    let before = edits.len();
    edits.retain(|e| !(e["path"] == "pkg-1.0.dist-info/RECORD" && e["field"] == "body"));
    assert!(
        edits.len() < before && !edits.is_empty(),
        "the scenario needs a RECORD body edit and another beside it: {report}"
    );
    serde_json::to_vec(&report).unwrap()
}

#[test]
fn the_new_id_alone_is_what_moved_the_wheel_digest() {
    // The published set is today's with the renamed ids changed back, and it hashes to the digest
    // records were signed under: nothing else about the set moved, and the ids are what moved it.
    assert_eq!(as_published().digest().to_hex(), PUBLISHED);
    assert_ne!(profile("wheel").unwrap().digest().to_hex(), PUBLISHED);
}

#[test]
fn a_record_naming_wheel_record_is_re_derived_through_its_archived_set_and_never_refuted() {
    let (upstream, rebuild) = pair();
    let c = compare_bytes(
        upstream.clone(),
        rebuild.clone(),
        Format::Zip,
        &as_published(),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(c.outcome, Match::NormalizedWithCaveats);
    let st = Statement::equivalence("pkg-1.0-py3-none-any.whl", &c);
    assert_eq!(st.predicate["stabilizerSet"]["digest"]["sha256"], PUBLISHED);
    let applied: Vec<&str> = st.predicate["applied"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["id"].as_str().unwrap())
        .collect();
    assert!(applied.contains(&"wheel-record"), "{applied:?}");
    let report = written_before_attribution(&c);

    // Today's set is not the one it was signed under, and says so: a set mismatch, which is not a
    // refutation, never a re-derivation under the wrong set.
    let e = rederive(&st, upstream.clone(), rebuild.clone()).unwrap_err();
    let AttestError::SetMismatch { claimed, current } = &e else {
        panic!("expected a set mismatch, got {e}");
    };
    assert_eq!(claimed, &format!("wheel@{}", &PUBLISHED[..12]));
    let today = profile("wheel").unwrap().digest().to_hex();
    assert_eq!(current, &format!("wheel@{}", &today[..12]));
    assert!(!e.fails_verification(), "{e}");

    // Its archived set re-derives it: the outcome and both stabilized digests hold, and what an
    // archived set cannot give — the report, and what the verdict says the comparison found — is
    // unchecked, never refuted.
    let d = rederive_with(&st, upstream, rebuild, Some(&mut Archived)).unwrap();
    assert!(d.holds(), "{d:?}");
    assert_eq!(d.actual, Match::NormalizedWithCaveats);
    assert_eq!(d.unchecked, ["differences", "applied", "members"]);
    assert_eq!(d.check_report(&report).unwrap(), None);
}

#[test]
fn under_an_unchanged_digest_an_honest_report_would_have_read_as_refuted() {
    // What the new id prevents. A record whose set digest is today's is re-derived natively, and
    // its report is held to the field edits re-deriving gives; one written before an archive
    // pass's body edit was attributed disagrees on exactly that, though nothing in it is false.
    let (upstream, rebuild) = pair();
    let set = profile("wheel").unwrap();
    let c = compare_bytes(
        upstream.clone(),
        rebuild.clone(),
        Format::Zip,
        &set,
        &Limits::default(),
    )
    .unwrap();
    let st = Statement::equivalence("pkg-1.0-py3-none-any.whl", &c);
    let d = rederive(&st, upstream, rebuild).unwrap();
    assert!(d.holds(), "{d:?}");
    let checked = d
        .check_report(&written_before_attribution(&c))
        .unwrap()
        .expect("re-derived natively, so the report is held to it");
    let fields: Vec<&str> = checked.disagreements.iter().map(|x| x.field).collect();
    assert_eq!(fields, ["diff.field_edits"], "{:?}", checked.disagreements);
    assert!(
        checked.disagreements[0]
            .to_string()
            .contains("pkg-1.0.dist-info/RECORD"),
        "{}",
        checked.disagreements[0]
    );
}
