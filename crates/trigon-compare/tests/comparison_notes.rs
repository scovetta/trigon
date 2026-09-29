//! What a comparison says about membership, and how its failures are classified.
//!
//! `docs/02-domain-model.md` §5 puts notes on `Comparison`: one per differing member, named, because
//! "four members differ" is an accusation and a path is a thing to go and look at. The four
//! membership codes were once declared and never constructed; these hold each of them to the case
//! it describes, including the direction of the two one-sided ones, which a reader acts on.

use trigon_archive::{ArchiveError, Limits};
use trigon_compare::{CompareError, Comparison, FileStatus, compare_bytes};
use trigon_core::{Classify, EntryPath, Fault, Format, Match, NoteCode, ProfileId};
use trigon_stabilize::profile;

fn tar_of(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = ::tar::Builder::new(Vec::new());
    for (name, body) in members {
        let mut h = ::tar::Header::new_ustar();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, name, *body).unwrap();
    }
    b.into_inner().unwrap()
}

fn compare_tars(upstream: &[(&str, &[u8])], rebuild: &[(&str, &[u8])]) -> Comparison {
    compare_bytes(
        tar_of(upstream),
        tar_of(rebuild),
        Format::Tar,
        &profile("tar").unwrap(),
        &Limits::default(),
    )
    .unwrap()
}

/// `(code, path, detail)` for every note the comparison made, in the order it made them.
fn notes(c: &Comparison) -> Vec<(NoteCode, String, String)> {
    c.notes
        .iter()
        .map(|n| {
            let path = n.path.as_ref().expect("a membership note names its member");
            (n.code, path.to_lossy().into_owned(), n.detail.clone())
        })
        .collect()
}

#[test]
fn a_member_only_the_rebuild_has_is_noted_as_the_rebuilds() {
    let c = compare_tars(
        &[("pkg/a.txt", b"same")],
        &[("pkg/a.txt", b"same"), ("pkg/generated.txt", b"extra")],
    );
    assert_eq!(c.outcome, Match::Divergent);
    let d = c.diff.as_ref().unwrap();
    assert_eq!((d.only_upstream, d.only_rebuild, d.identical), (0, 1, 1));
    let f = d
        .files
        .iter()
        .find(|f| f.status == FileStatus::OnlyRebuild)
        .unwrap();
    assert_eq!(f.path, EntryPath::from("pkg/generated.txt"));
    assert!(f.upstream_digest.is_none() && f.rebuild_digest.is_some());

    assert_eq!(
        notes(&c),
        vec![(
            NoteCode::MemberOnlyInRebuild,
            "pkg/generated.txt".to_string(),
            "in the rebuild and not the published artifact".to_string(),
        )]
    );
}

#[test]
fn every_differing_member_gets_one_note_of_its_own_kind_and_an_identical_one_gets_none() {
    let c = compare_tars(
        &[
            ("pkg/README.md", b"upstream docs"),
            ("pkg/lib.so", b"\x7fELF-one"),
            ("pkg/only-published.txt", b"x"),
            ("pkg/same.txt", b"same"),
        ],
        &[
            ("pkg/README.md", b"rebuilt docs!"),
            ("pkg/lib.so", b"\x7fELF-two"),
            ("pkg/same.txt", b"same"),
        ],
    );
    let differ = "the two copies differ".to_string();
    assert_eq!(
        notes(&c),
        vec![
            (
                NoteCode::MemberContentDiffers,
                "pkg/README.md".into(),
                differ.clone()
            ),
            // Named as executable, not merely as differing: that is the distinction the verdict
            // turns on, and the note that reaches a human even on a clean match.
            (
                NoteCode::ExecutableContentDiffers,
                "pkg/lib.so".into(),
                differ
            ),
            (
                NoteCode::MemberOnlyInUpstream,
                "pkg/only-published.txt".into(),
                "in the published artifact and not the rebuild".into(),
            ),
        ]
    );
    assert!(NoteCode::ExecutableContentDiffers.is_noteworthy());
}

#[test]
fn a_match_carries_no_membership_notes() {
    let c = compare_tars(&[("pkg/a.txt", b"same")], &[("pkg/a.txt", b"same")]);
    assert_eq!(c.outcome, Match::Exact);
    assert!(c.notes.is_empty(), "{:?}", c.notes);
}

// --- classification -------------------------------------------------------------------------------

/// One of each archive error, built fresh each call because `ArchiveError` is not `Clone`.
fn archive_errors() -> Vec<ArchiveError> {
    vec![
        ArchiveError::Io(std::io::Error::other("disk went away")),
        ArchiveError::Malformed {
            format: "tar",
            detail: "bad checksum".into(),
        },
        ArchiveError::LimitExceeded {
            limit: "total_expanded_bytes",
            actual: 2,
            allowed: 1,
        },
        ArchiveError::Unsupported("zip compression method 99".into()),
    ]
}

#[test]
fn a_comparison_that_failed_in_the_parser_is_classified_as_the_parser_classified_it() {
    // Delegated rather than restated: a malformed artifact is the artifact's fault whether the
    // parser was reached through a comparison or directly.
    for (direct, wrapped) in archive_errors().into_iter().zip(archive_errors()) {
        let wrapped = CompareError::from(wrapped);
        assert_eq!(wrapped.fault(), direct.fault(), "{direct}");
        assert_eq!(wrapped.is_retryable(), direct.is_retryable(), "{direct}");
        assert_eq!(wrapped.to_string(), direct.to_string(), "transparent");
    }
}

#[test]
fn comparing_across_stabilizer_sets_is_our_bug_and_retrying_cannot_fix_it() {
    let e = CompareError::SetMismatch(ProfileId::new("tar"), ProfileId::new("wheel"));
    assert_eq!(e.fault(), Fault::Bug);
    assert!(!e.is_retryable());
    let msg = e.to_string();
    assert!(msg.contains("tar") && msg.contains("wheel"), "{msg}");
}

#[test]
fn an_artifact_that_will_not_parse_fails_the_comparison_as_the_artifacts_fault() {
    let e = compare_bytes(
        b"not a zip at all".to_vec(),
        b"not a zip at all".to_vec(),
        Format::Zip,
        &profile("zip").unwrap(),
        &Limits::default(),
    )
    .unwrap_err();
    assert!(
        matches!(e, CompareError::Archive(ArchiveError::Malformed { .. })),
        "{e:?}"
    );
    assert_eq!(e.fault(), Fault::Upstream);
    assert!(
        !e.is_retryable(),
        "the same bytes fetched again are the same bytes"
    );
}
