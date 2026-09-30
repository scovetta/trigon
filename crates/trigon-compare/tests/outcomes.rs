//! What `compare` decides, and why.
//!
//! The provenance cap is the invariant the whole design rests on, so it gets tested from both
//! sides: a builtin-only run reaches `Normalized`, and the same run with one model-authored pass
//! reaches `NormalizedWithCaveats` and no further.

use std::sync::Arc;

use trigon_archive::{Entry, Limits};
use trigon_compare::{CompareError, FileStatus, compare_bytes, summarize};
use trigon_core::{Format, Match, Provenance, RiskTier, StabilizerId};
use trigon_stabilize::{Cx, Stabilizer, StabilizerSet, Touched, profile};

/// A tar whose members are fixed but whose build-environment metadata varies.
fn tar(mtime: u64, uid: u64, body: &[u8]) -> Vec<u8> {
    let mut b = ::tar::Builder::new(Vec::new());
    for (name, content) in [("pkg/a.txt", body), ("pkg/b.txt", b"constant")] {
        let mut h = ::tar::Header::new_ustar();
        h.set_size(content.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(mtime);
        h.set_uid(uid);
        h.set_cksum();
        b.append_data(&mut h, name, content).unwrap();
    }
    b.into_inner().unwrap()
}

fn gz(payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    trigon_archive::gzip::write(
        &trigon_archive::GzipHeader::default(),
        payload,
        flate2::Compression::default(),
        &mut v,
    )
    .unwrap();
    v
}

#[test]
fn identical_bytes_are_exact() {
    let a = tar(1, 1, b"same");
    let c = compare_bytes(
        a.clone(),
        a,
        Format::Tar,
        &profile("tar").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(c.outcome, Match::Exact);
    assert_eq!(c.upstream.raw.sha256, c.rebuild.raw.sha256);
    // Exact means no transform was needed, so nothing should have fired on either side.
    assert!(c.applied().is_empty() || c.upstream.stabilized == c.rebuild.stabilized);
}

#[test]
fn metadata_only_differences_are_normalized() {
    let c = compare_bytes(
        tar(1_700_000_000, 1000, b"same"),
        tar(1_500_000_000, 501, b"same"),
        Format::Tar,
        &profile("tar").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(c.outcome, Match::Normalized);
    assert_ne!(c.upstream.raw.sha256, c.rebuild.raw.sha256);
    assert_eq!(c.upstream.stabilized.sha256, c.rebuild.stabilized.sha256);
    assert!(
        c.cap_reason().is_none(),
        "a builtin-only run should not be capped"
    );
}

#[test]
fn content_differences_are_divergent() {
    let c = compare_bytes(
        tar(1, 1, b"upstream"),
        tar(1, 1, b"rebuilt!"),
        Format::Tar,
        &profile("tar").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(c.outcome, Match::Divergent);
    let d = c.diff.as_ref().unwrap();
    assert_eq!(d.differs, 1);
    assert_eq!(d.identical, 1);
    let f = d
        .files
        .iter()
        .find(|f| f.status == FileStatus::Differs)
        .unwrap();
    assert_eq!(f.path.to_lossy(), "pkg/a.txt");
    assert_ne!(f.upstream_digest, f.rebuild_digest);
}

// --- the provenance cap ---------------------------------------------------------------------------

/// A pass that does exactly what `tar-owners` does, but claims a model wrote it.
///
/// Its only purpose is to prove the cap fires on provenance rather than on behaviour.
#[derive(Debug)]
struct ModelAuthored;

impl Stabilizer for ModelAuthored {
    fn id(&self) -> StabilizerId {
        StabilizerId::new("test-model-authored")
    }
    fn risk(&self) -> RiskTier {
        RiskTier::Metadata
    }
    fn provenance(&self) -> Provenance {
        Provenance::Model {
            model_id: "claude-opus-5".into(),
            run_id: "01J".into(),
        }
    }
    fn applies(&self, _cx: &Cx) -> bool {
        true
    }
    fn on_entry(&self, e: &mut Entry, _cx: &Cx) -> Touched {
        if let trigon_archive::RawMeta::Tar(raw) = &mut e.raw {
            if raw.uid != 0 {
                raw.uid = 0;
                e.mark_dirty();
                return Touched::entry();
            }
        }
        Touched::NONE
    }
}

/// A pass that rewrites bytes inside a distributed file. Builtin, and above `Metadata` risk.
#[derive(Debug)]
struct ContentRewrite;

impl Stabilizer for ContentRewrite {
    fn id(&self) -> StabilizerId {
        StabilizerId::new("test-content-rewrite")
    }
    fn risk(&self) -> RiskTier {
        RiskTier::Content
    }
    fn applies(&self, _cx: &Cx) -> bool {
        true
    }
    fn on_entry(&self, e: &mut Entry, _cx: &Cx) -> Touched {
        if e.path.ends_with(b"a.txt") {
            if let Ok(b) = e.body_mut() {
                b.iter_mut().for_each(|x| *x = b'X');
                return Touched::entry_bytes(b.len() as u64);
            }
        }
        Touched::NONE
    }
}

fn set_with(extra: Arc<dyn Stabilizer>) -> StabilizerSet {
    let mut members = profile("tar").unwrap().members;
    members.push(extra);
    StabilizerSet::new("tar+test", members)
}

/// A set where a model-authored pass stands in for a builtin one rather than duplicating it.
///
/// Duplicating is the realistic mistake and it hides the cap: `tar-owners` sorts first, does the
/// work, and the model pass then finds nothing to do and correctly does not cap anything.
fn set_replacing_owners(extra: Arc<dyn Stabilizer>) -> StabilizerSet {
    let base = profile("tar")
        .unwrap()
        .filtered(&["all".into()], &["tar-owners".into()]);
    let mut members = base.members;
    members.push(extra);
    StabilizerSet::new("tar-minus-owners+test", members)
}

#[test]
fn a_model_authored_pass_caps_the_outcome() {
    let set = set_replacing_owners(Arc::new(ModelAuthored));
    assert!(
        !set.members.iter().any(|m| m.id().as_str() == "tar-owners"),
        "filtered() should have removed the builtin this pass stands in for"
    );
    let c = compare_bytes(
        tar(1_700_000_000, 1000, b"same"),
        tar(1_500_000_000, 501, b"same"),
        Format::Tar,
        &set,
        &Limits::default(),
    )
    .unwrap();

    // The digests still agree. The cap is about who wrote the transform, not whether it worked.
    assert_eq!(c.upstream.stabilized.sha256, c.rebuild.stabilized.sha256);
    assert_eq!(c.outcome, Match::NormalizedWithCaveats);
    assert!(c.cap_reason().unwrap().contains("test-model-authored"));
    assert!(!c.outcome.is_at_least(Match::Normalized));
}

#[test]
fn a_content_risk_pass_caps_the_outcome_too() {
    // Provenance is not the only cap: risk above Metadata does it as well, and for the same reason.
    let set = set_with(Arc::new(ContentRewrite));
    let c = compare_bytes(
        tar(1_700_000_000, 1000, b"aaaaaaaa"),
        tar(1_500_000_000, 501, b"bbbbbbbb"),
        Format::Tar,
        &set,
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(c.upstream.stabilized.sha256, c.rebuild.stabilized.sha256);
    assert_eq!(c.outcome, Match::NormalizedWithCaveats);
    assert!(c.cap_reason().unwrap().contains("Content"));
}

#[test]
fn a_capped_pass_that_does_nothing_does_not_cap() {
    // `applied` reports only passes that changed something, so a model-authored pass that found
    // nothing to do leaves the clean tier reachable. A pass that was merely configured has no
    // business in the predicate.
    let set = set_with(Arc::new(ModelAuthored));
    let already_zero_uid = tar(1_700_000_000, 0, b"same");
    let other = tar(1_500_000_000, 0, b"same");
    let c = compare_bytes(
        already_zero_uid,
        other,
        Format::Tar,
        &set,
        &Limits::default(),
    )
    .unwrap();
    assert!(
        !c.applied()
            .iter()
            .any(|a| a.id.as_str() == "test-model-authored"),
        "a pass that changed nothing must not appear in applied"
    );
    assert_eq!(c.outcome, Match::Normalized);
}

// --- containers, sets, and reports ---------------------------------------------------------------

#[test]
fn container_digest_separates_framing_from_content() {
    let inner = tar(1, 1, b"same");
    // Same tar, two different gzip framings.
    let a = gz(&inner);
    let mut b = Vec::new();
    trigon_archive::gzip::write(
        &trigon_archive::GzipHeader {
            os: 3,
            mtime: Some(99),
            ..Default::default()
        },
        &inner,
        flate2::Compression::none(),
        &mut b,
    )
    .unwrap();

    let c = compare_bytes(
        a,
        b,
        Format::TarGz,
        &profile("tar-gzip").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    assert_ne!(
        c.upstream.raw.sha256, c.rebuild.raw.sha256,
        "the framings differ"
    );
    assert_eq!(
        c.container_bit_identical(),
        Some(true),
        "the tars are identical"
    );
    assert_eq!(c.outcome, Match::Normalized);
}

/// A tar of one member, `pkg/extra.js`, that no rebuild of `tar` produces.
fn injected() -> Vec<u8> {
    let mut b = ::tar::Builder::new(Vec::new());
    let mut h = ::tar::Header::new_ustar();
    h.set_size(8);
    h.set_mode(0o644);
    h.set_mtime(1);
    h.set_uid(1);
    h.set_cksum();
    b.append_data(&mut h, "pkg/extra.js", &b"injected"[..])
        .unwrap();
    b.into_inner().unwrap()
}

/// `member` with the CRC-32 its trailer stores replaced by that of `content`.
fn with_crc_of(mut member: Vec<u8>, content: &[u8]) -> Vec<u8> {
    let mut crc = flate2::Crc::new();
    crc.update(content);
    let n = member.len();
    member[n - 8..n - 4].copy_from_slice(&crc.sum().to_le_bytes());
    member
}

#[test]
fn a_second_gzip_member_holding_data_is_never_skipped_and_never_matched() {
    // Node's zlib and Python's gzip read every member of a `.tgz` or an sdist, so tar entries in
    // a second member are part of what installs. The reader took the file's last eight bytes as
    // the first member's trailer, and a second member whose CRC was forged to the first's made
    // the published artifact stabilize to the digest of an honest rebuild of the first alone.
    // Cargo and RubyGems read the first member and stop, so the readers disagree about what such a
    // file holds, and it is refused however it is framed (`docs/16-findings.md` §3.106).
    let p = tar(1, 1, b"same");
    // Without its end-of-archive blocks, so the second member's tar carries straight on from it.
    let p_open = &p[..p.len() - 1024];
    let q = injected();
    let set = profile("tar-gzip").unwrap();
    let judge = |upstream: Vec<u8>| {
        compare_bytes(upstream, gz(&p), Format::TarGz, &set, &Limits::default())
    };
    for (how, upstream) in [
        // Forged: the second member's CRC is not its own.
        ("forged", [gz(p_open), with_crc_of(gz(&q), p_open)].concat()),
        // Honest framing, and still two readings of one file.
        ("honest", [gz(p_open), gz(&q)].concat()),
    ] {
        match judge(upstream) {
            Err(CompareError::Archive(trigon_archive::ArchiveError::Malformed {
                format,
                detail,
            })) => {
                assert_eq!(format, "gzip", "{how}");
                assert!(
                    detail.contains("holds data after a first member"),
                    "{how}: {detail}"
                )
            }
            other => panic!(
                "{how}: expected a refusal, got {:?}",
                other.map(|c| c.outcome)
            ),
        }
    }
}

#[test]
fn bytes_after_the_last_gzip_member_are_a_named_difference_and_not_a_match() {
    // The same tar either way; one side carries bytes after its member that begin no other.
    // gunzip ignores them with a warning, so they are framing — but framing a stabilizer does not
    // remove, and a verdict that dropped them would call two different files one.
    let inner = tar(1, 1, b"same");
    let c = compare_bytes(
        [gz(&inner), b"appended after the member".to_vec()].concat(),
        gz(&inner),
        Format::TarGz,
        &profile("tar-gzip").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(c.container_bit_identical(), Some(true), "one tar");
    assert_eq!(c.outcome, Match::Divergent);
    let codes = &c.diff.as_ref().unwrap().codes;
    assert_eq!(
        codes.iter().collect::<Vec<_>>(),
        ["container:gzip.trailing"],
        "the one difference, named"
    );
}

#[test]
fn a_lone_zero_block_ahead_of_more_entries_is_refused_rather_than_read_as_the_end() {
    // node-tar, which npm installs with, ends an archive only at two zero blocks in a row and reads
    // on past one. The `tar` crate, GNU tar and Python stop at the first. So entries after a lone
    // zero block installed from npm and were never seen here, and the published artifact matched an
    // honest rebuild without them. Readers that disagree on what an archive holds leave no one
    // answer to compare. Put behind a gzip member boundary, the zero block is refused sooner, by
    // the gzip reader, for the same reason: a second member that holds data is read by some
    // readers and not by others.
    let p = tar(1, 1, b"same");
    let p_open = &p[..p.len() - 1024];
    let q = injected();
    let set = profile("npm-tarball").unwrap();
    for (upstream, how, refused_by, why) in [
        (
            gz(&[p_open, &[0; 512], &q].concat()),
            "one member",
            "tar",
            "lone zero block",
        ),
        (
            [gz(p_open), gz(&[&[0; 512], &q[..]].concat())].concat(),
            "the zero block opening a second member",
            "gzip",
            "holds data after a first member",
        ),
    ] {
        match compare_bytes(upstream, gz(&p), Format::TarGz, &set, &Limits::default()) {
            Err(CompareError::Archive(trigon_archive::ArchiveError::Malformed {
                format,
                detail,
            })) => {
                assert_eq!(format, refused_by, "{how}");
                assert!(detail.contains(why), "{how}: {detail}");
            }
            other => panic!(
                "{how}: expected a refusal, got {:?}",
                other.map(|c| c.outcome)
            ),
        }
    }
}

#[test]
fn bytes_after_the_tar_end_of_archive_marker_are_a_named_difference_and_not_a_match() {
    // After two zero blocks every reader has stopped, node-tar too, so a whole second tar there is
    // in no archive anyone lists. It is still in the file, and a verdict that dropped it would call
    // two different files one. Here it follows the first tar's end in the same gzip member; in a
    // second member it would be refused before the tar was read, as the test above shows.
    let p = tar(1, 1, b"same");
    let c = compare_bytes(
        gz(&[&p[..], &injected()].concat()),
        gz(&p),
        Format::TarGz,
        &profile("npm-tarball").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(c.outcome, Match::Divergent);
    let codes = &c.diff.as_ref().unwrap().codes;
    assert_eq!(
        codes.iter().collect::<Vec<_>>(),
        ["container:tar.trailing"],
        "the one difference, named"
    );
}

#[test]
fn an_uncompressed_container_reports_no_container_digest() {
    let c = compare_bytes(
        tar(1, 1, b"x"),
        tar(1, 1, b"x"),
        Format::Tar,
        &profile("tar").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    assert!(c.upstream.container.is_none());
    assert_eq!(c.container_bit_identical(), None);
}

#[test]
fn comparing_across_stabilizer_sets_is_refused() {
    // The two sides must have been stabilized the same way, or the comparison means nothing.
    let (a, _) = summarize(
        tar(1, 1, b"x"),
        Format::Tar,
        &profile("tar").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    let (b, _) = summarize(
        tar(1, 1, b"x"),
        Format::Tar,
        &set_with(Arc::new(ModelAuthored)),
        &Limits::default(),
    )
    .unwrap();

    match trigon_compare::compare(a, b, None, None) {
        Err(CompareError::SetMismatch(x, y)) => {
            assert_ne!(x, y);
        }
        other => panic!("expected a set mismatch, got {other:?}"),
    }
}

#[test]
fn raw_sha512_rides_along_but_derived_digests_do_not() {
    // SHA-512 is for cross-checking against a registry, which publishes it for the artifact and for
    // nothing else. Doubling the derived digests would double the hashing cost for no reader.
    let (s, _) = summarize(
        gz(&tar(1, 1, b"x")),
        Format::TarGz,
        &profile("tar-gzip").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    assert!(s.raw.sha512.is_some());
    assert!(s.stabilized.sha512.is_none());
    assert!(s.container.unwrap().sha512.is_none());
}

#[test]
fn the_diff_report_names_members_only_on_one_side() {
    let mut b = ::tar::Builder::new(Vec::new());
    let mut h = ::tar::Header::new_ustar();
    h.set_size(4);
    h.set_mode(0o644);
    h.set_cksum();
    b.append_data(&mut h, "pkg/a.txt", &b"same"[..]).unwrap();
    let only_one = b.into_inner().unwrap();

    let c = compare_bytes(
        tar(1, 1, b"same"),
        only_one,
        Format::Tar,
        &profile("tar").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    let d = c.diff.as_ref().unwrap();
    assert_eq!(d.only_upstream, 1);
    assert_eq!(d.only_rebuild, 0);
    let f = d
        .files
        .iter()
        .find(|f| f.status == FileStatus::OnlyUpstream)
        .unwrap();
    assert_eq!(f.path.to_lossy(), "pkg/b.txt");
    assert!(f.rebuild_digest.is_none());
}

#[test]
fn executable_differences_are_counted_apart() {
    let build = |body: &[u8]| {
        let mut b = ::tar::Builder::new(Vec::new());
        for (name, content) in [("pkg/lib.so", body), ("pkg/README.md", b"docs" as &[u8])] {
            let mut h = ::tar::Header::new_ustar();
            h.set_size(content.len() as u64);
            h.set_mode(0o755);
            h.set_cksum();
            b.append_data(&mut h, name, content).unwrap();
        }
        b.into_inner().unwrap()
    };
    let c = compare_bytes(
        build(b"\x7fELF-one"),
        build(b"\x7fELF-two"),
        Format::Tar,
        &profile("tar").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    let d = c.diff.as_ref().unwrap();
    assert_eq!(d.differs, 1);
    assert_eq!(
        d.executable_differs, 1,
        "a difference in an executable is never benign"
    );
}

#[test]
fn a_member_is_classed_by_its_own_names_extension_in_any_case() {
    use trigon_compare::ContentKind::{self, *};
    let kind = |p: &str| ContentKind::classify(&trigon_core::EntryPath::from(p));
    for (path, want) in [
        ("lib/net45/Foo.DLL", Executable),
        ("pkg/native/libx.so", Executable),
        ("com/x/Main.class", Executable),
        ("src/lib.rs", Source),
        ("pkg/x.py", Source),
        ("include/x.H", Source),
        ("README.md", Documentation),
        ("docs/guide.RST", Documentation),
        ("LICENSE.txt", Documentation),
        ("Cargo.toml", Metadata),
        ("package.json", Metadata),
        ("pkg/setup.cfg", Metadata),
        ("logo.png", Binary),
        // A directory's extension says nothing about the file inside it.
        ("lib.so/notes", Binary),
        ("src.rs/logo.png", Binary),
    ] {
        assert_eq!(kind(path), want, "{path}");
    }
}

#[test]
fn nested_members_are_named_through_the_container() {
    // A difference inside a gem should name the file, not the container.
    let build = |inner_body: &[u8]| {
        let mut inner = ::tar::Builder::new(Vec::new());
        let mut h = ::tar::Header::new_ustar();
        h.set_size(inner_body.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        inner
            .append_data(&mut h, "lib/rails.rb", inner_body)
            .unwrap();
        let data_gz = gz(&inner.into_inner().unwrap());

        let mut outer = ::tar::Builder::new(Vec::new());
        let mut oh = ::tar::Header::new_ustar();
        oh.set_size(data_gz.len() as u64);
        oh.set_mode(0o644);
        oh.set_cksum();
        outer
            .append_data(&mut oh, "data.tar.gz", &data_gz[..])
            .unwrap();
        outer.into_inner().unwrap()
    };

    let c = compare_bytes(
        build(b"module Rails1"),
        build(b"module Rails2"),
        Format::Tar,
        &profile("gem").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(c.outcome, Match::Divergent);
    let d = c.diff.as_ref().unwrap();
    let named: Vec<String> = d
        .files
        .iter()
        .map(|f| f.path.to_lossy().into_owned())
        .collect();
    assert!(
        named.iter().any(|n| n == "data.tar.gz!lib/rails.rb"),
        "expected the inner file to be named, got {named:?}"
    );
}

#[test]
fn a_renamed_member_keeps_the_name_each_artifact_holds_it_under() {
    // A member is reported under the name the set gave it, which neither artifact carries; a
    // reader going back to the bytes needs each side's own spelling, and only where it differs.
    use std::io::Write as _;
    let nupkg = |folder: &str| {
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        w.start_file("Demo.nuspec", opts).unwrap();
        w.write_all(b"<package/>\n").unwrap();
        w.start_file(format!("lib/{folder}/Demo.dll"), opts)
            .unwrap();
        w.write_all(b"the same assembly").unwrap();
        w.finish().unwrap().into_inner()
    };
    let c = compare_bytes(
        nupkg("portable-net45%2Bwin8"),
        nupkg("portable45-net45+win8"),
        Format::Zip,
        &profile("nupkg").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    let d = c.diff.as_ref().unwrap();
    let file = |p: &str| {
        d.files
            .iter()
            .find(|f| f.path.to_lossy() == p)
            .unwrap_or_else(|| panic!("no `{p}` in {:?}", d.files))
    };
    let dll = file("lib/portable-net45+win8/Demo.dll");
    assert_eq!(dll.status, FileStatus::Identical);
    let raw = |p: &Option<trigon_core::EntryPath>| p.as_ref().map(|p| p.to_lossy().into_owned());
    assert_eq!(
        (raw(&dll.upstream_raw_path), raw(&dll.rebuild_raw_path)),
        (
            Some("lib/portable-net45%2Bwin8/Demo.dll".to_string()),
            Some("lib/portable45-net45+win8/Demo.dll".to_string())
        )
    );
    let nuspec = file("Demo.nuspec");
    assert_eq!(
        (&nuspec.upstream_raw_path, &nuspec.rebuild_raw_path),
        (&None, &None)
    );
}

#[test]
fn duplicate_paths_compare_positionally() {
    // Keying on path alone would make a duplicate unmatchable. Upstream's second a.txt compares
    // against the rebuild's second a.txt.
    let build = |first: &[u8], second: &[u8]| {
        let mut b = ::tar::Builder::new(Vec::new());
        for content in [first, second] {
            let mut h = ::tar::Header::new_ustar();
            h.set_size(content.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, "dup.txt", content).unwrap();
        }
        b.into_inner().unwrap()
    };
    let same = compare_bytes(
        build(b"one", b"two"),
        build(b"one", b"two"),
        Format::Tar,
        &profile("tar").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(same.diff.as_ref().unwrap().differs, 0);

    let swapped = compare_bytes(
        build(b"one", b"two"),
        build(b"two", b"one"),
        Format::Tar,
        &profile("tar").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(
        swapped.diff.as_ref().unwrap().differs,
        2,
        "both occurrences moved"
    );
}

// --- field-level attribution ---------------------------------------------------------------------

/// Every difference the comparator can name is joined to the pass that made it, from ground truth:
/// a member reconciled only by metadata passes carries edits and no codes, and a genuine body
/// difference no pass rewrote carries a code and no body edit.
#[test]
fn field_edits_attribute_each_change_to_its_pass() {
    // a.txt: bodies differ (nothing rewrites them) -> forces Divergent, a real `body@` residual.
    // b.txt: same body, differing mtime + uid -> reconciled by tar-time / tar-owners.
    let c = compare_bytes(
        tar(1_700_000_000, 1000, b"UPSTREAM"),
        tar(1_500_000_000, 501, b"rebuilt!"),
        Format::Tar,
        &profile("tar").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(c.outcome, Match::Divergent);
    let d = c.diff.as_ref().unwrap();

    let edits_for = |path: &str, field: &str| -> Vec<String> {
        d.field_edits
            .iter()
            .find(|e| e.path == path && e.field == field)
            .map(|e| e.passes.clone())
            .unwrap_or_default()
    };

    // b.txt's mtime was zeroed by tar-time, its owner ids by tar-owners — proven, not guessed.
    assert_eq!(
        edits_for("pkg/b.txt", "mtime"),
        vec!["tar-time".to_string()]
    );
    assert_eq!(
        edits_for("pkg/b.txt", "tar.uid"),
        vec!["tar-owners".to_string()]
    );
    // …and those reconciliations left no residual code behind.
    assert!(
        !d.codes.iter().any(|c| c.ends_with("@pkg/b.txt")),
        "b.txt should have no residual codes: {:?}",
        d.codes
    );

    // a.txt's body genuinely differs and no pass rewrote it: a code with no body edit to own it.
    assert!(d.codes.contains("body@pkg/a.txt"));
    assert!(
        edits_for("pkg/a.txt", "body").is_empty(),
        "no pass rewrote a.txt's body, so nothing should claim it"
    );
}

/// A pass that rewrites a body is credited for it — the `body` field is attributed from the pass's
/// own byte-count signal, never by reading the bytes.
#[test]
fn a_body_rewrite_is_attributed_to_the_pass_that_made_it() {
    // Two wheels whose RECORD/text differ only in line endings, which wheel-metadata-eol rewrites.
    // Built as a minimal zip so the eol pass has a body to rewrite.
    use std::io::Write as _;
    fn whl(crlf: bool) -> Vec<u8> {
        use zip::write::SimpleFileOptions;
        let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let eol = if crlf { "\r\n" } else { "\n" };
        w.start_file("demo-1.0.dist-info/METADATA", opts).unwrap();
        write!(
            w,
            "Metadata-Version: 2.1{eol}Name: demo{eol}Version: 1.0{eol}"
        )
        .unwrap();
        w.finish().unwrap().into_inner()
    }
    let c = compare_bytes(
        whl(true),
        whl(false),
        Format::Zip,
        &profile("wheel").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    let d = c.diff.as_ref().unwrap();
    let meta = d
        .field_edits
        .iter()
        .find(|e| e.path.ends_with("METADATA") && e.field == "body");
    assert!(
        meta.is_some_and(|e| e.passes.iter().any(|p| p == "wheel-metadata-eol")),
        "the eol pass should own the METADATA body rewrite: {:?}",
        d.field_edits
    );
}

// --- the pass-by-pass progression -----------------------------------------------------------------

/// The set re-applied one pass at a time: the metadata-only member closes on the pass that
/// normalizes it, the body difference survives every pass, and the last step reproduces the
/// signature the verdict was taken on.
#[test]
fn progression_shows_which_pass_closed_which_member() {
    let set = profile("tar").unwrap();
    let c = compare_bytes(
        tar(1_700_000_000, 1000, b"UPSTREAM"),
        tar(1_500_000_000, 501, b"rebuilt!"),
        Format::Tar,
        &set,
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(c.outcome, Match::Divergent);
    let p = c
        .diff
        .as_ref()
        .unwrap()
        .progression
        .as_ref()
        .expect("progression recorded");

    assert!(p.omitted.is_none(), "{:?}", p.omitted);
    assert!(
        p.consistent,
        "the last step must reproduce the verdict's signature"
    );
    assert_eq!(
        p.steps.len(),
        set.members.len() + 1,
        "one step per pass, plus as-published"
    );

    let first = &p.steps[0];
    assert!(first.pass.is_none());
    assert_eq!(first.members, 2, "as published, both members differ");

    let last = p.steps.last().unwrap();
    assert_eq!(last.members, 1, "only the body difference survives");
    assert_eq!(last.bodies, 1);

    // b.txt differed only in metadata; exactly one pass closed it, and it was a named pass.
    let closer: Vec<_> = p
        .steps
        .iter()
        .filter(|s| s.closed.iter().any(|m| m == "pkg/b.txt"))
        .collect();
    assert_eq!(closer.len(), 1, "{:#?}", p.steps);
    assert!(closer[0].pass.is_some());

    // Never worse after a pass than before it.
    for w in p.steps.windows(2) {
        assert!(w[1].members <= w[0].members, "{:#?}", p.steps);
    }
}

/// An exact match has nothing to close, and says so in one step rather than twelve.
#[test]
fn an_exact_match_has_one_step() {
    let a = tar(1, 1, b"same");
    let c = compare_bytes(
        a.clone(),
        a,
        Format::Tar,
        &profile("tar").unwrap(),
        &Limits::default(),
    )
    .unwrap();
    let p = c.diff.unwrap().progression.unwrap();
    assert_eq!(p.steps.len(), 1);
    assert_eq!(p.steps[0].differences, 0);
    assert!(p.consistent);
}

/// Two honest builds agree on what the claim is about and not on their raw bytes.
///
/// Six builds of one package produced six raw artifacts and one stabilized digest
/// (`docs/17-backlog.md` B31). A second attempt is compared with the first by `agreement`, so it
/// has to be the same for two rebuilds that differ only in what the set stabilizes away, and
/// different for two divergences that differ in what they found.
#[test]
fn the_agreement_digest_ignores_raw_bytes_and_keeps_what_was_found() {
    let set = profile("tar").unwrap();
    let judge = |rebuild: Vec<u8>| {
        compare_bytes(
            tar(1_700_000_000, 1000, b"same"),
            rebuild,
            Format::Tar,
            &set,
            &Limits::default(),
        )
        .unwrap()
    };

    let first = judge(tar(1_500_000_000, 501, b"same"));
    let second = judge(tar(1_600_000_000, 777, b"same"));
    assert_eq!(first.outcome, Match::Normalized);
    assert_ne!(
        first.rebuild.raw.sha256, second.rebuild.raw.sha256,
        "the premise: two rebuilds with different raw bytes"
    );
    assert_eq!(
        first.agreement(),
        second.agreement(),
        "two normalized rebuilds that stabilize alike are one answer"
    );

    let one_way = judge(tar(1, 1, b"diverges one way"));
    let other_way = judge(tar(1, 1, b"diverges another"));
    assert_eq!(one_way.outcome, Match::Divergent);
    assert_eq!(other_way.outcome, Match::Divergent);
    assert_ne!(
        one_way.agreement(),
        other_way.agreement(),
        "two divergences that found different things do not confirm each other"
    );
    assert_ne!(first.agreement(), one_way.agreement());

    // The published artifact is the question. One republished under the same name, differing
    // only in what the set strips, stabilizes as the first did — and is other bytes, which a
    // statement about the first does not describe.
    let republished = compare_bytes(
        tar(1_700_000_999, 1000, b"same"),
        tar(1_500_000_000, 501, b"same"),
        Format::Tar,
        &set,
        &Limits::default(),
    )
    .unwrap();
    assert_ne!(
        republished.upstream.raw.sha256, first.upstream.raw.sha256,
        "the premise: other published bytes"
    );
    assert_eq!(
        republished.upstream.stabilized.sha256, first.upstream.stabilized.sha256,
        "the premise: which the set makes one"
    );
    assert_ne!(
        republished.agreement(),
        first.agreement(),
        "attempts against two published artifacts confirmed each other"
    );
}
