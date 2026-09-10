use std::sync::Arc;

use trigon_archive::{Limits, parse, serialize};
use trigon_core::{Format, Note, Provenance, RiskTier};
use trigon_stabilize::{Applied, Stabilizer, StabilizerSet, apply, default_for, profile};

fn tar_with(mtime: u64, uid: u64, uname: &str, mode: u32) -> Vec<u8> {
    let mut b = ::tar::Builder::new(Vec::new());
    for name in ["z/last.txt", "a/first.txt"] {
        let mut h = ::tar::Header::new_ustar();
        h.set_size(4);
        h.set_mode(mode);
        h.set_mtime(mtime);
        h.set_uid(uid);
        h.set_gid(uid);
        h.set_username(uname).unwrap();
        h.set_groupname(uname).unwrap();
        h.set_cksum();
        b.append_data(&mut h, name, &b"data"[..]).unwrap();
    }
    b.into_inner().unwrap()
}

fn stabilize(bytes: Vec<u8>, format: Format, prof: &str) -> (Vec<u8>, Vec<Applied>) {
    let mut notes: Vec<Note> = Vec::new();
    let mut p = parse(bytes, format, &Limits::default(), &mut notes).unwrap();
    let set = profile(prof).unwrap();
    let applied = apply(&set, &mut p.archive);
    (serialize(&p.archive, true).unwrap(), applied)
}

#[test]
fn two_archives_differing_only_in_metadata_stabilize_identically() {
    let (a, _) = stabilize(
        tar_with(1_700_000_000, 1000, "alice", 0o644),
        Format::Tar,
        "tar",
    );
    let (b, _) = stabilize(
        tar_with(1_500_000_000, 501, "bob", 0o600),
        Format::Tar,
        "tar",
    );
    assert_eq!(a, b, "metadata-only differences must stabilize away");
}

#[test]
fn entry_order_is_normalized() {
    let (out, applied) = stabilize(tar_with(1, 1, "x", 0o644), Format::Tar, "tar");
    assert!(applied.iter().any(|x| x.id.as_str() == "tar-entry-order"));
    let mut notes = Vec::new();
    let p = parse(out, Format::Tar, &Limits::default(), &mut notes).unwrap();
    let names: Vec<_> = p
        .archive
        .entries
        .iter()
        .map(|e| e.path.to_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["a/first.txt", "z/last.txt"]);
}

#[test]
fn stabilization_is_idempotent() {
    let (once, _) = stabilize(
        tar_with(1_700_000_000, 1000, "alice", 0o644),
        Format::Tar,
        "tar",
    );
    let (twice, applied2) = stabilize(once.clone(), Format::Tar, "tar");
    assert_eq!(once, twice);
    assert!(
        applied2.is_empty(),
        "a second pass should change nothing, got {applied2:?}"
    );
}

#[test]
fn applied_reports_only_passes_that_fired() {
    let (_, applied) = stabilize(
        tar_with(1_700_000_000, 1000, "alice", 0o644),
        Format::Tar,
        "tar",
    );
    let ids: Vec<_> = applied.iter().map(|a| a.id.as_str().to_string()).collect();
    assert!(ids.contains(&"tar-time".to_string()));
    assert!(ids.contains(&"tar-owners".to_string()));
    assert!(!ids.contains(&"tar-xattrs".to_string()), "{ids:?}");
    assert!(!ids.contains(&"tar-device".to_string()), "{ids:?}");
    assert!(applied.iter().all(|a| a.provenance == Provenance::Builtin));
}

#[test]
fn the_gem_profile_stays_within_the_clean_tier() {
    let set = profile("gem").unwrap();
    let worst = set.members.iter().map(|m| m.risk()).max().unwrap();
    assert!(
        worst <= RiskTier::Metadata,
        "no gem could reach Normalized with a {worst:?} pass"
    );
    assert!(
        set.members
            .iter()
            .all(|m| m.provenance() == Provenance::Builtin)
    );
}

#[test]
fn the_crate_profile_is_capped_by_cargo_vcs_hash() {
    let set = profile("crate").unwrap();
    assert_eq!(
        set.members.iter().map(|m| m.risk()).max().unwrap(),
        RiskTier::Content
    );
}

#[test]
fn set_digest_is_stable_and_order_independent() {
    let a = profile("npm-tarball").unwrap();
    assert_eq!(a.digest(), profile("npm-tarball").unwrap().digest());
    let mut shuffled: Vec<Arc<dyn Stabilizer>> = a.members.clone();
    shuffled.reverse();
    assert_eq!(
        a.digest(),
        StabilizerSet::new("npm-tarball", shuffled).digest()
    );
    assert_ne!(a.digest(), profile("crate").unwrap().digest());
}

#[test]
fn default_profile_follows_the_format() {
    assert_eq!(default_for(Format::TarGz).id.as_str(), "tar-gzip");
    assert_eq!(default_for(Format::Zip).id.as_str(), "zip");
    assert!(default_for(Format::Raw).members.is_empty());
}

// --- wheel: the case StageFinalize exists for -----------------------------------------------------

fn wheel_fixture() -> Vec<u8> {
    use std::io::Write as _;
    use zip_crate::write::SimpleFileOptions;
    let opts = SimpleFileOptions::default()
        .compression_method(zip_crate::CompressionMethod::Deflated)
        .unix_permissions(0o644);
    let mut w = zip_crate::ZipWriter::new(std::io::Cursor::new(Vec::new()));

    w.start_file("pkg/__init__.py", opts).unwrap();
    w.write_all(b"__version__ = '1.0'\n").unwrap();
    // A .pyc whose header carries a compile timestamp.
    w.start_file("pkg/__pycache__/m.cpython-311.pyc", opts)
        .unwrap();
    let mut pyc = vec![0xa7, 0x0d, 0x0d, 0x0a];
    pyc.extend_from_slice(&[0, 0, 0, 0]);
    pyc.extend_from_slice(&1_700_000_000u32.to_le_bytes());
    pyc.extend_from_slice(&42u32.to_le_bytes());
    pyc.extend_from_slice(b"bytecode");
    w.write_all(&pyc).unwrap();
    // A file a Lossy pass will remove, which is what makes RECORD stale.
    w.start_file("pkg-1.0.dist-info/direct_url.json", opts)
        .unwrap();
    w.write_all(br#"{"url": "file:///home/alice/build"}"#)
        .unwrap();
    w.start_file("pkg-1.0.dist-info/METADATA", opts).unwrap();
    w.write_all(b"Name: pkg\n").unwrap();
    // A RECORD listing the wheel as it arrived, direct_url.json included.
    w.start_file("pkg-1.0.dist-info/RECORD", opts).unwrap();
    w.write_all(
        b"pkg/__init__.py,sha256=stale,20\n\
          pkg-1.0.dist-info/direct_url.json,sha256=stale,34\n\
          pkg-1.0.dist-info/RECORD,,\n",
    )
    .unwrap();
    w.finish().unwrap().into_inner()
}

fn record_of(bytes: Vec<u8>) -> String {
    let mut notes: Vec<Note> = Vec::new();
    let p = parse(bytes, Format::Zip, &Limits::default(), &mut notes).unwrap();
    let e = p
        .archive
        .entries
        .iter()
        .find(|e| e.path.ends_with(b"/RECORD"))
        .unwrap();
    String::from_utf8_lossy(&e.body_bytes().unwrap()).into_owned()
}

#[test]
fn record_is_regenerated_after_membership_changes() {
    let (out, applied) = stabilize(wheel_fixture(), Format::Zip, "wheel");
    let record = record_of(out);

    // The Lossy pass removed direct_url.json, and RECORD must not still list it. Regenerating at
    // Default rather than Finalize would produce a manifest of the wheel as it arrived.
    assert!(
        !record.contains("direct_url.json"),
        "stale RECORD entry survived:\n{record}"
    );
    assert!(record.contains("pkg/__init__.py,sha256="));
    assert!(record.trim_end().ends_with("pkg-1.0.dist-info/RECORD,,"));
    assert!(
        !record.contains("stale"),
        "RECORD was not regenerated:\n{record}"
    );

    let ids: Vec<_> = applied.iter().map(|a| a.id.as_str().to_string()).collect();
    assert!(ids.contains(&"wheel-record".to_string()));
    assert!(ids.contains(&"wheel-direct-url".to_string()));
    assert!(ids.contains(&"pyc-header".to_string()));
}

#[test]
fn record_lines_are_sorted_and_digests_are_base64url() {
    let (out, _) = stabilize(wheel_fixture(), Format::Zip, "wheel");
    let record = record_of(out);
    let lines: Vec<&str> = record.lines().collect();
    // Every line but the last sorts; RECORD's own line goes last, outside the sort.
    let (body, tail) = lines.split_at(lines.len() - 1);
    let mut sorted = body.to_vec();
    sorted.sort();
    assert_eq!(body, sorted.as_slice(), "RECORD body must be sorted");
    assert!(tail[0].ends_with(",,"));

    let digest_line = lines
        .iter()
        .find(|l| l.starts_with("pkg/__init__.py"))
        .unwrap();
    let b64 = digest_line
        .split("sha256=")
        .nth(1)
        .unwrap()
        .split(',')
        .next()
        .unwrap();
    assert_eq!(b64.len(), 43, "base64url of 32 bytes, unpadded");
    assert!(!b64.contains('='), "RECORD digests are unpadded");
    assert!(
        b64.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    );
}

#[test]
fn the_wheel_profile_reports_caveats() {
    // pyc-header rewrites bytes inside a distributed file and wheel-direct-url removes one, so a
    // wheel that needs them cannot present as a clean `Normalized`. That is the tier doing its job.
    let set = profile("wheel").unwrap();
    assert_eq!(
        set.members.iter().map(|m| m.risk()).max().unwrap(),
        RiskTier::Lossy
    );
}

#[test]
fn two_wheels_differing_in_pyc_timestamps_stabilize_identically() {
    let a = stabilize(wheel_fixture(), Format::Zip, "wheel").0;
    let b = stabilize(wheel_fixture(), Format::Zip, "wheel").0;
    assert_eq!(a, b);
    // And stabilizing twice changes nothing, RECORD regeneration included.
    assert_eq!(stabilize(a.clone(), Format::Zip, "wheel").0, a);
}
