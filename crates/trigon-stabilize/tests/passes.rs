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
fn a_filter_keeps_the_passes_it_names_and_none_is_a_keyword_only_on_its_own() {
    // `["all"]` keeps everything and `["none"]` nothing; any other list names the passes to keep,
    // so `none` beside a pass id is one more id that no pass has, not an order to drop the rest.
    // Read the other way, `--enable-passes none,tar-time` would bisect a mismatch to no pass.
    let tar = profile_of("tar");
    let names = |v: &[&str]| -> Vec<String> { v.iter().map(|s| s.to_string()).collect() };
    let kept = |enable: &[&str], disable: &[&str]| -> Vec<String> {
        let set = tar.filtered(&names(enable), &names(disable));
        assert_eq!(set.id, tar.id, "a filtered set keeps its profile's name");
        set.ids().iter().map(|i| i.to_string()).collect()
    };
    let every: Vec<String> = tar.ids().iter().map(|i| i.to_string()).collect();
    assert_eq!(kept(&["all"], &[]), every);
    assert!(kept(&["none"], &[]).is_empty());
    assert_eq!(kept(&["none", "tar-time"], &[]), ["tar-time"]);
    assert_eq!(kept(&["tar-time", "tar-mode"], &[]), ["tar-mode", "tar-time"]);
    // `disable` then removes from whatever survived.
    assert_eq!(kept(&["tar-time", "tar-mode"], &["tar-mode"]), ["tar-time"]);
    assert_eq!(kept(&["all"], &["tar-time"]).len(), every.len() - 1);
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
    assert!(ids.contains(&"wheel-record-v2".to_string()));
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
fn record_is_what_pip_computes_for_the_same_members() {
    // A shape is not a digest: the rows are checked against values computed outside this crate
    // (Python's `hashlib.sha256` and `base64.urlsafe_b64encode`, padding stripped), so a
    // hand-rolled encoder that is merely well formed does not pass. The first is the digest every
    // wheel's RECORD carries for an empty `__init__.py`.
    let wheel = wheel_with(&[
        ("pkg/m.py", b"import os\n"),
        ("pkg/__init__.py", b""),
        ("pkg-1.0.dist-info/RECORD", b"stale\n"),
    ]);
    let (out, _) = stabilize(wheel, Format::Zip, "wheel");
    assert_eq!(
        record_of(out),
        "pkg/__init__.py,sha256=47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU,0\n\
         pkg/m.py,sha256=Nyet_1JOBhYCLq3Y9K8hoHeLKfxMd73-_Rr84sv15Lc,10\n\
         pkg-1.0.dist-info/RECORD,,\n"
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

// ---------------------------------------------------------------------------
// wheel-metadata-eol

fn wheel_with(members: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write as _;
    let mut w = zip_crate::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts: zip_crate::write::FileOptions<'_, ()> = zip_crate::write::FileOptions::default()
        .compression_method(zip_crate::CompressionMethod::Stored);
    for (name, body) in members {
        w.start_file(*name, opts).unwrap();
        w.write_all(body).unwrap();
    }
    w.finish().unwrap().into_inner()
}

fn member(bytes: Vec<u8>, path: &str) -> Vec<u8> {
    let mut notes = Vec::new();
    let parsed = trigon_archive::parse(bytes, Format::Zip, &Limits::default(), &mut notes).unwrap();
    let e = parsed
        .archive
        .entries
        .iter()
        .find(|e| e.path.to_string() == path)
        .unwrap_or_else(|| panic!("no member {path}"));
    e.body_bytes().unwrap().into_owned()
}

#[test]
fn generated_wheel_metadata_loses_its_carriage_returns() {
    // A publisher on Windows writes CRLF into METADATA because the tool opened it in text mode.
    // The content is identical and the bytes are not, and no amount of pinning reaches it: we
    // cannot reproduce Windows text-mode I/O.
    let bytes = wheel_with(&[(
        "demo-1.0.dist-info/METADATA",
        b"Metadata-Version: 2.1\r\nName: demo\r\n",
    )]);
    let (out, _) = stabilize(bytes, Format::Zip, "wheel");
    assert_eq!(
        member(out, "demo-1.0.dist-info/METADATA"),
        b"Metadata-Version: 2.1\nName: demo\n"
    );
}

#[test]
fn package_source_keeps_its_line_endings() {
    // The distinction the pass rests on. A `.py` file's line endings are the author's choice and
    // part of what is under test; rewriting them would be editing the artifact rather than
    // normalizing a build-environment artefact.
    let bytes = wheel_with(&[
        ("demo/__init__.py", b"x = 1\r\ny = 2\r\n"),
        ("demo-1.0.dist-info/METADATA", b"Name: demo\r\n"),
    ]);
    let (out, _) = stabilize(bytes, Format::Zip, "wheel");
    assert_eq!(
        member(out.clone(), "demo/__init__.py"),
        b"x = 1\r\ny = 2\r\n",
        "source content must survive untouched"
    );
    assert_eq!(member(out, "demo-1.0.dist-info/METADATA"), b"Name: demo\n");
}

#[test]
fn a_licence_in_dist_info_is_not_generated_metadata() {
    // `dist-info/` is not a licence to rewrite everything inside it: a wheel may ship arbitrary
    // files there, including ones the author wrote by hand.
    let bytes = wheel_with(&[(
        "demo-1.0.dist-info/LICENSE",
        b"Copyright\r\nAll rights reserved\r\n",
    )]);
    let (out, _) = stabilize(bytes, Format::Zip, "wheel");
    assert_eq!(
        member(out, "demo-1.0.dist-info/LICENSE"),
        b"Copyright\r\nAll rights reserved\r\n"
    );
}

#[test]
fn a_lone_carriage_return_is_content_not_a_line_ending() {
    let bytes = wheel_with(&[(
        "demo-1.0.dist-info/METADATA",
        b"Summary: a\rb\r\nName: d\r\n",
    )]);
    let (out, _) = stabilize(bytes, Format::Zip, "wheel");
    assert_eq!(
        member(out, "demo-1.0.dist-info/METADATA"),
        b"Summary: a\rb\nName: d\n",
        "only a CR immediately before LF is a line ending"
    );
}

#[test]
fn two_wheels_differing_only_in_metadata_line_endings_agree_after_stabilizing() {
    // The property that makes it worth the risk tier: this is what flips `sniffio` from divergent.
    let crlf = wheel_with(&[
        ("demo/__init__.py", b"x = 1\n"),
        ("demo-1.0.dist-info/METADATA", b"Metadata-Version: 2.1\r\n"),
    ]);
    let lf = wheel_with(&[
        ("demo/__init__.py", b"x = 1\n"),
        ("demo-1.0.dist-info/METADATA", b"Metadata-Version: 2.1\n"),
    ]);
    assert_ne!(crlf, lf);
    assert_eq!(
        stabilize(crlf, Format::Zip, "wheel").0,
        stabilize(lf, Format::Zip, "wheel").0
    );
}

// ---------------------------------------------------------------------------
// The set manifest

#[test]
fn a_manifest_recomputes_the_digest_it_claims() {
    // The property that makes publishing one worth anything. A verifier holding an attestation made
    // under a set they do not have gets a digest that does not match theirs and, without this, no
    // way to learn what it was — and no way to tell a faithful record from a document that merely
    // asserts a digest.
    for profile in trigon_stabilize::all_profiles() {
        let set = profile_of(profile);
        let m = set.manifest();
        assert!(
            m.self_consistent(),
            "`{profile}` manifest does not recompute its own digest"
        );
        assert_eq!(m.digest, set.digest().to_hex());
        assert_eq!(m.members.len(), set.members.len());
    }
}

#[test]
fn a_manifest_survives_a_round_trip_through_json() {
    // It is published as a file and read by somebody else's build. A manifest that only verifies
    // in the process that produced it verifies nothing.
    let set = profile_of("wheel");
    let m = set.manifest();
    let back: trigon_stabilize::SetManifest =
        serde_json::from_str(&serde_json::to_string(&m).unwrap()).unwrap();
    assert_eq!(back, m);
    assert!(back.self_consistent());
}

#[test]
fn editing_a_manifest_breaks_its_own_check() {
    // Downgrading a risk tier in the document without changing the set is exactly the edit that
    // would make a capped outcome look clean. It does not survive the recomputation.
    let mut m = profile_of("wheel").manifest();
    let touched = m
        .members
        .iter_mut()
        .find(|x| x.risk != "Structural")
        .expect("the wheel set has a member above Structural risk");
    touched.risk = "Structural".into();
    assert!(
        !m.self_consistent(),
        "a rewritten risk tier must not verify"
    );
}

#[test]
fn the_manifest_names_what_the_digest_covers_and_no_more() {
    // Four fields, the same four the digest is computed over. A manifest carrying richer fields
    // than the digest covers would be a document nobody could check against the set.
    let m = profile_of("wheel").manifest();
    let v = serde_json::to_value(&m.members[0]).unwrap();
    // Compared as a set: `serde_json` orders keys itself, and the claim here is about which fields
    // exist rather than how they are laid out.
    let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(keys, ["id", "provenance", "risk", "stage"]);
}

fn profile_of(name: &str) -> StabilizerSet {
    profile(name).unwrap_or_else(|| panic!("no profile `{name}`"))
}

/// A `.sig` the package ships is not the gem's signature.
///
/// **This produced false matches, which is the worst thing this project can do.** A `.gem` is a
/// tar holding `metadata.gz`, `checksums.yaml.gz`, `data.tar.gz` and the signing artifacts
/// `*.sig`. `gem-exclude-signatures` drops every entry ending `.sig` and `gem-exclude-checksums`
/// drops every `checksums.yaml.gz` — and `apply` runs the whole set at every archive depth, so
/// both also fired inside `data.tar.gz`, which is the payload.
///
/// A gem that ships a certificate, a test fixture, or a detached signature under any name ending
/// `.sig` therefore had that file deleted from *both* sides before they were compared. A real
/// difference in it became no difference at all, and the run reported a match.
///
/// The vocabulary to say this correctly already existed: `has_gzip` is written as
/// `… && (cx.at_depth(0) || is_structural(cx))`, and `is_structural` even names the three gem
/// members by hand. These two passes were the ones that did not ask.
fn gem_with(payload_sig: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    fn tar_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut b = ::tar::Builder::new(Vec::new());
        for (name, body) in entries {
            let mut h = ::tar::Header::new_ustar();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_mtime(1_700_000_000);
            h.set_cksum();
            b.append_data(&mut h, name, *body).unwrap();
        }
        b.into_inner().unwrap()
    }
    fn gz(b: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut e = flate2::write::GzEncoder::new(&mut out, flate2::Compression::default());
        e.write_all(b).unwrap();
        e.finish().unwrap();
        out
    }

    // The payload, one level down, carrying a file the package itself ships.
    let data = gz(&tar_of(&[
        ("lib/thing.rb", b"THING = 1\n"),
        ("lib/trusted-cert.sig", payload_sig),
        ("lib/checksums.yaml.gz", &gz(b"a file the package ships\n")),
    ]));

    // The gem's own envelope, at depth 0, which is what the two passes are actually for.
    tar_of(&[
        ("metadata.gz", &gz(b"--- !ruby/object:Gem::Specification\n")),
        ("checksums.yaml.gz", &gz(b"---\nSHA256:\n")),
        ("data.tar.gz", &data),
        ("metadata.gz.sig", b"the gem's signature"),
        ("data.tar.gz.sig", b"the gem's other signature"),
    ])
}

#[test]
fn a_gem_payloads_own_sig_survives_the_signature_exclusion() {
    let (a, _) = stabilize(gem_with(b"CERTIFICATE ONE"), Format::Tar, "gem");
    let (b, _) = stabilize(gem_with(b"CERTIFICATE TWO"), Format::Tar, "gem");

    assert_ne!(
        a, b,
        "two gems whose payloads carry different `lib/trusted-cert.sig` stabilized to identical \
         bytes. The comparison that follows reports a match for a package that changed."
    );

    // And the exclusion is still doing its job, or the fix has simply turned the passes off and
    // this test would pass against a set that stabilizes nothing at all.
    let (c, applied) = stabilize(gem_with(b"SAME"), Format::Tar, "gem");
    let (d, _) = stabilize(gem_with(b"SAME"), Format::Tar, "gem");
    assert_eq!(c, d, "the same gem twice must stabilize the same");
    assert!(
        applied
            .iter()
            .any(|x| x.id.as_str() == "gem-exclude-signatures"),
        "the exclusion did not fire at all, so this test proves nothing: {applied:?}"
    );
}

/// The envelope's own signatures and checksums are still dropped.
#[test]
fn the_gems_own_envelope_is_still_excluded() {
    use trigon_archive::{Limits, parse};
    let (out, _) = stabilize(gem_with(b"SAME"), Format::Tar, "gem");
    let mut notes = Vec::new();
    let p = parse(out, Format::Tar, &Limits::default(), &mut notes).unwrap();
    let names: Vec<String> = p
        .archive
        .entries
        .iter()
        .map(|e| e.path.to_lossy().into_owned())
        .collect();

    for gone in ["metadata.gz.sig", "data.tar.gz.sig", "checksums.yaml.gz"] {
        assert!(
            !names.contains(&gone.to_string()),
            "`{gone}` is the gem's own signing envelope and should still be excluded: {names:?}"
        );
    }
    assert!(
        names.contains(&"data.tar.gz".to_string()),
        "the payload went missing: {names:?}"
    );
}

/// A symlink member does not stabilize into a regular file.
///
/// **A false match with a supply-chain consequence.** `zip-versions` zeroed `external_attrs` to
/// normalize the unix mode — 0644 against 0664 is packaging noise — and the whole field includes
/// the **file-type** bits. The zip writer emits `raw.external_attrs` and never consults
/// `Entry::kind`, which the reader had set correctly, so once the pass ran a symlink and a regular
/// file with the same bytes were the same archive.
///
/// Measured through the CLI on two 228-byte zips whose `pkg/x.py` was a symlink to `/etc/passwd`
/// on one side and a file containing that text on the other:
///
/// ```text
/// ✔ normalized
///   stabilized   b60c55d03b98…      b60c55d03b98…      =
/// ```
///
/// A published wheel that replaced a file with a symlink would have been reported as reproduced.
#[test]
fn a_symlink_does_not_stabilize_into_a_regular_file() {
    use trigon_archive::{EntryKind, RawMeta};

    /// The fixture, built through the archive model because no zip writer here can be made to
    /// emit `S_IFLNK` reliably across versions. The reader's own `kind` is what the pass must
    /// consult, so setting it is exactly the state a real symlinked member arrives in.
    fn zip_with(symlink: bool) -> Vec<u8> {
        use std::io::Write as _;
        let mut w = zip_crate::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts: zip_crate::write::FileOptions<'_, ()> = zip_crate::write::FileOptions::default()
            .compression_method(zip_crate::CompressionMethod::Stored);
        for (name, body) in [("pkg/x.py", &b"/etc/passwd"[..]), ("pkg/ok.py", b"print(1)\n")] {
            w.start_file(name, opts).unwrap();
            w.write_all(body).unwrap();
        }
        let bytes = w.finish().unwrap().into_inner();

        let mut notes: Vec<Note> = Vec::new();
        let mut p = parse(bytes, Format::Zip, &Limits::default(), &mut notes).unwrap();
        if symlink {
            let e = p
                .archive
                .entries
                .iter_mut()
                .find(|e| e.path.to_lossy().ends_with("x.py"))
                .expect("the member");
            e.kind = EntryKind::Symlink {
                target: b"/etc/passwd".to_vec(),
            };
            if let RawMeta::Zip(raw) = &mut e.raw {
                raw.external_attrs = 0o120777 << 16;
            }
        }
        serialize(&p.archive, true).unwrap()
    }

    let (sym, _) = stabilize(zip_with(true), Format::Zip, "zip");
    let (reg, _) = stabilize(zip_with(false), Format::Zip, "zip");

    assert_ne!(
        sym, reg,
        "a symlink to /etc/passwd and a regular file containing that text stabilized to the same \
         bytes. `trigon verify` reports this pair as reproduced."
    );

    // And the normalization it was written for still works: the mode bits that really are noise
    // must still come out the same, or this fix has traded a false match for a false divergence.
    let a = zip_with(false);
    let b = {
        let mut notes: Vec<Note> = Vec::new();
        let mut p = parse(a.clone(), Format::Zip, &Limits::default(), &mut notes).unwrap();
        for e in p.archive.entries.iter_mut() {
            if let RawMeta::Zip(raw) = &mut e.raw {
                // One side written by a tool that records a mode, the other by one that does not.
                raw.external_attrs = 0o100664 << 16;
                raw.creator_version = 0x031e;
            }
            e.mark_dirty();
        }
        serialize(&p.archive, true).unwrap()
    };
    let (sa, _) = stabilize(a, Format::Zip, "zip");
    let (sb, _) = stabilize(b, Format::Zip, "zip");
    assert_eq!(
        sa, sb,
        "two zips differing only in recorded permissions must still agree; that is what zeroing \
         the field was for"
    );
}
