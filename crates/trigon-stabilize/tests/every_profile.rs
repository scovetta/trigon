//! Every profile stabilizes idempotently — not the one profile somebody happened to write a test
//! for.
//!
//! `stabilize(stabilize(x)) == stabilize(x)` is the property a signed digest rests on, and it is
//! the only thing standing between a divergence report and a coin flip. Before this file, every
//! test of it in the tree ran the `tar` profile: `tests/passes.rs`, `tests/properties.rs`, and the
//! `stabilize` fuzz target between them covered `tar`, `gem`, `npm-tarball`, `crate` and `wheel`.
//!
//! The uncovered ones included `nupkg`, which is the profile that most needs it. It has seven
//! passes, and `profiles.rs` documents an ordering hazard in its own construction:
//!
//! > **Before the zip set.** This renames entries, and `zip-entry-order` sorts them; a rename
//! > afterwards would leave the sort stale and the digest dependent on the order the two spellings
//! > happened to arrive in.
//!
//! A hazard a comment warns about, in the profile no idempotence test ran, is the definition of an
//! unchecked claim. This is also the second time this exact omission has happened here —
//! `all_profiles()` once omitted `wheel`, and its doc comment says why that was not cosmetic.
//!
//! So the list is not written out. It is `all_profiles()`, and a profile added tomorrow either
//! gets a fixture here or fails this file.

use trigon_archive::{Limits, parse, serialize};
use trigon_core::{Format, Note};
use trigon_stabilize::{all_profiles, apply, profile};

fn tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = ::tar::Builder::new(Vec::new());
    for (name, body) in entries {
        let mut h = ::tar::Header::new_ustar();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(1_700_000_000);
        h.set_uid(1000);
        h.set_gid(1000);
        h.set_username("alice").unwrap();
        h.set_groupname("alice").unwrap();
        h.set_cksum();
        b.append_data(&mut h, name, *body).unwrap();
    }
    b.into_inner().unwrap()
}

/// Gzip with a *dirty* header — a name, an mtime, and a named OS.
///
/// flate2's plain `GzEncoder` already writes mtime 0, no name and OS unknown, which is exactly what
/// `gzip-meta` normalizes to. Compressing with it would hand the pass its own output and prove
/// nothing, so the fixture puts back the three fields real `gzip(1)` writes.
fn gzip(body: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    let mut e = flate2::GzBuilder::new()
        .filename("payload.tar")
        .mtime(1_700_000_000)
        .operating_system(3) // Unix, i.e. "the machine that packed this was a Linux box"
        .write(Vec::new(), flate2::Compression::default());
    e.write_all(body).unwrap();
    e.finish().unwrap()
}

fn zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write as _;
    let mut w = zip_crate::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts: zip_crate::write::FileOptions<()> = zip_crate::write::FileOptions::default()
        .compression_method(zip_crate::CompressionMethod::Deflated)
        .last_modified_time(zip_crate::DateTime::from_date_and_time(2021, 3, 4, 5, 6, 7).unwrap());
    for (name, body) in entries {
        w.start_file(*name, opts).unwrap();
        w.write_all(body).unwrap();
    }
    w.finish().unwrap().into_inner()
}

/// A payload shaped like the thing each profile is for, so its passes actually fire.
///
/// `None` for a profile that stabilizes nothing and has nothing to be idempotent about.
fn fixture(profile: &str) -> Option<(Format, Vec<u8>)> {
    let plain: &[(&str, &[u8])] = &[
        ("z/last.txt", b"data"),
        ("a/first.txt", b"data"),
        ("m/middle.txt", b"data"),
    ];
    Some(match profile {
        "tar" => (Format::Tar, tar(plain)),
        "tar-gzip" => (Format::TarGz, gzip(&tar(plain))),
        "gzip" => (Format::Gzip, gzip(b"a body that is not an archive")),
        "zip" => (Format::Zip, zip(plain)),
        "npm-tarball" => (
            Format::TarGz,
            gzip(&tar(&[
                ("package/package.json", br#"{"name":"x","_id":"x@1.0.0"}"#),
                ("package/index.js", b"module.exports = 1\n"),
            ])),
        ),
        "crate" => (
            Format::TarGz,
            gzip(&tar(&[
                ("x-1.0.0/.cargo_vcs_info.json", br#"{"git":{"sha1":"abc"}}"#),
                ("x-1.0.0/src/lib.rs", b"pub fn x() {}\n"),
            ])),
        ),
        "gem" => (
            Format::Tar,
            tar(&[
                ("metadata.gz", &gzip(b"--- !ruby/object:Gem::Specification\ndate: 2021-01-01\n")),
                ("checksums.yaml.gz", &gzip(b"---\n")),
                ("data.tar.gz", &gzip(&tar(&[("lib/x.rb", b"X = 1\n")]))),
            ]),
        ),
        "wheel" => (
            Format::Zip,
            zip(&[
                ("x/__init__.py", b"X = 1\n"),
                ("x-1.0.dist-info/direct_url.json", br#"{"url":"file:///tmp"}"#),
                ("x-1.0.dist-info/METADATA", b"Name: x\r\nVersion: 1.0\r\n"),
                ("x-1.0.dist-info/RECORD", b"x/__init__.py,,\n"),
            ]),
        ),
        // Both spellings of one target framework, which canonicalize to the same name. This is the
        // rename the profile's own comment warns about, and putting the two in an order the sort
        // would otherwise disagree with is the point of the fixture.
        "nupkg" => (
            Format::Zip,
            zip(&[
                ("lib/portable45-net45+win8+wp8+wpa81/z.dll", b"MZ\x90\x00late"),
                ("lib/net45/a.dll", b"MZ\x90\x00early"),
                ("x.nuspec", b"<package><metadata><id>x</id></metadata></package>\r\n"),
                (".signature.p7s", b"\x30\x82signature"),
                ("[Content_Types].xml", b"<Types/>"),
            ]),
        ),
        "raw" => return None,
        _ => return None,
    })
}

fn run(format: Format, prof: &str, bytes: Vec<u8>) -> (Vec<u8>, Vec<trigon_stabilize::Applied>) {
    let mut notes: Vec<Note> = Vec::new();
    let mut p = parse(bytes, format, &Limits::default(), &mut notes)
        .unwrap_or_else(|e| panic!("the `{prof}` fixture does not parse as {format:?}: {e}"));
    let applied = apply(&profile(prof).unwrap(), &mut p.archive);
    (serialize(&p.archive, true).unwrap(), applied)
}

#[test]
fn every_profile_is_idempotent() {
    for prof in all_profiles() {
        let Some((format, bytes)) = fixture(prof) else {
            continue;
        };
        let (once, first) = run(format, prof, bytes);
        let (twice, second) = run(format, prof, once.clone());

        assert_eq!(
            once, twice,
            "`{prof}` is not idempotent: stabilizing twice changed the bytes. A digest computed \
             from these is a coin flip."
        );
        assert!(
            second.is_empty(),
            "`{prof}` reported work on a second pass over already-stabilized bytes: {second:?}. \
             Either the first pass did not finish or the second is not detecting its own output.",
        );
        assert!(
            !first.is_empty(),
            "`{prof}` stabilized nothing at all, so this case proves idempotence of doing nothing. \
             Fix the fixture, not the assertion."
        );
    }
}

#[test]
fn every_profile_is_deterministic() {
    // The same input twice, through two independent parses. A pass that reads a HashMap in
    // iteration order, or a clock, or an address, fails here and not above.
    for prof in all_profiles() {
        let Some((format, bytes)) = fixture(prof) else {
            continue;
        };
        let (a, _) = run(format, prof, bytes.clone());
        let (b, _) = run(format, prof, bytes);
        assert_eq!(a, b, "`{prof}` produced different bytes for one input");
    }
}

/// The list above must cover the list the build actually answers to.
///
/// Without this, adding a profile silently adds an uncovered one — which is how `nupkg` came to
/// have no idempotence test, and how `all_profiles()` itself once came to omit `wheel`.
#[test]
fn no_profile_is_left_without_a_fixture() {
    // The profiles that legitimately have no passes, and why. Anything else needs a fixture.
    const EMPTY_BY_DESIGN: &[&str] = &["raw"];

    let missing: Vec<&str> = all_profiles()
        .into_iter()
        .filter(|p| fixture(p).is_none() && !EMPTY_BY_DESIGN.contains(p))
        .collect();
    assert!(
        missing.is_empty(),
        "these profiles have no fixture in this file, so nothing checks that they are idempotent: \
         {missing:?}"
    );

    for p in EMPTY_BY_DESIGN {
        assert!(
            profile(p).expect("listed profile").manifest().members.is_empty(),
            "`{p}` is excused from a fixture on the grounds that it has no passes, and it now has \
             some"
        );
    }
}

/// The fuzz target's profile table must cover the same list.
///
/// `fuzz/fuzz_targets/stabilize.rs` checks idempotence too, against inputs nobody wrote by hand,
/// which is the half this file cannot do. It had its own hardcoded list of four profiles. Two
/// hardcoded lists of the same enumeration, neither checked against it, is the defect ADR-0008 is
/// about, and the reason `nupkg` was missing from both.
///
/// Reading the fuzz target's source is crude, and it is what is available: the fuzz crate is not a
/// workspace member (it needs a nightly toolchain and `cargo-fuzz`), so nothing links it.
#[test]
fn the_fuzz_target_covers_every_profile_too() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/fuzz_targets/stabilize.rs");
    let Ok(text) = std::fs::read_to_string(&src) else {
        panic!("the stabilize fuzz target is missing from {}", src.display());
    };

    let missing: Vec<&str> = all_profiles()
        .into_iter()
        .filter(|p| !text.contains(&format!("\"{p}\"")))
        .collect();
    assert!(
        missing.is_empty(),
        "these profiles are not in the fuzz target's table, so no generated input ever reaches \
         them: {missing:?}. Add them to {}",
        src.display()
    );
}
