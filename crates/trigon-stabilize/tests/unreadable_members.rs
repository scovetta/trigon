//! A member whose bytes cannot be read is left exactly as it was, by every pass that reads bodies.
//!
//! `lib.rs`'s third rule: stabilizers are total, return no error, and fall back to the original
//! bytes, which leaves no half-stabilized state. A body can fail to read — a spilled member whose
//! file went away, a range past the end of its source — and every content pass reaches it through
//! `body_bytes` or `body_mut`. Each must decline rather than panic, drop the member, or claim a
//! change it did not make; and `wheel-record-v2`, which digests every member, must leave RECORD as
//! it arrived rather than write a manifest of a wheel that does not exist.

use std::sync::Arc;

use trigon_archive::{Archive, Body, Entry, Limits, SourceMap, parse};
use trigon_core::{Format, Note};
use trigon_stabilize::{Applied, apply, profile};

/// A body whose range lies past the end of its source, so reading it is an error.
fn unreadable() -> Body {
    Body::Original {
        src: Arc::new(SourceMap::owned(Vec::new())),
        off: 0,
        len: 16,
    }
}

fn is_still_unreadable(e: &Entry) -> bool {
    matches!(
        e.body,
        Body::Original {
            off: 0,
            len: 16,
            ..
        }
    ) && e.body_bytes().is_err()
}

fn parsed(bytes: Vec<u8>, format: Format) -> Archive {
    let mut notes: Vec<Note> = Vec::new();
    parse(bytes, format, &Limits::default(), &mut notes)
        .unwrap()
        .archive
}

fn entry<'a>(a: &'a mut Archive, name: &str) -> &'a mut Entry {
    a.entries
        .iter_mut()
        .find(|e| e.path.to_lossy() == name)
        .unwrap_or_else(|| panic!("no member `{name}`"))
}

fn zip(members: &[(&str, &[u8])]) -> Vec<u8> {
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

fn tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = ::tar::Builder::new(Vec::new());
    for (name, body) in entries {
        let mut h = ::tar::Header::new_ustar();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, name, *body).unwrap();
    }
    b.into_inner().unwrap()
}

fn gzip(body: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(body).unwrap();
    e.finish().unwrap()
}

/// Run `profile` over `a` with each of `names` made unreadable, and check each is untouched and
/// that none of `readers` — the passes that would have read them — claims any work.
fn assert_all_left_alone(prof: &str, mut a: Archive, names: &[&str], readers: &[&str]) {
    for n in names {
        entry(&mut a, n).body = unreadable();
    }
    let applied: Vec<Applied> = apply(&profile(prof).unwrap(), &mut a);
    for n in names {
        let e = a
            .entries
            .iter()
            .find(|e| e.path.to_lossy() == *n || e.raw_path().to_lossy() == *n)
            .unwrap_or_else(|| panic!("`{prof}` dropped the unreadable member `{n}`"));
        assert!(
            is_still_unreadable(e),
            "`{prof}` replaced the body of `{n}`"
        );
    }
    for r in readers {
        assert!(
            !applied.iter().any(|x| x.id.as_str() == *r),
            "`{r}` claimed work on bytes it could not read: {applied:?}"
        );
    }
}

#[test]
fn nupkg_passes_leave_an_unreadable_member_alone() {
    let names = [
        "Demo.nuspec",
        "README.md",
        "lib/net8.0/Demo.dll",
        "lib/net8.0/Demo.xml",
        "_rels/.rels",
        "package/services/metadata/core-properties/abc.psmdcp",
    ];
    let members: Vec<(&str, &[u8])> = names.iter().map(|n| (*n, &b"x\r\n"[..])).collect();
    assert_all_left_alone(
        "nupkg",
        parsed(zip(&members), Format::Zip),
        &names,
        &[
            "nupkg-repository-branch-v2",
            "nupkg-readme-markers-v2",
            "nupkg-text-eol",
            "nupkg-doc-member-order-v2",
            "nupkg-packager-version",
            "dotnet-assembly-identity-v2",
            "dotnet-il-canonical-v3",
        ],
    );
}

#[test]
fn wheel_passes_leave_an_unreadable_member_alone_and_record_as_it_arrived() {
    let record = b"pkg/__init__.py,sha256=stale,1\npkg-1.0.dist-info/RECORD,,\n";
    let mut a = parsed(
        zip(&[
            ("pkg/__init__.py", b"x = 1\n"),
            ("pkg/__pycache__/m.cpython-312.pyc", &[0xcb; 20]),
            ("pkg-1.0.dist-info/METADATA", b"Name: pkg\r\n"),
            ("pkg-1.0.dist-info/RECORD", record),
        ]),
        Format::Zip,
    );
    // RECORD itself is readable. What cannot be read is a member it would have to digest.
    entry(&mut a, "pkg/__init__.py").body = unreadable();
    assert_all_left_alone(
        "wheel",
        a,
        &[
            "pkg/__pycache__/m.cpython-312.pyc",
            "pkg-1.0.dist-info/METADATA",
        ],
        &["pyc-header-v2", "wheel-metadata-eol", "wheel-record-v3"],
    );

    let mut a = parsed(
        zip(&[
            ("pkg/__init__.py", b"x = 1\n"),
            ("pkg-1.0.dist-info/RECORD", record),
        ]),
        Format::Zip,
    );
    entry(&mut a, "pkg/__init__.py").body = unreadable();
    apply(&profile("wheel").unwrap(), &mut a);
    let rec = entry(&mut a, "pkg-1.0.dist-info/RECORD");
    assert_eq!(
        rec.body_bytes().unwrap().as_ref(),
        record,
        "a manifest computed without one member is a manifest of a wheel that does not exist"
    );
}

#[test]
fn tar_content_passes_leave_an_unreadable_member_alone() {
    let a = parsed(
        gzip(&tar(&[
            (
                "x-1.0.0/.cargo_vcs_info.json",
                br#"{"git":{"sha1":"0123456789abcdef0123456789abcdef01234567"}}"#,
            ),
            ("x-1.0.0/src/lib.rs", b"pub fn x() {}\n"),
        ])),
        Format::TarGz,
    );
    assert_all_left_alone(
        "crate",
        a,
        &["x-1.0.0/.cargo_vcs_info.json"],
        &["cargo-vcs-hash-v2"],
    );

    let a = parsed(
        gzip(&tar(&[(
            "package/package.json",
            b"{\n  \"_id\": \"x@1\",\n  \"name\": \"x\"\n}\n",
        )])),
        Format::TarGz,
    );
    assert_all_left_alone(
        "npm-tarball",
        a,
        &["package/package.json"],
        &["npm-install-fields-v2"],
    );
}

#[test]
fn gem_metadata_passes_leave_an_unreadable_spec_alone() {
    let spec = b"--- !ruby/object:Gem::Specification\ndate: 2024-03-15 00:00:00.000000000 Z\n\
                 rubygems_version: 3.5.6\ncert_chain:\n- |\n  CERT\n";
    let mut a = parsed(tar(&[("metadata.gz", &gzip(spec))]), Format::Tar);
    let Body::Nested { inner, .. } = &mut entry(&mut a, "metadata.gz").body else {
        panic!("metadata.gz did not parse as a nested archive");
    };
    let inner_name = inner.entries[0].path.to_lossy().into_owned();
    inner.entries[0].body = unreadable();
    let applied = apply(&profile("gem").unwrap(), &mut a);
    let Body::Nested { inner, .. } = &entry(&mut a, "metadata.gz").body else {
        unreachable!()
    };
    assert!(
        is_still_unreadable(&inner.entries[0]),
        "`{inner_name}` was replaced"
    );
    for r in [
        "gem-metadata-date-v2",
        "gem-metadata-rubygems-version-v2",
        "gem-metadata-cert-chain-v2",
    ] {
        assert!(
            !applied.iter().any(|x| x.id.as_str() == r),
            "`{r}`: {applied:?}"
        );
    }
}
