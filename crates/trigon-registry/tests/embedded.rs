//! Where a published artifact itself says its source is, read out of real archive bytes.
//!
//! `nupkg_source` and `crate_commit` are the strongest source-discovery rungs NuGet and crates.io
//! have, and both read a file someone else packed: a `.nuspec` at the root of a zip, a
//! `.cargo_vcs_info.json` one directory down in a gzipped tar. What they promise (`embedded.rs`) is
//! that the field the publishing tool wrote is taken at its word, that a file somewhere else in the
//! archive is not, and that anything that does not look like a repository or a commit is not
//! returned as one. The archives here are built byte by byte, so what is under test is the reading
//! and not an archiver.

use std::io::Write as _;

use trigon_core::SourceDiscovery;
use trigon_registry::{crate_commit, nupkg_source};

const COMMIT: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4";

/// A zip holding these files, as `dotnet pack` would lay them out.
fn zip(files: &[(&str, &str)]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts: zip::write::FileOptions<'_, ()> =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for (name, body) in files {
        w.start_file(*name, opts).unwrap();
        w.write_all(body.as_bytes()).unwrap();
    }
    w.finish().unwrap().into_inner()
}

fn nuspec(repository: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<package><metadata>\n  <id>Widget</id>\n  \
         {repository}\n</metadata></package>\n"
    )
}

/// A ustar archive holding these regular files.
fn tar(files: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, body) in files {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..107].copy_from_slice(b"0000644");
        h[108..115].copy_from_slice(b"0000000");
        h[116..123].copy_from_slice(b"0000000");
        h[124..135].copy_from_slice(format!("{:011o}", body.len()).as_bytes());
        h[136..147].copy_from_slice(b"00000000000");
        h[148..156].copy_from_slice(b"        ");
        h[156] = b'0';
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        out.extend_from_slice(&h);
        out.extend_from_slice(body.as_bytes());
        out.resize(out.len().div_ceil(512) * 512, 0);
    }
    out.resize(out.len() + 1024, 0);
    out
}

/// One gzip member of stored deflate blocks, which every inflater reads.
fn gzip(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
    let blocks: Vec<&[u8]> = data.chunks(65_535).collect();
    for (i, block) in blocks.iter().enumerate() {
        out.push(u8::from(i + 1 == blocks.len()));
        let len = block.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(block);
    }
    let mut crc = !0u32;
    for b in data {
        crc ^= u32::from(*b);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    out.extend_from_slice(&(!crc).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

fn dot_crate(files: &[(&str, &str)]) -> Vec<u8> {
    gzip(&tar(files))
}

fn vcs_info(sha1: &str) -> String {
    format!("{{\n  \"git\": {{\n    \"sha1\": \"{sha1}\"\n  }},\n  \"path_in_vcs\": \"\"\n}}")
}

#[test]
fn a_nupkg_that_records_its_commit_is_published_provenance() {
    // `dotnet pack` writes `<repository commit>` from SourceLink during the build being reproduced,
    // which is the strongest source statement any of the four ecosystems makes.
    let bytes = zip(&[
        ("_rels/.rels", "<Relationships/>"),
        (
            "Widget.nuspec",
            &nuspec(&format!(
                "<repository type=\"git\" url=\"https://github.com/o/widget.git\" \
                 branch=\"refs/heads/main\" commit=\"{COMMIT}\" />"
            )),
        ),
        ("lib/net8.0/Widget.dll", "MZ"),
    ]);
    let s = nupkg_source(&bytes).expect("the nuspec names a repository");
    assert_eq!(s.repo_url, "https://github.com/o/widget");
    assert_eq!(
        s.declared_url.as_deref(),
        Some("https://github.com/o/widget.git"),
        "what the package said, beside what it was canonicalized to"
    );
    assert_eq!(s.commit, COMMIT);
    assert_eq!(s.ref_name.as_deref(), Some("refs/heads/main"));
    assert_eq!(s.how, SourceDiscovery::PublishedProvenance);
    assert_eq!(s.subdir, None);
}

#[test]
fn a_nupkg_with_a_repository_and_no_commit_still_needs_the_tag_ladder() {
    let bytes = zip(&[(
        "Widget.nuspec",
        &nuspec("<repository type=\"git\" url=\"https://github.com/o/widget\" />"),
    )]);
    let s = nupkg_source(&bytes).expect("a repository is still a source location");
    assert!(s.commit.is_empty());
    assert_eq!(s.declared_url, None, "nothing was canonicalized away");
    assert_eq!(s.how, SourceDiscovery::RegistryMetadata);
}

#[test]
fn only_the_nuspec_at_the_root_speaks_for_the_package() {
    // A `.nuspec` deeper in the tree belongs to something the package vendored. Reading it would
    // attach this package's verdict to somebody else's repository.
    let vendored = nuspec(&format!(
        "<repository type=\"git\" url=\"https://github.com/someone/else\" commit=\"{COMMIT}\" />"
    ));
    let bytes = zip(&[
        ("content/vendor/Other.nuspec", &vendored),
        ("lib/net8.0/Widget.dll", "MZ"),
    ]);
    assert_eq!(nupkg_source(&bytes), None);

    // A root nuspec with no repository element says nothing, and the vendored one still does not
    // speak for it.
    let bytes = zip(&[
        ("Widget.nuspec", &nuspec("")),
        ("content/vendor/Other.nuspec", &vendored),
    ]);
    assert_eq!(nupkg_source(&bytes), None);
}

#[test]
fn bytes_that_are_not_a_readable_nupkg_name_no_source() {
    // A truncated download, the wrong file, or a nuspec that is not text: no source, and no panic.
    assert_eq!(nupkg_source(b"not a zip at all"), None);
    assert_eq!(nupkg_source(&[]), None);
    let mut not_utf8 = nuspec("<repository url=\"https://github.com/o/w\" />").into_bytes();
    not_utf8.extend_from_slice(&[0xff, 0xfe, 0xfd]);
    let bytes = {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default();
        w.start_file("Widget.nuspec", opts).unwrap();
        w.write_all(&not_utf8).unwrap();
        w.finish().unwrap().into_inner()
    };
    assert_eq!(nupkg_source(&bytes), None);
}

#[test]
fn a_crate_packaged_from_a_clean_checkout_names_its_commit() {
    // `cargo package` writes `.cargo_vcs_info.json` one directory down, in the package directory.
    let bytes = dot_crate(&[
        ("widget-1.0.0/Cargo.toml", "[package]\nname = \"widget\"\n"),
        ("widget-1.0.0/.cargo_vcs_info.json", &vcs_info(COMMIT)),
        ("widget-1.0.0/src/lib.rs", "pub fn f() {}\n"),
    ]);
    assert_eq!(crate_commit(&bytes).as_deref(), Some(COMMIT));
}

#[test]
fn only_the_vcs_info_one_directory_down_speaks_for_the_crate() {
    // `cargo vendor` output keeps each vendored crate's `.cargo_vcs_info.json`. A crate that ships
    // one and has none of its own must not be attached to the vendored crate's commit.
    let bytes = dot_crate(&[
        ("widget-1.0.0/Cargo.toml", "[package]\n"),
        (
            "widget-1.0.0/vendor/dep/.cargo_vcs_info.json",
            &vcs_info(COMMIT),
        ),
    ]);
    assert_eq!(crate_commit(&bytes), None);

    // Nor when a directory whose name sorts before `.` holds one and the crate's own is there too:
    // the package's file is the one read, wherever the other falls in the archive.
    let other = "0".repeat(40);
    let bytes = dot_crate(&[
        (
            "widget-1.0.0/-vendor/dep/.cargo_vcs_info.json",
            &vcs_info(&other),
        ),
        ("widget-1.0.0/.cargo_vcs_info.json", &vcs_info(COMMIT)),
    ]);
    assert_eq!(crate_commit(&bytes).as_deref(), Some(COMMIT));
}

#[test]
fn a_crate_with_no_commit_or_a_malformed_one_names_none() {
    // Packaged outside a git checkout: the file is absent, which is ordinary.
    let bytes = dot_crate(&[("widget-1.0.0/Cargo.toml", "[package]\n")]);
    assert_eq!(crate_commit(&bytes), None);

    // A value that is not a full commit id is not handed to `git checkout`.
    for sha1 in ["HEAD", "a1b2c3d", &"z".repeat(40)] {
        let bytes = dot_crate(&[("widget-1.0.0/.cargo_vcs_info.json", &vcs_info(sha1))]);
        assert_eq!(crate_commit(&bytes), None, "{sha1}");
    }

    // A file that is not the JSON it should be, or lacks the field.
    for body in [
        "{ not json",
        "{\"path_in_vcs\": \"\"}",
        "{\"git\": {\"sha1\": 7}}",
    ] {
        let bytes = dot_crate(&[("widget-1.0.0/.cargo_vcs_info.json", body)]);
        assert_eq!(crate_commit(&bytes), None, "{body}");
    }

    // And bytes that are not a gzipped tar at all.
    assert_eq!(crate_commit(b"\x1f\x8b not really"), None);
    assert_eq!(
        crate_commit(&tar(&[("a/b", "c")])),
        None,
        "a tar that is not gzipped"
    );
}
