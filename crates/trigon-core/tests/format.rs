//! A format's name, which is recorded in a signed attestation and read back by a verifier.
//!
//! `src/format.rs` is the one parser: two hand-written tables once accepted different subsets of
//! the same spellings. Every alias parses, the written name reads back as itself and matches the
//! serde name, and a name nothing knows is refused with the name in the message.

use std::str::FromStr;

use trigon_core::{EntryPath, Format, UnknownFormat};

const ALL: [Format; 5] = [
    Format::TarGz,
    Format::Tar,
    Format::Zip,
    Format::Gzip,
    Format::Raw,
];

#[test]
fn every_spelling_ever_written_parses_to_its_format() {
    for (s, f) in [
        ("tar+gzip", Format::TarGz),
        ("tar-gz", Format::TarGz),
        ("tar-gzip", Format::TarGz),
        ("tar.gz", Format::TarGz),
        ("tgz", Format::TarGz),
        ("tar", Format::Tar),
        ("zip", Format::Zip),
        ("gzip", Format::Gzip),
        ("gz", Format::Gzip),
        ("raw", Format::Raw),
    ] {
        assert_eq!(Format::from_str(s), Ok(f), "{s}");
    }
}

#[test]
fn the_written_name_reads_back_and_is_the_serde_name() {
    for f in ALL {
        assert_eq!(Format::from_str(&f.to_string()), Ok(f), "{f}");
        assert_eq!(serde_json::to_string(&f).unwrap(), format!("\"{f}\""));
    }
}

#[test]
fn a_name_nothing_knows_is_refused_and_named() {
    let e = Format::from_str("tar.bz2").unwrap_err();
    assert_eq!(e, UnknownFormat("tar.bz2".into()));
    assert_eq!(e.to_string(), "unknown format `tar.bz2`");
    let _: &dyn std::error::Error = &e;
}

#[test]
fn a_member_path_debugs_as_quoted_text_and_knows_when_it_is_empty() {
    // Bytes, not text, so a path that is not UTF-8 still has to print as something readable.
    let p = EntryPath::new(b"lib/\xffname".to_vec());
    assert_eq!(format!("{p:?}"), "\"lib/\u{fffd}name\"");
    assert_eq!(p.to_string(), "lib/\u{fffd}name");
    assert!(!p.is_empty());
    assert!(EntryPath::new(Vec::new()).is_empty());
}
