//! The half of the archived-set ABI that runs natively, without a wasm32 build or the host.
//!
//! The format numbering is archival: a module archived today is read by a host built later, and
//! the doc on `format_from_u32` says the mapping may only be appended to, because renumbering
//! would make an old set silently stabilize the wrong way. So the numbers are pinned here, not
//! just round-tripped — a round trip survives a renumbering, and an old module does not.

use trigon_archive::Limits;
use trigon_core::Format;
use trigon_stabilize_wasm::{format_from_u32, format_to_u32, stabilize};

#[test]
fn the_format_numbers_an_archived_module_was_built_against_do_not_move() {
    let pinned = [
        (0, Format::TarGz),
        (1, Format::Tar),
        (2, Format::Zip),
        (3, Format::Gzip),
        (4, Format::Raw),
    ];
    for (n, f) in pinned {
        assert_eq!(format_from_u32(n), Some(f), "{n}");
        assert_eq!(format_to_u32(f), n, "{f:?}");
    }
}

#[test]
fn a_format_number_nothing_was_assigned_is_refused() {
    // Not guessed at: a host newer than the module asking for a format the module never knew
    // gets a refusal the host can report, not a stabilization of the wrong shape.
    for n in [5, 6, 255, u32::MAX] {
        assert_eq!(format_from_u32(n), None, "{n}");
    }
}

fn wheel() -> Vec<u8> {
    use std::io::Write as _;
    let mut w = zip_crate::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts: zip_crate::write::FileOptions<'_, ()> = zip_crate::write::FileOptions::default()
        .compression_method(zip_crate::CompressionMethod::Deflated)
        .last_modified_time(zip_crate::DateTime::from_date_and_time(2023, 5, 6, 7, 8, 10).unwrap());
    for (name, body) in [
        ("demo/__init__.py", &b"x = 1\n"[..]),
        ("demo-1.0.dist-info/METADATA", b"Name: demo\r\n"),
        ("demo-1.0.dist-info/RECORD", b""),
    ] {
        w.start_file(name, opts).unwrap();
        w.write_all(body).unwrap();
    }
    w.finish().unwrap().into_inner()
}

#[test]
fn the_guest_entry_point_stabilizes_as_the_compiled_set_does() {
    // What the module's `trigon_stabilize` runs, called natively. Parse, apply, serialize
    // store-only — nothing more, or the archived set would answer a different question.
    let bytes = wheel();
    let got = stabilize("wheel", Format::Zip, bytes.clone()).expect("a valid wheel");

    let mut notes = Vec::new();
    let mut p = trigon_archive::parse(bytes, Format::Zip, &Limits::default(), &mut notes).unwrap();
    trigon_stabilize::apply(&trigon_stabilize::profile("wheel").unwrap(), &mut p.archive);
    assert_eq!(got, trigon_archive::serialize(&p.archive, true).unwrap());

    // And it did stabilize: the output is a fixed point.
    assert_eq!(stabilize("wheel", Format::Zip, got.clone()).unwrap(), got);
}

#[test]
fn an_unknown_profile_and_an_unparseable_artifact_are_both_refusals() {
    // The two causes the ABI's `0` merges; the host tells them apart by asking for the set
    // digest. Neither may produce bytes that would digest to something that looks like an answer.
    assert_eq!(stabilize("no-such-profile", Format::Zip, wheel()), None);
    assert_eq!(
        stabilize("wheel", Format::Zip, b"not a zip at all".to_vec()),
        None
    );
}
