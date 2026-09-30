//! The difference signature's vocabulary, one field at a time.
//!
//! `signature` is what a signed divergence statement carries (`docs/09-attestations.md`) and what a
//! deviation in the differential test is written against (`docs/05-archive-and-normalization.md`
//! §6). Every field it compares therefore has to be named by its own code when that field, and only
//! that field, differs. A code that went missing would let a difference through that no deviation
//! declared; a code that fired for a neighbouring field would put a false claim into a statement
//! about somebody else's package.
//!
//! So each case parses one artifact twice, changes exactly one thing on one copy, and asserts the
//! *whole* signature rather than that it contains something.
//!
//! Two fields are held apart from the per-field tables. A member's `size` and a zip member's
//! `crc32` are functions of its body, which the writer recomputes on every write; `body@` already
//! names them, and `docs/17-backlog.md` B47 drops both from the signature once its format is
//! versioned. Their test says so, so that fix reads as the planned change it is rather than as a
//! regression.

use std::collections::BTreeSet;
use std::io::Write as _;
use std::sync::Arc;

use trigon_archive::{
    Archive, Body, Entry, EntryKind, GzipHeader, Limits, RawMeta, SourceMap, TarRaw, Trailer,
    ZipRaw, parse,
};
use trigon_compare::{matches, signature};
use trigon_core::Format;

// --- fixtures -------------------------------------------------------------------------------------

/// A ustar holding these members, in this order, every header field fixed.
fn tar_of(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = ::tar::Builder::new(Vec::new());
    for (name, body) in members {
        let mut h = ::tar::Header::new_ustar();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(1_700_000_000);
        h.set_cksum();
        b.append_data(&mut h, name, *body).unwrap();
    }
    b.into_inner().unwrap()
}

/// A stored zip holding one member.
fn zip_of(name: &str, body: &[u8]) -> Vec<u8> {
    use zip::write::SimpleFileOptions;
    let opts = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .unix_permissions(0o644);
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    w.start_file(name, opts).unwrap();
    w.write_all(body).unwrap();
    w.finish().unwrap().into_inner()
}

/// A gzip member framed by our own writer, uncompressed, so its length is a function of what it
/// holds and a one-byte change inside it is a one-byte change outside it.
fn gz(header: &GzipHeader, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    trigon_archive::gzip::write(header, payload, flate2::Compression::none(), &mut v).unwrap();
    v
}

fn read(bytes: &[u8], format: Format) -> Archive {
    parse(bytes.to_vec(), format, &Limits::default(), &mut Vec::new())
        .unwrap()
        .archive
}

fn set(codes: &[&str]) -> BTreeSet<String> {
    codes.iter().map(|c| c.to_string()).collect()
}

/// One change to one member, named by the code it must produce.
type Edit = fn(&mut Entry);

/// One change to a gzip header, likewise.
type HeaderEdit = fn(&mut GzipHeader);

fn tar_raw(e: &mut Entry) -> &mut TarRaw {
    match &mut e.raw {
        RawMeta::Tar(t) => t,
        RawMeta::Zip(_) => panic!("the fixture is a tar"),
    }
}

fn zip_raw(e: &mut Entry) -> &mut ZipRaw {
    match &mut e.raw {
        RawMeta::Zip(z) => z,
        RawMeta::Tar(_) => panic!("the fixture is a zip"),
    }
}

// --- one field of one member ----------------------------------------------------------------------

#[test]
fn each_tar_member_field_that_differs_is_named_by_its_own_code_and_nothing_else() {
    let bytes = tar_of(&[("pkg/a.txt", b"body")]);
    let cases: &[(&str, Edit)] = &[
        ("entry:kind@pkg/a.txt", |e| e.kind = EntryKind::Directory),
        ("entry:mtime@pkg/a.txt", |e| e.meta.mtime = Some(1)),
        ("entry:mode@pkg/a.txt", |e| e.meta.mode = 0o755),
        ("entry:tar.typeflag@pkg/a.txt", |e| {
            tar_raw(e).typeflag = b'7'
        }),
        ("entry:tar.linkname@pkg/a.txt", |e| {
            tar_raw(e).linkname = b"elsewhere".to_vec()
        }),
        ("entry:tar.uid@pkg/a.txt", |e| tar_raw(e).uid = 1000),
        ("entry:tar.gid@pkg/a.txt", |e| tar_raw(e).gid = 1000),
        ("entry:tar.uname@pkg/a.txt", |e| {
            tar_raw(e).uname = b"builder".to_vec()
        }),
        ("entry:tar.gname@pkg/a.txt", |e| {
            tar_raw(e).gname = b"staff".to_vec()
        }),
        // Major and minor are one finding: a device number is the pair.
        ("entry:tar.device@pkg/a.txt", |e| tar_raw(e).devmajor = 8),
        ("entry:tar.device@pkg/a.txt", |e| tar_raw(e).devminor = 1),
        ("entry:tar.atime@pkg/a.txt", |e| tar_raw(e).atime = Some(5)),
        ("entry:tar.ctime@pkg/a.txt", |e| tar_raw(e).ctime = Some(5)),
        ("entry:tar.pax.SCHILY.xattr.user.x@pkg/a.txt", |e| {
            tar_raw(e)
                .pax
                .insert("SCHILY.xattr.user.x".into(), "1".into());
        }),
        ("body@pkg/a.txt", |e| {
            e.body = Body::Inline(b"BODY".to_vec())
        }),
        // A tar member compared with a zip member has no field-by-field comparison to offer.
        ("entry:raw.format@pkg/a.txt", |e| {
            e.raw = RawMeta::Zip(ZipRaw::default())
        }),
    ];
    for (code, edit) in cases {
        let reference = read(&bytes, Format::Tar);
        let mut ours = read(&bytes, Format::Tar);
        edit(&mut ours.entries[0]);
        assert_eq!(
            signature(&reference, &ours),
            set(&[code]),
            "editing for {code}"
        );
    }
}

#[test]
fn each_zip_member_field_that_differs_is_named_by_its_own_code_and_nothing_else() {
    let bytes = zip_of("lib/x.py", b"print(1)\n");
    let cases: &[(&str, Edit)] = &[
        ("entry:zip.creator_version@lib/x.py", |e| {
            zip_raw(e).creator_version ^= 0x0300
        }),
        ("entry:zip.reader_version@lib/x.py", |e| {
            zip_raw(e).reader_version += 1
        }),
        ("entry:zip.flags@lib/x.py", |e| zip_raw(e).flags ^= 1 << 11),
        ("entry:zip.method@lib/x.py", |e| zip_raw(e).method = 8),
        ("entry:zip.extra@lib/x.py", |e| {
            zip_raw(e).extra = vec![0x55, 0x54, 0, 0]
        }),
        ("entry:zip.comment@lib/x.py", |e| {
            zip_raw(e).comment = b"why".to_vec()
        }),
        ("entry:zip.external_attrs@lib/x.py", |e| {
            zip_raw(e).external_attrs ^= 1
        }),
        ("entry:zip.internal_attrs@lib/x.py", |e| {
            zip_raw(e).internal_attrs = 1
        }),
        ("entry:zip.dos_datetime@lib/x.py", |e| {
            zip_raw(e).dos_datetime.1 ^= 1
        }),
        ("entry:raw.format@lib/x.py", |e| {
            e.raw = RawMeta::Tar(TarRaw::default())
        }),
    ];
    for (code, edit) in cases {
        let reference = read(&bytes, Format::Zip);
        let mut ours = read(&bytes, Format::Zip);
        edit(&mut ours.entries[0]);
        assert_eq!(
            signature(&reference, &ours),
            set(&[code]),
            "editing for {code}"
        );
    }
}

#[test]
fn the_codes_b47_would_drop_stay_until_the_signature_format_is_versioned() {
    // B47: `entry:size` and `entry:zip.crc32` over-report, because the writer recomputes both from
    // the body and `body@` already names a body that differs. The fix is deferred because it
    // changes the published divergence signature, which "wants versioning of the signature format
    // alongside, not a silent change under existing attestations". This holds the second half:
    // drop these codes together with a signature version, and change this test with them.
    let why = "B47: a vocabulary change under signed statements needs a signature version";

    let bytes = tar_of(&[("pkg/a.txt", b"body")]);
    let reference = read(&bytes, Format::Tar);
    let mut ours = read(&bytes, Format::Tar);
    ours.entries[0].meta.size += 1;
    assert_eq!(
        signature(&reference, &ours),
        set(&["entry:size@pkg/a.txt"]),
        "{why}"
    );

    let bytes = zip_of("lib/x.py", b"print(1)\n");
    let reference = read(&bytes, Format::Zip);
    let mut ours = read(&bytes, Format::Zip);
    zip_raw(&mut ours.entries[0]).crc32 ^= 1;
    assert_eq!(
        signature(&reference, &ours),
        set(&["entry:zip.crc32@lib/x.py"]),
        "{why}"
    );
}

#[test]
fn a_difference_in_each_pax_keyword_is_its_own_finding() {
    // An exemption for one keyword must not cover another, so one code each rather than one for
    // "the PAX records differ" — and a record present on one side only is a difference too.
    let bytes = tar_of(&[("a", b"x")]);
    let mut reference = read(&bytes, Format::Tar);
    let mut ours = read(&bytes, Format::Tar);
    tar_raw(&mut reference.entries[0])
        .pax
        .insert("comment".into(), "published".into());
    tar_raw(&mut reference.entries[0])
        .pax
        .insert("SCHILY.fflags".into(), "same".into());
    tar_raw(&mut ours.entries[0])
        .pax
        .insert("SCHILY.fflags".into(), "same".into());
    tar_raw(&mut ours.entries[0])
        .pax
        .insert("LIBARCHIVE.creationtime".into(), "1".into());

    assert_eq!(
        signature(&reference, &ours),
        set(&[
            "entry:tar.pax.LIBARCHIVE.creationtime@a",
            "entry:tar.pax.comment@a"
        ])
    );
}

#[test]
fn a_body_neither_side_can_read_is_never_taken_to_be_equal() {
    // The walker has no bytes to compare, so it has no grounds for "the same". Staying silent
    // would read as agreement in a signed statement; the member is named as unreadable instead.
    let bytes = tar_of(&[("pkg/a.txt", b"body")]);
    let unreadable = || Body::Original {
        src: Arc::new(SourceMap::owned(Vec::new())),
        off: 0,
        len: 4,
    };
    let mut reference = read(&bytes, Format::Tar);
    let mut ours = read(&bytes, Format::Tar);
    ours.entries[0].body = unreadable();
    assert_eq!(
        signature(&reference, &ours),
        set(&["body-unreadable@pkg/a.txt"])
    );

    reference.entries[0].body = unreadable();
    assert_eq!(
        signature(&reference, &ours),
        set(&["body-unreadable@pkg/a.txt"]),
        "two unreadable bodies are two things nobody looked at, not two equal things"
    );
}

// --- the archive as a whole -----------------------------------------------------------------------

#[test]
fn the_container_format_and_trailer_kind_are_named_apart() {
    let bytes = tar_of(&[("a", b"x")]);

    let reference = read(&bytes, Format::Tar);
    let mut ours = read(&bytes, Format::Tar);
    ours.format = Format::TarGz;
    assert_eq!(signature(&reference, &ours), set(&["container:format"]));

    let mut ours = read(&bytes, Format::Tar);
    ours.trailer = Trailer::None;
    assert_eq!(signature(&reference, &ours), set(&["container:trailer"]));
}

#[test]
fn each_gzip_header_field_that_differs_is_named_by_its_own_code() {
    let bytes = tar_of(&[("a", b"x")]);
    let cases: &[(&str, HeaderEdit)] = &[
        ("container:gzip.mtime", |h| h.mtime = Some(1_700_000_000)),
        ("container:gzip.name", |h| {
            h.name = Some(b"pkg.tar".to_vec())
        }),
        ("container:gzip.comment", |h| {
            h.comment = Some(b"hi".to_vec())
        }),
        ("container:gzip.extra", |h| h.extra = Some(vec![1, 2, 3, 4])),
        ("container:gzip.os", |h| h.os = 3),
        ("container:gzip.xfl", |h| h.xfl = 2),
        ("container:gzip.trailing", |h| {
            h.trailing = b"after the last member".to_vec()
        }),
    ];
    for (code, edit) in cases {
        let mut reference = read(&bytes, Format::Tar);
        let mut ours = read(&bytes, Format::Tar);
        let mut h = GzipHeader::default();
        reference.trailer = Trailer::Gzip(h.clone());
        edit(&mut h);
        ours.trailer = Trailer::Gzip(h);
        assert_eq!(
            signature(&reference, &ours),
            set(&[code]),
            "editing for {code}"
        );
    }
}

#[test]
fn a_zip_archive_comment_is_named_and_an_equal_one_is_not() {
    let bytes = zip_of("a.txt", b"x");
    let reference = read(&bytes, Format::Zip);
    let mut ours = read(&bytes, Format::Zip);
    assert!(signature(&reference, &ours).is_empty());

    ours.trailer = Trailer::Zip {
        comment: b"built on a laptop".to_vec(),
    };
    assert_eq!(
        signature(&reference, &ours),
        set(&["container:zip.comment"])
    );
}

#[test]
fn bytes_after_the_tar_end_of_archive_marker_are_named_and_equal_ones_are_not() {
    let bytes = tar_of(&[("a", b"x")]);
    let reference = read(&bytes, Format::Tar);
    let mut ours = read(&bytes, Format::Tar);
    ours.tar_trailing = b"after the end".to_vec();
    assert_eq!(
        signature(&reference, &ours),
        set(&["container:tar.trailing"])
    );

    let mut theirs = read(&bytes, Format::Tar);
    theirs.tar_trailing = b"after the end".to_vec();
    assert!(signature(&theirs, &ours).is_empty());
}

#[test]
fn the_same_members_in_another_order_are_one_order_code_and_no_membership_codes() {
    let reference = read(&tar_of(&[("a", b"1"), ("b", b"2")]), Format::Tar);
    let ours = read(&tar_of(&[("b", b"2"), ("a", b"1")]), Format::Tar);
    assert_eq!(signature(&reference, &ours), set(&["entry-order"]));
}

#[test]
fn a_member_only_the_rebuild_has_is_named_as_ours() {
    let reference = read(&tar_of(&[("a", b"1")]), Format::Tar);
    let ours = read(&tar_of(&[("a", b"1"), ("extra.txt", b"2")]), Format::Tar);
    assert_eq!(
        signature(&reference, &ours),
        set(&["member-only-in-ours@extra.txt"])
    );
}

// --- inside a nested archive ----------------------------------------------------------------------

/// An outer tar holding `data.tar.gz`, which holds these members under this gzip header.
fn gem(inner: &[(&str, &[u8])], header: &GzipHeader) -> Archive {
    let data = gz(header, &tar_of(inner));
    read(&tar_of(&[("data.tar.gz", &data)]), Format::Tar)
}

#[test]
fn a_difference_inside_a_nested_archive_is_named_through_its_container() {
    let h = GzipHeader::default();
    let reference = gem(&[("lib/x.rb", b"one"), ("lib/y.rb", b"two")], &h);
    assert!(
        matches!(reference.entries[0].body, Body::Nested { .. }),
        "the premise: the inner archive was descended into"
    );

    let body = gem(&[("lib/x.rb", b"ONE"), ("lib/y.rb", b"two")], &h);
    assert_eq!(
        signature(&reference, &body),
        set(&["body@data.tar.gz!lib/x.rb"])
    );

    let order = gem(&[("lib/y.rb", b"two"), ("lib/x.rb", b"one")], &h);
    assert_eq!(
        signature(&reference, &order),
        set(&["entry-order@data.tar.gz"]),
        "an archive-level code inside a member names the member, without the separator"
    );

    let framing = gem(
        &[("lib/x.rb", b"one"), ("lib/y.rb", b"two")],
        &GzipHeader {
            os: 3,
            ..GzipHeader::default()
        },
    );
    assert_eq!(
        signature(&reference, &framing),
        set(&["container:gzip.os@data.tar.gz"])
    );

    // The inner tar's own end sits beside the gzip header that is its trailer, and is named too.
    let mut after = gem(&[("lib/x.rb", b"one"), ("lib/y.rb", b"two")], &h);
    let Body::Nested { inner, .. } = &mut after.entries[0].body else {
        unreachable!("descended into, as above")
    };
    inner.tar_trailing = b"after the end".to_vec();
    assert_eq!(
        signature(&reference, &after),
        set(&["container:tar.trailing@data.tar.gz"])
    );
}

#[test]
fn a_gz_member_only_one_side_descended_into_is_compared_by_the_bytes_it_stabilizes_to() {
    // One side's `.gz` parsed and the other's did not (`NestedParseFailed`), so one member is an
    // archive and the other is bytes. Both can be read: an archive nothing changed contributes the
    // bytes it arrived as. `body-unreadable` said that nobody could look, which was not so.
    let h = GzipHeader::default();
    let nested = gem(&[("lib/x.rb", b"one")], &h);
    assert!(
        matches!(nested.entries[0].body, Body::Nested { .. }),
        "the premise: one side was descended into"
    );
    let inline = |bytes: Vec<u8>| {
        let mut a = gem(&[("lib/x.rb", b"one")], &h);
        a.entries[0].body = Body::Inline(bytes);
        a
    };
    let other = gz(&h, &tar_of(&[("lib/x.rb", b"ONE")]));
    assert_eq!(
        signature(&nested, &inline(other.clone())),
        set(&["body@data.tar.gz"])
    );
    assert_eq!(
        signature(&inline(other), &nested),
        set(&["body@data.tar.gz"]),
        "whichever side it is that descended"
    );

    let arrived = gz(&h, &tar_of(&[("lib/x.rb", b"one")]));
    assert_eq!(
        signature(&nested, &inline(arrived)),
        set(&[]),
        "the same bytes either way are the same member"
    );
}

// --- deviation patterns ---------------------------------------------------------------------------

#[test]
fn a_pattern_whose_middle_part_is_absent_does_not_match() {
    assert!(!matches("a*b*c", "ac"));
    assert!(!matches("entry:*.uid@*", "entry:tar.gid@x"));
    assert!(matches("entry:*.uid@*", "entry:tar.uid@x"));
}

#[test]
fn a_lone_wildcard_matches_every_code() {
    for code in [
        "",
        "entry-order",
        "body@a/b!c/d.rb",
        "container:gzip.os@x.gz",
    ] {
        assert!(matches("*", code), "{code}");
    }
}

#[test]
fn a_prefix_and_suffix_may_not_share_characters() {
    // `ab*ba` needs at least four characters. Anchoring both ends of `aba` at once would claim it.
    assert!(!matches("ab*ba", "aba"));
    assert!(matches("ab*ba", "abba"));
}
