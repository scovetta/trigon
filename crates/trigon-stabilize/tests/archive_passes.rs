//! The tar, zip, npm, wheel and gem passes, on the cases their own comments describe.
//!
//! Each pass promises to remove one class of difference and nothing else, so each case is a pair:
//! two artifacts that differ only in that class agree after the pass, and the difference is really
//! there before it — or the test proves the fixture, not the pass.

use trigon_archive::{
    Archive, ArchiveError, EntryKind, Limits, RawMeta, TarRaw, Trailer, ZipRaw, parse, serialize,
};
use trigon_core::{Format, Note, NoteCode, RiskTier};
use trigon_stabilize::{Applied, FieldEdit, StabilizerSet, apply, apply_traced, profile};

fn tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = ::tar::Builder::new(Vec::new());
    for (name, body) in entries {
        let mut h = ::tar::Header::new_ustar();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(1_700_000_000);
        h.set_uid(1000);
        h.set_gid(1000);
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

fn zip(members: &[(&str, &[u8])], comment: &str) -> Vec<u8> {
    use std::io::Write as _;
    let mut w = zip_crate::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts: zip_crate::write::FileOptions<'_, ()> = zip_crate::write::FileOptions::default()
        .compression_method(zip_crate::CompressionMethod::Stored);
    for (name, body) in members {
        w.start_file(*name, opts).unwrap();
        w.write_all(body).unwrap();
    }
    w.set_comment(comment);
    w.finish().unwrap().into_inner()
}

fn parsed(bytes: Vec<u8>, format: Format) -> Archive {
    let mut notes: Vec<Note> = Vec::new();
    parse(bytes, format, &Limits::default(), &mut notes)
        .unwrap()
        .archive
}

fn stabilized(set: &StabilizerSet, mut a: Archive) -> (Vec<u8>, Vec<Applied>) {
    let applied = apply(set, &mut a);
    (serialize(&a, true).unwrap(), applied)
}

fn fired(applied: &[Applied], id: &str) -> bool {
    applied.iter().any(|a| a.id.as_str() == id)
}

fn body_of(bytes: Vec<u8>, format: Format, name: &str) -> String {
    let a = parsed(bytes, format);
    let e = a
        .entries
        .iter()
        .find(|e| e.path.to_lossy() == name)
        .unwrap_or_else(|| panic!("no member `{name}`"));
    String::from_utf8(e.body_bytes().unwrap().into_owned()).unwrap()
}

// --- tar-xattrs ----------------------------------------------------------------------------------

/// A tarball as node-tar packs it: a PAX record per member carrying the packing machine's inode
/// and device numbers, and more.
fn packed_with(records: &[(&str, &str)]) -> Archive {
    let mut a = parsed(
        tar(&[
            ("package/index.js", b"module.exports = 1\n"),
            ("package/package.json", b"{}\n"),
        ]),
        Format::Tar,
    );
    for e in &mut a.entries {
        let RawMeta::Tar(raw) = &mut e.raw else {
            unreachable!()
        };
        for (k, v) in records {
            raw.pax.insert(k.to_string(), v.as_bytes().to_vec());
        }
        e.mark_dirty();
    }
    a
}

#[test]
fn host_state_in_pax_records_does_not_reach_the_stabilized_bytes() {
    // docs/05 §7: `SCHILY.ino`, `SCHILY.dev`, a `NODETAR.*` per field of package.json. Keeping any
    // made the digest a function of where the package was built.
    let here = || {
        packed_with(&[
            ("SCHILY.ino", "1234"),
            ("SCHILY.dev", "66306"),
            ("NODETAR.x", "1"),
        ])
    };
    let there = || packed_with(&[("SCHILY.ino", "98765"), ("SCHILY.nlink", "1")]);

    // The records do reach the bytes without the pass, so the fixture is a real difference.
    let without = profile("tar")
        .unwrap()
        .filtered(&["all".into()], &["tar-xattrs".into()]);
    assert_ne!(
        stabilized(&without, here()).0,
        stabilized(&without, there()).0
    );

    let (a, applied) = stabilized(&profile("tar").unwrap(), here());
    let (b, _) = stabilized(&profile("tar").unwrap(), there());
    assert_eq!(a, b, "PAX host state survived tar-xattrs");
    let x = applied
        .iter()
        .find(|x| x.id.as_str() == "tar-xattrs")
        .unwrap();
    assert_eq!((x.entries_touched, x.risk), (2, RiskTier::Metadata));
}

#[test]
fn each_dropped_pax_record_is_attributed_to_tar_xattrs() {
    // The comparator names PAX differences one keyword at a time, so the attribution must too.
    let mut a = packed_with(&[("SCHILY.ino", "1234"), ("NODETAR.name", "x")]);
    let (_, edits) = apply_traced(&profile("tar").unwrap(), &mut a);
    for field in ["tar.pax.SCHILY.ino", "tar.pax.NODETAR.name"] {
        let want = FieldEdit {
            path: "package/index.js".into(),
            field: field.into(),
            pass: trigon_core::StabilizerId::new("tar-xattrs"),
        };
        assert!(edits.contains(&want), "missing {want:?} in {edits:#?}");
    }
}

// --- tar-device ----------------------------------------------------------------------------------

fn device(kind: ::tar::EntryType, major: u32, minor: u32) -> Vec<u8> {
    let mut b = ::tar::Builder::new(Vec::new());
    let mut h = ::tar::Header::new_ustar();
    h.set_entry_type(kind);
    h.set_device_major(major).unwrap();
    h.set_device_minor(minor).unwrap();
    h.set_size(0);
    h.set_mode(0o666);
    h.set_cksum();
    b.append_data(&mut h, "dev/node", &[][..]).unwrap();
    b.into_inner().unwrap()
}

#[test]
fn device_numbers_are_zeroed_and_the_node_type_is_kept() {
    let tar_set = profile("tar").unwrap();
    let (a, applied) = stabilized(
        &tar_set,
        parsed(device(::tar::EntryType::Char, 1, 3), Format::Tar),
    );
    let (b, _) = stabilized(
        &tar_set,
        parsed(device(::tar::EntryType::Char, 8, 0), Format::Tar),
    );
    assert_eq!(
        a, b,
        "two character devices differing only in their numbers"
    );
    assert!(fired(&applied, "tar-device"), "{applied:?}");
    let e = &parsed(a.clone(), Format::Tar).entries[0];
    assert_eq!(e.kind, EntryKind::CharDevice { major: 0, minor: 0 });

    // What the entry *is* is not a number: a block device is still not a character device.
    let (c, _) = stabilized(
        &tar_set,
        parsed(device(::tar::EntryType::Block, 1, 3), Format::Tar),
    );
    assert_ne!(a, c);
}

#[test]
fn a_zeroed_device_is_attributed_in_both_places_it_is_recorded() {
    // The numbers live in the header fields and in the entry's kind, and the comparator compares
    // both, so a pass that changed both must be named for both.
    let mut a = parsed(device(::tar::EntryType::Char, 1, 3), Format::Tar);
    let (_, edits) = apply_traced(&profile("tar").unwrap(), &mut a);
    let by_device: Vec<&str> = edits
        .iter()
        .filter(|e| e.pass.as_str() == "tar-device")
        .map(|e| e.field.as_str())
        .collect();
    assert_eq!(by_device, ["kind", "tar.device"]);
}

// --- zip-compression -----------------------------------------------------------------------------

#[test]
fn the_archive_comment_is_cleared() {
    // The zip trailer's comment is the container's, not a member's: a tool's banner, a build id.
    let a = zip(&[("a.txt", b"one")], "built by CI run 4117");
    let b = zip(&[("a.txt", b"one")], "");
    assert_ne!(a, b);
    let (sa, applied) = stabilized(&profile("zip").unwrap(), parsed(a, Format::Zip));
    let (sb, _) = stabilized(&profile("zip").unwrap(), parsed(b, Format::Zip));
    assert_eq!(sa, sb);
    assert!(fired(&applied, "zip-compression"), "{applied:?}");
    assert_eq!(
        parsed(sa, Format::Zip).trailer,
        Trailer::Zip {
            comment: Vec::new()
        }
    );
}

// --- zip-misc ------------------------------------------------------------------------------------

/// A zip whose members carry what one writer adds and another does not: an extra field (an
/// extended timestamp, a unix uid/gid), a per-member comment, general-purpose flags and the
/// "text file" internal attribute.
fn zip_with_writer_extras() -> Archive {
    let mut a = parsed(
        zip(&[("a.txt", b"one"), ("b/c.txt", b"two")], ""),
        Format::Zip,
    );
    for e in &mut a.entries {
        let RawMeta::Zip(raw) = &mut e.raw else {
            unreachable!()
        };
        raw.extra = vec![0x55, 0x54, 0x05, 0x00, 0x01, 0x00, 0x2c, 0x5e, 0x65];
        raw.comment = b"added by the packing tool".to_vec();
        raw.flags = 0x0800;
        raw.internal_attrs = 1;
        e.mark_dirty();
    }
    a
}

#[test]
fn per_member_extras_comments_and_flags_are_cleared() {
    let plain = || {
        parsed(
            zip(&[("a.txt", b"one"), ("b/c.txt", b"two")], ""),
            Format::Zip,
        )
    };
    let without = profile("zip")
        .unwrap()
        .filtered(&["all".into()], &["zip-misc".into()]);
    assert_ne!(
        stabilized(&without, zip_with_writer_extras()).0,
        stabilized(&without, plain()).0,
        "the fixture's extras never reached the bytes"
    );

    let (a, applied) = stabilized(&profile("zip").unwrap(), zip_with_writer_extras());
    let (b, _) = stabilized(&profile("zip").unwrap(), plain());
    assert_eq!(a, b);
    let x = applied
        .iter()
        .find(|x| x.id.as_str() == "zip-misc")
        .unwrap();
    assert_eq!((x.entries_touched, x.risk), (2, RiskTier::Metadata));

    let mut a = zip_with_writer_extras();
    let (_, edits) = apply_traced(&profile("zip").unwrap(), &mut a);
    let mut by_misc: Vec<&str> = edits
        .iter()
        .filter(|e| e.pass.as_str() == "zip-misc" && e.path == "a.txt")
        .map(|e| e.field.as_str())
        .collect();
    by_misc.sort();
    assert_eq!(
        by_misc,
        [
            "zip.comment",
            "zip.extra",
            "zip.flags",
            "zip.internal_attrs"
        ]
    );
}

// --- npm-install-fields --------------------------------------------------------------------------

fn npm(package_json: &str) -> Archive {
    parsed(
        gzip(&tar(&[
            ("package/package.json", package_json.as_bytes()),
            ("package/index.js", b"module.exports = 1\n"),
        ])),
        Format::TarGz,
    )
}

#[test]
fn fields_an_installing_client_injects_are_dropped() {
    // docs/03 §1: `_resolved`, `_integrity`, `_from` (and `_id`) are written into package.json by
    // the client that installed it, not by the author.
    let installed = "{\n  \"_from\": \"left-pad@1.3.0\",\n  \"_id\": \"left-pad@1.3.0\",\n  \
                     \"_integrity\": \"sha512-AAAA\",\n  \
                     \"_resolved\": \"https://registry.npmjs.org/left-pad/-/lp-1.3.0.tgz\",\n  \
                     \"name\": \"left-pad\",\n  \"version\": \"1.3.0\"\n}\n";
    let authored = "{\n  \"name\": \"left-pad\",\n  \"version\": \"1.3.0\"\n}\n";
    let set = profile("npm-tarball").unwrap();
    let (a, applied) = stabilized(&set, npm(installed));
    let (b, _) = stabilized(&set, npm(authored));
    assert_eq!(
        body_of(a.clone(), Format::TarGz, "package/package.json"),
        authored
    );
    assert_eq!(a, b);
    let x = applied
        .iter()
        .find(|x| x.id.as_str() == "npm-install-fields-v2")
        .unwrap();
    assert_eq!(x.risk, RiskTier::Metadata);
    let dropped: u64 = installed
        .lines()
        .filter(|l| l.trim_start().starts_with("\"_"))
        .map(|l| l.len() as u64)
        .sum();
    assert_eq!(x.bytes_changed, dropped);
}

#[test]
fn fields_injected_last_leave_the_object_well_formed() {
    // A client may append its fields after the author's rather than lead with them. Dropping
    // their lines alone left the comma that separated the author's last property from them in
    // front of the `}`: not JSON, and never equal to the package as its author wrote it.
    let installed = "{\n  \"name\": \"x\",\n  \"version\": \"1.0.0\",\n  \
                     \"_resolved\": \"https://registry.npmjs.org/x/-/x-1.0.0.tgz\",\n  \
                     \"_integrity\": \"sha512-A\"\n}\n";
    let authored = "{\n  \"name\": \"x\",\n  \"version\": \"1.0.0\"\n}\n";
    let set = profile("npm-tarball").unwrap();
    let (a, applied) = stabilized(&set, npm(installed));
    let (b, _) = stabilized(&set, npm(authored));
    assert_eq!(
        body_of(a.clone(), Format::TarGz, "package/package.json"),
        authored
    );
    assert_eq!(a, b);
    // The comma is a byte the pass removed too, counted beside the lines it dropped.
    let x = applied
        .iter()
        .find(|x| x.id.as_str() == "npm-install-fields-v2")
        .unwrap();
    let dropped: u64 = installed
        .lines()
        .filter(|l| l.trim_start().starts_with("\"_"))
        .map(|l| l.len() as u64)
        .sum();
    assert_eq!(x.bytes_changed, dropped + 1);

    // A comma inside a nested object the injected fields did not close is the author's, and
    // stays; so does an object that held nothing but injected fields.
    let nested = "{\n  \"a\": {\n    \"b\": 1,\n    \"c\": 2\n  },\n  \"_id\": \"x@1.0.0\"\n}\n";
    let (out, _) = stabilized(&set, npm(nested));
    assert_eq!(
        body_of(out, Format::TarGz, "package/package.json"),
        "{\n  \"a\": {\n    \"b\": 1,\n    \"c\": 2\n  }\n}\n"
    );
    let (out, _) = stabilized(&set, npm("{\n  \"_id\": \"x@1.0.0\"\n}\n"));
    assert_eq!(
        body_of(out, Format::TarGz, "package/package.json"),
        "{\n}\n"
    );
}

#[test]
fn a_package_json_with_nothing_injected_is_not_claimed() {
    let authored =
        "{\n  \"name\": \"x\",\n  \"description\": \"mentions \\\"_id\\\" in prose\"\n}\n";
    let (out, applied) = stabilized(&profile("npm-tarball").unwrap(), npm(authored));
    assert!(!fired(&applied, "npm-install-fields-v2"), "{applied:?}");
    assert_eq!(
        body_of(out, Format::TarGz, "package/package.json"),
        authored
    );
}

// --- cargo-vcs-hash ------------------------------------------------------------------------------

fn crate_with(vcs_info: &str) -> Archive {
    parsed(
        gzip(&tar(&[
            ("demo-0.1.0/.cargo_vcs_info.json", vcs_info.as_bytes()),
            ("demo-0.1.0/src/lib.rs", b"pub fn f() {}\n"),
        ])),
        Format::TarGz,
    )
}

const VCS_INFO: &str = ".cargo_vcs_info.json";

#[test]
fn the_commit_a_crate_was_packaged_from_is_masked_and_nothing_around_it_moves() {
    // `cargo package` records the commit it ran at; a rebuild from a detached checkout of the same
    // tree names it too, or names another. The 40 hex digits are masked in place, so the file keeps
    // its shape and every byte either side of the value.
    let pretty = |sha: &str| {
        format!("{{\n  \"git\": {{\n    \"sha1\": \"{sha}\"\n  }},\n  \"path_in_vcs\": \"\"\n}}")
    };
    let compact = |sha: &str| format!("{{\"git\":{{\"sha1\":\"{sha}\",\"dirty\":true}},\"x\":1}}");
    // JSON allows space before the colon as well as after it.
    let spaced = |sha: &str| format!("{{ \"git\" : {{ \"sha1\"  :\t\"{sha}\" }} }}\n");
    let one = "0123456789abcdef0123456789abcdef01234567";
    let two = "FEDCBA9876543210fedcba9876543210FEDCBA98";
    let masked = "x".repeat(40);
    let set = profile("crate").unwrap();
    for shape in [&pretty as &dyn Fn(&str) -> String, &compact, &spaced] {
        let (a, applied) = stabilized(&set, crate_with(&shape(one)));
        let (b, _) = stabilized(&set, crate_with(&shape(two)));
        let path = format!("demo-0.1.0/{VCS_INFO}");
        assert_eq!(body_of(a.clone(), Format::TarGz, &path), shape(&masked));
        assert_eq!(a, b, "{}", shape(one));
        let x = applied
            .iter()
            .find(|x| x.id.as_str() == "cargo-vcs-hash-v2")
            .unwrap();
        assert_eq!(
            (x.risk, x.entries_touched, x.bytes_changed),
            (RiskTier::Content, 1, 40)
        );
    }
}

#[test]
fn a_sha1_that_is_not_forty_hex_digits_is_left_as_it_is() {
    // The pass is total because it declines a shape it does not recognise rather than guess at it.
    let set = profile("crate").unwrap();
    for text in [
        "{\"git\":{\"sha1\":\"0123456789abcdef0123456789abcdef0123456\"}}",
        "{\"git\":{\"sha1\":\"0123456789abcdef0123456789abcdef012345678\"}}",
        "{\"git\":{\"sha1\":\"0123456789abcdefg123456789abcdef01234567\"}}",
        "{\"git\":{\"sha1\":\"0123456789abcdef0123456789abcdef01234567}}",
        "{\"git\":{\"sha1\" 0123456789abcdef0123456789abcdef01234567}}",
        "{\"git\":{\"rev\":\"0123456789abcdef0123456789abcdef01234567\"}}",
    ] {
        let (out, applied) = stabilized(&set, crate_with(text));
        assert!(!fired(&applied, "cargo-vcs-hash-v2"), "{text}: {applied:?}");
        assert_eq!(
            body_of(out, Format::TarGz, &format!("demo-0.1.0/{VCS_INFO}")),
            text
        );
    }
}

// --- wheel-record-v2 -----------------------------------------------------------------------------

#[test]
fn a_record_inside_a_tarball_the_wheel_ships_is_left_as_the_tarball_has_it() {
    // `wheel-record-v2` rewrites the wheel's own manifest. A `.dist-info/RECORD` inside an archive
    // the wheel ships, a vendored distribution or a test fixture, is a file the package delivers,
    // and `apply` visits that archive too.
    let stale = "dep/x.py,sha256=stale,1\ndep-1.0.dist-info/RECORD,,\n";
    let vendored = gzip(&tar(&[
        ("dep/x.py", b"x = 1\n"),
        ("dep-1.0.dist-info/RECORD", stale.as_bytes()),
    ]));
    let wheel = zip(
        &[
            ("pkg/__init__.py", b""),
            ("pkg/vendored.tar.gz", &vendored),
            ("pkg-1.0.dist-info/RECORD", b""),
        ],
        "",
    );
    let mut a = parsed(wheel, Format::Zip);
    let applied = apply(&profile("wheel").unwrap(), &mut a);
    assert!(
        fired(&applied, "wheel-record-v3"),
        "the wheel's own RECORD: {applied:?}"
    );
    let shipped = a
        .entries
        .iter()
        .find(|e| e.path.to_lossy() == "pkg/vendored.tar.gz")
        .expect("the vendored tarball");
    let trigon_archive::Body::Nested { inner, .. } = &shipped.body else {
        panic!("a `.tar.gz` member is read as a nested archive")
    };
    let record = inner
        .entries
        .iter()
        .find(|e| e.path.ends_with(b".dist-info/RECORD"))
        .expect("the vendored RECORD");
    assert_eq!(record.body_bytes().unwrap().as_ref(), stale.as_bytes());
}

/// A wheel that vendors a distribution with its `.dist-info`, as `zzz-1.0-py3-none-any.whl` does:
/// under `aaa/_vendor/`, which sorts before the wheel's own `zzz-1.0.dist-info`.
fn vendoring(own_record: &[u8]) -> Vec<u8> {
    zip(
        &[
            ("zzz/__init__.py", b""),
            ("aaa/_vendor/dep-1.0.dist-info/RECORD", b"dep/x.py,,\n"),
            ("aaa/_vendor/dep-1.0.dist-info/METADATA", b"Name: dep\n"),
            ("zzz-1.0.dist-info/METADATA", b"Name: zzz\n"),
            ("zzz-1.0.dist-info/RECORD", own_record),
        ],
        "",
    )
}

#[test]
fn the_wheels_own_record_is_regenerated_though_a_vendored_one_sorts_first() {
    // `wheel-record-v2` took the first `.dist-info/RECORD` in path order: the vendored one. It
    // regenerated that, a file the wheel ships, and compared the wheel's own as published, so two
    // wheels whose own RECORDs differed only in how their builders wrote them stayed apart.
    let set = profile("wheel").unwrap();
    let (a, applied) = stabilized(&set, parsed(vendoring(b"stale\n"), Format::Zip));
    let (b, _) = stabilized(
        &set,
        parsed(
            vendoring(b"zzz/__init__.py,,\nzzz-1.0.dist-info/RECORD,,\n"),
            Format::Zip,
        ),
    );
    assert!(fired(&applied, "wheel-record-v3"), "{applied:?}");
    assert_eq!(
        body_of(
            a.clone(),
            Format::Zip,
            "aaa/_vendor/dep-1.0.dist-info/RECORD"
        ),
        "dep/x.py,,\n",
        "the vendored RECORD is the wheel's content"
    );
    let own = body_of(a.clone(), Format::Zip, "zzz-1.0.dist-info/RECORD");
    assert!(
        own.contains("aaa/_vendor/dep-1.0.dist-info/RECORD,sha256="),
        "the wheel's RECORD lists the vendored one as a member: {own}"
    );
    assert!(own.ends_with("zzz-1.0.dist-info/RECORD,,\n"), "{own}");
    assert_eq!(a, b, "the wheel's own RECORD was compared as published");
}

#[test]
fn a_wheel_with_two_dist_info_directories_at_its_root_keeps_every_record() {
    // The format puts one `.dist-info` at the root and pip refuses a wheel with two, so neither
    // RECORD is the wheel's by the format, and neither is rewritten on a guess.
    let bytes = zip(
        &[
            ("a-1.0.dist-info/RECORD", b"stale a\n"),
            ("b-1.0.dist-info/RECORD", b"stale b\n"),
            ("pkg/__init__.py", b""),
        ],
        "",
    );
    let (out, applied) = stabilized(&profile("wheel").unwrap(), parsed(bytes, Format::Zip));
    assert!(!fired(&applied, "wheel-record-v3"), "{applied:?}");
    assert_eq!(
        body_of(out.clone(), Format::Zip, "a-1.0.dist-info/RECORD"),
        "stale a\n"
    );
    assert_eq!(
        body_of(out, Format::Zip, "b-1.0.dist-info/RECORD"),
        "stale b\n"
    );
}

#[test]
fn record_quotes_a_path_only_where_csv_needs_it() {
    // PEP 376: RECORD is CSV. A comma or a quote in a member name has to be quoted, or the row
    // splits in the wrong place; every other path is written bare, as every wheel builder does.
    let bytes = zip(
        &[
            ("pkg/a,b.py", b"x = 1\n"),
            ("pkg/say \"hi\".py", b"y = 2\n"),
            ("pkg/plain.py", b"z = 3\n"),
            ("pkg-1.0.dist-info/RECORD", b""),
        ],
        "",
    );
    let (out, _) = stabilized(&profile("wheel").unwrap(), parsed(bytes, Format::Zip));
    let record = body_of(out, Format::Zip, "pkg-1.0.dist-info/RECORD");
    let lines: Vec<&str> = record.lines().collect();
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("\"pkg/a,b.py\",sha256=")),
        "{record}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("\"pkg/say \"\"hi\"\".py\",sha256=")),
        "{record}"
    );
    assert!(
        lines.iter().any(|l| l.starts_with("pkg/plain.py,sha256=")),
        "{record}"
    );
    assert_eq!(lines.last(), Some(&"pkg-1.0.dist-info/RECORD,,"));
}

// --- gem-metadata-cert-chain ---------------------------------------------------------------------

#[test]
fn an_unsigned_gem_has_no_certificate_chain_to_drop() {
    let spec = "--- !ruby/object:Gem::Specification\nname: x\ncert_chain: []\nsummary: x\n";
    let gem = tar(&[("metadata.gz", &gzip(spec.as_bytes()))]);
    let set = profile("gem")
        .unwrap()
        .filtered(&["gem-metadata-cert-chain-v2".into()], &[]);
    let (_, applied) = stabilized(&set, parsed(gem, Format::Tar));
    assert!(applied.is_empty(), "{applied:?}");
}

// --- gzip-meta: which gzip headers are a container -----------------------------------------------

/// A gzip stream whose header carries a build time, a file name and a Unix OS byte.
fn gzip_stamped(body: &[u8], mtime: u32, name: &str) -> Vec<u8> {
    use std::io::Write as _;
    let mut w = flate2::GzBuilder::new()
        .mtime(mtime)
        .filename(name)
        .operating_system(3)
        .write(Vec::new(), flate2::Compression::default());
    w.write_all(body).unwrap();
    w.finish().unwrap()
}

#[test]
fn the_gzip_headers_of_a_gems_own_members_are_normalized() {
    // `metadata.gz` and `data.tar.gz` are framing the gem format mandates, one level down: their
    // headers say when and where `gem build` ran, not what the gem holds.
    let spec = b"--- !ruby/object:Gem::Specification\nname: x\n";
    let payload = tar(&[("lib/x.rb", b"X = 1\n")]);
    let gem = |mtime: u32| {
        tar(&[
            ("metadata.gz", &gzip_stamped(spec, mtime, "metadata")),
            ("data.tar.gz", &gzip_stamped(&payload, mtime, "data.tar")),
        ])
    };
    assert_ne!(gem(1_600_000_000), gem(1_700_000_000));
    let set = profile("gem").unwrap();
    let (a, applied) = stabilized(&set, parsed(gem(1_600_000_000), Format::Tar));
    let (b, _) = stabilized(&set, parsed(gem(1_700_000_000), Format::Tar));
    assert_eq!(
        a, b,
        "two gems differing only in their members' gzip headers"
    );
    assert!(fired(&applied, "gzip-meta-v2"), "{applied:?}");
}

#[test]
fn a_gzip_file_a_package_ships_keeps_its_header() {
    // An npm package's `banner.json.gz` is a gzip member of an outer tar exactly as a gem's
    // `metadata.gz` is, and it is a deliverable: its header is bytes the package ships, and
    // normalizing it would rewrite content rather than a container.
    let package = |mtime: u32| {
        gzip(&tar(&[
            ("package/package.json", b"{}\n"),
            (
                "package/banner.json.gz",
                &gzip_stamped(b"{\"hello\": 1}\n", mtime, "banner.json"),
            ),
        ]))
    };
    let set = profile("npm-tarball").unwrap();
    let mut a = parsed(package(1_600_000_000), Format::TarGz);
    apply(&set, &mut a);
    let banner = a
        .entries
        .iter()
        .find(|e| e.path.to_lossy() == "package/banner.json.gz")
        .expect("the shipped gzip file");
    let trigon_archive::Body::Nested { inner, .. } = &banner.body else {
        panic!("a `.gz` member is read as a nested archive")
    };
    let Trailer::Gzip(h) = &inner.trailer else {
        panic!("a gzip member carries a gzip header")
    };
    assert_eq!(
        (h.mtime, h.name.as_deref(), h.os),
        (Some(1_600_000_000), Some(&b"banner.json"[..]), 3)
    );

    let (x, _) = stabilized(&set, parsed(package(1_600_000_000), Format::TarGz));
    let (y, _) = stabilized(&set, parsed(package(1_700_000_000), Format::TarGz));
    assert_ne!(
        x, y,
        "a difference in a file the package ships is still a difference"
    );
}

/// Gzip with a clean header, at a compression level of the caller's.
fn gzip_at(body: &[u8], level: u32) -> Vec<u8> {
    use std::io::Write as _;
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(level));
    e.write_all(body).unwrap();
    e.finish().unwrap()
}

/// A tar already in the form the tar passes leave, in the order given: PAX atime 0, mtime 0, mode
/// 0777, no owner. Nothing in it is left for a pass to change but, perhaps, the order.
fn settled_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let set = profile("tar")
        .unwrap()
        .filtered(&["all".into()], &["tar-entry-order-v2".into()]);
    let mut a = parsed(tar(entries), Format::Tar);
    apply(&set, &mut a);
    serialize(&a, true).unwrap()
}

#[test]
fn a_nested_tar_is_written_back_sorted_when_only_its_order_moved() {
    // The pair that showed it (`docs/16-findings.md` §3.106): one `pkg/inner.tar.gz` each, the same
    // two members in either order and nothing else to normalize in them. The sort marked no member,
    // so the inner archive went out as it arrived, and the two stayed `divergent` with the pass in
    // `applied`.
    let outer = |order: &[(&str, &[u8])]| {
        let inner = gzip_at(&settled_tar(order), 9);
        gzip(&tar(&[("pkg/inner.tar.gz", &inner)]))
    };
    let (a, b): (&[u8], &[u8]) = (b"a", b"b");
    let x = outer(&[("a", a), ("b", b)]);
    let y = outer(&[("b", b), ("a", a)]);
    assert_ne!(x, y);
    let set = profile("tar-gzip").unwrap();
    let (sx, _) = stabilized(&set, parsed(x, Format::TarGz));
    let (sy, applied) = stabilized(&set, parsed(y, Format::TarGz));
    assert!(fired(&applied, "tar-entry-order-v2"), "{applied:?}");
    assert!(
        sx == sy,
        "two archives differing only in an order the pass sorted"
    );
}

#[test]
fn the_gzip_framing_of_a_gem_is_written_again_however_it_was_compressed() {
    // A gem's own members are framing, and the serializer writes framing uncompressed so that no
    // encoder's choices reach a digest. One with a clean header and nothing inside to normalize
    // went out as it arrived, and two gems that differed only in `gem build`'s compression level
    // stayed `divergent`.
    let spec = b"--- !ruby/object:Gem::Specification\nname: x\n\
                 date: 1980-01-02 00:00:00.000000000 Z\n";
    let payload = settled_tar(&[("lib/x.rb", b"X = 1\n")]);
    let gem = |level: u32| {
        tar(&[
            ("data.tar.gz", &gzip_at(&payload, level)),
            ("metadata.gz", &gzip_at(spec, level)),
        ])
    };
    assert_ne!(gem(1), gem(9));
    let set = profile("gem").unwrap();
    let (a, _) = stabilized(&set, parsed(gem(1), Format::Tar));
    let (b, _) = stabilized(&set, parsed(gem(9), Format::Tar));
    assert!(
        a == b,
        "two gems differing only in the compression level of their framing"
    );
}

#[test]
fn a_gzip_file_a_package_ships_keeps_its_compressed_bytes() {
    // The other side of the line, and a limit rather than a defect: a `.gz` that is not a tar is
    // a file the package delivers, nothing normalizes what it holds, and it is compared as it was
    // shipped, its compression level with it.
    let package = |level: u32| {
        gzip(&tar(&[
            ("package/package.json", b"{}\n"),
            (
                "package/banner.json.gz",
                &gzip_at(&b"{\"hello\": 1}\n".repeat(64), level),
            ),
        ]))
    };
    let set = profile("tar-gzip").unwrap();
    let (x, _) = stabilized(&set, parsed(package(1), Format::TarGz));
    let (y, _) = stabilized(&set, parsed(package(9), Format::TarGz));
    assert_ne!(x, y);
}

/// A tar of two small entries split after the first: the first member holds the first entry and no
/// end of archive, the second the rest.
fn in_two_members(whole: &[u8]) -> (Vec<u8>, Vec<u8>) {
    use std::io::Read as _;
    let two = [gzip(&whole[..1024]), gzip(&whole[1024..])].concat();
    // What Cargo's `GzDecoder` and RubyGems' `GzipReader` read of it: the first member, one entry.
    let mut first = Vec::new();
    flate2::read::GzDecoder::new(&two[..])
        .read_to_end(&mut first)
        .unwrap();
    assert_eq!(
        first,
        whole[..1024],
        "the fixture splits after the first entry"
    );
    (gzip(whole), two)
}

#[test]
fn a_gem_whose_payload_rubygems_reads_in_part_does_not_match_the_whole_of_it() {
    // RubyGems reads `data.tar.gz` as its first gzip member and stops; gunzip reads every member.
    // A payload whose last entry sat in a second member was read here as the whole tar, written
    // again as one member, and matched an honest build of every entry, though the gem installs
    // without the last one (`docs/16-findings.md` §3.106). The layer is not opened now, and the
    // two compare as the bytes they are.
    let whole = tar(&[("lib/a.rb", b"A = 1\n"), ("lib/hardening.rb", b"H = 1\n")]);
    let (one, two) = in_two_members(&whole);
    let gem = |data: &[u8]| tar(&[("data.tar.gz", data)]);
    let set = profile("gem").unwrap();
    let (honest, _) = stabilized(&set, parsed(gem(&one), Format::Tar));
    let mut notes: Vec<Note> = Vec::new();
    let split = parse(gem(&two), Format::Tar, &Limits::default(), &mut notes).unwrap();
    assert!(
        notes.iter().any(|n| n.code == NoteCode::NestedParseFailed),
        "{notes:?}"
    );
    let (partial, applied) = stabilized(&set, split.archive);
    assert!(
        honest != partial,
        "a gem RubyGems installs in part matched the whole of it: {applied:?}"
    );
}

#[test]
fn a_crate_whose_gzip_layer_holds_a_second_member_of_data_is_refused() {
    // Cargo unpacks a `.crate` through `flate2`'s `GzDecoder`, which reads the first member and
    // stops. Read as every member, a crate in two installed only its first member's files and
    // matched a rebuild of all of them. It is refused, and reaches no verdict.
    let whole = tar(&[
        ("x-1.0/src/lib.rs", b"pub fn a() {}\n"),
        ("x-1.0/src/b.rs", b"pub fn b() {}\n"),
    ]);
    let (_, two) = in_two_members(&whole);
    let mut notes: Vec<Note> = Vec::new();
    match parse(two, Format::TarGz, &Limits::default(), &mut notes) {
        Err(ArchiveError::Malformed {
            format: "gzip",
            detail,
        }) => assert!(
            detail.contains("holds data after a first member"),
            "{detail}"
        ),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// --- metadata of the other format ----------------------------------------------------------------

// A tar pass reads a tar entry's raw fields, a zip pass a zip entry's, and `gzip-meta` a gzip
// header. The parser never hands a format the other's metadata, but the model's fields are public,
// so a pass can meet it; it declines it rather than act on fields that are not there. Each case
// first shows the passes apply to that archive as parsed, or the decline would prove nothing.

#[test]
fn tar_passes_decline_an_entry_carrying_zip_metadata() {
    let foreign = ZipRaw {
        creator_version: 0x031e,
        reader_version: 20,
        flags: 0x0808,
        method: 8,
        crc32: 0xdead_beef,
        extra: b"UT\x05\x00\x01\x00\x00\x00\x00".to_vec(),
        comment: b"packed by hand".to_vec(),
        external_attrs: 0o100644 << 16,
        internal_attrs: 1,
        dos_datetime: (0x5a21, 0x6c1e),
    };
    let bytes = tar(&[("pkg/a.txt", b"a"), ("pkg/b.txt", b"b")]);
    let (_, applied) = stabilized(&profile("tar").unwrap(), parsed(bytes.clone(), Format::Tar));
    assert!(
        fired(&applied, "tar-time") && fired(&applied, "tar-owners"),
        "{applied:?}"
    );

    let mut a = parsed(bytes, Format::Tar);
    for e in &mut a.entries {
        e.raw = RawMeta::Zip(foreign.clone());
        // `tar-mode` reads no raw field, so it is given nothing to do rather than excused.
        e.meta.mode = 0o777;
    }
    let applied = apply(&profile("tar").unwrap(), &mut a);
    assert!(
        applied.is_empty(),
        "a tar pass acted on zip metadata: {applied:?}"
    );
    assert!(!a.is_dirty());
    for e in &a.entries {
        assert_eq!(e.raw, RawMeta::Zip(foreign.clone()));
        assert_eq!(e.meta.mtime, Some(1_700_000_000), "`tar-time` half applied");
    }
}

#[test]
fn zip_passes_decline_an_entry_carrying_tar_metadata() {
    let mut foreign = TarRaw {
        uid: 1000,
        gid: 1000,
        uname: b"alice".to_vec(),
        gname: b"staff".to_vec(),
        devmajor: 8,
        devminor: 1,
        atime: Some(1_700_000_000),
        ctime: Some(1_700_000_000),
        ..TarRaw::default()
    };
    foreign.pax.insert("SCHILY.ino".into(), "4242".into());
    let bytes = zip(&[("a.txt", b"one"), ("b.txt", b"two")], "");
    let (_, applied) = stabilized(&profile("zip").unwrap(), parsed(bytes.clone(), Format::Zip));
    assert!(fired(&applied, "zip-versions"), "{applied:?}");

    let mut a = parsed(bytes, Format::Zip);
    let mtimes: Vec<Option<i64>> = a.entries.iter().map(|e| e.meta.mtime).collect();
    for e in &mut a.entries {
        e.raw = RawMeta::Tar(foreign.clone());
    }
    let applied = apply(&profile("zip").unwrap(), &mut a);
    assert!(
        applied.is_empty(),
        "a zip pass acted on tar metadata: {applied:?}"
    );
    assert!(!a.is_dirty());
    for (e, mtime) in a.entries.iter().zip(mtimes) {
        assert_eq!(e.raw, RawMeta::Tar(foreign.clone()));
        assert_eq!(e.meta.mtime, mtime, "`zip-time` half applied");
    }
}

#[test]
fn gzip_meta_declines_a_trailer_that_is_not_a_gzip_header() {
    use std::io::Write as _;
    let mut w = flate2::GzBuilder::new()
        .mtime(1_700_000_000)
        .filename("pkg.tar")
        .write(Vec::new(), flate2::Compression::default());
    w.write_all(&tar(&[("pkg/a.txt", b"a")])).unwrap();
    let gz = w.finish().unwrap();
    let set = profile("tar-gzip")
        .unwrap()
        .filtered(&["gzip-meta-v2".into()], &[]);
    let (_, applied) = stabilized(&set, parsed(gz.clone(), Format::TarGz));
    assert!(fired(&applied, "gzip-meta-v2"), "{applied:?}");

    let mut a = parsed(gz, Format::TarGz);
    let foreign = Trailer::Zip {
        comment: b"not a gzip header".to_vec(),
    };
    a.trailer = foreign.clone();
    let applied = apply(&set, &mut a);
    assert!(applied.is_empty(), "{applied:?}");
    assert!(!a.is_dirty());
    assert_eq!(a.trailer, foreign);
}
