//! What a run says about itself: which pass touched which field of which member, who wrote each
//! pass, and where in an artifact a pass is running.
//!
//! `apply_traced`'s edits are the ground truth behind "which pass did what to this file", joined
//! to the comparator's difference codes by `(field, path)`. A field named in a spelling the
//! comparator does not use joins to nothing, and the page then says no pass touched it — so each
//! field is checked here against the comparator's own vocabulary, one pass changing one field.
//! Custom passes stand in for the definitions repository's, which may change any field at all.

use std::sync::Arc;

use trigon_archive::{Archive, Entry, EntryKind, Limits, RawMeta, TarRaw, ZipRaw, parse};
use trigon_core::{Format, Note, Provenance, RiskTier, StabilizerId};
use trigon_stabilize::{
    Cx, FieldEdit, Stabilizer, StabilizerSet, Stage, Touched, all_builtin, all_profiles, apply,
    apply_traced, profile,
};

/// A pass that applies `f` to every entry at `depth` and reports `touched` for each.
struct Custom {
    id: &'static str,
    stage: Stage,
    provenance: Provenance,
    depth: usize,
    touched: Touched,
    f: Box<dyn Fn(&mut Entry) + Send + Sync>,
}

impl std::fmt::Debug for Custom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Custom({})", self.id)
    }
}

impl Stabilizer for Custom {
    fn id(&self) -> StabilizerId {
        StabilizerId::new(self.id)
    }
    fn stage(&self) -> Stage {
        self.stage
    }
    fn risk(&self) -> RiskTier {
        RiskTier::Content
    }
    fn provenance(&self) -> Provenance {
        self.provenance.clone()
    }
    fn applies(&self, cx: &Cx) -> bool {
        cx.at_depth(self.depth)
    }
    fn on_entry(&self, e: &mut Entry, _cx: &Cx) -> Touched {
        (self.f)(e);
        self.touched
    }
}

fn custom(f: impl Fn(&mut Entry) + Send + Sync + 'static) -> Custom {
    Custom {
        id: "custom-edit",
        stage: Stage::Patch,
        provenance: Provenance::Human {
            reviewer: "alice".into(),
        },
        depth: 0,
        touched: Touched::entry(),
        f: Box::new(f),
    }
}

fn set_of(passes: Vec<Custom>) -> StabilizerSet {
    StabilizerSet::new(
        "custom",
        passes
            .into_iter()
            .map(|p| Arc::new(p) as Arc<dyn Stabilizer>)
            .collect(),
    )
}

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

fn gzip(body: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(body).unwrap();
    e.finish().unwrap()
}

fn zip(members: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write as _;
    let mut w = zip_crate::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts: zip_crate::write::FileOptions<'_, ()> = zip_crate::write::FileOptions::default()
        .compression_method(zip_crate::CompressionMethod::Deflated);
    for (name, body) in members {
        w.start_file(*name, opts).unwrap();
        w.write_all(body).unwrap();
    }
    w.finish().unwrap().into_inner()
}

fn parsed(bytes: Vec<u8>, format: Format) -> Archive {
    let mut notes: Vec<Note> = Vec::new();
    parse(bytes, format, &Limits::default(), &mut notes)
        .unwrap()
        .archive
}

fn tar_raw(e: &mut Entry) -> &mut TarRaw {
    match &mut e.raw {
        RawMeta::Tar(r) => r,
        RawMeta::Zip(_) => panic!("a tar entry with zip metadata"),
    }
}

fn zip_raw(e: &mut Entry) -> &mut ZipRaw {
    match &mut e.raw {
        RawMeta::Zip(r) => r,
        RawMeta::Tar(_) => panic!("a zip entry with tar metadata"),
    }
}

fn edit(path: &str, field: &str) -> FieldEdit {
    FieldEdit {
        path: path.into(),
        field: field.into(),
        pass: StabilizerId::new("custom-edit"),
    }
}

// --- one pass, one field -------------------------------------------------------------------------

#[test]
fn each_tar_field_a_pass_changes_is_named_as_the_comparator_names_it() {
    type Change = fn(&mut Entry);
    let cases: Vec<(&str, Change)> = vec![
        ("kind", |e| e.kind = EntryKind::Directory),
        ("size", |e| e.meta.size += 1),
        ("mtime", |e| e.meta.mtime = Some(42)),
        ("mode", |e| e.meta.mode = 0o600),
        ("tar.typeflag", |e| tar_raw(e).typeflag = b'7'),
        ("tar.linkname", |e| {
            tar_raw(e).linkname = b"elsewhere".to_vec()
        }),
        ("tar.uid", |e| tar_raw(e).uid = 7),
        ("tar.gid", |e| tar_raw(e).gid = 7),
        ("tar.uname", |e| tar_raw(e).uname = b"mallory".to_vec()),
        ("tar.gname", |e| tar_raw(e).gname = b"mallory".to_vec()),
        ("tar.device", |e| tar_raw(e).devminor = 3),
        ("tar.atime", |e| tar_raw(e).atime = Some(9)),
        ("tar.ctime", |e| tar_raw(e).ctime = Some(9)),
        ("tar.pax.comment", |e| {
            tar_raw(e).pax.insert("comment".into(), "x".into());
        }),
        ("raw.format", |e| e.raw = RawMeta::Zip(ZipRaw::default())),
    ];
    for (field, change) in cases {
        let mut a = parsed(tar(&[("a.txt", b"data")]), Format::Tar);
        let (applied, edits) = apply_traced(&set_of(vec![custom(change)]), &mut a);
        assert_eq!(edits, [edit("a.txt", field)], "changing `{field}`");
        assert_eq!(applied.len(), 1, "`{field}`: {applied:?}");
    }
}

#[test]
fn each_zip_field_a_pass_changes_is_named_as_the_comparator_names_it() {
    type Change = fn(&mut Entry);
    let cases: Vec<(&str, Change)> = vec![
        ("zip.creator_version", |e| zip_raw(e).creator_version ^= 1),
        ("zip.reader_version", |e| zip_raw(e).reader_version ^= 1),
        ("zip.flags", |e| zip_raw(e).flags ^= 1),
        ("zip.method", |e| zip_raw(e).method ^= 1),
        ("zip.crc32", |e| zip_raw(e).crc32 ^= 1),
        ("zip.extra", |e| zip_raw(e).extra.push(0)),
        ("zip.comment", |e| zip_raw(e).comment.push(b'c')),
        ("zip.external_attrs", |e| zip_raw(e).external_attrs ^= 1),
        ("zip.internal_attrs", |e| zip_raw(e).internal_attrs ^= 1),
        ("zip.dos_datetime", |e| zip_raw(e).dos_datetime.0 ^= 1),
        ("raw.format", |e| e.raw = RawMeta::Tar(TarRaw::default())),
    ];
    for (field, change) in cases {
        let mut a = parsed(zip(&[("a.txt", b"data")]), Format::Zip);
        let (_, edits) = apply_traced(&set_of(vec![custom(change)]), &mut a);
        assert_eq!(edits, [edit("a.txt", field)], "changing `{field}`");
    }
}

#[test]
fn a_pax_keyword_a_pass_rewrites_is_one_edit_however_many_sides_carry_it() {
    // A keyword present before and after the pass is found on both sides of the fingerprint, and
    // the edit is still one field of one member changed by one pass — as the comparator, which
    // names it once, counts it.
    let mut a = parsed(tar(&[("a.txt", b"data")]), Format::Tar);
    tar_raw(&mut a.entries[0])
        .pax
        .insert("comment".into(), "before".into());
    let pass = custom(|e| {
        tar_raw(e).pax.insert("comment".into(), "after".into());
    });
    let (_, edits) = apply_traced(&set_of(vec![pass]), &mut a);
    assert_eq!(edits, [edit("a.txt", "tar.pax.comment")]);

    // One removed and one added are two keywords, each named once.
    let mut a = parsed(tar(&[("a.txt", b"data")]), Format::Tar);
    tar_raw(&mut a.entries[0])
        .pax
        .insert("comment".into(), "x".into());
    let pass = custom(|e| {
        let pax = &mut tar_raw(e).pax;
        pax.remove("comment");
        pax.insert("hdrcharset".into(), "BINARY".into());
    });
    let (_, edits) = apply_traced(&set_of(vec![pass]), &mut a);
    assert_eq!(
        edits,
        [
            edit("a.txt", "tar.pax.comment"),
            edit("a.txt", "tar.pax.hdrcharset")
        ]
    );
}

#[test]
fn a_member_inside_a_nested_archive_is_named_outer_bang_inner() {
    // The comparator's spelling for a nested member, so a difference inside a gem's data.tar.gz
    // joins to the pass that caused it rather than to nothing.
    let inner = gzip(&tar(&[("lib/x.rb", b"X = 1\n")]));
    let mut a = parsed(tar(&[("data.tar.gz", &inner)]), Format::Tar);
    let mut pass = custom(|e| tar_raw(e).uid = 7);
    pass.depth = 1;
    let (_, edits) = apply_traced(&set_of(vec![pass]), &mut a);
    assert_eq!(edits, [edit("data.tar.gz!lib/x.rb", "tar.uid")]);
}

#[test]
fn a_body_change_is_attributed_from_what_the_pass_reports() {
    // Bodies are not fingerprinted — reading them would defeat copy-on-write — so a pass that
    // rewrote one says so through `Touched::bytes`, and that is what names it.
    let mut pass = custom(|e| e.body_mut().unwrap().copy_from_slice(b"DATA"));
    pass.touched = Touched::entry_bytes(4);
    let mut a = parsed(tar(&[("a.txt", b"data")]), Format::Tar);
    let (applied, edits) = apply_traced(&set_of(vec![pass]), &mut a);
    assert_eq!(edits, [edit("a.txt", "body")]);
    assert_eq!(applied[0].bytes_changed, 4);

    // Metadata alone, reported as such, names no body.
    let mut a = parsed(tar(&[("a.txt", b"data")]), Format::Tar);
    let (_, edits) = apply_traced(&set_of(vec![custom(|e| e.meta.mode = 0o600)]), &mut a);
    assert_eq!(edits, [edit("a.txt", "mode")]);
}

#[test]
fn a_pass_that_reports_bytes_and_no_entries_still_changed_something() {
    // Entries and bytes are each a report of work, and `applied` keeps a pass that did any: a pass
    // counting only the bytes it rewrote is applied, capped for, and named for the body it wrote.
    let mut pass = custom(|e| e.body_mut().unwrap().copy_from_slice(b"DATA"));
    pass.touched = Touched {
        entries: 0,
        bytes: 4,
    };
    let mut a = parsed(tar(&[("a.txt", b"data")]), Format::Tar);
    let (applied, edits) = apply_traced(&set_of(vec![pass]), &mut a);
    let [x] = applied.as_slice() else {
        panic!("{applied:?}")
    };
    assert_eq!((x.entries_touched, x.bytes_changed), (0, 4));
    assert_eq!(edits, [edit("a.txt", "body")]);
}

#[test]
fn a_pass_that_changes_nothing_is_neither_applied_nor_attributed() {
    // `applied` is what the provenance cap reads: a configured pass that did no work has no
    // business capping the verdict.
    let mut pass = custom(|_| {});
    pass.touched = Touched::NONE;
    let mut a = parsed(tar(&[("a.txt", b"data")]), Format::Tar);
    let (applied, edits) = apply_traced(&set_of(vec![pass]), &mut a);
    assert!(applied.is_empty(), "{applied:?}");
    assert!(edits.is_empty(), "{edits:?}");
}

// --- who wrote a pass ----------------------------------------------------------------------------

#[test]
fn who_wrote_a_pass_travels_into_applied_the_digest_and_the_manifest() {
    let by = |provenance: Provenance| {
        let mut p = custom(|e| e.meta.mode = 0o600);
        p.provenance = provenance;
        set_of(vec![p])
    };
    let human = by(Provenance::Human {
        reviewer: "alice".into(),
    });
    let model = by(Provenance::Model {
        model_id: "m-1".into(),
        run_id: "run-7".into(),
    });
    let builtin = by(Provenance::Builtin);

    let mut a = parsed(tar(&[("a.txt", b"data")]), Format::Tar);
    let applied = apply(&human, &mut a);
    assert_eq!(
        applied[0].provenance,
        Provenance::Human {
            reviewer: "alice".into()
        },
        "the cap needs to see a human-written pass fired"
    );

    // The same id, stage and risk, written by someone else, is a different set.
    assert_ne!(human.digest(), model.digest());
    assert_ne!(human.digest(), builtin.digest());
    for (set, tag) in [
        (&human, "human:alice"),
        (&model, "model:m-1:run-7"),
        (&builtin, "builtin"),
    ] {
        let m = set.manifest();
        assert_eq!(m.members[0].provenance, tag);
        assert!(
            m.self_consistent(),
            "`{tag}` manifest does not recompute its digest"
        );
    }
}

// --- the catalogue and the order passes run in ---------------------------------------------------

#[test]
fn a_sets_ids_run_default_then_patch_then_finalize() {
    let mut late = custom(|_| {});
    late.id = "a-custom-patch";
    let mut wheel: Vec<Arc<dyn Stabilizer>> = profile("wheel").unwrap().members;
    wheel.reverse();
    wheel.insert(0, Arc::new(late));
    let set = StabilizerSet::new("wheel+patch", wheel);
    let ids: Vec<String> = set.ids().iter().map(|i| i.to_string()).collect();
    // A patch from the definitions repository runs after every builtin default and before RECORD
    // is regenerated, so the manifest describes the wheel the patch left.
    assert_eq!(
        ids[ids.len() - 2..],
        ["a-custom-patch", "wheel-record"],
        "{ids:?}"
    );
    let defaults = &ids[..ids.len() - 2];
    let mut sorted = defaults.to_vec();
    sorted.sort();
    assert_eq!(
        defaults,
        sorted.as_slice(),
        "default passes run in id order"
    );
}

#[test]
fn the_builtin_catalogue_is_every_pass_the_profiles_use() {
    // "Every builtin pass", as `all_builtin` says of itself, and the same list the profiles draw
    // on: a pass a profile runs and the catalogue omits is invisible to anything enumerating it.
    let catalogue: Vec<String> = all_builtin().iter().map(|p| p.id().to_string()).collect();
    let mut unique = catalogue.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(
        unique.len(),
        catalogue.len(),
        "a pass listed twice: {catalogue:?}"
    );

    let mut used: Vec<String> = all_profiles()
        .into_iter()
        .flat_map(|p| profile(p).unwrap().ids())
        .map(|i| i.to_string())
        .collect();
    used.sort();
    used.dedup();
    assert_eq!(unique, used, "the catalogue and the profiles disagree");
    assert!(
        all_builtin()
            .iter()
            .all(|p| p.provenance() == Provenance::Builtin)
    );
}

// --- where a pass runs ---------------------------------------------------------------------------

#[test]
fn a_context_knows_its_depth_format_and_where_it_was_found() {
    // The vocabulary gem passes are written in: "at depth 0", "at minimum depth 1", "only inside
    // metadata.gz".
    let root = Cx::root(Format::Tar);
    assert_eq!((root.depth(), root.format()), (0, Format::Tar));
    assert!(root.archive_path().is_none());
    assert!(root.at_depth(0) && root.min_depth(0) && !root.min_depth(1));
    assert!(!root.archive_path_ends_with(b"metadata.gz"));

    let meta = root.push(
        Format::Gzip,
        trigon_core::EntryPath::new(b"metadata.gz".to_vec()),
    );
    assert_eq!((meta.depth(), meta.format()), (1, Format::Gzip));
    assert!(meta.at_depth(1) && meta.min_depth(1) && !meta.min_depth(2));
    assert!(meta.archive_path_ends_with(b"metadata.gz"));
    assert!(!meta.archive_path_ends_with(b"data.tar.gz"));

    // Pushing makes a new context; the parent is unchanged.
    assert_eq!(root.depth(), 0);
    let deeper = meta.push(Format::Tar, trigon_core::EntryPath::new(b"x.tar".to_vec()));
    assert!(deeper.min_depth(1) && deeper.min_depth(2) && !deeper.at_depth(1));

    // A context with no levels at all reads as a raw, outermost one rather than panicking.
    let empty = Cx::default();
    assert_eq!((empty.depth(), empty.format()), (0, Format::Raw));
}
