//! Limits at their exact boundary, and what they leave behind.
//!
//! `Limits` is the whole defence against a hostile artifact. Three of its five fields are enforced
//! today — `recursion`, `total_expanded_bytes`, `max_entries` — and `docs/threat-model.md` P1 rests
//! on all three: "Parsing a hostile artifact does not panic, escape its *enforced* limits ... or
//! silently change a digest. **Every limit is enforced against what decompression produces, not
//! against the size the input declares.**"
//!
//! `crates/trigon-archive/tests/limits.rs` already shows that each of the three fires *somewhere*.
//! What it does not show is where. A ceiling checked with `>=` where the code means `>` rejects a
//! legitimate artifact; one checked with `>` where the code means `>=` admits one byte more than the
//! operator configured, every time, silently. Neither shows up in a test that feeds a 4 GiB claim
//! through a 1 MiB budget: that input is four thousand times over, so it trips whichever comparison
//! is written. So every ceiling here is exercised twice, with inputs one unit apart.
//!
//! The second half of the class is the record a trip leaves. `ArchiveError::LimitExceeded` carries
//! `limit`, `actual` and `allowed` precisely so an operator sweeping a corpus can tell "raise the
//! ceiling" from "this package is hostile" without re-running anything. A limit that fires and
//! reports only "too big" has cost them the diagnosis, so the fields are asserted by value and not
//! merely by variant.

use std::io::Write as _;

use trigon_archive::{Archive, ArchiveError, Body, GzipHeader, Limits, gzip, parse};
use trigon_core::{Format, Note, NoteCode};

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

/// A tar of `n` one-byte members.
fn tar_with_entries(n: usize) -> Vec<u8> {
    let mut b = ::tar::Builder::new(Vec::new());
    for i in 0..n {
        let mut h = ::tar::Header::new_ustar();
        h.set_size(1);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, format!("f{i}.txt"), &b"x"[..])
            .unwrap();
    }
    b.into_inner().unwrap()
}

/// A tar holding one honest member of exactly `size` bytes.
fn tar_of_exactly(size: usize) -> Vec<u8> {
    let body = vec![b'a'; size];
    let mut b = ::tar::Builder::new(Vec::new());
    let mut h = ::tar::Header::new_ustar();
    h.set_size(size as u64);
    h.set_mode(0o644);
    h.set_cksum();
    b.append_data(&mut h, "body.bin", &body[..]).unwrap();
    b.into_inner().unwrap()
}

/// A gzip member whose payload inflates to exactly `size` bytes.
fn gzip_of_exactly(size: usize) -> Vec<u8> {
    let mut out = Vec::new();
    gzip::write(
        &GzipHeader::default(),
        &vec![0u8; size],
        flate2::Compression::best(),
        &mut out,
    )
    .unwrap();
    out
}

/// An honest stored zip of `n` distinct members, each one byte.
fn zip_with_entries(n: usize) -> Vec<u8> {
    use zip_crate::write::SimpleFileOptions;
    let opts =
        SimpleFileOptions::default().compression_method(zip_crate::CompressionMethod::Stored);
    let mut w = zip_crate::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for i in 0..n {
        w.start_file(format!("f{i}.txt"), opts).unwrap();
        w.write_all(b"x").unwrap();
    }
    w.finish().unwrap().into_inner()
}

/// A zip whose central directory declares `copies` stored members, all pointing at one local
/// header, each declaring `declared_uncomp` uncompressed bytes regardless of how many the member
/// actually holds.
///
/// Hand-assembled: this crate's own zip writer is honest by construction, and the lie is the point.
/// `copies > 1` is the overlapping-member shape — one body, many directory entries naming it.
fn stored_zip(payload: &[u8], copies: u16, declared_uncomp: u32) -> Vec<u8> {
    let crc = crc32fast::hash(payload);
    let comp = payload.len() as u32;

    let mut out = Vec::new();
    let name0 = b"shared.bin";
    out.extend_from_slice(&0x0403_4b50u32.to_le_bytes()); // local file header
    out.extend_from_slice(&20u16.to_le_bytes()); // version needed
    out.extend_from_slice(&0u16.to_le_bytes()); // flags
    out.extend_from_slice(&0u16.to_le_bytes()); // method: store
    out.extend_from_slice(&0u16.to_le_bytes()); // time
    out.extend_from_slice(&0u16.to_le_bytes()); // date
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&comp.to_le_bytes());
    out.extend_from_slice(&comp.to_le_bytes()); // the local header is honest; the directory is not
    out.extend_from_slice(&(name0.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // extra length
    out.extend_from_slice(name0);
    out.extend_from_slice(payload);

    let cd_offset = out.len() as u32;
    let mut cd = Vec::new();
    for i in 0..copies {
        // Distinct names, so nothing is refused for being a duplicate path rather than for being
        // over the ceiling.
        let name = format!("copy{i:05}.bin").into_bytes();
        cd.extend_from_slice(&0x0201_4b50u32.to_le_bytes()); // central directory header
        cd.extend_from_slice(&20u16.to_le_bytes()); // version made by
        cd.extend_from_slice(&20u16.to_le_bytes()); // version needed
        cd.extend_from_slice(&0u16.to_le_bytes()); // flags
        cd.extend_from_slice(&0u16.to_le_bytes()); // method: store
        cd.extend_from_slice(&0u16.to_le_bytes()); // time
        cd.extend_from_slice(&0u16.to_le_bytes()); // date
        cd.extend_from_slice(&crc.to_le_bytes());
        cd.extend_from_slice(&comp.to_le_bytes()); // compressed size: the bytes it really yields
        cd.extend_from_slice(&declared_uncomp.to_le_bytes()); // uncompressed size: the claim
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes()); // extra
        cd.extend_from_slice(&0u16.to_le_bytes()); // comment
        cd.extend_from_slice(&0u16.to_le_bytes()); // disk
        cd.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        cd.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        cd.extend_from_slice(&0u32.to_le_bytes()); // every entry points at offset 0
        cd.extend_from_slice(&name);
    }
    let cd_size = cd.len() as u32;
    out.extend_from_slice(&cd);

    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes()); // end of central directory
    out.extend_from_slice(&0u16.to_le_bytes()); // this disk
    out.extend_from_slice(&0u16.to_le_bytes()); // cd disk
    out.extend_from_slice(&copies.to_le_bytes()); // entries here
    out.extend_from_slice(&copies.to_le_bytes()); // entries total
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment length
    out
}

/// `bytes` framed as a single-member tar named `name`.
fn tar_holding(name: &str, bytes: &[u8]) -> Vec<u8> {
    let mut b = ::tar::Builder::new(Vec::new());
    let mut h = ::tar::Header::new_ustar();
    h.set_size(bytes.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    b.append_data(&mut h, name, bytes).unwrap();
    b.into_inner().unwrap()
}

fn gz(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    gzip::write(
        &GzipHeader::default(),
        bytes,
        flate2::Compression::default(),
        &mut out,
    )
    .unwrap();
    out
}

/// A tar nested `levels` deep: each level is a tar holding one `.tar.gz` member, and the innermost
/// holds a text file. `levels == 0` is the bare leaf.
fn nested_chain(levels: u32) -> Vec<u8> {
    let mut cur = tar_holding("leaf.txt", b"bottom");
    for i in (1..=levels).rev() {
        cur = tar_holding(&format!("level{i}.tar.gz"), &gz(&cur));
    }
    cur
}

/// How many `Body::Nested` hops the deepest path through `a` takes.
fn descended_levels(a: &Archive) -> u32 {
    a.entries
        .iter()
        .map(|e| match &e.body {
            Body::Nested { inner, .. } => 1 + descended_levels(inner),
            _ => 0,
        })
        .max()
        .unwrap_or(0)
}

/// The deepest archive reached by following `Body::Nested`, and the entry that was not descended
/// into.
fn deepest(a: &Archive) -> &Archive {
    match a.entries.iter().find_map(|e| match &e.body {
        Body::Nested { inner, .. } => Some(inner.as_ref()),
        _ => None,
    }) {
        Some(inner) => deepest(inner),
        None => a,
    }
}

fn limit_exceeded(err: &ArchiveError) -> (&'static str, u64, u64) {
    match err {
        ArchiveError::LimitExceeded {
            limit,
            actual,
            allowed,
        } => (limit, *actual, *allowed),
        other => panic!("expected LimitExceeded, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------
// max_entries
// ---------------------------------------------------------------------------------------------

#[test]
fn a_tar_of_exactly_max_entries_is_whole_and_unremarked_while_one_more_is_cut_and_noted() {
    // `tar.rs` stops on `ordinal >= limits.max_entries` over a zero-based ordinal, so "10 entries
    // allowed" has to mean ten kept. The failure mode either side is quiet: one fewer silently
    // drops a member from a legitimate package and changes its digest, one more admits a member
    // past the configured ceiling. Neither is visible in a test that feeds 50 entries through a
    // limit of 10, because 50 trips both readings.
    let limits = Limits {
        max_entries: 10,
        ..Limits::default()
    };

    let mut notes: Vec<Note> = Vec::new();
    let at = parse(tar_with_entries(10), Format::Tar, &limits, &mut notes).unwrap();
    assert_eq!(at.archive.entries.len(), 10, "ten allowed means ten kept");
    assert!(
        !notes.iter().any(|n| n.code == NoteCode::EntryLimitReached),
        "an archive that fits under the ceiling was not truncated, so nothing should say it was: \
         a spurious note here reads as evidence of tampering, {notes:?}"
    );

    let mut notes: Vec<Note> = Vec::new();
    let over = parse(tar_with_entries(11), Format::Tar, &limits, &mut notes).unwrap();
    assert_eq!(over.archive.entries.len(), 10, "the eleventh is dropped");
    let note = notes
        .iter()
        .find(|n| n.code == NoteCode::EntryLimitReached)
        .expect("a truncated archive must say it was truncated");
    // The detail carries where it stopped. Without it the note says an archive was cut and not
    // where, and the operator cannot tell a 10-entry overshoot from a million-entry one.
    assert!(
        note.detail.contains("10"),
        "the note names the ordinal it stopped at: {}",
        note.detail
    );
}

#[test]
fn the_zip_reader_stops_at_the_same_entry_count_the_tar_reader_does() {
    // Two hand-written readers, one limit. They are separate code (`tar.rs:46`, `zip.rs:99`) with
    // separate ordinal types, so "both stop at the same place" is an agreement nothing else
    // asserts — and a zip reader that kept one member more than the tar reader would make the
    // ceiling depend on the artifact's format rather than on the operator's configuration.
    let limits = Limits {
        max_entries: 4,
        ..Limits::default()
    };

    let mut notes: Vec<Note> = Vec::new();
    let at = parse(zip_with_entries(4), Format::Zip, &limits, &mut notes).unwrap();
    assert_eq!(at.archive.entries.len(), 4);
    assert!(!notes.iter().any(|n| n.code == NoteCode::EntryLimitReached));

    let mut notes: Vec<Note> = Vec::new();
    let over = parse(zip_with_entries(5), Format::Zip, &limits, &mut notes).unwrap();
    assert_eq!(over.archive.entries.len(), 4);
    assert!(
        notes.iter().any(|n| n.code == NoteCode::EntryLimitReached),
        "{notes:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// total_expanded_bytes
// ---------------------------------------------------------------------------------------------

#[test]
fn a_tar_sitting_exactly_on_the_expansion_ceiling_parses_and_one_byte_over_names_the_limit() {
    // `expanded > total_expanded_bytes`, so a member of exactly the budget is admitted. That is
    // the right direction — a ceiling of N should permit N — but it is a `>` where a `>=` would
    // read just as natural, so it is worth a test that can tell the two apart.
    const N: usize = 4096;
    let bytes = tar_of_exactly(N);

    let exact = Limits {
        total_expanded_bytes: N as u64,
        ..Limits::default()
    };
    let p = parse(bytes.clone(), Format::Tar, &exact, &mut Vec::new())
        .expect("a ceiling of N must admit exactly N");
    assert_eq!(p.archive.entries[0].meta.size, N as u64);

    let tight = Limits {
        total_expanded_bytes: (N - 1) as u64,
        ..Limits::default()
    };
    let err = parse(bytes, Format::Tar, &tight, &mut Vec::new())
        .expect_err("and must refuse N against a ceiling of N-1");

    // The three fields are the diagnosis. `limit` has to be the field's own name so an operator can
    // grep `Limits` for it; `actual` and `allowed` are what tells them whether to raise the ceiling
    // or to look harder at the package.
    let (limit, actual, allowed) = limit_exceeded(&err);
    assert_eq!(limit, "total_expanded_bytes");
    assert_eq!(actual, N as u64);
    assert_eq!(allowed, (N - 1) as u64);
    assert!(
        err.to_string().contains("total_expanded_bytes")
            && err.to_string().contains(&N.to_string()),
        "and they reach the rendered message, which is what lands in a log: {err}"
    );
}

#[test]
fn a_gzip_payload_of_exactly_the_budget_inflates_and_one_byte_more_does_not() {
    // The gzip budget is enforced on the way out: `take(budget + 1)`, then a length check. The
    // `+ 1` is what makes "stopped exactly at the limit" distinguishable from "exhausted", and it
    // is the kind of arithmetic that gets simplified away by someone who does not know why it is
    // there. Both sides of it are pinned here.
    const N: usize = 4096;
    let bytes = gzip_of_exactly(N);

    let exact = Limits {
        total_expanded_bytes: N as u64,
        ..Limits::default()
    };
    let p = parse(bytes.clone(), Format::Gzip, &exact, &mut Vec::new())
        .expect("a budget of N must inflate N");
    assert_eq!(p.container.as_ref().map(Vec::len), Some(N));

    let tight = Limits {
        total_expanded_bytes: (N - 1) as u64,
        ..Limits::default()
    };
    let err = parse(bytes, Format::Gzip, &tight, &mut Vec::new())
        .expect_err("and must refuse N against a budget of N-1");
    let (limit, actual, allowed) = limit_exceeded(&err);
    assert_eq!(limit, "total_expanded_bytes");
    assert_eq!(allowed, (N - 1) as u64);
    assert_eq!(
        actual, N as u64,
        "one byte over the budget is still measured exactly"
    );
}

#[test]
fn the_size_a_gzip_bomb_reports_is_a_witness_one_byte_past_the_budget_and_not_a_measurement() {
    // A bomb that inflates to 64 MiB against a 1 MiB budget reports `actual = 1048577`, not
    // 67108864, because the reader stops one byte past the budget rather than inflating the whole
    // thing to find out how big it was. That is the correct trade — measuring it is doing the
    // exact work the limit exists to prevent — but it means `actual` is a lower bound, and an
    // operator reading "1048577 > 1048576" could reasonably conclude the artifact was marginal and
    // raise the ceiling by a megabyte.
    //
    // Pinned rather than fixed: if this ever starts reporting a true size, whoever changes it has
    // to come here, and the honest reading of the field changes with it.
    let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
    e.write_all(&vec![0u8; 64 * 1024 * 1024]).unwrap();
    let deflated = e.finish().unwrap();
    let mut bomb = Vec::new();
    bomb.extend_from_slice(&[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255]);
    bomb.extend_from_slice(&deflated);
    bomb.extend_from_slice(&crc32fast::hash(&vec![0u8; 64 * 1024 * 1024]).to_le_bytes());
    bomb.extend_from_slice(&(64u32 * 1024 * 1024).to_le_bytes());
    assert!(bomb.len() < 100_000, "small on the wire: {}", bomb.len());

    const BUDGET: u64 = 1024 * 1024;
    let limits = Limits {
        total_expanded_bytes: BUDGET,
        ..Limits::default()
    };
    let err = parse(bomb, Format::Gzip, &limits, &mut Vec::new())
        .expect_err("64 MiB through a 1 MiB ceiling");
    let (limit, actual, allowed) = limit_exceeded(&err);
    assert_eq!(limit, "total_expanded_bytes");
    assert_eq!(allowed, BUDGET);
    assert!(actual > allowed, "the error is at least self-consistent");
    assert_eq!(
        actual,
        BUDGET + 1,
        "the reported size is the witness the reader stopped on, not the bomb's real size"
    );
}

#[test]
fn a_stored_zip_member_is_bounded_by_the_bytes_it_yields_and_not_by_the_size_it_declares() {
    // `docs/threat-model.md` P1: "Every limit is enforced against what decompression produces, not
    // against the size the input declares." The deflate arm of `read_member` earns that twice over
    // — an output budget, then a declared-versus-produced equality check — and
    // `a_zip_member_that_lies_about_its_size_is_refused` covers it.
    //
    // The store arm has neither. `expanded` accumulates the central directory's `uncomp_size`, and
    // `METHOD_STORE => Ok(raw.to_vec())` copies `comp_size` bytes out with no budget passed and no
    // comparison against what was declared. A member declaring one byte and holding 512 KiB is
    // therefore counted as one byte against the artifact's ceiling.
    //
    // No decompression is involved, so the produced bytes are bounded by the input's own size and
    // this alone is not an amplifier. It is still the ceiling being enforced against a number the
    // attacker wrote, which is the property P1 states and the reason the deflate arm was fixed.
    const BODY: usize = 512 * 1024;
    const CEILING: u64 = 64 * 1024;
    let limits = Limits {
        total_expanded_bytes: CEILING,
        ..Limits::default()
    };

    // The identical member, declared honestly, is refused. So the ceiling is real and the
    // declaration is the only thing it consults: the lie is what evades it, not some gap in the
    // zip reader's coverage of the store method.
    let honest = stored_zip(&vec![b'z'; BODY], 1, BODY as u32);
    let err = parse(honest, Format::Zip, &limits, &mut Vec::new())
        .expect_err("512 KiB declared against a 64 KiB ceiling");
    let (limit, actual, allowed) = limit_exceeded(&err);
    assert_eq!(limit, "total_expanded_bytes");
    assert_eq!(actual, BODY as u64);
    assert_eq!(allowed, CEILING);

    let bytes = stored_zip(&vec![b'z'; BODY], 1, 1);
    let produced = match parse(bytes, Format::Zip, &limits, &mut Vec::new()) {
        Err(err) => {
            let (limit, _, allowed) = limit_exceeded(&err);
            assert_eq!(limit, "total_expanded_bytes");
            assert_eq!(allowed, CEILING);
            0
        }
        Ok(p) => p.archive.entries.iter().map(|e| e.body.len()).sum::<u64>(),
    };
    assert!(
        produced <= CEILING,
        "a {CEILING}-byte ceiling admitted {produced} bytes of member body, because the member \
         declared 1 and the store path never looked at what it actually held"
    );
}

#[test]
fn many_directory_entries_naming_one_stored_member_cannot_outrun_the_expansion_ceiling() {
    // The amplifying form of the same gap, and the reason it is worth more than a contract note.
    //
    // Nothing requires two central directory entries to point at different local headers. Sixty-four
    // entries naming one 256 KiB stored member, each declaring a single uncompressed byte, is a
    // ~260 KiB artifact that the walker charges 64 bytes against the ceiling and then materializes
    // sixty-four separate 256 KiB bodies for. The multiplier is the entry count, and `max_entries`
    // defaults to a million: the same shape at that scale is a small file against a 4 GiB ceiling
    // producing terabytes.
    //
    // The deflate arm's declared-versus-produced check would catch every one of these. The store
    // arm has no check to catch them with.
    const COPIES: u16 = 64;
    const BODY: usize = 256 * 1024;
    const CEILING: u64 = 1024 * 1024;
    let bytes = stored_zip(&vec![b'z'; BODY], COPIES, 1);
    assert!(
        bytes.len() < 300 * 1024,
        "small on the wire: {}",
        bytes.len()
    );

    let limits = Limits {
        total_expanded_bytes: CEILING,
        ..Limits::default()
    };
    let produced = match parse(bytes, Format::Zip, &limits, &mut Vec::new()) {
        Err(_) => 0,
        Ok(p) => p.archive.entries.iter().map(|e| e.body.len()).sum::<u64>(),
    };
    assert!(
        produced <= CEILING,
        "{COPIES} overlapping stored members expanded to {produced} bytes under a {CEILING}-byte \
         ceiling"
    );
}

#[test]
fn the_expansion_ceiling_is_fatal_rather_than_noted_so_nobody_gets_a_quietly_truncated_archive() {
    // The two channels are a deliberate split and worth pinning as one. `max_entries` truncates and
    // leaves a note, because an archive with its tail cut off is still a describable thing and the
    // note says what was lost. `total_expanded_bytes` returns an error and no archive at all,
    // because stopping mid-member would hand a caller an archive whose digest is over fewer bytes
    // than the artifact holds — a silent wrong answer, which is the one outcome this crate exists
    // to avoid.
    //
    // If someone ever "improves" the byte ceiling into a truncate-and-note, this fails, which is
    // exactly when it should.
    let limits = Limits {
        total_expanded_bytes: 1024,
        ..Limits::default()
    };
    let mut notes: Vec<Note> = Vec::new();
    let err = parse(tar_of_exactly(64 * 1024), Format::Tar, &limits, &mut notes)
        .expect_err("64 KiB through a 1 KiB ceiling");
    assert!(matches!(err, ArchiveError::LimitExceeded { .. }));
    assert!(
        notes.is_empty(),
        "the byte ceiling reports through the error channel, not by returning a short archive with \
         an apology attached: {notes:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// recursion
// ---------------------------------------------------------------------------------------------

#[test]
fn the_recursion_ceiling_descends_one_level_fewer_than_its_number() {
    // `descend` is entered at depth 1 and returns immediately when `depth >= limits.recursion`, so
    // `recursion: N` parses N-1 levels of nested archive. `recursion: 1` descends into nothing at
    // all, and the shipped default of 4 sees three levels down — not four, which is what the field
    // name, `limits.rs`'s "how deep nested archives may go", and `docs/threat-model.md` P1's
    // "recursion is depth-limited to 4" all read as.
    //
    // The direction is the safe one: stricter than advertised, never looser. It is pinned because
    // the off-by-one is in the arithmetic rather than in the comparison, so anyone "fixing" the
    // comparison to `>` would widen the real ceiling by a level while believing they had left it
    // alone.
    for recursion in 1..=5u8 {
        let mut notes: Vec<Note> = Vec::new();
        let p = parse(
            nested_chain(4),
            Format::Tar,
            &Limits {
                recursion,
                ..Limits::default()
            },
            &mut notes,
        )
        .unwrap();
        let reached = descended_levels(&p.archive);
        assert_eq!(
            reached,
            u32::from(recursion - 1).min(4),
            "recursion {recursion} should descend {} levels",
            recursion - 1
        );
    }
}

#[test]
fn stopping_at_the_recursion_ceiling_notes_it_and_finishing_the_chain_does_not() {
    // The note is only owed when there was something left to look at. A chain that fits reports
    // nothing, and a chain that does not reports `RecursionLimitReached` — which is how a verdict
    // says "I answered a narrower question than you asked" rather than quietly answering it.
    let mut notes: Vec<Note> = Vec::new();
    parse(
        nested_chain(3),
        Format::Tar,
        &Limits {
            recursion: 4,
            ..Limits::default()
        },
        &mut notes,
    )
    .unwrap();
    assert!(
        !notes
            .iter()
            .any(|n| n.code == NoteCode::RecursionLimitReached),
        "a chain that fits under the ceiling was fully descended, so nothing was missed: {notes:?}"
    );

    let mut notes: Vec<Note> = Vec::new();
    parse(
        nested_chain(4),
        Format::Tar,
        &Limits {
            recursion: 4,
            ..Limits::default()
        },
        &mut notes,
    )
    .unwrap();
    let note = notes
        .iter()
        .find(|n| n.code == NoteCode::RecursionLimitReached)
        .expect("one level too deep must be reported");
    assert!(
        note.detail.contains('4'),
        "the note says where it stopped: {}",
        note.detail
    );
}

#[test]
fn a_member_left_undescended_keeps_its_exact_bytes_so_the_digest_is_over_what_arrived() {
    // The whole reason recursion is bounded in the model rather than inside a stabilizer. When the
    // walker stops, the member it did not open has to still be the bytes the artifact shipped: not
    // an empty body, not a re-serialized one, not a `Nested` the writer would rebuild from a parse
    // that never happened. Anything else changes the stabilized digest as a side effect of a
    // *limit*, and a limit that moves the answer is worse than no limit — the prior art swallows
    // exactly this error and reports a different digest with no signal at all.
    let leaf_gz = gz(&tar_holding("leaf.txt", b"bottom"));
    let level1 = tar_holding("level1.tar.gz", &leaf_gz);

    let mut notes: Vec<Note> = Vec::new();
    let stopped = parse(
        level1.clone(),
        Format::Tar,
        &Limits {
            recursion: 1,
            ..Limits::default()
        },
        &mut notes,
    )
    .unwrap();

    let e = &stopped.archive.entries[0];
    assert!(
        !matches!(e.body, Body::Nested { .. }),
        "the ceiling stopped before this was parsed, so it must not claim to have been"
    );
    assert_eq!(
        e.stabilized_bytes().unwrap().as_ref(),
        leaf_gz.as_slice(),
        "byte for byte what the artifact shipped"
    );
    assert_eq!(e.meta.size, leaf_gz.len() as u64);
    assert!(
        notes
            .iter()
            .any(|n| n.code == NoteCode::RecursionLimitReached)
    );

    // And the bytes a descended member contributes are the same bytes, so raising the ceiling
    // cannot move a digest either. `Body::Nested` keeps the original alongside the parse precisely
    // for this.
    let descended = parse(level1, Format::Tar, &Limits::default(), &mut Vec::new()).unwrap();
    let d = &descended.archive.entries[0];
    assert!(matches!(d.body, Body::Nested { .. }));
    assert_eq!(
        d.stabilized_bytes().unwrap().as_ref(),
        leaf_gz.as_slice(),
        "descending is for seeing inside; it is not licence to rewrite"
    );
}

#[test]
fn the_innermost_archive_a_bounded_walk_reaches_is_still_a_parsed_archive_and_not_a_stub() {
    // A bounded walk that returned something unusable at the bottom would push every caller into
    // treating depth as a special case. The deepest level is an ordinary `Archive` holding the
    // member it declined to open.
    let p = parse(
        nested_chain(4),
        Format::Tar,
        &Limits::default(),
        &mut Vec::new(),
    )
    .unwrap();
    let bottom = deepest(&p.archive);
    assert_eq!(bottom.entries.len(), 1);
    assert_eq!(bottom.entries[0].path.as_bytes(), b"level4.tar.gz");
    assert!(!bottom.entries[0].body.is_empty());
}

// ---------------------------------------------------------------------------------------------
// The channel a trip reports through
// ---------------------------------------------------------------------------------------------

#[test]
fn every_note_a_limit_trip_leaves_is_noteworthy_so_it_reaches_a_log_without_a_verbose_flag() {
    // `parse` logs `is_noteworthy()` codes at `warn` and everything else at `debug`. A limit note
    // that fell outside that set would be emitted, stored, and never seen by the operator sweeping
    // a corpus — the failure mode where a control is present, correct, and invisible.
    let mut notes: Vec<Note> = Vec::new();
    parse(
        tar_with_entries(11),
        Format::Tar,
        &Limits {
            max_entries: 10,
            ..Limits::default()
        },
        &mut notes,
    )
    .unwrap();
    parse(
        nested_chain(4),
        Format::Tar,
        &Limits {
            recursion: 1,
            ..Limits::default()
        },
        &mut notes,
    )
    .unwrap();

    let limit_notes: Vec<_> = notes
        .iter()
        .filter(|n| {
            matches!(
                n.code,
                NoteCode::EntryLimitReached
                    | NoteCode::RecursionLimitReached
                    | NoteCode::SizeLimitReached
            )
        })
        .collect();
    assert_eq!(limit_notes.len(), 2, "both trips were recorded: {notes:?}");
    for n in limit_notes {
        assert!(
            n.code.is_noteworthy(),
            "{:?} is how a limit trip reaches an operator; it must warn, not debug",
            n.code
        );
        assert!(
            !n.detail.is_empty(),
            "{:?} carries no detail, so the record says a limit fired and not where",
            n.code
        );
    }
}

// ---------------------------------------------------------------------------------------------
// The two that are not wired
// ---------------------------------------------------------------------------------------------

#[test]
fn the_two_inline_limits_bound_nothing_today_so_wiring_them_will_be_a_deliberate_change() {
    // `max_inline_bytes` and `max_inline_total` are read nowhere outside `limits.rs`. That is
    // already recorded — `docs/16-findings.md` §3.15, and D23 in the threat model — and this is not
    // a re-find. It is the pin.
    //
    // Dead configuration is only safe while everyone knows it is dead. Wiring either field would
    // start spilling member bodies to disk, which is a host side effect D23 explicitly disclaims,
    // and would do it the first time a real artifact crossed 8 MiB. So the test asserts the current
    // behaviour: both fields at zero, a member far above them, and nothing happens — same member
    // count, same bytes, body still in memory, no `SpilledToDisk`. Whoever wires them gets a
    // failing test that names the doc and the disclaimer they now have to update.
    let bytes = tar_of_exactly(64 * 1024);

    let starved = Limits {
        max_inline_bytes: 0,
        max_inline_total: 0,
        ..Limits::default()
    };
    let mut notes: Vec<Note> = Vec::new();
    let p = parse(bytes.clone(), Format::Tar, &starved, &mut notes).unwrap();

    assert_eq!(p.archive.entries.len(), 1);
    let e = &p.archive.entries[0];
    assert_eq!(e.body.len(), 64 * 1024, "the whole member, in memory");
    assert!(
        !matches!(e.body, Body::Spilled { .. }),
        "`Body::Spilled` is matched in three places and constructed in none (docs/16 §3.15)"
    );
    assert!(
        !notes.iter().any(|n| n.code == NoteCode::SpilledToDisk),
        "nothing spilled, so nothing said it did: {notes:?}"
    );

    // And the two fields make no difference to the parse at all: zero and the shipped defaults
    // produce the same archive. This is the assertion that fails the moment either is read.
    let generous = parse(bytes, Format::Tar, &Limits::default(), &mut Vec::new()).unwrap();
    assert_eq!(generous.archive.entries.len(), p.archive.entries.len());
    assert_eq!(
        generous.archive.entries[0].body_bytes().unwrap(),
        e.body_bytes().unwrap(),
        "the inline limits changed nothing, because nothing reads them"
    );
}

#[test]
fn the_tiny_limits_are_below_the_defaults_on_every_field_that_is_enforced() {
    // `Limits::tiny()` exists so a test or a fuzz target can reach a ceiling cheaply. It is only
    // useful if every enforced ceiling is genuinely lower — a field left at the default here is a
    // fuzz target that never reaches that limit, and silently covers less than its name claims.
    let (t, d) = (Limits::tiny(), Limits::default());
    assert!(t.recursion < d.recursion, "recursion");
    assert!(
        t.total_expanded_bytes < d.total_expanded_bytes,
        "total_expanded_bytes"
    );
    assert!(t.max_entries < d.max_entries, "max_entries");
    assert!(t.recursion >= 1, "a recursion of 0 would be a strange walk");
}
