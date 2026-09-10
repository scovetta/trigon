//! The properties M0 exists to guarantee, over generated archives.

use proptest::prelude::*;
use trigon_archive::{Limits, parse, serialize};
use trigon_core::{Format, Note};
use trigon_stabilize::{apply, profile};

/// A generated tar. Paths, contents, modes, times, owners and ordering all vary, including the
/// awkward cases: duplicate paths, empty bodies, and names too long for the ustar name field.
fn arb_tar() -> impl Strategy<Value = Vec<u8>> {
    let entry = (
        prop_oneof![
            "[a-z]{1,8}(/[a-z]{1,8}){0,3}",
            Just("x".repeat(130)),
            Just("dup.txt".to_string()),
        ],
        prop::collection::vec(any::<u8>(), 0..64),
        0o400u32..0o777,
        0u64..2_000_000_000,
        0u64..2000,
    );
    prop::collection::vec(entry, 1..12).prop_map(|entries| {
        let mut b = ::tar::Builder::new(Vec::new());
        for (name, body, mode, mtime, uid) in entries {
            let mut h = ::tar::Header::new_ustar();
            h.set_size(body.len() as u64);
            h.set_mode(mode);
            h.set_mtime(mtime);
            h.set_uid(uid);
            h.set_gid(uid);
            h.set_cksum();
            // A name the ustar header cannot hold is written through the GNU path by this builder,
            // which is exactly the re-encoding case we want covered.
            let _ = b.append_data(&mut h, &name, &body[..]);
        }
        b.into_inner().unwrap()
    })
}

fn stabilized(bytes: Vec<u8>) -> Vec<u8> {
    let mut notes: Vec<Note> = Vec::new();
    let mut p = parse(bytes, Format::Tar, &Limits::default(), &mut notes).unwrap();
    apply(&profile("tar").unwrap(), &mut p.archive);
    serialize(&p.archive, true).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// stabilize(stabilize(x)) == stabilize(x). Required, and what `StageFinalize` exists to repair.
    #[test]
    fn stabilization_is_idempotent(bytes in arb_tar()) {
        let once = stabilized(bytes);
        let twice = stabilized(once.clone());
        prop_assert_eq!(once, twice);
    }

    /// The same input produces the same bytes, every time. A digest that is a coin flip is the
    /// failure this crate exists to prevent.
    #[test]
    fn output_is_deterministic(bytes in arb_tar()) {
        let a = stabilized(bytes.clone());
        let b = stabilized(bytes);
        prop_assert_eq!(a, b);
    }

    /// parse(write(a)) preserves paths and bodies.
    #[test]
    fn round_trip_preserves_members(bytes in arb_tar()) {
        let mut notes: Vec<Note> = Vec::new();
        let p = parse(bytes, Format::Tar, &Limits::default(), &mut notes).unwrap();
        let before: Vec<_> = p.archive.entries.iter()
            .map(|e| (e.path.clone(), e.body_bytes().unwrap().into_owned()))
            .collect();

        let out = serialize(&p.archive, true).unwrap();
        let mut notes2: Vec<Note> = Vec::new();
        let q = parse(out, Format::Tar, &Limits::default(), &mut notes2).unwrap();
        let after: Vec<_> = q.archive.entries.iter()
            .map(|e| (e.path.clone(), e.body_bytes().unwrap().into_owned()))
            .collect();

        prop_assert_eq!(before, after);
    }

    /// Stabilized output carries no timestamp, owner or mode variation, whatever went in.
    #[test]
    fn metadata_is_erased(bytes in arb_tar()) {
        let out = stabilized(bytes);
        let mut notes: Vec<Note> = Vec::new();
        let p = parse(out, Format::Tar, &Limits::default(), &mut notes).unwrap();
        for e in &p.archive.entries {
            prop_assert_eq!(e.meta.mtime, Some(0));
            prop_assert_eq!(e.meta.mode, 0o777);
            if let trigon_archive::RawMeta::Tar(raw) = &e.raw {
                prop_assert_eq!(raw.uid, 0);
                prop_assert_eq!(raw.gid, 0);
                prop_assert!(raw.uname.is_empty());
            }
        }
    }

    /// Entries come out in a total order, so a duplicate path cannot make the digest a coin flip.
    #[test]
    fn ordering_is_total(bytes in arb_tar()) {
        let out = stabilized(bytes);
        let mut notes: Vec<Note> = Vec::new();
        let p = parse(out, Format::Tar, &Limits::default(), &mut notes).unwrap();
        let paths: Vec<_> = p.archive.entries.iter().map(|e| e.path.clone()).collect();
        let mut sorted = paths.clone();
        sorted.sort();
        prop_assert_eq!(paths, sorted);
    }
}

#[test]
fn output_is_stable_across_threads() {
    let fixture = {
        let mut b = ::tar::Builder::new(Vec::new());
        for i in 0..50 {
            let mut h = ::tar::Header::new_ustar();
            let body = format!("content {i}");
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_mtime(1_700_000_000 + i);
            h.set_cksum();
            b.append_data(&mut h, format!("d{}/f{i}.txt", i % 7), body.as_bytes())
                .unwrap();
        }
        b.into_inner().unwrap()
    };
    let expected = stabilized(fixture.clone());
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let f = fixture.clone();
            std::thread::spawn(move || stabilized(f))
        })
        .collect();
    for h in handles {
        assert_eq!(h.join().unwrap(), expected);
    }
}
