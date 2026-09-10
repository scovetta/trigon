//! Anything that parses must re-serialize, and re-serializing must be idempotent.
//!
//! `write(parse(write(a))) == write(a)` is the property a signed digest depends on. A fuzzer
//! finding a counterexample here is finding a case where our digest is a coin flip.

#![no_main]
use libfuzzer_sys::fuzz_target;
use trigon_archive::{Limits, parse, serialize};
use trigon_core::{Format, Note};

fuzz_target!(|data: &[u8]| {
    for format in [Format::Tar, Format::TarGz, Format::Zip] {
        let mut notes: Vec<Note> = Vec::new();
        let Ok(p) = parse(data.to_vec(), format, &Limits::tiny(), &mut notes) else { continue };
        let Ok(once) = serialize(&p.archive, true) else { continue };

        let mut notes2: Vec<Note> = Vec::new();
        let Ok(q) = parse(once.clone(), format, &Limits::tiny(), &mut notes2) else { continue };
        let Ok(twice) = serialize(&q.archive, true) else { continue };
        assert_eq!(once, twice, "re-serializing a parsed archive changed the bytes");
    }
});
