//! Parsing attacker-controlled bytes must not panic, and must respect its limits.

#![no_main]
use libfuzzer_sys::fuzz_target;
use trigon_archive::{Limits, parse};
use trigon_core::{Format, Note};

fuzz_target!(|data: &[u8]| {
    // Tiny limits, because a fuzzer that spends its budget inflating a 4 GiB claim is a fuzzer
    // that never reaches the interesting code.
    let limits = Limits::tiny();
    for format in [Format::Tar, Format::TarGz, Format::Zip, Format::Gzip, Format::Raw] {
        let mut notes: Vec<Note> = Vec::new();
        if let Ok(p) = parse(data.to_vec(), format, &limits, &mut notes) {
            assert!(
                p.archive.entries.len() <= limits.max_entries as usize,
                "the entry limit was not respected"
            );
        }
    }
});
