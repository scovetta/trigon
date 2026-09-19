//! Stabilizers are total and idempotent, whatever they are handed.
//!
//! Totality is a type-level claim: the trait returns no error. A panic would break it, and a
//! non-idempotent pass would mean the stabilized digest depends on how many times we ran.

#![no_main]
use libfuzzer_sys::fuzz_target;
use trigon_archive::{Limits, parse, serialize};
use trigon_core::{Format, Note};
use trigon_stabilize::{apply, profile};

fuzz_target!(|data: &[u8]| {
    // Every profile `all_profiles()` answers to, with the format its artifacts arrive in. Kept in
    // step with that list by `trigon-stabilize/tests/every_profile.rs`, which reads this file: a
    // profile added to the build and not to this table is a profile nothing fuzzes, which is how
    // `nupkg` — seven passes, and an ordering hazard its own source comments warn about — came to
    // have no coverage here at all.
    for (format, prof) in [
        (Format::Tar, "tar"),
        (Format::TarGz, "tar-gzip"),
        (Format::Zip, "zip"),
        (Format::Gzip, "gzip"),
        (Format::TarGz, "npm-tarball"),
        (Format::TarGz, "crate"),
        (Format::Tar, "gem"),
        (Format::Zip, "wheel"),
        (Format::Zip, "nupkg"),
        (Format::Raw, "raw"),
    ] {
        let set = profile(prof).unwrap();
        let mut notes: Vec<Note> = Vec::new();
        let Ok(mut p) = parse(data.to_vec(), format, &Limits::tiny(), &mut notes) else { continue };

        apply(&set, &mut p.archive);
        let Ok(once) = serialize(&p.archive, true) else { continue };

        let mut notes2: Vec<Note> = Vec::new();
        let Ok(mut q) = parse(once.clone(), format, &Limits::tiny(), &mut notes2) else { continue };
        let second = apply(&set, &mut q.archive);
        let Ok(twice) = serialize(&q.archive, true) else { continue };

        assert_eq!(once, twice, "stabilization is not idempotent for {prof}");
        assert!(
            second.is_empty(),
            "a second pass over stabilized bytes reported work for {prof}: {second:?}"
        );
    }
});
