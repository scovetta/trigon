//! An evidence repository read as a client reads one (`docs/19` §4, §5, §6, §8): records verified
//! against the log, every way one fails, lookup and supersession over the leaves, index paths,
//! and re-deriving a published verdict from its record.
//!
//! The golden repository is under `testdata/evidence/`, written by `build.rs` from fixed keys and
//! compared byte for byte. When a change to a format is deliberate, rewrite it with
//! `TRIGON_WRITE_GOLDEN=1 cargo test -p trigon-attest --test evidence_repo`, and say why in the
//! commit: every record and leaf in it is signed, and so is everything a client already holds.

#[allow(dead_code)]
#[path = "../evidence_log/common.rs"]
mod common;

mod build;
mod golden;
mod lookup;
mod paths;
mod records;
mod rerun;
