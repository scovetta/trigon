//! The evidence log (`docs/19` §2.3, §8), format by format: signed notes, checkpoints, the Merkle
//! tree and its proofs, tiles and entry bundles, leaves, a log verified from its files, and
//! rotation. Every refusal a format or a check makes has a test here.
//!
//! The golden files are under `testdata/log/`. The vectors that are not ours — Go's signed notes,
//! the RFC 6962 trees — are someone else's arithmetic, and the tests hold this code to them. The
//! repository under `testdata/log/repo/` is ours: the writer's output, byte for byte, which a test
//! regenerates and compares. When a change to a format is deliberate, rewrite it with
//! `TRIGON_WRITE_GOLDEN=1 cargo test -p trigon-attest --test evidence_log`, and say why in the
//! commit: every byte of it is signed, and a client already holding one will refuse another.

mod chains;
mod checkpoint;
mod common;
mod golden;
mod leaves;
mod merkle;
mod note;
mod rotation;
mod tiles;
mod verify;
