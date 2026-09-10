use std::sync::Arc;

use trigon_archive::{Limits, parse, serialize};
use trigon_core::{Format, Note, Provenance, RiskTier};
use trigon_stabilize::{Applied, Stabilizer, StabilizerSet, apply, default_for, profile};

fn tar_with(mtime: u64, uid: u64, uname: &str, mode: u32) -> Vec<u8> {
    let mut b = ::tar::Builder::new(Vec::new());
    for name in ["z/last.txt", "a/first.txt"] {
        let mut h = ::tar::Header::new_ustar();
        h.set_size(4);
        h.set_mode(mode);
        h.set_mtime(mtime);
        h.set_uid(uid);
        h.set_gid(uid);
        h.set_username(uname).unwrap();
        h.set_groupname(uname).unwrap();
        h.set_cksum();
        b.append_data(&mut h, name, &b"data"[..]).unwrap();
    }
    b.into_inner().unwrap()
}

fn stabilize(bytes: Vec<u8>, format: Format, prof: &str) -> (Vec<u8>, Vec<Applied>) {
    let mut notes: Vec<Note> = Vec::new();
    let mut p = parse(bytes, format, &Limits::default(), &mut notes).unwrap();
    let set = profile(prof).unwrap();
    let applied = apply(&set, &mut p.archive);
    (serialize(&p.archive, true).unwrap(), applied)
}

#[test]
fn two_archives_differing_only_in_metadata_stabilize_identically() {
    let (a, _) = stabilize(
        tar_with(1_700_000_000, 1000, "alice", 0o644),
        Format::Tar,
        "tar",
    );
    let (b, _) = stabilize(
        tar_with(1_500_000_000, 501, "bob", 0o600),
        Format::Tar,
        "tar",
    );
    assert_eq!(a, b, "metadata-only differences must stabilize away");
}

#[test]
fn entry_order_is_normalized() {
    let (out, applied) = stabilize(tar_with(1, 1, "x", 0o644), Format::Tar, "tar");
    assert!(applied.iter().any(|x| x.id.as_str() == "tar-entry-order"));
    let mut notes = Vec::new();
    let p = parse(out, Format::Tar, &Limits::default(), &mut notes).unwrap();
    let names: Vec<_> = p
        .archive
        .entries
        .iter()
        .map(|e| e.path.to_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["a/first.txt", "z/last.txt"]);
}

#[test]
fn stabilization_is_idempotent() {
    let (once, _) = stabilize(
        tar_with(1_700_000_000, 1000, "alice", 0o644),
        Format::Tar,
        "tar",
    );
    let (twice, applied2) = stabilize(once.clone(), Format::Tar, "tar");
    assert_eq!(once, twice);
    assert!(
        applied2.is_empty(),
        "a second pass should change nothing, got {applied2:?}"
    );
}

#[test]
fn applied_reports_only_passes_that_fired() {
    let (_, applied) = stabilize(
        tar_with(1_700_000_000, 1000, "alice", 0o644),
        Format::Tar,
        "tar",
    );
    let ids: Vec<_> = applied.iter().map(|a| a.id.as_str().to_string()).collect();
    assert!(ids.contains(&"tar-time".to_string()));
    assert!(ids.contains(&"tar-owners".to_string()));
    assert!(!ids.contains(&"tar-xattrs".to_string()), "{ids:?}");
    assert!(!ids.contains(&"tar-device".to_string()), "{ids:?}");
    assert!(applied.iter().all(|a| a.provenance == Provenance::Builtin));
}

#[test]
fn the_gem_profile_stays_within_the_clean_tier() {
    let set = profile("gem").unwrap();
    let worst = set.members.iter().map(|m| m.risk()).max().unwrap();
    assert!(
        worst <= RiskTier::Metadata,
        "no gem could reach Normalized with a {worst:?} pass"
    );
    assert!(
        set.members
            .iter()
            .all(|m| m.provenance() == Provenance::Builtin)
    );
}

#[test]
fn the_crate_profile_is_capped_by_cargo_vcs_hash() {
    let set = profile("crate").unwrap();
    assert_eq!(
        set.members.iter().map(|m| m.risk()).max().unwrap(),
        RiskTier::Content
    );
}

#[test]
fn set_digest_is_stable_and_order_independent() {
    let a = profile("npm-tarball").unwrap();
    assert_eq!(a.digest(), profile("npm-tarball").unwrap().digest());
    let mut shuffled: Vec<Arc<dyn Stabilizer>> = a.members.clone();
    shuffled.reverse();
    assert_eq!(
        a.digest(),
        StabilizerSet::new("npm-tarball", shuffled).digest()
    );
    assert_ne!(a.digest(), profile("crate").unwrap().digest());
}

#[test]
fn default_profile_follows_the_format() {
    assert_eq!(default_for(Format::TarGz).id.as_str(), "tar-gzip");
    assert_eq!(default_for(Format::Zip).id.as_str(), "zip");
    assert!(default_for(Format::Raw).members.is_empty());
}
