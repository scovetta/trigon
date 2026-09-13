//! TEMPORARY scratch test — delete.
use trigon_attest::Statement;
use trigon_compare::{Comparison, Summary};
use trigon_core::{Digest, Format, Match, MultiDigest, ProfileId, Provenance, RiskTier, StabilizerId};
use trigon_stabilize::Applied;

fn md(b: u8) -> MultiDigest {
    MultiDigest { sha256: Digest::from_bytes([b; 32]), sha512: None }
}

fn summary(applied: Vec<Applied>, raw: u8, stab: u8) -> Summary {
    Summary {
        format: Format::Tar,
        bytes: 10,
        raw: md(raw),
        container: None,
        stabilized: md(stab),
        applied,
        notes: vec![],
        set: (ProfileId::new("npm-tarball"), Digest::from_bytes([9; 32])),
    }
}

#[test]
fn the_signed_cap_block_reads_only_the_upstream_side() {
    // A model-authored, Lossy pass fired on the REBUILD only.
    let dirty = Applied {
        id: StabilizerId::new("model-authored"),
        risk: RiskTier::Lossy,
        provenance: Provenance::Model { model_id: "m".into(), run_id: "r".into() },
        entries_touched: 1,
        bytes_changed: 5,
    };
    let c = Comparison {
        outcome: Match::NormalizedWithCaveats, // what compare() would return
        upstream: summary(vec![], 1, 7),
        rebuild: summary(vec![dirty], 2, 7),
        diff: None,
    };
    let st = Statement::equivalence("pkg-1.0.0.tar", &c);
    println!("outcome       = {}", st.predicate["outcome"]);
    println!("allBuiltin    = {}", st.predicate["provenanceCap"]["allBuiltin"]);
    println!("maxRiskApplied= {}", st.predicate["provenanceCap"]["maxRiskApplied"]);
    println!("applied       = {}", st.predicate["applied"]);
}
