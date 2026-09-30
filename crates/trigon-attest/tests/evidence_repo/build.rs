//! Writing an evidence repository as `publish` will (`docs/19` §2.3, §4.1, §10 phase 5): signed
//! record files, their evidence, a leaf per record, the tiles and checkpoints, and the index —
//! without `publish`'s rules, so that a test can write the repository a check exists to refuse.
//!
//! [`golden`] is the committed fixture, `testdata/evidence/`; the smaller helpers build its parts,
//! and the variants the tests need.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use trigon_archive::Limits;
use trigon_attest::evidence::{evidence_path, index_files, record_leaf, record_path};
use trigon_attest::log::{
    KeyChangeLeaf, Leaf, LogContinuationLeaf, LogEndLeaf, RecordLeaf, ReleaseLeaf,
    SignedCheckpoint, Successor, verify_source,
};
use trigon_attest::{
    Envelope, EvidenceDigests, LocalKey, Record, RunFacts, RunIdentity, Signer as _, Statement,
    Subject, SupersedeReason, Supersession, VerdictFacts, VoidFacts, sign_statement,
};
use trigon_compare::{Comparison, compare_bytes};
use trigon_core::purl::canonicalize;
use trigon_core::{Digest, Format};
use trigon_stabilize::profile;

use crate::common::{
    ORIGIN, SUCCESSOR, T0, Writer, attestation_key, heartbeat, log_key, successor_key,
};

/// Where a dispute about the golden repository's verdicts goes.
pub const DISPUTES: &str = "https://example.com/trigon-evidence/issues";

/// The attestation key the golden repository never had: records signed by it are refused.
pub const STRANGER: u8 = 9;

/// A tar of one member, `package/index.js`, holding `body` and modified at `mtime`: the `tar`
/// profile stabilizes the time, so two of these differing only in it compare `normalized`.
pub fn tar(mtime: u64, body: &[u8]) -> Vec<u8> {
    let mut b = ::tar::Builder::new(Vec::new());
    let mut h = ::tar::Header::new_ustar();
    h.set_size(body.len() as u64);
    h.set_mode(0o644);
    h.set_mtime(mtime);
    h.set_cksum();
    b.append_data(&mut h, "package/index.js", body).unwrap();
    b.into_inner().unwrap()
}

/// One package version, and the two artifacts a verdict about it compares.
#[derive(Clone, Debug)]
pub struct Pair {
    /// `demo-a`, and so on.
    pub name: String,
    pub upstream: Vec<u8>,
    pub rebuilt: Vec<u8>,
}

impl Pair {
    /// A package whose published and rebuilt artifacts hold `upstream` and `rebuilt`, built at
    /// times one second apart unless `same`, when the rebuild is the published bytes exactly.
    pub fn new(name: &str, upstream: &[u8], rebuilt: &[u8], same: bool) -> Pair {
        let up = tar(1, upstream);
        Pair {
            name: name.into(),
            rebuilt: if same { up.clone() } else { tar(2, rebuilt) },
            upstream: up,
        }
    }

    pub fn purl(&self) -> String {
        format!("pkg:npm/{}@1.0.0", self.name)
    }

    pub fn file(&self) -> String {
        format!("{}-1.0.0.tar", self.name)
    }

    pub fn subject(&self) -> Subject {
        Subject::of_bytes(self.file(), &self.upstream, true)
    }

    pub fn comparison(&self) -> Comparison {
        compare_bytes(
            self.upstream.clone(),
            self.rebuilt.clone(),
            Format::Tar,
            &profile("tar").unwrap(),
            &Limits::default(),
        )
        .unwrap()
    }
}

/// A record file, signed, with the evidence files it names and the leaf that logs it.
#[derive(Clone, Debug)]
pub struct Made {
    pub bytes: Vec<u8>,
    pub digest: Digest,
    pub leaf: RecordLeaf,
    pub evidence: Vec<Vec<u8>>,
}

impl Made {
    /// Write the record file and its evidence files into the repository at `root`.
    pub fn write(&self, root: &Path) {
        write(root, &record_path(&self.digest), &self.bytes);
        for e in &self.evidence {
            write(root, &evidence_path(&sha256(e)), e);
        }
    }

    /// The record's statement, as signed.
    pub fn statement(&self) -> Statement {
        Record::from_slice(&self.bytes)
            .unwrap()
            .statement()
            .unwrap()
    }
}

pub fn write(root: &Path, path: &str, bytes: &[u8]) {
    let p = root.join(path);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, bytes).unwrap();
}

pub fn sha256(bytes: &[u8]) -> Digest {
    Record::digest_of(bytes)
}

/// Canonical JSON of `v`, as the store keeps a strategy.
fn canonical(v: &Value) -> Vec<u8> {
    trigon_core::jcs::canonicalize(v).unwrap().into_bytes()
}

/// The run's facts as `rebuild` and `buildobservation` sign them: the guard armed with `guard`,
/// the manifest the verdict names as evidence, as the attestor signs both from one run.
fn run_facts<'a>(run: &'a str, set: Option<(&'a str, &'a str)>, guard: &'a str) -> RunFacts<'a> {
    RunFacts {
        run_id: run,
        started: "2026-09-27T00:00:00Z",
        finished: Some("2026-09-27T00:02:00Z"),
        base_image: "docker.io/library/node:20",
        egress: "mirror-only",
        isolation: "rootless",
        attestable: true,
        trigon_version: "0.0.0+git.2222222222222222222222222222222222222222",
        stabilizer_set: set,
        guard_manifest: Some(guard),
        guarded_members: Some(1),
        ..RunFacts::default()
    }
}

/// A leaf for `bytes`, signed with `key`, logged at `time`.
pub fn leaf_for(bytes: &[u8], key: &LocalKey, time: u64) -> RecordLeaf {
    record_leaf(bytes, &key.key_id(), time).unwrap()
}

fn made(statements: Vec<Envelope>, evidence: Vec<Vec<u8>>, key: &LocalKey, time: u64) -> Made {
    let bytes = Record::assemble(statements).unwrap().encode().unwrap();
    Made {
        digest: sha256(&bytes),
        leaf: leaf_for(&bytes, key, time),
        bytes,
        evidence,
    }
}

/// A v2 verdict about `pair`, with its `rebuild` and `buildobservation`, signed with `key`, and
/// every piece of evidence it names but the rebuilt artifact, which is a release asset. Its
/// falsifying command names [`ORIGIN`], the log it is logged in.
pub fn verdict(
    pair: &Pair,
    key: &LocalKey,
    run: &str,
    supersedes: Option<Supersession>,
    time: u64,
) -> Made {
    verdict_in(ORIGIN, pair, key, run, supersedes, time)
}

/// [`verdict`], for the log `origin`: a verdict's falsifying command names the log it is logged
/// in, and a client refuses one that names another (`docs/19` §4.2 item 6).
pub fn verdict_in(
    origin: &str,
    pair: &Pair,
    key: &LocalKey,
    run: &str,
    supersedes: Option<Supersession>,
    time: u64,
) -> Made {
    let c = pair.comparison();
    let set = profile("tar").unwrap();
    let manifest = trigon_attest::set_manifest_file(&set.manifest()).unwrap();
    let report = serde_json::to_vec(&c).unwrap();
    let strategy = canonical(&json!({ "name": pair.name, "steps": ["npm pack"] }));
    let guard = canonical(&json!({ "members": [pair.file()] }));
    let hex = |b: &[u8]| sha256(b).to_hex();
    let (m, r, s, g, a) = (
        hex(&manifest),
        hex(&report),
        hex(&strategy),
        hex(&guard),
        hex(&pair.rebuilt),
    );
    let purl = canonicalize(&pair.purl()).unwrap();
    let facts = VerdictFacts {
        run: identity(&purl, run),
        derivation: Some("heuristic"),
        evidence: EvidenceDigests {
            stabilizer_set_manifest: Some(&m),
            // Signed before verdicts named a module: the fixture is written byte for byte by
            // this, and a module here would be a new fixture.
            stabilizer_set_module: None,
            comparison: Some(&r),
            strategy: Some(&s),
            guard_manifest: Some(&g),
            rebuilt_artifact: Some(&a),
        },
        namespace: Some((origin, DISPUTES)),
        supersedes,
    };
    let st = Statement::verdict(pair.subject(), &c, &facts).unwrap();
    let set_digest = set.digest().to_hex();
    let facts = run_facts(run, Some(("tar", &set_digest)), &g);
    let rebuild = Statement::rebuild(
        Subject::of_bytes(format!("rebuilt-{}", pair.file()), &pair.rebuilt, false),
        &facts,
    );
    let observation = Statement::build_observation(pair.subject(), &facts);
    let statements = [st, rebuild, observation]
        .iter()
        .map(|s| sign_statement(s, key).unwrap())
        .collect();
    made(
        statements,
        vec![manifest, report, strategy, guard],
        key,
        time,
    )
}

fn identity<'a>(purl: &'a trigon_core::purl::CanonicalPurl, run: &'a str) -> RunIdentity<'a> {
    RunIdentity {
        purl,
        run_id: run,
        started: "2026-09-27T00:00:00Z",
        finished: Some("2026-09-27T00:02:00Z"),
        builder_version: Some("0.0.0+git.1111111111111111111111111111111111111111"),
        attestor_version: "0.0.0+git.2222222222222222222222222222222222222222",
        egress: "mirror-only",
        attestable: true,
    }
}

/// `m` with its statements decoded, each edited by `edit` — given its place in the record, `0` the
/// result — and signed again with `key`, the record assembled again from them, and a leaf for the
/// new bytes logged at `time`: a record `publish` would never write, for a test to log and refuse.
/// `evidence` replaces the evidence files written beside it, where given.
pub fn resigned(
    m: &Made,
    key: &LocalKey,
    time: u64,
    evidence: Option<Vec<Vec<u8>>>,
    edit: impl Fn(usize, &mut Statement),
) -> Made {
    let record = Record::from_slice(&m.bytes).unwrap();
    let statements = record
        .statements
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let mut st: Statement = serde_json::from_slice(&e.decoded_payload().unwrap()).unwrap();
            edit(i, &mut st);
            sign_statement(&st, key).unwrap()
        })
        .collect();
    made(
        statements,
        evidence.unwrap_or_else(|| m.evidence.clone()),
        key,
        time,
    )
}

/// A `void/v1` about `pair`'s published artifact: its guard tripped, so it names no set, and its
/// one piece of evidence is the guard manifest.
pub fn void(pair: &Pair, key: &LocalKey, run: &str, time: u64) -> Made {
    let purl = canonicalize(&pair.purl()).unwrap();
    let guard = canonical(&json!({ "members": [pair.file()] }));
    let g = sha256(&guard).to_hex();
    let trips = vec!["package/index.js".to_string()];
    let st = Statement::void(
        pair.subject(),
        &VoidFacts {
            run: identity(&purl, run),
            because: "guard_tripped",
            guard_trips: &trips,
            guard_manifest: Some(&g),
            guarded_members: Some(1),
            authored: &[],
            stabilizer_set: None,
            guard_manifest_evidence: Some(&g),
            supersedes: None,
        },
    );
    made(
        vec![sign_statement(&st, key).unwrap()],
        vec![guard],
        key,
        time,
    )
}

/// A `withdrawal/v1` of `of`, signed with `key`.
pub fn withdrawal(of: &Made, key: &LocalKey, time: u64) -> Made {
    let st = of.statement();
    let w = Statement::withdrawal(
        st.subject[0].clone(),
        st.predicate["purl"].as_str().unwrap(),
        st.predicate["purlCanon"].as_u64().unwrap(),
        Supersession {
            record: of.digest,
            reason: SupersedeReason::Withdrawn,
        },
        "0.0.0+git.2222222222222222222222222222222222222222",
    );
    made(
        vec![sign_statement(&w, key).unwrap()],
        Vec::new(),
        key,
        time,
    )
}

/// A clock that moves a minute at a time.
pub struct Clock(pub u64);

impl Clock {
    pub fn tick(&mut self) -> u64 {
        let t = self.0;
        self.0 += 60;
        t
    }
}

/// A record, and its leaf's place as the log and the index in it: `None` where it is unlogged.
pub type Placed = (Made, Option<(usize, u64)>);

/// What building the golden repository produced beside its files.
pub struct Golden {
    /// Each record by name, with its leaf's place.
    pub records: BTreeMap<&'static str, Placed>,
    /// Every checkpoint `log/` had, in order.
    pub checkpoints: Vec<SignedCheckpoint>,
    /// The artifacts of the packages a verdict re-derives from, by file name.
    pub artifacts: BTreeMap<String, Vec<u8>>,
}

/// The packages of the golden repository, by the name its records go by.
pub fn pairs() -> BTreeMap<&'static str, Pair> {
    BTreeMap::from([
        ("a", Pair::new("demo-a", b"a\n", b"a\n", false)),
        ("b", Pair::new("demo-b", b"b\n", b"B\n", false)),
        ("c", Pair::new("demo-c", b"c\n", b"c\n", false)),
        ("d", Pair::new("demo-d", b"d\n", b"d\n", true)),
        ("e", Pair::new("demo-e", b"e\n", b"e\n", true)),
        ("f", Pair::new("demo-f", b"f\n", b"f\n", false)),
        ("g", Pair::new("demo-g", b"g\n", b"g\n", false)),
        ("h", Pair::new("demo-h", b"h\n", b"h\n", false)),
        ("i", Pair::new("demo-i", b"i\n", b"i\n", false)),
        ("j", Pair::new("demo-j", b"j\n", b"j\n", false)),
        ("k", Pair::new("demo-k", b"k\n", b"k\n", false)),
    ])
}

/// Write the golden repository under `root`: see `golden.rs` for what it holds.
pub fn golden(root: &Path) -> Golden {
    let (k3, k4, release_key, stranger) = (
        attestation_key(3),
        attestation_key(4),
        attestation_key(5),
        attestation_key(STRANGER),
    );
    let p = pairs();
    let mut clock = Clock(T0);
    let mut records = BTreeMap::new();
    let mut checkpoints = Vec::new();

    write(
        root,
        "keys/log.vkey",
        format!("{}\n", log_key().vkey()).as_bytes(),
    );
    write(root, "keys/attestation.pub", k3.public_pem().as_bytes());
    let mut log = Writer::init(&root.join("log"), log_key());
    checkpoints.push(log.checkpoint());

    // Publication 1: verdicts, a divergence, a void, and the three records that fail.
    let a1 = verdict(&p["a"], &k3, "1789000000-aaaaaaa1", None, clock.tick());
    let b = verdict(&p["b"], &k3, "1789000000-bbbbbbbb", None, clock.tick());
    let c = void(&p["c"], &k3, "1789000000-cccccccc", clock.tick());
    let d0 = verdict(&p["d"], &k3, "1789000000-dddddddd", None, clock.tick());
    let f = verdict(&p["f"], &k3, "1789000000-ffffffff", None, clock.tick());
    // A statement that disagrees with its leaf: the leaf logs `exact` for a `normalized` verdict.
    let mut i = verdict(&p["i"], &k3, "1789000000-99999999", None, clock.tick());
    i.leaf.outcome = Some(trigon_attest::log::LeafOutcome::Exact);
    // Signed by a key the source never had.
    let h = verdict(
        &p["h"],
        &stranger,
        "1789000000-88888888",
        None,
        clock.tick(),
    );
    let first = [&a1, &b, &c, &d0, &f, &i, &h];
    log.append(&first.map(|m| Leaf::Record(m.leaf.clone())));
    checkpoints.push(log.checkpoint());

    // Publication 2: a heartbeat, and a verdict superseding the first.
    let quiet = clock.tick();
    let a2 = verdict(
        &p["a"],
        &k3,
        "1789000100-aaaaaaa2",
        Some(Supersession {
            record: a1.digest,
            reason: SupersedeReason::SetChanged,
        }),
        clock.tick(),
    );
    log.append(&[heartbeat(quiet), Leaf::Record(a2.leaf.clone())]);
    checkpoints.push(log.checkpoint());

    // Publication 3: the key change from key 3 to key 4, a withdrawal under key 4, a record
    // signed by the retired key after it, a client release, and an exact verdict under key 4.
    let change = KeyChangeLeaf::sign(ORIGIN, clock.tick(), &k3, &k4).unwrap();
    let w = withdrawal(&d0, &k4, clock.tick());
    let g = verdict(&p["g"], &k3, "1789000200-77777777", None, clock.tick());
    let release = ReleaseLeaf::sign(
        ORIGIN,
        clock.tick(),
        "trigon-check",
        "0.1.0",
        BTreeMap::from([(
            "trigon-check-0.1.0.tgz".to_string(),
            BTreeMap::from([(
                "sha256".to_string(),
                sha256(b"trigon-check-0.1.0.tgz").to_hex(),
            )]),
        )]),
        &release_key,
    )
    .unwrap();
    let e = verdict(&p["e"], &k4, "1789000200-eeeeeeee", None, clock.tick());
    log.append(&[
        Leaf::KeyChange(change),
        Leaf::Record(w.leaf.clone()),
        Leaf::Record(g.leaf.clone()),
        Leaf::Release(release),
        Leaf::Record(e.leaf.clone()),
    ]);
    checkpoints.push(log.checkpoint());

    // Publication 4: the end, naming a successor in this repository.
    log.append(&[Leaf::LogEnd(LogEndLeaf {
        time: clock.tick(),
        successor: Successor {
            origin: successor_key().name().into(),
            log_key: successor_key().vkey().to_string(),
            urls: Vec::new(),
            dir: "log/1".into(),
        },
    })]);
    let last = log.checkpoint();
    checkpoints.push(last.clone());

    // The successor: the continuation, a verdict under key 4, then a heartbeat.
    let mut next = Writer::init(&root.join("log/1"), successor_key());
    let continuation = Leaf::LogContinuation(LogContinuationLeaf {
        time: clock.tick(),
        checkpoint: last.note().cosign(&successor_key()).unwrap().to_string(),
    });
    // Its falsifying command names the successor, the log it is logged in.
    let k = verdict_in(
        SUCCESSOR,
        &p["k"],
        &k4,
        "1789000300-kkkkkkkk",
        None,
        clock.tick(),
    );
    next.append(&[continuation, Leaf::Record(k.leaf.clone())]);
    next.append(&[heartbeat(clock.tick())]);

    // A record signed like any other and never logged.
    let j = verdict(&p["j"], &k4, "1789000300-jjjjjjjj", None, clock.tick());

    for (name, m, at) in [
        ("a1", a1, Some((0, 0))),
        ("b", b, Some((0, 1))),
        ("c", c, Some((0, 2))),
        ("d0", d0, Some((0, 3))),
        ("f", f, Some((0, 4))),
        ("i", i, Some((0, 5))),
        ("h", h, Some((0, 6))),
        ("a2", a2, Some((0, 8))),
        ("w", w, Some((0, 10))),
        ("g", g, Some((0, 11))),
        ("e", e, Some((0, 13))),
        ("k", k, Some((1, 1))),
        ("j", j, None),
    ] {
        // `f`'s file is the one a deletion took: its leaf stays, and its evidence, shared by
        // others' or not, is there.
        match name {
            "f" => {
                for ev in &m.evidence {
                    write(root, &evidence_path(&sha256(ev)), ev);
                }
            }
            _ => m.write(root),
        }
        records.insert(name, (m, at));
    }

    // The index, derived from the log as `publish` derives it.
    let source = verify_source(root, &log_key().vkey(), None).unwrap();
    for (path, file) in index_files(&source).unwrap() {
        write(root, &path, &file.encode().unwrap());
    }

    let mut artifacts = BTreeMap::new();
    for name in ["a", "b", "e"] {
        let pair = &p[name];
        artifacts.insert(pair.file(), pair.upstream.clone());
        artifacts.insert(format!("rebuilt-{}", pair.file()), pair.rebuilt.clone());
    }
    Golden {
        records,
        checkpoints,
        artifacts,
    }
}

/// The committed fixture, `crates/trigon-attest/testdata/evidence/`.
pub fn testdata() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/evidence")
}

/// The committed golden repository.
pub fn repo() -> PathBuf {
    testdata().join("repo")
}

/// A copy of the directory at `from` under `to`, for a test to damage.
pub fn copy(from: &Path, to: &Path) {
    for (path, bytes) in crate::common::tree_of(from) {
        write(to, &path, &bytes);
    }
}

/// The golden records, by name: digest, subject sha256, purl and leaf, from `records.json`.
pub fn names() -> BTreeMap<String, Value> {
    serde_json::from_slice(&std::fs::read(testdata().join("records.json")).unwrap()).unwrap()
}

/// A golden record's digest, by name.
pub fn digest(name: &str) -> Digest {
    let r = &names()[name]["record"];
    Digest::from_hex(r.as_str().unwrap().strip_prefix("sha256:").unwrap()).unwrap()
}

/// The attestation key the golden repository pins: key 3.
pub fn pinned() -> trigon_attest::AttestationKey {
    trigon_attest::AttestationKey::from(attestation_key(3).public_key())
}

/// The golden repository, opened as a client pinned to its keys opens it.
pub fn open_golden() -> trigon_attest::evidence::Repository {
    trigon_attest::evidence::Repository::open(&repo(), &log_key().vkey(), &pinned(), None).unwrap()
}

/// A repository of one log holding `records`' leaves in the order given, their record files and
/// evidence, under `root`, for a test to open with key 3 pinned.
pub fn small(root: &Path, records: &[&Made]) {
    write(
        root,
        "keys/log.vkey",
        format!("{}\n", log_key().vkey()).as_bytes(),
    );
    let mut log = Writer::init(&root.join("log"), log_key());
    let leaves: Vec<Leaf> = records
        .iter()
        .map(|m| Leaf::Record(m.leaf.clone()))
        .collect();
    log.append(&leaves);
    for m in records {
        m.write(root);
    }
}

/// The repository at `root`, opened with the golden keys.
pub fn open(root: &Path) -> trigon_attest::evidence::Repository {
    trigon_attest::evidence::Repository::open(root, &log_key().vkey(), &pinned(), None).unwrap()
}
