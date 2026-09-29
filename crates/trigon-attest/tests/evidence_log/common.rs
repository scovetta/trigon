//! What every test of the log builds on: fixed keys, leaves, and a writer that lays a log out on
//! disk as `publish` will (`docs/19` §2.3, §10 phase 5) — without the rules, so that a test can
//! write the log a rule exists to refuse.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sha2::Digest as _;
use trigon_attest::log::merkle::leaf_hash;
use trigon_attest::log::{
    Append, Checkpoint, DirFiles, HeartbeatLeaf, Leaf, LeafOutcome, LogSigner, RecordLeaf,
    SignedCheckpoint, Tree, plan_append,
};
use trigon_attest::{EQUIVALENCE_V2, LocalKey, Signer as _};
use trigon_core::Digest;

pub const ORIGIN: &str = "example.com/trigon-evidence";
pub const SUCCESSOR: &str = "example.com/trigon-evidence/1";

/// 2026-09-27T00:00:00Z: when the first leaf of every test log is logged.
pub const T0: u64 = 1_790_467_200;

/// The log key of [`ORIGIN`]. Fixed, so a golden file signed with it is the same on every run.
pub fn log_key() -> LogSigner {
    LogSigner::from_seed(ORIGIN, [1; 32]).unwrap()
}

/// The log key of [`SUCCESSOR`].
pub fn successor_key() -> LogSigner {
    LogSigner::from_seed(SUCCESSOR, [2; 32]).unwrap()
}

/// Attestation key `n`: 3 is the pinned one, 4 the one it rotates to.
pub fn attestation_key(n: u8) -> LocalKey {
    LocalKey::from_bytes(&[n; 32]).unwrap()
}

pub fn sha256(s: &str) -> Digest {
    Digest::from_bytes(sha2::Sha256::digest(s.as_bytes()).into())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A record leaf for an `equivalence/v2` verdict about artifact `n`, signed by `key`.
pub fn record_leaf(time: u64, n: u32, key: &LocalKey) -> RecordLeaf {
    let artifact = format!("left-pad-1.3.{n}.tgz");
    RecordLeaf {
        time,
        subject: BTreeMap::from([
            ("sha256".into(), sha256(&artifact).to_hex()),
            (
                "sha512".into(),
                hex(&sha2::Sha512::digest(artifact.as_bytes())),
            ),
        ]),
        purl: format!("pkg:npm/left-pad@1.3.{n}"),
        purl_canon: 1,
        predicate_type: EQUIVALENCE_V2.into(),
        outcome: Some(LeafOutcome::Normalized),
        stabilizer_set: Some(sha256("stabilizer set")),
        key_id: key.key_id(),
        record: sha256(&format!("record {n}")),
        supersedes: None,
        reason: None,
    }
}

pub fn record(time: u64, n: u32, key: &LocalKey) -> Leaf {
    Leaf::Record(record_leaf(time, n, key))
}

pub fn heartbeat(time: u64) -> Leaf {
    Leaf::Heartbeat(HeartbeatLeaf { time })
}

/// `n` heartbeats a minute apart, from `from`.
pub fn heartbeats(from: u64, n: u64) -> Vec<Leaf> {
    (0..n).map(|i| heartbeat(from + 60 * i)).collect()
}

/// A log being written into a directory: each append writes the files [`plan_append`] plans,
/// removes the partials it makes obsolete, and signs a new checkpoint.
pub struct Writer {
    pub root: PathBuf,
    pub signer: LogSigner,
    pub tree: Tree,
    pub entries: Vec<Vec<u8>>,
}

impl Writer {
    /// A log with no leaves: its directory, and a checkpoint of size 0.
    pub fn init(root: &Path, signer: LogSigner) -> Writer {
        std::fs::create_dir_all(root).unwrap();
        let w = Writer {
            root: root.to_path_buf(),
            signer,
            tree: Tree::new(),
            entries: Vec::new(),
        };
        w.sign();
        w
    }

    pub fn append(&mut self, leaves: &[Leaf]) -> Append {
        let entries = leaves.iter().map(|l| l.encode().unwrap()).collect();
        self.append_raw(entries)
    }

    /// Append leaves as bytes, whatever they are.
    pub fn append_raw(&mut self, new: Vec<Vec<u8>>) -> Append {
        let tail = self.entries.len() - self.entries.len() % 256;
        let append = plan_append(&self.tree, &self.entries[tail..], &new).unwrap();
        for (path, bytes) in &append.files {
            self.write(path, bytes);
        }
        for dir in &append.obsolete {
            std::fs::remove_dir_all(self.root.join(dir)).unwrap();
        }
        for e in new {
            self.tree.push(leaf_hash(&e));
            self.entries.push(e);
        }
        assert_eq!(self.tree.root(), append.root);
        self.sign();
        append
    }

    /// Sign the tree as it stands and write the checkpoint.
    pub fn sign(&self) -> SignedCheckpoint {
        let cp = Checkpoint {
            origin: self.signer.name().to_string(),
            size: self.tree.size(),
            root: self.tree.root(),
        };
        let signed = SignedCheckpoint::sign(&cp, &self.signer).unwrap();
        self.write("checkpoint", signed.to_string().as_bytes());
        signed
    }

    /// The checkpoint on disk.
    pub fn checkpoint(&self) -> SignedCheckpoint {
        let bytes = std::fs::read(self.root.join("checkpoint")).unwrap();
        SignedCheckpoint::open(&bytes, &self.signer.vkey()).unwrap()
    }

    pub fn files(&self) -> DirFiles {
        DirFiles::new(&self.root)
    }

    pub fn write(&self, path: &str, bytes: &[u8]) {
        let p = self.root.join(path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }

    pub fn read(&self, path: &str) -> Vec<u8> {
        std::fs::read(self.root.join(path)).unwrap()
    }
}

/// Every file under `root`, by its path relative to it, `/`-separated, in order.
pub fn tree_of(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else {
                let rel = p.strip_prefix(root).unwrap();
                let rel: Vec<_> = rel.iter().map(|c| c.to_str().unwrap()).collect();
                out.insert(rel.join("/"), std::fs::read(&p).unwrap());
            }
        }
    }
    out
}

/// The message of an error, for asserting on.
pub fn err<T: std::fmt::Debug, E: std::fmt::Display>(r: Result<T, E>) -> String {
    match r {
        Ok(v) => panic!("expected an error, got {v:?}"),
        Err(e) => e.to_string(),
    }
}
