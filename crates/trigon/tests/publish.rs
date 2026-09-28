//! `trigon log keygen`, `log init`, `log sign` and `trigon publish`, through the binary, against
//! local git repositories made in temp directories: no network (`docs/19` §10 phase 5).
//!
//! One test per done-when item of phase 5 in scope here: a run publishes to a bare repository in
//! one commit and a fresh clone verifies it with the reader's code; a withheld run is refused and a
//! void one publishes only as `void/v1`; two publishers racing leave one linear history, one root
//! per size, and no signed checkpoint outside the loser's clone; a publisher killed between steps
//! leaves the old state or the new; files planted in `log/` beyond the checkpoint are never
//! signed; `--dry-run` leaves everything byte-identical; `--reconcile` restores a deleted index
//! file; a withdrawal is logged with its supersession; a heartbeat is appended only when due; and
//! the repository named each way publishes. HTTPS and SSH cannot be reached offline; that they
//! reach `git` exactly as configured is a unit test of `crates/trigon/src/publish/git.rs`.
//!
//! Publishable runs are made the way phase 3 records them — two agreeing attempts at one cache
//! key, on two machines, two hours apart — from artifacts compared here, not built by podman.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use trigon_attest::evidence::{Answer, Key, RecordFailure, Repository};
use trigon_attest::log::{Checkpoint, LogSigner, SignedNote};
use trigon_attest::{AttestationKey, LocalKey};
use trigon_core::Match;
use trigon_store::{ArtifactRef, CacheState, Environment, RunRecord, RunState, Store};

const ORIGIN: &str = "example.com/trigon-evidence";
const DISPUTES: &str = "https://example.com/trigon-evidence/issues";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_trigon")
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Everything one test works in: a store, a home with `evidence.toml` in it, a working directory,
/// an empty bare repository, the attestation key and the log key.
struct World {
    dir: PathBuf,
    store: PathBuf,
    remote: PathBuf,
    key: PathBuf,
    log_key: PathBuf,
}

impl World {
    fn new(name: &str) -> World {
        let dir =
            std::env::temp_dir().join(format!("trigon-publish-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for sub in ["store", "home/.config/trigon", "project"] {
            std::fs::create_dir_all(dir.join(sub)).unwrap();
        }
        let w = World {
            store: dir.join("store"),
            remote: dir.join("remote.git"),
            key: dir.join("signing.key"),
            log_key: dir.join("log.key"),
            dir,
        };
        git(
            &w.dir,
            &["init", "--quiet", "--bare", "-b", "main", "remote.git"],
        );
        let seed: String = attestation()
            .seed()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        std::fs::write(&w.key, format!("{seed}\n")).unwrap();
        w.config("");
        ok(&w.trigon(&[
            "log",
            "keygen",
            "--origin",
            ORIGIN,
            "--out",
            w.log_key.to_str().unwrap(),
        ]));
        w
    }

    /// `evidence.toml`, with `[publish]` naming the origin, the dispute channel and the log key,
    /// and `extra` after them.
    fn config(&self, extra: &str) {
        std::fs::write(
            self.dir.join("home/.config/trigon/evidence.toml"),
            format!(
                "[publish]\norigin = \"{ORIGIN}\"\ndisputes = \"{DISPUTES}\"\n\
                 log_key = \"{}\"\n{extra}",
                self.log_key.display()
            ),
        )
        .unwrap();
    }

    /// `trigon <args>` in the working directory, with this world's home and state directory — the
    /// host's, as far as `publish` and `log sign` can tell — and none of this process's
    /// `TRIGON_*`.
    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(bin());
        c.current_dir(self.dir.join("project"))
            .env("HOME", self.dir.join("home"))
            .env("XDG_CONFIG_HOME", self.dir.join("home/.config"))
            .env("XDG_STATE_HOME", self.dir.join("home/.local/state"))
            .env("GIT_CONFIG_NOSYSTEM", "1");
        for (k, _) in std::env::vars_os() {
            if k.to_string_lossy().starts_with("TRIGON_") {
                c.env_remove(k);
            }
        }
        c.args(args);
        c
    }

    fn trigon(&self, args: &[&str]) -> Output {
        self.command(args).output().unwrap()
    }

    fn init(&self, repo: &str) -> String {
        ok(&self.init_as(repo, ORIGIN))
    }

    /// `trigon log init` of the log `origin` in `repo`, as it ended.
    fn init_as(&self, repo: &str, origin: &str) -> Output {
        let key = attestation().public_hex();
        self.trigon(&[
            "log",
            "init",
            "--origin",
            origin,
            "--repo",
            repo,
            "--attestation-key",
            &key,
        ])
    }

    /// A log of its own, `origin`, with a key of its own, as `evidence.toml` then names it, and
    /// `extra` after: every repository a host begins is another log, since one key signing two
    /// logs' trees would sign two roots for one size. Its key file.
    fn another_log(&self, origin: &str, extra: &str) -> PathBuf {
        let key = self.dir.join(format!("{}.key", origin.replace('/', "_")));
        ok(&self.trigon(&[
            "log",
            "keygen",
            "--origin",
            origin,
            "--out",
            key.to_str().unwrap(),
        ]));
        std::fs::write(
            self.dir.join("home/.config/trigon/evidence.toml"),
            format!(
                "[publish]\norigin = \"{origin}\"\ndisputes = \"{DISPUTES}\"\n\
                 log_key = \"{}\"\n{extra}",
                key.display()
            ),
        )
        .unwrap();
        key
    }

    /// The operator's own git configuration, `~/.gitconfig` in this world's home, which `publish`
    /// keeps for its credential helper.
    fn gitconfig(&self, text: &str) {
        std::fs::write(self.dir.join("home/.gitconfig"), text).unwrap();
    }

    fn attest(&self, id: &str, extra: &[&str]) -> String {
        let mut args = vec![
            "attest",
            id,
            "--store",
            self.store.to_str().unwrap(),
            "--key",
            self.key.to_str().unwrap(),
        ];
        args.extend_from_slice(extra);
        ok(&self.trigon(&args))
    }

    /// `trigon publish` to the bare repository, from this world's store.
    fn publish(&self, args: &[&str]) -> Output {
        self.publish_from(&self.store, args)
    }

    fn publish_from(&self, store: &Path, args: &[&str]) -> Output {
        let mut all = vec![
            "publish",
            "--store",
            store.to_str().unwrap(),
            "--repo",
            self.remote.to_str().unwrap(),
        ];
        all.extend_from_slice(args);
        self.trigon(&all)
    }

    /// A fresh clone of the bare repository, as a consumer makes one.
    fn clone_fresh(&self, name: &str) -> PathBuf {
        let to = self.dir.join(name);
        let _ = std::fs::remove_dir_all(&to);
        git(
            &self.dir,
            &[
                "clone",
                "--quiet",
                "-b",
                "main",
                self.remote.to_str().unwrap(),
                to.to_str().unwrap(),
            ],
        );
        to
    }

    /// The clone opened as a client pinned to this world's keys opens it.
    fn open(&self, clone: &Path) -> Repository {
        Repository::open(clone, &self.vkey(), &pinned(), None).unwrap()
    }

    fn vkey(&self) -> trigon_attest::LogVkey {
        LogSigner::from_file(&self.log_key).unwrap().vkey()
    }

    fn run(&self, id: &str) -> RunRecord {
        rt().block_on(Store::local(&self.store).unwrap().get_run(id))
            .unwrap()
    }

    fn commits(&self) -> u64 {
        git(&self.remote, &["rev-list", "--count", "main"])
            .parse()
            .unwrap()
    }

    fn head(&self) -> String {
        git(&self.remote, &["rev-parse", "main"])
    }

    /// Commit `files` to the bare repository from a clone of its own, as whoever holds the push
    /// credential could: `None` removes the file.
    fn plant(&self, files: &[(&str, Option<&[u8]>)]) {
        plant_in(&self.clone_fresh("planter"), files);
    }
}

/// Commit `files` in the clone `c` and push them to its origin's `main`: `None` removes the file.
fn plant_in(c: &Path, files: &[(&str, Option<&[u8]>)]) {
    for (path, bytes) in files {
        let p = c.join(path);
        match bytes {
            Some(b) => {
                std::fs::create_dir_all(p.parent().unwrap()).unwrap();
                std::fs::write(&p, b).unwrap();
            }
            None => std::fs::remove_file(&p).unwrap(),
        }
    }
    git(c, &["add", "--all", "--force"]);
    git(c, &["commit", "--quiet", "-m", "planted"]);
    git(c, &["push", "--quiet", "origin", "main"]);
}

/// A bare repository at `repo` whose `main` has one commit, of `files`: a branch as a hosting
/// template may make it, before `log init`.
fn seeded(repo: &Path, files: &[(&str, &[u8])]) {
    let parent = repo.parent().unwrap();
    let name = repo.file_name().unwrap().to_str().unwrap();
    if !repo.exists() {
        git(parent, &["init", "--quiet", "--bare", "-b", "main", name]);
    }
    let seed = parent.join(format!("{name}-seed"));
    let _ = std::fs::remove_dir_all(&seed);
    git(
        parent,
        &["init", "--quiet", "-b", "main", seed.to_str().unwrap()],
    );
    git(&seed, &["remote", "add", "origin", repo.to_str().unwrap()]);
    let files: Vec<(&str, Option<&[u8]>)> = files.iter().map(|(p, b)| (*p, Some(*b))).collect();
    plant_in(&seed, &files);
}

/// The attestation key every record here is signed with.
fn attestation() -> LocalKey {
    LocalKey::from_bytes(&[3; 32]).unwrap()
}

fn pinned() -> AttestationKey {
    AttestationKey::from(attestation().public_key())
}

/// `git` in `dir`, with no configuration of the host's and a fixed identity, and its output.
fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn ok(out: &Output) -> String {
    let t = text(out);
    assert!(out.status.success(), "{t}");
    t
}

fn refused(out: &Output) -> String {
    let t = text(out);
    assert!(!out.status.success(), "expected a refusal: {t}");
    t
}

// ---------------------------------------------------------------------------------------------
// Runs, as phase 3 records a publishable one
// ---------------------------------------------------------------------------------------------

fn tgz(body: &[u8], mtime: u64) -> Vec<u8> {
    let mut b = ::tar::Builder::new(Vec::new());
    let mut h = ::tar::Header::new_ustar();
    h.set_size(body.len() as u64);
    h.set_mode(0o644);
    h.set_mtime(mtime);
    h.set_cksum();
    b.append_data(&mut h, "package/index.js", body).unwrap();
    let tar = b.into_inner().unwrap();
    let mut gz = Vec::new();
    {
        use std::io::Write as _;
        let mut e = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
        e.write_all(&tar).unwrap();
        e.finish().unwrap();
    }
    gz
}

/// A package version and the two artifacts a run of it compares.
struct Package {
    name: String,
    upstream: Vec<u8>,
    rebuilt: Vec<u8>,
}

impl Package {
    /// `demo-<name>@1.0.0`, rebuilt `normalized`, or `divergent` where `diverges`.
    fn new(name: &str, diverges: bool) -> Package {
        let body = format!("module.exports = '{name}'\n");
        Package {
            name: name.into(),
            upstream: tgz(body.as_bytes(), 1),
            rebuilt: match diverges {
                true => tgz(b"module.exports = 'something else'\n", 2),
                false => tgz(body.as_bytes(), 2),
            },
        }
    }

    fn target(&self) -> String {
        format!("pkg:npm/demo-{}@1.0.0", self.name)
    }

    fn file(&self) -> String {
        format!("demo-{}-1.0.0.tgz", self.name)
    }

    fn sha256(&self) -> String {
        trigon_attest::Record::digest_of(&self.upstream).to_hex()
    }
}

/// One attempt at `p`, as `record_run` writes one: both artifacts, the comparison, the strategy
/// and the guard manifest in the store; the machine it ran on, its cache state, when it began, the
/// cache key and the agreement digest.
async fn attempt(
    store: &Store,
    id: &str,
    p: &Package,
    key: &str,
    host: char,
    started: &str,
    egress: &str,
) -> RunRecord {
    let up = store.blobs().put(p.upstream.clone()).await.unwrap();
    let rb = store.blobs().put(p.rebuilt.clone()).await.unwrap();
    let comparison = trigon_compare::compare_bytes(
        p.upstream.clone(),
        p.rebuilt.clone(),
        trigon_core::Format::TarGz,
        &trigon_stabilize::profile("tar-gzip").unwrap(),
        &trigon_archive::Limits::default(),
    )
    .unwrap();
    let cmp = store
        .blobs()
        .put(serde_json::to_vec(&comparison).unwrap())
        .await
        .unwrap();
    let strategy = trigon_strategy::from_yaml(
        "schema: 1\nkind: flow\nlocation:\n  repo: https://github.com/owner/demo\n  ref: \
         ff8e7ba8b4122829cf66125ca8445cac7f073bce\nsrc:\n- uses: git-checkout\nbuild:\n- runs: npm \
         pack\noutput_path: '*.tgz'\n",
    )
    .unwrap();
    let json = trigon_strategy::canonical(&strategy).unwrap();
    let strategy_blob = store.blobs().put(json.into_bytes()).await.unwrap();
    let tools = trigon_strategy::ToolRegistry::builtin().unwrap();
    let guard = store
        .blobs()
        .put(format!(r#"{{"artifact":"{}","members":["x"]}}"#, p.name).into_bytes())
        .await
        .unwrap();
    let mut r = RunRecord::new(
        id,
        p.target(),
        ArtifactRef {
            name: p.file(),
            sha256: up,
            bytes: p.upstream.len() as u64,
            stored: true,
        },
        Environment {
            base_image: "docker.io/library/debian@sha256:aa".into(),
            derived_image: None,
            egress: egress.into(),
            isolation: "user_ns".into(),
            guard_manifest: Some(guard.to_hex()),
            guarded_members: Some(1),
            attestable: egress != "open",
            registry_moment: None,
            pin: None,
        },
        started,
    );
    r.state = RunState::Done;
    r.outcome = Some(comparison.outcome.to_string());
    r.comparison = Some(cmp);
    r.rebuild = Some(ArtifactRef {
        name: p.file(),
        sha256: rb,
        bytes: p.rebuilt.len() as u64,
        stored: true,
    });
    r.upstream_digests = Some(trigon_store::UpstreamDigests {
        sha512: trigon_attest::sha512_of(&p.upstream),
        sha1: Some(trigon_attest::sha1_of(&p.upstream)),
        declared: Vec::new(),
        note: None,
    });
    r.strategy = Some(strategy_blob);
    r.strategy_digest = Some(trigon_strategy::strategy_digest(&strategy, &tools).unwrap());
    r.trigon_version = Some("0.0.0+git.1111111111111111111111111111111111111111".into());
    r.derivation = Some("heuristic".into());
    r.non_builtin_stabilizer = Some(false);
    r.cache_key = Some(key.into());
    r.agreement = Some(comparison.agreement());
    r.host = Some(format!("machine-id:{}", host.to_string().repeat(64)));
    r.cache = Some(CacheState::default());
    store.put_run(&r).await.unwrap();
    r
}

/// Two agreeing attempts at `p`, on two machines two hours apart: a pair the gate publishes. The
/// first is attested; its id is returned first.
fn pair(w: &World, p: &Package, tag: &str) -> (String, String) {
    let store = Store::local(&w.store).unwrap();
    let (a, b) = (
        format!("1789000000-{tag}0001"),
        format!("1789007200-{tag}0002"),
    );
    let key = format!("ck1:{tag}");
    rt().block_on(async {
        attempt(
            &store,
            &a,
            p,
            &key,
            'a',
            "2026-09-27T00:00:00Z",
            "mirror-only",
        )
        .await;
        attempt(
            &store,
            &b,
            p,
            &key,
            'b',
            "2026-09-27T02:00:00Z",
            "mirror-only",
        )
        .await;
    });
    w.attest(&a, &[]);
    (a, b)
}

/// The record file of `digest` in the clone at `root`.
fn record_file(root: &Path, digest: &trigon_core::Digest) -> PathBuf {
    root.join(trigon_attest::evidence::record_path(digest))
}

// ---------------------------------------------------------------------------------------------
// The done-when items
// ---------------------------------------------------------------------------------------------

#[test]
fn a_run_publishes_in_one_commit_and_a_fresh_clone_verifies_it() {
    let w = World::new("one-commit");
    let said = w.init(w.remote.to_str().unwrap());
    assert!(
        said.contains("gh api --method POST repos/<owner>/<repo>/rulesets"),
        "{said}"
    );
    assert_eq!(w.commits(), 1);
    let p = Package::new("a", false);
    let (first, second) = pair(&w, &p, "aaaa");
    let said = ok(&w.publish(&[&first]));
    assert!(
        said.contains("logged    leaf 0: run 1789000000-aaaa0001"),
        "{said}"
    );

    // One commit, with the message §2.3 gives, on top of the log's first.
    assert_eq!(w.commits(), 2);
    assert_eq!(
        git(&w.remote, &["log", "-1", "--format=%s", "main"]),
        "publish: 1 record, tree 0 → 1"
    );

    // A fresh clone verifies it with the reader's own code, and finds the verdict by its digest.
    let clone = w.clone_fresh("consumer");
    let repo = w.open(&clone);
    let found = repo.lookup(&Key::Digest {
        algorithm: "sha256",
        hex: p.sha256(),
    });
    assert_eq!(
        found.answer(Match::NormalizedWithCaveats),
        Answer::Outcome(Match::Normalized)
    );
    let current: Vec<_> = found.current().collect();
    assert_eq!(current.len(), 1);
    let record = current[0].verified().unwrap();
    assert_eq!(record.statement.predicate["run"]["id"], first.as_str());
    assert_eq!(
        record.record.statements.len(),
        3,
        "the verdict, its rebuild, its observation"
    );

    // Every evidence file it names is there, and holds.
    assert!(
        record.unchecked().all(|e| e.name == "rebuiltArtifact"),
        "{:?}",
        record.evidence
    );

    // The run says where it was published.
    let run = w.run(&first);
    let published = run
        .published
        .expect("the run records where it was published");
    assert_eq!(published.leaf, 0);
    assert_eq!(published.record, record.digest);
    assert_eq!(published.commit, w.head());
    assert_eq!(published.repository, w.remote.to_str().unwrap());

    // And the network-free verifier checks the record from the clone.
    let file = record_file(&clone, &record.digest);
    let out = w.trigon(&[
        "verify-attestation",
        "--record",
        file.to_str().unwrap(),
        "--evidence",
        clone.to_str().unwrap(),
        "--log-vkey",
        &w.vkey().to_string(),
        "--attestation-key",
        &attestation().public_hex(),
    ]);
    ok(&out);

    // Of two agreeing attempts one is published, and a run is published once.
    let again = refused(&w.publish(&[&second]));
    assert!(
        again.contains("agrees with run `1789000000-aaaa0001`, which is published"),
        "{again}"
    );
    let again = refused(&w.publish(&[&first]));
    assert!(again.contains("already published"), "{again}");
    assert_eq!(w.commits(), 2, "a refusal writes nothing");
}

#[test]
fn a_withheld_run_is_refused_and_a_void_run_publishes_only_as_void() {
    let w = World::new("gate");
    w.init(w.remote.to_str().unwrap());
    let store = Store::local(&w.store).unwrap();

    // One attempt: awaiting confirmation, withheld.
    let lone = Package::new("lone", false);
    rt().block_on(attempt(
        &store,
        "1789000000-10ae0001",
        &lone,
        "ck1:lone",
        'a',
        "2026-09-27T00:00:00Z",
        "mirror-only",
    ));
    w.attest("1789000000-10ae0001", &[]);
    let said = refused(&w.publish(&["1789000000-10ae0001"]));
    assert!(
        said.contains("withholds it (awaiting_confirmation)"),
        "{said}"
    );
    assert!(said.contains("nothing was written"), "{said}");

    // A divergence, confirmed, and refused while `divergences` is "refuse".
    let div = Package::new("div", true);
    let (d, _) = pair(&w, &div, "d1d1");
    let said = refused(&w.publish(&[&d]));
    assert!(
        said.contains("it is a divergence, and `[publish] divergences` is \"refuse\""),
        "{said}"
    );
    assert_eq!(w.commits(), 1);

    // Open egress: void, on one attempt, and signed and published as `void/v1` alone — even for a
    // divergence, since a void says nothing of which way its comparison went.
    let open = Package::new("open", true);
    rt().block_on(attempt(
        &store,
        "1789000000-0be00001",
        &open,
        "ck1:open",
        'a',
        "2026-09-27T00:00:00Z",
        "open",
    ));
    let signed = w.attest("1789000000-0be00001", &[]);
    assert!(signed.contains("void/v1"), "{signed}");
    ok(&w.publish(&["1789000000-0be00001"]));
    let clone = w.clone_fresh("consumer");
    let found = w.open(&clone).lookup(&Key::Digest {
        algorithm: "sha256",
        hex: open.sha256(),
    });
    assert_eq!(found.answer(Match::NormalizedWithCaveats), Answer::Void);
    let v = found.current().next().unwrap().verified().unwrap();
    assert_eq!(v.record.statements.len(), 1);
    assert_eq!(v.statement.predicate_type, trigon_attest::VOID);
    assert_eq!(v.leaf.outcome.map(|o| o.as_str()), Some("void"));
    assert!(v.statement.predicate.get("comparison").is_none());
}

#[test]
fn a_verdict_without_its_falsifying_command_or_for_a_current_artifact_is_refused() {
    let w = World::new("statement");
    w.init(w.remote.to_str().unwrap());
    // Attested with no `[publish] origin` and `disputes`: no falsifying command, no dispute
    // pointer, and not publishable.
    std::fs::write(
        w.dir.join("home/.config/trigon/evidence.toml"),
        format!("[publish]\nlog_key = \"{}\"\n", w.log_key.display()),
    )
    .unwrap();
    let p = Package::new("a", false);
    let (first, _) = pair(&w, &p, "aaaa");
    w.config("");
    let said = refused(&w.publish(&[&first]));
    assert!(said.contains("signs no falsifying command"), "{said}");

    // Attested again with them: published.
    w.attest(&first, &[]);
    ok(&w.publish(&[&first]));

    // Another pair about the same artifact, under another strategy: it has a current record, and
    // is published only as that record's supersession.
    let (again, _) = pair(&w, &p, "a2a2");
    let said = refused(&w.publish(&[&again]));
    assert!(said.contains("has a current record"), "{said}");
    let clone = w.clone_fresh("consumer");
    let digest = w.run(&first).published.unwrap().record;
    let file = record_file(&clone, &digest);
    w.attest(
        &again,
        &[
            "--supersedes",
            file.to_str().unwrap(),
            "--reason",
            "set_changed",
        ],
    );
    ok(&w.publish(&[&again]));
    let clone = w.clone_fresh("consumer");
    let found = w.open(&clone).lookup(&Key::Digest {
        algorithm: "sha256",
        hex: p.sha256(),
    });
    assert_eq!(found.found.len(), 2);
    assert_eq!(found.found[0].superseded_by.len(), 1);
    assert_eq!(found.current().count(), 1);

    // A repository whose log is another origin's is refused whole.
    std::fs::write(
        w.dir.join("home/.config/trigon/evidence.toml"),
        format!(
            "[publish]\norigin = \"example.com/elsewhere\"\ndisputes = \"{DISPUTES}\"\n\
             log_key = \"{}\"\n",
            w.log_key.display()
        ),
    )
    .unwrap();
    let said = refused(&w.publish(&["--heartbeat"]));
    assert!(
        said.contains("keys/log.vkey names the log `example.com/trigon-evidence`"),
        "{said}"
    );
}

/// Everything a repository's object store holds that is a checkpoint of this log: `(size, root)`,
/// whether a commit reaches it or not.
fn checkpoints_in(repo: &Path) -> BTreeSet<(u64, [u8; 32])> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["cat-file", "--batch-all-objects", "--batch"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(out.status.success());
    let bytes = out.stdout;
    let mut found = BTreeSet::new();
    let mut at = 0;
    while at < bytes.len() {
        let nl = at + bytes[at..].iter().position(|b| *b == b'\n').unwrap();
        let header = String::from_utf8_lossy(&bytes[at..nl]).to_string();
        let size: usize = header.rsplit(' ').next().unwrap().parse().unwrap();
        let body = &bytes[nl + 1..nl + 1 + size];
        if header.split(' ').nth(1) == Some("blob")
            && let Ok(note) = SignedNote::parse(body)
            && let Ok(c) = Checkpoint::parse(note.text())
            && c.origin == ORIGIN
        {
            found.insert((c.size, c.root));
        }
        at = nl + 1 + size + 1;
    }
    found
}

/// The one directory under a store's `publish/`: the state of the one repository it publishes to.
fn state_dir(store: &Path) -> PathBuf {
    std::fs::read_dir(store.join("publish"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.is_dir())
        .unwrap()
}

/// Two publishers — two hosts, as far as either can tell: two stores, two state directories, two
/// working clones, one bare remote, so neither the store's lock nor the host's keeps them apart —
/// the second publishing in the moment between the first's commit and its push, by a hook in the
/// first's working clone. The first loses the push, discards its commit and the checkpoint signed
/// for it, and publishes again on top of the second.
#[test]
fn two_publishers_leave_one_linear_history_and_one_root_per_size() {
    let w = World::new("race");
    w.init(w.remote.to_str().unwrap());
    let (pa, pb) = (Package::new("a", false), Package::new("b", false));
    let (a, _) = pair(&w, &pa, "aaaa");
    // B's runs, in a store of their own, attested there.
    let b_store = w.dir.join("store-b");
    let b = {
        let store = Store::local(&b_store).unwrap();
        let key = "ck1:bbbb".to_string();
        rt().block_on(async {
            attempt(
                &store,
                "1789000000-bbbb0001",
                &pb,
                &key,
                'c',
                "2026-09-27T00:00:00Z",
                "mirror-only",
            )
            .await;
            attempt(
                &store,
                "1789007200-bbbb0002",
                &pb,
                &key,
                'd',
                "2026-09-27T02:00:00Z",
                "mirror-only",
            )
            .await;
        });
        ok(&w.trigon(&[
            "attest",
            "1789000000-bbbb0001",
            "--store",
            b_store.to_str().unwrap(),
            "--key",
            w.key.to_str().unwrap(),
        ]));
        "1789000000-bbbb0001"
    };

    // A's working clone, made by publishing a heartbeat, and a hook in it that has B publish the
    // moment A has committed, then removes itself.
    ok(&w.publish(&["--heartbeat"]));
    let a_clone = state_dir(&w.store).join("clone");
    let hook = a_clone.join(".git/hooks/post-commit");
    std::fs::write(
        &hook,
        format!(
            "#!/bin/sh\nrm -f \"$0\"\nexport XDG_STATE_HOME='{}'\n\
             exec '{}' publish '{b}' --store '{}' --repo '{}' >'{}' 2>&1\n",
            w.dir.join("host-b").display(),
            bin(),
            b_store.display(),
            w.remote.display(),
            w.dir.join("b.log").display()
        ),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let said = ok(&w.publish(&[&a]));
    let b_said = std::fs::read_to_string(w.dir.join("b.log")).unwrap_or_default();
    assert!(
        b_said.contains("logged    leaf 1"),
        "B published first: {b_said}"
    );
    assert!(
        said.contains("lost      the push to another writer"),
        "{said}\nB: {b_said}"
    );
    assert!(
        said.contains("logged    leaf 2: run 1789000000-aaaa0001"),
        "{said}"
    );

    // One linear history: every commit has one parent, the first none.
    let commits = git(&w.remote, &["rev-list", "--parents", "main"]);
    assert_eq!(commits.lines().count(), 4, "{commits}");
    assert!(
        commits.lines().all(|l| l.split(' ').count() <= 2),
        "{commits}"
    );

    // One root per size, among every checkpoint the remote's object store holds, reachable or not.
    let remote = checkpoints_in(&w.remote);
    let mut sizes: BTreeMap<u64, usize> = BTreeMap::new();
    for (size, _) in &remote {
        *sizes.entry(*size).or_default() += 1;
    }
    assert!(sizes.values().all(|n| *n == 1), "{sizes:?}");
    assert_eq!(sizes.keys().copied().collect::<Vec<_>>(), [0, 1, 2, 3]);

    // The checkpoint A signed for the push it lost is in A's clone, and nowhere else.
    let lost: BTreeSet<_> = checkpoints_in(&a_clone)
        .difference(&remote)
        .copied()
        .collect();
    assert!(
        !lost.is_empty(),
        "A signed a checkpoint for the push it lost"
    );
    let b_clone = state_dir(&b_store).join("clone");
    assert!(lost.is_disjoint(&checkpoints_in(&b_clone)));
    assert!(lost.is_disjoint(&remote));

    // And the log verifies, both records in it once.
    let clone = w.clone_fresh("consumer");
    let repo = w.open(&clone);
    assert_eq!(repo.record_leaves().count(), 2);
}

/// A publisher stopped at each step, as a kill would stop it, leaves the remote as it was or as
/// the publication makes it; the next run finishes the job, and nothing is logged twice.
#[test]
fn a_publisher_killed_between_steps_leaves_the_old_state_or_the_new() {
    let w = World::new("killed");
    w.init(w.remote.to_str().unwrap());
    for (point, tag) in [
        ("written", "a1a1"),
        ("signed", "b1b1"),
        ("committed", "c1c1"),
        ("pushed", "d1d1"),
    ] {
        let p = Package::new(tag, false);
        let (id, _) = pair(&w, &p, tag);
        let before = (w.head(), w.commits());
        let out = w
            .command(&[
                "publish",
                "--store",
                w.store.to_str().unwrap(),
                "--repo",
                w.remote.to_str().unwrap(),
                &id,
            ])
            .env("TRIGON_PUBLISH_DIE_AT", point)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(137), "{point}: {}", text(&out));
        let after = (w.head(), w.commits());
        match point {
            "pushed" => {
                assert_eq!(after.1, before.1 + 1, "{point}: the push happened");
                assert!(w.run(&id).published.is_none(), "{point}: step 7 did not");
            }
            _ => assert_eq!(after, before, "{point}: the remote is as it was"),
        }
        // The next run resets the working clone and finishes: a new publication, or, after the
        // push, only the run's record of it.
        let said = ok(&w.publish(&[&id]));
        match point {
            "pushed" => {
                assert!(said.contains(&format!("completed run {id}")), "{said}");
                assert_eq!(w.commits(), before.1 + 1, "nothing is logged again");
            }
            _ => assert_eq!(w.commits(), before.1 + 1, "{point}: {said}"),
        }
        assert!(w.run(&id).published.is_some(), "{point}");
    }
    let clone = w.clone_fresh("consumer");
    let repo = w.open(&clone);
    assert_eq!(repo.record_leaves().count(), 4);
    for (_, leaf) in repo.record_leaves() {
        let bytes = repo.read_record(&leaf.record).unwrap().unwrap();
        repo.verify_record(&bytes).unwrap();
    }
}

/// Whoever holds the push credential can commit files into `log/` beyond the checkpoint — here a
/// bundle and a tile at exactly the paths the next publication writes, naming a record of theirs,
/// and a wider partial besides. None of it is signed: the publication overwrites what is at its
/// own paths, never reads past the checkpoint, and the record planted stays unlogged.
#[test]
fn files_planted_in_the_log_beyond_the_checkpoint_are_never_signed() {
    let w = World::new("planted");
    w.init(w.remote.to_str().unwrap());
    let (a, b) = (Package::new("a", false), Package::new("b", false));
    let (first, _) = pair(&w, &a, "aaaa");
    ok(&w.publish(&[&first]));
    let clone = w.clone_fresh("reader");
    let leaf0 = std::fs::read(clone.join("log/tile/entries/000.p/1")).unwrap();
    // A heartbeat every rule of the log allows where it sits — later than the leaf before it — so
    // that only never reading past the checkpoint keeps it out.
    let time = w.open(&clone).newest_time().unwrap();
    let forged = format!(r#"{{"kind":"heartbeat","time":{}}}"#, time + 1).into_bytes();
    let mut bundle = leaf0.clone();
    bundle.extend_from_slice(&(forged.len() as u16).to_be_bytes());
    bundle.extend_from_slice(&forged);
    w.plant(&[
        ("log/tile/entries/000.p/2", Some(&bundle)),
        ("log/tile/0/000.p/2", Some(&[7u8; 64])),
        ("log/tile/entries/000.p/9", Some(b"anything at all")),
        ("records/de/ad/dead.json", Some(b"{}")),
    ]);
    let (second, _) = pair(&w, &b, "bbbb");
    ok(&w.publish(&[&second]));

    let clone = w.clone_fresh("reader");
    let repo = w.open(&clone);
    let log = &repo.source().logs[0].log;
    assert_eq!(log.size(), 2, "the planted leaf is not the log's");
    assert!(
        log.leaves()
            .all(|(_, l)| matches!(l, trigon_attest::log::Leaf::Record(_))),
        "no heartbeat was signed"
    );
    let leaves: Vec<_> = repo.record_leaves().collect();
    assert_eq!(leaves.len(), 2);
    let bytes = repo.read_record(&leaves[1].1.record).unwrap().unwrap();
    let v = repo.verify_record(&bytes).unwrap();
    assert_eq!(v.statement.predicate["run"]["id"], second.as_str());
    // A planted record file is no record: it is unlogged, and fails.
    let e = repo.verify_record(b"{}").unwrap_err();
    assert!(matches!(e, RecordFailure::Unlogged { .. }), "{e}");
    // The wider partial is still there, and read by nothing.
    assert!(clone.join("log/tile/entries/000.p/9").exists());
}

/// Every file under `root`, by path, with its bytes.
fn snapshot(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            let m = std::fs::symlink_metadata(&p).unwrap();
            if m.is_dir() {
                stack.push(p);
            } else {
                out.insert(
                    p.strip_prefix(root).unwrap().display().to_string(),
                    std::fs::read(&p).unwrap_or_default(),
                );
            }
        }
    }
    out
}

#[test]
fn a_dry_run_prints_what_it_would_write_and_leaves_everything_byte_identical() {
    let w = World::new("dry-run");
    w.init(w.remote.to_str().unwrap());
    // A working clone to leave alone.
    ok(&w.publish(&["--heartbeat"]));
    let p = Package::new("a", false);
    let (first, _) = pair(&w, &p, "aaaa");
    let state = state_dir(&w.store);
    // The host's state is the newest checkpoint it has published; its lock names whoever holds it,
    // a dry run as much as any.
    let everything = || {
        (
            snapshot(&w.remote),
            snapshot(&state),
            std::fs::read(newest_published(&w)).unwrap(),
            w.run(&first),
        )
    };
    let before = everything();
    let said = ok(&w.publish(&[&first, "--dry-run"]));
    assert!(
        before == everything(),
        "a dry run changed the repository, the working clone, the host's checkpoint or the run"
    );
    assert!(said.contains("`trigon log sign` is not run"), "{said}");
    assert!(said.contains("write     records/"), "{said}");
    assert!(said.contains("write     evidence/sha256/"), "{said}");
    assert!(said.contains("write     index/sha512/"), "{said}");
    assert!(
        said.contains("write     log/tile/entries/000.p/2"),
        "{said}"
    );
    assert!(said.contains("leaf 1    {\"keyId\""), "{said}");
    assert!(
        said.contains(&format!("checkpoint, unsigned:\n  {ORIGIN}\n  2\n")),
        "{said}"
    );
}

#[test]
fn reconcile_restores_a_deleted_index_file() {
    let w = World::new("reconcile");
    w.init(w.remote.to_str().unwrap());
    let p = Package::new("a", false);
    let (first, _) = pair(&w, &p, "aaaa");
    ok(&w.publish(&[&first]));
    let clone = w.clone_fresh("reader");
    let path = format!(
        "index/sha256/{}/{}/{}.json",
        &p.sha256()[..2],
        &p.sha256()[2..4],
        p.sha256()
    );
    let want = std::fs::read(clone.join(&path)).unwrap();
    w.plant(&[
        (path.as_str(), None),
        (
            "index/sha1/00/00/0000000000000000000000000000000000000000.json",
            Some(b"{}"),
        ),
    ]);
    let said = ok(&w.publish(&["--reconcile"]));
    assert!(said.contains("publish: reconcile index/, tree 1"), "{said}");
    let clone = w.clone_fresh("reader");
    assert_eq!(std::fs::read(clone.join(&path)).unwrap(), want);
    assert!(
        !clone.join("index/sha1/00").exists(),
        "what the log does not imply is removed"
    );
    // Nothing left to reconcile, and nothing committed for it.
    let commits = w.commits();
    let said = ok(&w.publish(&["--reconcile"]));
    assert!(
        said.contains("index/ is already what the log implies"),
        "{said}"
    );
    assert_eq!(w.commits(), commits);
}

#[test]
fn a_withdrawal_of_a_published_record_is_logged_with_its_supersession() {
    let w = World::new("withdrawal");
    w.init(w.remote.to_str().unwrap());
    let p = Package::new("a", false);
    let (first, _) = pair(&w, &p, "aaaa");
    ok(&w.publish(&[&first]));
    let digest = w.run(&first).published.unwrap().record;
    let clone = w.clone_fresh("reader");
    let file = record_file(&clone, &digest);
    let said = ok(&w.trigon(&[
        "attest",
        "--withdraw",
        file.to_str().unwrap(),
        "--reason",
        "withdrawn",
        "--store",
        w.store.to_str().unwrap(),
        "--key",
        w.key.to_str().unwrap(),
    ]));
    let envelope = w.store.join(
        said.lines()
            .find_map(|l| {
                l.trim()
                    .strip_prefix("withdrawals/")
                    .map(|r| format!("withdrawals/{r}"))
            })
            .unwrap_or_else(|| panic!("no withdrawal filed: {said}")),
    );
    ok(&w.publish(&["--withdrawal", envelope.to_str().unwrap()]));

    let clone = w.clone_fresh("reader");
    let repo = w.open(&clone);
    let found = repo.lookup(&Key::Digest {
        algorithm: "sha256",
        hex: p.sha256(),
    });
    assert_eq!(
        found.answer(Match::NormalizedWithCaveats),
        Answer::Withdrawn
    );
    assert_eq!(found.found.len(), 2);
    let by = &found.found[0].superseded_by;
    assert_eq!(by.len(), 1);
    assert_eq!(by[0].reason, trigon_attest::SupersedeReason::Withdrawn);
    // An entry in every index file of the subject's keys.
    for key in ["sha256", "sha512", "sha1"] {
        let dir = clone.join("index").join(key);
        let files = snapshot(&dir);
        assert_eq!(files.len(), 1, "{key}");
        let index: serde_json::Value =
            serde_json::from_slice(files.values().next().unwrap()).unwrap();
        assert_eq!(
            index["records"].as_array().unwrap().len(),
            2,
            "{key}: {index}"
        );
    }
    // Once is enough, and a withdrawal of what the log does not hold is refused.
    let said = refused(&w.publish(&["--withdrawal", envelope.to_str().unwrap()]));
    assert!(said.contains("already logged"), "{said}");
}

#[test]
fn a_heartbeat_is_appended_only_when_one_is_due() {
    let w = World::new("heartbeat");
    w.init(w.remote.to_str().unwrap());
    // A log with no leaves has nothing that says it is alive: one is due.
    ok(&w.publish(&["--heartbeat"]));
    assert_eq!(
        git(&w.remote, &["log", "-1", "--format=%s", "main"]),
        "publish: heartbeat, tree 0 → 1"
    );
    // And then none is, for `[publish] heartbeat`.
    let said = ok(&w.publish(&["--heartbeat"]));
    assert!(said.contains("heartbeat not due"), "{said}");
    assert!(
        said.contains("within `[publish] heartbeat` of 7 days"),
        "{said}"
    );
    assert_eq!(w.commits(), 2);
    let clone = w.clone_fresh("reader");
    assert_eq!(w.open(&clone).source().logs[0].log.size(), 1);
}

/// `docs/19` §2.4: a `file://` URL, a bare repository's path, a working tree's path published into
/// in place, and a relative path, from `--repo`, `TRIGON_PUBLISH_REPO` and `[publish] repo`.
#[test]
fn the_repository_named_each_way_publishes() {
    let w = World::new("each-way");

    // A `file://` URL, from the environment.
    let url = format!("file://{}", w.remote.display());
    w.init(&url);
    let out = w
        .command(&[
            "publish",
            "--store",
            w.store.to_str().unwrap(),
            "--heartbeat",
        ])
        .env("TRIGON_PUBLISH_REPO", &url)
        .output()
        .unwrap();
    ok(&out);
    assert_eq!(w.commits(), 2);

    // Each repository after the first is a log of its own, with an origin and a key of its own:
    // this host has published the first, and its key never begins another.
    git(
        &w.dir,
        &["init", "--quiet", "--bare", "-b", "main", "remote-x.git"],
    );
    let said = refused(&w.init_as(w.dir.join("remote-x.git").to_str().unwrap(), ORIGIN));
    assert!(
        said.contains("this host has published `example.com/trigon-evidence` at 1 leaves"),
        "{said}"
    );

    // A relative path, from `[publish] repo`, taken from the configuration file's directory.
    let rel = PathBuf::from("../../../remote-2.git");
    git(
        &w.dir,
        &["init", "--quiet", "--bare", "-b", "main", "remote-2.git"],
    );
    w.another_log(
        "example.com/evidence-2",
        &format!("repo = \"{}\"\n", rel.display()),
    );
    ok(&w.init_as(
        w.dir.join("remote-2.git").to_str().unwrap(),
        "example.com/evidence-2",
    ));
    ok(&w.trigon(&[
        "publish",
        "--store",
        w.store.to_str().unwrap(),
        "--heartbeat",
    ]));
    assert_eq!(
        git(
            &w.dir.join("remote-2.git"),
            &["rev-list", "--count", "main"]
        ),
        "2"
    );

    // A relative path on the command line, from the working directory.
    git(
        &w.dir,
        &["init", "--quiet", "--bare", "-b", "main", "remote-3.git"],
    );
    w.another_log("example.com/evidence-3", "");
    ok(&w.init_as("../remote-3.git", "example.com/evidence-3"));
    ok(&w.trigon(&[
        "publish",
        "--store",
        w.store.to_str().unwrap(),
        "--repo",
        "../remote-3.git",
        "--heartbeat",
    ]));
    assert_eq!(
        git(
            &w.dir.join("remote-3.git"),
            &["rev-list", "--count", "main"]
        ),
        "2"
    );

    // A working tree, published into in place: the commit is there, and nothing is pushed.
    let tree = w.dir.join("tree");
    git(&w.dir, &["init", "--quiet", "-b", "main", "tree"]);
    let key = w.another_log("example.com/evidence-4", "");
    ok(&w.init_as(tree.to_str().unwrap(), "example.com/evidence-4"));
    ok(&w.trigon(&[
        "publish",
        "--store",
        w.store.to_str().unwrap(),
        "--repo",
        tree.to_str().unwrap(),
        "--heartbeat",
    ]));
    assert_eq!(git(&tree, &["rev-list", "--count", "main"]), "2");
    assert_eq!(git(&tree, &["status", "--porcelain"]), "");
    let vkey = LogSigner::from_file(&key).unwrap().vkey();
    Repository::open(&tree, &vkey, &pinned(), None).unwrap();
    // Refused unless it is clean and on the branch.
    std::fs::write(tree.join("stray"), "x").unwrap();
    let said = refused(&w.trigon(&[
        "publish",
        "--store",
        w.store.to_str().unwrap(),
        "--repo",
        tree.to_str().unwrap(),
        "--reconcile",
    ]));
    assert!(said.contains("uncommitted change"), "{said}");
    std::fs::remove_file(tree.join("stray")).unwrap();
    git(&tree, &["checkout", "--quiet", "-b", "other"]);
    let said = refused(&w.trigon(&[
        "publish",
        "--store",
        w.store.to_str().unwrap(),
        "--repo",
        tree.to_str().unwrap(),
        "--reconcile",
    ]));
    assert!(
        said.contains("it is on `other`, and [publish] branch is `main`"),
        "{said}"
    );
}

#[test]
fn log_keygen_and_init_refuse_to_overwrite_and_init_writes_what_a_log_starts_with() {
    let w = World::new("init");
    // The key: `0600`, Go's format, never over one already there.
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&w.log_key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    let skey = std::fs::read_to_string(&w.log_key).unwrap();
    assert!(
        skey.starts_with(&format!("PRIVATE+KEY+{ORIGIN}+")),
        "{skey}"
    );
    let said = refused(&w.trigon(&[
        "log",
        "keygen",
        "--origin",
        ORIGIN,
        "--out",
        w.log_key.to_str().unwrap(),
    ]));
    assert!(said.contains("Refusing to overwrite a log key"), "{said}");
    let said = refused(&w.trigon(&[
        "log",
        "keygen",
        "--origin",
        "https://example.com/x",
        "--out",
        "k",
    ]));
    assert!(said.contains("has a scheme"), "{said}");

    // The first commit: keys, README, and a checkpoint of size 0 over nothing.
    w.init(w.remote.to_str().unwrap());
    let clone = w.clone_fresh("reader");
    assert_eq!(
        std::fs::read_to_string(clone.join("keys/log.vkey"))
            .unwrap()
            .trim(),
        w.vkey().to_string()
    );
    assert_eq!(
        AttestationKey::from_pem(
            &std::fs::read_to_string(clone.join("keys/attestation.pub")).unwrap()
        )
        .unwrap(),
        pinned()
    );
    let log = w.open(&clone).source().logs[0].log.clone();
    assert_eq!(log.size(), 0);
    assert_eq!(*log.checkpoint().checkpoint(), Checkpoint::empty(ORIGIN));
    let readme = std::fs::read_to_string(clone.join("README.md")).unwrap();
    for says in [
        ORIGIN,
        &w.vkey().to_string(),
        &pinned().to_hex(),
        "once per publication, and at least every 7 days",
        DISPUTES,
    ] {
        assert!(readme.contains(says), "{says}: {readme}");
    }
    assert_eq!(
        git(&w.remote, &["log", "-1", "--format=%s", "main"]),
        format!("log init: {ORIGIN}, tree 0")
    );

    // Once only.
    let key = attestation().public_hex();
    let said = refused(&w.trigon(&[
        "log",
        "init",
        "--origin",
        ORIGIN,
        "--repo",
        w.remote.to_str().unwrap(),
        "--attestation-key",
        &key,
    ]));
    assert!(said.contains("already has log/"), "{said}");
    assert_eq!(w.commits(), 1);

    // `log sign` never begins a log over one, and never signs a tree without a checkpoint of its
    // own key to extend.
    let said = refused(&w.trigon(&[
        "log",
        "sign",
        "--init",
        "--tree",
        clone.to_str().unwrap(),
        "--key",
        w.log_key.to_str().unwrap(),
    ]));
    assert!(said.contains("already there"), "{said}");
    let other = w.dir.join("other.key");
    ok(&w.trigon(&[
        "log",
        "keygen",
        "--origin",
        ORIGIN,
        "--out",
        other.to_str().unwrap(),
    ]));
    let said = refused(&w.trigon(&[
        "log",
        "sign",
        "--tree",
        clone.to_str().unwrap(),
        "--size",
        "0",
        "--key",
        other.to_str().unwrap(),
    ]));
    assert!(said.contains("refusing to sign"), "{said}");
}

/// `publish` never opens the log key: `trigon log sign`, a child process, does, and checks the
/// tree again itself. A key it cannot read, or one that is not the log's, stops the publication at
/// that step, the commit is never made, and the working clone is put back as the remote has it.
#[test]
fn log_sign_is_its_own_step_and_what_it_refuses_is_never_committed() {
    let w = World::new("sign-step");
    w.init(w.remote.to_str().unwrap());
    let p = Package::new("a", false);
    let (first, _) = pair(&w, &p, "aaaa");
    let clone = || state_dir(&w.store).join("clone");

    // Another key under the log's own name: the checkpoint the tree extends does not open under
    // it, so it signs nothing.
    let other = w.dir.join("other.key");
    ok(&w.trigon(&[
        "log",
        "keygen",
        "--origin",
        ORIGIN,
        "--out",
        other.to_str().unwrap(),
    ]));
    let real = w.log_key.clone();
    let with_key = |key: &Path| {
        std::fs::write(
            w.dir.join("home/.config/trigon/evidence.toml"),
            format!(
                "[publish]\norigin = \"{ORIGIN}\"\ndisputes = \"{DISPUTES}\"\nlog_key = \"{}\"\n",
                key.display()
            ),
        )
        .unwrap();
    };
    with_key(&other);
    let said = refused(&w.publish(&[&first]));
    assert!(
        said.contains("`trigon log sign` refused to sign the new checkpoint"),
        "{said}"
    );
    assert!(said.contains("refusing to sign"), "{said}");
    assert_eq!(w.commits(), 1);
    assert_eq!(
        git(
            &clone(),
            &["status", "--porcelain", "--untracked-files=all"]
        ),
        ""
    );
    assert_eq!(git(&clone(), &["rev-parse", "HEAD"]), w.head());
    assert!(w.run(&first).published.is_none());

    // No key at all: the step that reads it says so, and a dry run, which signs nothing, needs
    // none.
    with_key(&w.dir.join("no-such.key"));
    let said = refused(&w.publish(&[&first]));
    assert!(said.contains("could not read the log key"), "{said}");
    ok(&w.publish(&[&first, "--dry-run"]));
    assert_eq!(w.commits(), 1);

    // And `[publish] log_key` unset is refused before anything is read.
    std::fs::write(
        w.dir.join("home/.config/trigon/evidence.toml"),
        format!("[publish]\norigin = \"{ORIGIN}\"\ndisputes = \"{DISPUTES}\"\n"),
    )
    .unwrap();
    let said = refused(&w.publish(&[&first]));
    assert!(said.contains("`[publish] log_key` is not set"), "{said}");

    with_key(&real);
    ok(&w.publish(&[&first]));
    assert_eq!(w.commits(), 2);
}

/// The newest checkpoint of the log this host has published, where it keeps it: under the host's
/// state directory, named by the log's origin.
fn newest_published(w: &World) -> PathBuf {
    let dir = w.dir.join("home/.local/state/trigon/publish");
    let hash = trigon_attest::Record::digest_of(ORIGIN.as_bytes()).to_hex();
    dir.join(format!("{hash}.checkpoint"))
}

/// Step 1, and step 5 on its own: a remote whose log does not extend the newest checkpoint this
/// host has published — rolled back by whoever can push, here to its first commit — is refused,
/// and nothing is built on it. From any store, however the repository is named, since what caught
/// it is kept by the log and not by the store or the spelling; and `trigon log sign`, handed a
/// tree built on the rolled-back log, refuses it too, so the log key never signs a second root for
/// a size it has published.
#[test]
fn a_remote_rolled_back_behind_what_this_host_published_is_refused() {
    let w = World::new("rollback");
    w.init(w.remote.to_str().unwrap());
    let first = w.head();
    ok(&w.publish(&["--heartbeat"]));
    assert_eq!(w.commits(), 2);
    let state = newest_published(&w);
    let kept = std::fs::read_to_string(&state).unwrap();
    assert!(kept.starts_with(&format!("{ORIGIN}\n1\n")), "{kept}");

    // What a force-push that the ruleset should have refused would leave.
    git(&w.remote, &["update-ref", "refs/heads/main", &first]);
    let refusal = |said: &str| {
        assert!(
            said.contains(
                "does not extend the newest checkpoint of `example.com/trigon-evidence` this \
                 host has published or verified"
            ),
            "{said}"
        );
        assert!(
            said.contains("fewer than the 1 of the checkpoint last accepted"),
            "{said}"
        );
    };
    refusal(&refused(&w.publish(&["--heartbeat"])));
    // The same repository named another way, and from a store that has never published.
    let url = format!("file://{}", w.remote.display());
    refusal(&refused(&w.trigon(&[
        "publish",
        "--store",
        w.store.to_str().unwrap(),
        "--repo",
        &url,
        "--heartbeat",
    ])));
    let fresh = w.dir.join("fresh-store");
    Store::local(&fresh).unwrap();
    refusal(&refused(&w.publish_from(&fresh, &["--heartbeat"])));
    assert_eq!(w.head(), first, "nothing is built on it");
    assert_eq!(std::fs::read_to_string(&state).unwrap(), kept);

    // `log sign` itself, handed a tree built on the rolled-back log — a heartbeat after the
    // checkpoint of 0, as a publisher with no memory of its own would build it, logged later than
    // the one published, so that it is another leaf and another root.
    let tree = w.clone_fresh("rolled-back");
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let append = w.open(&tree).source().logs[0]
        .log
        .plan_append(&[trigon_attest::log::Leaf::Heartbeat(
            trigon_attest::log::HeartbeatLeaf { time },
        )])
        .unwrap();
    for (path, bytes) in &append.files {
        let p = tree.join("log").join(path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }
    let sign = |state_home: &Path| {
        w.command(&[
            "log",
            "sign",
            "--tree",
            tree.to_str().unwrap(),
            "--size",
            "1",
            "--key",
            w.log_key.to_str().unwrap(),
        ])
        .env("XDG_STATE_HOME", state_home)
        .output()
        .unwrap()
    };
    let said = refused(&sign(&w.dir.join("home/.local/state")));
    assert!(said.contains("refusing to sign"), "{said}");
    assert!(
        said.contains("the first 1 leaves of the tree offered hash to"),
        "{said}"
    );
    let signed = std::fs::read(tree.join("log/checkpoint")).unwrap();
    assert!(signed.starts_with(format!("{ORIGIN}\n0\n").as_bytes()));
    // It is that memory, and nothing else about the tree, that refuses it: a host with none signs.
    ok(&sign(&w.dir.join("elsewhere")));
}

// ---------------------------------------------------------------------------------------------
// What git is told, and what it is not let do
// ---------------------------------------------------------------------------------------------

/// Whoever can push can commit a `.gitignore` — a hosting template may begin the branch with one
/// — and an operator's own excludes follow every repository they touch. Neither keeps a tile, a
/// bundle, a record, its evidence or an index file out of the commit `log sign` checked, nor the
/// checkpoint out of `log init`'s; and a working tree whose git directory ignores them is published
/// into whole.
#[test]
fn what_a_publication_writes_is_committed_whatever_git_is_told_to_ignore() {
    let w = World::new("ignored");
    let ignore: &[u8] = b"log/\nkeys/\ntile/\nrecords/\nevidence/\nindex/\n*.json\ncheckpoint\n";
    seeded(&w.remote, &[(".gitignore", ignore)]);
    std::fs::write(w.dir.join("operator-ignore"), ignore).unwrap();
    w.gitconfig(&format!(
        "[core]\n\texcludesFile = {}\n",
        w.dir.join("operator-ignore").display()
    ));
    w.init(w.remote.to_str().unwrap());
    assert_eq!(
        w.open(&w.clone_fresh("reader")).source().logs[0].log.size(),
        0
    );

    let (a, b) = (Package::new("a", false), Package::new("b", false));
    let (first, _) = pair(&w, &a, "aaaa");
    ok(&w.publish(&[&first]));
    let (second, _) = pair(&w, &b, "bbbb");
    ok(&w.publish(&[&second]));

    let clone = w.clone_fresh("reader");
    let repo = w.open(&clone);
    assert_eq!(repo.record_leaves().count(), 2);
    for (_, leaf) in repo.record_leaves() {
        let bytes = repo.read_record(&leaf.record).unwrap().unwrap();
        let v = repo.verify_record(&bytes).unwrap();
        assert!(v.unchecked().all(|e| e.name == "rebuiltArtifact"));
    }
    for p in [&a, &b] {
        let index = format!(
            "index/sha256/{}/{}/{}.json",
            &p.sha256()[..2],
            &p.sha256()[2..4],
            p.sha256()
        );
        assert!(clone.join(&index).is_file(), "{index}");
    }

    // A working tree whose own excludes name the directories a publication writes.
    let tree = w.dir.join("tree");
    git(&w.dir, &["init", "--quiet", "-b", "main", "tree"]);
    std::fs::write(tree.join(".git/info/exclude"), ignore).unwrap();
    let key = w.another_log("example.com/evidence-2", "");
    ok(&w.init_as(tree.to_str().unwrap(), "example.com/evidence-2"));
    let c = Package::new("c", false);
    let (third, _) = pair(&w, &c, "cccc");
    let publish = || {
        w.trigon(&[
            "publish",
            "--store",
            w.store.to_str().unwrap(),
            "--repo",
            tree.to_str().unwrap(),
            &third,
        ])
    };
    // A file it ignores where a publication reads would be read and never committed: refused.
    std::fs::create_dir_all(tree.join("records/00/00")).unwrap();
    std::fs::write(tree.join("records/00/00/stray.json"), "{}").unwrap();
    let said = refused(&publish());
    assert!(said.contains("file(s) git ignores under"), "{said}");
    std::fs::remove_dir_all(tree.join("records")).unwrap();
    // A publication that fails is discarded whole, what it wrote where the tree ignores included.
    let real = std::fs::read_to_string(w.dir.join("home/.config/trigon/evidence.toml")).unwrap();
    std::fs::write(
        w.dir.join("home/.config/trigon/evidence.toml"),
        real.replace(key.to_str().unwrap(), w.log_key.to_str().unwrap()),
    )
    .unwrap();
    let said = refused(&publish());
    assert!(said.contains("refused to sign"), "{said}");
    assert_eq!(
        git(
            &tree,
            &[
                "status",
                "--porcelain",
                "--ignored",
                "--untracked-files=all"
            ]
        ),
        ""
    );
    std::fs::write(w.dir.join("home/.config/trigon/evidence.toml"), real).unwrap();
    ok(&publish());
    assert_eq!(
        git(
            &tree,
            &[
                "status",
                "--porcelain",
                "--ignored",
                "--untracked-files=all"
            ]
        ),
        "",
        "everything written is committed"
    );
    let vkey = LogSigner::from_file(&key).unwrap().vkey();
    let repo = Repository::open(&tree, &vkey, &pinned(), None).unwrap();
    let (_, leaf) = repo.record_leaves().next().unwrap();
    let file = trigon_attest::evidence::record_path(&leaf.record);
    assert_eq!(git(&tree, &["ls-tree", "--name-only", "HEAD", &file]), file);
}

/// A `.gitattributes` can name a filter the operator's configuration defines, or a line-end
/// conversion, and `git` runs it on every checkout: the files a publication reads would not be the
/// blobs every client clones. A branch that names attributes is refused before it is checked out,
/// so no such filter ever runs, and nothing is written; so is one `log init` would begin a log on.
#[test]
fn a_branch_that_names_git_attributes_is_refused_before_it_is_checked_out() {
    let w = World::new("attributes");
    w.init(w.remote.to_str().unwrap());
    // A working clone, checked out, for the next fetch to find the attributes in.
    ok(&w.publish(&["--heartbeat"]));
    let marker = w.dir.join("the-filter-ran");
    w.gitconfig(&format!(
        "[filter \"evil\"]\n\tsmudge = sh -c 'touch {}; cat'\n\tclean = cat\n",
        marker.display()
    ));
    w.plant(&[("log/.gitattributes", Some(b"* filter=evil\n"))]);
    let before = w.head();
    for args in [&["--reconcile"][..], &["--reconcile", "--dry-run"]] {
        let said = refused(&w.publish(args));
        assert!(said.contains("it has `log/.gitattributes`"), "{said}");
    }
    assert!(!marker.exists(), "the filter ran");
    assert_eq!(w.head(), before);

    // A branch a log is to be begun on, with attributes of its own.
    let other = w.dir.join("other.git");
    seeded(&other, &[(".gitattributes", b"* text eol=crlf\n")]);
    w.another_log("example.com/evidence-2", "");
    let said = refused(&w.init_as(other.to_str().unwrap(), "example.com/evidence-2"));
    assert!(said.contains("it has `.gitattributes`"), "{said}");
    assert_eq!(git(&other, &["rev-list", "--count", "main"]), "1");
}

/// `publish` keeps the operator's git configuration, for the credential helper that lives there.
/// Nothing else in it changes what is committed or how: commit and push signing, which would sign
/// a public commit with the operator's own key or wait on a passphrase; `core.autocrlf`, which
/// rewrites line ends on checkout; and the operator's attributes and excludes, which name filters,
/// conversions and paths to skip.
#[test]
fn the_operators_git_configuration_changes_nothing_that_is_committed() {
    let w = World::new("operator-config");
    let stub = w.dir.join("gpg-stub");
    let called = w.dir.join("gpg-called");
    let marker = w.dir.join("the-filter-ran");
    std::fs::write(
        &stub,
        format!("#!/bin/sh\necho \"$@\" >> '{}'\nexit 1\n", called.display()),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::fs::write(
        w.dir.join("operator-attributes"),
        "* text eol=crlf filter=evil\n",
    )
    .unwrap();
    std::fs::write(
        w.dir.join("operator-ignore"),
        "log/\nrecords/\nindex/\nevidence/\nkeys/\n",
    )
    .unwrap();
    w.gitconfig(&format!(
        "[user]\n\tsigningkey = OPERATOR-KEY\n[commit]\n\tgpgsign = true\n[push]\n\tgpgSign = \
         true\n[gpg]\n\tprogram = {}\n[core]\n\tautocrlf = true\n\tattributesFile = {}\n\t\
         excludesFile = {}\n[filter \"evil\"]\n\tclean = sh -c 'touch {m}; tr a b'\n\tsmudge = \
         sh -c 'touch {m}; tr a b'\n",
        stub.display(),
        w.dir.join("operator-attributes").display(),
        w.dir.join("operator-ignore").display(),
        m = marker.display()
    ));
    w.init(w.remote.to_str().unwrap());
    let (a, b) = (Package::new("a", false), Package::new("b", false));
    let (first, _) = pair(&w, &a, "aaaa");
    ok(&w.publish(&[&first]));
    // The second is built on the working clone as checked out: its files are the blobs.
    let (second, _) = pair(&w, &b, "bbbb");
    ok(&w.publish(&[&second]));
    let working = state_dir(&w.store).join("clone");
    assert_eq!(
        git(
            &working,
            &["status", "--porcelain", "--untracked-files=all"]
        ),
        ""
    );

    assert!(!called.exists(), "gpg was asked to sign");
    assert!(!marker.exists(), "the operator's filter ran");
    assert_eq!(
        git(&w.remote, &["log", "--format=%G?", "main"]),
        "N\nN\nN",
        "a commit is signed"
    );
    let clone = w.clone_fresh("reader");
    let repo = w.open(&clone);
    assert_eq!(repo.record_leaves().count(), 2);
    for (_, leaf) in repo.record_leaves() {
        let bytes = repo.read_record(&leaf.record).unwrap().unwrap();
        repo.verify_record(&bytes).unwrap();
    }
}

/// A store is often kept inside a checkout, as `./trigon-store` usually is. A working clone whose
/// `.git` is gone — a backup that skipped it, a kill mid-clone — is made again, and the checkout
/// around the store is never taken for it: its remote, its branch and its uncommitted work are
/// left exactly as they were.
#[test]
fn a_working_clone_without_its_git_directory_is_made_again_and_never_the_checkout_around_it() {
    let w = World::new("enclosed");
    w.init(w.remote.to_str().unwrap());
    let project = w.dir.join("checkout");
    git(&w.dir, &["init", "--quiet", "-b", "main", "checkout"]);
    git(
        &project,
        &[
            "remote",
            "add",
            "origin",
            "https://example.org/me/project.git",
        ],
    );
    std::fs::write(project.join(".gitignore"), "trigon-store/\n").unwrap();
    std::fs::write(project.join("src.txt"), "one\n").unwrap();
    git(&project, &["add", "--all"]);
    git(&project, &["commit", "--quiet", "-m", "project"]);
    let head = git(&project, &["rev-parse", "HEAD"]);
    let store = project.join("trigon-store");
    Store::local(&store).unwrap();
    ok(&w.publish_from(&store, &["--heartbeat"]));

    let clone = state_dir(&store).join("clone");
    std::fs::remove_dir_all(clone.join(".git")).unwrap();
    std::fs::write(project.join("src.txt"), "one\nuncommitted\n").unwrap();
    let said = ok(&w.publish_from(&store, &["--heartbeat"]));
    assert!(said.contains("heartbeat not due"), "{said}");

    assert_eq!(
        git(&project, &["remote", "get-url", "origin"]),
        "https://example.org/me/project.git"
    );
    assert_eq!(git(&project, &["rev-parse", "HEAD"]), head);
    assert_eq!(
        std::fs::read_to_string(project.join("src.txt")).unwrap(),
        "one\nuncommitted\n"
    );
    assert!(!project.join("keys").exists() && !project.join("log").exists());
    assert!(
        clone.join(".git").is_dir(),
        "the working clone is made again"
    );
    assert_eq!(git(&clone, &["rev-parse", "HEAD"]), w.head());
}

/// One `publish` at a time on a host, whatever store it runs from: two would build on the same log
/// and race to push. A second, from another store, started while the first holds the host's lock,
/// is refused, names the first, and waits for nothing; the first publishes.
#[test]
fn one_publish_runs_at_a_time_on_a_host_whatever_store_it_runs_from() {
    let w = World::new("host-lock");
    w.init(w.remote.to_str().unwrap());
    let p = Package::new("a", false);
    let (first, _) = pair(&w, &p, "aaaa");
    ok(&w.publish(&["--heartbeat"]));
    let other = w.dir.join("store-b");
    Store::local(&other).unwrap();
    // The second starts in the moment between the first's commit and its push, by a hook in the
    // first's working clone, with the first's environment — the same host.
    let hook = state_dir(&w.store).join("clone/.git/hooks/post-commit");
    std::fs::write(
        &hook,
        format!(
            "#!/bin/sh\nrm -f \"$0\"\n\
             exec '{}' publish --heartbeat --store '{}' --repo '{}' >'{}' 2>&1\n",
            bin(),
            other.display(),
            w.remote.display(),
            w.dir.join("b.log").display()
        ),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let said = ok(&w.publish(&[&first]));
    assert!(!said.contains("lost"), "{said}");
    let b_said = std::fs::read_to_string(w.dir.join("b.log")).unwrap();
    assert!(
        b_said.contains("another `trigon publish` holds"),
        "{b_said}"
    );
    assert!(
        b_said.contains(&format!("from {}", w.store.display())),
        "the holder is named: {b_said}"
    );
    assert_eq!(w.commits(), 3);
}

/// A push the remote took, whose answer was lost with the connection, is a publication, not a lost
/// race: the remote's branch is at the commit just pushed. The run is recorded as published, and
/// nothing is discarded or built again.
#[test]
fn a_push_the_remote_took_is_published_even_when_the_connection_goes_before_it_answers() {
    let w = World::new("push-answer");
    w.init(w.remote.to_str().unwrap());
    let p = Package::new("a", false);
    let (first, _) = pair(&w, &p, "aaaa");
    // Once the remote has updated the branch, its end of the connection goes before it says so.
    let hook = w.remote.join("hooks/reference-transaction");
    std::fs::write(
        &hook,
        "#!/bin/sh\nif [ \"$1\" = committed ]; then rm -f \"$0\"; kill -9 $PPID; fi\n",
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let said = ok(&w.publish(&[&first]));
    assert!(!hook.exists(), "the push reached the remote");
    assert!(!said.contains("lost"), "{said}");
    assert_eq!(w.commits(), 2);
    let published = w.run(&first).published.expect("the run is published");
    assert_eq!(published.commit, w.head());
}

/// `index` planted as a link to a directory of the host's is refused before anything is read
/// through it: `--reconcile` lists nothing of the host's, even in a dry run, and removes nothing.
#[test]
fn reconcile_never_reads_through_a_link_planted_as_index() {
    let w = World::new("index-link");
    w.init(w.remote.to_str().unwrap());
    let p = Package::new("a", false);
    let (first, _) = pair(&w, &p, "aaaa");
    ok(&w.publish(&[&first]));
    let host = w.dir.join("host-dir");
    std::fs::create_dir_all(host.join("sub")).unwrap();
    std::fs::write(host.join("sub/private.txt"), "the host's").unwrap();
    let c = w.clone_fresh("planter");
    git(&c, &["rm", "-r", "--quiet", "index"]);
    std::os::unix::fs::symlink(&host, c.join("index")).unwrap();
    git(&c, &["add", "index"]);
    git(&c, &["commit", "--quiet", "-m", "planted"]);
    git(&c, &["push", "--quiet", "origin", "main"]);
    for args in [&["--reconcile", "--dry-run"][..], &["--reconcile"]] {
        let said = refused(&w.publish(args));
        assert!(!said.contains("private.txt"), "{said}");
        assert!(
            said.contains("`index`") && said.contains("is a link or a file"),
            "{said}"
        );
    }
    assert!(host.join("sub/private.txt").exists());
}

/// A run whose record the log holds, completed after whoever can push removed its record file, is
/// recorded with the commit that logged it — found from the log's own history — and said to be
/// missing: never recorded as whatever commit the branch is at now.
#[test]
fn a_run_completed_after_its_record_file_was_removed_names_the_commit_that_logged_it() {
    let w = World::new("completion");
    w.init(w.remote.to_str().unwrap());
    let p = Package::new("a", false);
    let (first, _) = pair(&w, &p, "aaaa");
    let out = w
        .command(&[
            "publish",
            "--store",
            w.store.to_str().unwrap(),
            "--repo",
            w.remote.to_str().unwrap(),
            &first,
        ])
        .env("TRIGON_PUBLISH_DIE_AT", "pushed")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(137), "{}", text(&out));
    let logged = w.head();
    let clone = w.clone_fresh("reader");
    let records = snapshot(&clone.join("records"));
    assert_eq!(records.len(), 1);
    let file = format!("records/{}", records.keys().next().unwrap());
    w.plant(&[(file.as_str(), None)]);
    assert_ne!(w.head(), logged);

    let said = ok(&w.publish(&[&first]));
    assert!(said.contains(&format!("completed run {first}")), "{said}");
    assert!(
        said.contains(&format!(
            "has no `{file}`: every client reports it as deleted"
        )),
        "{said}"
    );
    assert_eq!(w.run(&first).published.unwrap().commit, logged);
}
