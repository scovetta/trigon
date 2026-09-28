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
    /// `TRIGON_*`, nor any GitHub token it holds: a test that talks to "GitHub" names the server
    /// it runs itself. `git` may reach nothing but files, so a location spelled as a GitHub URL
    /// reaches the network only if it is not rewritten to a local repository, and then fails.
    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(bin());
        c.current_dir(self.dir.join("project"))
            .env("HOME", self.dir.join("home"))
            .env("XDG_CONFIG_HOME", self.dir.join("home/.config"))
            .env("XDG_STATE_HOME", self.dir.join("home/.local/state"))
            .env("XDG_CACHE_HOME", self.dir.join("home/.cache"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_ALLOW_PROTOCOL", "file")
            .env_remove("GITHUB_TOKEN")
            .env_remove("GH_TOKEN");
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

// ---------------------------------------------------------------------------------------------
// Rotation: `trigon log key-change` and `trigon log succeed` (docs/19 §8)
// ---------------------------------------------------------------------------------------------

/// The successor every succession here names.
const SUCCESSOR: &str = "example.com/trigon-evidence/1";

/// The attestation key a key change here hands over to.
fn rotated() -> LocalKey {
    LocalKey::from_bytes(&[4; 32]).unwrap()
}

impl World {
    /// `evidence.toml` naming `origin` and the log key at `key`, with `extra` after: the
    /// configuration the operator switches to after a succession.
    fn configure(&self, origin: &str, key: &Path, extra: &str) {
        std::fs::write(
            self.dir.join("home/.config/trigon/evidence.toml"),
            format!(
                "[publish]\norigin = \"{origin}\"\ndisputes = \"{DISPUTES}\"\n\
                 log_key = \"{}\"\n{extra}",
                key.display()
            ),
        )
        .unwrap();
    }

    /// A key file of `key`, as `trigon keygen` writes one, named `name`.
    fn key_file(&self, name: &str, key: &LocalKey) -> PathBuf {
        let path = self.dir.join(name);
        let seed: String = key.seed().iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(&path, format!("{seed}\n")).unwrap();
        path
    }

    /// A log key for the log `origin`, made by `trigon log keygen`.
    fn log_key_for(&self, origin: &str, name: &str) -> PathBuf {
        let path = self.dir.join(name);
        ok(&self.trigon(&[
            "log",
            "keygen",
            "--origin",
            origin,
            "--out",
            path.to_str().unwrap(),
        ]));
        path
    }

    /// `trigon log <sub> <args>` against the bare repository, from this world's store.
    fn log_command(&self, sub: &str, args: &[&str]) -> Output {
        let mut all = vec![
            "log",
            sub,
            "--store",
            self.store.to_str().unwrap(),
            "--repo",
            self.remote.to_str().unwrap(),
        ];
        all.extend_from_slice(args);
        self.trigon(&all)
    }

    /// A `[[source]]` for the chain this world's repository begins, from its first log's key and
    /// the attestation key it starts at, named `chain`: how a publisher into a successor elsewhere
    /// reads the logs before it.
    fn chain_source(&self) -> String {
        format!(
            "\n[[source]]\nname = \"chain\"\nurls = [\"{}\"]\nlog_key = \"{}\"\n\
             attestation_key = \"{}\"\n",
            self.remote.display(),
            self.vkey(),
            attestation().public_hex()
        )
    }

    /// `trigon verify-attestation --record` of `record` from the clone at `clone`, pinned to the
    /// first log's key and the attestation key every chain here starts at, as a client pins them.
    fn verify_record(&self, clone: &Path, record: &trigon_core::Digest) -> Output {
        let file = record_file(clone, record);
        self.trigon(&[
            "verify-attestation",
            "--record",
            file.to_str().unwrap(),
            "--evidence",
            clone.to_str().unwrap(),
            "--log-vkey",
            &self.vkey().to_string(),
            "--attestation-key",
            &attestation().public_hex(),
        ])
    }
}

/// `trigon log key-change` logs a leaf signed by the current attestation key and the new one; a
/// fresh verification follows it from the key it pinned, records published before it still verify,
/// and from then on `publish` publishes only what the new key signed.
#[test]
fn a_key_change_is_followed_and_publish_then_expects_the_new_key() {
    let w = World::new("key-change");
    w.init(w.remote.to_str().unwrap());
    let pa = Package::new("a", false);
    let (a, _) = pair(&w, &pa, "aaaa");
    ok(&w.publish(&[&a]));
    let new = w.key_file("signing-2.key", &rotated());
    let new_s = new.to_str().unwrap();
    let third = w.key_file("signing-3.key", &LocalKey::from_bytes(&[5; 32]).unwrap());

    // Only the key current now can hand over, and to another key.
    let said = refused(&w.log_command(
        "key-change",
        &["--key", new_s, "--new-key", third.to_str().unwrap()],
    ));
    assert!(said.contains("--key is the key"), "{said}");
    let said = refused(&w.log_command(
        "key-change",
        &[
            "--key",
            w.key.to_str().unwrap(),
            "--new-key",
            w.key.to_str().unwrap(),
        ],
    ));
    assert!(said.contains("--key and --new-key are one key"), "{said}");
    assert!(!said.contains("evidence source"), "{said}");
    assert_eq!(w.commits(), 2);

    // A dry run signs nothing: the leaf is shown with both signatures empty — a signed one left in
    // a CI log would be a hand-over anyone holding the log key could append — the files it would
    // write by path, and the checkpoint by size; and it refuses what the real run refuses.
    let before = w.head();
    let dry = |key: &str, new: &str| {
        w.log_command("key-change", &["--key", key, "--new-key", new, "--dry-run"])
    };
    let said = ok(&dry(w.key.to_str().unwrap(), new_s));
    let line = said
        .lines()
        .find_map(|l| l.strip_prefix("leaf 1"))
        .unwrap_or_else(|| panic!("{said}"));
    let leaf: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(leaf["kind"], "key-change");
    assert_eq!(leaf["old"]["publicKey"], attestation().public_hex());
    assert_eq!(leaf["new"]["publicKey"], rotated().public_hex());
    assert_eq!(
        (&leaf["old"]["signature"], &leaf["new"]["signature"]),
        (&"".into(), &"".into())
    );
    assert!(said.contains("write     log/tile/entries/"), "{said}");
    assert!(said.contains("write     README.md"), "{said}");
    assert!(said.contains("which a dry run does not make"), "{said}");
    let said = refused(&dry(new_s, third.to_str().unwrap()));
    assert!(said.contains("--key is the key"), "{said}");
    let said = refused(&dry(new_s, new_s));
    assert!(said.contains("--key and --new-key are one key"), "{said}");
    assert_eq!(w.head(), before);

    let said = ok(&w.log_command(
        "key-change",
        &["--key", w.key.to_str().unwrap(), "--new-key", new_s],
    ));
    assert!(said.contains("logged    leaf 1: key change"), "{said}");
    // It says how the operator switches.
    assert!(
        said.contains("trigon attest <run> --key <new key file>"),
        "{said}"
    );
    assert_eq!(w.commits(), 3);
    assert_eq!(
        git(&w.remote, &["log", "-1", "--format=%s", "main"]),
        "publish: key change, tree 1 → 2"
    );

    // A fresh clone, verified from the keys a client pinned: the change is followed, and the record
    // published under the old key still verifies, by the reader's code and by the verifier.
    let clone = w.clone_fresh("consumer");
    let repo = w.open(&clone);
    assert_eq!(
        repo.keys().current(),
        &AttestationKey::from(rotated().public_key())
    );
    let first = w.run(&a).published.unwrap().record;
    let bytes = repo.read_record(&first).unwrap().unwrap();
    repo.verify_record(&bytes).unwrap();
    ok(&w.verify_record(&clone, &first));
    let readme = std::fs::read_to_string(clone.join("README.md")).unwrap();
    assert!(readme.contains("## Key changes and successors"), "{readme}");
    assert!(readme.contains(&rotated().public_hex()), "{readme}");
    // `keys/attestation.pub` stays the key the chain starts at.
    assert_eq!(
        AttestationKey::from_pem(
            &std::fs::read_to_string(clone.join("keys/attestation.pub")).unwrap()
        )
        .unwrap(),
        pinned()
    );

    // Signed with the old key: refused, with the key it needs.
    let pb = Package::new("b", false);
    let (b, _) = pair(&w, &pb, "bbbb");
    let said = refused(&w.publish(&[&b]));
    assert!(
        said.contains(&format!(
            "the repository's attestation key is {} since the key change at leaf 1",
            AttestationKey::from(rotated().public_key()).key_id()
        )),
        "{said}"
    );
    // Attested again with the new key, it publishes, and verifies from the old pin.
    ok(&w.trigon(&[
        "attest",
        &b,
        "--store",
        w.store.to_str().unwrap(),
        "--key",
        new_s,
    ]));
    ok(&w.publish(&[&b]));
    let clone = w.clone_fresh("consumer");
    let second = w.run(&b).published.unwrap().record;
    let repo = w.open(&clone);
    let v = repo
        .verify_record(&repo.read_record(&second).unwrap().unwrap())
        .unwrap();
    assert_eq!(v.key, AttestationKey::from(rotated().public_key()));
    ok(&w.verify_record(&clone, &second));

    // A key the log has retired is never current again.
    let said = refused(&w.log_command(
        "key-change",
        &["--key", new_s, "--new-key", w.key.to_str().unwrap()],
    ));
    assert!(said.contains("never current again"), "{said}");
}

/// `trigon log succeed` ends the log with a log-end naming the successor and begins the successor
/// with its log-continuation, in one commit; a fresh verification follows the pair from the first
/// log's key, the verifier checks records on either side of it, and `publish` goes on into the
/// successor once the operator switches to it — and only then.
#[test]
fn a_succession_is_followed_and_publish_continues_into_the_successor() {
    let w = World::new("succeed");
    w.init(w.remote.to_str().unwrap());
    let pa = Package::new("a", false);
    let (a, _) = pair(&w, &pa, "aaaa");
    ok(&w.publish(&[&a]));
    let next = w.log_key_for(SUCCESSOR, "successor.key");
    let next_s = next.to_str().unwrap();

    // A key named for another log is refused.
    let said = refused(&w.log_command(
        "succeed",
        &["--origin", "example.com/elsewhere", "--log-key", next_s],
    ));
    assert!(
        said.contains("a log key's name is its log's origin"),
        "{said}"
    );
    // Nor is a successor begun where no log-end can name it.
    let said = refused(&w.log_command(
        "succeed",
        &["--origin", SUCCESSOR, "--log-key", next_s, "--dir", "log"],
    ));
    assert!(said.contains("is not where a successor can be"), "{said}");
    // A dry run writes nothing, and says what begins the successor.
    let before = w.head();
    let said = ok(&w.log_command(
        "succeed",
        &["--origin", SUCCESSOR, "--log-key", next_s, "--dry-run"],
    ));
    assert!(said.contains("\"kind\":\"log-end\""), "{said}");
    assert!(
        said.contains("begin     `example.com/trigon-evidence/1` at log/1"),
        "{said}"
    );
    assert_eq!(w.head(), before);

    let said = ok(&w.log_command("succeed", &["--origin", SUCCESSOR, "--log-key", next_s]));
    assert!(said.contains("logged    leaf 1: log-end"), "{said}");
    assert!(
        said.contains("set `origin = \"example.com/trigon-evidence/1\"`"),
        "{said}"
    );
    assert_eq!(w.commits(), 3, "one commit");
    let message = git(&w.remote, &["log", "-1", "--format=%s", "main"]);
    assert!(message.starts_with("log succeed: "), "{message}");

    // A fresh clone, verified from the first log's key: the chain is followed into `log/1`, whose
    // first leaf holds the old log's final checkpoint, signed by both keys.
    let clone = w.clone_fresh("consumer");
    let repo = w.open(&clone);
    let logs = &repo.source().logs;
    assert_eq!(logs.len(), 2);
    assert_eq!(logs[1].dir, "log/1");
    assert_eq!(logs[1].log.origin(), SUCCESSOR);
    assert_eq!(logs[1].log.size(), 1);
    let last = std::fs::read(clone.join("log/checkpoint")).unwrap();
    let note = SignedNote::parse(&last).unwrap();
    note.verify(&w.vkey()).unwrap();
    note.verify(&LogSigner::from_file(&next).unwrap().vkey())
        .unwrap();
    let first = w.run(&a).published.unwrap().record;
    ok(&w.verify_record(&clone, &first));

    // Publishing under the old configuration is refused, and says where it goes on.
    let pb = Package::new("b", false);
    let (b, _) = pair(&w, &pb, "bbbb");
    let said = refused(&w.publish(&[&b]));
    assert!(
        said.contains("has ended, and its successor `example.com/trigon-evidence/1` is at `log/1`"),
        "{said}"
    );
    // Switched to the successor, and attested again under its origin, a run publishes into it.
    w.configure(SUCCESSOR, &next, "");
    let said = refused(&w.publish(&[&b]));
    assert!(
        said.contains("its falsifying command names the log"),
        "{said}"
    );
    w.attest(&b, &[]);
    let said = ok(&w.publish(&[&b]));
    assert!(
        said.contains("logged    leaf 1: run 1789000000-bbbb0001"),
        "{said}"
    );
    let published = w.run(&b).published.unwrap();
    assert_eq!(published.leaf, 1);
    assert_eq!(published.log.as_deref(), Some("log/1"));

    // And a client from the first log's key finds it there, and the verifier checks it.
    let clone = w.clone_fresh("consumer");
    let repo = w.open(&clone);
    let found = repo.lookup(&Key::Digest {
        algorithm: "sha256",
        hex: pb.sha256(),
    });
    let current: Vec<_> = found.current().collect();
    assert_eq!(current.len(), 1);
    assert_eq!(
        current[0].pos,
        trigon_attest::log::LeafPos { log: 1, index: 1 }
    );
    ok(&w.verify_record(&clone, &published.record));
    // The successor is begun once.
    let other = w.log_key_for("example.com/trigon-evidence/2", "successor-2.key");
    let said = refused(&w.log_command(
        "succeed",
        &["--origin", SUCCESSOR, "--log-key", other.to_str().unwrap()],
    ));
    assert!(
        said.contains("a log key's name is its log's origin"),
        "{said}"
    );
}

/// A successor the old log's log-end does not name is refused: planted in its place by whoever can
/// push, it fails every client's verification, and `log sign` begins no log its predecessor does
/// not name.
#[test]
fn a_successor_the_log_end_does_not_name_is_refused() {
    let w = World::new("unnamed-successor");
    w.init(w.remote.to_str().unwrap());
    let pa = Package::new("a", false);
    let (a, _) = pair(&w, &pa, "aaaa");
    ok(&w.publish(&[&a]));
    let next = w.log_key_for(SUCCESSOR, "successor.key");
    ok(&w.log_command(
        "succeed",
        &["--origin", SUCCESSOR, "--log-key", next.to_str().unwrap()],
    ));
    let tree = w.clone_fresh("tree");

    // `log/1` replaced with a log under another key of the successor's name, continuing the same
    // final checkpoint and cosigned by that key.
    let impostor = LogSigner::from_seed(SUCCESSOR, [9; 32]).unwrap();
    let clone = w.clone_fresh("planter");
    let last = std::fs::read(clone.join("log/checkpoint")).unwrap();
    let cosigned = SignedNote::parse(&last)
        .unwrap()
        .cosign(&impostor)
        .unwrap()
        .to_string();
    let end_time = w.open(&clone).source().logs[0].log.newest_time().unwrap();
    let leaf = trigon_attest::log::Leaf::LogContinuation(trigon_attest::log::LogContinuationLeaf {
        time: end_time,
        checkpoint: cosigned,
    });
    let append = trigon_attest::log::plan_append(
        &trigon_attest::log::Tree::new(),
        &[] as &[Vec<u8>],
        &[leaf.encode().unwrap()],
    )
    .unwrap();
    let mut files: Vec<(String, Vec<u8>)> = append
        .files
        .iter()
        .map(|(p, b)| (format!("log/1/{p}"), b.clone()))
        .collect();
    let signed = trigon_attest::log::SignedCheckpoint::sign(
        &Checkpoint {
            origin: SUCCESSOR.into(),
            size: 1,
            root: append.root,
        },
        &impostor,
    )
    .unwrap();
    files.push(("log/1/checkpoint".into(), signed.to_string().into_bytes()));
    let planted: Vec<(&str, Option<&[u8]>)> = files
        .iter()
        .map(|(p, b)| (p.as_str(), Some(b.as_slice())))
        .collect();
    plant_in(&clone, &planted);

    let clone = w.clone_fresh("consumer");
    let e = Repository::open(&clone, &w.vkey(), &pinned(), None)
        .unwrap_err()
        .to_string();
    assert!(e.contains("is not the successor"), "{e}");
    let first = w.run(&a).published.unwrap().record;
    let out = w.verify_record(&clone, &first);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    // Nothing is built on it.
    w.configure(SUCCESSOR, &next, "");
    let said = refused(&w.publish(&["--heartbeat"]));
    assert!(said.contains("does not verify"), "{said}");

    // `log sign` begins no successor its predecessor's log-end does not name.
    let stranger = w.log_key_for("example.com/trigon-evidence/2", "stranger.key");
    let said = refused(&w.trigon(&[
        "log",
        "sign",
        "--tree",
        tree.to_str().unwrap(),
        "--log",
        "log/2",
        "--size",
        "1",
        "--key",
        stranger.to_str().unwrap(),
        "--continuing",
        tree.to_str().unwrap(),
    ]));
    assert!(said.contains("ends naming the log key"), "{said}");
}

/// A successor in another repository: the log-end naming it is pushed first, and the successor is
/// begun there after, as that repository's first commit. Stopped between the two, the old log has
/// ended and nothing publishes into it; `log succeed` run again begins the successor, from the
/// final checkpoint the first push published, and a client follows the pair across the two.
#[test]
fn a_succession_into_another_repository_is_begun_there_after_the_end_is_pushed() {
    let w = World::new("succeed-elsewhere");
    w.init(w.remote.to_str().unwrap());
    let pa = Package::new("a", false);
    let (a, _) = pair(&w, &pa, "aaaa");
    ok(&w.publish(&[&a]));
    let next = w.log_key_for(SUCCESSOR, "successor.key");
    let next_s = next.to_str().unwrap();
    // The successor's repository, named by a URL anyone can clone, which git here reaches as the
    // bare repository beside it.
    git(
        &w.dir,
        &["init", "--quiet", "--bare", "-b", "main", "successor.git"],
    );
    let url = "https://github.com/owner/successor.git";
    w.gitconfig(&format!(
        "[url \"file://{}\"]\n\tinsteadOf = {url}\n",
        w.dir.join("successor.git").display()
    ));
    let succeed = || {
        w.command(&[
            "log",
            "succeed",
            "--store",
            w.store.to_str().unwrap(),
            "--repo",
            w.remote.to_str().unwrap(),
            "--origin",
            SUCCESSOR,
            "--log-key",
            next_s,
            "--url",
            url,
        ])
    };
    // A path is no location a log-end names.
    let said = refused(&w.log_command(
        "succeed",
        &[
            "--origin",
            SUCCESSOR,
            "--log-key",
            next_s,
            "--url",
            w.dir.join("successor.git").to_str().unwrap(),
        ],
    ));
    assert!(said.contains("is a path on this machine"), "{said}");

    // Stopped once the old log's end is pushed, before the successor is begun.
    let out = succeed()
        .env("TRIGON_PUBLISH_DIE_AT", "ended")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(137), "{}", text(&out));
    assert_eq!(w.commits(), 3);
    let successor_commits = || {
        Command::new("git")
            .arg("-C")
            .arg(w.dir.join("successor.git"))
            .args(["rev-list", "--count", "main"])
            .output()
            .unwrap()
            .stdout
    };
    assert!(
        String::from_utf8_lossy(&successor_commits())
            .trim()
            .is_empty(),
        "nothing was begun"
    );
    // The old log has ended: nothing more is published into it, and it says where to go.
    let said = refused(&w.publish(&["--heartbeat"]));
    assert!(
        said.contains("its successor `example.com/trigon-evidence/1` is in another repository"),
        "{said}"
    );

    // Run again, it begins the successor from what the first push published; and again, it has
    // nothing left to do.
    let said = ok(&succeed().output().unwrap());
    assert!(
        said.contains("begun     `example.com/trigon-evidence/1` at log"),
        "{said}"
    );
    assert_eq!(w.commits(), 3, "the old log is not written again");
    assert_eq!(String::from_utf8_lossy(&successor_commits()).trim(), "1");
    let said = ok(&succeed().output().unwrap());
    assert!(said.contains("is begun already"), "{said}");

    // A client follows the pair: the old log names the successor elsewhere, and the successor's
    // first leaf holds its final checkpoint, signed by both keys.
    let old = w.clone_fresh("old");
    let repo = w.open(&old);
    let named = repo
        .source()
        .continues_at
        .clone()
        .expect("it names a successor");
    assert_eq!(named.urls, [url]);
    assert_eq!(named.dir, "log");
    let there = w.dir.join("successor-clone");
    git(
        &w.dir,
        &[
            "clone",
            "--quiet",
            w.dir.join("successor.git").to_str().unwrap(),
            there.to_str().unwrap(),
        ],
    );
    let followed = trigon_attest::log::follow(
        &repo.source().logs[0].log,
        &trigon_attest::log::DirFiles::in_repository(&there, "log"),
        None,
    )
    .unwrap();
    assert_eq!(followed.origin(), SUCCESSOR);
    let vkey2 = LogSigner::from_file(&next).unwrap().vkey();
    assert_eq!(
        std::fs::read_to_string(there.join("keys/log.vkey"))
            .unwrap()
            .trim(),
        vkey2.to_string()
    );

    // Switched to it, publishing goes on there, standing on the whole chain, which begins in the
    // old repository: until an evidence source reaches it, a run is refused, saying how to add one.
    w.configure(
        SUCCESSOR,
        &next,
        &format!("repo = \"{}\"\n", w.dir.join("successor.git").display()),
    );
    let pb = Package::new("b", false);
    let (b, _) = pair(&w, &pb, "bbbb");
    let said = refused(&w.trigon(&["publish", "--store", w.store.to_str().unwrap(), &b]));
    assert!(
        said.contains("no evidence source configured here reaches it"),
        "{said}"
    );
    assert!(said.contains("trigon evidence add"), "{said}");
    w.configure(
        SUCCESSOR,
        &next,
        &format!(
            "repo = \"{}\"\n{}",
            w.dir.join("successor.git").display(),
            w.chain_source()
        ),
    );
    let said = ok(&w.trigon(&["publish", "--store", w.store.to_str().unwrap(), &b]));
    assert!(
        said.contains("the whole chain is read, from the evidence source `chain`"),
        "{said}"
    );
    git(&there, &["pull", "--quiet", "--ff-only"]);
    let repo = Repository::open(&there, &vkey2, &pinned(), None).unwrap();
    let found = repo.lookup(&Key::Digest {
        algorithm: "sha256",
        hex: pb.sha256(),
    });
    assert_eq!(found.current().count(), 1);
}

/// Publishing into a successor in another repository reads the whole chain before step 2's
/// refusals, through an evidence source that reaches the log it continues: a verdict for an
/// artifact with a current record in the old repository is refused as a second current record,
/// and published only as its supersession, which a client following the chain across both
/// repositories applies; and a withdrawal of a record logged in the old repository is published
/// into the successor.
#[test]
fn publishing_into_a_successor_elsewhere_reads_the_whole_chain() {
    let w = World::new("whole-chain");
    w.init(w.remote.to_str().unwrap());
    let pa = Package::new("a", false);
    let (a, _) = pair(&w, &pa, "aaaa");
    let pb = Package::new("b", false);
    let (b, _) = pair(&w, &pb, "bbbb");
    ok(&w.publish(&[&a, &b]));
    let first = w.run(&a).published.unwrap().record;
    let withdrawn = w.run(&b).published.unwrap().record;
    let old = w.clone_fresh("old");

    let next = w.log_key_for(SUCCESSOR, "successor.key");
    git(
        &w.dir,
        &["init", "--quiet", "--bare", "-b", "main", "successor.git"],
    );
    let successor = w.dir.join("successor.git");
    let url = "https://github.com/owner/successor.git";
    w.gitconfig(&format!(
        "[url \"file://{}\"]\n\tinsteadOf = {url}\n",
        successor.display()
    ));
    ok(&w.log_command(
        "succeed",
        &[
            "--origin",
            SUCCESSOR,
            "--log-key",
            next.to_str().unwrap(),
            "--url",
            url,
        ],
    ));
    w.configure(
        SUCCESSOR,
        &next,
        &format!("repo = \"{}\"\n{}", successor.display(), w.chain_source()),
    );
    let publish = |args: &[&str]| {
        let mut all = vec!["publish", "--store", w.store.to_str().unwrap()];
        all.extend_from_slice(args);
        w.trigon(&all)
    };

    // Another pair of the same artifact, attested under the successor's origin: its artifact has
    // a current record, in the old repository.
    let (c, _) = pair(&w, &pa, "cccc");
    let said = refused(&publish(&[&c]));
    assert!(
        said.contains(&format!(
            "its artifact has a current record, sha256:{} at leaf 0 of `{ORIGIN}`",
            first.to_hex()
        )),
        "{said}"
    );
    // Superseding it, it publishes.
    let file = record_file(&old, &first);
    ok(&w.trigon(&[
        "attest",
        &c,
        "--store",
        w.store.to_str().unwrap(),
        "--key",
        w.key.to_str().unwrap(),
        "--supersedes",
        file.to_str().unwrap(),
        "--reason",
        "set_changed",
    ]));
    let said = ok(&publish(&[&c]));
    assert!(
        said.contains("logged    leaf 1: run 1789000000-cccc0001"),
        "{said}"
    );

    // A withdrawal of a record logged in the old repository goes into the successor.
    let said = ok(&w.trigon(&[
        "attest",
        "--withdraw",
        record_file(&old, &withdrawn).to_str().unwrap(),
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
    ok(&publish(&["--withdrawal", envelope.to_str().unwrap()]));

    // A client following the chain across both repositories applies both.
    let there = w.dir.join("successor-clone");
    git(
        &w.dir,
        &[
            "clone",
            "--quiet",
            successor.to_str().unwrap(),
            there.to_str().unwrap(),
        ],
    );
    git(&old, &["pull", "--quiet", "--ff-only"]);
    let head = trigon_attest::log::verify_source(&old, &w.vkey(), None).unwrap();
    let prev = head.logs.last().unwrap().log.clone();
    let tail = trigon_attest::log::verify_continuation(&prev, &there).unwrap();
    let chain =
        Repository::chain(vec![(old.clone(), head), (there, tail)], &pinned(), None).unwrap();
    let found = chain.lookup(&Key::Digest {
        algorithm: "sha256",
        hex: pa.sha256(),
    });
    assert_eq!(found.found.len(), 2);
    assert_eq!(
        found.found[0].superseded_by.len(),
        1,
        "the old record is superseded"
    );
    let current: Vec<_> = found.current().collect();
    assert_eq!(current.len(), 1);
    assert_eq!(
        current[0].pos.log, 1,
        "and the current one is the successor's"
    );
    let found = chain.lookup(&Key::Digest {
        algorithm: "sha256",
        hex: pb.sha256(),
    });
    assert_eq!(
        found.answer(Match::NormalizedWithCaveats),
        Answer::Withdrawn
    );
}

/// Publishing into a successor elsewhere reads the chain from its first log, and only from there:
/// a source pinned partway through the succession — at a later log's key — reads part of the
/// chain and is passed over, so a second current record for an artifact whose record is current in
/// an earlier log is never published through it. A source synced before the log it reaches ended
/// is synced again, however fresh, and then serves. A dry run syncs nothing.
#[test]
fn publishing_into_a_successor_elsewhere_reads_the_chain_from_its_first_log() {
    const ELSEWHERE: &str = "example.com/trigon-evidence/2";
    let w = World::new("chain-from-first");
    w.init(w.remote.to_str().unwrap());
    let pa = Package::new("a", false);
    let (a, _) = pair(&w, &pa, "aaaa");
    ok(&w.publish(&[&a]));
    let first = w.run(&a).published.unwrap().record;
    // The source that reads the chain from its first log, synced now, before the logs go on.
    w.configure(ORIGIN, &w.log_key, &w.chain_source());
    ok(&w.trigon(&["evidence", "sync"]));

    // In place, to `…/1` at log/1; and from there into another repository, `…/2`.
    let next = w.log_key_for(SUCCESSOR, "successor.key");
    ok(&w.log_command(
        "succeed",
        &["--origin", SUCCESSOR, "--log-key", next.to_str().unwrap()],
    ));
    w.configure(SUCCESSOR, &next, &w.chain_source());
    let last = w.log_key_for(ELSEWHERE, "elsewhere.key");
    git(
        &w.dir,
        &["init", "--quiet", "--bare", "-b", "main", "elsewhere.git"],
    );
    let elsewhere = w.dir.join("elsewhere.git");
    let url = "https://github.com/owner/elsewhere.git";
    w.gitconfig(&format!(
        "[url \"file://{}\"]\n\tinsteadOf = {url}\n",
        elsewhere.display()
    ));
    ok(&w.log_command(
        "succeed",
        &[
            "--origin",
            ELSEWHERE,
            "--log-key",
            last.to_str().unwrap(),
            "--url",
            url,
        ],
    ));
    let publish = |args: &[&str]| {
        let mut all = vec!["publish", "--store", w.store.to_str().unwrap()];
        all.extend_from_slice(args);
        w.trigon(&all)
    };

    // Pinned at `…/1`'s key: its chain begins partway, without the log `a`'s record is in.
    let partway = format!(
        "\n[[source]]\nname = \"partway\"\nurls = [\"{}\"]\nlog_key = \"{}\"\n\
         attestation_key = \"{}\"\n",
        w.remote.display(),
        LogSigner::from_file(&next).unwrap().vkey(),
        attestation().public_hex()
    );
    w.configure(
        ELSEWHERE,
        &last,
        &format!("repo = \"{}\"\n{partway}", elsewhere.display()),
    );
    let (c, _) = pair(&w, &pa, "cccc");
    let begun = git(&elsewhere, &["rev-parse", "main"]);
    let said = refused(&publish(&[&c]));
    assert!(
        said.contains(&format!(
            "`partway` reaches it, and its chain begins at `{SUCCESSOR}`, which continues an \
             earlier log"
        )),
        "{said}"
    );
    assert!(said.contains("pinned to the chain's first log key"), "{said}");
    assert_eq!(
        git(&elsewhere, &["rev-parse", "main"]),
        begun,
        "nothing is published"
    );

    // With the source from the first log too. A dry run syncs nothing: made stale, the source is
    // read from its clone as it is, which is from before the logs went on, and its state is left.
    w.configure(
        ELSEWHERE,
        &last,
        &format!(
            "repo = \"{}\"\n{partway}{}",
            elsewhere.display(),
            w.chain_source()
        ),
    );
    let record = w.dir.join("home/.local/state/trigon/evidence/chain/sync");
    let fresh = std::fs::read(&record).unwrap();
    let mut stale: serde_json::Value = serde_json::from_slice(&fresh).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    stale["lastSuccess"] = serde_json::json!(now - 2 * 86_400);
    std::fs::write(&record, serde_json::to_vec(&stale).unwrap()).unwrap();
    let written = std::fs::read(&record).unwrap();
    let said = refused(&publish(&["--dry-run", &c]));
    assert!(said.contains("A dry run syncs nothing"), "{said}");
    assert!(said.contains("`trigon evidence sync`"), "{said}");
    assert_eq!(
        std::fs::read(&record).unwrap(),
        written,
        "the dry run synced nothing"
    );

    // Fresh, and synced all the same, since the log it reaches has ended since: the chain is read
    // whole, and `a`'s record in the first log is current.
    std::fs::write(&record, &fresh).unwrap();
    let said = refused(&publish(&[&c]));
    assert!(
        said.contains("source    `chain`: synced first: this command needs what it serves now"),
        "{said}"
    );
    assert!(
        said.contains("the whole chain is read, from the evidence source `chain`"),
        "{said}"
    );
    assert!(
        said.contains(&format!(
            "its artifact has a current record, sha256:{} at leaf 0 of `{ORIGIN}`",
            first.to_hex()
        )),
        "{said}"
    );
    assert_eq!(git(&elsewhere, &["rev-parse", "main"]), begun);
}

// ---------------------------------------------------------------------------------------------
// Rebuilt artifacts as release assets (`[publish] rebuilt_artifacts = "github-release"`)
// ---------------------------------------------------------------------------------------------

/// The repository every release test publishes to, as GitHub names it.
const GITHUB_REPO: &str = "owner/trigon-evidence";
const TOKEN: &str = "test-token-not-a-secret";

/// One asset of a release the fake API holds.
#[derive(Clone, Debug)]
struct FakeAsset {
    id: u64,
    name: String,
    bytes: Vec<u8>,
    state: String,
}

/// One release the fake API holds.
#[derive(Clone, Debug)]
struct FakeRelease {
    id: u64,
    tag: String,
    draft: bool,
    assets: Vec<FakeAsset>,
}

/// One request the fake API was sent: the method, the path with its query, and whether it carried
/// the token, in the header and nowhere else.
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    authorized: bool,
}

#[derive(Default)]
struct GitHubState {
    releases: Vec<FakeRelease>,
    next: u64,
    seen: Vec<Seen>,
    fail_uploads: bool,
    /// Report no digest for any asset, as GitHub does for an older one.
    no_digest: bool,
    /// Where each release says its assets are uploaded, where not this server: `http://host:port`.
    upload_origin: Option<String>,
    /// Refuse every upload, quoting back the `Authorization` header it came with.
    echo_token: bool,
}

/// The few endpoints of GitHub's REST API that publishing uses — list releases, create one, list a
/// release's assets, upload an asset, delete one — served on `127.0.0.1:0` from a thread, one
/// connection at a time, and closed after each answer.
struct FakeGitHub {
    addr: std::net::SocketAddr,
    state: std::sync::Arc<std::sync::Mutex<GitHubState>>,
}

impl FakeGitHub {
    fn start() -> FakeGitHub {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let state = std::sync::Arc::new(std::sync::Mutex::new(GitHubState {
            next: 1,
            ..Default::default()
        }));
        let shared = state.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let _ = serve_one(stream, &shared, addr);
            }
        });
        FakeGitHub { addr, state }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn state(&self) -> std::sync::MutexGuard<'_, GitHubState> {
        self.state.lock().unwrap()
    }

    /// The release `tag`, filled with other assets until it holds `n`.
    fn fill(&self, tag: &str, n: usize) {
        let mut s = self.state();
        let at = s.releases.iter().position(|r| r.tag == tag).unwrap();
        for i in s.releases[at].assets.len()..n {
            let id = s.next;
            s.next += 1;
            s.releases[at].assets.push(FakeAsset {
                id,
                name: format!("sha256-{i:064x}"),
                bytes: vec![0],
                state: "uploaded".into(),
            });
        }
    }

    fn uploads_of(&self, name: &str) -> usize {
        self.state()
            .seen
            .iter()
            .filter(|r| r.method == "POST" && r.path.contains(&format!("name={name}")))
            .count()
    }

    fn deletes(&self) -> usize {
        self.state()
            .seen
            .iter()
            .filter(|r| r.method == "DELETE")
            .count()
    }

    /// A release `tag` made beforehand, by hand, a draft where `draft`.
    fn release(&self, tag: &str, draft: bool) {
        let mut s = self.state();
        let id = s.next;
        s.next += 1;
        s.releases.push(FakeRelease {
            id,
            tag: tag.into(),
            draft,
            assets: Vec::new(),
        });
    }

    /// The asset `name` of release `tag`, put there beforehand as `bytes` in `state`, in place of
    /// any of that name.
    fn seed(&self, tag: &str, name: &str, bytes: &[u8], state: &str) {
        let mut s = self.state();
        let id = s.next;
        s.next += 1;
        let r = s.releases.iter_mut().find(|r| r.tag == tag).unwrap();
        r.assets.retain(|a| a.name != name);
        r.assets.push(FakeAsset {
            id,
            name: name.into(),
            bytes: bytes.to_vec(),
            state: state.into(),
        });
    }

    /// The bytes of the asset `name`, in whichever release holds it.
    fn asset(&self, name: &str) -> Option<Vec<u8>> {
        self.state()
            .releases
            .iter()
            .flat_map(|r| &r.assets)
            .find(|a| a.name == name)
            .map(|a| a.bytes.clone())
    }
}

fn serve_one(
    stream: std::net::TcpStream,
    state: &std::sync::Mutex<GitHubState>,
    addr: std::net::SocketAddr,
) -> std::io::Result<()> {
    use std::io::{BufRead as _, Read as _, Write as _};
    let mut reader = std::io::BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let (method, path) = (
        parts.next().unwrap_or_default().to_string(),
        parts.next().unwrap_or_default().to_string(),
    );
    let mut length = 0usize;
    let mut authorized = false;
    loop {
        let mut h = String::new();
        reader.read_line(&mut h)?;
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        let (k, v) = h.split_once(':').unwrap_or((h, ""));
        let (k, v) = (k.to_ascii_lowercase(), v.trim());
        if k == "content-length" {
            length = v.parse().unwrap_or(0);
        }
        if k == "authorization" {
            authorized = v == format!("Bearer {TOKEN}");
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    let (status, answer) = route(state, addr, &method, &path, &body, authorized);
    let answer = answer.to_string();
    let mut out = stream;
    write!(
        out,
        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
         connection: close\r\n\r\n{answer}",
        answer.len()
    )?;
    out.flush()
}

fn route(
    state: &std::sync::Mutex<GitHubState>,
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    body: &[u8],
    authorized: bool,
) -> (u16, serde_json::Value) {
    use serde_json::json;
    let mut s = state.lock().unwrap();
    s.seen.push(Seen {
        method: method.into(),
        path: path.into(),
        authorized,
    });
    if !authorized {
        return (401, json!({"message": "Bad credentials"}));
    }
    let (route, query) = path.split_once('?').unwrap_or((path, ""));
    let page: usize = query
        .split('&')
        .find_map(|q| q.strip_prefix("page="))
        .and_then(|p| p.parse().ok())
        .unwrap_or(1);
    let pageful = |items: Vec<serde_json::Value>| {
        json!(
            items
                .into_iter()
                .skip((page - 1) * 100)
                .take(100)
                .collect::<Vec<_>>()
        )
    };
    let origin = s
        .upload_origin
        .clone()
        .unwrap_or_else(|| format!("http://{addr}"));
    let release_json = |r: &FakeRelease| {
        json!({
            "id": r.id,
            "tag_name": r.tag,
            "draft": r.draft,
            "upload_url": format!(
                "{origin}/uploads/repos/{GITHUB_REPO}/releases/{}/assets{{?name,label}}",
                r.id
            ),
        })
    };
    let no_digest = s.no_digest;
    let asset_json = |a: &FakeAsset| {
        let digest: String = sha2::Sha256::digest(&a.bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let mut o = json!({
            "id": a.id,
            "name": a.name,
            "size": a.bytes.len(),
            "state": a.state,
            "digest": format!("sha256:{digest}"),
        });
        if no_digest {
            o.as_object_mut().unwrap().remove("digest");
        }
        o
    };
    let releases = format!("/repos/{GITHUB_REPO}/releases");
    let uploads = format!("/uploads/repos/{GITHUB_REPO}/releases/");
    use sha2::Digest as _;
    if method == "GET" && route == releases {
        return (200, pageful(s.releases.iter().map(release_json).collect()));
    }
    if method == "POST" && route == releases {
        let asked: serde_json::Value = serde_json::from_slice(body).unwrap();
        let tag = asked["tag_name"].as_str().unwrap().to_string();
        if s.releases.iter().any(|r| r.tag == tag) {
            return (422, json!({"message": "Validation Failed"}));
        }
        let id = s.next;
        s.next += 1;
        let r = FakeRelease {
            id,
            tag,
            draft: false,
            assets: Vec::new(),
        };
        let answer = release_json(&r);
        s.releases.push(r);
        return (201, answer);
    }
    if method == "GET"
        && let Some(id) = route
            .strip_prefix(&format!("{releases}/"))
            .and_then(|r| r.strip_suffix("/assets"))
            .and_then(|id| id.parse::<u64>().ok())
    {
        let Some(r) = s.releases.iter().find(|r| r.id == id) else {
            return (404, json!({"message": "Not Found"}));
        };
        return (200, pageful(r.assets.iter().map(asset_json).collect()));
    }
    if method == "POST"
        && let Some(id) = route
            .strip_prefix(&uploads)
            .and_then(|r| r.strip_suffix("/assets"))
            .and_then(|id| id.parse::<u64>().ok())
    {
        if s.fail_uploads {
            return (500, json!({"message": "Server Error"}));
        }
        if s.echo_token {
            return (
                500,
                json!({"message": format!("refused Authorization: Bearer {TOKEN}")}),
            );
        }
        let name = query
            .split('&')
            .find_map(|q| q.strip_prefix("name="))
            .unwrap_or_default()
            .to_string();
        let aid = s.next;
        s.next += 1;
        let Some(r) = s.releases.iter_mut().find(|r| r.id == id) else {
            return (404, json!({"message": "Not Found"}));
        };
        if r.assets.iter().any(|a| a.name == name) {
            return (422, json!({"message": "Validation Failed"}));
        }
        let a = FakeAsset {
            id: aid,
            name,
            bytes: body.to_vec(),
            state: "uploaded".into(),
        };
        let answer = asset_json(&a);
        r.assets.push(a);
        return (201, answer);
    }
    if method == "DELETE"
        && let Some(id) = route
            .strip_prefix(&format!("{releases}/assets/"))
            .and_then(|id| id.parse::<u64>().ok())
    {
        for r in &mut s.releases {
            r.assets.retain(|a| a.id != id);
        }
        return (204, json!(null));
    }
    (404, json!({"message": "Not Found"}))
}

/// The month a publication now is logged in, as a release series is named: `YYYY-MM`, UTC.
fn this_month() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // Civil-from-days (Howard Hinnant), as `trigon` computes it.
    let z = secs.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}")
}

impl World {
    /// This world's evidence repository, named by its GitHub URL, which git here reaches as the
    /// bare repository: begun, and configured to publish rebuilt artifacts as release assets.
    fn on_github(&self, extra: &str) -> &'static str {
        let url = "https://github.com/owner/trigon-evidence.git";
        self.gitconfig(&format!(
            "[url \"file://{}\"]\n\tinsteadOf = {url}\n",
            self.remote.display()
        ));
        self.init(url);
        self.config(&format!(
            "repo = \"{url}\"\nrebuilt_artifacts = \"github-release\"\n{extra}"
        ));
        url
    }

    /// `trigon publish <args>` to the repository `[publish] repo` names, with the token, against
    /// `gh`.
    fn publish_with(&self, gh: &FakeGitHub, args: &[&str]) -> Output {
        let mut all = vec!["publish", "--store", self.store.to_str().unwrap()];
        all.extend_from_slice(args);
        self.command(&all)
            .env("GITHUB_TOKEN", TOKEN)
            .env("TRIGON_GITHUB_API", gh.url())
            .output()
            .unwrap()
    }
}

/// A verdict's rebuilt artifact is uploaded as the asset `sha256-<hex>` of the digest it signs, to
/// the month's release, before the commit that names it; the token goes in the header and nowhere
/// else; a location that is not on GitHub, and a missing token, are refused before anything is
/// written.
#[test]
fn a_rebuilt_artifact_is_a_release_asset_uploaded_before_its_record_is_committed() {
    let w = World::new("release");
    let gh = FakeGitHub::start();
    let url = w.on_github("");
    let pa = Package::new("a", false);
    let (a, _) = pair(&w, &pa, "aaaa");
    let rebuilt = trigon_attest::Record::digest_of(&pa.rebuilt).to_hex();
    let name = format!("sha256-{rebuilt}");

    // No token: refused before anything is written, and nothing is asked of GitHub.
    let said = refused(&w.trigon(&["publish", "--store", w.store.to_str().unwrap(), &a]));
    assert!(
        said.contains("neither GITHUB_TOKEN nor GH_TOKEN is set"),
        "{said}"
    );
    assert!(said.contains("Nothing was written"), "{said}");
    // A location with no releases: refused, token or not.
    let out = w
        .command(&[
            "publish",
            "--store",
            w.store.to_str().unwrap(),
            "--repo",
            w.remote.to_str().unwrap(),
            &a,
        ])
        .env("GITHUB_TOKEN", TOKEN)
        .env("TRIGON_GITHUB_API", gh.url())
        .output()
        .unwrap();
    let said = refused(&out);
    assert!(said.contains("is not a repository on github.com"), "{said}");
    assert_eq!(w.commits(), 1);
    assert!(gh.state().seen.is_empty(), "GitHub was asked something");

    // A dry run says where the asset would go, and uploads nothing.
    let said = ok(&w.publish_with(&gh, &[&a, "--dry-run"]));
    assert!(said.contains(&format!("asset     {name}")), "{said}");
    assert_eq!(gh.uploads_of(&name), 0);

    let said = ok(&w.publish_with(&gh, &[&a]));
    let tag = format!("rebuilt-{}", this_month());
    assert!(
        said.contains(&format!(
            "asset     {name} in release {tag} of {GITHUB_REPO}"
        )),
        "{said}"
    );
    assert_eq!(w.commits(), 2);
    {
        let s = gh.state();
        let release = s.releases.iter().find(|r| r.tag == tag).unwrap();
        let asset = release.assets.iter().find(|x| x.name == name).unwrap();
        assert_eq!(asset.bytes, pa.rebuilt, "the asset is the rebuilt artifact");
        assert!(s.seen.iter().all(|r| r.authorized), "{:?}", s.seen);
        assert!(s.seen.iter().all(|r| !r.path.contains(TOKEN)));
    }
    assert!(!said.contains(TOKEN));
    // The record names it by the digest its verdict signs.
    let clone = w.clone_fresh("reader");
    let record = w.run(&a).published.unwrap().record;
    let v = w
        .open(&clone)
        .verify_record(&std::fs::read(record_file(&clone, &record)).unwrap())
        .unwrap();
    assert_eq!(
        v.record.evidence.get("rebuiltArtifact").map(String::as_str),
        Some(format!("sha256:{rebuilt}").as_str())
    );
    let _ = url;
}

/// An upload that fails leaves no commit; a publisher stopped after its upload and before its
/// commit leaves only the asset, which the next attempt reuses rather than uploads again; a month
/// whose release is full continues in the next of its series; an exact rebuild, which is the
/// published artifact, is not uploaded at all; and an artifact over GitHub's 2 GiB is refused.
#[test]
fn an_asset_is_reused_on_retry_and_a_full_release_continues_its_series() {
    let w = World::new("release-retry");
    let gh = FakeGitHub::start();
    w.on_github("");
    let tag = format!("rebuilt-{}", this_month());

    let pb = Package::new("b", false);
    let (b, _) = pair(&w, &pb, "bbbb");
    let name = format!(
        "sha256-{}",
        trigon_attest::Record::digest_of(&pb.rebuilt).to_hex()
    );
    gh.state().fail_uploads = true;
    let said = refused(&w.publish_with(&gh, &[&b]));
    assert!(said.contains("GitHub answered 500"), "{said}");
    assert_eq!(w.commits(), 1, "nothing is committed without its asset");
    gh.state().fail_uploads = false;

    let out = w
        .command(&["publish", "--store", w.store.to_str().unwrap(), &b])
        .env("GITHUB_TOKEN", TOKEN)
        .env("TRIGON_GITHUB_API", gh.url())
        .env("TRIGON_PUBLISH_DIE_AT", "uploaded")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(137), "{}", text(&out));
    assert_eq!(w.commits(), 1);
    assert_eq!(gh.uploads_of(&name), 2, "one refused, one taken");
    let said = ok(&w.publish_with(&gh, &[&b]));
    assert!(said.contains(&format!("{name} in release {tag}")), "{said}");
    assert!(said.contains("there already"), "{said}");
    assert_eq!(gh.uploads_of(&name), 2, "reused, not uploaded again");
    assert_eq!(w.commits(), 2);

    // The month's release is full: the next asset starts `.2`.
    gh.fill(&tag, 1000);
    let pc = Package::new("c", false);
    let (c, _) = pair(&w, &pc, "cccc");
    let said = ok(&w.publish_with(&gh, &[&c]));
    assert!(said.contains(&format!("in release {tag}.2")), "{said}");

    // An exact rebuild is the published artifact byte for byte: not ours to redistribute.
    let exact = Package {
        name: "exact".into(),
        upstream: tgz(b"module.exports = 'exact'\n", 1),
        rebuilt: tgz(b"module.exports = 'exact'\n", 1),
    };
    let (e, _) = pair(&w, &exact, "eeee");
    let before = gh.state().seen.len();
    ok(&w.publish_with(&gh, &[&e]));
    assert!(
        gh.state().seen[before..].iter().all(|r| r.method == "GET"),
        "an exact rebuild was uploaded"
    );

    // Not under 2 GiB, as the run recorded it — exactly 2 GiB is refused too: refused before
    // anything is uploaded or written.
    let pd = Package::new("d", false);
    let (d, _) = pair(&w, &pd, "dddd");
    rt().block_on(async {
        let store = Store::local(&w.store).unwrap();
        let mut r = store.get_run(&d).await.unwrap();
        r.rebuild.as_mut().unwrap().bytes = 2 << 30;
        store.put_run(&r).await.unwrap();
    });
    let before = (w.commits(), gh.state().seen.len());
    let said = refused(&w.publish_with(&gh, &[&d]));
    assert!(
        said.contains("GitHub takes a release asset only under 2 GiB"),
        "{said}"
    );
    assert_eq!((w.commits(), gh.state().seen.len()), before);
}

/// The name `sha256-<hex>` is a claim about the bytes, and GitHub will hold anything under it. An
/// asset of that name is taken for the artifact only where it is the artifact: one of another size,
/// or of its size with another digest, is refused with nothing committed and nothing uploaded; one
/// GitHub left unfinished is removed and uploaded again; and one GitHub reports no digest for,
/// which its size alone cannot tell from another artifact's, is uploaded again in its place.
#[test]
fn an_asset_of_the_artifacts_name_is_taken_for_it_only_when_it_is_it() {
    let w = World::new("release-same");
    let gh = FakeGitHub::start();
    w.on_github("");
    let tag = format!("rebuilt-{}", this_month());
    gh.release(&tag, false);
    let pb = Package::new("b", false);
    let (b, _) = pair(&w, &pb, "bbbb");
    let name = format!(
        "sha256-{}",
        trigon_attest::Record::digest_of(&pb.rebuilt).to_hex()
    );
    let mut forged = pb.rebuilt.clone();
    *forged.last_mut().unwrap() ^= 0xff;

    gh.seed(&tag, &name, b"another artifact", "uploaded");
    let said = refused(&w.publish_with(&gh, &[&b]));
    assert!(said.contains("so that one is not the artifact"), "{said}");
    gh.seed(&tag, &name, &forged, "uploaded");
    let said = refused(&w.publish_with(&gh, &[&b]));
    assert!(said.contains("with digest sha256:"), "{said}");
    assert!(said.contains("so that one is not the artifact"), "{said}");
    assert_eq!((w.commits(), gh.uploads_of(&name), gh.deletes()), (1, 0, 0));
    assert!(w.run(&b).published.is_none());

    // Begun and never finished: removed, and the artifact uploaded in its place.
    gh.seed(&tag, &name, &pb.rebuilt[..10], "starter");
    let said = ok(&w.publish_with(&gh, &[&b]));
    assert!(!said.contains("there already"), "{said}");
    assert_eq!((gh.deletes(), gh.uploads_of(&name)), (1, 1));
    assert_eq!(gh.asset(&name).unwrap(), pb.rebuilt);
    assert_eq!(w.commits(), 2);

    // No digest reported: of the artifact's size, it is uploaded again in its place, never taken
    // on its size; of another size, it is refused as any other artifact under the name is.
    gh.state().no_digest = true;
    let pc = Package::new("c", false);
    let (c, _) = pair(&w, &pc, "cccc");
    let name = format!(
        "sha256-{}",
        trigon_attest::Record::digest_of(&pc.rebuilt).to_hex()
    );
    let mut forged = pc.rebuilt.clone();
    *forged.last_mut().unwrap() ^= 0xff;
    gh.seed(&tag, &name, b"another artifact", "uploaded");
    let said = refused(&w.publish_with(&gh, &[&c]));
    assert!(said.contains("so that one is not the artifact"), "{said}");
    gh.seed(&tag, &name, &forged, "uploaded");
    let said = ok(&w.publish_with(&gh, &[&c]));
    assert!(!said.contains("there already"), "{said}");
    assert_eq!((gh.deletes(), gh.uploads_of(&name)), (2, 1));
    assert_eq!(gh.asset(&name).unwrap(), pc.rebuilt);
    assert_eq!(w.commits(), 3);
}

/// The token goes nowhere but GitHub, and into no message: a release that names an upload URL on
/// another host, or another port of this one, is refused and that host is never contacted; a
/// server that quotes the token back in a refusal has it taken out of what is shown; and no asset
/// is put in a draft release of the month's tag, which the public cannot see, when the release
/// cannot be made because the draft has its tag.
#[test]
fn the_token_goes_to_no_other_host_and_no_asset_into_a_draft() {
    let w = World::new("release-token");
    let gh = FakeGitHub::start();
    w.on_github("");
    let tag = format!("rebuilt-{}", this_month());
    let pb = Package::new("b", false);
    let (b, _) = pair(&w, &pb, "bbbb");
    let name = format!(
        "sha256-{}",
        trigon_attest::Record::digest_of(&pb.rebuilt).to_hex()
    );

    gh.release(&tag, true);
    let said = refused(&w.publish_with(&gh, &[&b]));
    assert!(
        said.contains("A draft release of that tag is there"),
        "{said}"
    );
    assert_eq!((w.commits(), gh.uploads_of(&name)), (1, 0));
    gh.state().releases.clear();

    let foreign = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    foreign.set_nonblocking(true).unwrap();
    gh.state().upload_origin = Some(format!("http://{}", foreign.local_addr().unwrap()));
    let said = refused(&w.publish_with(&gh, &[&b]));
    assert!(said.contains("which is not GitHub's upload host"), "{said}");
    assert!(
        matches!(foreign.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
        "the other host was sent the upload"
    );
    assert_eq!((w.commits(), gh.uploads_of(&name)), (1, 0));
    gh.state().upload_origin = None;

    gh.state().echo_token = true;
    let said = refused(&w.publish_with(&gh, &[&b]));
    assert!(said.contains("GitHub answered 500"), "{said}");
    assert!(said.contains("Bearer ***"), "{said}");
    assert!(!said.contains(TOKEN), "{said}");
    assert_eq!(w.commits(), 1);
    gh.state().echo_token = false;

    let said = ok(&w.publish_with(&gh, &[&b]));
    assert!(!said.contains(TOKEN), "{said}");
    assert_eq!(gh.asset(&name).unwrap(), pb.rebuilt);
}

/// Only once a run is published may its rebuilt artifact go: `publish --prune` prunes it after
/// step 7, and `attest --prune` refuses a run not yet published where the repository publishes
/// rebuilt artifacts; elsewhere `attest --prune` prunes as it always did.
#[test]
fn a_rebuilt_artifact_is_pruned_only_once_its_run_is_published() {
    let w = World::new("prune");
    let gh = FakeGitHub::start();
    w.on_github("");
    let pa = Package::new("a", false);
    let (a, _) = pair(&w, &pa, "aaaa");
    let said = refused(&w.trigon(&[
        "attest",
        &a,
        "--store",
        w.store.to_str().unwrap(),
        "--key",
        w.key.to_str().unwrap(),
        "--prune",
    ]));
    assert!(said.contains("refusing --prune: run `1789000000-aaaa0001` is not published yet"));
    assert!(said.contains("Nothing was signed"), "{said}");
    assert!(w.run(&a).rebuild.unwrap().stored);
    // Published, it may be pruned by attest.
    ok(&w.publish_with(&gh, &[&a]));
    let said = ok(&w.trigon(&[
        "attest",
        &a,
        "--store",
        w.store.to_str().unwrap(),
        "--key",
        w.key.to_str().unwrap(),
        "--prune",
    ]));
    // Its reference goes, and the bytes stay: the second attempt rebuilt the same bytes, which
    // are one blob, and its record still names them.
    assert!(
        said.contains(
            "pruned this run's rebuilt artifact, and kept its bytes, which run \
             1789007200-aaaa0002 still names"
        ),
        "{said}"
    );
    assert!(!w.run(&a).rebuild.unwrap().stored);
    // The second of a pair is never published once its first is, so no publication would upload
    // its artifact: attest prunes it, where holding it back would hold it for ever.
    let pq = Package::new("q", false);
    let (q, q2) = pair(&w, &pq, "qqqq");
    ok(&w.publish_with(&gh, &[&q]));
    let prune = |id: &str| {
        w.trigon(&[
            "attest",
            id,
            "--store",
            w.store.to_str().unwrap(),
            "--key",
            w.key.to_str().unwrap(),
            "--prune",
        ])
    };
    let said = refused(&w.publish_with(&gh, &[&q2, "--prune"]));
    assert!(said.contains("which is published"), "{said}");
    let said = ok(&prune(&q2));
    assert!(
        said.contains("pruned this run's rebuilt artifact, and kept its bytes"),
        "{said}"
    );
    assert!(!w.run(&q2).rebuild.unwrap().stored);
    // A run the gate withholds, awaiting its confirmation, is refused, and says why.
    let store = Store::local(&w.store).unwrap();
    let pw = Package::new("w", false);
    rt().block_on(attempt(
        &store,
        "1789000000-wwww0001",
        &pw,
        "ck1:wwww",
        'a',
        "2026-09-27T00:00:00Z",
        "mirror-only",
    ));
    let said = refused(&prune("1789000000-wwww0001"));
    assert!(
        said.contains("withholds it now (awaiting_confirmation)"),
        "{said}"
    );

    // `publish --prune` prunes once the run is published and recorded.
    let pc = Package::new("c", false);
    let (c, _) = pair(&w, &pc, "cccc");
    let said = ok(&w.publish_with(&gh, &[&c, "--prune"]));
    assert!(said.contains("pruned    run 1789000000-cccc0001"), "{said}");
    let run = w.run(&c);
    assert!(run.published.is_some());
    assert!(!run.rebuild.unwrap().stored);

    // Without release assets, attest prunes as it always did, published or not.
    w.config("");
    let pb = Package::new("b", false);
    let (b, _) = pair(&w, &pb, "bbbb");
    let said = ok(&w.trigon(&[
        "attest",
        &b,
        "--store",
        w.store.to_str().unwrap(),
        "--key",
        w.key.to_str().unwrap(),
        "--prune",
    ]));
    assert!(
        said.contains("pruned this run's rebuilt artifact"),
        "{said}"
    );
}

// ---------------------------------------------------------------------------------------------
// The divergence feed (`[publish] divergences = "feed"`)
// ---------------------------------------------------------------------------------------------

const ATOM: &str = "http://www.w3.org/2005/Atom";

/// The Atom elements named `name` directly under `n`.
fn atom<'a>(n: roxmltree::Node<'a, 'a>, name: &str) -> Vec<roxmltree::Node<'a, 'a>> {
    n.children()
        .filter(|c| c.tag_name().namespace() == Some(ATOM) && c.tag_name().name() == name)
        .collect()
}

/// With the feed on, a divergence is published with its entry in `feed/divergences.atom` in the
/// same commit — valid Atom, parsed here, linking the record and its dispute pointer — and a
/// withdrawal of it regenerates the feed with the entry marked superseded. The feed is the log's:
/// an entry planted in it is gone at `--reconcile`.
#[test]
fn a_divergence_is_published_with_its_feed_entry_in_the_same_commit() {
    let w = World::new("feed");
    w.init(w.remote.to_str().unwrap());
    let readme = std::fs::read_to_string(w.clone_fresh("reader").join("README.md")).unwrap();
    assert!(readme.contains("the most recent 200 of them"), "{readme}");
    w.config("divergences = \"feed\"\n");
    let div = Package::new("div", true);
    let (d, _) = pair(&w, &div, "d1d1");
    ok(&w.publish(&[&d]));
    let changed = git(
        &w.remote,
        &["diff-tree", "--no-commit-id", "--name-only", "-r", "main"],
    );
    assert!(
        changed.lines().any(|l| l == "feed/divergences.atom"),
        "{changed}"
    );
    assert!(
        changed.lines().any(|l| l.starts_with("records/")),
        "{changed}"
    );

    let clone = w.clone_fresh("reader");
    let xml = std::fs::read_to_string(clone.join("feed/divergences.atom")).unwrap();
    let doc = roxmltree::Document::parse(&xml).unwrap();
    let feed = doc.root_element();
    assert_eq!(feed.tag_name().namespace(), Some(ATOM));
    for required in ["id", "title", "updated", "author"] {
        assert_eq!(atom(feed, required).len(), 1, "{required}");
    }
    let entries = atom(feed, "entry");
    assert_eq!(entries.len(), 1);
    let entry = entries[0];
    let href = |rel: &str| {
        atom(entry, "link")
            .into_iter()
            .find(|l| l.attribute("rel") == Some(rel))
            .and_then(|l| l.attribute("href"))
            .map(str::to_string)
    };
    let record = w.run(&d).published.unwrap().record;
    let alternate = href("alternate").unwrap();
    assert_eq!(
        alternate,
        format!("../{}", trigon_attest::evidence::record_path(&record))
    );
    assert!(clone.join("feed").join(&alternate).is_file());
    assert_eq!(href("related").as_deref(), Some(DISPUTES));
    let content = atom(entry, "content")[0].text().unwrap().to_string();
    assert!(
        content.contains("trigon verify-attestation --lookup"),
        "{content}"
    );
    assert!(content.contains(&format!("--origin {ORIGIN}")), "{content}");
    assert!(content.contains(&div.sha256()), "{content}");

    // Withdrawn, the entry stays, marked superseded, and the feed is regenerated with it.
    let said = ok(&w.trigon(&[
        "attest",
        "--withdraw",
        record_file(&clone, &record).to_str().unwrap(),
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
            .unwrap(),
    );
    ok(&w.publish(&["--withdrawal", envelope.to_str().unwrap()]));
    let clone = w.clone_fresh("reader");
    let xml = std::fs::read_to_string(clone.join("feed/divergences.atom")).unwrap();
    let doc = roxmltree::Document::parse(&xml).unwrap();
    let entry = atom(doc.root_element(), "entry")[0];
    assert!(
        atom(entry, "category")
            .iter()
            .any(|c| c.attribute("term") == Some("superseded"))
    );
    let content = atom(entry, "content")[0].text().unwrap().to_string();
    assert!(content.starts_with("Superseded (withdrawn)"), "{content}");

    // An entry planted by whoever can push is gone at the next reconcile, and the feed is as the
    // log implies it.
    let want = std::fs::read(clone.join("feed/divergences.atom")).unwrap();
    w.plant(&[
        (
            "feed/divergences.atom",
            Some(b"<feed xmlns=\"http://www.w3.org/2005/Atom\"><entry/></feed>"),
        ),
        ("feed/other.atom", Some(b"planted")),
    ]);
    let said = ok(&w.publish(&["--reconcile"]));
    assert!(said.contains("reconcile index/ and the feed"), "{said}");
    let clone = w.clone_fresh("reader");
    assert_eq!(
        std::fs::read(clone.join("feed/divergences.atom")).unwrap(),
        want
    );
    assert!(!clone.join("feed/other.atom").exists());
}

// ---------------------------------------------------------------------------------------------
// `trigon serve`: the repository's kill-switch beside its own
// ---------------------------------------------------------------------------------------------

/// A `trigon serve` of this world's store on `127.0.0.1:0`, killed when dropped: the address it
/// bound, and what it said on starting.
struct Served {
    child: std::process::Child,
    addr: String,
    said: String,
}

impl Drop for Served {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Served {
    fn start(w: &World, extra: &[&str]) -> Served {
        use std::io::BufRead as _;
        let mut args = vec![
            "serve",
            w.store.to_str().unwrap(),
            "--bind",
            "127.0.0.1:0",
            "--refresh-seconds",
            "0",
        ];
        args.extend_from_slice(extra);
        let mut child = w
            .command(&args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let mut out = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut said = String::new();
        let mut addr = None;
        // What it says before it serves: the address, the mode, and both switches.
        for _ in 0..8 {
            let mut line = String::new();
            if out.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            if let Some(rest) = line.strip_prefix("serving ") {
                addr = rest
                    .split("http://")
                    .nth(1)
                    .and_then(|r| r.split_whitespace().next())
                    .map(str::to_string);
            }
            said.push_str(&line);
            if line.contains("a confirmation is") {
                break;
            }
        }
        Served {
            addr: addr.unwrap_or_else(|| panic!("serve did not say where it serves: {said}")),
            child,
            said,
        }
    }

    fn health(&self) -> serde_json::Value {
        use std::io::{Read as _, Write as _};
        let mut s = std::net::TcpStream::connect(&self.addr).unwrap();
        write!(
            s,
            "GET /v1/health HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            self.addr
        )
        .unwrap();
        let mut answer = String::new();
        s.read_to_string(&mut answer).unwrap();
        let body = answer.split_once("\r\n\r\n").unwrap().1;
        serde_json::from_str(body).unwrap_or_else(|e| panic!("{e}: {answer}"))
    }
}

/// `trigon serve` reports the evidence repository's kill-switch beside its own, as the
/// publisher's working clone last fetched it and with when: unknown with no clone, never off;
/// clear, then set once a fetch sees the file; and each switch as what it is.
#[test]
fn serve_reports_the_repositorys_kill_switch_beside_its_own() {
    let w = World::new("serve-switch");
    w.init(w.remote.to_str().unwrap());
    w.config(&format!("repo = \"{}\"\n", w.remote.display()));

    let s = Served::start(&w, &[]);
    let k = &s.health()["kill_switches"];
    assert_eq!(k["repository"]["state"], "unknown", "{k}");
    assert!(k["repository"]["as_of"].is_null());
    assert_eq!(k["serve"]["set"], false);
    assert!(s.said.contains("is unknown"), "{}", s.said);
    drop(s);

    // A publish makes the working clone and fetches: clear, as of that fetch.
    ok(&w.publish(&["--heartbeat"]));
    let s = Served::start(&w, &[]);
    let k = &s.health()["kill_switches"];
    assert_eq!(k["repository"]["state"], "clear", "{k}");
    assert!(k["repository"]["as_of"].as_str().is_some(), "{k}");
    drop(s);

    // The file planted on the branch is seen at the next fetch, whatever that publish does: set,
    // and this server's own switch reported beside it as what it is.
    w.plant(&[(
        "kill-switch",
        Some(b"stopped: review the false-mismatch rate\n"),
    )]);
    ok(&w.publish(&["--heartbeat"]));
    let s = Served::start(&w, &[]);
    let h = s.health();
    assert_eq!(h["kill_switches"]["repository"]["state"], "set", "{h}");
    assert_eq!(h["kill_switches"]["serve"]["set"], false);
    assert_eq!(h["divergence_publication"], "running");
    assert!(s.said.contains("is SET"), "{}", s.said);
    drop(s);
    let s = Served::start(&w, &["--stop-divergences"]);
    let h = s.health();
    assert_eq!(h["kill_switches"]["serve"]["set"], true);
    assert_eq!(h["divergence_publication"], "stopped");
    assert!(s.said.contains("STOPPED"), "{}", s.said);
}

/// The switch `serve` reports is as of the working clone's last fetch that succeeded. A fetch
/// that fails — the remote gone, a credential expired — changes neither what is reported nor when
/// it is said to be from, however the remote has changed meanwhile; and a `kill-switch` git lists
/// but that is no file, a submodule entry whose commit the clone does not hold, is reported set, as
/// `publish` counts it, never clear.
#[test]
fn serve_reports_the_switch_as_of_the_last_fetch_that_succeeded() {
    let w = World::new("serve-switch-fetch");
    w.init(w.remote.to_str().unwrap());
    w.config(&format!("repo = \"{}\"\n", w.remote.display()));
    ok(&w.publish(&["--heartbeat"]));
    let s = Served::start(&w, &[]);
    let k = s.health()["kill_switches"]["repository"].clone();
    drop(s);
    assert_eq!(k["state"], "clear", "{k}");
    let fetched = k["as_of"].as_str().unwrap().to_string();

    // A second later, the switch is set on the remote, and the remote then cannot be reached: the
    // fetch fails, and what was read, and when, is what the last good fetch said.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    w.plant(&[("kill-switch", Some(b"stopped\n"))]);
    let away = w.dir.join("remote-away.git");
    std::fs::rename(&w.remote, &away).unwrap();
    refused(&w.publish(&["--heartbeat"]));
    let s = Served::start(&w, &[]);
    let k = s.health()["kill_switches"]["repository"].clone();
    drop(s);
    assert_eq!(k["state"], "clear", "{k}");
    assert_eq!(k["as_of"], fetched.as_str(), "{k}");
    assert!(
        k["detail"]
            .as_str()
            .unwrap()
            .contains("last fetch that succeeded"),
        "{k}"
    );

    // Reachable again, the next fetch sees it.
    std::fs::rename(&away, &w.remote).unwrap();
    ok(&w.publish(&["--heartbeat"]));
    let s = Served::start(&w, &[]);
    let k = s.health()["kill_switches"]["repository"].clone();
    drop(s);
    assert_eq!(k["state"], "set", "{k}");
    assert!(k["as_of"].as_str().unwrap() > fetched.as_str(), "{k}");

    // A submodule entry named `kill-switch`, whose commit nobody fetched: `publish` checks out a
    // directory there and withholds divergences, and `serve` says set, not clear.
    let c = w.clone_fresh("planter");
    git(&c, &["rm", "--quiet", "kill-switch"]);
    git(
        &c,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("160000,{},kill-switch", "5".repeat(40)),
        ],
    );
    git(&c, &["commit", "--quiet", "-m", "a gitlink"]);
    git(&c, &["push", "--quiet", "origin", "main"]);
    ok(&w.publish(&["--heartbeat"]));
    let s = Served::start(&w, &[]);
    let k = s.health()["kill_switches"]["repository"].clone();
    drop(s);
    assert_eq!(k["state"], "set", "{k}");
}

/// A log-end is for good, so a log is ended only naming a place its successor can be begun: the
/// evidence repository itself, however it is spelled, a repository holding a log already, and one
/// git cannot reach are each refused with nothing written, and the log goes on. Begun elsewhere,
/// the successor starts with the kill-switch the ended log's repository had set, which a
/// succession never clears.
#[test]
fn a_log_is_ended_only_naming_a_place_its_successor_can_be_begun() {
    let w = World::new("succeed-where");
    let url = |name: &str| format!("https://github.com/owner/{name}.git");
    let mut rewrites = String::new();
    for (name, repo) in [
        ("trigon-evidence", w.remote.clone()),
        ("other", w.dir.join("other.git")),
        ("successor", w.dir.join("successor.git")),
        ("missing", w.dir.join("missing.git")),
    ] {
        rewrites.push_str(&format!(
            "[url \"file://{}\"]\n\tinsteadOf = {}\n",
            repo.display(),
            url(name)
        ));
    }
    w.gitconfig(&rewrites);
    w.init(&url("trigon-evidence"));
    w.config(&format!(
        "repo = \"{}\"\ndivergences = \"feed\"\n",
        url("trigon-evidence")
    ));
    seeded(
        &w.dir.join("other.git"),
        &[("keys/log.vkey", b"somebody's log\n")],
    );
    git(
        &w.dir,
        &["init", "--quiet", "--bare", "-b", "main", "successor.git"],
    );
    let next = w.log_key_for(SUCCESSOR, "successor.key");
    let succeed = |to: &str| {
        w.trigon(&[
            "log",
            "succeed",
            "--store",
            w.store.to_str().unwrap(),
            "--origin",
            SUCCESSOR,
            "--log-key",
            next.to_str().unwrap(),
            "--url",
            to,
        ])
    };
    let before = w.head();
    for (to, why) in [
        (url("trigon-evidence"), "is the evidence repository itself"),
        (
            "git@github.com:OWNER/trigon-evidence.git".to_string(),
            "is the evidence repository itself",
        ),
        (url("other"), "has keys/ on `main` already"),
        (url("missing"), "the log has not been ended"),
    ] {
        let said = refused(&succeed(&to));
        assert!(said.contains(why), "{to}: {said}");
        assert!(said.contains("othing was written"), "{to}: {said}");
        assert_eq!(w.head(), before, "{to}: something was pushed");
    }
    // The log has not ended: it is published into as before.
    ok(&w.trigon(&[
        "publish",
        "--store",
        w.store.to_str().unwrap(),
        "--heartbeat",
    ]));

    // The kill-switch set, the log ends into an empty repository, and the switch goes with it.
    w.plant(&[(
        "kill-switch",
        Some(b"stopped: reviewing the false-mismatch rate\n"),
    )]);
    let said = ok(&succeed(&url("successor")));
    assert!(said.contains("kill-switch set in"), "{said}");
    let there = w.dir.join("successor-clone");
    git(
        &w.dir,
        &[
            "clone",
            "--quiet",
            w.dir.join("successor.git").to_str().unwrap(),
            there.to_str().unwrap(),
        ],
    );
    assert_eq!(
        std::fs::read(there.join("kill-switch")).unwrap(),
        b"stopped: reviewing the false-mismatch rate\n"
    );
    // So a divergence is withheld there as it was in the ended log's repository.
    w.configure(
        SUCCESSOR,
        &next,
        &format!("repo = \"{}\"\ndivergences = \"feed\"\n", url("successor")),
    );
    let div = Package::new("div", true);
    let (d, _) = pair(&w, &div, "d1d1");
    let said = refused(&w.trigon(&["publish", "--store", w.store.to_str().unwrap(), &d]));
    assert!(said.contains("(kill_switch)"), "{said}");
}

/// A run whose record was pushed, and whose publisher was killed before step 7, is completed after
/// an in-repository succession against the log that holds its leaf: `published` names that log,
/// its leaf there and the commit that logged it, never the successor, whose leaf of the same index
/// is another leaf altogether.
#[test]
fn a_run_logged_before_a_succession_is_completed_against_its_own_log() {
    let w = World::new("complete-across-succession");
    w.init(w.remote.to_str().unwrap());
    let pa = Package::new("a", false);
    let (a, _) = pair(&w, &pa, "aaaa");
    let out = w
        .command(&[
            "publish",
            "--store",
            w.store.to_str().unwrap(),
            "--repo",
            w.remote.to_str().unwrap(),
            &a,
        ])
        .env("TRIGON_PUBLISH_DIE_AT", "pushed")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(137), "{}", text(&out));
    let logged = w.head();
    assert!(w.run(&a).published.is_none());

    let next = w.log_key_for(SUCCESSOR, "successor.key");
    ok(&w.log_command(
        "succeed",
        &["--origin", SUCCESSOR, "--log-key", next.to_str().unwrap()],
    ));
    w.configure(SUCCESSOR, &next, "");
    let said = ok(&w.publish(&[&a]));
    assert!(
        said.contains(&format!(
            "logged at leaf 0 of `{ORIGIN}` in commit {logged}"
        )),
        "{said}"
    );
    let p = w.run(&a).published.unwrap();
    assert_eq!((p.log, p.leaf, p.commit), (None, 0, logged));
    let clone = w.clone_fresh("reader");
    ok(&w.verify_record(&clone, &p.record));
}

/// With the feed on, the repository's kill-switch is what stands between a confirmed divergence
/// and its publication (ADR-0010 safeguard 5): while anything named `kill-switch` is on the branch
/// — a file, or a directory — the divergence is withheld, nothing is committed and there is no
/// feed; an equivalence, which it does not stop, publishes meanwhile; and once a person removes
/// it, the same divergence publishes with its entry.
#[test]
fn the_kill_switch_withholds_a_divergence_the_feed_would_publish() {
    let w = World::new("feed-kill-switch");
    w.init(w.remote.to_str().unwrap());
    w.config("divergences = \"feed\"\n");
    let div = Package::new("div", true);
    let (d, _) = pair(&w, &div, "d1d1");
    let withheld = |w: &World| {
        let before = (w.head(), w.commits());
        let said = refused(&w.publish(&[&d]));
        assert!(
            said.contains("the publication gate withholds it (kill_switch)"),
            "{said}"
        );
        assert!(said.contains("nothing was written"), "{said}");
        assert_eq!((w.head(), w.commits()), before);
        assert!(!w.clone_fresh("reader").join("feed").exists());
        assert!(w.run(&d).published.is_none());
    };
    w.plant(&[("kill-switch", Some(b"stopped\n"))]);
    withheld(&w);
    w.plant(&[
        ("kill-switch", None),
        ("kill-switch/why", Some(b"stopped\n")),
    ]);
    withheld(&w);

    let pe = Package::new("eq", false);
    let (e, _) = pair(&w, &pe, "e1e1");
    ok(&w.publish(&[&e]));

    w.plant(&[("kill-switch/why", None)]);
    ok(&w.publish(&[&d]));
    assert!(w.run(&d).published.is_some());
    let clone = w.clone_fresh("reader");
    let xml = std::fs::read_to_string(clone.join("feed/divergences.atom")).unwrap();
    let doc = roxmltree::Document::parse(&xml).unwrap();
    assert_eq!(atom(doc.root_element(), "entry").len(), 1);
}
