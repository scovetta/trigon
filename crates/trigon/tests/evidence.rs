//! `trigon evidence add`, `list`, `remove` and `sync`, through the binary, against evidence
//! repositories `trigon log init` and `trigon publish` build in local bare repositories: no network
//! (`docs/19` §6, §6.1, §10 phase 6).
//!
//! What each test holds, against the items of the phase: a source syncs from a `file://` URL, a
//! bare repository's path and a relative path, and from `TRIGON_EVIDENCE_REPO` with its keys; a
//! checkpoint that does not extend the accepted one — another log of the same size, pushed with
//! force — is refused with both signed notes and the old clone kept; a rollback behind the state is
//! refused, served or on disk; mirrors in agreement, one lagging, one equivocating; trust on first
//! use recorded once and labelled everywhere; stale from the last sync and frozen from the newest
//! leaf, time stated rather than waited for; a key change and a succession followed on sync, into
//! another repository too; a lost state reported and accepted only when asked, starting over only
//! what was lost; a sync stopped partway made again, never taken for one that finished; a branch
//! named as an option never fetched; a repository's own attributes changing nothing verified; a
//! source whose state cannot be read unknown, and the others answering; `add`, `list` and `remove`
//! keeping the file as it was; a project's file held to its rules, its successor to HTTPS, and its
//! sources labelled; and pruning one of an agreeing pair keeping the bytes the other names.
//!
//! Publishable runs are made the way phase 3 records them — two agreeing attempts at one cache key,
//! on two machines, two hours apart — from artifacts compared here, not built by podman, as
//! `publish.rs` makes them.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use trigon_attest::LocalKey;
use trigon_attest::log::{
    Checkpoint, DirFiles, HeartbeatLeaf, Leaf, LogSigner, SignedCheckpoint, Tree, plan_append,
    verify_log,
};
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

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A publisher and a consumer on one machine: a store, a home with `evidence.toml` in it, a
/// working directory, an empty bare repository, the attestation key and the log key.
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
            std::env::temp_dir().join(format!("trigon-evidence-{}-{name}", std::process::id()));
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

    fn config_path(&self) -> PathBuf {
        self.dir.join("home/.config/trigon/evidence.toml")
    }

    /// `evidence.toml`, with `[publish]` naming the origin, the dispute channel and the log key,
    /// and `extra` after them.
    fn config(&self, extra: &str) {
        std::fs::write(
            self.config_path(),
            format!(
                "[publish]\norigin = \"{ORIGIN}\"\ndisputes = \"{DISPUTES}\"\n\
                 log_key = \"{}\"\n{extra}",
                self.log_key.display()
            ),
        )
        .unwrap();
    }

    /// `trigon <args>` in the working directory, with this world's home, cache and state
    /// directories and none of this process's `TRIGON_*`. `git` may reach nothing but files.
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

    fn init(&self) {
        ok(&self.trigon(&[
            "log",
            "init",
            "--origin",
            ORIGIN,
            "--repo",
            self.remote.to_str().unwrap(),
            "--attestation-key",
            &attestation().public_hex(),
        ]));
    }

    fn attest(&self, id: &str) {
        ok(&self.trigon(&[
            "attest",
            id,
            "--store",
            self.store.to_str().unwrap(),
            "--key",
            self.key.to_str().unwrap(),
        ]));
    }

    fn publish(&self, args: &[&str]) -> Output {
        let mut all = vec![
            "publish",
            "--store",
            self.store.to_str().unwrap(),
            "--repo",
            self.remote.to_str().unwrap(),
        ];
        all.extend_from_slice(args);
        self.trigon(&all)
    }

    /// Publish a new agreeing pair of `name`, and return the id published.
    fn publish_package(&self, name: &str, tag: &str) -> String {
        let (a, _) = pair(self, &Package::new(name, false), tag);
        ok(&self.publish(&[&a]));
        a
    }

    fn vkey(&self) -> trigon_attest::LogVkey {
        LogSigner::from_file(&self.log_key).unwrap().vkey()
    }

    /// `trigon evidence add <name> <urls>` pinned to this world's keys, and `extra` after.
    fn add(&self, name: &str, urls: &[&str], extra: &[&str]) -> Output {
        let vkey = self.vkey().to_string();
        let key = attestation().public_hex();
        let mut args = vec!["evidence", "add", name];
        args.extend_from_slice(urls);
        args.extend_from_slice(&["--log-key", &vkey, "--attestation-key", &key]);
        args.extend_from_slice(extra);
        self.trigon(&args)
    }

    fn sync(&self, extra: &[&str]) -> Output {
        let mut args = vec!["evidence", "sync"];
        args.extend_from_slice(extra);
        self.trigon(&args)
    }

    /// `evidence list --output json`, by source name.
    fn list(&self) -> serde_json::Value {
        let out = self.trigon(&["evidence", "list", "--output", "json"]);
        let t = ok(&out);
        let rows: Vec<serde_json::Value> =
            serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {t}"));
        let mut by = serde_json::Map::new();
        for r in rows {
            by.insert(r["name"].as_str().unwrap().to_string(), r);
        }
        serde_json::Value::Object(by)
    }

    fn state(&self, name: &str) -> PathBuf {
        self.dir
            .join("home/.local/state/trigon/evidence")
            .join(name)
    }

    fn cache(&self, name: &str) -> PathBuf {
        self.dir.join("home/.cache/trigon/evidence").join(name)
    }

    /// The clones kept for a source.
    fn clones(&self, name: &str) -> Vec<PathBuf> {
        let mut out: Vec<PathBuf> = std::fs::read_dir(self.cache(name))
            .map(|d| {
                d.flatten()
                    .map(|e| e.path())
                    .filter(|p| p.join(".git").is_dir())
                    .collect()
            })
            .unwrap_or_default();
        out.sort();
        out
    }

    /// The remote's `log/checkpoint`, as the branch holds it.
    fn remote_checkpoint(&self, repo: &Path) -> Vec<u8> {
        Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["show", "main:log/checkpoint"])
            .output()
            .unwrap()
            .stdout
    }

    fn head(&self, repo: &Path) -> String {
        git(repo, &["rev-parse", "main"])
    }

    /// A bare copy of the remote as it is now, as a mirror serves it.
    fn mirror(&self, name: &str) -> PathBuf {
        let to = self.dir.join(name);
        let _ = std::fs::remove_dir_all(&to);
        git(
            &self.dir,
            &[
                "clone",
                "--quiet",
                "--bare",
                self.remote.to_str().unwrap(),
                to.to_str().unwrap(),
            ],
        );
        to
    }

    /// Commit, on top of `base` in the bare repository `repo`, a log that appends `leaves` to the
    /// log there, signed by this world's log key, and push it — with force where `force`: what
    /// whoever holds the log key and the push credential could do.
    fn append_signed(&self, repo: &Path, base: &str, leaves: Vec<Leaf>, force: bool) {
        let c = self.dir.join("forger");
        let _ = std::fs::remove_dir_all(&c);
        git(
            &self.dir,
            &[
                "clone",
                "--quiet",
                repo.to_str().unwrap(),
                c.to_str().unwrap(),
            ],
        );
        git(&c, &["reset", "--quiet", "--hard", base]);
        let log = verify_log(&DirFiles::new(c.join("log")), &self.vkey(), None).unwrap();
        let append = log.plan_append(&leaves).unwrap();
        for dir in &append.obsolete {
            let _ = std::fs::remove_dir_all(c.join("log").join(dir));
        }
        for (path, bytes) in &append.files {
            let p = c.join("log").join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, bytes).unwrap();
        }
        let signer = LogSigner::from_file(&self.log_key).unwrap();
        let signed = SignedCheckpoint::sign(
            &Checkpoint {
                origin: ORIGIN.into(),
                size: append.size,
                root: append.root,
            },
            &signer,
        )
        .unwrap();
        std::fs::write(c.join("log/checkpoint"), signed.to_string()).unwrap();
        git(&c, &["add", "--all", "--force"]);
        git(&c, &["commit", "--quiet", "-m", "appended by hand"]);
        let mut push = vec!["push", "--quiet"];
        if force {
            push.push("--force");
        }
        push.extend(["origin", "main"]);
        git(&c, &push);
    }
}

impl World {
    /// Replace everything `repo`'s branch holds with a log of `leaves` signed by `signer`, and
    /// `keys/` naming `signer` and `key`, pushed with force: what whoever holds the push credential
    /// and neither key could do.
    fn replace_log(&self, repo: &Path, signer: &LogSigner, key: &LocalKey, leaves: &[Leaf]) {
        let c = self.dir.join("thief");
        let _ = std::fs::remove_dir_all(&c);
        git(
            &self.dir,
            &["init", "--quiet", "-b", "main", c.to_str().unwrap()],
        );
        std::fs::create_dir_all(c.join("keys")).unwrap();
        std::fs::write(c.join("keys/log.vkey"), format!("{}\n", signer.vkey())).unwrap();
        std::fs::write(c.join("keys/attestation.pub"), key.public_pem()).unwrap();
        let encoded: Vec<Vec<u8>> = leaves.iter().map(|l| l.encode().unwrap()).collect();
        let append = plan_append(&Tree::new(), &[] as &[Vec<u8>], &encoded).unwrap();
        for (path, bytes) in &append.files {
            let p = c.join("log").join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, bytes).unwrap();
        }
        let signed = SignedCheckpoint::sign(
            &Checkpoint {
                origin: ORIGIN.into(),
                size: append.size,
                root: append.root,
            },
            signer,
        )
        .unwrap();
        std::fs::create_dir_all(c.join("log")).unwrap();
        std::fs::write(c.join("log/checkpoint"), signed.to_string()).unwrap();
        git(&c, &["add", "--all", "--force"]);
        git(&c, &["commit", "--quiet", "-m", "replaced"]);
        git(
            &c,
            &[
                "push",
                "--quiet",
                "--force",
                repo.to_str().unwrap(),
                "main",
            ],
        );
    }
}

/// A world a test passed in is removed; one it failed in is kept, to be looked at.
impl Drop for World {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

/// The attestation key every record here is signed with.
fn attestation() -> LocalKey {
    LocalKey::from_bytes(&[3; 32]).unwrap()
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

/// The output of a command that exited `code`.
fn exits(out: &Output, code: i32) -> String {
    let t = text(out);
    assert_eq!(out.status.code(), Some(code), "{t}");
    t
}

fn heartbeat(time: u64) -> Leaf {
    Leaf::Heartbeat(HeartbeatLeaf { time })
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
}

/// One attempt at `p`, as `record_run` writes one.
async fn attempt(store: &Store, id: &str, p: &Package, key: &str, host: char, started: &str) {
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
            egress: "mirror-only".into(),
            isolation: "user_ns".into(),
            guard_manifest: Some(guard.to_hex()),
            guarded_members: Some(1),
            attestable: true,
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
}

/// Two agreeing attempts at `p`, on two machines two hours apart: a pair the gate publishes. The
/// first is attested; both ids are returned, the first first.
fn pair(w: &World, p: &Package, tag: &str) -> (String, String) {
    let store = Store::local(&w.store).unwrap();
    let (a, b) = (
        format!("1789000000-{tag}0001"),
        format!("1789007200-{tag}0002"),
    );
    let key = format!("ck1:{tag}");
    rt().block_on(async {
        attempt(&store, &a, p, &key, 'a', "2026-09-27T00:00:00Z").await;
        attempt(&store, &b, p, &key, 'b', "2026-09-27T02:00:00Z").await;
    });
    w.attest(&a);
    (a, b)
}

// ---------------------------------------------------------------------------------------------
// Syncing
// ---------------------------------------------------------------------------------------------

/// A source syncs from a `file://` URL, from a bare repository's path, and from a relative path —
/// one written in `evidence.toml`, taken from the file's directory, and one given to `evidence
/// add` from the working directory — each verified, each state written only then. A remote is
/// cloned shallow, partial and sparse; a local path in full, and `-v` says so.
#[test]
fn a_source_syncs_from_a_file_url_a_bare_path_and_a_relative_path() {
    let w = World::new("locations");
    w.init();
    w.publish_package("a", "aaaa");
    let remote = w.remote.to_str().unwrap().to_string();
    // `home/.config/trigon/evidence.toml`, so the world's directory is three up from it.
    w.config(&format!(
        "\n[[source]]\nname = \"relative\"\nurls = [\"../../../remote.git\"]\nlog_key = \"{}\"\n\
         attestation_key = \"{}\"\n",
        w.vkey(),
        attestation().public_hex()
    ));
    ok(&w.add("url", &[&format!("file://{remote}")], &[]));
    ok(&w.add("path", &[&remote], &[]));
    // From the working directory, `project/`, and written to the file absolute.
    ok(&w.add("cwd", &["../remote.git"], &[]));
    let file = std::fs::read_to_string(w.config_path()).unwrap();
    assert!(file.contains(&format!("urls = [\"{remote}\"]")), "{file}");

    let said = ok(&w.trigon(&["-v", "evidence", "sync"]));
    for name in ["relative", "url", "path", "cwd"] {
        assert!(said.contains(&format!("source    `{name}`")), "{said}");
    }
    assert_eq!(
        said.matches("synced    `example.com/trigon-evidence`: 1 leaves")
            .count(),
        4,
        "{said}"
    );
    assert!(said.contains("(file): 1 leaves, answering"), "{said}");
    assert!(
        said.contains("(local path): 1 leaves, answering: a local path, cloned in full"),
        "{said}"
    );
    assert!(
        said.contains("the first that verifies under its log key is accepted"),
        "{said}"
    );

    // Each state holds the checkpoint accepted, byte for byte as the remote has it.
    for name in ["relative", "url", "path", "cwd"] {
        assert_eq!(
            std::fs::read(w.state(name).join("checkpoint")).unwrap(),
            w.remote_checkpoint(&w.remote),
            "{name}"
        );
        assert!(w.state(name).join("keys").is_file());
        assert!(w.state(name).join("sync").is_file());
    }
    // The `file://` clone is shallow and sparse: keys, log and records, and not index or
    // evidence. The local path's is a full clone.
    let url = &w.clones("url")[0];
    assert!(url.join(".git/shallow").is_file());
    for (path, there) in [
        ("keys", true),
        ("log", true),
        ("records", true),
        ("index", false),
        ("evidence", false),
    ] {
        assert_eq!(url.join(path).exists(), there, "{path}");
    }
    assert!(!w.clones("path")[0].join(".git/shallow").exists());
    // Every clone reads exactly the blobs, whatever the tree's attributes say.
    assert!(
        std::fs::read_to_string(url.join(".git/info/attributes"))
            .unwrap()
            .contains("-text")
    );

    let list = w.list();
    for name in ["relative", "url", "path", "cwd"] {
        assert_eq!(list[name]["standing"], "fresh", "{list}");
        assert_eq!(list[name]["size"], 1, "{list}");
        assert_eq!(list[name]["origin"], ORIGIN, "{list}");
    }
    assert_eq!(list["url"]["urls"][0]["transport"], "file");
    assert_eq!(list["path"]["urls"][0]["transport"], "local path");

    // A later sync fetches what was published since.
    w.publish_package("b", "bbbb");
    let said = ok(&w.sync(&["--source", "url", "--source", "path"]));
    assert!(
        said.matches("synced    `example.com/trigon-evidence`: 2 leaves")
            .count()
            == 2,
        "{said}"
    );
    assert!(
        !said.contains("`relative`"),
        "only the sources named: {said}"
    );
    assert_eq!(w.list()["url"]["size"], 2);
    // A source nobody configured is the tool failing, with the names that are configured.
    let said = exits(&w.sync(&["--source", "nothing"]), 5);
    assert!(said.contains("the sources configured are"), "{said}");
}

/// `--full-history` keeps each clone's whole git history, and says when a fetch is not a
/// fast-forward: history rewritten under a log that still verifies is shown, and the log decides.
#[test]
fn full_history_keeps_the_history_and_says_when_it_was_rewritten() {
    let w = World::new("full-history");
    w.init();
    w.publish_package("a", "aaaa");
    ok(&w.add("main", &[&format!("file://{}", w.remote.display())], &[]));
    ok(&w.sync(&[]));
    let clone = w.clones("main")[0].clone();
    assert!(clone.join(".git/shallow").is_file(), "shallow by default");
    ok(&w.sync(&["--full-history"]));
    assert!(
        !clone.join(".git/shallow").exists(),
        "the whole history is fetched"
    );
    assert_eq!(git(&clone, &["rev-list", "--count", "HEAD"]), "2");

    // The last commit rewritten, its tree and so its log unchanged, and pushed with force.
    let c = w.dir.join("rewriter");
    git(
        &w.dir,
        &[
            "clone",
            "--quiet",
            w.remote.to_str().unwrap(),
            c.to_str().unwrap(),
        ],
    );
    git(&c, &["commit", "--quiet", "--amend", "-m", "rewritten"]);
    git(&c, &["push", "--quiet", "--force", "origin", "main"]);
    let said = ok(&w.sync(&[]));
    assert!(said.contains("is not a fast-forward"), "{said}");
    assert!(said.contains("1 leaves, answering"), "{said}");
    // Kept whole from then on.
    assert!(!clone.join(".git/shallow").exists());
}

/// `TRIGON_EVIDENCE_REPO` adds a required source named `env`, pinned by the keys beside it; it
/// syncs like any other, from several locations, and `evidence remove` refuses it, saying why.
#[test]
fn trigon_evidence_repo_with_its_keys_syncs_as_a_required_source() {
    let w = World::new("env");
    w.init();
    w.publish_package("a", "aaaa");
    let remote = w.remote.to_str().unwrap();
    let env_command = |args: &[&str]| {
        let mut c = w.command(args);
        c.env("TRIGON_EVIDENCE_REPO", format!("file://{remote} {remote}"))
            .env("TRIGON_EVIDENCE_LOG_KEY", w.vkey().to_string())
            .env(
                "TRIGON_EVIDENCE_ATTESTATION_KEY",
                attestation().public_hex(),
            );
        c.output().unwrap()
    };
    let said = ok(&env_command(&["evidence", "sync"]));
    assert!(
        said.contains("source    `env`, from TRIGON_EVIDENCE_REPO"),
        "{said}"
    );
    assert!(said.contains("1 leaves, answering"), "{said}");
    let out = env_command(&["evidence", "list", "--output", "json"]);
    let rows: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(rows[0]["name"], "env");
    assert_eq!(rows[0]["required"], true);
    assert_eq!(rows[0]["addedBy"], "TRIGON_EVIDENCE_REPO");
    assert_eq!(rows[0]["standing"], "fresh");
    let said = exits(&env_command(&["evidence", "remove", "env"]), 5);
    assert!(said.contains("unset TRIGON_EVIDENCE_REPO"), "{said}");
    // Without both keys it is refused, unless it trusts on first use.
    let mut c = w.command(&["evidence", "sync"]);
    c.env("TRIGON_EVIDENCE_REPO", remote);
    let said = exits(&c.output().unwrap(), 5);
    assert!(said.contains("TRIGON_EVIDENCE_TOFU=1"), "{said}");
}

/// A checkpoint that does not extend the one accepted — another log of the same size under the
/// same key, pushed with force — is refused: both signed notes are printed, the clone is kept as
/// it was, the state is untouched, and every command asking the source exits 4 until a sync of it
/// works.
#[test]
fn a_checkpoint_that_does_not_extend_the_accepted_one_is_refused_and_the_clone_kept() {
    let w = World::new("not-extending");
    w.init();
    let first = w.head(&w.remote);
    w.publish_package("a", "aaaa");
    ok(&w.add("main", &[&format!("file://{}", w.remote.display())], &[]));
    ok(&w.sync(&[]));
    let accepted = std::fs::read(w.state("main").join("checkpoint")).unwrap();
    let clone = w.clones("main")[0].clone();
    let at = git(&clone, &["rev-parse", "HEAD"]);

    // One leaf, as the log the client accepted has, and another one: a heartbeat, not the record.
    w.append_signed(&w.remote, &first, vec![heartbeat(now())], true);
    let said = exits(&w.sync(&[]), 4);
    assert!(said.contains("REFUSED"), "{said}");
    assert!(said.contains("The checkpoint last accepted:"), "{said}");
    assert!(said.contains("The checkpoint offered:"), "{said}");
    assert!(
        said.contains(
            &String::from_utf8_lossy(&accepted)
                .lines()
                .next()
                .unwrap()
                .to_string()
        ),
        "{said}"
    );
    assert!(
        said.contains("every command asking `main` exits 4"),
        "{said}"
    );
    assert_eq!(git(&clone, &["rev-parse", "HEAD"]), at, "the clone is kept");
    assert_eq!(
        std::fs::read(w.state("main").join("checkpoint")).unwrap(),
        accepted,
        "the state is untouched"
    );
    let list = w.list();
    assert_eq!(list["main"]["standing"], "refused", "{list}");
    assert_eq!(list["main"]["failure"]["refused"], true, "{list}");
}

/// A checkpoint older than the one accepted is a rollback, and refused: served so by the
/// remote, or found so in the clone on disk, as a cache restored from an older job would hold it.
#[test]
fn a_rollback_behind_the_accepted_checkpoint_is_refused_served_or_on_disk() {
    let w = World::new("rollback");
    w.init();
    w.publish_package("a", "aaaa");
    let one = w.head(&w.remote);
    w.publish_package("b", "bbbb");
    let two = w.head(&w.remote);
    ok(&w.add("main", &[w.remote.to_str().unwrap()], &[]));
    ok(&w.sync(&[]));
    assert_eq!(w.list()["main"]["size"], 2);

    // Served: the remote's branch put back a publication.
    git(&w.remote, &["update-ref", "refs/heads/main", &one]);
    let said = exits(&w.sync(&[]), 4);
    assert!(
        said.contains("fewer than the 2 of the checkpoint last accepted"),
        "{said}"
    );
    assert!(said.contains("rollback"), "{said}");
    let clone = w.clones("main")[0].clone();
    assert_eq!(
        git(&clone, &["rev-parse", "HEAD"]),
        two,
        "the clone is kept"
    );

    // Put right, it syncs again, and the refusal no longer stands.
    git(&w.remote, &["update-ref", "refs/heads/main", &two]);
    ok(&w.sync(&[]));
    assert_eq!(w.list()["main"]["standing"], "fresh");

    // On disk: the clone put back behind the state, which a command reads it against.
    git(&clone, &["reset", "--quiet", "--hard", &one]);
    let list = w.list();
    assert_eq!(list["main"]["standing"], "refused", "{list}");
    assert!(
        list["main"]["why"]
            .as_str()
            .unwrap()
            .contains("fewer than the 2 of the checkpoint last accepted"),
        "{list}"
    );
}

/// Every URL of a source is fetched and verified, and they are held to one another: two in
/// agreement, one lagging, which is said and answered past; and one that serves another log of the
/// same size under the same key, which is an equivocation, printed with both signed notes, exit 4.
#[test]
fn mirrors_in_agreement_lagging_and_equivocating() {
    let w = World::new("mirrors");
    w.init();
    let first = w.head(&w.remote);
    w.publish_package("a", "aaaa");
    let lagging = w.mirror("lagging.git");
    w.publish_package("b", "bbbb");
    let agreeing = w.mirror("agreeing.git");
    let urls: Vec<String> = [&w.remote, &agreeing, &lagging]
        .iter()
        .map(|p| format!("file://{}", p.display()))
        .collect();
    let urls: Vec<&str> = urls.iter().map(String::as_str).collect();
    ok(&w.add("main", &urls, &[]));
    let said = ok(&w.sync(&[]));
    assert!(
        said.contains("remote.git (file): 2 leaves, answering"),
        "{said}"
    );
    assert!(
        said.contains("agreeing.git (file): 2 leaves, in agreement"),
        "{said}"
    );
    assert!(
        said.contains("lagging.git (file): 1 leaves, lagging"),
        "{said}"
    );
    assert!(said.contains("lagging.git is lagging: it serves"), "{said}");
    assert_eq!(w.clones("main").len(), 3);
    let accepted = std::fs::read(w.state("main").join("checkpoint")).unwrap();

    // One mirror serves another log: one leaf, where the others' first is a record.
    let other = w.mirror("equivocating.git");
    w.append_signed(&other, &first, vec![heartbeat(now())], true);
    let urls: Vec<String> = [&w.remote, &other]
        .iter()
        .map(|p| format!("file://{}", p.display()))
        .collect();
    let urls: Vec<&str> = urls.iter().map(String::as_str).collect();
    ok(&w.add("split", &urls, &[]));
    let said = exits(&w.sync(&["--source", "split"]), 4);
    assert!(
        said.contains("serve one source and are not one log"),
        "{said}"
    );
    assert!(
        said.contains("the smaller is not a prefix of the larger"),
        "{said}"
    );
    assert!(said.contains("equivocation"), "{said}");
    assert!(said.contains("remote.git`:"), "both signed notes: {said}");
    assert!(
        said.contains("equivocating.git`:"),
        "both signed notes: {said}"
    );
    assert!(
        !w.state("split").join("checkpoint").exists(),
        "nothing is accepted"
    );
    assert!(
        w.clones("split").is_empty(),
        "no clone of a refused first sync is kept"
    );
    // The other source is as it was.
    assert_eq!(
        std::fs::read(w.state("main").join("checkpoint")).unwrap(),
        accepted
    );
}

/// Trust on first use: a source that pins no key reads the repository's `keys/` on its first
/// sync, records them, and every answer from it says it rests on them — `evidence list`, and the
/// record form of `verify-attestation`, which reads the recorded keys instead of refusing it. The
/// first checkpoint that verifies is accepted, and said to be. `TRIGON_EVIDENCE_TOFU=1` does the
/// same for `TRIGON_EVIDENCE_REPO`.
#[test]
fn trust_on_first_use_is_recorded_once_and_every_answer_says_it_rests_on_it() {
    let w = World::new("tofu");
    w.init();
    w.publish_package("a", "aaaa");
    let remote = w.remote.to_str().unwrap();
    // Before its first sync the verifier has nothing to hold a record to.
    ok(&w.trigon(&["evidence", "add", "tofu", remote, "--trust-on-first-use"]));
    let file = std::fs::read_to_string(w.config_path()).unwrap();
    assert!(file.contains("trust_on_first_use = true"), "{file}");
    assert!(!file.contains("log_key = \"example.com"), "{file}");
    assert_eq!(w.list()["tofu"]["trust"], "first-use-pending");

    let said = ok(&w.sync(&[]));
    assert!(
        said.contains("trusting on first use: the log key"),
        "{said}"
    );
    assert!(
        said.contains("the first that verifies under its log key is accepted"),
        "{said}"
    );
    let keys: serde_json::Value =
        serde_json::from_slice(&std::fs::read(w.state("tofu").join("keys")).unwrap()).unwrap();
    assert_eq!(keys["logKey"], w.vkey().to_string());
    assert_eq!(keys["attestationKey"], attestation().public_hex());
    assert_eq!(keys["firstUse"]["readFrom"], remote);
    let list = w.list();
    assert_eq!(
        list["tofu"]["trust"]["firstUse"]["readFrom"], remote,
        "{list}"
    );
    assert!(
        list["tofu"]["label"]
            .as_str()
            .unwrap()
            .contains("resting on keys trusted on first use"),
        "{list}"
    );
    assert_eq!(
        list["tofu"]["origin"],
        format!("{ORIGIN} (read on first use)")
    );

    // The record form reads the recorded keys, and says what they rest on.
    let clone = w.clones("tofu")[0].clone();
    let record = std::fs::read_dir(clone.join("records"))
        .unwrap()
        .flatten()
        .flat_map(|a| std::fs::read_dir(a.path()).unwrap().flatten())
        .flat_map(|b| std::fs::read_dir(b.path()).unwrap().flatten())
        .map(|e| e.path())
        .next()
        .unwrap();
    let said = ok(&w.trigon(&[
        "verify-attestation",
        "--record",
        record.to_str().unwrap(),
        "--evidence",
        clone.to_str().unwrap(),
        "--source",
        "tofu",
    ]));
    assert!(
        said.contains("resting on keys trusted on first use"),
        "{said}"
    );
    assert!(
        said.contains("the log is held to the checkpoint of 1 leaves"),
        "{said}"
    );

    // The environment's form.
    let mut c = w.command(&["evidence", "sync", "--source", "env"]);
    c.env("TRIGON_EVIDENCE_REPO", format!("file://{remote}"))
        .env("TRIGON_EVIDENCE_TOFU", "1");
    let said = ok(&c.output().unwrap());
    assert!(said.contains("trusting on first use"), "{said}");
    assert!(w.state("env").join("keys").is_file());

    // What the repository's keys/ says afterwards changes nothing: the keys were read once.
    let other = LogSigner::from_seed(ORIGIN, [8; 32])
        .unwrap()
        .vkey()
        .to_string();
    let c = w.dir.join("planter");
    git(&w.dir, &["clone", "--quiet", remote, c.to_str().unwrap()]);
    std::fs::write(c.join("keys/log.vkey"), format!("{other}\n")).unwrap();
    git(&c, &["commit", "--quiet", "-am", "another key"]);
    git(&c, &["push", "--quiet", "origin", "main"]);
    ok(&w.sync(&[]));
    let again: serde_json::Value =
        serde_json::from_slice(&std::fs::read(w.state("tofu").join("keys")).unwrap()).unwrap();
    assert_eq!(again["logKey"], w.vkey().to_string());

    // A source first synced now reads keys/ as it now stands, and first contact is all it rests
    // on: the log does not verify under the key planted there, and nothing is accepted.
    ok(&w.trigon(&["evidence", "add", "late", remote, "--trust-on-first-use"]));
    let said = exits(&w.sync(&["--source", "late"]), 4);
    assert!(said.contains("carries no signature by"), "{said}");
    assert!(!w.state("late").join("checkpoint").exists());
}

/// Freshness has two clocks (`docs/19` §6): stale is read from the last sync that worked, and
/// frozen from the newest leaf's time, whatever the sync did. Time is stated — the sync record's
/// time, the leaves' — never waited for.
#[test]
fn stale_from_the_last_sync_and_frozen_from_the_newest_leaf() {
    let w = World::new("freshness");
    w.init();
    let first = w.head(&w.remote);
    ok(&w.add("main", &[w.remote.to_str().unwrap()], &[]));
    // A log of no leaf says nothing about how recent it is: frozen.
    ok(&w.sync(&[]));
    assert_eq!(w.list()["main"]["standing"], "frozen");

    // One heartbeat, logged thirty days ago: synced now, and frozen.
    let month = now() - 30 * 86_400;
    w.append_signed(&w.remote, &first, vec![heartbeat(month)], false);
    ok(&w.sync(&[]));
    let list = w.list();
    assert_eq!(list["main"]["standing"], "frozen", "{list}");
    assert_eq!(list["main"]["newestLeaf"], month);
    // Frozen is measured against `frozen_after`: sixty days, and it is fresh.
    let file = std::fs::read_to_string(w.config_path()).unwrap();
    std::fs::write(
        w.config_path(),
        format!("{file}\n[freshness]\nfrozen_after = \"60d\"\n"),
    )
    .unwrap();
    assert_eq!(w.list()["main"]["standing"], "fresh");

    // Stale: the last sync that worked was two days ago.
    let path = w.state("main").join("sync");
    let mut record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    record["lastSuccess"] = serde_json::json!(now() - 2 * 86_400);
    std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
    let list = w.list();
    assert_eq!(list["main"]["standing"], "unknown", "{list}");
    assert!(
        list["main"]["why"]
            .as_str()
            .unwrap()
            .contains("it is stale"),
        "{list}"
    );
    // A sync puts it right.
    ok(&w.sync(&[]));
    assert_eq!(w.list()["main"]["standing"], "fresh");
}

/// A key change and a succession in the same repository are followed on sync, and the state keeps
/// the key history the log gives: every log of the chain and every attestation key. A history in
/// the state that disagrees with the log is reported, and the log wins.
#[test]
fn a_key_change_and_a_succession_are_followed_on_sync() {
    let w = World::new("rotations");
    w.init();
    w.publish_package("a", "aaaa");
    let new = w.dir.join("signing-2.key");
    let seed: String = LocalKey::from_bytes(&[4; 32])
        .unwrap()
        .seed()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    std::fs::write(&new, format!("{seed}\n")).unwrap();
    let rotate = |sub: &str, args: &[&str]| {
        let mut all = vec![
            "log",
            sub,
            "--store",
            w.store.to_str().unwrap(),
            "--repo",
            w.remote.to_str().unwrap(),
        ];
        all.extend_from_slice(args);
        ok(&w.trigon(&all))
    };
    rotate(
        "key-change",
        &[
            "--key",
            w.key.to_str().unwrap(),
            "--new-key",
            new.to_str().unwrap(),
        ],
    );
    let next = w.dir.join("successor.key");
    ok(&w.trigon(&[
        "log",
        "keygen",
        "--origin",
        "example.com/trigon-evidence/1",
        "--out",
        next.to_str().unwrap(),
    ]));
    rotate(
        "succeed",
        &[
            "--origin",
            "example.com/trigon-evidence/1",
            "--log-key",
            next.to_str().unwrap(),
        ],
    );
    ok(&w.add("main", &[w.remote.to_str().unwrap()], &[]));
    let said = ok(&w.sync(&[]));
    assert!(
        said.contains("synced    `example.com/trigon-evidence/1`: 1 leaves"),
        "{said}"
    );
    assert!(
        said.contains("the last of the 2 logs of its chain"),
        "{said}"
    );
    let keys: serde_json::Value =
        serde_json::from_slice(&std::fs::read(w.state("main").join("keys")).unwrap()).unwrap();
    assert_eq!(keys["logs"].as_array().unwrap().len(), 2, "{keys}");
    assert_eq!(keys["logs"][1]["origin"], "example.com/trigon-evidence/1");
    let epochs = keys["attestationKeys"].as_array().unwrap();
    assert_eq!(epochs.len(), 2, "{keys}");
    assert_eq!(epochs[0]["publicKey"], attestation().public_hex());
    assert_eq!(epochs[1]["from"]["index"], 1);
    // The accepted checkpoint is the successor's, the chain's last log.
    let accepted =
        String::from_utf8(std::fs::read(w.state("main").join("checkpoint")).unwrap()).unwrap();
    assert!(
        accepted.starts_with("example.com/trigon-evidence/1\n"),
        "{accepted}"
    );

    // A history kept that says less than the log: reported, and written again from the log.
    let mut edited = keys.clone();
    edited["attestationKeys"][1]["publicKey"] = serde_json::json!("00".repeat(32));
    std::fs::write(
        w.state("main").join("keys"),
        serde_json::to_vec(&edited).unwrap(),
    )
    .unwrap();
    let said = ok(&w.sync(&[]));
    assert!(
        said.contains("disagrees with the log, and the log wins"),
        "{said}"
    );
    let back: serde_json::Value =
        serde_json::from_slice(&std::fs::read(w.state("main").join("keys")).unwrap()).unwrap();
    assert_eq!(back, keys);
}

/// A succession into another repository is followed on sync as part of the same source: the
/// successor's repository, named by a URL the log-end gives, is cloned and verified too, and the
/// accepted checkpoint is the successor's.
#[test]
fn a_succession_into_another_repository_is_followed_on_sync() {
    let w = World::new("successor-elsewhere");
    w.init();
    w.publish_package("a", "aaaa");
    git(
        &w.dir,
        &["init", "--quiet", "--bare", "-b", "main", "successor.git"],
    );
    // A URL anyone could clone, which git here reaches as the bare repository beside it.
    let url = "https://github.com/owner/successor.git";
    std::fs::write(
        w.dir.join("home/.gitconfig"),
        format!(
            "[url \"file://{}\"]\n\tinsteadOf = {url}\n",
            w.dir.join("successor.git").display()
        ),
    )
    .unwrap();
    let next = w.dir.join("successor.key");
    ok(&w.trigon(&[
        "log",
        "keygen",
        "--origin",
        "example.com/trigon-evidence/1",
        "--out",
        next.to_str().unwrap(),
    ]));
    ok(&w.trigon(&[
        "log",
        "succeed",
        "--store",
        w.store.to_str().unwrap(),
        "--repo",
        w.remote.to_str().unwrap(),
        "--origin",
        "example.com/trigon-evidence/1",
        "--log-key",
        next.to_str().unwrap(),
        "--url",
        url,
    ]));
    ok(&w.add("main", &[w.remote.to_str().unwrap()], &[]));
    let said = ok(&w.sync(&[]));
    assert!(
        said.contains(
            "successor `example.com/trigon-evidence/1` is followed into another repository"
        ),
        "{said}"
    );
    assert!(
        said.contains(&format!("url       {url} (https): 1 leaves, answering")),
        "{said}"
    );
    assert_eq!(w.clones("main").len(), 2, "a clone of each repository");
    let accepted =
        String::from_utf8(std::fs::read(w.state("main").join("checkpoint")).unwrap()).unwrap();
    assert!(
        accepted.starts_with("example.com/trigon-evidence/1\n"),
        "{accepted}"
    );
    assert_eq!(w.list()["main"]["standing"], "fresh");

    // Publishing goes on in the successor, standing on the whole chain, which it reads through
    // the source; a sync follows it there.
    let successor = w.dir.join("successor.git");
    let begun = w.head(&successor);
    let file = std::fs::read_to_string(w.config_path()).unwrap();
    std::fs::write(
        w.config_path(),
        file.replace(
            &format!("origin = \"{ORIGIN}\""),
            "origin = \"example.com/trigon-evidence/1\"",
        )
        .replace(
            &format!("log_key = \"{}\"", w.log_key.display()),
            &format!("log_key = \"{}\"", next.display()),
        ),
    )
    .unwrap();
    let (b, _) = pair(&w, &Package::new("b", false), "bbbb");
    let said = ok(&w.trigon(&[
        "publish",
        "--store",
        w.store.to_str().unwrap(),
        "--repo",
        successor.to_str().unwrap(),
        &b,
    ]));
    assert!(
        said.contains("the whole chain is read, from the evidence source `main`"),
        "{said}"
    );
    let said = ok(&w.sync(&[]));
    assert!(
        said.contains("synced    `example.com/trigon-evidence/1`: 2 leaves"),
        "{said}"
    );
    // Held to it: the successor rolled back behind what was accepted is refused.
    git(&successor, &["update-ref", "refs/heads/main", &begun]);
    let said = exits(&w.sync(&[]), 4);
    assert!(
        said.contains("fewer than the 2 of the checkpoint last accepted"),
        "{said}"
    );
}

/// A source that has synced before and lost its state is reported, never silently given a new
/// one: the sync is refused, and the state stays missing, until `--accept-state-loss` names it.
#[test]
fn a_lost_state_is_reported_and_accepted_only_when_asked() {
    let w = World::new("state-loss");
    w.init();
    w.publish_package("a", "aaaa");
    ok(&w.add("main", &[w.remote.to_str().unwrap()], &[]));
    ok(&w.sync(&[]));
    std::fs::remove_file(w.state("main").join("checkpoint")).unwrap();

    let said = exits(&w.sync(&[]), 4);
    assert!(said.contains("its state is gone"), "{said}");
    assert!(said.contains("--accept-state-loss main"), "{said}");
    assert!(
        !w.state("main").join("checkpoint").exists(),
        "not silently made again"
    );
    assert_eq!(w.list()["main"]["standing"], "refused");
    // Naming a source not being synced is refused.
    let said = exits(&w.sync(&["--accept-state-loss", "other"]), 5);
    assert!(
        said.contains("no source being synced is named that"),
        "{said}"
    );

    let said = ok(&w.sync(&["--accept-state-loss", "main"]));
    assert!(said.contains("state loss accepted"), "{said}");
    assert!(w.state("main").join("checkpoint").exists());
    assert_eq!(w.list()["main"]["standing"], "fresh");
}

/// A sync stopped partway — killed while `git clone` ran, or after it and before the clone was
/// accepted — leaves nothing that looks like a sync that finished: the next sync is a first sync,
/// not a refusal, and makes the clone again, and the source then answers from it. Once it has
/// synced, a state lost — the whole directory, as on a new machine whose cache step kept the
/// clones — is refused until `--accept-state-loss`.
#[test]
fn a_sync_stopped_before_it_was_accepted_is_made_again_and_a_later_loss_refused() {
    let w = World::new("stopped");
    w.init();
    w.publish_package("a", "aaaa");
    ok(&w.add("main", &[&format!("file://{}", w.remote.display())], &[]));
    ok(&w.sync(&[]));
    let clone = w.clones("main")[0].clone();
    let name = clone.file_name().unwrap().to_str().unwrap().to_string();

    // Killed while `git clone` ran: a clone begun beside where it goes, and no state.
    std::fs::remove_dir_all(w.state("main")).unwrap();
    std::fs::remove_dir_all(&clone).unwrap();
    let making = w.cache("main").join(format!(".{name}.making"));
    git(&w.dir, &["init", "--quiet", making.to_str().unwrap()]);
    let said = ok(&w.sync(&[]));
    assert!(
        said.contains("the first that verifies under its log key is accepted"),
        "{said}"
    );
    assert!(!making.exists(), "what the stopped sync left is gone");

    // Killed after the clone and before it was accepted: the clone still marked, and no state.
    std::fs::remove_dir_all(w.state("main")).unwrap();
    std::fs::write(clone.join(".git/trigon-unaccepted"), b"").unwrap();
    let said = ok(&w.sync(&[]));
    assert!(
        said.contains("the first that verifies under its log key is accepted"),
        "{said}"
    );
    assert!(
        !clone.join(".git/trigon-unaccepted").exists(),
        "made again, and accepted"
    );
    assert_eq!(w.list()["main"]["standing"], "fresh");

    // It has synced now: the whole state directory lost is refused, not started over.
    std::fs::remove_dir_all(w.state("main")).unwrap();
    let said = exits(&w.sync(&[]), 4);
    assert!(said.contains("its clones are in"), "{said}");
    assert!(said.contains("--accept-state-loss main"), "{said}");
    assert!(!w.state("main").join("checkpoint").exists());
    assert_eq!(w.list()["main"]["standing"], "refused");
    ok(&w.sync(&["--accept-state-loss", "main"]));
    assert_eq!(w.list()["main"]["standing"], "fresh");
}

/// Accepting a lost state starts over only what was lost. A source trusting on first use that lost
/// its checkpoint keeps the keys it first read, so a log under keys swapped in since is still
/// refused, and the verifier refuses the lost checkpoint as the sync does; one that lost its keys
/// reads them again, and the checkpoint it kept must open under them, so swapped keys are refused
/// there too; put back, the keys read again are the ones it opens under, and it is accepted.
#[test]
fn accepting_a_lost_state_keeps_what_survives_of_it() {
    let w = World::new("partial-loss");
    w.init();
    w.publish_package("a", "aaaa");
    let remote = w.remote.to_str().unwrap();
    ok(&w.trigon(&["evidence", "add", "tofu", remote, "--trust-on-first-use"]));
    ok(&w.sync(&[]));
    let good = w.head(&w.remote);
    let keys = std::fs::read(w.state("tofu").join("keys")).unwrap();
    let clone = w.clones("tofu")[0].clone();
    let record = std::fs::read_dir(clone.join("records"))
        .unwrap()
        .flatten()
        .flat_map(|a| std::fs::read_dir(a.path()).unwrap().flatten())
        .flat_map(|b| std::fs::read_dir(b.path()).unwrap().flatten())
        .map(|e| e.path())
        .next()
        .unwrap();
    // Whoever holds the push credential puts a log under keys of their own in its place.
    let thief = LogSigner::from_seed(ORIGIN, [8; 32]).unwrap();
    let thiefs = LocalKey::from_bytes(&[9; 32]).unwrap();
    w.replace_log(&w.remote, &thief, &thiefs, &[heartbeat(now())]);

    // The checkpoint lost: the keys first read still pin the source.
    std::fs::remove_file(w.state("tofu").join("checkpoint")).unwrap();
    let said = exits(&w.sync(&[]), 4);
    assert!(said.contains("still under the keys first read from"), "{said}");
    let said = exits(
        &w.trigon(&[
            "verify-attestation",
            "--record",
            record.to_str().unwrap(),
            "--evidence",
            clone.to_str().unwrap(),
            "--source",
            "tofu",
        ]),
        5,
    );
    assert!(said.contains("has synced before"), "{said}");
    assert!(said.contains("--accept-state-loss tofu"), "{said}");
    let said = exits(&w.sync(&["--accept-state-loss", "tofu"]), 4);
    assert!(said.contains("REFUSED"), "{said}");
    assert!(said.contains("carries no signature by"), "{said}");
    assert_eq!(
        std::fs::read(w.state("tofu").join("keys")).unwrap(),
        keys,
        "the keys first read are kept"
    );
    git(&w.remote, &["update-ref", "refs/heads/main", &good]);
    ok(&w.sync(&["--accept-state-loss", "tofu"]));

    // The keys lost: read again, and held to the checkpoint kept, which they do not open.
    w.replace_log(&w.remote, &thief, &thiefs, &[heartbeat(now())]);
    std::fs::remove_file(w.state("tofu").join("keys")).unwrap();
    let said = exits(&w.sync(&[]), 4);
    assert!(said.contains("holds no keys first read"), "{said}");
    assert!(
        said.contains("the checkpoint last accepted, which is kept, must open under them"),
        "{said}"
    );
    let said = exits(&w.sync(&["--accept-state-loss", "tofu"]), 4);
    assert!(said.contains("REFUSED"), "{said}");
    assert!(!w.state("tofu").join("keys").exists(), "nothing recorded");
    // Put back, the keys read again open it, and are recorded.
    git(&w.remote, &["update-ref", "refs/heads/main", &good]);
    let said = ok(&w.sync(&["--accept-state-loss", "tofu"]));
    assert!(said.contains("state loss accepted"), "{said}");
    assert!(said.contains("trusting on first use: the log key"), "{said}");
    let again: serde_json::Value =
        serde_json::from_slice(&std::fs::read(w.state("tofu").join("keys")).unwrap()).unwrap();
    assert_eq!(again["logKey"], w.vkey().to_string());
}

/// A repository's default branch is its own to name, and one named as an option — here
/// `--upload-pack=<command>`, which a bare `git fetch origin <branch>` would run — is refused
/// before anything is fetched: nothing runs, on a first sync or any later one.
#[test]
fn a_branch_named_as_an_option_is_never_fetched() {
    let w = World::new("branch-option");
    w.init();
    w.publish_package("a", "aaaa");
    let branch = "refs/heads/--upload-pack=touch${IFS}$HOME/ran;git-upload-pack";
    git(&w.remote, &["update-ref", branch, "main"]);
    git(&w.remote, &["symbolic-ref", "HEAD", branch]);
    ok(&w.add("url", &[&format!("file://{}", w.remote.display())], &[]));
    ok(&w.add("path", &[w.remote.to_str().unwrap()], &[]));
    for _ in 0..2 {
        let said = exits(&w.sync(&[]), 4);
        assert_eq!(
            said.matches("failed    it could not be synced").count(),
            2,
            "{said}"
        );
        assert!(
            said.contains("which is not a name git makes a branch of, so it is not fetched"),
            "{said}"
        );
    }
    assert!(
        !w.dir.join("home/ran").exists(),
        "the branch's name was run as a command"
    );
    assert!(w.clones("url").is_empty() && w.clones("path").is_empty());
}

/// A source whose state cannot be read answers unknown, saying why, and every other source
/// answers as it is: sync, and failure, are per source.
#[test]
fn a_source_whose_state_cannot_be_read_is_unknown_and_the_others_answer() {
    let w = World::new("state-unreadable");
    w.init();
    w.publish_package("a", "aaaa");
    ok(&w.add("a", &[w.remote.to_str().unwrap()], &[]));
    ok(&w.add("b", &[w.remote.to_str().unwrap()], &[]));
    ok(&w.sync(&[]));
    std::fs::write(w.state("a").join("sync"), "not a record\n").unwrap();
    let list = w.list();
    assert_eq!(list["b"]["standing"], "fresh", "{list}");
    assert_eq!(list["a"]["standing"], "unknown", "{list}");
    assert!(
        list["a"]["why"]
            .as_str()
            .unwrap()
            .contains("it is not a sync record this build reads"),
        "{list}"
    );
    assert!(
        list["a"]["stateUnreadable"]
            .as_str()
            .unwrap()
            .contains("/a/sync"),
        "{list}"
    );
    let said = ok(&w.trigon(&["evidence", "list"]));
    assert!(said.contains("state     cannot be read"), "{said}");
    assert!(said.contains("source    `b`"), "{said}");
    // A sync says the same of `a`, and syncs `b`.
    let said = exits(&w.sync(&[]), 4);
    assert!(said.contains("synced    `example.com/trigon-evidence`"), "{said}");
    assert!(said.contains("it is not a sync record this build reads"), "{said}");
}

/// Every clone reads exactly the blobs, whatever the repository's own attributes say: a tree whose
/// `.gitattributes` would check every file out with CRLF line ends is verified byte for byte,
/// cloned from a `file://` URL and from a path, and fetched into clones made before it.
#[test]
fn a_repositorys_own_attributes_never_change_what_is_verified() {
    let w = World::new("attributes");
    w.init();
    w.publish_package("a", "aaaa");
    let url = format!("file://{}", w.remote.display());
    let path = w.remote.to_str().unwrap();
    ok(&w.add("url", &[&url], &[]));
    ok(&w.add("path", &[path], &[]));
    ok(&w.sync(&[]));
    // A leaf appended, and then attributes committed on top, as whoever can push could.
    let head = w.head(&w.remote);
    w.append_signed(&w.remote, &head, vec![heartbeat(now())], false);
    let c = w.dir.join("attributes");
    git(&w.dir, &["clone", "--quiet", path, c.to_str().unwrap()]);
    std::fs::write(c.join(".gitattributes"), "* text eol=crlf ident\n").unwrap();
    git(&c, &["add", ".gitattributes"]);
    git(&c, &["commit", "--quiet", "-m", "attributes"]);
    git(&c, &["push", "--quiet", "origin", "main"]);
    // Clones made now check out a tree that names them.
    ok(&w.add("url-new", &[&url], &[]));
    ok(&w.add("path-new", &[path], &[]));
    let said = ok(&w.sync(&[]));
    assert_eq!(
        said.matches("synced    `example.com/trigon-evidence`: 2 leaves")
            .count(),
        4,
        "{said}"
    );
    let blob = w.remote_checkpoint(&w.remote);
    assert!(!blob.contains(&b'\r'));
    for name in ["url", "path", "url-new", "path-new"] {
        let clone = &w.clones(name)[0];
        assert_eq!(
            std::fs::read(clone.join("log/checkpoint")).unwrap(),
            blob,
            "{name}"
        );
        assert_eq!(
            std::fs::read(w.state(name).join("checkpoint")).unwrap(),
            blob,
            "{name}"
        );
    }
}

/// `evidence add` writes a source into the user's file keeping every comment and the order of what
/// is there, and `evidence remove` takes it out again, leaving the file as it was. A name any
/// source has is refused, ignoring case, and so is a source that pins no key without trusting on
/// first use. A source the project's file or the environment added is not removed, and says why.
#[test]
fn add_list_and_remove_keep_the_file_as_it_was() {
    let w = World::new("add-remove");
    w.init();
    let original = format!(
        "# The evidence I trust.\n[publish]\norigin = \"{ORIGIN}\"   # mine\n\
         disputes = \"{DISPUTES}\"\nlog_key = \"{}\"\n\n# Freshness, tightened.\n[freshness]\n\
         stale_after = \"12h\"\n",
        w.log_key.display()
    );
    std::fs::write(w.config_path(), &original).unwrap();
    let said = ok(&w.add("Main", &[w.remote.to_str().unwrap()], &["--required"]));
    assert!(
        said.contains(&format!("origin    {ORIGIN}, the log key's name")),
        "{said}"
    );
    let file = std::fs::read_to_string(w.config_path()).unwrap();
    assert!(file.starts_with(original.trim_end()), "{file}");
    assert!(
        file.contains("# mine") && file.contains("# Freshness, tightened."),
        "{file}"
    );
    assert!(file.contains("[[source]]\nname = \"Main\""), "{file}");
    assert!(file.contains("required = true"), "{file}");
    let list = w.list();
    assert_eq!(list["Main"]["required"], true);
    assert_eq!(list["Main"]["standing"], "unknown", "never synced");

    // Taken, whatever the case.
    let said = exits(&w.add("main", &[w.remote.to_str().unwrap()], &[]), 5);
    assert!(said.contains("is configured already"), "{said}");
    let said = exits(
        &w.trigon(&["evidence", "add", "nokeys", w.remote.to_str().unwrap()]),
        5,
    );
    assert!(said.contains("--trust-on-first-use"), "{said}");
    let said = exits(
        &w.add(
            "both",
            &[w.remote.to_str().unwrap()],
            &["--trust-on-first-use"],
        ),
        5,
    );
    assert!(said.contains("nothing to trust on first use"), "{said}");
    // A checkpoint the log key does not open is refused now, not on the first sync.
    let bad = w.dir.join("bad.checkpoint");
    std::fs::write(&bad, "not a checkpoint\n").unwrap();
    let said = exits(
        &w.add(
            "cp",
            &[w.remote.to_str().unwrap()],
            &["--checkpoint", bad.to_str().unwrap()],
        ),
        5,
    );
    assert!(
        said.contains("is not a checkpoint the log key opens"),
        "{said}"
    );
    assert_eq!(
        std::fs::read_to_string(w.config_path()).unwrap(),
        file,
        "a refusal writes nothing"
    );

    ok(&w.sync(&[]));
    assert!(w.state("Main").exists() && w.cache("Main").exists());
    let said = ok(&w.trigon(&["evidence", "remove", "MAIN"]));
    assert!(said.contains("removed   `Main`"), "{said}");
    assert_eq!(std::fs::read_to_string(w.config_path()).unwrap(), original);
    assert!(!w.state("Main").exists() && !w.cache("Main").exists());
    let said = exits(&w.trigon(&["evidence", "remove", "Main"]), 5);
    assert!(
        said.contains("no evidence source is named `Main`"),
        "{said}"
    );
}

/// A project's `.trigon/evidence.toml` may only add sources, each with both keys and a checkpoint
/// pinned and HTTPS URLs only, and a file that tries anything else is refused whole: a URL added to
/// an existing source, trust on first use, an `http://` or `file://` URL, `required`. A source it
/// adds syncs like any other, and everything about it names the file that added it; `evidence
/// remove` leaves it to the project.
#[test]
fn a_projects_file_is_held_to_its_rules_and_its_sources_name_it() {
    let w = World::new("project");
    w.init();
    w.publish_package("a", "aaaa");
    ok(&w.add("trigon", &[w.remote.to_str().unwrap()], &[]));
    let url = "https://example.org/theirs.git";
    std::fs::write(
        w.dir.join("home/.gitconfig"),
        format!(
            "[url \"file://{}\"]\n\tinsteadOf = {url}\n",
            w.remote.display()
        ),
    )
    .unwrap();
    let project = w.dir.join("project/.trigon");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("theirs.checkpoint"),
        w.remote_checkpoint(&w.remote),
    )
    .unwrap();
    let source = |name: &str, url: &str, extra: &str| {
        format!(
            "[[source]]\nname = \"{name}\"\nurls = [\"{url}\"]\nlog_key = \"{}\"\n\
             attestation_key = \"{}\"\ncheckpoint = \"theirs.checkpoint\"\n{extra}",
            w.vkey(),
            attestation().public_hex()
        )
    };
    for (bad, rule) in [
        (source("trigon", url, ""), "already configured"),
        (source("TRIGON", url, ""), "already configured"),
        (
            source("theirs", url, "trust_on_first_use = true\n"),
            "trust_on_first_use",
        ),
        (
            source("theirs", "http://example.org/theirs.git", ""),
            "HTTPS only",
        ),
        (
            source("theirs", &format!("file://{}", w.remote.display()), ""),
            "HTTPS only",
        ),
        (source("theirs", url, "required = true\n"), "`required`"),
    ] {
        std::fs::write(project.join("evidence.toml"), &bad).unwrap();
        for args in [&["evidence", "list"][..], &["evidence", "sync"][..]] {
            let said = exits(&w.trigon(args), 5);
            assert!(said.contains(rule), "{bad}\n{said}");
            assert!(said.contains("is refused, all of it"), "{bad}\n{said}");
        }
    }

    std::fs::write(project.join("evidence.toml"), source("theirs", url, "")).unwrap();
    let said = ok(&w.sync(&["--source", "theirs"]));
    assert!(said.contains("added by the project's own"), "{said}");
    assert!(
        said.contains(&format!("url       {url} (https): 1 leaves, answering")),
        "{said}"
    );
    let list = w.list();
    assert_eq!(list["theirs"]["projectFile"], true, "{list}");
    assert!(
        list["theirs"]["label"]
            .as_str()
            .unwrap()
            .contains("added by the project's own"),
        "{list}"
    );
    let said = exits(&w.trigon(&["evidence", "remove", "theirs"]), 5);
    assert!(said.contains("the project's to change"), "{said}");
}

/// A project's source is fetched over HTTPS only, and so is where its log goes on: a log-end,
/// signed by the key the project pins, naming its successor at an `ssh://` location is refused, and
/// nothing is fetched from there. The same log added from the user's own file, which may name any
/// location, is followed.
#[test]
fn a_projects_source_follows_its_successor_over_https_only() {
    let w = World::new("project-successor");
    w.init();
    w.publish_package("a", "aaaa");
    let project = w.dir.join("project/.trigon");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("theirs.checkpoint"),
        w.remote_checkpoint(&w.remote),
    )
    .unwrap();
    git(
        &w.dir,
        &["init", "--quiet", "--bare", "-b", "main", "successor.git"],
    );
    let url = "https://example.org/theirs.git";
    let ssh = "ssh://attacker.example/successor.git";
    std::fs::write(
        w.dir.join("home/.gitconfig"),
        format!(
            "[url \"file://{}\"]\n\tinsteadOf = {url}\n[url \"file://{}\"]\n\tinsteadOf = {ssh}\n",
            w.remote.display(),
            w.dir.join("successor.git").display()
        ),
    )
    .unwrap();
    let next = w.dir.join("successor.key");
    ok(&w.trigon(&[
        "log",
        "keygen",
        "--origin",
        "example.com/trigon-evidence/1",
        "--out",
        next.to_str().unwrap(),
    ]));
    ok(&w.trigon(&[
        "log",
        "succeed",
        "--store",
        w.store.to_str().unwrap(),
        "--repo",
        w.remote.to_str().unwrap(),
        "--origin",
        "example.com/trigon-evidence/1",
        "--log-key",
        next.to_str().unwrap(),
        "--url",
        ssh,
    ]));
    std::fs::write(
        project.join("evidence.toml"),
        format!(
            "[[source]]\nname = \"theirs\"\nurls = [\"{url}\"]\nlog_key = \"{}\"\n\
             attestation_key = \"{}\"\ncheckpoint = \"theirs.checkpoint\"\n",
            w.vkey(),
            attestation().public_hex()
        ),
    )
    .unwrap();
    let said = exits(&w.sync(&["--source", "theirs"]), 4);
    assert!(said.contains("REFUSED"), "{said}");
    assert!(said.contains(&format!("names its successor at {ssh} (ssh)")), "{said}");
    assert!(said.contains("is fetched over HTTPS only"), "{said}");
    assert!(w.clones("theirs").is_empty(), "nothing is kept");
    assert_eq!(w.list()["theirs"]["standing"], "refused");

    ok(&w.add("mine", &[w.remote.to_str().unwrap()], &[]));
    let said = ok(&w.sync(&["--source", "mine"]));
    assert!(said.contains("is followed into another repository"), "{said}");
}

/// Two agreeing attempts rebuild byte-identical artifacts, which the store keeps as one blob:
/// pruning one keeps the bytes the other still names, which then attests as its record says it
/// can; and bytes a record says are kept and the store has lost are reported missing.
#[test]
fn pruning_one_of_an_agreeing_pair_keeps_the_bytes_the_other_names() {
    let w = World::new("prune-pair");
    let p = Package::new("a", false);
    let (a, b) = pair(&w, &p, "aaaa");
    let said = ok(&w.trigon(&[
        "attest",
        &a,
        "--store",
        w.store.to_str().unwrap(),
        "--key",
        w.key.to_str().unwrap(),
        "--prune",
    ]));
    assert!(said.contains(&format!("run {b} still names")), "{said}");
    // The second attempt's bytes are there, and it attests from them.
    w.attest(&b);
    let store = Store::local(&w.store).unwrap();
    let rebuilt = rt().block_on(store.get_run(&b)).unwrap().rebuild.unwrap();
    assert!(rt().block_on(store.kept(&rebuilt)).unwrap());

    // Lost from outside the store: said to be missing, never read as there.
    rt().block_on(store.blobs().delete(&rebuilt.sha256))
        .unwrap();
    let out = w.trigon(&[
        "attest",
        &b,
        "--store",
        w.store.to_str().unwrap(),
        "--key",
        w.key.to_str().unwrap(),
    ]);
    let said = text(&out);
    assert!(!out.status.success(), "{said}");
    assert!(said.contains("the bytes are missing"), "{said}");
}

/// The evidence commands say what there is when there is little: with no source configured,
/// `evidence list` says how to add one, and its JSON is an empty list, never an error;
/// `--accept-state-loss` names only a source being synced, exit 5, and nothing is synced; `evidence
/// add` with an initial checkpoint says the source is held to it; and `evidence list` says a
/// source trusting on first use has its keys still to read, and when a sync last failed, and why.
#[test]
fn the_evidence_commands_say_what_there_is_when_there_is_little() {
    let w = World::new("little");
    let said = ok(&w.trigon(&["evidence", "list"]));
    assert!(
        said.contains("no evidence source is configured. Add one with `trigon evidence add"),
        "{said}"
    );
    let out = w.trigon(&["evidence", "list", "--output", "json"]);
    ok(&out);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "[]");

    w.init();
    let remote = w.remote.to_str().unwrap();
    ok(&w.add("main", &[remote], &[]));
    ok(&w.add("other", &[remote], &[]));
    let said = exits(&w.sync(&["--source", "main", "--accept-state-loss", "other"]), 5);
    assert!(
        said.contains(
            "--accept-state-loss other: no source being synced is named that; name it with \
             --source too"
        ),
        "{said}"
    );
    let said = exits(&w.sync(&["--accept-state-loss", "nowhere"]), 5);
    assert!(
        said.contains("--accept-state-loss nowhere: no source being synced is named that"),
        "{said}"
    );
    assert!(!said.contains("--source too"), "{said}");
    assert!(!w.state("main").exists() && !w.state("other").exists());

    let initial = w.dir.join("initial.checkpoint");
    let out = Command::new("git")
        .arg("-C")
        .arg(&w.remote)
        .args(["show", "main:log/checkpoint"])
        .output()
        .unwrap();
    std::fs::write(&initial, out.stdout).unwrap();
    let said = ok(&w.add(
        "pinned",
        &[remote],
        &["--checkpoint", initial.to_str().unwrap()],
    ));
    assert!(
        said.contains(&format!("pinned    the initial checkpoint {}", initial.display())),
        "{said}"
    );

    ok(&w.trigon(&["evidence", "add", "tofu", remote, "--trust-on-first-use"]));
    let said = ok(&w.trigon(&["evidence", "list"]));
    assert!(
        said.contains(
            "trust     on first use: its keys will be read from the repository on its first sync"
        ),
        "{said}"
    );
    // A sync that fails is said, with when and why.
    std::fs::rename(&w.remote, w.dir.join("gone.git")).unwrap();
    exits(&w.sync(&["--source", "main"]), 4);
    let said = ok(&w.trigon(&["evidence", "list"]));
    assert!(
        said.lines()
            .any(|l| l.starts_with("failed    20") && l.contains("Z: ")),
        "{said}"
    );
}

/// Trust on first use reads only a key the source does not pin, and only from `keys/` of the first
/// location a first sync reaches: a location that cannot be reached is passed over for the next; a
/// key the source pins is used as pinned, on the first sync and every one after, whatever `keys/`
/// names, and the sync says which key it read; and a repository with no key to read, like no
/// location reached, gives nothing to trust, so nothing is accepted.
#[test]
fn trust_on_first_use_reads_only_what_is_not_pinned_from_the_first_location_reached() {
    let w = World::new("tofu-partial");
    w.init();
    w.publish_package("a", "aaaa");
    let remote = w.remote.to_str().unwrap();
    let recorded = |name: &str| -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(w.state(name).join("keys")).unwrap()).unwrap()
    };

    // The first location is not there: the keys are read from the second.
    let nowhere = w.dir.join("nowhere.git");
    ok(&w.trigon(&[
        "evidence",
        "add",
        "second",
        nowhere.to_str().unwrap(),
        remote,
        "--trust-on-first-use",
    ]));
    let said = ok(&w.sync(&["--source", "second"]));
    assert!(said.contains(nowhere.to_str().unwrap()), "{said}");
    let keys = recorded("second");
    assert_eq!(keys["firstUse"]["readFrom"], remote, "{keys}");
    assert_eq!(keys["logKey"], w.vkey().to_string(), "{keys}");
    assert!(w.state("second").join("checkpoint").is_file());

    // One key pinned, the other read: the pinned one as pinned, now and on the next sync, and the
    // sync says which was read and which is pinned.
    let vkey = w.vkey().to_string();
    let key = attestation().public_hex();
    let id = |hex: &str| {
        trigon_attest::AttestationKey::from_hex(hex)
            .unwrap()
            .key_id()
    };
    for (name, pin, note) in [
        (
            "log-pinned",
            ["--log-key", vkey.as_str()],
            format!(
                "the attestation key {}, beside the log key {vkey} the source pins, was read from \
                 {remote}'s keys/",
                id(&key)
            ),
        ),
        (
            "key-pinned",
            ["--attestation-key", key.as_str()],
            format!(
                "the log key {vkey}, beside the attestation key {} the source pins, was read from \
                 {remote}'s keys/",
                id(&key)
            ),
        ),
    ] {
        let mut args = vec!["evidence", "add", name, remote, "--trust-on-first-use"];
        args.extend(pin);
        ok(&w.trigon(&args));
        let said = ok(&w.sync(&["--source", name]));
        assert!(said.contains(&note), "{name}: {said}");
        let keys = recorded(name);
        assert_eq!(keys["logKey"], vkey, "{name}: {keys}");
        assert_eq!(keys["attestationKey"], key, "{name}: {keys}");
        assert_eq!(keys["firstUse"]["readFrom"], remote, "{name}: {keys}");
        ok(&w.sync(&["--source", name]));
        assert_eq!(recorded(name)["logKey"], vkey, "{name}");
    }

    // A pin that differs from what `keys/` publishes, so that a key read in its place would show.
    // An attestation key of its own is recorded as pinned, beside the log key read, on the first
    // sync and the next; the key `keys/attestation.pub` names is not taken.
    let other = LocalKey::from_bytes(&[4; 32]).unwrap().public_hex();
    assert_ne!(other, key);
    ok(&w.trigon(&[
        "evidence",
        "add",
        "other-key",
        remote,
        "--trust-on-first-use",
        "--attestation-key",
        &other,
    ]));
    let said = ok(&w.sync(&["--source", "other-key"]));
    assert!(
        said.contains(&format!(
            "the log key {vkey}, beside the attestation key {} the source pins, was read from \
             {remote}'s keys/",
            id(&other)
        )),
        "{said}"
    );
    for sync in ["first", "next"] {
        let keys = recorded("other-key");
        assert_eq!(keys["attestationKey"], other, "{sync}: {keys}");
        assert_eq!(
            keys["attestationKeys"][0]["publicKey"], other,
            "{sync}: {keys}"
        );
        assert_eq!(keys["logKey"], vkey, "{sync}: {keys}");
        assert_eq!(keys["firstUse"]["readFrom"], remote, "{sync}: {keys}");
        ok(&w.sync(&["--source", "other-key"]));
    }
    // And the record, signed by the key `keys/` names, is held to the pinned one, which did not
    // sign it: it fails verification, where the source pinned to the signing key answers.
    let lookup = |name: &str| {
        w.trigon(&[
            "lookup",
            "pkg:npm/demo-a@1.0.0",
            "--source",
            name,
            "--offline",
        ])
    };
    exits(&lookup("key-pinned"), 0);
    let said = exits(&lookup("other-key"), 4);
    assert!(said.contains("failed verification"), "{said}");
    // A log key of its own, of the same origin, is the one the checkpoint is held to: the log the
    // repository signs does not verify under it, and nothing is accepted or recorded.
    let other_log = LogSigner::from_seed(ORIGIN, [4; 32])
        .unwrap()
        .vkey()
        .to_string();
    assert_ne!(other_log, vkey);
    ok(&w.trigon(&[
        "evidence",
        "add",
        "other-log",
        remote,
        "--trust-on-first-use",
        "--log-key",
        &other_log,
    ]));
    exits(&w.sync(&["--source", "other-log"]), 4);
    assert!(!w.state("other-log").join("checkpoint").exists());
    assert!(!w.state("other-log").join("keys").exists());

    // A repository with no `keys/log.vkey`.
    let bare = w.dir.join("keyless.git");
    git(
        &w.dir,
        &["clone", "--quiet", "--bare", remote, bare.to_str().unwrap()],
    );
    let c = w.dir.join("keyless");
    git(
        &w.dir,
        &["clone", "--quiet", bare.to_str().unwrap(), c.to_str().unwrap()],
    );
    git(&c, &["rm", "--quiet", "keys/log.vkey"]);
    git(&c, &["commit", "--quiet", "-m", "no key"]);
    git(&c, &["push", "--quiet", "origin", "main"]);
    ok(&w.trigon(&[
        "evidence",
        "add",
        "keyless",
        bare.to_str().unwrap(),
        "--trust-on-first-use",
    ]));
    let said = exits(&w.sync(&["--source", "keyless"]), 4);
    assert!(
        said.contains("has no keys/log.vkey, so there is no key to trust on first use"),
        "{said}"
    );
    assert!(!w.state("keyless").join("checkpoint").exists());
    assert!(!w.state("keyless").join("keys").exists());

    // No location reached at all: nothing to read a key from.
    ok(&w.trigon(&[
        "evidence",
        "add",
        "unreached",
        nowhere.to_str().unwrap(),
        "--trust-on-first-use",
    ]));
    let said = exits(&w.sync(&["--source", "unreached"]), 4);
    assert!(
        said.contains(
            "`unreached` trusts on first use, and no location of it could be reached to read its \
             keys from"
        ),
        "{said}"
    );
    assert!(!w.state("unreached").join("keys").exists());
}

/// Whichever order a source lists its locations in, the one furthest ahead answers and one behind
/// it is said to lag; and a location whose log cannot be read — its leaves not there — is said to
/// be, and the others answer.
#[test]
fn the_location_furthest_ahead_answers_whatever_order_they_are_listed_in() {
    let w = World::new("mirror-order");
    w.init();
    w.publish_package("a", "aaaa");
    let lagging = w.mirror("lagging.git");
    w.publish_package("b", "bbbb");
    let damaged = w.mirror("damaged.git");
    let c = w.dir.join("damaging");
    git(
        &w.dir,
        &["clone", "--quiet", damaged.to_str().unwrap(), c.to_str().unwrap()],
    );
    git(&c, &["rm", "--quiet", "log/tile/entries/000.p/2"]);
    git(&c, &["commit", "--quiet", "-m", "leaves gone"]);
    git(&c, &["push", "--quiet", "origin", "main"]);
    let urls: Vec<String> = [&lagging, &damaged, &w.remote]
        .iter()
        .map(|p| format!("file://{}", p.display()))
        .collect();
    let urls: Vec<&str> = urls.iter().map(String::as_str).collect();
    ok(&w.add("main", &urls, &[]));
    let said = ok(&w.sync(&[]));
    for line in [
        "remote.git (file): 2 leaves, answering",
        "lagging.git (file): 1 leaves, lagging",
        "lagging.git is lagging: it serves",
        "damaged.git (file): unreachable",
        "its log could not be read",
    ] {
        assert!(said.contains(line), "{line}\n{said}");
    }
    let accepted = std::fs::read_to_string(w.state("main").join("checkpoint")).unwrap();
    assert_eq!(accepted.lines().nth(1), Some("2"), "{accepted}");
}

/// A state file found missing is said, never passed over (`docs/19` §6.1): the record of when a
/// source last synced, and its key history, are each made again on the next sync, which says it
/// was not there; the checkpoint last accepted, which is what a rollback is caught against, is
/// kept.
#[test]
fn a_missing_sync_record_or_key_history_is_made_again_and_said() {
    let w = World::new("state-missing");
    w.init();
    w.publish_package("a", "aaaa");
    ok(&w.add("main", &[w.remote.to_str().unwrap()], &[]));
    ok(&w.sync(&[]));
    let accepted = std::fs::read(w.state("main").join("checkpoint")).unwrap();
    for (file, says) in [
        (
            "sync",
            "was not there, so when this source last synced was not known until now",
        ),
        ("keys", "was not there, and is written again from the log"),
    ] {
        let path = w.state("main").join(file);
        std::fs::remove_file(&path).unwrap();
        let said = ok(&w.sync(&[]));
        assert!(
            said.contains(&format!("{} {says}", path.display())),
            "{file}: {said}"
        );
        assert!(path.is_file(), "{file}");
        assert_eq!(
            std::fs::read(w.state("main").join("checkpoint")).unwrap(),
            accepted
        );
    }
}
