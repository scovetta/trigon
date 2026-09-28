//! `trigon lookup`, `trigon check` against evidence sources, `verify-attestation --lookup` and
//! `--remote`, through the binary, against evidence repositories `trigon log init` and `trigon
//! publish` build in local bare repositories (`docs/19` §6, §6.1, §10 phase 6).
//!
//! "A machine whose only network access is to GitHub" is simulated the way phase 6a's tests do it:
//! every source is a local bare repository, reached by a `file://` URL, a path, or an HTTPS URL
//! that `url.<local>.insteadOf` rewrites, with `GIT_ALLOW_PROTOCOL=file`; `--remote` and the release
//! assets are read from a server of the test's own on `127.0.0.1:0`. No test touches the network.
//!
//! What each test holds, against the phase's done-when: a lockfile checked after one sync and no
//! further git call, every published verdict named and never checked for the rest; unknown when
//! the clone is stale and the source cannot be reached, or the source is frozen; a record file
//! removed in a later commit deleted, a record with one byte changed failing verification with
//! exit 4, and a logged record whose index entry was removed still found; a superseded record
//! shown superseded, and a withdrawn one withdrawn; `verify-attestation --lookup …
//! --rerun-comparison` re-deriving a published verdict from the upstream file and the rebuilt one,
//! given or from its release asset; a source configured by `evidence.toml`, by
//! `TRIGON_EVIDENCE_REPO` and by `evidence add`, with an HTTPS URL, a `file://` URL and a local
//! path; two sources, a divergence in either failing the check with the disagreement printed, an
//! unreachable source that is not required leaving only its own answers missing, and a record
//! signed with one source's key refused in another's repository; `--remote` proving inclusion and
//! refusing a record it cannot prove; the record form reading a source's clones across
//! repositories; and a sync removing the clone of a location no longer configured.

use std::io::{BufRead as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use sha2::Digest as _;
use trigon_attest::LocalKey;
use trigon_attest::log::{
    Checkpoint, DirFiles, HeartbeatLeaf, Leaf, LogSigner, SignedCheckpoint, verify_log,
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
    origin: String,
    seed: u8,
    /// A `git` that writes each command line it is given to `git.log` before running the real one.
    shim: PathBuf,
}

impl World {
    fn new(name: &str) -> World {
        World::with(name, ORIGIN, 3)
    }

    /// A world whose log is `origin` and whose records are signed by the key of `seed`.
    fn with(name: &str, origin: &str, seed: u8) -> World {
        let dir = std::env::temp_dir().join(format!("trigon-lookup-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for sub in ["store", "home/.config/trigon", "project", "bin"] {
            std::fs::create_dir_all(dir.join(sub)).unwrap();
        }
        let w = World {
            store: dir.join("store"),
            remote: dir.join("remote.git"),
            key: dir.join("signing.key"),
            log_key: dir.join("log.key"),
            origin: origin.into(),
            seed,
            shim: dir.join("bin"),
            dir,
        };
        git(
            &w.dir,
            &["init", "--quiet", "--bare", "-b", "main", "remote.git"],
        );
        let hex: String = w
            .attestation()
            .seed()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        std::fs::write(&w.key, format!("{hex}\n")).unwrap();
        let real = std::env::var_os("PATH")
            .and_then(|p| {
                std::env::split_paths(&p)
                    .map(|d| d.join("git"))
                    .find(|g| g.is_file())
            })
            .expect("git is on PATH");
        let shim = w.shim.join("git");
        std::fs::write(
            &shim,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nexec '{}' \"$@\"\n",
                w.dir.join("git.log").display(),
                real.display()
            ),
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        w.config("");
        ok(&w.trigon(&[
            "log",
            "keygen",
            "--origin",
            origin,
            "--out",
            w.log_key.to_str().unwrap(),
        ]));
        w
    }

    /// The attestation key this world's records are signed with.
    fn attestation(&self) -> LocalKey {
        LocalKey::from_bytes(&[self.seed; 32]).unwrap()
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
                "[publish]\norigin = \"{}\"\ndisputes = \"{DISPUTES}\"\nlog_key = \"{}\"\n{extra}",
                self.origin,
                self.log_key.display()
            ),
        )
        .unwrap();
    }

    /// Add `text` to the end of `evidence.toml`.
    fn append_config(&self, text: &str) {
        let file = std::fs::read_to_string(self.config_path()).unwrap();
        std::fs::write(self.config_path(), format!("{file}\n{text}")).unwrap();
    }

    /// `trigon <args>` in the working directory, with this world's home, cache and state
    /// directories and none of this process's `TRIGON_*`. `git` may reach nothing but files, and
    /// is the shim that writes down every command it runs.
    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(bin());
        let path = std::env::join_paths(std::iter::once(self.shim.clone()).chain(
            std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()),
        ))
        .unwrap();
        c.current_dir(self.dir.join("project"))
            .env("HOME", self.dir.join("home"))
            .env("XDG_CONFIG_HOME", self.dir.join("home/.config"))
            .env("XDG_STATE_HOME", self.dir.join("home/.local/state"))
            .env("XDG_CACHE_HOME", self.dir.join("home/.cache"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_ALLOW_PROTOCOL", "file")
            .env("PATH", path)
            .env("NO_COLOR", "1")
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

    /// Every git command run since the last call, and forget them.
    fn git_calls(&self) -> Vec<String> {
        let path = self.dir.join("git.log");
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let _ = std::fs::remove_file(&path);
        text.lines().map(str::to_string).collect()
    }

    fn init(&self) {
        ok(&self.trigon(&[
            "log",
            "init",
            "--origin",
            &self.origin,
            "--repo",
            self.remote.to_str().unwrap(),
            "--attestation-key",
            &self.attestation().public_hex(),
        ]));
    }

    fn attest(&self, id: &str, extra: &[&str]) {
        let mut args = vec![
            "attest",
            id,
            "--store",
            self.store.to_str().unwrap(),
            "--key",
            self.key.to_str().unwrap(),
        ];
        args.extend_from_slice(extra);
        ok(&self.trigon(&args));
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

    /// Publish a new agreeing pair of `p`, and return the id published.
    fn publish_package(&self, p: &Package, tag: &str) -> String {
        let (a, _) = pair(self, p, tag);
        ok(&self.publish(&[&a]));
        a
    }

    /// The record a run was published as, by its sha256 in hex.
    fn record_of(&self, id: &str) -> String {
        let store = Store::local(&self.store).unwrap();
        rt().block_on(store.get_run(id))
            .unwrap()
            .published
            .unwrap_or_else(|| panic!("run {id} is not published"))
            .record
            .to_hex()
    }

    fn vkey(&self) -> trigon_attest::LogVkey {
        LogSigner::from_file(&self.log_key).unwrap().vkey()
    }

    /// `trigon evidence add <name> <urls>` pinned to this world's keys, and `extra` after.
    fn add(&self, name: &str, urls: &[&str], extra: &[&str]) -> Output {
        self.add_pinned(self, name, urls, extra)
    }

    /// `trigon evidence add` in this world's configuration, pinned to `to`'s keys.
    fn add_pinned(&self, to: &World, name: &str, urls: &[&str], extra: &[&str]) -> Output {
        let vkey = to.vkey().to_string();
        let key = to.attestation().public_hex();
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

    /// A working tree of the remote as it is now, at `name` beside it.
    fn checkout(&self, name: &str) -> PathBuf {
        let to = self.dir.join(name);
        let _ = std::fs::remove_dir_all(&to);
        git(
            &self.dir,
            &[
                "clone",
                "--quiet",
                self.remote.to_str().unwrap(),
                to.to_str().unwrap(),
            ],
        );
        to
    }

    /// Change the remote as `change` changes a working tree of it, in one commit pushed on top:
    /// what whoever holds the push credential and no key could do.
    fn commit_on_remote(&self, message: &str, change: impl FnOnce(&Path)) {
        let c = self.checkout("pusher");
        change(&c);
        git(&c, &["add", "--all", "--force"]);
        git(&c, &["commit", "--quiet", "-m", message]);
        git(&c, &["push", "--quiet", "origin", "main"]);
    }

    /// Set the time of the last sync of `name` that worked to `at`, as though it were then.
    fn synced_at(&self, name: &str, at: u64) {
        let path = self.state(name).join("sync");
        let mut record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        record["lastSuccess"] = serde_json::json!(at);
        std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
    }

    /// [`Self::synced_at`], for the source `name` of the consumer `consumer`.
    fn synced_at_in(&self, consumer: &World, name: &str, at: u64) {
        consumer.synced_at(name, at);
    }

    /// Commit, on top of the bare repository `repo`'s branch, a log that appends `leaves` to the
    /// log there, signed by this world's log key, with `files` written beside it.
    fn append_signed(&self, repo: &Path, leaves: Vec<Leaf>, files: &[(String, Vec<u8>)]) {
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
        for (path, bytes) in files {
            let p = c.join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, bytes).unwrap();
        }
        let signer = LogSigner::from_file(&self.log_key).unwrap();
        let signed = SignedCheckpoint::sign(
            &Checkpoint {
                origin: self.origin.clone(),
                size: append.size,
                root: append.root,
            },
            &signer,
        )
        .unwrap();
        std::fs::write(c.join("log/checkpoint"), signed.to_string()).unwrap();
        git(&c, &["add", "--all", "--force"]);
        git(&c, &["commit", "--quiet", "-m", "appended by hand"]);
        git(&c, &["push", "--quiet", "origin", "main"]);
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

/// The JSON document a command printed, having exited `code`.
fn json_of(out: &Output, code: i32) -> serde_json::Value {
    let t = exits(out, code);
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {t}"))
}

/// The checkpoint a bare repository's branch holds, as its file is.
fn checkpoint_of(repo: &Path) -> Vec<u8> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["show", "main:log/checkpoint"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(out.status.success());
    out.stdout
}

fn record_path(hex: &str) -> String {
    format!("records/{}/{}/{hex}.json", &hex[..2], &hex[2..4])
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
    /// The egress tier its runs had: `open` makes them void.
    egress: &'static str,
    /// Its ecosystem, the purl type: `npm`, whose subjects carry a sha1, or `pypi`, whose do not.
    ecosystem: &'static str,
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
            egress: "mirror-only",
            ecosystem: "npm",
        }
    }

    /// The same, run with open egress: void, whatever its comparison found.
    fn void(name: &str) -> Package {
        Package {
            egress: "open",
            ..Package::new(name, false)
        }
    }

    /// `pkg:pypi/demo-<name>@1.0.0`, rebuilt `normalized`: a subject that carries no sha1.
    fn pypi(name: &str) -> Package {
        Package {
            ecosystem: "pypi",
            ..Package::new(name, false)
        }
    }

    fn target(&self) -> String {
        format!("pkg:{}/demo-{}@1.0.0", self.ecosystem, self.name)
    }

    fn file(&self) -> String {
        format!("demo-{}-1.0.0.tgz", self.name)
    }

    fn sha256(&self) -> String {
        hex(&sha2::Sha256::digest(&self.upstream))
    }

    fn sha512(&self) -> String {
        hex(&sha2::Sha512::digest(&self.upstream))
    }

    fn sha1(&self) -> String {
        trigon_attest::sha1_of(&self.upstream).to_hex()
    }

    /// npm's `integrity` for the upstream artifact.
    fn integrity(&self) -> String {
        format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(&self.upstream))
        )
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
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
            egress: p.egress.into(),
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
        sha1: (p.ecosystem == "npm").then(|| trigon_attest::sha1_of(&p.upstream)),
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
    w.attest(&a, &[]);
    (a, b)
}

/// A `package-lock.json` in the world's working directory naming `packages`, each with the
/// integrity string given, and its path.
fn lockfile(w: &World, packages: &[(&str, &str)]) -> PathBuf {
    let mut entries = serde_json::Map::new();
    entries.insert(
        "".into(),
        serde_json::json!({"name": "consumer", "version": "1.0.0"}),
    );
    for (name, integrity) in packages {
        entries.insert(
            format!("node_modules/{name}"),
            serde_json::json!({
                "version": "1.0.0",
                "resolved": format!("https://registry.npmjs.org/{name}/-/{name}-1.0.0.tgz"),
                "integrity": integrity,
            }),
        );
    }
    let path = w.dir.join("project/package-lock.json");
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "lockfileVersion": 3,
            "packages": entries,
        }))
        .unwrap(),
    )
    .unwrap();
    path
}

/// The result row of `name`@1.0.0 in `check --format json`.
fn row<'a>(doc: &'a serde_json::Value, purl: &str) -> &'a serde_json::Value {
    doc["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["purl"] == purl)
        .unwrap_or_else(|| panic!("no row for {purl}: {doc}"))
}

// ---------------------------------------------------------------------------------------------
// A local HTTP server: raw files for `--remote`, and GitHub's release API for rebuilt artifacts
// ---------------------------------------------------------------------------------------------

/// What the server holds and was asked.
#[derive(Default)]
struct Served {
    /// Working trees served as raw files, by `owner/repo`, at `/<owner>/<repo>/HEAD/<path>`.
    raw: Vec<(String, PathBuf)>,
    /// Release assets, by `owner/repo` and name, each repository's in one release.
    assets: Vec<(String, String, Vec<u8>)>,
    /// Paths answered with a status of their own, and nothing else: a host refusing, failing or
    /// rate-limiting a request.
    fail: Vec<(String, u16)>,
    /// Every path asked for, in order.
    asked: Vec<String>,
}

impl Served {
    /// Serve `dir` as the raw files of `repo`, in place of whatever was.
    fn serve(&mut self, repo: &str, dir: &Path) {
        self.raw.retain(|(r, _)| r != repo);
        self.raw.push((repo.into(), dir.to_path_buf()));
    }
}

/// A server on `127.0.0.1:0`, one connection at a time, closed after each answer.
struct Server {
    addr: std::net::SocketAddr,
    state: Arc<Mutex<Served>>,
}

impl Server {
    fn start() -> Server {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(Served::default()));
        let shared = state.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let _ = serve_one(stream, &shared, addr);
            }
        });
        Server { addr, state }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn state(&self) -> std::sync::MutexGuard<'_, Served> {
        self.state.lock().unwrap()
    }

    /// Every path asked for since the last call, and forget them.
    fn asked(&self) -> Vec<String> {
        std::mem::take(&mut self.state().asked)
    }
}

fn serve_one(
    stream: std::net::TcpStream,
    state: &Mutex<Served>,
    addr: std::net::SocketAddr,
) -> std::io::Result<()> {
    let mut reader = std::io::BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let path = line
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_string();
    loop {
        let mut h = String::new();
        reader.read_line(&mut h)?;
        if h.trim_end().is_empty() {
            break;
        }
    }
    let (status, body) = route(state, addr, &path);
    let mut out = stream;
    write!(
        out,
        "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    )?;
    out.write_all(&body)?;
    out.flush()
}

fn route(state: &Mutex<Served>, addr: std::net::SocketAddr, path: &str) -> (u16, Vec<u8>) {
    let mut s = state.lock().unwrap();
    s.asked.push(path.to_string());
    let (route, _) = path.split_once('?').unwrap_or((path, ""));
    if let Some((_, status)) = s.fail.iter().find(|(p, _)| route.ends_with(p.as_str())) {
        return (*status, b"refused".to_vec());
    }
    for (repo, root) in &s.raw {
        if let Some(rel) = route.strip_prefix(&format!("/{repo}/HEAD/")) {
            return match std::fs::read(root.join(rel)) {
                Ok(b) => (200, b),
                Err(_) => (404, b"404: Not Found".to_vec()),
            };
        }
    }
    if let Some(rest) = route.strip_prefix("/repos/")
        && let Some((repo, tail)) = rest.split_once("/releases")
    {
        let assets: Vec<serde_json::Value> = s
            .assets
            .iter()
            .filter(|(r, _, _)| r == repo)
            .map(|(_, name, bytes)| {
                serde_json::json!({
                    "id": 1,
                    "name": name,
                    "size": bytes.len(),
                    "browser_download_url": format!("http://{addr}/download/{repo}/{name}"),
                })
            })
            .collect();
        return match tail {
            "" => (
                200,
                serde_json::to_vec(&match assets.is_empty() {
                    true => serde_json::json!([]),
                    false => serde_json::json!([{"id": 7, "tag_name": "rebuilt-2026-09"}]),
                })
                .unwrap(),
            ),
            "/7/assets" => (200, serde_json::to_vec(&assets).unwrap()),
            _ => (404, Vec::new()),
        };
    }
    if let Some((repo, name)) = route
        .strip_prefix("/download/")
        .and_then(|r| r.rsplit_once('/'))
    {
        return match s.assets.iter().find(|(r, n, _)| r == repo && n == name) {
            Some((_, _, b)) => (200, b.clone()),
            None => (404, Vec::new()),
        };
    }
    (404, Vec::new())
}

/// Point `https://github.com/owner/trigon-evidence.git` at `repo` for every `git` this world runs,
/// as `url.<local>.insteadOf` does: a URL anyone could clone, which git here reaches as a local
/// bare repository.
fn github_url_to(w: &World, repo: &Path) -> &'static str {
    let url = "https://github.com/owner/trigon-evidence.git";
    std::fs::write(
        w.dir.join("home/.gitconfig"),
        format!("[url \"file://{}\"]\n\tinsteadOf = {url}\n", repo.display()),
    )
    .unwrap();
    url
}

/// End `w`'s log, and go on in a successor, `example.com/trigon-evidence/1`, in another bare
/// repository, as `trigon log succeed` does; `[publish]` names the successor from then on. Both
/// repositories are reached by their `https://github.com/owner/…` URLs as well as by path. The
/// successor's repository and its log key's file.
fn succeed_elsewhere(w: &World) -> (PathBuf, PathBuf) {
    git(
        &w.dir,
        &["init", "--quiet", "--bare", "-b", "main", "successor.git"],
    );
    let successor = w.dir.join("successor.git");
    let url = "https://github.com/owner/successor.git";
    std::fs::write(
        w.dir.join("home/.gitconfig"),
        format!(
            "[url \"file://{}\"]\n\tinsteadOf = {url}\n\
             [url \"file://{}\"]\n\tinsteadOf = https://github.com/owner/trigon-evidence.git\n",
            successor.display(),
            w.remote.display()
        ),
    )
    .unwrap();
    let next = w.dir.join("successor.key");
    let origin = format!("{ORIGIN}/1");
    ok(&w.trigon(&[
        "log",
        "keygen",
        "--origin",
        &origin,
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
        &origin,
        "--log-key",
        next.to_str().unwrap(),
        "--url",
        url,
    ]));
    let file = std::fs::read_to_string(w.config_path()).unwrap();
    std::fs::write(
        w.config_path(),
        file.replace(
            &format!("origin = \"{ORIGIN}\""),
            &format!("origin = \"{origin}\""),
        )
        .replace(
            &format!("log_key = \"{}\"", w.log_key.display()),
            &format!("log_key = \"{}\"", next.display()),
        ),
    )
    .unwrap();
    (successor, next)
}

// ---------------------------------------------------------------------------------------------
// check, after one sync
// ---------------------------------------------------------------------------------------------

/// `trigon check` over a lockfile names every published verdict after one sync and no further
/// request, and says never checked for the rest. Each package is found by the digest the lockfile
/// declares; the second check, with the remote gone, runs no git command that reaches a remote.
#[test]
fn a_lockfile_is_checked_after_one_sync_and_nothing_is_fetched_again() {
    let w = World::new("one-sync");
    w.init();
    let (a, b, c) = (
        Package::new("a", false),
        Package::new("b", false),
        Package::new("c", false),
    );
    w.publish_package(&a, "aaaa");
    w.publish_package(&b, "bbbb");
    ok(&w.add("main", &[&format!("file://{}", w.remote.display())], &[]));
    let lock = lockfile(
        &w,
        &[
            ("demo-a", &a.integrity()),
            ("demo-b", &b.integrity()),
            ("demo-c", &c.integrity()),
        ],
    );
    let lock = lock.to_str().unwrap();
    w.git_calls();

    let doc = json_of(&w.trigon(&["check", lock, "--format", "json"]), 2);
    for p in [&a, &b] {
        let r = row(&doc, &p.target());
        assert_eq!(r["status"], "normalized", "{r}");
        assert_eq!(r["exit"], 0, "{r}");
        assert_eq!(
            r["sources"][0]["foundBy"],
            serde_json::json!(["sha512"]),
            "{r}"
        );
        let rec = &r["sources"][0]["records"][0];
        assert_eq!(rec["state"], "verified", "{r}");
        assert!(rec["falsifyingCommand"]["argv"].is_array(), "{r}");
        assert!(rec["disputePointer"]["url"].is_string(), "{r}");
    }
    let r = row(&doc, &c.target());
    assert_eq!(r["status"], "never checked", "{r}");
    assert_eq!(r["exit"], 2);
    assert_eq!(
        doc["sources"][0]["notes"][0],
        "synced first: it had never been synced"
    );
    let calls = w.git_calls();
    let reaching: Vec<&String> = calls
        .iter()
        .filter(|c| c.contains("clone") || c.contains("fetch") || c.contains("ls-remote"))
        .collect();
    assert_eq!(
        reaching.len(),
        1,
        "one clone, for the whole lockfile: {calls:#?}"
    );

    // The source goes away: the check answers from the clone, fresh, and nothing reaches out.
    std::fs::rename(&w.remote, w.dir.join("gone.git")).unwrap();
    let said = exits(&w.trigon(&["check", lock]), 2);
    let calls = w.git_calls();
    assert!(
        !calls
            .iter()
            .any(|c| c.contains("clone") || c.contains("fetch") || c.contains("ls-remote")),
        "{calls:#?}"
    );
    assert!(!said.contains("synced first"), "{said}");
    assert!(said.contains("normalized"), "{said}");
    assert!(
        said.contains("pkg:npm/demo-c@1.0.0 — never checked"),
        "{said}"
    );
    assert!(
        said.contains("exit      2: never checked, or withdrawn"),
        "{said}"
    );
    // The two published are not listed one by one: they pass.
    assert!(!said.contains("pkg:npm/demo-a@1.0.0 —"), "{said}");
}

/// A source whose clone is stale and which cannot be reached answers unknown, as does a frozen
/// one, however it was reached; with no other source, no package can be answered, which is exit 4.
/// `--offline` answers unknown for a stale source without trying.
#[test]
fn stale_and_unreachable_or_frozen_is_unknown() {
    let w = World::new("unknown");
    w.init();
    let a = Package::new("a", false);
    w.publish_package(&a, "aaaa");
    ok(&w.add("main", &[w.remote.to_str().unwrap()], &[]));
    ok(&w.sync(&[]));
    let lock = lockfile(&w, &[("demo-a", &a.integrity())]);
    let lock = lock.to_str().unwrap();
    exits(&w.trigon(&["check", lock]), 0);

    // Two days since the last sync that worked, and the source gone.
    w.synced_at("main", now() - 2 * 86_400);
    std::fs::rename(&w.remote, w.dir.join("gone.git")).unwrap();
    let doc = json_of(&w.trigon(&["check", lock, "--format", "json"]), 4);
    let r = row(&doc, &a.target());
    assert_eq!(r["status"], "unknown", "{r}");
    assert_eq!(r["sources"][0]["said"], "unknown", "{r}");
    assert_eq!(doc["sources"][0]["standing"], "unknown", "{doc}");
    let notes = doc["sources"][0]["notes"].to_string();
    assert!(notes.contains("synced first"), "{notes}");
    assert!(notes.contains("the sync failed"), "{notes}");
    assert!(
        doc["sources"][0]["why"].as_str().unwrap().contains("stale"),
        "{doc}"
    );
    let said = exits(&w.trigon(&["lookup", &a.integrity()]), 4);
    assert!(said.contains("answer    unknown"), "{said}");
    // Offline, it does not try.
    w.git_calls();
    let said = exits(&w.trigon(&["check", lock, "--offline"]), 4);
    assert!(!said.contains("synced first"), "{said}");
    assert!(!w.git_calls().iter().any(|c| c.contains("fetch")));

    // Frozen: a log whose newest leaf is a month old, reached and synced now.
    let f = World::new("frozen");
    f.init();
    f.append_signed(
        &f.remote,
        vec![Leaf::Heartbeat(HeartbeatLeaf {
            time: now() - 30 * 86_400,
        })],
        &[],
    );
    ok(&f.add("main", &[f.remote.to_str().unwrap()], &[]));
    let lock = lockfile(&f, &[("demo-a", &a.integrity())]);
    let doc = json_of(
        &f.trigon(&["check", lock.to_str().unwrap(), "--format", "json"]),
        4,
    );
    assert_eq!(row(&doc, &a.target())["status"], "unknown", "{doc}");
    assert_eq!(doc["sources"][0]["standing"], "frozen", "{doc}");
    // Frozen is measured against `frozen_after`: sixty days, and it answers — never checked.
    f.append_config("[freshness]\nfrozen_after = \"60d\"\n");
    let doc = json_of(
        &f.trigon(&["check", lock.to_str().unwrap(), "--format", "json"]),
        2,
    );
    assert_eq!(row(&doc, &a.target())["status"], "never checked", "{doc}");
}

/// The log wins, and the disagreement is shown (`docs/19` §8): a record file removed in a later
/// commit is deleted, and exit 4; a record with one byte changed fails verification, and exit 4;
/// and a record whose index entry was removed is still found, since the log is read and never the
/// index.
#[test]
fn a_deleted_record_a_changed_byte_and_a_missing_index_entry() {
    let w = World::new("damage");
    w.init();
    let (a, b, c) = (
        Package::new("a", false),
        Package::new("b", false),
        Package::new("c", false),
    );
    w.publish_package(&a, "aaaa");
    let rb = w.record_of(&w.publish_package(&b, "bbbb"));
    let rc = w.record_of(&w.publish_package(&c, "cccc"));
    ok(&w.add("main", &[&format!("file://{}", w.remote.display())], &[]));
    for p in [&a, &b, &c] {
        exits(&w.trigon(&["lookup", &p.integrity()]), 0);
    }

    // The index entries of a, under every key, removed.
    let sha512 = a.sha512();
    w.commit_on_remote("index gone", |t| {
        for (kind, hex) in [
            ("sha512", sha512.as_str()),
            ("sha256", &a.sha256()),
            ("sha1", &a.sha1()),
        ] {
            std::fs::remove_file(t.join(format!(
                "index/{kind}/{}/{}/{hex}.json",
                &hex[..2],
                &hex[2..4]
            )))
            .unwrap();
        }
    });
    // The record file of b removed; one byte of c's changed.
    w.commit_on_remote("record gone", |t| {
        std::fs::remove_file(t.join(record_path(&rb))).unwrap();
        let p = t.join(record_path(&rc));
        let mut bytes = std::fs::read(&p).unwrap();
        let at = bytes.len() / 2;
        bytes[at] ^= 0x01;
        std::fs::write(&p, bytes).unwrap();
    });
    ok(&w.sync(&[]));

    let said = exits(&w.trigon(&["lookup", &a.integrity()]), 0);
    assert!(said.contains("answer    normalized"), "{said}");
    let said = exits(&w.trigon(&["lookup", &b.integrity()]), 4);
    assert!(said.contains("DELETED"), "{said}");
    assert!(said.contains("answer    deleted"), "{said}");
    // What a deleted record's leaf says is never shown without the record.
    assert!(!said.contains("claims"), "{said}");
    let said = exits(&w.trigon(&["lookup", &format!("sha256:{}", c.sha256())]), 4);
    assert!(said.contains("FAILED VERIFICATION"), "{said}");
    assert!(said.contains("not-its-leaf"), "{said}");

    let lock = lockfile(
        &w,
        &[
            ("demo-a", &a.integrity()),
            ("demo-b", &b.integrity()),
            ("demo-c", &c.integrity()),
        ],
    );
    let doc = json_of(
        &w.trigon(&["check", lock.to_str().unwrap(), "--format", "json"]),
        4,
    );
    assert_eq!(row(&doc, &a.target())["status"], "normalized");
    assert_eq!(row(&doc, &b.target())["status"], "deleted");
    assert_eq!(row(&doc, &c.target())["status"], "failed verification");
    assert_eq!(
        row(&doc, &c.target())["sources"][0]["records"][0]["failure"]["kind"],
        "not-its-leaf"
    );
}

/// A superseded record is shown superseded — struck through, with the reason and both leaves —
/// beside the record that supersedes it, which answers; and a withdrawn record reads as withdrawn,
/// exit 2.
#[test]
fn a_superseded_record_is_shown_superseded_and_a_withdrawn_one_withdrawn() {
    let w = World::new("superseded");
    w.init();
    let a = Package::new("a", false);
    let first = w.record_of(&w.publish_package(&a, "aaaa"));
    let reader = w.checkout("reader");
    let (again, _) = pair(&w, &a, "a2a2");
    w.attest(
        &again,
        &[
            "--supersedes",
            reader.join(record_path(&first)).to_str().unwrap(),
            "--reason",
            "set_changed",
        ],
    );
    ok(&w.publish(&[&again]));
    let second = w.record_of(&again);
    ok(&w.add("main", &[w.remote.to_str().unwrap()], &[]));

    let said = exits(&w.trigon(&["lookup", &a.integrity()]), 0);
    assert!(
        said.contains(&format!(
            "record    ~~sha256:{first} at leaf 0 of `{ORIGIN}`: normalized~~ SUPERSEDED by \
             sha256:{second} at leaf 1 of `{ORIGIN}` (set_changed)"
        )),
        "{said}"
    );
    assert!(
        said.contains(&format!(
            "record    sha256:{second} at leaf 1 of `{ORIGIN}`, current"
        )),
        "{said}"
    );
    assert!(
        said.contains(&format!("supersedes sha256:{first} (set_changed)")),
        "{said}"
    );
    // The superseded record's §4.2 fields are shown too, struck through as it is: its outcome is
    // never shown without its falsifying command and its dispute pointer.
    let struck = said
        .split(&format!("record    sha256:{second}"))
        .next()
        .unwrap();
    for label in [
        "set", "run", "trigon", "egress", "derived", "falsify", "dispute",
    ] {
        assert!(
            struck.contains(&format!("\n{label:<10}~~")),
            "{label}: {said}"
        );
    }
    assert!(
        struck.contains(&format!("dispute   ~~{DISPUTES}~~")),
        "{said}"
    );
    let doc = json_of(
        &w.trigon(&["lookup", &a.integrity(), "--output", "json"]),
        0,
    );
    let records = &doc["sources"][0]["records"];
    assert_eq!(records[0]["current"], false, "{doc}");
    assert_eq!(records[0]["supersededBy"][0]["reason"], "set_changed");
    assert_eq!(records[0]["supersededBy"][0]["leaf"]["index"], 1);
    assert_eq!(records[1]["current"], true);

    // Withdrawn: the current record withdrawn, and nothing current left but the withdrawal.
    let reader = w.checkout("reader");
    let out = ok(&w.trigon(&[
        "attest",
        "--withdraw",
        reader.join(record_path(&second)).to_str().unwrap(),
        "--reason",
        "withdrawn",
        "--store",
        w.store.to_str().unwrap(),
        "--key",
        w.key.to_str().unwrap(),
    ]));
    let envelope = w.store.join(
        out.lines()
            .find_map(|l| {
                l.trim()
                    .strip_prefix("withdrawals/")
                    .map(|r| format!("withdrawals/{r}"))
            })
            .unwrap_or_else(|| panic!("no withdrawal filed: {out}")),
    );
    ok(&w.publish(&["--withdrawal", envelope.to_str().unwrap()]));
    // The source is fresh, so nothing syncs it by itself: a sync brings the withdrawal.
    ok(&w.sync(&[]));
    let said = exits(&w.trigon(&["lookup", &a.integrity()]), 2);
    assert!(said.contains("answer    withdrawn"), "{said}");
    assert!(said.contains("withdraws sha256:"), "{said}");
    let lock = lockfile(&w, &[("demo-a", &a.integrity())]);
    let doc = json_of(
        &w.trigon(&["check", lock.to_str().unwrap(), "--format", "json"]),
        2,
    );
    assert_eq!(row(&doc, &a.target())["status"], "withdrawn");
}

/// The falsifying command a record signs, run as written: `verify-attestation --lookup … --origin
/// … --rerun-comparison --upstream <file>`, with the rebuilt file given, resolves the current
/// record in the source that has the log, fetches the evidence it names from the clone's remote,
/// and re-derives the verdict, the published comparison report held to it. The wrong rebuilt file
/// refutes it, exit 4; an origin no source has is said, exit 4; and where rebuilt artifacts are
/// published, the release asset the verdict names is downloaded and held to its digest.
#[test]
fn the_falsifying_command_re_derives_a_published_verdict() {
    let w = World::new("falsify");
    w.init();
    // Served as GitHub serves a repository, so the clone is partial and truly lacks `evidence/`:
    // a `file://` remote refuses a filter unless told to take one.
    git(&w.remote, &["config", "uploadpack.allowFilter", "true"]);
    git(
        &w.remote,
        &["config", "uploadpack.allowAnySHA1InWant", "true"],
    );
    let a = Package::new("a", false);
    w.publish_package(&a, "aaaa");
    ok(&w.add("main", &[&format!("file://{}", w.remote.display())], &[]));
    let doc = json_of(
        &w.trigon(&["lookup", &a.integrity(), "--output", "json"]),
        0,
    );
    let argv: Vec<String> = doc["sources"][0]["records"][0]["falsifyingCommand"]["argv"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    let upstream = w.dir.join(a.file());
    std::fs::write(&upstream, &a.upstream).unwrap();
    let rebuilt = w.dir.join("rebuilt.tgz");
    std::fs::write(&rebuilt, &a.rebuilt).unwrap();
    // The command as signed, `<file>` the upstream artifact, and the rebuilt one given.
    let command = |rebuild: Option<&Path>| {
        let mut args: Vec<String> = argv[1..]
            .iter()
            .map(|x| match x.as_str() {
                "<file>" => upstream.display().to_string(),
                other => other.to_string(),
            })
            .collect();
        if let Some(r) = rebuild {
            args.extend(["--rebuild".to_string(), r.display().to_string()]);
        }
        args
    };
    let run = |args: Vec<String>| {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        w.trigon(&args)
    };
    assert_eq!(argv[..3], ["trigon", "verify-attestation", "--lookup"]);
    w.git_calls();
    let said = exits(&run(command(Some(&rebuilt))), 0);
    assert!(
        said.contains("resolved as the current record of sha256:"),
        "{said}"
    );
    // The evidence the record names was not in the clone, and was fetched as it was read: said,
    // since it names the record to the host.
    assert!(
        said.contains("evidence file(s) the record names from file://"),
        "{said}"
    );
    assert!(
        said.contains("which names the record to that host"),
        "{said}"
    );
    assert!(said.contains("comparison sha256:"), "{said}");
    assert!(w.git_calls().iter().any(|c| c.contains("cat-file --batch")));
    assert!(
        said.contains("rederived normalized under tar-gzip"),
        "{said}"
    );
    assert!(said.contains("the claim holds"), "{said}");
    assert!(
        said.contains("the published comparison report agrees with the re-derivation"),
        "{said}"
    );
    assert!(
        !said.contains("evidence  comparison sha256:") || said.contains("matches"),
        "{said}"
    );

    // Another rebuilt file is not the one the verdict names: the check is not made, exit 5.
    let wrong = w.dir.join("wrong.tgz");
    std::fs::write(&wrong, Package::new("a", true).rebuilt).unwrap();
    let said = exits(&run(command(Some(&wrong))), 5);
    assert!(
        said.contains("is not the one this statement is about"),
        "{said}"
    );

    // An origin no source here has: said, and never resolved elsewhere.
    let mut elsewhere = command(Some(&rebuilt));
    let at = elsewhere.iter().position(|x| x == "--origin").unwrap();
    elsewhere[at + 1] = "example.com/somewhere-else".into();
    let said = exits(&run(elsewhere), 4);
    assert!(
        said.contains("no evidence source configured here has the log"),
        "{said}"
    );
    // No rebuilt file, and none published: the tool cannot check, exit 5.
    let said = exits(&run(command(None)), 5);
    assert!(said.contains("--rebuild <file>"), "{said}");
    // An artifact nothing is published for: never checked, exit 2.
    let said = exits(
        &w.trigon(&[
            "verify-attestation",
            "--lookup",
            &format!("sha256:{}", "0".repeat(64)),
        ]),
        2,
    );
    assert!(said.contains("never checked"), "{said}");

    // The published comparison report altered in a later commit: fetched from git's objects as
    // the record names it, it is not the bytes the verdict signs, and the record fails, exit 4.
    let cmp = doc["sources"][0]["records"][0]["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "comparison")
        .unwrap()["digest"]
        .as_str()
        .unwrap()
        .trim_start_matches("sha256:")
        .to_string();
    let good = w.remote.join("..").canonicalize().unwrap();
    let before = git(&w.remote, &["rev-parse", "main"]);
    w.commit_on_remote("comparison altered", |t| {
        let p = t.join(format!(
            "evidence/sha256/{}/{}/{cmp}",
            &cmp[..2],
            &cmp[2..4]
        ));
        let mut bytes = std::fs::read(&p).unwrap();
        bytes.extend_from_slice(b" ");
        std::fs::write(&p, bytes).unwrap();
    });
    ok(&w.sync(&[]));
    let said = exits(&run(command(Some(&rebuilt))), 4);
    assert!(
        said.contains("is not the bytes its statement signs"),
        "{said}"
    );
    git(
        &good.join("remote.git"),
        &["update-ref", "refs/heads/main", &before],
    );
    std::fs::remove_dir_all(w.cache("main")).unwrap();
    std::fs::remove_dir_all(w.state("main")).unwrap();

    // Published rebuilt artifacts: the release asset the verdict names, from the source's GitHub
    // repository, downloaded and held to its digest.
    let server = Server::start();
    let url = github_url_to(&w, &w.remote);
    ok(&w.add("gh", &[url], &[]));
    w.append_config(""); // the file ends in a newline either way
    let file = std::fs::read_to_string(w.config_path()).unwrap();
    std::fs::write(
        w.config_path(),
        file.replacen(
            "[publish]\n",
            "[publish]\nrebuilt_artifacts = \"github-release\"\n",
            1,
        ),
    )
    .unwrap();
    let rebuilt_hex = hex(&sha2::Sha256::digest(&a.rebuilt));
    server.state().assets.push((
        "owner/trigon-evidence".into(),
        format!("sha256-{rebuilt_hex}"),
        a.rebuilt.clone(),
    ));
    let mut c = w.command(&[]);
    c.args(command(None)).env("TRIGON_GITHUB_API", server.url());
    let said = exits(&c.output().unwrap(), 0);
    assert!(
        said.contains(&format!(
            "the rebuilt artifact is the release asset sha256-{rebuilt_hex} of owner/trigon-evidence"
        )),
        "{said}"
    );
    assert!(said.contains("the claim holds"), "{said}");
    // An asset that is not the bytes its name says is refused.
    server.state().assets[0].2 = Package::new("a", true).rebuilt;
    let mut c = w.command(&[]);
    c.args(command(None)).env("TRIGON_GITHUB_API", server.url());
    let said = exits(&c.output().unwrap(), 4);
    assert!(
        said.contains("is not the rebuilt artifact the verdict signs"),
        "{said}"
    );
}

/// The falsifying command is answered in the log its origin names and nowhere else. A source a
/// project's `.trigon/evidence.toml` adds, whose own log key has that origin's name, is set aside
/// where the user's own source holds the origin, and said to be; it answers, as the project's
/// claim, only where nothing else holds it; and two of the user's own sources that give the origin
/// to different keys are refused as ambiguous. A source of another origin is not synced for it.
#[test]
fn the_falsifying_command_is_answered_in_its_origins_log_alone() {
    let w = World::new("origin");
    w.init();
    let a = Package::new("a", false);
    w.publish_package(&a, "aaaa");
    // Another log, given the same origin under a key of its own, whose record for the artifact
    // says it diverges.
    let evil = World::with("origin-evil", ORIGIN, 9);
    evil.init();
    evil.config("divergences = \"feed\"\n");
    evil.publish_package(&Package::new("a", true), "eeee");
    // And a source of another origin.
    let other = World::with("origin-other", "example.com/other", 4);
    other.init();
    other.publish_package(&Package::new("o", false), "oooo");
    ok(&w.add("main", &[w.remote.to_str().unwrap()], &[]));
    ok(&w.add_pinned(&other, "other", &[other.remote.to_str().unwrap()], &[]));
    let url = github_url_to(&w, &evil.remote);
    let project = w.dir.join("project/.trigon");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("evil.checkpoint"), checkpoint_of(&evil.remote)).unwrap();
    std::fs::write(
        project.join("evidence.toml"),
        format!(
            "[[source]]\nname = \"evil\"\nurls = [\"{url}\"]\nlog_key = \"{}\"\n\
             attestation_key = \"{}\"\ncheckpoint = \"evil.checkpoint\"\n",
            evil.vkey(),
            evil.attestation().public_hex()
        ),
    )
    .unwrap();
    ok(&w.sync(&[]));
    let args = [
        "verify-attestation".to_string(),
        "--lookup".into(),
        format!("sha256:{}", a.sha256()),
        "--origin".into(),
        ORIGIN.into(),
    ];
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    // `other` is stale: a command that asked it would sync it first.
    w.synced_at("other", now() - 2 * 86_400);
    w.git_calls();
    let said = exits(&w.trigon(&args), 0);
    assert!(
        said.contains(&format!(
            "resolved as the current record of sha256:{} in `main`",
            a.sha256()
        )),
        "{said}"
    );
    assert!(!said.contains("in `evil`, through its log"), "{said}");
    assert!(
        said.contains(&format!(
            "`evil`, added by the project's own {}, has a log named `{ORIGIN}` under another key",
            project.join("evidence.toml").display()
        )),
        "{said}"
    );
    assert!(said.contains("and is not asked"), "{said}");
    let calls = w.git_calls();
    assert!(
        !calls.iter().any(|c| c.contains("/evidence/other")),
        "a source of another origin was synced: {calls:#?}"
    );
    // Where nothing else holds the origin, the project's source answers, as the project's claim.
    ok(&w.trigon(&["evidence", "remove", "main"]));
    let said = exits(&w.trigon(&args), 1);
    assert!(said.contains("in `evil`, through its log"), "{said}");
    assert!(said.contains("added by the project's own"), "{said}");
    // Two of the user's own sources that give the origin to two keys: nothing tells which log the
    // command was signed in.
    ok(&w.add("main", &[w.remote.to_str().unwrap()], &[]));
    ok(&w.add_pinned(&evil, "evil-too", &[evil.remote.to_str().unwrap()], &[]));
    ok(&w.sync(&[]));
    let said = exits(&w.trigon(&args), 5);
    assert!(said.contains("under different log keys"), "{said}");
    assert!(said.contains("`main`"), "{said}");
    assert!(said.contains("`evil-too`"), "{said}");
}

/// Every source the falsifying command asks is weighed, as `lookup` weighs it: a mirror of the
/// log configured as a source of its own, required, and stale and unreachable, fails the command
/// though another source holds the current record, and is said to.
#[test]
fn the_falsifying_command_weighs_every_source_it_asks() {
    let w = World::new("weighs");
    w.init();
    let a = Package::new("a", false);
    w.publish_package(&a, "aaaa");
    let mirror = w.dir.join("mirror.git");
    git(
        &w.dir,
        &[
            "clone",
            "--quiet",
            "--bare",
            w.remote.to_str().unwrap(),
            mirror.to_str().unwrap(),
        ],
    );
    ok(&w.add("main", &[w.remote.to_str().unwrap()], &[]));
    ok(&w.add("mirror", &[mirror.to_str().unwrap()], &["--required"]));
    ok(&w.sync(&[]));
    let subject = format!("sha256:{}", a.sha256());
    let args = [
        "verify-attestation",
        "--lookup",
        &subject,
        "--origin",
        ORIGIN,
    ];
    let said = exits(&w.trigon(&args), 0);
    assert!(said.contains("`mirror` says normalized"), "{said}");
    w.synced_at("mirror", now() - 2 * 86_400);
    std::fs::rename(&mirror, w.dir.join("gone.git")).unwrap();
    let said = exits(&w.trigon(&args), 4);
    assert!(said.contains("`mirror` cannot answer"), "{said}");
    assert!(said.contains("exit 4, not this record's 0"), "{said}");
    let mut json = args.to_vec();
    json.extend(["--output", "json"]);
    assert_eq!(json_of(&w.trigon(&json), 4)["exit"], 4);
}

/// Across a succession into another repository, the falsifying command of a record logged there
/// finds the rebuilt artifact among that repository's release assets, where its publisher
/// uploaded it. And a void, asked to re-derive, is reported as the void it is, exit 3: it has no
/// claim to re-derive, which is no failure of the tool's.
#[test]
fn the_falsifying_command_across_a_succession_and_for_a_void() {
    let w = World::new("falsify-successor");
    w.init();
    let v = Package::void("v");
    let (vid, _) = pair(&w, &v, "vvvv");
    ok(&w.publish(&[&vid]));
    let (successor, _) = succeed_elsewhere(&w);
    ok(&w.add(
        "main",
        &["https://github.com/owner/trigon-evidence.git"],
        &[],
    ));
    ok(&w.sync(&[]));
    let b = Package::new("b", false);
    let (id, _) = pair(&w, &b, "bbbb");
    ok(&w.trigon(&[
        "publish",
        "--store",
        w.store.to_str().unwrap(),
        "--repo",
        successor.to_str().unwrap(),
        &id,
    ]));
    ok(&w.sync(&[]));
    let file = std::fs::read_to_string(w.config_path()).unwrap();
    std::fs::write(
        w.config_path(),
        file.replacen(
            "[publish]\n",
            "[publish]\nrebuilt_artifacts = \"github-release\"\n",
            1,
        ),
    )
    .unwrap();
    let server = Server::start();
    let rebuilt_hex = hex(&sha2::Sha256::digest(&b.rebuilt));
    server.state().assets.push((
        "owner/successor".into(),
        format!("sha256-{rebuilt_hex}"),
        b.rebuilt.clone(),
    ));
    let upstream = w.dir.join(b.file());
    std::fs::write(&upstream, &b.upstream).unwrap();
    let subject = format!("sha256:{}", b.sha256());
    let origin = format!("{ORIGIN}/1");
    let mut c = w.command(&[
        "verify-attestation",
        "--lookup",
        &subject,
        "--origin",
        &origin,
        "--rerun-comparison",
        "--upstream",
        upstream.to_str().unwrap(),
    ]);
    c.env("TRIGON_GITHUB_API", server.url());
    let said = exits(&c.output().unwrap(), 0);
    assert!(
        said.contains(&format!(
            "the rebuilt artifact is the release asset sha256-{rebuilt_hex} of owner/successor"
        )),
        "{said}"
    );
    assert!(said.contains("the claim holds"), "{said}");
    let asked = server.asked();
    assert!(
        asked
            .iter()
            .any(|p| p.starts_with("/repos/owner/successor/releases")),
        "{asked:#?}"
    );
    assert!(
        !asked.iter().any(|p| p.contains("owner/trigon-evidence")),
        "{asked:#?}"
    );

    // The void, asked to re-derive: reported, exit 3, and said not to have been re-derived.
    let (vup, vre) = (w.dir.join("v.tgz"), w.dir.join("v-rebuilt.tgz"));
    std::fs::write(&vup, &v.upstream).unwrap();
    std::fs::write(&vre, &v.rebuilt).unwrap();
    let vsubject = format!("sha256:{}", v.sha256());
    let said = exits(
        &w.trigon(&[
            "verify-attestation",
            "--lookup",
            &vsubject,
            "--origin",
            ORIGIN,
            "--rerun-comparison",
            "--upstream",
            vup.to_str().unwrap(),
            "--rebuild",
            vre.to_str().unwrap(),
        ]),
        3,
    );
    assert!(
        said.contains("not re-derived: a void makes no comparison claim"),
        "{said}"
    );
}

/// A source answers whether `evidence.toml` names it, `TRIGON_EVIDENCE_REPO` adds it, or `evidence
/// add` writes it, each by an HTTPS URL, a `file://` URL and a local path; and each answer names
/// where its source came from. The environment's source is required: while it cannot answer, a
/// check fails, whatever the others say.
#[test]
fn a_source_answers_however_it_was_configured() {
    let w = World::new("configured");
    w.init();
    let a = Package::new("a", false);
    w.publish_package(&a, "aaaa");
    let https = github_url_to(&w, &w.remote);
    let file = format!("file://{}", w.remote.display());
    let path = w.remote.to_str().unwrap().to_string();
    let forms = [
        ("https", https),
        ("file", file.as_str()),
        ("path", path.as_str()),
    ];
    for (form, url) in forms {
        w.append_config(&format!(
            "[[source]]\nname = \"toml-{form}\"\nurls = [\"{url}\"]\nlog_key = \"{}\"\n\
             attestation_key = \"{}\"\n",
            w.vkey(),
            w.attestation().public_hex()
        ));
        ok(&w.add(&format!("add-{form}"), &[url], &[]));
    }
    let env = |c: &mut Command, url: &str| {
        c.env("TRIGON_EVIDENCE_REPO", url)
            .env("TRIGON_EVIDENCE_LOG_KEY", w.vkey().to_string())
            .env(
                "TRIGON_EVIDENCE_ATTESTATION_KEY",
                w.attestation().public_hex(),
            );
    };
    for (n, (form, url)) in forms.into_iter().enumerate() {
        let mut c = w.command(&["lookup", &a.integrity(), "--output", "json"]);
        env(&mut c, url);
        let doc = json_of(&c.output().unwrap(), 0);
        let sources = doc["sources"].as_array().unwrap();
        assert_eq!(sources.len(), 7, "{form}: {doc}");
        for s in sources {
            assert_eq!(s["answer"], "normalized", "{form}: {s}");
            assert_eq!(s["records"].as_array().unwrap().len(), 1, "{form}: {s}");
        }
        let label = |n: &str| {
            sources
                .iter()
                .find(|s| s["name"] == n)
                .unwrap_or_else(|| panic!("{n}: {doc}"))["label"]
                .as_str()
                .unwrap()
                .to_string()
        };
        assert!(label("env").contains("from TRIGON_EVIDENCE_REPO"), "{doc}");
        for (f, _) in forms {
            assert!(
                label(&format!("toml-{f}")).contains("evidence.toml"),
                "{doc}"
            );
            assert!(
                label(&format!("add-{f}")).contains("evidence.toml"),
                "{doc}"
            );
        }
        let env_source = sources.iter().find(|s| s["name"] == "env").unwrap();
        assert_eq!(env_source["required"], true, "{form}: {doc}");
        // Its URL changed since its last sync, which was a moment ago: no location it names has
        // a clone, so it is synced first, as a source never synced is.
        if n > 0 {
            assert!(
                env_source["notes"][0]
                    .as_str()
                    .unwrap()
                    .contains("no location it names has a clone"),
                "{form}: {doc}"
            );
        }
    }
    // The environment's source is required: where it cannot be reached, a check fails, though
    // every other source answers for every package.
    let lock = lockfile(&w, &[("demo-a", &a.integrity())]);
    let mut c = w.command(&["check", lock.to_str().unwrap(), "--format", "json"]);
    env(&mut c, w.dir.join("nowhere.git").to_str().unwrap());
    let doc = json_of(&c.output().unwrap(), 4);
    let r = row(&doc, &a.target());
    assert_eq!(r["status"], "normalized", "{r}");
    assert_eq!(r["exit"], 4, "{r}");
    assert_eq!(
        r["sourceFailure"]["requiredUnknown"],
        serde_json::json!(["env"]),
        "{r}"
    );
    let env_said = r["sources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "env")
        .unwrap()["said"]
        .clone();
    assert_eq!(env_said, "unknown, and it is required", "{r}");
    let mut c = w.command(&["check", lock.to_str().unwrap()]);
    env(&mut c, w.dir.join("nowhere.git").to_str().unwrap());
    let said = exits(&c.output().unwrap(), 4);
    assert!(
        said.contains("fails the check: `env` required, and could not answer"),
        "{said}"
    );
    // One trusting on first use says what its answers rest on, in every answer.
    ok(&w.trigon(&[
        "evidence",
        "add",
        "tofu",
        w.remote.to_str().unwrap(),
        "--trust-on-first-use",
    ]));
    let doc = json_of(
        &w.trigon(&[
            "lookup",
            &a.integrity(),
            "--source",
            "tofu",
            "--output",
            "json",
        ]),
        0,
    );
    assert_eq!(doc["sources"][0]["trustOnFirstUse"], true, "{doc}");
    assert!(
        doc["sources"][0]["label"]
            .as_str()
            .unwrap()
            .contains("resting on keys trusted on first use, read from"),
        "{doc}"
    );
}

/// Two sources are two witnesses, never one pool (`docs/19` §6.1): a divergence from either fails
/// the check, and the disagreement is printed; a source that cannot be reached and is not required
/// leaves only its own answers missing, while one that is required fails the check; and a record
/// signed with one source's key is refused when it is found in another's repository.
#[test]
fn two_sources_are_answered_each_and_never_merged() {
    let w = World::with("two-a", "example.com/a", 3);
    let b = World::with("two-b", "example.com/b", 4);
    w.init();
    b.init();
    b.config("divergences = \"feed\"\n");
    let (x, y) = (Package::new("x", false), Package::new("y", false));
    let xa = w.publish_package(&x, "aaaa");
    w.publish_package(&y, "bbbb");
    // The other operator's rebuild of x diverges, from the same published artifact.
    b.publish_package(&Package::new("x", true), "cccc");
    ok(&w.add("a", &[w.remote.to_str().unwrap()], &[]));
    ok(&w.add_pinned(&b, "b", &[b.remote.to_str().unwrap()], &[]));
    let lock = lockfile(
        &w,
        &[("demo-x", &x.integrity()), ("demo-y", &y.integrity())],
    );
    let lock = lock.to_str().unwrap();

    let doc = json_of(&w.trigon(&["check", lock, "--format", "json"]), 1);
    let r = row(&doc, &x.target());
    assert_eq!(r["status"], "divergent", "{r}");
    assert_eq!(
        r["disagreement"],
        serde_json::json!(["`a` says normalized", "`b` says divergent"]),
        "{r}"
    );
    // b holds nothing about y, which does not make it never checked.
    assert_eq!(row(&doc, &y.target())["status"], "normalized");
    let said = exits(&w.trigon(&["check", lock]), 1);
    assert!(
        said.contains("the sources disagree: `a` says normalized, `b` says divergent"),
        "{said}"
    );
    let said = exits(&w.trigon(&["lookup", &x.integrity()]), 1);
    assert!(
        said.contains("disagree  the sources disagree about it:"),
        "{said}"
    );
    assert!(said.contains("`a` says normalized"), "{said}");
    assert!(said.contains("`b` says divergent"), "{said}");

    // b cannot be reached, and its clone is stale: only its answers are missing.
    b.synced_at_in(&w, "b", now() - 2 * 86_400);
    std::fs::rename(&b.remote, b.dir.join("gone.git")).unwrap();
    let doc = json_of(&w.trigon(&["check", lock, "--format", "json"]), 0);
    assert_eq!(row(&doc, &x.target())["status"], "normalized", "{doc}");
    assert_eq!(
        row(&doc, &x.target())["sources"][1]["said"],
        "unknown",
        "{doc}"
    );
    let said = exits(&w.trigon(&["check", lock]), 0);
    assert!(
        said.contains("it is not required, so only its own answers are missing"),
        "{said}"
    );
    // Required, its being unknown fails every package.
    let said = exits(&w.trigon(&["check", lock, "--require", "b"]), 4);
    assert!(said.contains("it is required"), "{said}");
    assert!(
        said.contains("fails the check: `b` required, and could not answer"),
        "{said}"
    );
    // The SARIF files each such package under the source that fails it, at error, and never as
    // the warning a's answer alone would be.
    let sarif = json_of(
        &w.trigon(&["check", lock, "--require", "b", "--format", "sarif"]),
        4,
    );
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 2, "{sarif}");
    for r in results {
        assert_eq!(r["ruleId"], "trigon/required-source-unknown", "{r}");
        assert_eq!(r["level"], "error", "{r}");
        assert_eq!(r["kind"], "fail", "{r}");
        assert_eq!(r["properties"]["status"], "normalized", "{r}");
        assert_eq!(
            r["properties"]["sources"][1]["said"],
            "unknown, and it is required"
        );
    }
    // A required source the command does not ask could never fail it: refused, exit 5.
    let said = exits(
        &w.trigon(&["check", lock, "--source", "a", "--require", "b"]),
        5,
    );
    assert!(
        said.contains("names a source --source leaves out"),
        "{said}"
    );
    exits(
        &w.trigon(&[
            "check",
            lock,
            "--source",
            "a",
            "--source",
            "b",
            "--require",
            "b",
        ]),
        4,
    );
    std::fs::rename(b.dir.join("gone.git"), &b.remote).unwrap();

    // A record signed with a's key, logged by b's log key in b's repository: b's pinned key is
    // not the key that signed it, and the record is refused there.
    let a_log = verify_log(
        &DirFiles::new(w.checkout("a-log").join("log")),
        &w.vkey(),
        None,
    )
    .unwrap();
    let leaf = a_log.leaf(0).unwrap().clone();
    let Leaf::Record(r) = &leaf else {
        panic!("leaf 0 is a record")
    };
    let digest = r.record.to_hex();
    assert_eq!(digest, w.record_of(&xa));
    let bytes = std::fs::read(w.checkout("a-files").join(record_path(&digest))).unwrap();
    let mut late = r.clone();
    late.time = now();
    b.append_signed(
        &b.remote,
        vec![Leaf::Record(late)],
        &[(record_path(&digest), bytes)],
    );
    ok(&w.sync(&["--source", "b"]));
    let doc = json_of(
        &w.trigon(&[
            "lookup",
            &x.integrity(),
            "--source",
            "b",
            "--output",
            "json",
        ]),
        4,
    );
    let records = doc["sources"][0]["records"].as_array().unwrap();
    let foreign = records
        .iter()
        .find(|r| r["record"] == format!("sha256:{digest}"))
        .unwrap_or_else(|| panic!("{doc}"));
    assert_eq!(foreign["state"], "failed-verification", "{doc}");
    assert_eq!(foreign["failure"]["kind"], "signature", "{doc}");
    // And a's answer about it is a's own, unchanged.
    exits(&w.trigon(&["lookup", &x.integrity(), "--source", "a"]), 0);
}

/// `--remote` answers one question with plain GETs, proving each record's leaf included from the
/// log's tiles and running no git at all; it says its three caveats whenever it is used; a record
/// whose leaf it cannot prove — the index pointing it at another leaf, or a hash tile altered —
/// fails verification, exit 4; a served log behind the checkpoint a sync accepted is refused; and a
/// source with no github.com HTTPS URL cannot be asked this way, exit 5.
#[test]
fn remote_proves_inclusion_and_refuses_what_it_cannot_prove() {
    let w = World::new("remote");
    w.init();
    let (a, b) = (Package::new("a", false), Package::new("b", false));
    let ra = w.record_of(&w.publish_package(&a, "aaaa"));
    w.publish_package(&b, "bbbb");
    let server = Server::start();
    let served = w.checkout("served");
    server.state().serve("owner/trigon-evidence", &served);
    let url = github_url_to(&w, &w.remote);
    ok(&w.add("gh", &[url], &[]));
    let remote = |args: &[&str]| {
        let mut c = w.command(args);
        c.env("TRIGON_EVIDENCE_RAW_BASE", server.url());
        c.output().unwrap()
    };
    w.git_calls();
    server.asked();

    let said = exits(&remote(&["lookup", &a.integrity(), "--remote"]), 0);
    assert!(said.contains("answer    normalized"), "{said}");
    assert!(
        said.contains("read over HTTPS from owner/trigon-evidence"),
        "{said}"
    );
    assert_eq!(said.matches("caveat    --remote").count(), 3, "{said}");
    assert!(
        said.contains("tells GitHub which package was asked about"),
        "{said}"
    );
    assert!(said.contains("rate-limited"), "{said}");
    assert!(
        said.contains("only where the index file for the key lists it"),
        "{said}"
    );
    assert!(w.git_calls().is_empty(), "--remote runs no git");
    assert!(w.clones("gh").is_empty(), "and makes no clone");
    let asked = server.asked();
    let sha512 = a.sha512();
    for path in [
        "log/checkpoint".to_string(),
        format!(
            "index/sha512/{}/{}/{sha512}.json",
            &sha512[..2],
            &sha512[2..4]
        ),
        record_path(&ra),
        "log/tile/entries/000.p/2".to_string(),
        "log/tile/0/000.p/2".to_string(),
    ] {
        assert!(
            asked.contains(&format!("/owner/trigon-evidence/HEAD/{path}")),
            "{path}: {asked:#?}"
        );
    }
    // `check --remote` asks the same way, per package.
    let lock = lockfile(
        &w,
        &[("demo-a", &a.integrity()), ("demo-b", &b.integrity())],
    );
    let doc = json_of(
        &remote(&[
            "check",
            lock.to_str().unwrap(),
            "--remote",
            "--format",
            "json",
        ]),
        0,
    );
    assert_eq!(doc["caveats"].as_array().unwrap().len(), 3, "{doc}");
    assert_eq!(row(&doc, &b.target())["status"], "normalized", "{doc}");

    // The index points a's record at leaf 1, whose proven leaf logs b's: not provable.
    let index = served.join(format!(
        "index/sha512/{}/{}/{sha512}.json",
        &sha512[..2],
        &sha512[2..4]
    ));
    let original = std::fs::read(&index).unwrap();
    let mut f: serde_json::Value = serde_json::from_slice(&original).unwrap();
    f["records"][0]["leaf"] = serde_json::json!(1);
    std::fs::write(&index, serde_json::to_vec(&f).unwrap()).unwrap();
    let said = exits(&remote(&["lookup", &a.integrity(), "--remote"]), 4);
    assert!(said.contains("FAILED VERIFICATION"), "{said}");
    assert!(said.contains("and that leaf logs sha256:"), "{said}");
    std::fs::write(&index, &original).unwrap();

    // A hash tile altered: the inclusion proof leads to no signed root.
    let tile = served.join("log/tile/0/000.p/2");
    let original = std::fs::read(&tile).unwrap();
    let mut bytes = original.clone();
    bytes[40] ^= 0xff;
    std::fs::write(&tile, &bytes).unwrap();
    let said = exits(&remote(&["lookup", &a.integrity(), "--remote"]), 4);
    assert!(said.contains("could not be proven included"), "{said}");
    std::fs::write(&tile, &original).unwrap();
    exits(&remote(&["lookup", &a.integrity(), "--remote"]), 0);

    // Synced, the source is held to the checkpoint it accepted: what is served behind it is
    // refused as a rollback.
    w.publish_package(&Package::new("c", false), "cccc");
    ok(&w.sync(&[]));
    let said = exits(&remote(&["lookup", &a.integrity(), "--remote"]), 4);
    assert!(said.contains("REFUSED"), "{said}");
    assert!(said.contains("does not extend the checkpoint"), "{said}");
    // Served as the repository now is, it extends it, by a consistency proof from the tiles.
    let served = w.checkout("served");
    server.state().serve("owner/trigon-evidence", &served);
    exits(&remote(&["lookup", &a.integrity(), "--remote"]), 0);

    // A source whose only location is not a GitHub HTTPS URL cannot be asked this way.
    ok(&w.add("local", &[w.remote.to_str().unwrap()], &[]));
    let said = exits(&remote(&["lookup", &a.integrity(), "--remote"]), 5);
    assert!(
        said.contains("`local` has no https://github.com/<owner>/<repo> URL"),
        "{said}"
    );
    exits(
        &remote(&["lookup", &a.integrity(), "--remote", "--source", "gh"]),
        0,
    );
}

/// What `--remote` cannot read is unknown, as `docs/19` §4.2 has a failed `--remote` lookup, and
/// never a failed verification, which says it may be an attack: a tile the host answers 500 or 429
/// for, one it does not serve, and an index entry past the checkpoint read, which is what a publish
/// landing between two requests looks like. And it holds to the state as a sync does: a key
/// history recorded under another pin than the configuration's now is not used, and a source
/// whose last sync was refused answers nothing.
#[test]
fn remote_answers_unknown_for_what_it_cannot_read_and_holds_to_the_state() {
    let w = World::new("remote-state");
    w.init();
    let (a, b) = (Package::new("a", false), Package::new("b", false));
    let a_id = w.publish_package(&a, "aaaa");
    w.publish_package(&b, "bbbb");
    let server = Server::start();
    let served = w.checkout("served");
    server.state().serve("owner/trigon-evidence", &served);
    let url = github_url_to(&w, &w.remote);
    ok(&w.add("gh", &[url], &[]));
    let remote = |args: &[&str]| {
        let mut c = w.command(args);
        c.env("TRIGON_EVIDENCE_RAW_BASE", server.url());
        c.output().unwrap()
    };
    // Unknown, for this question: the source was read, and what answers it could not be.
    let unknown = |key: &str, why: &str| {
        let said = exits(&remote(&["lookup", key, "--remote"]), 4);
        assert!(said.contains("answer    unknown"), "{said}");
        assert!(said.contains("--remote could not answer"), "{said}");
        assert!(said.contains(why), "{why}: {said}");
        assert!(!said.contains("FAILED VERIFICATION"), "{said}");
    };
    exits(&remote(&["lookup", &a.integrity(), "--remote"]), 0);
    let lock = lockfile(&w, &[("demo-a", &a.integrity())]);
    let lock = lock.to_str().unwrap();
    let ra = w.record_of(&a_id);

    // The host failing, or rate-limiting, the request for a record whose index file it served:
    // the source cannot answer that question, and nothing about the record is known.
    for status in [500, 429] {
        server.state().fail = vec![(record_path(&ra), status)];
        unknown(&a.integrity(), &format!("it answered {status}"));
        let doc = json_of(&remote(&["check", lock, "--remote", "--format", "json"]), 4);
        assert_eq!(row(&doc, &a.target())["status"], "unknown", "{doc}");
        assert_eq!(
            row(&doc, &a.target())["sources"][0]["said"],
            "unknown",
            "{doc}"
        );
        // The other package's record is read, and answers.
        exits(&remote(&["lookup", &b.integrity(), "--remote"]), 0);
    }
    // A tile it fails for, or does not serve: nothing can be proven, and the source answers
    // unknown for every question.
    for status in [503, 404] {
        server.state().fail = vec![("log/tile/0/000.p/2".into(), status)];
        let said = exits(&remote(&["lookup", &a.integrity(), "--remote"]), 4);
        assert!(said.contains("answer    unknown"), "{said}");
        assert!(!said.contains("FAILED VERIFICATION"), "{said}");
    }
    server.state().fail.clear();
    exits(&remote(&["lookup", &a.integrity(), "--remote"]), 0);

    // A publish lands between the checkpoint's request and the index file's: the index lists the
    // new record at a leaf past the checkpoint read.
    let c = Package::new("c", false);
    let rc = w.record_of(&w.publish_package(&c, "cccc"));
    let now_served = w.checkout("now-served");
    let sha512 = c.sha512();
    let index = format!(
        "index/sha512/{}/{}/{sha512}.json",
        &sha512[..2],
        &sha512[2..4]
    );
    let record = record_path(&rc);
    for path in [&index, &record] {
        let to = served.join(path);
        std::fs::create_dir_all(to.parent().unwrap()).unwrap();
        std::fs::copy(now_served.join(path), to).unwrap();
    }
    unknown(&c.integrity(), "past the 2 leaves of the checkpoint read");

    // Synced, with its key history recorded, and served as it is now.
    server.state().serve("owner/trigon-evidence", &now_served);
    ok(&w.sync(&[]));
    exits(&remote(&["lookup", &a.integrity(), "--remote"]), 0);
    // The attestation key re-pinned since: the history the sync recorded starts at the key the
    // user pinned away from, and is not used, so a record under that key fails verification here,
    // as it does in the clone.
    let config = std::fs::read_to_string(w.config_path()).unwrap();
    let old = w.attestation().public_hex();
    let other = LocalKey::from_bytes(&[9; 32]).unwrap().public_hex();
    std::fs::write(w.config_path(), config.replace(&old, &other)).unwrap();
    let said = exits(&remote(&["lookup", &a.integrity(), "--remote"]), 4);
    assert!(said.contains("the pin changed since"), "{said}");
    assert!(said.contains("FAILED VERIFICATION (signature)"), "{said}");
    exits(&w.trigon(&["lookup", &a.integrity(), "--offline"]), 4);
    std::fs::write(w.config_path(), &config).unwrap();
    exits(&remote(&["lookup", &a.integrity(), "--remote"]), 0);

    // A sync refused — the repository rolled back behind the checkpoint accepted — and the host
    // serving the raw files as they were: a refused source answers nothing, over HTTPS too.
    let before = git(&w.remote, &["rev-parse", "main"]);
    w.publish_package(&Package::new("d", false), "dddd");
    ok(&w.sync(&[]));
    server
        .state()
        .serve("owner/trigon-evidence", &w.checkout("latest"));
    exits(&remote(&["lookup", &a.integrity(), "--remote"]), 0);
    git(&w.remote, &["update-ref", "refs/heads/main", &before]);
    let said = exits(&w.sync(&[]), 4);
    assert!(said.contains("REFUSED"), "{said}");
    let said = exits(&remote(&["lookup", &a.integrity(), "--remote"]), 4);
    assert!(said.contains("answer    REFUSED"), "{said}");
    assert!(said.contains("its last sync was refused"), "{said}");
    let doc = json_of(&remote(&["check", lock, "--remote", "--format", "json"]), 4);
    assert_eq!(doc["sources"][0]["standing"], "refused", "{doc}");
}

/// `--remote` follows a log-end into its successor in another repository only where the
/// successor's first leaf, proven, is the log-continuation the log-end requires, as a sync
/// follows one: a successor that opens under the key the log-end names and does not begin with
/// one is refused.
#[test]
fn remote_follows_a_succession_only_through_its_continuation() {
    let w = World::new("remote-succession");
    w.init();
    let a = Package::new("a", false);
    w.publish_package(&a, "aaaa");
    let (successor, next) = succeed_elsewhere(&w);
    // Publishing into the successor reads the whole chain, from a source that reaches its first
    // log.
    ok(&w.add("main", &[w.remote.to_str().unwrap()], &[]));
    ok(&w.sync(&[]));
    let b = Package::new("b", false);
    let (id, _) = pair(&w, &b, "bbbb");
    ok(&w.trigon(&[
        "publish",
        "--store",
        w.store.to_str().unwrap(),
        "--repo",
        successor.to_str().unwrap(),
        &id,
    ]));
    let server = Server::start();
    server
        .state()
        .serve("owner/trigon-evidence", &w.checkout("served"));
    let theirs = w.dir.join("successor-served");
    git(
        &w.dir,
        &[
            "clone",
            "--quiet",
            successor.to_str().unwrap(),
            theirs.to_str().unwrap(),
        ],
    );
    server.state().serve("owner/successor", &theirs);
    ok(&w.add("gh", &["https://github.com/owner/trigon-evidence.git"], &[]));
    let remote = |args: &[&str]| {
        let mut c = w.command(args);
        c.args(["--remote", "--source", "gh"])
            .env("TRIGON_EVIDENCE_RAW_BASE", server.url());
        c.output().unwrap()
    };
    let said = exits(&remote(&["lookup", &b.integrity()]), 0);
    assert!(said.contains("answer    normalized"), "{said}");
    assert!(
        said.contains(&format!(
            "`{ORIGIN}` ended, and its successor `{ORIGIN}/1` is read from owner/successor"
        )),
        "{said}"
    );
    exits(&remote(&["lookup", &a.integrity()]), 0);

    // Served in its place: a log the successor's key signs, whose first leaf is a heartbeat, so
    // nothing in it holds the final checkpoint of the log it would go on from.
    let forged = w.dir.join("forged");
    let leaves = vec![
        Leaf::Heartbeat(HeartbeatLeaf { time: now() })
            .encode()
            .unwrap(),
    ];
    let append = trigon_attest::log::plan_append(
        &trigon_attest::log::Tree::new(),
        &[] as &[Vec<u8>],
        &leaves,
    )
    .unwrap();
    for (path, bytes) in &append.files {
        let p = forged.join("log").join(path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }
    let signed = SignedCheckpoint::sign(
        &Checkpoint {
            origin: format!("{ORIGIN}/1"),
            size: append.size,
            root: append.root,
        },
        &LogSigner::from_file(&next).unwrap(),
    )
    .unwrap();
    std::fs::write(forged.join("log/checkpoint"), signed.to_string()).unwrap();
    server.state().serve("owner/successor", &forged);
    let said = exits(&remote(&["lookup", &a.integrity()]), 4);
    assert!(said.contains("answer    REFUSED"), "{said}");
    assert!(
        said.contains("does not begin with a log-continuation leaf"),
        "{said}"
    );
}

/// `verify-attestation --record <file> --source <name>`, with no `--evidence`, reads the source's
/// own clones as its last sync left them, and follows its chain into the repository it has gone
/// on in, as the sync did: a record logged in the successor is checked where it is logged.
#[test]
fn the_record_form_reads_a_sources_clones_across_repositories() {
    let w = World::new("record-form");
    w.init();
    let a = Package::new("a", false);
    let ra = w.record_of(&w.publish_package(&a, "aaaa"));
    git(
        &w.dir,
        &["init", "--quiet", "--bare", "-b", "main", "successor.git"],
    );
    let successor = w.dir.join("successor.git");
    let url = "https://github.com/owner/successor.git";
    std::fs::write(
        w.dir.join("home/.gitconfig"),
        format!(
            "[url \"file://{}\"]\n\tinsteadOf = {url}\n",
            successor.display()
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
    ok(&w.sync(&[]));
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
    let b = Package::new("b", false);
    let (id, _) = pair(&w, &b, "bbbb");
    ok(&w.trigon(&[
        "publish",
        "--store",
        w.store.to_str().unwrap(),
        "--repo",
        successor.to_str().unwrap(),
        &id,
    ]));
    let rb = w.record_of(&id);
    ok(&w.sync(&[]));

    let there = |repo: &Path, hex: &str| {
        let c = w.dir.join(format!("files-{}", &hex[..8]));
        let _ = std::fs::remove_dir_all(&c);
        git(
            &w.dir,
            &[
                "clone",
                "--quiet",
                repo.to_str().unwrap(),
                c.to_str().unwrap(),
            ],
        );
        c.join(record_path(hex))
    };
    let file_b = there(&successor, &rb);
    let said = exits(
        &w.trigon(&[
            "verify-attestation",
            "--record",
            file_b.to_str().unwrap(),
            "--source",
            "main",
        ]),
        0,
    );
    assert!(said.contains("read from its clones in"), "{said}");
    assert!(
        said.contains(&format!(
            "record    sha256:{rb} at leaf 1 of example.com/trigon-evidence/1"
        )),
        "{said}"
    );
    assert!(
        said.contains("is followed into another repository"),
        "{said}"
    );
    assert!(said.contains("answer    normalized"), "{said}");
    let file_a = there(&w.remote, &ra);
    let said = exits(
        &w.trigon(&[
            "verify-attestation",
            "--record",
            file_a.to_str().unwrap(),
            "--source",
            "main",
        ]),
        0,
    );
    assert!(
        said.contains(&format!("record    sha256:{ra} at leaf 0 of {ORIGIN}")),
        "{said}"
    );
    // Given the first repository alone, the same record's answer now is unknown: its log goes on
    // where that directory does not reach.
    let said = exits(
        &w.trigon(&[
            "verify-attestation",
            "--record",
            file_a.to_str().unwrap(),
            "--evidence",
            file_a
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .to_str()
                .unwrap(),
            "--source",
            "main",
        ]),
        4,
    );
    assert!(said.contains("answer    unknown"), "{said}");
}

/// A sync removes, from the cache and nowhere else, the clone of a location the source no longer
/// names, and says so.
#[test]
fn a_sync_removes_the_clone_of_a_location_no_longer_configured() {
    let w = World::new("forget");
    w.init();
    let a = Package::new("a", false);
    w.publish_package(&a, "aaaa");
    let mirror = w.dir.join("mirror.git");
    git(
        &w.dir,
        &[
            "clone",
            "--quiet",
            "--bare",
            w.remote.to_str().unwrap(),
            mirror.to_str().unwrap(),
        ],
    );
    let source = |urls: &str| {
        w.config(&format!(
            "[[source]]\nname = \"main\"\nurls = [{urls}]\nlog_key = \"{}\"\nattestation_key = \"{}\"\n",
            w.vkey(),
            w.attestation().public_hex()
        ));
    };
    source(&format!(
        "\"{}\", \"{}\"",
        w.remote.display(),
        mirror.display()
    ));
    ok(&w.sync(&[]));
    assert_eq!(w.clones("main").len(), 2);
    let checkpoint = std::fs::read(w.state("main").join("checkpoint")).unwrap();

    source(&format!("\"{}\"", w.remote.display()));
    let said = ok(&w.sync(&[]));
    assert!(
        said.contains(&format!(
            "removed the clone of {}, a location this source no longer names, from the cache",
            mirror.display()
        )),
        "{said}"
    );
    assert_eq!(w.clones("main").len(), 1);
    assert_eq!(
        std::fs::read(w.state("main").join("checkpoint")).unwrap(),
        checkpoint,
        "its state is the source's, and stays"
    );
    exits(&w.trigon(&["lookup", &a.integrity()]), 0);
    // Nothing more to remove.
    let said = ok(&w.sync(&[]));
    assert!(!said.contains("removed the clone"), "{said}");
}

/// `check`'s threshold is §6's: `--min` an outcome floor through `Match::is_at_least`, and
/// `--max-risk` a cap on the riskiest stabilizer a verdict was reached through, each exit 3 below
/// it. What the tool cannot read is exit 5: a lockfile, an argument, a key, no source. `--store`
/// checks a local store as `check` always did.
#[test]
fn check_holds_answers_to_the_threshold_and_refuses_what_it_cannot_read() {
    let w = World::new("threshold");
    w.init();
    let a = Package::new("a", false);
    w.publish_package(&a, "aaaa");
    // No source yet: a command that needs one says so, exit 5.
    let lock = lockfile(&w, &[("demo-a", &a.integrity())]);
    let lock = lock.to_str().unwrap();
    let said = exits(&w.trigon(&["check", lock]), 5);
    assert!(said.contains("no evidence source is configured"), "{said}");
    exits(&w.trigon(&["lookup", &a.integrity()]), 5);
    ok(&w.add("main", &[w.remote.to_str().unwrap()], &[]));

    exits(&w.trigon(&["check", lock]), 0);
    let doc = json_of(
        &w.trigon(&["check", lock, "--min", "exact", "--format", "json"]),
        3,
    );
    assert_eq!(row(&doc, &a.target())["status"], "normalized");
    assert_eq!(row(&doc, &a.target())["exit"], 3);
    // Normalized through a metadata-risk pass: above `structural`, within `metadata`.
    let doc = json_of(
        &w.trigon(&[
            "check",
            lock,
            "--max-risk",
            "structural",
            "--format",
            "json",
        ]),
        3,
    );
    assert_eq!(
        row(&doc, &a.target())["status"],
        "above --max-risk",
        "{doc}"
    );
    assert_eq!(doc["maxRisk"], "structural");
    exits(&w.trigon(&["check", lock, "--max-risk", "metadata"]), 0);
    let sarif = json_of(
        &w.trigon(&[
            "check",
            lock,
            "--max-risk",
            "structural",
            "--format",
            "sarif",
        ]),
        3,
    );
    let result = &sarif["runs"][0]["results"][0];
    assert_eq!(result["ruleId"], "trigon/above-max-risk", "{sarif}");
    assert_eq!(
        result["properties"]["sources"][0]["name"], "main",
        "{sarif}"
    );
    // Every package is in the SARIF with every source's answer, the ones that pass too.
    let sarif = json_of(&w.trigon(&["check", lock, "--format", "sarif"]), 0);
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 1, "{sarif}");
    assert_eq!(results[0]["ruleId"], "trigon/pass", "{sarif}");
    assert_eq!(results[0]["kind"], "pass", "{sarif}");
    assert_eq!(results[0]["level"], "none", "{sarif}");
    assert_eq!(
        results[0]["properties"]["sources"][0]["said"], "normalized",
        "{sarif}"
    );
    assert_eq!(
        results[0]["properties"]["sources"][0]["records"][0]["state"], "verified",
        "{sarif}"
    );

    // Found by digest first: a requirement whose `--hash` is the artifact's sha256, whatever
    // package it names.
    let reqs = w.dir.join("project/requirements.txt");
    std::fs::write(
        &reqs,
        format!("renamed==1.0.0 \\\n    --hash=sha256:{}\n", a.sha256()),
    )
    .unwrap();
    let doc = json_of(
        &w.trigon(&["check", reqs.to_str().unwrap(), "--format", "json"]),
        0,
    );
    let r = row(&doc, "pkg:pypi/renamed@1.0.0");
    assert_eq!(
        r["version"], "1.0.0",
        "the hash is no part of the version: {r}"
    );
    assert_eq!(r["status"], "normalized", "{r}");
    assert_eq!(r["sources"][0]["foundBy"], serde_json::json!(["sha256"]));
    // A purl whose records are all about another artifact than the one the lockfile pins is not
    // an answer about it.
    let other = Package::new("other", false);
    let lock2 = lockfile(&w, &[("demo-a", &other.integrity())]);
    let doc = json_of(
        &w.trigon(&["check", lock2.to_str().unwrap(), "--format", "json"]),
        2,
    );
    let r = row(&doc, &a.target());
    assert_eq!(r["status"], "never checked", "{r}");
    assert!(
        r["sources"][0]["answerNotes"][0]
            .as_str()
            .unwrap()
            .contains("about another artifact than the one the lockfile pins"),
        "{r}"
    );
    // An SBOM keeps every package: one found by its checksum, one of an ecosystem nothing here
    // rebuilds, and one with nothing to look it up by.
    let sbom = w.dir.join("project/app.spdx.json");
    std::fs::write(
        &sbom,
        serde_json::to_vec(&serde_json::json!({
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {"SPDXID": "SPDXRef-a", "name": "vendored-a", "versionInfo": "1",
                 "checksums": [{"algorithm": "SHA512", "checksumValue": a.sha512()}]},
                {"SPDXID": "SPDXRef-deb", "name": "openssl", "externalRefs": [
                    {"referenceType": "purl", "referenceLocator": "pkg:deb/debian/openssl@3.0.11"}]},
                {"SPDXID": "SPDXRef-bare", "name": "bare"}
            ]
        }))
        .unwrap(),
    )
    .unwrap();
    let doc = json_of(
        &w.trigon(&["check", sbom.to_str().unwrap(), "--format", "json"]),
        2,
    );
    assert_eq!(doc["packages"], 3, "{doc}");
    let by_name = |n: &str| {
        doc["results"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == n)
            .unwrap_or_else(|| panic!("{n}: {doc}"))
            .clone()
    };
    assert_eq!(by_name("vendored-a")["status"], "normalized");
    assert_eq!(by_name("openssl")["status"], "never checked");
    assert_eq!(by_name("bare")["status"], "never checked");
    assert!(
        by_name("bare")["unfindable"]
            .as_str()
            .unwrap()
            .contains("nothing to look it up by")
    );

    // What cannot be read is the tool failing, exit 5 — `clap`'s refusals among them.
    exits(&w.trigon(&["check", "missing/package-lock.json"]), 5);
    exits(&w.trigon(&["check", "Cargo.lock"]), 5);
    exits(&w.trigon(&["check", lock, "--min", "perfect"]), 5);
    exits(&w.trigon(&["check", lock, "--offline", "--remote"]), 5);
    exits(&w.trigon(&["check", lock, "--source", "nothing"]), 5);
    exits(&w.trigon(&["check", lock, "--require", "nothing"]), 5);
    exits(&w.trigon(&["lookup", "not-a-key"]), 5);
    exits(&w.trigon(&["--theme", "bbs", "lookup"]), 5);

    // `--store` is `check` as it was: a local store's newest runs, five rows, exit 0.
    let said = exits(
        &w.trigon(&["check", lock, "--store", w.store.to_str().unwrap()]),
        0,
    );
    assert!(said.contains("reproduced"), "{said}");
    exits(
        &w.trigon(&[
            "check",
            lock,
            "--store",
            w.store.to_str().unwrap(),
            "--offline",
        ]),
        5,
    );
}

/// A package is answered for the artifact its lockfile pins, and for nothing else of its name.
/// Two artifacts of one name and version are two packages, each answered for itself. A record
/// found by sha1 whose sha512 is not the one the lockfile declares is another artifact's, and
/// answers nothing; one found by the sha512 answers, and a sha1 beside it that disagrees is said.
/// A record found by purl whose subject carries none of the algorithms the lockfile declares
/// answers, and says it could not be compared. An SBOM's purl without a version is the version
/// its `versionInfo` gives.
#[test]
fn check_answers_for_the_artifact_the_lockfile_pins() {
    let w = World::new("pinned");
    w.init();
    let a = Package::new("a", false);
    let p = Package::pypi("p");
    w.publish_package(&a, "aaaa");
    w.publish_package(&p, "pppp");
    ok(&w.add("main", &[w.remote.to_str().unwrap()], &[]));
    let other = Package::new("other", false);
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let sha1_of = |x: &Package| b64(&trigon_attest::sha1_of(&x.upstream).0);
    let npm = |entries: &[(&str, String)]| {
        let mut packages = serde_json::Map::new();
        packages.insert("".into(), serde_json::json!({"name": "consumer"}));
        for (path, integrity) in entries {
            packages.insert(
                (*path).into(),
                serde_json::json!({"version": "1.0.0", "integrity": integrity}),
            );
        }
        let path = w.dir.join("project/package-lock.json");
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(
                &serde_json::json!({"lockfileVersion": 3, "packages": packages}),
            )
            .unwrap(),
        )
        .unwrap();
        path
    };
    let rows = |doc: &serde_json::Value, purl: &str| -> Vec<serde_json::Value> {
        doc["results"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["purl"] == purl)
            .cloned()
            .collect()
    };

    // Two artifacts of demo-a@1.0.0: the one published, and a substitute nothing has checked.
    let lock = npm(&[
        ("node_modules/demo-a", a.integrity()),
        ("node_modules/x/node_modules/demo-a", other.integrity()),
    ]);
    let doc = json_of(
        &w.trigon(&["check", lock.to_str().unwrap(), "--format", "json"]),
        2,
    );
    assert_eq!(doc["packages"], 2, "{doc}");
    let two = rows(&doc, &a.target());
    let statuses: Vec<&str> = two.iter().map(|r| r["status"].as_str().unwrap()).collect();
    assert_eq!(statuses.len(), 2, "{doc}");
    assert!(statuses.contains(&"normalized"), "{doc}");
    assert!(statuses.contains(&"never checked"), "{doc}");
    let said = exits(&w.trigon(&["check", lock.to_str().unwrap()]), 2);
    assert!(
        said.contains(&format!(
            "pkg:npm/demo-a@1.0.0 (sha512:{}…) — never checked",
            &other.sha512()[..16]
        )),
        "{said}"
    );

    // The sha512 of another artifact, and the sha1 of the one published: that record is another
    // artifact's, found by a collision-broken digest, and the package is never checked.
    let lock = npm(&[(
        "node_modules/demo-a",
        format!("{} sha1-{}", other.integrity(), sha1_of(&a)),
    )]);
    let doc = json_of(
        &w.trigon(&["check", lock.to_str().unwrap(), "--format", "json"]),
        2,
    );
    let r = row(&doc, &a.target());
    assert_eq!(r["status"], "never checked", "{r}");
    assert_eq!(r["sources"][0]["records"], serde_json::json!([]), "{r}");
    let notes = r["sources"][0]["answerNotes"].to_string();
    assert!(
        notes.contains("found by sha1, is about another artifact"),
        "{notes}"
    );
    assert!(notes.contains("sha1 is collision-broken"), "{notes}");
    assert!(
        notes.contains(&format!("the lockfile declares sha512:{}", other.sha512())),
        "{notes}"
    );
    // The other way about: the sha512 decides, and the sha1 that disagrees is said.
    let lock = npm(&[(
        "node_modules/demo-a",
        format!("{} sha1-{}", a.integrity(), sha1_of(&other)),
    )]);
    let doc = json_of(
        &w.trigon(&["check", lock.to_str().unwrap(), "--format", "json"]),
        0,
    );
    let r = row(&doc, &a.target());
    assert_eq!(r["status"], "normalized", "{r}");
    assert_eq!(
        r["sources"][0]["foundBy"],
        serde_json::json!(["sha512"]),
        "{r}"
    );
    assert!(
        r["sources"][0]["answerNotes"]
            .to_string()
            .contains("the lockfile's digests are not of one artifact"),
        "{r}"
    );

    // An SBOM: demo-p, a PyPI package, declares only a sha1, which its record's subject does not
    // carry, so the record found by purl answers, and says it could not be compared; demo-a's
    // purl names no version, and `versionInfo` gives two, each its own package.
    let sbom = w.dir.join("project/app.spdx.json");
    let purl_ref =
        |locator: &str| serde_json::json!([{"referenceType": "purl", "referenceLocator": locator}]);
    std::fs::write(
        &sbom,
        serde_json::to_vec(&serde_json::json!({
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {"SPDXID": "SPDXRef-p", "name": "demo-p",
                 "externalRefs": purl_ref(&p.target()),
                 "checksums": [{"algorithm": "SHA1", "checksumValue": other.sha1()}]},
                {"SPDXID": "SPDXRef-a1", "name": "demo-a", "versionInfo": "1.0.0",
                 "externalRefs": purl_ref("pkg:npm/demo-a")},
                {"SPDXID": "SPDXRef-a2", "name": "demo-a", "versionInfo": "2.0.0",
                 "externalRefs": purl_ref("pkg:npm/demo-a")},
                {"SPDXID": "SPDXRef-a3", "name": "demo-a",
                 "externalRefs": purl_ref("pkg:npm/demo-a")}
            ]
        }))
        .unwrap(),
    )
    .unwrap();
    let doc = json_of(
        &w.trigon(&["check", sbom.to_str().unwrap(), "--format", "json"]),
        2,
    );
    assert_eq!(doc["packages"], 4, "{doc}");
    let r = row(&doc, &p.target());
    assert_eq!(r["status"], "normalized", "{r}");
    assert_eq!(
        r["sources"][0]["foundBy"],
        serde_json::json!(["purl"]),
        "{r}"
    );
    assert!(
        r["sources"][0]["answerNotes"]
            .to_string()
            .contains("could not be compared"),
        "{r}"
    );
    assert_eq!(row(&doc, &a.target())["status"], "normalized", "{doc}");
    assert_eq!(
        row(&doc, "pkg:npm/demo-a@2.0.0")["status"],
        "never checked",
        "{doc}"
    );
    // No version at all: every version's records are no answer about the one installed.
    let bare = row(&doc, "pkg:npm/demo-a");
    assert_eq!(bare["status"], "never checked", "{bare}");
    assert!(
        bare["unfindable"]
            .as_str()
            .unwrap()
            .contains("with no version"),
        "{bare}"
    );
}

/// `lookup` takes a key as a person has one: npm's integrity string, `sha256:`, `sha512:` and
/// `sha1:` with their hex, a purl with its version, a package without one, or the file itself.
/// Found by sha1 alone, it says sha1 is collision-broken.
#[test]
fn lookup_takes_every_form_of_key() {
    let w = World::new("keys");
    w.init();
    let a = Package::new("a", false);
    w.publish_package(&a, "aaaa");
    ok(&w.add("main", &[w.remote.to_str().unwrap()], &[]));
    let file = w.dir.join(a.file());
    std::fs::write(&file, &a.upstream).unwrap();
    for key in [
        a.integrity(),
        format!("sha256:{}", a.sha256()),
        format!("sha512:{}", a.sha512()),
        format!("sha1:{}", a.sha1()),
        a.target(),
        "pkg:npm/demo-a".into(),
        file.display().to_string(),
    ] {
        let doc = json_of(&w.trigon(&["lookup", &key, "--output", "json"]), 0);
        assert_eq!(doc["sources"][0]["answer"], "normalized", "{key}: {doc}");
        assert_eq!(
            doc["sources"][0]["records"].as_array().unwrap().len(),
            1,
            "{key}"
        );
    }
    let said = exits(&w.trigon(&["lookup", &format!("sha1:{}", a.sha1())]), 0);
    assert!(
        said.contains("found by sha1 alone, which is collision-broken"),
        "{said}"
    );
    let said = exits(&w.trigon(&["lookup", &format!("sha256:{}", a.sha256())]), 0);
    assert!(!said.contains("collision-broken"), "{said}");
    exits(&w.trigon(&["lookup", "pkg:npm/demo-nothing@1.0.0"]), 2);
}
