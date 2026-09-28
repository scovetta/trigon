//! Where evidence is published to and read from: `evidence.toml`, and the environment.
//!
//! `docs/19` §2.4 in full. Nothing about a repository's location is compiled in; the repository
//! `publish` writes to and every source a consumer syncs are named here, and this module turns the
//! files and the environment into one resolved [`EvidenceConfig`] that the rest of the code asks.
//!
//! **Here, in `trigon-attest`, rather than in the binary**, because both builds read it: the
//! network-free verifier takes a source's keys and checkpoint from `--source <name>`, so the
//! parser has to link without a runtime or a network client, which this crate is held to by `xtask
//! policy`. It reads files and the environment and opens no socket.
//!
//! What it reads, in order, each able to add to what came before and none able to take away:
//!
//! 1. The user's file, `$XDG_CONFIG_HOME/trigon/evidence.toml` (`~/.config/trigon/evidence.toml`
//!    when that is unset), or the file `TRIGON_EVIDENCE_CONFIG` names instead.
//! 2. The environment: `TRIGON_PUBLISH_REPO` replaces `[publish] repo`; `TRIGON_EVIDENCE_REPO`
//!    adds a required source named `env`, pinned by `TRIGON_EVIDENCE_LOG_KEY` and
//!    `TRIGON_EVIDENCE_ATTESTATION_KEY`; `TRIGON_EVIDENCE_CACHE` and `TRIGON_EVIDENCE_STATE`
//!    replace the two directories.
//! 3. The project's file, `.trigon/evidence.toml` in the working directory, unless
//!    `TRIGON_EVIDENCE_CONFIG` is set. It is chosen by whoever controls the project — in CI on a
//!    pull request, its author — so it is held to less: see [`load`]'s project rules.
//!
//! **An unknown key is an error, in every table.** This file pins the keys a verdict is checked
//! against, and a typo in a security setting that is silently ignored is a setting that is
//! silently off.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::keys::{AttestationKey, LogVkey};
use crate::location::{Location, printable};

/// The name of the source `TRIGON_EVIDENCE_REPO` adds, reserved so no file can shadow it.
pub const ENV_SOURCE: &str = "env";

/// The process environment, as far as this module reads it, captured once.
///
/// A value rather than calls to `std::env` scattered through the loader, so a test states the
/// environment it means instead of mutating the process's, which is unsafe under a threaded test
/// harness and leaks between tests.
#[derive(Clone, Debug, Default)]
pub struct Env {
    /// The working directory: where `.trigon/evidence.toml` is looked for, and what a relative
    /// path from the environment is relative to. Absolute.
    pub cwd: PathBuf,
    pub home: Option<PathBuf>,
    pub xdg_config_home: Option<PathBuf>,
    pub xdg_cache_home: Option<PathBuf>,
    pub xdg_state_home: Option<PathBuf>,
    /// `TRIGON_EVIDENCE_CONFIG`
    pub evidence_config: Option<PathBuf>,
    /// `TRIGON_PUBLISH_REPO`
    pub publish_repo: Option<String>,
    /// `TRIGON_EVIDENCE_REPO`: one or more locations, separated by whitespace.
    pub evidence_repo: Option<String>,
    /// `TRIGON_EVIDENCE_LOG_KEY`
    pub evidence_log_key: Option<String>,
    /// `TRIGON_EVIDENCE_ATTESTATION_KEY`
    pub evidence_attestation_key: Option<String>,
    /// `TRIGON_EVIDENCE_CHECKPOINT`
    pub evidence_checkpoint: Option<String>,
    /// `TRIGON_EVIDENCE_TOFU`
    pub evidence_tofu: Option<String>,
    /// `TRIGON_EVIDENCE_CACHE`
    pub evidence_cache: Option<PathBuf>,
    /// `TRIGON_EVIDENCE_STATE`
    pub evidence_state: Option<PathBuf>,
}

impl Env {
    /// Read this process's environment. An empty variable counts as unset, as a shell's `FOO=`
    /// usually means.
    pub fn from_process() -> Result<Env, ConfigError> {
        let cwd = std::env::current_dir().map_err(|e| ConfigError::Env {
            var: "the working directory",
            message: format!("cannot be read ({e})"),
        })?;
        let path = |var: &str| {
            std::env::var_os(var)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        };
        fn text(var: &'static str) -> Result<Option<String>, ConfigError> {
            match std::env::var_os(var).filter(|v| !v.is_empty()) {
                None => Ok(None),
                Some(v) => v.into_string().map(Some).map_err(|_| ConfigError::Env {
                    var,
                    message: "is not valid Unicode".into(),
                }),
            }
        }
        Ok(Env {
            cwd,
            home: path("HOME"),
            xdg_config_home: path("XDG_CONFIG_HOME"),
            xdg_cache_home: path("XDG_CACHE_HOME"),
            xdg_state_home: path("XDG_STATE_HOME"),
            evidence_config: path("TRIGON_EVIDENCE_CONFIG"),
            publish_repo: text("TRIGON_PUBLISH_REPO")?,
            evidence_repo: text("TRIGON_EVIDENCE_REPO")?,
            evidence_log_key: text("TRIGON_EVIDENCE_LOG_KEY")?,
            evidence_attestation_key: text("TRIGON_EVIDENCE_ATTESTATION_KEY")?,
            evidence_checkpoint: text("TRIGON_EVIDENCE_CHECKPOINT")?,
            evidence_tofu: text("TRIGON_EVIDENCE_TOFU")?,
            evidence_cache: path("TRIGON_EVIDENCE_CACHE"),
            evidence_state: path("TRIGON_EVIDENCE_STATE"),
        })
    }

    /// An XDG base directory, or the default under HOME. A relative value is ignored, as the XDG
    /// specification requires: it names no fixed place.
    fn xdg(&self, set: &Option<PathBuf>, default: &str) -> Option<PathBuf> {
        match set {
            Some(p) if p.is_absolute() => Some(p.clone()),
            _ => self.home.as_ref().map(|h| h.join(default)),
        }
    }

    /// Where the user's own `evidence.toml` is, whether or not it exists.
    pub fn user_config_path(&self) -> Option<PathBuf> {
        match &self.evidence_config {
            Some(p) => Some(absolute(p, &self.cwd)),
            None => self
                .xdg(&self.xdg_config_home, ".config")
                .map(|d| d.join("trigon").join("evidence.toml")),
        }
    }
}

/// What configuration is wrong, where, and what to do about it.
///
/// Every variant is the tool failing before it could answer, which `docs/19` §6 gives exit code
/// 5, so [`Self::exit_code`] is 5 for all of them.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading {}: {source}", path.display())]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(
        "TRIGON_EVIDENCE_CONFIG names {}, which does not exist. Unset it to read \
         ~/.config/trigon/evidence.toml, or point it at the file you meant",
        path.display()
    )]
    NamedFileMissing { path: PathBuf },
    #[error("{}: {message}", path.display())]
    File { path: PathBuf, message: String },
    #[error(
        "{} is refused, all of it: {rule}. A project's evidence.toml may only add [[source]] \
         entries, each under a new name, with both keys and an initial checkpoint pinned, HTTPS \
         URLs only, and files inside the project (docs/19 §2.4)",
        path.display()
    )]
    ProjectRule { path: PathBuf, rule: String },
    #[error("{var} {message}")]
    Env { var: &'static str, message: String },
    #[error(
        "no evidence source is configured, so there is nothing to answer from. Add a [[source]] \
         to {config} with its `urls`, `log_key` and `attestation_key`, or set TRIGON_EVIDENCE_REPO \
         with TRIGON_EVIDENCE_LOG_KEY and TRIGON_EVIDENCE_ATTESTATION_KEY (docs/19 §2.4)"
    )]
    NoSource { config: String },
    #[error("there is no {what} directory: set {var}, or HOME so the default under it can be used")]
    NoDirectory {
        what: &'static str,
        var: &'static str,
    },
}

impl ConfigError {
    /// `docs/19` §6: the tool itself failed — bad arguments, an unreadable input, or no source
    /// configured.
    pub fn exit_code(&self) -> i32 {
        5
    }
}

/// `divergences`, docs/19 D7: what `publish` does with a divergence.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Divergences {
    /// Refuse to publish one, until safeguard 4 has a channel. The default.
    #[default]
    Refuse,
    /// Publish, and write the entry to `feed/divergences.atom` in the same commit.
    Feed,
}

/// `rebuilt_artifacts`, docs/19 D4: whether a rebuilt artifact is published beside its record.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RebuiltArtifacts {
    /// Not published: the falsifying command takes `--rebuild <file>`. The default.
    #[default]
    None,
    /// Published as a release asset of the evidence repository, named by digest.
    GithubRelease,
}

/// `[publish]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishConfig {
    /// The repository `publish` writes to: `[publish] repo`, or `TRIGON_PUBLISH_REPO` over it.
    pub repo: Option<Location>,
    pub branch: String,
    /// The log's origin, schema-less (`github.com/<owner>/trigon-evidence`).
    pub origin: Option<String>,
    /// Where a dispute is filed, an `https://` URL.
    pub disputes: Option<String>,
    /// The log's private key, read only by `trigon log sign`. A path, never read here.
    pub log_key: Option<PathBuf>,
    pub divergences: Divergences,
    pub rebuilt_artifacts: RebuiltArtifacts,
    /// docs/19 D8. `false` by default.
    pub same_host_confirmation: bool,
    /// The least time between two agreeing attempts. One hour by default.
    pub confirmation_interval: Duration,
    /// The longest the log goes without a leaf before a heartbeat is logged. Seven days by default.
    pub heartbeat: Duration,
}

impl Default for PublishConfig {
    fn default() -> Self {
        PublishConfig {
            repo: None,
            branch: "main".into(),
            origin: None,
            disputes: None,
            log_key: None,
            divergences: Divergences::default(),
            rebuilt_artifacts: RebuiltArtifacts::default(),
            same_host_confirmation: false,
            confirmation_interval: Duration::from_secs(3600),
            heartbeat: Duration::from_secs(7 * 86_400),
        }
    }
}

impl PublishConfig {
    /// The origin and the dispute channel, when both are set, which is when `attest` signs them
    /// into the falsifying command and the dispute pointer (`docs/19` §2.4, §4.2 item 6).
    ///
    /// Both or neither: a falsifying command that names an origin with no way to dispute beside
    /// it, or a dispute pointer with no command to run, is half of what ADR-0010 requires, and
    /// signing half is how a record comes to look complete when it is not.
    pub fn namespace(&self) -> Option<(&str, &str)> {
        Some((self.origin.as_deref()?, self.disputes.as_deref()?))
    }
}

/// `[freshness]`: the two clocks of `docs/19` §6.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Freshness {
    /// A source whose last successful sync is older than this is synced first. One day.
    pub stale_after: Duration,
    /// A source whose newest leaf is older than this answers unknown. Fourteen days.
    pub frozen_after: Duration,
}

impl Default for Freshness {
    fn default() -> Self {
        Freshness {
            stale_after: Duration::from_secs(86_400),
            frozen_after: Duration::from_secs(14 * 86_400),
        }
    }
}

/// Which file, or the environment, added a source.
///
/// Kept on every source because an answer from a source a project added is input chosen by the
/// thing under test, and every such answer names the file that added it (`docs/19` §2.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddedBy {
    /// The user's own `evidence.toml`, or the file `TRIGON_EVIDENCE_CONFIG` named.
    UserFile(PathBuf),
    /// A project's `.trigon/evidence.toml`.
    ProjectFile(PathBuf),
    /// `TRIGON_EVIDENCE_REPO`.
    Environment,
}

impl std::fmt::Display for AddedBy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddedBy::UserFile(p) => write!(f, "{}", p.display()),
            AddedBy::ProjectFile(p) => write!(f, "{} (the project's own)", p.display()),
            AddedBy::Environment => f.write_str("TRIGON_EVIDENCE_REPO"),
        }
    }
}

/// One evidence source: one log, served from one or more locations (`docs/19` §6.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Source {
    pub name: String,
    /// One log and its mirrors. Never empty.
    pub urls: Vec<Location>,
    /// The pinned log key, whose name is the origin. `None` only under trust on first use.
    pub log_key: Option<LogVkey>,
    /// The pinned attestation key. `None` only under trust on first use.
    pub attestation_key: Option<AttestationKey>,
    /// The initial checkpoint, a file. Not read here.
    pub checkpoint: Option<PathBuf>,
    /// Whether this source being unknown fails a check.
    pub required: bool,
    /// Whether a key this source does not pin is read from the repository's `keys/` on the first
    /// sync. True only where a key is missing and trust on first use was asked for; every answer
    /// from such a source says it rests on keys read that way.
    pub trust_on_first_use: bool,
    pub added_by: AddedBy,
}

/// The resolved configuration: the one view the rest of the code asks.
#[derive(Clone, Debug)]
pub struct EvidenceConfig {
    publish: PublishConfig,
    freshness: Freshness,
    sources: Vec<Source>,
    cache_dir: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    read: Vec<PathBuf>,
    user_config: Option<PathBuf>,
}

impl EvidenceConfig {
    /// Read the files and the environment `env` describes, and resolve them.
    ///
    /// **The project rules.** `.trigon/evidence.toml` may only add `[[source]]` entries, each
    /// under a name no other file or the environment uses, each with `log_key`, `attestation_key`
    /// and `checkpoint`, every URL HTTPS, and neither `required` nor `trust_on_first_use` set. A
    /// file it names — a PEM attestation key, the checkpoint — must be inside the working
    /// directory once symlinks are followed, so a project cannot have Trigon read a file of the
    /// host's by naming it as a key, and so must the project's file itself, which must also be a
    /// regular file of at most [`PROJECT_FILE_LIMIT`] bytes. A file that breaks any rule is refused
    /// whole, with the rule, and every string of the project's a refusal quotes is escaped.
    pub fn load(env: &Env) -> Result<EvidenceConfig, ConfigError> {
        let mut config = EvidenceConfig {
            publish: PublishConfig::default(),
            freshness: Freshness::default(),
            sources: Vec::new(),
            cache_dir: None,
            state_dir: None,
            read: Vec::new(),
            user_config: env.user_config_path(),
        };

        if let Some(path) = config.user_config.clone() {
            match std::fs::read_to_string(&path) {
                Ok(text) => {
                    config.user_file(&path, &text, env)?;
                    config.read.push(path);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    if env.evidence_config.is_some() {
                        return Err(ConfigError::NamedFileMissing { path });
                    }
                }
                Err(source) => return Err(ConfigError::Read { path, source }),
            }
        }

        config.environment(env)?;

        if env.evidence_config.is_none() {
            let path = env.cwd.join(".trigon").join("evidence.toml");
            if let Some(text) = read_project_file(&path, &env.cwd)? {
                config.project_file(&path, &text, env)?;
                config.read.push(path);
            }
        }

        config.cache_dir = match &env.evidence_cache {
            Some(p) => Some(absolute(p, &env.cwd)),
            None => env
                .xdg(&env.xdg_cache_home, ".cache")
                .map(|d| d.join("trigon").join("evidence")),
        };
        config.state_dir = match &env.evidence_state {
            Some(p) => Some(absolute(p, &env.cwd)),
            None => env
                .xdg(&env.xdg_state_home, ".local/state")
                .map(|d| d.join("trigon").join("evidence")),
        };
        Ok(config)
    }

    pub fn publish(&self) -> &PublishConfig {
        &self.publish
    }

    pub fn freshness(&self) -> &Freshness {
        &self.freshness
    }

    /// Every configured source, in the order they were read: the user's file, the environment,
    /// then the project's file.
    pub fn sources(&self) -> &[Source] {
        &self.sources
    }

    pub fn source(&self, name: &str) -> Option<&Source> {
        self.sources.iter().find(|s| s.name == name)
    }

    /// Whether a source already has this name, or one that differs from it only in case. A name
    /// is the source's directory under the cache and the state directories, and on a
    /// case-insensitive filesystem — macOS's default — `Trigon` and `trigon` are one directory, so
    /// a project's `Trigon` would share the user's `trigon`'s checkpoint and key history.
    fn name_taken(&self, name: &str) -> bool {
        self.sources.iter().any(|s| same_name(&s.name, name))
    }

    /// Every source, or the refusal a command that needs one gives when there are none.
    ///
    /// Until `docs/19` D3 names our repository no default source ships, so a consumer configures
    /// at least one, and a command with nothing to ask says how rather than answering "never
    /// checked" for everything — which is the answer an empty configuration would otherwise give,
    /// and exactly the wrong one.
    pub fn require_sources(&self) -> Result<&[Source], ConfigError> {
        if self.sources.is_empty() {
            return Err(ConfigError::NoSource {
                config: self
                    .user_config
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "~/.config/trigon/evidence.toml".into()),
            });
        }
        Ok(&self.sources)
    }

    /// Where clones are kept: `TRIGON_EVIDENCE_CACHE`, or `$XDG_CACHE_HOME/trigon/evidence`.
    pub fn cache_dir(&self) -> Result<&Path, ConfigError> {
        self.cache_dir.as_deref().ok_or(ConfigError::NoDirectory {
            what: "cache",
            var: "TRIGON_EVIDENCE_CACHE",
        })
    }

    /// Where each source's last accepted checkpoint and key history are kept:
    /// `TRIGON_EVIDENCE_STATE`, or `$XDG_STATE_HOME/trigon/evidence`.
    pub fn state_dir(&self) -> Result<&Path, ConfigError> {
        self.state_dir.as_deref().ok_or(ConfigError::NoDirectory {
            what: "state",
            var: "TRIGON_EVIDENCE_STATE",
        })
    }

    /// The files that were read, in order.
    pub fn files_read(&self) -> &[PathBuf] {
        &self.read
    }

    fn user_file(&mut self, path: &Path, text: &str, env: &Env) -> Result<(), ConfigError> {
        let file_error = |message: String| ConfigError::File {
            path: path.to_path_buf(),
            message,
        };
        let doc: FileDoc = toml::from_str(text).map_err(|e| file_error(e.to_string()))?;
        let base = parent_of(path);
        let home = env.home.as_deref();

        if let Some(p) = doc.publish {
            let publish = &mut self.publish;
            if let Some(r) = p.repo {
                publish.repo = Some(
                    Location::parse(&r, &base, home)
                        .map_err(|e| file_error(format!("[publish] repo: {e}")))?,
                );
            }
            if let Some(b) = p.branch {
                publish.branch = branch(&b).map_err(|m| file_error(format!("[publish] {m}")))?;
            }
            if let Some(o) = p.origin {
                publish.origin =
                    Some(origin(&o).map_err(|m| file_error(format!("[publish] {m}")))?);
            }
            if let Some(d) = p.disputes {
                publish.disputes =
                    Some(disputes(&d).map_err(|m| file_error(format!("[publish] {m}")))?);
            }
            if let Some(k) = p.log_key {
                publish.log_key = Some(
                    expand_path(&k, &base, home)
                        .map_err(|m| file_error(format!("[publish] log_key: {m}")))?,
                );
            }
            if let Some(d) = p.divergences {
                publish.divergences = d;
            }
            if let Some(r) = p.rebuilt_artifacts {
                publish.rebuilt_artifacts = r;
            }
            if let Some(s) = p.same_host_confirmation {
                publish.same_host_confirmation = s;
            }
            if let Some(i) = p.confirmation_interval {
                publish.confirmation_interval =
                    duration("[publish] confirmation_interval", &i).map_err(file_error)?;
            }
            if let Some(h) = p.heartbeat {
                publish.heartbeat = duration("[publish] heartbeat", &h).map_err(file_error)?;
            }
        }
        if let Some(f) = doc.freshness {
            if let Some(s) = f.stale_after {
                self.freshness.stale_after =
                    duration("[freshness] stale_after", &s).map_err(file_error)?;
            }
            if let Some(s) = f.frozen_after {
                self.freshness.frozen_after =
                    duration("[freshness] frozen_after", &s).map_err(file_error)?;
            }
        }
        for s in doc.source {
            let source = self
                .source_from(s, &AddedBy::UserFile(path.to_path_buf()), &base, env)
                .map_err(file_error)?;
            self.sources.push(source);
        }
        Ok(())
    }

    fn project_file(&mut self, path: &Path, text: &str, env: &Env) -> Result<(), ConfigError> {
        let refuse = |rule: String| ConfigError::ProjectRule {
            path: path.to_path_buf(),
            rule,
        };
        // Not toml's own message, which quotes the offending line of the file: where the line is
        // and what is wrong with it, escaped, since the refusal is printed into a CI log.
        let doc: FileDoc = toml::from_str(text).map_err(|e| ConfigError::File {
            path: path.to_path_buf(),
            message: parse_error(text, &e),
        })?;
        if doc.publish.is_some() {
            return Err(refuse(
                "it sets [publish], which is the user's to set".into(),
            ));
        }
        if doc.freshness.is_some() {
            return Err(refuse(
                "it sets [freshness], and how old an answer may be is the user's to decide".into(),
            ));
        }
        let base = parent_of(path);
        let mut added = Vec::new();
        for s in doc.source {
            let name = s.name.clone();
            // Escaped for the message: the project's strings are input chosen by the thing under
            // test, and the refusal is printed into somebody's terminal or CI log.
            let shown = printable(&name);
            let rule = |what: &str| refuse(format!("[[source]] `{shown}` {what}"));
            if s.required.is_some() {
                return Err(rule(
                    "sets `required`, and which sources must answer is the user's to decide",
                ));
            }
            if s.trust_on_first_use.is_some() {
                return Err(rule(
                    "sets `trust_on_first_use`; a project's source pins both keys",
                ));
            }
            if s.log_key.is_none() || s.attestation_key.is_none() {
                return Err(rule("does not pin both `log_key` and `attestation_key`"));
            }
            let Some(checkpoint) = &s.checkpoint else {
                return Err(rule("pins no initial `checkpoint`"));
            };
            if self.name_taken(&name) || added.iter().any(|a: &Source| same_name(&a.name, &name)) {
                return Err(rule(
                    "uses a name that is already configured. A project may add a source, never \
                     add a URL to one, change one or replace one",
                ));
            }
            // By what is written, before anything is parsed: a project's location is an
            // `https://` URL, which `Location::parse` classifies as nothing else, and the refusal
            // of anything else is this rule rather than whatever parsing it would have said.
            for u in &s.urls {
                if !u
                    .get(..8)
                    .is_some_and(|p| p.eq_ignore_ascii_case("https://"))
                {
                    return Err(rule(&format!(
                        "names `{}`, and a project's URLs are HTTPS only",
                        printable(u)
                    )));
                }
            }
            // Files the project names must be the project's own. Checked after following
            // symlinks, which the project also controls.
            let inside = |what: &str, value: &str| -> Result<(), ConfigError> {
                inside_project(value, &base, &env.cwd).map_err(|why| {
                    rule(&format!("names {what} `{}`, which {why}", printable(value)))
                })
            };
            inside("the checkpoint", checkpoint)?;
            if let Some(k) = &s.attestation_key
                && !AttestationKey::looks_like_hex(k)
            {
                inside("the attestation key", k)?;
            }
            // Escaped once more here, whatever `source_from` already escaped: every message it
            // gives quotes something of the project's, and the next one added may forget.
            let source = self
                .source_from(s, &AddedBy::ProjectFile(path.to_path_buf()), &base, env)
                .map_err(|m| ConfigError::File {
                    path: path.to_path_buf(),
                    message: printable(&m),
                })?;
            added.push(source);
        }
        self.sources.extend(added);
        Ok(())
    }

    fn environment(&mut self, env: &Env) -> Result<(), ConfigError> {
        let home = env.home.as_deref();
        if let Some(r) = &env.publish_repo {
            self.publish.repo =
                Some(
                    Location::parse(r, &env.cwd, home).map_err(|e| ConfigError::Env {
                        var: "TRIGON_PUBLISH_REPO",
                        message: e.to_string(),
                    })?,
                );
        }

        let tofu = match env.evidence_tofu.as_deref() {
            None | Some("0") => false,
            Some("1") => true,
            Some(other) => {
                return Err(ConfigError::Env {
                    var: "TRIGON_EVIDENCE_TOFU",
                    message: format!("is `{other}`; it is `1` to trust on first use, or unset"),
                });
            }
        };
        let Some(repo) = &env.evidence_repo else {
            // A pin with nothing to pin is a mistake worth saying, not a setting to ignore: the
            // user believes a key is pinned.
            for (var, set) in [
                ("TRIGON_EVIDENCE_LOG_KEY", env.evidence_log_key.is_some()),
                (
                    "TRIGON_EVIDENCE_ATTESTATION_KEY",
                    env.evidence_attestation_key.is_some(),
                ),
                (
                    "TRIGON_EVIDENCE_CHECKPOINT",
                    env.evidence_checkpoint.is_some(),
                ),
                ("TRIGON_EVIDENCE_TOFU", env.evidence_tofu.is_some()),
            ] {
                if set {
                    return Err(ConfigError::Env {
                        var,
                        message: "is set and TRIGON_EVIDENCE_REPO is not, so it applies to \
                                  nothing. Set TRIGON_EVIDENCE_REPO to the source it belongs to, \
                                  or unset it"
                            .into(),
                    });
                }
            }
            return Ok(());
        };

        let var_error =
            |var: &'static str| move |message: String| ConfigError::Env { var, message };
        let mut urls = Vec::new();
        for u in repo.split_whitespace() {
            let l = Location::parse(u, &env.cwd, home)
                .map_err(|e| var_error("TRIGON_EVIDENCE_REPO")(format!("names {e}")))?;
            if !urls.contains(&l) {
                urls.push(l);
            }
        }
        let log_key =
            match &env.evidence_log_key {
                Some(k) => Some(LogVkey::parse(k).map_err(|e| {
                    var_error("TRIGON_EVIDENCE_LOG_KEY")(format!("is refused: {e}"))
                })?),
                None => None,
            };
        let attestation_key = match &env.evidence_attestation_key {
            Some(k) => Some(attestation_key(k, &env.cwd, home).map_err(|m| {
                var_error("TRIGON_EVIDENCE_ATTESTATION_KEY")(format!("is refused: {m}"))
            })?),
            None => None,
        };
        let checkpoint = match &env.evidence_checkpoint {
            Some(c) => Some(expand_path(c, &env.cwd, home).map_err(|m| {
                var_error("TRIGON_EVIDENCE_CHECKPOINT")(format!("is refused: {m}"))
            })?),
            None => None,
        };
        let unpinned = log_key.is_none() || attestation_key.is_none();
        if unpinned && !tofu {
            return Err(ConfigError::Env {
                var: "TRIGON_EVIDENCE_REPO",
                message: format!(
                    "names a source without {}. Set TRIGON_EVIDENCE_LOG_KEY and \
                     TRIGON_EVIDENCE_ATTESTATION_KEY to pin it, or TRIGON_EVIDENCE_TOFU=1 to read \
                     the keys from the repository's keys/ on the first sync, which every answer \
                     from it will then say it rests on",
                    missing_keys(log_key.is_none(), attestation_key.is_none())
                ),
            });
        }
        if urls.is_empty() {
            return Err(var_error("TRIGON_EVIDENCE_REPO")(
                "names no location: it is one or more, separated by spaces".into(),
            ));
        }
        self.sources.push(Source {
            name: ENV_SOURCE.into(),
            urls,
            log_key,
            attestation_key,
            checkpoint,
            required: true,
            trust_on_first_use: tofu && unpinned,
            added_by: AddedBy::Environment,
        });
        Ok(())
    }

    /// A `[[source]]` entry, checked. The error is the message only; the caller says which file.
    fn source_from(
        &self,
        s: SourceDoc,
        added_by: &AddedBy,
        base: &Path,
        env: &Env,
    ) -> Result<Source, String> {
        let home = env.home.as_deref();
        let name = s.name;
        let at = |m: String| format!("[[source]] `{name}`: {m}");
        source_name(&name).map_err(|m| format!("[[source]] {m}"))?;
        if same_name(&name, ENV_SOURCE) {
            return Err(format!(
                "[[source]] `{name}`: that name is TRIGON_EVIDENCE_REPO's, `{ENV_SOURCE}`, in any \
                 case; choose another"
            ));
        }
        if self.name_taken(&name) {
            return Err(at(
                "is configured twice. A source is one log; list its mirrors in one `urls`".into(),
            ));
        }
        if s.urls.is_empty() {
            return Err(at(
                "`urls` is empty; a source needs at least one location".into()
            ));
        }
        let mut urls = Vec::new();
        for u in &s.urls {
            let l = Location::parse(u, base, home).map_err(|e| at(format!("urls: {e}")))?;
            if urls.contains(&l) {
                return Err(at(format!("urls: `{u}` is listed twice")));
            }
            urls.push(l);
        }
        let log_key = match &s.log_key {
            Some(k) => Some(LogVkey::parse(k).map_err(|e| at(format!("log_key: {e}")))?),
            None => None,
        };
        let attestation_key = match &s.attestation_key {
            Some(k) => Some(
                attestation_key(k, base, home).map_err(|m| at(format!("attestation_key: {m}")))?,
            ),
            None => None,
        };
        let checkpoint = match &s.checkpoint {
            Some(c) => {
                Some(expand_path(c, base, home).map_err(|m| at(format!("checkpoint: {m}")))?)
            }
            None => None,
        };
        let tofu = s.trust_on_first_use.unwrap_or(false);
        let unpinned = log_key.is_none() || attestation_key.is_none();
        if unpinned && !tofu {
            return Err(at(format!(
                "does not pin {}. Pin both, or set `trust_on_first_use = true` to read them from \
                 the repository's keys/ on the first sync, which every answer from it will then \
                 say it rests on",
                missing_keys(log_key.is_none(), attestation_key.is_none())
            )));
        }
        Ok(Source {
            name,
            urls,
            log_key,
            attestation_key,
            checkpoint,
            required: s.required.unwrap_or(false),
            trust_on_first_use: tofu && unpinned,
            added_by: added_by.clone(),
        })
    }
}

/// `"30s"`, `"15m"`, `"1h"`, `"7d"`: a whole number and one unit.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let bad = || {
        format!(
            "`{s}` is not a duration: write a whole number and one unit, s, m, h or d, as in \
             `30m`, `1h` or `7d`"
        )
    };
    let unit = s.chars().last().ok_or_else(bad)?;
    let seconds: u64 = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86_400,
        _ => return Err(bad()),
    };
    let n = &s[..s.len() - 1];
    if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    let n: u64 = n.parse().map_err(|_| bad())?;
    n.checked_mul(seconds)
        .map(Duration::from_secs)
        .ok_or_else(|| format!("`{s}` is longer than this build can count"))
}

fn duration(key: &str, s: &str) -> Result<Duration, String> {
    parse_duration(s).map_err(|m| format!("{key}: {m}"))
}

fn missing_keys(log: bool, attestation: bool) -> &'static str {
    match (log, attestation) {
        (true, true) => "a log key or an attestation key",
        (true, false) => "a log key",
        _ => "an attestation key",
    }
}

/// A source's name: a directory under the cache and state directories, so path-safe.
fn source_name(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && name != "."
        && name != ".."
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    match ok {
        true => Ok(()),
        false => Err(format!(
            "name `{}` is not a source name: ASCII letters, digits, `.`, `_` and `-`, not \
             starting with `-`. It names the source's directory in the cache",
            printable(name)
        )),
    }
}

/// Whether two source names are one directory on a case-insensitive filesystem. Source names are
/// ASCII, so ASCII case is all there is to fold.
fn same_name(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// The origin line of a log: schema-less and permanent (`docs/19` §2.3).
fn origin(s: &str) -> Result<String, String> {
    let bad = |why: &str| {
        format!(
            "origin `{s}` {why}. An origin is schema-less, as in \
             `github.com/<owner>/trigon-evidence`"
        )
    };
    if s.is_empty() {
        return Err(bad("is empty"));
    }
    if s.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(bad("contains whitespace"));
    }
    if s.contains("://") {
        return Err(bad("has a scheme"));
    }
    // It is also the log key's name, and a C2SP key name cannot contain `+`.
    if s.contains('+') {
        return Err(bad("contains `+`, which a log key's name cannot"));
    }
    Ok(s.to_string())
}

/// The dispute channel: a URL a reader can open, so HTTPS.
fn disputes(s: &str) -> Result<String, String> {
    let host = s
        .strip_prefix("https://")
        .map(|r| r.split(['/', '?', '#']).next().unwrap_or_default());
    match host {
        Some(h) if !h.is_empty() && !s.chars().any(|c| c.is_whitespace() || c.is_control()) => {
            Ok(s.to_string())
        }
        _ => Err(format!(
            "disputes `{s}` is not an https:// URL. It is signed into every record as where a \
             dispute goes, as in `https://github.com/<owner>/trigon-evidence/issues`"
        )),
    }
}

fn branch(s: &str) -> Result<String, String> {
    if s.is_empty() || s.starts_with('-') || s.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(format!("branch `{s}` is not a branch name"));
    }
    Ok(s.to_string())
}

/// 64 hex digits, or a path to a PEM file, read now.
fn attestation_key(s: &str, base: &Path, home: Option<&Path>) -> Result<AttestationKey, String> {
    if AttestationKey::looks_like_hex(s) {
        return AttestationKey::from_hex(s).map_err(|e| e.to_string());
    }
    let path = expand_path(s, base, home)?;
    let shown = printable(&path.display().to_string());
    let pem = read_limited(&path, KEY_FILE_LIMIT).map_err(|e| {
        format!(
            "`{}` is neither 64 hex digits nor a PEM file that can be read: {shown}: {e}",
            printable(s)
        )
    })?;
    AttestationKey::from_pem(&pem).map_err(|e| format!("{shown}: {e}"))
}

/// A path from a configuration value: `~/` expanded, and a relative path taken from `base`.
fn expand_path(s: &str, base: &Path, home: Option<&Path>) -> Result<PathBuf, String> {
    if s.is_empty() {
        return Err("the path is empty".into());
    }
    let path = if s == "~" || s.starts_with("~/") {
        let home = home.ok_or("it starts with `~/`, and HOME is not set to expand it")?;
        home.join(s.trim_start_matches('~').trim_start_matches('/'))
    } else if s.starts_with('~') {
        return Err(format!(
            "`{}`: only `~/` is expanded, to your own home directory; write the path in full",
            printable(s)
        ));
    } else {
        base.join(s)
    };
    Ok(absolute(&path, base))
}

/// Whether a path a project names stays inside the project once symlinks are followed.
fn inside_project(value: &str, base: &Path, project: &Path) -> Result<(), String> {
    if value.starts_with('~') || Path::new(value).is_absolute() {
        return Err("is not a path inside the project".into());
    }
    let joined = base.join(value);
    let real = std::fs::canonicalize(&joined).map_err(|e| format!("cannot be read ({e})"))?;
    let root = std::fs::canonicalize(project)
        .map_err(|e| format!("cannot be checked against the project ({e})"))?;
    match real.starts_with(&root) {
        true => Ok(()),
        false => Err(format!(
            "resolves to {}, outside the project",
            printable(&real.display().to_string())
        )),
    }
}

/// The largest `.trigon/evidence.toml` read. A few sources are a few hundred bytes; the limit is
/// there so that a project cannot have the loader read without end.
pub const PROJECT_FILE_LIMIT: u64 = 64 * 1024;

/// The largest PEM attestation key read. One is under 200 bytes.
const KEY_FILE_LIMIT: u64 = 16 * 1024;

/// The project's own `.trigon/evidence.toml`, or `None` where there is none.
///
/// Held to the rule the files it names are held to, because the pull request that writes it
/// writes its symlinks too: a `.trigon/evidence.toml`, or a `.trigon`, that is a link to a file of
/// the host's — a secrets file, `/proc/self/environ` — would otherwise be read, fail to parse, and
/// have the parser quote it into the CI log. So it must resolve to inside the project, be a
/// regular file rather than a device or a pipe, and be small.
fn read_project_file(path: &Path, project: &Path) -> Result<Option<String>, ConfigError> {
    let refuse = |rule: String| ConfigError::ProjectRule {
        path: path.to_path_buf(),
        rule,
    };
    // Not following the last link, so a link that points at nothing is a file that is there and
    // is refused, rather than a file that is absent.
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(ConfigError::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    let real = std::fs::canonicalize(path).map_err(|e| {
        refuse(format!(
            "it cannot be resolved to a file in the project ({e})"
        ))
    })?;
    let root = std::fs::canonicalize(project).map_err(|source| ConfigError::Read {
        path: project.to_path_buf(),
        source,
    })?;
    if !real.starts_with(&root) {
        return Err(refuse(format!(
            "it resolves to {}, outside the project",
            printable(&real.display().to_string())
        )));
    }
    read_limited(&real, PROJECT_FILE_LIMIT)
        .map(Some)
        .map_err(|why| refuse(format!("it {why}")))
}

/// A regular file of at most `limit` bytes, as text. The error is the reason alone, phrased to
/// follow "it".
fn read_limited(path: &Path, limit: u64) -> Result<String, String> {
    use std::io::Read as _;
    let file = std::fs::File::open(path).map_err(|e| format!("cannot be read ({e})"))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot be read ({e})"))?;
    if !meta.is_file() {
        return Err("is not a regular file".into());
    }
    // Read through `take`, not only checked against the size the metadata gives: a file can grow
    // between the two, and a special file reports a size that is not what reading it yields.
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot be read ({e})"))?;
    if bytes.len() as u64 > limit {
        return Err(format!("is larger than {limit} bytes"));
    }
    String::from_utf8(bytes).map_err(|_| "is not UTF-8 text".into())
}

/// A TOML error as a refusal of a project's file quotes it: the line and column, and toml's
/// description escaped, without the line of the file toml's own message prints.
fn parse_error(text: &str, e: &toml::de::Error) -> String {
    let at = match e.span() {
        Some(span) => {
            let before = text.get(..span.start).unwrap_or(text);
            let line = before.matches('\n').count() + 1;
            let column = before
                .rsplit('\n')
                .next()
                .unwrap_or_default()
                .chars()
                .count()
                + 1;
            format!("TOML parse error at line {line}, column {column}: ")
        }
        None => "TOML parse error: ".into(),
    };
    format!("{at}{}", printable(e.message().trim_end()))
}

fn absolute(p: &Path, base: &Path) -> PathBuf {
    let joined = base.join(p);
    let mut out = PathBuf::new();
    for c in joined.components() {
        if c != std::path::Component::CurDir {
            out.push(c.as_os_str());
        }
    }
    out
}

fn parent_of(path: &Path) -> PathBuf {
    path.parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileDoc {
    publish: Option<PublishDoc>,
    freshness: Option<FreshnessDoc>,
    #[serde(default)]
    source: Vec<SourceDoc>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishDoc {
    repo: Option<String>,
    branch: Option<String>,
    origin: Option<String>,
    disputes: Option<String>,
    log_key: Option<String>,
    divergences: Option<Divergences>,
    rebuilt_artifacts: Option<RebuiltArtifacts>,
    same_host_confirmation: Option<bool>,
    confirmation_interval: Option<String>,
    heartbeat: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FreshnessDoc {
    stale_after: Option<String>,
    frozen_after: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceDoc {
    name: String,
    urls: Vec<String>,
    log_key: Option<String>,
    attestation_key: Option<String>,
    checkpoint: Option<String>,
    required: Option<bool>,
    trust_on_first_use: Option<bool>,
}
