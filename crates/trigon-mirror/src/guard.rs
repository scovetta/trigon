//! The artifact-hash check.
//!
//! The attack this exists for uses only capabilities the design grants. The repository, the README,
//! the CI config and a helpfully named `BUILD.md` are all attacker-controlled and all read while
//! inferring a strategy. Injected content says the build needs a prebuilt binary from
//! `cdn.evil.example`. The strategy that results is syntactically valid, passes schema validation,
//! builds, and matches the published artifact **byte for byte**, because it *is* the published
//! artifact. It then passes the clean re-run, deterministically, every time.
//!
//! **The clean re-run is not a defence here. It is the mechanism of the attack.** What defeats it is
//! noticing that the artifact arrived over the network rather than being built.
//!
//! So: hash every response body crossing into the sandbox, and decompose it when it is itself an
//! archive, because the interesting case is the target's compiled `.so` smuggled inside some
//! unrelated tarball rather than the whole artifact arriving under its own name.
//!
//! A match makes the run **`Void`**: not a pass and not a failure. The build may be perfectly
//! honest, and we cannot tell, which is exactly what `Void` says. See `docs/12-security.md` §2.

use std::collections::BTreeSet;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use trigon_compare::ContentKind;
use trigon_core::{Digest, EntryPath, Format};

/// Members below this are not guarded.
///
/// Every empty file in the world hashes the same, and so do stock licence texts, `__init__.py` and
/// `.gitkeep`. An unfiltered member set voids any build that downloads an archive containing one,
/// which is every build. See `docs/12-security.md` §2.2.
const MIN_GUARDED_BYTES: u64 = 4096;

/// Responses larger than this are hashed whole but not decomposed.
///
/// Decomposing is the expensive half and an attacker gains nothing by hiding a member inside a
/// gigabyte tarball that the build then has to unpack: the whole-body hash still catches the
/// artifact itself, and the size is recorded so the limit is visible rather than silent.
pub(crate) const MAX_DECOMPOSE_BYTES: usize = 64 * 1024 * 1024;

/// What a run refuses to let into its own sandbox.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardManifest {
    /// The published artifact this run is trying to reproduce.
    pub artifact: Option<Digest>,
    /// Its URL, refused outright for the duration of the run. The cheapest control there is: at
    /// `mirror-only` egress the mirror is the only reachable host, so a build that asks for its own
    /// published artifact gets nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refuse_url: Option<String>,
    /// Member digests worth guarding, after filtering.
    #[serde(default)]
    pub members: BTreeSet<Digest>,
    /// How many members the filters dropped, so the narrowing is visible.
    #[serde(default)]
    pub filtered_out: usize,
    /// The version the index must not offer, because it is the one under test.
    ///
    /// Paired with `refuse_url` rather than replacing it. The refusal is the control: the target's
    /// bytes never cross, whatever route is tried. This is what makes the refusal survivable — a
    /// resolver that is never offered the version picks another one, where a resolver that is
    /// offered it and then denied the file fails outright. See [`crate::npm::withhold_version`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withhold: Option<Withheld>,
}

/// One package version an index must not offer.
///
/// The project is carried beside the version because a mirror serves every index a build asks for,
/// and dropping `1.2.0` from whatever packument happened to arrive would quietly remove an
/// unrelated package's release.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Withheld {
    pub project: String,
    pub version: String,
}

impl GuardManifest {
    /// Build a manifest from the published artifact's bytes.
    ///
    /// Filtering narrows what triggers a `Void` and changes nothing about the comparison: a dropped
    /// member is still compared member-for-member when the verdict is decided.
    pub fn for_artifact(bytes: &[u8], format: Format, url: Option<String>) -> Self {
        Self::build(bytes, format, url, &BTreeSet::new())
    }

    /// As [`Self::for_artifact`], also dropping anything byte-identical to a file in the source.
    ///
    /// A file the artifact ships and the repository also contains is not evidence of anything: the
    /// build is entitled to fetch it, and something else in the ecosystem vendoring the same file
    /// is ordinary rather than suspicious. Guarding it produces a `Void` on an honest run, and a
    /// control that fires on honest runs is one people turn off.
    pub fn for_artifact_with_source(
        bytes: &[u8],
        format: Format,
        url: Option<String>,
        source_tree: &std::path::Path,
    ) -> Self {
        Self::build(bytes, format, url, &digest_tree(source_tree))
    }

    fn build(
        bytes: &[u8],
        format: Format,
        url: Option<String>,
        in_source: &BTreeSet<Digest>,
    ) -> Self {
        let artifact = Digest::from_bytes(Sha256::digest(bytes).into());
        let mut members = BTreeSet::new();
        let mut filtered_out = 0;

        let mut notes = Vec::new();
        if let Ok(parsed) = trigon_archive::parse(
            bytes.to_vec(),
            format,
            &trigon_archive::Limits::default(),
            &mut notes,
        ) {
            for e in &parsed.archive.entries {
                let Ok(body) = e.stabilized_bytes() else {
                    continue;
                };
                let digest = Digest::from_bytes(Sha256::digest(&body).into());
                // `guardable` exempts executables from every filter "unconditionally", and the
                // also-in-source check sat after it behind an `||`, so it dropped them anyway. An
                // executable that the repository also contains is exactly the case worth guarding:
                // a build fetching a prebuilt binary is the attack in `docs/12-security.md` §1.1,
                // and "the repo has a copy too" is what that attack looks like from here.
                let exempt = ContentKind::classify(&e.path) == ContentKind::Executable;
                if !guardable(&e.path, &body) || (!exempt && in_source.contains(&digest)) {
                    filtered_out += 1;
                    continue;
                }
                members.insert(digest);
            }
        }

        GuardManifest {
            artifact: Some(artifact),
            refuse_url: url,
            members,
            filtered_out,
            withhold: None,
        }
    }

    /// Whether this manifest guards nothing at all.
    ///
    /// **Counts `refuse_url`.** It did not, while `is_armed` did, so a manifest carrying only a
    /// refusal URL was simultaneously "empty" and "armed" depending on which question was asked —
    /// and the two are asked by different callers deciding whether the guard is doing anything.
    pub fn is_empty(&self) -> bool {
        self.artifact.is_none()
            && self.members.is_empty()
            && self.refuse_url.is_none()
            && self.withhold.is_none()
    }

    /// Also withhold this version from the index, so a resolver routes around it.
    pub fn withholding(mut self, project: &str, version: &str) -> Self {
        self.withhold = Some(Withheld {
            project: project.to_string(),
            version: version.to_string(),
        });
        self
    }
}

/// Whether a member is worth guarding.
///
/// Executables are guarded whatever their size: they are what an attacker wants to smuggle, and a
/// size threshold that let a small `.so` through would exempt the only case that matters.
fn guardable(path: &EntryPath, body: &[u8]) -> bool {
    if body.is_empty() {
        return false;
    }
    // Executables first, and unconditionally. They are what an attacker wants to smuggle, so
    // neither a size threshold nor a content rule gets to exempt one.
    if ContentKind::classify(path) == ContentKind::Executable {
        return true;
    }
    body.len() as u64 >= MIN_GUARDED_BYTES && !is_stock(path, body)
}

/// Whether a member is boilerplate that unrelated packages carry byte-identical copies of.
///
/// The size threshold does not cover this. An Apache-2.0 LICENSE is eleven kilobytes and a GPL is
/// thirty-five, so both sail past it, and they are byte-identical across thousands of packages: a
/// guard that included one would void any build that downloaded any other Apache-2.0 package. Which
/// is most builds.
///
/// Matched on the name *and* the content. Name alone would drop a file someone chose to call
/// `LICENSE` that holds something else; content alone would drop source that quotes a licence
/// header, which plenty of source does.
fn is_stock(path: &EntryPath, body: &[u8]) -> bool {
    let name = String::from_utf8_lossy(path.file_name()).to_ascii_uppercase();
    let stem = name.split('.').next().unwrap_or(&name).to_string();

    // Generated markers, whatever they contain: they exist to be present, not to hold anything.
    if matches!(
        name.as_str(),
        ".GITKEEP" | ".NPMIGNORE" | "PY.TYPED" | ".KEEP"
    ) {
        return true;
    }
    // Nothing but whitespace is the same file everywhere.
    if body.iter().all(|b| b.is_ascii_whitespace()) {
        return true;
    }

    let licence_name = matches!(
        stem.as_str(),
        "LICENSE" | "LICENCE" | "COPYING" | "COPYRIGHT" | "NOTICE" | "UNLICENSE" | "UNLICENCE"
    );
    if !licence_name {
        return false;
    }
    // A prefix is enough: licence texts differ in a copyright line near the top and are identical
    // for thousands of lines after it, and reading the whole of a large file to decide this is
    // waste on a path that runs per member.
    let head = &body[..body.len().min(8192)];
    let text = String::from_utf8_lossy(head);
    const MARKERS: &[&str] = &[
        "Apache License",
        "Permission is hereby granted, free of charge",
        "Redistribution and use in source and binary forms",
        "GNU GENERAL PUBLIC LICENSE",
        "GNU LESSER GENERAL PUBLIC LICENSE",
        "GNU AFFERO GENERAL PUBLIC LICENSE",
        "Mozilla Public License",
        "THE SOFTWARE IS PROVIDED",
        "This is free and unencumbered software released into the public domain",
        "PERMISSION IS HEREBY GRANTED",
    ];
    MARKERS.iter().any(|m| text.contains(m))
}

/// Every file in a source tree, by content digest.
///
/// Walked rather than asked of git, because what matters is what is on disk at the commit the
/// build checks out, and a `.gitignore`d file the build generates is not in the repository's index
/// but is in the tree the artifact was packed from.
fn digest_tree(root: &std::path::Path) -> BTreeSet<Digest> {
    let mut out = BTreeSet::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            // `.git` holds packed objects, not source: hashing it finds nothing and costs plenty.
            if p.file_name().is_some_and(|n| n == ".git") {
                continue;
            }
            match e.file_type() {
                Ok(t) if t.is_dir() => stack.push(p),
                Ok(t) if t.is_file() => {
                    if let Ok(bytes) = std::fs::read(&p) {
                        out.insert(Digest::from_bytes(Sha256::digest(&bytes).into()));
                    }
                }
                _ => {}
            }
        }
    }
    out
}

/// The records a marker prefixes, read out of a container log.
///
/// **A record is the marker, a space, and a JSON object.** Text after the marker that is not an
/// object is not a truncated record, it is a different kind of line — which is exactly what a
/// `tracing` message mentioning the marker in its prose turned out to be. That happened, and it
/// made every run carrying a trip report "we could not tell whether the artifact arrived": the
/// strictness below is deliberate and it fired on the right thing for the wrong reason.
///
/// Everything from `{` onwards is still strict. A line that begins an object and does not finish
/// one is a record that was written and cannot be read, and skipping it would make a truncated log
/// indistinguishable from a clean run — the difference this whole reader exists to keep.
fn records<T: serde::de::DeserializeOwned>(
    logs: &str,
    marker: &str,
    what: &str,
) -> Result<Vec<T>, String> {
    let mut out = Vec::new();
    for line in logs
        .lines()
        .filter_map(|l| l.split_once(marker).map(|(_, rest)| rest.trim()))
    {
        if !line.starts_with('{') {
            continue;
        }
        match serde_json::from_str::<T>(line) {
            Ok(v) => out.push(v),
            Err(e) => return Err(format!("unreadable {what} line `{line}`: {e}")),
        }
    }
    Ok(out)
}

/// Something the guard caught. Whether it *voids* the run is decided later — see [`voiding`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trip {
    pub url: String,
    pub matched: GuardMatch,
}

impl Trip {
    /// The marker line, JSON after the marker.
    ///
    /// It used to be the marker and the URL, which was enough while every trip meant the same
    /// thing. It no longer is: a member trip carries the digest that matched, and the void decision
    /// is made against the artifact the build produced rather than at the moment the bytes arrive.
    /// A line that drops the digest makes that decision unmakeable outside the island.
    pub fn line(&self) -> String {
        match serde_json::to_string(self) {
            Ok(json) => format!("{TRIP_MARKER} {json}"),
            // Never an empty line. A trip that could not be written must still be *present* and
            // unreadable, so the reader refuses it — "we could not tell whether the artifact
            // arrived" is the honest answer, and a blank record would have read as a clean run.
            Err(e) => format!("{TRIP_MARKER} {{\"unserializable\":\"{e}\"}}"),
        }
    }

    pub fn emit(&self) {
        println!("{}", self.line());
    }

    /// Read trips back out of a container log.
    ///
    /// An unreadable line is an error rather than a skip, for the reason every other reader here
    /// gives: "we could not tell" and "nothing tripped" are different answers and only one of them
    /// means the run is evidence of anything.
    pub fn parse_log(logs: &str) -> Result<Vec<Trip>, String> {
        records(logs, TRIP_MARKER, "trip")
    }

    /// One line a person can read, used wherever a trip is reported.
    pub fn describe(&self) -> String {
        match &self.matched {
            GuardMatch::WholeArtifact => {
                format!("the artifact under test arrived from {}", self.url)
            }
            GuardMatch::Member { digest } => format!(
                "a member of the artifact under test (sha256 {}) arrived from {}",
                &digest[..digest.len().min(16)],
                self.url
            ),
            GuardMatch::RefusedUrl => {
                format!("the build asked for its own artifact at {}", self.url)
            }
        }
    }

    /// The member digest this trip matched, where it matched one.
    pub fn member(&self) -> Option<&str> {
        match &self.matched {
            GuardMatch::Member { digest } => Some(digest),
            _ => None,
        }
    }
}

/// Which of the trips that arrived actually void the run.
///
/// **The decision moved here, and it moved on purpose.** It used to be made at the moment the bytes
/// crossed the mirror: any guarded digest arriving voided the run. That is right for the whole
/// artifact and wrong for a member, and wrong in the direction that matters — it fires on honest
/// builds. `packaging` needs `packaging` to build, so the resolver installs the neighbouring
/// version, and a file unchanged between the two is byte-identical to a member of the target. The
/// most important control in the system was voiding a run for a dependency doing nothing unusual,
/// and a control that fires on honest runs is one people turn off.
///
/// The harm was never a member *arriving*. It is a member arriving **and coming back out in the
/// rebuilt artifact**, which is the whole shape of the attack in `docs/12-security.md` §1.1: bytes
/// fetched rather than built, re-emitted as though they had been. So that is the question asked,
/// and it can only be asked once the build has produced something.
///
/// Three consequences, each an improvement rather than a cost:
///
/// - The decision is a pure function of two digest sets, so a third party can re-derive it from the
///   attestation instead of taking a network proxy's word for it.
/// - `rebuilt: None` — a build that produced no artifact — voids nothing. Nothing was smuggled out
///   of a build with no output, and the run is already `BuildFailed`.
/// - `WholeArtifact` is unconditional. There is no honest reason for the published artifact to
///   arrive whole, and the check costs nothing.
pub fn voiding(trips: &[Trip], rebuilt: Option<&BTreeSet<Digest>>) -> Vec<Trip> {
    trips
        .iter()
        .filter(|t| match &t.matched {
            GuardMatch::WholeArtifact => true,
            GuardMatch::RefusedUrl => false,
            GuardMatch::Member { digest } => {
                rebuilt.is_some_and(|out| out.iter().any(|d| d.to_hex() == *digest))
            }
        })
        .cloned()
        .collect()
}

/// [`member_digests`] for an artifact on disk, naming its format from the file name.
///
/// `None` where the file cannot be read or its name does not identify an archive format — both of
/// which mean we could not look inside, which voids no member trip. The alternative, guessing a
/// format, would compare one archive's members against another format's parse and answer a
/// security question with a coincidence.
///
/// One function rather than one per caller: the host mirror and the island mirror both decide a
/// void this way, and two implementations of "what is in the rebuilt artifact" are two things that
/// have to agree with nothing asserting that they do.
pub fn member_digests_at(path: &std::path::Path) -> Option<BTreeSet<Digest>> {
    let name = path.file_name()?.to_str()?;
    let format = Format::from_file_name(name)?;
    let bytes = std::fs::read(path).ok()?;
    Some(member_digests(&bytes, format))
}

/// Every member digest in an archive, unfiltered.
///
/// Deliberately not [`GuardManifest`]'s filtered set. The manifest decides which of the *published*
/// artifact's files are worth watching for; this answers "is this digest in what the build made",
/// where filtering could only hide an answer.
///
/// Computed over `stabilized_bytes`, the same form the manifest uses, so the two sets are
/// comparable at all. Bytes that will not parse as an archive give an empty set, which voids no
/// member trip — the same direction as `None`, and for the same reason: we could not look inside,
/// so we do not claim to have found something.
pub fn member_digests(bytes: &[u8], format: Format) -> BTreeSet<Digest> {
    let mut out = BTreeSet::new();
    let mut notes = Vec::new();
    let Ok(parsed) = trigon_archive::parse(
        bytes.to_vec(),
        format,
        &trigon_archive::Limits::default(),
        &mut notes,
    ) else {
        return out;
    };
    for e in &parsed.archive.entries {
        if let Ok(body) = e.stabilized_bytes() {
            out.insert(Digest::from_bytes(Sha256::digest(&body).into()));
        }
    }
    out
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "matched", rename_all = "snake_case")]
pub enum GuardMatch {
    /// The published artifact itself arrived over the network.
    WholeArtifact,
    /// A guarded member of it arrived, inside something else.
    Member { digest: String },
    /// The build asked the mirror for its own published artifact.
    RefusedUrl,
}

/// The manifest plus what it caught.
#[derive(Debug, Default)]
pub struct Guard {
    manifest: GuardManifest,
    trips: Mutex<Vec<Trip>>,
    /// URLs whose bodies were hashed whole but never decomposed, because they crossed
    /// [`MAX_DECOMPOSE_BYTES`].
    ///
    /// **Not a trip.** Voiding a run for downloading a large file would fire on honest builds, and
    /// a control that fires on honest runs is one people turn off. But the skip cannot be silent
    /// either: the member check is what catches the target's files arriving inside something else,
    /// the size that suppresses it is chosen by the thing under test, and without this a run whose
    /// every download was too large read exactly like a run that was opened and cleared.
    undecomposed: Mutex<Vec<String>>,
}

/// The line a trip writes.
///
/// Distinctive on purpose: the mirror usually runs in a container, and reading its log is how the
/// process that started it finds out. A verdict that depends on parsing prose would be fragile, so
/// this is a fixed prefix.
pub const TRIP_MARKER: &str = "GUARD-TRIPPED";

/// The prefix on every line of the network transcript.
///
/// Tier 1 of `docs/08-execution.md` §7, and the only observability tier v1 ships. The mirror
/// already computed all of this and threw it away: it hashes every body as it streams past, which
/// is how the guard works, and then kept the hash only when it matched. A transcript is those
/// discarded observations written down.
///
/// **Stdout, not `tracing`.** Trips go through `tracing::error!` and survive the default `warn`
/// filter; an `info!` line would not, and the mirror container is started with no `-v` and no
/// `RUST_LOG`. A record that appears only when somebody set an environment variable is the
/// "configuration that looks applied and isn't" bug wearing a different hat — and this one decides
/// whether a run is attestable. Rust's stdout is line-buffered and `println!` holds the lock for
/// the whole line, so lines stay whole across concurrent responses.
///
/// The escape is the container log, same as [`TRIP_MARKER`] and for the same reason: the mirror
/// sits inside the island and the host has no route to it. One JSON object per line behind a fixed
/// prefix, so a line the host cannot read is visibly a line it cannot read rather than a silently
/// shorter transcript. Only the mirror writes to this log, so a build cannot forge a line into it
/// the way it can into its own output.
pub const EXCHANGE_MARKER: &str = "NET-EXCHANGE";

/// One response body the mirror served into the build.
///
/// This is what answers "what did this build download?" — which `docs/08` §7 calls the question
/// people actually ask, and the reason Tier 1 carries most of the forensic value by itself.
///
/// Only bodies that were actually served appear. A refused request is not a download: it is a
/// counter on [`Observed`](crate::Observed), and a refusal the guard cared about is a trip.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exchange {
    /// Which route served it, because each is a different claim: an `index` response is the
    /// registry pin working, an `artifact` is a dependency, a `toolchain` is the one thing a build
    /// fetches that then *runs*, and a `passthrough` is something on an index host that no filter
    /// applied to. A vaguer label would be a wrong label on a record we sign.
    pub route: String,
    pub url: String,
    /// SHA-256 of the bytes as served, undecoded. The same digest the guard compared, so a reader
    /// can check the guard's verdict rather than take it.
    pub sha256: String,
    pub bytes: u64,
    /// How far the guard got with it. Without this, "opened and clean" and "never opened" read
    /// identically, and they are the difference between a check and the appearance of one.
    pub checked: Checked,
    /// Versions the time filter removed from this index document before serving it.
    ///
    /// `None` on anything that is not a filtered index, which is not the same as `Some(0)`: an
    /// index document that withheld nothing is evidence the pin applied and found nothing to
    /// remove, and a dependency tarball is not evidence about the pin at all.
    ///
    /// Here rather than only in a counter because a counter cannot leave the island. Under an
    /// enforced tier the mirror runs inside the build's network namespace and the host has no route
    /// to it, so [`Observed`](crate::Observed) — the control that caught the `PIP_TRUSTED_HOST`
    /// finding — read `null` on exactly the tier where it is the claim. It is a per-response fact
    /// anyway, which is why it belongs here rather than in a counter that has to be shipped out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withheld: Option<u64>,
}

/// The prefix on every line recording a request the mirror turned away.
///
/// A refusal serves no body, so it is not an [`Exchange`] and has no business in a list whose every
/// other row carries a digest and a byte count. It is still evidence: somebody asked and was
/// refused, which is a different thing to investigate than silence — most often a client that
/// dropped the credentials carrying the pinned moment, which is how a build comes to resolve
/// against today's index while every log line says it was pinned.
pub const REFUSAL_MARKER: &str = "NET-REFUSED";

/// The prefix on a line saying the build asked for its own published artifact and was **refused**.
///
/// Separate from [`TRIP_MARKER`], and the separation is the whole point. A trip means the artifact
/// *arrived*: the run is evidence of nothing, because a build that downloads its own published
/// output reproduces it perfectly. A refusal means it did **not** arrive — the control worked — and
/// recording a successful defence as a failed run is the wrong verdict.
///
/// It matters because some packages are part of the machinery that builds packages: `python -m
/// build` needs `packaging` and `pyproject-hooks`, so rebuilding either one makes the build ask for
/// it. On the M1 PyPI smoke corpus at `mirror-only` that voided three of seventeen targets and not
/// one was a real catch. Voiding there would mean `setuptools`, `wheel`, `tomli`, `flit-core` and
/// `hatchling` can never be verified at an enforced tier — the packages everything else depends on.
///
/// What still catches an actual attempt is the whole-body hash, which runs on every response by
/// every route: this refusal knows one URL, and a build fetching the same bytes from anywhere else
/// trips [`GuardMatch::WholeArtifact`] instead. The refusal is a convenience; the hash is the
/// control.
pub const REFUSED_ARTIFACT_MARKER: &str = "GUARD-REFUSED";

/// One request the mirror declined to serve.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    /// The path as asked for. Not an upstream URL: there is no upstream request to name, because
    /// this one never got that far.
    pub path: String,
    pub status: u16,
    /// What the mirror said. A reader can then tell "no filter" from "host not on the allowlist"
    /// from "upstream returned 500" — three refusals with three different fixes, which the single
    /// `rejected` counter collapsed into one number.
    pub reason: String,
}

impl Refusal {
    /// The exact line [`emit`](Self::emit) writes. Split out for the reason [`Exchange::line`] is.
    pub fn line(&self) -> String {
        match serde_json::to_string(self) {
            Ok(json) => format!("{REFUSAL_MARKER} {json}"),
            Err(e) => format!("{REFUSAL_MARKER} {{\"unserializable\":\"{e}\"}}"),
        }
    }

    pub fn emit(&self) {
        println!("{}", self.line());
    }

    /// Read refusals back out of a container log. Strict, for the reason [`Exchange::parse_log`] is.
    pub fn parse_log(logs: &str) -> Result<Vec<Refusal>, String> {
        records(logs, REFUSAL_MARKER, "refusal")
    }
}

/// How far the artifact guard got with one body.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Checked {
    /// Opened: every member was hashed and compared against the manifest.
    Opened,
    /// The whole-body digest was compared and nothing more — the body was past
    /// [`MAX_DECOMPOSE_BYTES`], was not an archive we parse, or the manifest carries no members.
    /// The artifact arriving under its own name is still caught; a file of it hidden inside
    /// something else is not.
    Hashed,
    /// The mirror composed this body itself — a filtered index — so there is nothing for the guard
    /// to catch. Transcribed anyway, because it is what the build resolved against.
    Generated,
    /// No guard manifest was loaded, so nothing was compared against anything.
    Unarmed,
    /// The response never finished — the client hung up, or the connection broke — so the guard
    /// could not run on it at all.
    ///
    /// The row is still written, and that is the point. `bytes` is what actually crossed and
    /// `sha256` is the digest of *that prefix*, not of the resource: a partial body recorded as a
    /// whole one is the single most misleading line a transcript could carry. But recording nothing
    /// is worse, because the transcript's claim is that it lists everything that crossed — and a
    /// build that aborts every download at ninety-nine per cent would otherwise pull gigabytes and
    /// leave an empty, `attestable: true` account behind it.
    Partial,
}

impl Exchange {
    /// One exchange, with anything credential-shaped taken out of the URL first.
    ///
    /// The URLs that reach here are the *upstream* ones — `https://registry.npmjs.org/…`, built
    /// from an allowlisted host and a path — so there is nothing to redact today. This exists
    /// because the mirror's own rewritten form carries the pinned moment as a password
    /// (`http://npm:2018-04-09T01:10:45Z@timewarp/…`), one refactor could route that form through
    /// here, and `docs/08-execution.md` §6 is explicit: the proxy sees plaintext and transcripts
    /// are shown to users. Redacting at the one place an `Exchange` is built is cheaper than
    /// finding out later which of its readers leaked it.
    pub fn new(route: &str, url: &str, sha256: String, bytes: u64, checked: Checked) -> Self {
        Exchange {
            route: route.to_string(),
            url: redact_userinfo(url),
            sha256,
            bytes,
            checked,
            withheld: None,
        }
    }

    /// Record how many versions the time filter removed from this index document before serving it.
    pub fn withholding(mut self, versions: u64) -> Self {
        self.withheld = Some(versions);
        self
    }

    /// The exact line [`emit`](Self::emit) writes.
    ///
    /// Split out from the writing so a test can round-trip through the real formatter rather than
    /// through a second copy of it that has to agree with this one.
    pub fn line(&self) -> String {
        match serde_json::to_string(self) {
            Ok(json) => format!("{EXCHANGE_MARKER} {json}"),
            // Four strings and an integer do not fail to serialize, but a transcript that quietly
            // loses a line is worse than one that says which line it lost.
            Err(e) => format!("{EXCHANGE_MARKER} {{\"unserializable\":\"{e}\"}}"),
        }
    }

    /// Write one transcript line. See [`EXCHANGE_MARKER`] for why this is `println!`.
    pub fn emit(&self) {
        println!("{}", self.line());
    }

    /// Read a transcript back out of a container log.
    ///
    /// A line carrying the marker but no readable object is an error rather than a skip. A short
    /// transcript and a corrupted one look identical to a caller, and only one of them leaves the
    /// run attestable.
    pub fn parse_log(logs: &str) -> Result<Vec<Exchange>, String> {
        records(logs, EXCHANGE_MARKER, "transcript")
    }

    /// Read a transcript back out of its **stored** form: one JSON object per line, no marker.
    ///
    /// The marker is the container log's escape mechanism and nothing else, so it is stripped
    /// before a transcript is stored. A separate reader rather than one that tolerates both: a
    /// reader that skips what it does not recognise would read a blob of the wrong format as an
    /// empty transcript, and an empty transcript is a *claim* here — that the build fetched
    /// nothing — rather than an absence.
    pub fn parse_jsonl(blob: &str) -> Result<Vec<Exchange>, String> {
        Self::read(blob.lines())
    }

    fn read<'a>(lines: impl Iterator<Item = &'a str>) -> Result<Vec<Exchange>, String> {
        let mut out = Vec::new();
        for line in lines {
            let line = line.trim();
            // A trailing newline is one empty line, and every writer produces one.
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<Exchange>(line) {
                Ok(e) => out.push(e),
                Err(e) => return Err(format!("unreadable transcript line `{line}`: {e}")),
            }
        }
        Ok(out)
    }
}

impl Guard {
    pub fn new(manifest: GuardManifest) -> Self {
        Guard {
            manifest,
            trips: Mutex::new(Vec::new()),
            undecomposed: Mutex::new(Vec::new()),
        }
    }

    pub fn is_armed(&self) -> bool {
        // One question, one answer: `is_empty` now counts `refuse_url` itself.
        !self.manifest.is_empty()
    }

    /// Whether the body has to be kept, not just hashed.
    ///
    /// Only member checking needs the bytes; the whole-artifact hash is computed as they stream
    /// past. With no guarded members, which is the common case for a small package where the size
    /// filter drops everything, buffering every dependency the build downloads is pure cost.
    pub fn wants_body(&self) -> bool {
        !self.manifest.members.is_empty()
    }

    /// Whether this URL is the run's own published artifact.
    pub fn refuses(&self, url: &str) -> bool {
        self.manifest
            .refuse_url
            .as_deref()
            .is_some_and(|r| same_artifact(r, url))
    }

    /// The version this run's index responses must not offer, if any.
    pub fn withheld(&self) -> Option<&Withheld> {
        self.manifest.withhold.as_ref()
    }

    pub fn record_refusal(&self, url: &str) {
        self.record(Trip {
            url: url.to_string(),
            matched: GuardMatch::RefusedUrl,
        });
    }

    /// Bodies that were hashed whole and never opened, because they were too large.
    ///
    /// A non-empty list means the guard answered a narrower question than it was asked. The run is
    /// not void — see the field's own note — but an operator reading a clean result is entitled to
    /// know the member check did not run on these.
    pub fn undecomposed(&self) -> Vec<String> {
        self.undecomposed
            .lock()
            .map(|u| u.clone())
            .unwrap_or_default()
    }

    /// As [`Self::observe`], for a body the stream stopped collecting because of its size.
    ///
    /// The whole-artifact hash still runs — that half never needed the bytes — and the member half
    /// is recorded as not having run rather than as having found nothing.
    pub fn observe_oversized(&self, url: &str, body_digest: Digest) -> Checked {
        if let Ok(mut u) = self.undecomposed.lock() {
            u.push(url.to_string());
        }
        self.observe(url, body_digest, None)
    }

    /// Check a response body that has finished streaming, and report how far the check got.
    ///
    /// The return value is what the transcript records, and it is returned from here rather than
    /// inferred by the caller because every reason the member check stops early lives in this
    /// function. A caller reconstructing it from a size limit would call a body `opened` that was
    /// never an archive, or that arrived while the manifest carried no members — which is the
    /// difference between a check that ran and one that only looks like it did.
    pub fn observe(&self, url: &str, body_digest: Digest, body: Option<&[u8]>) -> Checked {
        if !self.is_armed() {
            return Checked::Unarmed;
        }
        if self.manifest.artifact == Some(body_digest) {
            self.record(Trip {
                url: url.to_string(),
                matched: GuardMatch::WholeArtifact,
            });
            return Checked::Hashed;
        }
        // The interesting case: not the artifact under its own name, but one of its files arriving
        // inside something unrelated.
        let Some(body) = body else {
            return Checked::Hashed;
        };
        if self.manifest.members.is_empty() || body.len() > MAX_DECOMPOSE_BYTES {
            return Checked::Hashed;
        }
        let Some(format) = sniff(body) else {
            return Checked::Hashed;
        };
        let mut notes = Vec::new();
        let Ok(parsed) = trigon_archive::parse(
            body.to_vec(),
            format,
            &trigon_archive::Limits::default(),
            &mut notes,
        ) else {
            // It looked like an archive and would not open. The member check did not run, and
            // saying it did would be the exact lie this return value exists to prevent.
            return Checked::Hashed;
        };
        for e in &parsed.archive.entries {
            let Ok(bytes) = e.stabilized_bytes() else {
                continue;
            };
            let d = Digest::from_bytes(Sha256::digest(&bytes).into());
            if self.manifest.members.contains(&d) {
                self.record(Trip {
                    url: url.to_string(),
                    matched: GuardMatch::Member { digest: d.to_hex() },
                });
                return Checked::Opened;
            }
        }
        Checked::Opened
    }

    pub fn trips(&self) -> Vec<Trip> {
        self.trips.lock().map(|t| t.clone()).unwrap_or_default()
    }

    fn record(&self, trip: Trip) {
        // Two markers, because the host has to tell the two apart without reading prose and they
        // mean opposite things. `RefusedUrl` is the build *asking* and being turned away; the other
        // two are the artifact getting in.
        match trip.matched {
            GuardMatch::RefusedUrl => {
                println!("{REFUSED_ARTIFACT_MARKER} {}", trip.url);
                tracing::warn!(
                    url = %trip.url,
                    "the build asked the mirror for its own published artifact and was refused. \
                     Nothing arrived, so this is not a void: some packages are part of the \
                     machinery that builds packages, and rebuilding one makes the build ask for it."
                );
            }
            _ => {
                trip.emit();
                // **The marker is not in this message.** It used to be, and the reader added in
                // this change splits the container log on the marker — so the log line and the
                // record line both matched, the prose failed to parse as JSON, and the whole run
                // came back "we could not tell whether the artifact arrived". Caught by the
                // parser refusing an unreadable line rather than skipping it, which is the reason
                // it refuses.
                tracing::error!(
                    url = %trip.url,
                    matched = ?trip.matched,
                    "the artifact under test reached the build over the network. Whether that \
                     voids the run is decided against what the build produced."
                );
            }
        }
        if let Ok(mut t) = self.trips.lock() {
            t.push(trip);
        }
    }

    /// Trips where something actually arrived: the artifact, or a guarded member of it.
    ///
    /// **Not the same as voiding.** Whether a member arriving voids the run depends on whether it
    /// came back out in the rebuilt artifact, which is not known here — see [`voiding`], which
    /// takes these and the build's output and answers that.
    pub fn arrived(&self) -> Vec<Trip> {
        self.trips()
            .into_iter()
            .filter(|t| t.matched != GuardMatch::RefusedUrl)
            .collect()
    }

    /// Times the build asked for its own artifact and was turned away. Not a void; see
    /// [`REFUSED_ARTIFACT_MARKER`].
    pub fn refused(&self) -> Vec<Trip> {
        self.trips()
            .into_iter()
            .filter(|t| t.matched == GuardMatch::RefusedUrl)
            .collect()
    }
}

/// Replace `scheme://user:pass@host/…` with `scheme://host/…`.
///
/// Only the authority, and only up to the first `/` after `//`, so a `@` in a path or a query — npm
/// scopes are full of them — is left alone.
fn redact_userinfo(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("//") else {
        return url.to_string();
    };
    let (authority, tail) = match rest.find('/') {
        Some(i) => rest.split_at(i),
        None => (rest, ""),
    };
    match authority.rsplit_once('@') {
        Some((_, host)) => format!("{scheme}//{host}{tail}"),
        None => url.to_string(),
    }
}

/// Whether two URLs name the same artifact.
///
/// Compared on the tail of the path rather than on the whole string, because the mirror rewrites
/// artifact URLs through itself and the build never sees the upstream form it was given.
///
/// **The tail is the last segment, unless that segment identifies nothing.** It used to be the last
/// segment always, which works for npm and PyPI because their artifact URLs end in a filename. A
/// crates.io download URL is `.../crates/{name}/{version}/download` — the last segment is the
/// literal word `download` for every crate ever published. Under the old rule the first dependency
/// a crates.io build fetched would have matched the run's own `refuse_url`, been refused 403, and
/// recorded as a `RefusedUrl` trip: every crates.io run `Void`, every time, for a control firing on
/// traffic it was never meant to see.
///
/// So a segment that names no particular file falls back to the segment before it, which for that
/// shape is the version — and `{name}/{version}/download` compared two-deep is as specific as a
/// filename. A control this cheap to fool is not a control.
fn same_artifact(a: &str, b: &str) -> bool {
    let tail = |u: &str| {
        let path = u.split(['?', '#']).next().unwrap_or(u);
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let take = match segments.last() {
            Some(last) if NAMES_NOTHING.contains(&last.to_ascii_lowercase().as_str()) => 2,
            _ => 1,
        };
        let n = segments.len();
        segments[n.saturating_sub(take)..].join("/")
    };
    let (a, b) = (tail(a), tail(b));
    !a.is_empty() && a == b
}

/// Last path segments that identify a route rather than a file.
///
/// Deliberately tiny and hand-maintained. Every entry is a segment a registry appends to an
/// otherwise-identifying path, so matching on it alone would equate unrelated artifacts. Getting
/// this wrong in the other direction is harmless — a missed entry means the guard compares one
/// segment where it could have compared two — which is why it is a short list rather than a
/// heuristic about what "looks like a filename".
const NAMES_NOTHING: &[&str] = &["download", "file", "artifact"];

/// The container format a response body appears to be.
fn sniff(body: &[u8]) -> Option<Format> {
    match body {
        [0x1f, 0x8b, ..] => Some(Format::TarGz),
        [b'P', b'K', ..] => Some(Format::Zip),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tgz(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut b = ::tar::Builder::new(Vec::new());
        for (name, body) in members {
            let mut h = ::tar::Header::new_ustar();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, *name, *body).unwrap();
        }
        let tar = b.into_inner().unwrap();
        let mut out = Vec::new();
        {
            use std::io::Write as _;
            let mut e = flate2::write::GzEncoder::new(&mut out, flate2::Compression::default());
            e.write_all(&tar).unwrap();
            e.finish().unwrap();
        }
        out
    }

    fn trip(matched: GuardMatch) -> Trip {
        Trip {
            url: "https://files.example/x".into(),
            matched,
        }
    }

    #[test]
    fn a_member_that_did_not_come_back_out_does_not_void() {
        // The bug this closes, and it is the control firing on an honest build. `packaging` needs
        // `packaging` to build, so the resolver installs the neighbouring version and a file
        // unchanged between the two is byte-identical to a member of the target. Nothing was
        // smuggled: the bytes went into the build environment and the rebuilt artifact does not
        // contain them.
        let arrived = Digest::from_bytes([3; 32]);
        let t = trip(GuardMatch::Member {
            digest: arrived.to_hex(),
        });
        let output = BTreeSet::from([Digest::from_bytes([9; 32])]);
        assert!(voiding(std::slice::from_ref(&t), Some(&output)).is_empty());

        // And the attack is untouched: the same member, present in what the build emitted, is
        // bytes fetched rather than built and re-emitted as though they had been.
        let output = BTreeSet::from([arrived]);
        assert_eq!(voiding(&[t], Some(&output)).len(), 1);
    }

    #[test]
    fn the_whole_artifact_voids_whatever_the_build_produced() {
        // Unconditional on purpose. There is no honest reason for the published artifact to arrive
        // whole, so this half asks nothing about the output — including when there is none.
        let t = trip(GuardMatch::WholeArtifact);
        assert_eq!(voiding(std::slice::from_ref(&t), None).len(), 1);
        assert_eq!(voiding(&[t], Some(&BTreeSet::new())).len(), 1);
    }

    #[test]
    fn a_build_that_produced_nothing_voids_no_member() {
        // Nothing was smuggled out of a build with no output, and the run is already
        // `BuildFailed`. Voiding it as well would report a security event for a compile error.
        let t = trip(GuardMatch::Member {
            digest: Digest::from_bytes([3; 32]).to_hex(),
        });
        assert!(voiding(&[t], None).is_empty());
    }

    #[test]
    fn a_refusal_never_voids() {
        assert!(voiding(&[trip(GuardMatch::RefusedUrl)], None).is_empty());
        let out = BTreeSet::from([Digest::from_bytes([3; 32])]);
        assert!(voiding(&[trip(GuardMatch::RefusedUrl)], Some(&out)).is_empty());
    }

    #[test]
    fn member_digests_sees_what_the_manifest_guards() {
        // The two sides of the void decision have to be computed the same way or they can never
        // match. The manifest filters — small files, stock text — and this does not, but for a
        // member both agree on, the digests are equal.
        let big = vec![b'z'; 8192];
        let bytes = tgz(&[("pkg/lib.js", &big)]);
        let m = GuardManifest::for_artifact(&bytes, Format::TarGz, None);
        let all = member_digests(&bytes, Format::TarGz);
        assert_eq!(m.members.len(), 1);
        assert!(
            m.members.iter().all(|d| all.contains(d)),
            "every guarded member is findable in the same archive's unfiltered set"
        );
    }

    #[test]
    fn member_digests_of_unopenable_bytes_is_empty() {
        // Which voids no member trip: we could not look inside, so we do not claim to have found
        // something. Same direction as no artifact at all.
        assert!(member_digests(b"not an archive", Format::TarGz).is_empty());
    }

    #[test]
    fn a_trip_survives_the_container_log() {
        // The line is the only way a trip leaves the island, and the void decision is now made
        // outside it — so a line that drops the digest makes that decision unmakeable. Round-trip
        // rather than eyeballing the format.
        let t = trip(GuardMatch::Member {
            digest: Digest::from_bytes([5; 32]).to_hex(),
        });
        let logs = format!("noise\n{}\nmore noise\n", t.line());
        assert_eq!(Trip::parse_log(&logs).unwrap(), vec![t]);
    }

    #[test]
    fn an_unreadable_trip_line_is_an_error_not_a_skip() {
        // "We could not tell" and "nothing tripped" are different answers, and only one of them
        // means the run is evidence of anything.
        let logs = format!("{TRIP_MARKER} {{not json\n");
        assert!(Trip::parse_log(&logs).is_err());
    }

    #[test]
    fn prose_that_mentions_the_marker_is_not_a_record() {
        // This happened. The `tracing` line beside the record carried the marker in its message,
        // so the reader saw two lines per trip: the record, and a sentence. The sentence would not
        // parse, and every run carrying a trip came back "we could not tell whether the artifact
        // under test reached the build" — which is the strictest possible answer, produced by a
        // log line rather than by anything about the run.
        //
        // A record is the marker, a space and a JSON object. Prose is a different kind of line,
        // not a damaged record, and the rest of the container's log is full of it.
        let t = trip(GuardMatch::WholeArtifact);
        let logs = format!(
            "2026-09-14T21:00:00Z ERROR {TRIP_MARKER}: the artifact under test reached the build \
             url=https://x matched=WholeArtifact\n{}\n",
            t.line()
        );
        assert_eq!(
            Trip::parse_log(&logs).unwrap(),
            vec![t],
            "the record is read and the sentence about it is not mistaken for one"
        );
    }

    #[test]
    fn the_whole_artifact_arriving_trips_the_guard() {
        let artifact = tgz(&[("pkg/index.js", &vec![b'x'; 8192])]);
        let g = Guard::new(GuardManifest::for_artifact(&artifact, Format::TarGz, None));
        g.observe(
            "http://cdn.evil.example/prebuilt.tgz",
            Digest::from_bytes(Sha256::digest(&artifact).into()),
            Some(&artifact),
        );
        assert_eq!(g.trips().len(), 1);
        assert_eq!(g.trips()[0].matched, GuardMatch::WholeArtifact);
    }

    #[test]
    fn a_guarded_member_inside_something_else_trips_it() {
        // The case worth catching. Hashing only the whole body would miss exactly this: the
        // target's compiled output smuggled inside an unrelated download.
        let secret = vec![b'S'; 9000];
        let artifact = tgz(&[("pkg/native.so", &secret)]);
        let g = Guard::new(GuardManifest::for_artifact(&artifact, Format::TarGz, None));

        let carrier = tgz(&[("vendor/thing.so", &secret), ("readme", b"hello")]);
        g.observe(
            "http://cdn.evil.example/toolkit.tgz",
            Digest::from_bytes(Sha256::digest(&carrier).into()),
            Some(&carrier),
        );
        assert!(matches!(
            g.trips().first().map(|t| &t.matched),
            Some(GuardMatch::Member { .. })
        ));
    }

    #[test]
    fn an_unrelated_download_does_not_trip_it() {
        let artifact = tgz(&[("pkg/index.js", &vec![b'x'; 8192])]);
        let g = Guard::new(GuardManifest::for_artifact(&artifact, Format::TarGz, None));
        let other = tgz(&[("lib/other.js", &vec![b'y'; 9000])]);
        g.observe(
            "https://registry.npmjs.org/other/-/other-1.0.0.tgz",
            Digest::from_bytes(Sha256::digest(&other).into()),
            Some(&other),
        );
        assert!(g.trips().is_empty());
    }

    #[test]
    fn small_members_are_filtered_out() {
        // Every empty file in the world hashes the same, and so does stock licence text. An
        // unfiltered member set voids any build that downloads an archive containing one, which is
        // every build.
        let artifact = tgz(&[
            ("pkg/__init__.py", b""),
            ("pkg/LICENSE", b"MIT\n"),
            ("pkg/index.js", &vec![b'x'; 8192]),
        ]);
        let m = GuardManifest::for_artifact(&artifact, Format::TarGz, None);
        assert_eq!(m.members.len(), 1, "only the large member is guarded");
        assert_eq!(m.filtered_out, 2);

        // And a build that downloads a package containing an empty file is not voided.
        let g = Guard::new(m);
        let innocent = tgz(&[("other/__init__.py", b""), ("other/LICENSE", b"MIT\n")]);
        g.observe(
            "https://registry.npmjs.org/other/-/other-1.0.0.tgz",
            Digest::from_bytes(Sha256::digest(&innocent).into()),
            Some(&innocent),
        );
        assert!(g.trips().is_empty());
    }

    const APACHE: &str = "\n                                 Apache License\n                           Version 2.0, January 2004\n                        http://www.apache.org/licenses/\n\n   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION\n";

    #[test]
    fn stock_licence_text_is_not_guarded() {
        // The size threshold does not cover this. An Apache-2.0 LICENSE is eleven kilobytes and a
        // GPL is thirty-five, so both sail past it, and they are byte-identical across thousands of
        // packages. Guarding one voids any build that downloads any other Apache-2.0 package.
        let licence = format!("{APACHE}{}", "x".repeat(9000));
        let artifact = tgz(&[
            ("pkg/LICENSE", licence.as_bytes()),
            ("pkg/index.js", &vec![b'x'; 8192]),
        ]);
        let m = GuardManifest::for_artifact(&artifact, Format::TarGz, None);
        assert_eq!(m.members.len(), 1, "only the real member is guarded");
        assert_eq!(m.filtered_out, 1);

        // And a build downloading an unrelated package with the same licence is not voided.
        let g = Guard::new(m);
        let other = tgz(&[("other/LICENSE", licence.as_bytes())]);
        g.observe(
            "https://registry.npmjs.org/other/-/other-1.0.0.tgz",
            Digest::from_bytes(Sha256::digest(&other).into()),
            Some(&other),
        );
        assert!(g.trips().is_empty());
    }

    #[test]
    fn a_file_merely_called_licence_is_still_guarded() {
        // Name alone would drop whatever someone chose to put in a file called LICENSE, which is
        // exactly where an attacker would put something once the rule was known.
        let payload = vec![b'Z'; 9000];
        let artifact = tgz(&[("pkg/LICENSE", &payload)]);
        let m = GuardManifest::for_artifact(&artifact, Format::TarGz, None);
        assert_eq!(
            m.members.len(),
            1,
            "no licence marker in it, so it is not stock"
        );
    }

    #[test]
    fn source_that_quotes_a_licence_header_is_still_guarded() {
        // Content alone would drop source that carries a licence header, and plenty of source does.
        let mut src = APACHE.as_bytes().to_vec();
        src.extend(vec![b'c'; 9000]);
        let artifact = tgz(&[("pkg/vendored.js", &src)]);
        let m = GuardManifest::for_artifact(&artifact, Format::TarGz, None);
        assert_eq!(m.members.len(), 1, "the name is not a licence name");
    }

    #[test]
    fn an_executable_is_never_dropped_by_the_stock_rule() {
        // Ordering matters: a guard that exempted `LICENSE.so` because of its name would exempt
        // the one case worth catching.
        let mut body = APACHE.as_bytes().to_vec();
        body.extend(vec![0u8; 9000]);
        let artifact = tgz(&[("pkg/LICENSE.so", &body)]);
        let m = GuardManifest::for_artifact(&artifact, Format::TarGz, None);
        assert_eq!(
            m.members.len(),
            1,
            "an executable is guarded whatever it is called"
        );
    }

    #[test]
    fn a_member_that_is_also_in_the_source_tree_is_not_guarded() {
        // A file the artifact ships and the repository also contains is not evidence of anything:
        // the build is entitled to fetch it, and something else vendoring the same file is
        // ordinary rather than suspicious.
        let vendored = vec![b'V'; 9000];
        let own = vec![b'O'; 9000];
        let artifact = tgz(&[("pkg/vendored.js", &vendored), ("pkg/own.js", &own)]);

        let dir = std::env::temp_dir().join(format!("trigon-guard-src-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("lib")).unwrap();
        std::fs::write(dir.join("lib/vendored.js"), &vendored).unwrap();
        // Present in the repository under a different path, which is the normal case: the filter
        // is on content, not on where the file sits.
        let m = GuardManifest::for_artifact_with_source(&artifact, Format::TarGz, None, &dir);
        assert_eq!(
            m.members.len(),
            1,
            "the vendored file is dropped, the package's own is kept"
        );
        assert_eq!(m.filtered_out, 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_source_tree_guards_everything() {
        // Failing open here would be the wrong direction: a filter that cannot read the source
        // should narrow nothing rather than silently drop the whole member set.
        let artifact = tgz(&[("pkg/index.js", &vec![b'x'; 8192])]);
        let m = GuardManifest::for_artifact_with_source(
            &artifact,
            Format::TarGz,
            None,
            std::path::Path::new("/nonexistent-source-tree"),
        );
        assert_eq!(m.members.len(), 1);
    }

    #[test]
    fn generated_markers_are_not_guarded() {
        let artifact = tgz(&[
            ("pkg/.gitkeep", &vec![b' '; 9000]),
            ("pkg/py.typed", &vec![b'\n'; 9000]),
        ]);
        let m = GuardManifest::for_artifact(&artifact, Format::TarGz, None);
        assert!(m.members.is_empty());
        assert_eq!(m.filtered_out, 2);
    }

    #[test]
    fn an_executable_is_guarded_whatever_its_size() {
        // A size threshold that let a small `.so` through would exempt the only case that matters.
        let artifact = tgz(&[("pkg/tiny.so", b"\x7fELF-ish")]);
        let m = GuardManifest::for_artifact(&artifact, Format::TarGz, None);
        assert_eq!(
            m.members.len(),
            1,
            "the executable is guarded despite being 8 bytes"
        );
    }

    #[test]
    fn the_runs_own_artifact_url_is_refused() {
        let m = GuardManifest {
            refuse_url: Some("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz".into()),
            ..Default::default()
        };
        let g = Guard::new(m);
        // Compared on the filename, because the mirror rewrites artifact URLs through itself and
        // the build never sees the upstream form.
        assert!(g.refuses(
            "http://timewarp:8129/-artifact/npm/x/registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
        ));
        assert!(!g.refuses(
            "http://timewarp:8129/-artifact/npm/x/registry.npmjs.org/left-pad/-/left-pad-1.2.0.tgz"
        ));
    }

    #[test]
    fn a_manifest_round_trips_as_json() {
        // It travels to the mirror as a file, because the mirror usually runs in a container.
        let artifact = tgz(&[("pkg/index.js", &vec![b'x'; 8192])]);
        let m =
            GuardManifest::for_artifact(&artifact, Format::TarGz, Some("https://x/y.tgz".into()));
        let text = serde_json::to_string(&m).unwrap();
        assert_eq!(serde_json::from_str::<GuardManifest>(&text).unwrap(), m);
    }
}
