//! `trigon runs export` and `trigon runs import`: runs moved from one store to another, so two
//! machines can confirm each other without sharing a store (`docs/19` D8).
//!
//! `rebuild --confirm`, `attest` and `publish` each read one local store, and a confirmation made
//! on a second machine counts only where the first attempt is. So machine A exports the run it
//! made, B imports it and confirms it, B exports the confirmation, and A imports it and publishes.
//!
//! **What an export holds** is each run's record and every file the record names that `attest`,
//! `publish` and `rebuild --confirm` read, or that a published record carries: the published and
//! rebuilt artifacts where the record says they are kept, the comparison, the strategy, the build
//! log, the model exchange, the network transcript, the guard manifest and the rendered
//! instructions; each statement the record names, at the path it names it by, and every blob a
//! statement signs as evidence, the stabilizer set's manifest file among them; and the set's
//! manifest the store publishes under `stabilizers/`. The guard manifest and the instructions go
//! where the store holds them, since runs recorded before they were kept name digests of bytes
//! nobody has, and so does the set's manifest, which `attest` publishes; anything else missing
//! refuses the export. What a run does not name is left out: the reading aids under `derived/` and
//! `decompiled/`, which are keyed by the digest of something else, so an import could not hold them
//! to their names, and which `trigon rederive` and `serve` make again from the artifacts; the
//! store's `publish/`; and withdrawals, which are about records and not runs.
//!
//! **The container is a tar, written by `trigon-archive` and never compressed.** `trigon-runs.json`
//! comes first, naming the schema and the runs; then every other file, in path order: a record as
//! `runs/<id>.json`, a set's manifest as `stabilizers/sha256/<hex>.json` and a statement at the
//! path its record names, as the store names them, and a blob as `blobs/sha256/<hex>`, without the
//! directory of its first two hex digits that the store files it under. Each is a regular file of
//! mode 0644 modified at the epoch ([`trigon_archive::Entry::tar_file`]), so the same runs give the
//! same bytes. Chosen over one canonical JSON document carrying the blobs, which the repository
//! also reads and writes safely, because an artifact is binary and may run to hundreds of
//! megabytes: in JSON it would be base64, a third larger and held three times over while it is
//! read, and a run record, which carries floats, is not canonical JSON at all. The tar reader is
//! the one the repository points at hostile artifacts, under the same [`Limits`], and the writer is
//! the byte-exact one stabilization rests on. `tar tvf` lists an export.
//!
//! **An import is untrusted input, and nothing is written until all of it is checked.** The file is
//! a regular file within the ceiling an artifact may expand to (`Limits::total_expanded_bytes`),
//! with no more entries than one may hold; it is never decompressed, so it cannot expand, and a
//! compressed one is refused. Every entry is a regular file — no link, directory or device, no PAX
//! record beyond a long name, nothing the reader had to note, nothing after the end of the archive
//! — at a path an export writes, matched whole, so no `..` and no leading `/`. Every blob hashes to
//! its name, and every JSON document is at most a published record's length and parses. Every
//! record's id is its file's and one the store addresses; every file it names is carried; and each
//! statement is filed under its own run or its published artifact. And every entry is named by a
//! run in the file, so an import writes nothing no record names. Against the store, a run already
//! there as the file has it is left alone, one there that differs is refused, and so is a statement
//! at a path that holds another. Only then are the blobs written, then the sets' manifests, then
//! the statements, and each record last, under the lock a prune takes turns on
//! ([`Store::keeping`]): a failed import leaves blobs no record names, never a record naming blobs
//! that are not there. A statement and a record are each written as a create, never over another
//! ([`Store::put_statement`], [`Store::create_run`]), since the lock is shared between writers: a
//! record another writer files under the same id after the store was looked at is refused and left
//! as it is, never replaced.
//!
//! **An import checks the file, not what it claims.** A record says which machine made the run,
//! when it began, what it could reuse and how its base image was pinned, and the import writes it
//! as it came, with nothing about the importing machine. The publication gate's same-host rule
//! compares the host ids the records carry, so importing a run trusts whoever made the export as
//! far as sharing a store with them would (the threat model's D40). So does confirming one:
//! `rebuild --confirm` of an imported run repeats the strategy the file carries, the source it
//! fetches and the commands it runs, on the base image and at the egress tier the record names,
//! and the confirming machine's operator cannot override either, so the file's maker chooses what
//! the second machine pulls and runs.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context as _, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use trigon_archive::{Archive, Entry, EntryKind, Limits, RawMeta, SourceMap, Trailer};
use trigon_attest::location::printable;
use trigon_core::{Digest, EntryPath, Format};
use trigon_stabilize::SetManifest;
use trigon_store::{RunRecord, Store, StoreError};

/// The first file of every export.
const MANIFEST: &str = "trigon-runs.json";

/// The value of the manifest's `schema`.
const SCHEMA: &str = "trigon.runs/v1";

/// The longest JSON document an import reads: the manifest, a record, a statement, a set's
/// manifest. A published record, which holds a verdict's three statements, is no longer.
const DOCUMENT_LIMIT: u64 = trigon_attest::evidence::RECORD_LIMIT;

/// `trigon-runs.json`: what the file is, and the runs it holds.
#[derive(Serialize, Deserialize)]
struct Manifest {
    schema: String,
    /// By id, in the order their records are written.
    runs: Vec<String>,
}

/// `trigon runs export <run>... --store <dir> --out <file>`.
pub(crate) fn export(store: &Path, runs: &[String], out: &Path) -> Result<()> {
    // Sorted and each once, so the same runs make the same file however they were named.
    let ids: BTreeSet<&str> = runs.iter().map(String::as_str).collect();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (records, files) = rt.block_on(async {
        let store = Store::existing(store)?;
        let mut records = Vec::new();
        let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for id in &ids {
            let r = store.get_run(id).await?;
            gather(&store, &r, &mut files).await?;
            files.insert(run_path(id), serde_json::to_vec_pretty(&r)?);
            records.push(r);
        }
        anyhow::Ok((records, files))
    })?;

    let manifest = Manifest {
        schema: SCHEMA.into(),
        runs: ids.iter().map(|id| id.to_string()).collect(),
    };
    let manifest = trigon_core::jcs::canonicalize(&serde_json::to_value(&manifest)?)?;
    let count = files.len() + 1;
    let mut archive = Archive::new(Format::Tar, Trailer::Tar);
    archive.entries.push(Entry::tar_file(
        EntryPath::from(MANIFEST),
        0,
        manifest.into_bytes(),
    ));
    for (n, (path, bytes)) in files.into_iter().enumerate() {
        let path = EntryPath::from(path.as_str());
        archive
            .entries
            .push(Entry::tar_file(path, n as u32 + 1, bytes));
    }
    let mut bytes = Vec::new();
    trigon_archive::tar::write(&archive, &mut bytes)?;
    drop(archive);

    // Held to what an import holds it to before it is written, so a store this cannot export
    // whole is refused here, and not on the machine the file was carried to.
    let src = Arc::new(SourceMap::owned(bytes));
    check(src.clone(), &Limits::default()).context(
        "`trigon runs import` would refuse the export of these runs, so it was not written",
    )?;
    std::fs::write(out, src.as_slice()).with_context(|| format!("writing {}", out.display()))?;

    for r in &records {
        println!("{}", line(r, "exported"));
    }
    println!(
        "\nwrote {}: {} run(s), {count} file(s), {} bytes",
        out.display(),
        records.len(),
        src.as_slice().len()
    );
    Ok(())
}

/// `trigon runs import <file> --store <dir>`.
pub(crate) fn import(file: &Path, store: &Path) -> Result<()> {
    import_within(file, store, &Limits::default())
}

/// [`import`], under `limits`: the file is at most `total_expanded_bytes` long, and holds at most
/// `max_entries` files.
fn import_within(file: &Path, store: &Path, limits: &Limits) -> Result<()> {
    let refused = || {
        format!(
            "refusing to import {}, and nothing was written",
            file.display()
        )
    };
    let bytes = read_bounded(file, limits.total_expanded_bytes).with_context(refused)?;
    let checked = check(Arc::new(SourceMap::owned(bytes)), limits).with_context(refused)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let store = Store::local(store)?;
        let Against { new, here, refused } = against(&store, &checked).await?;
        if !refused.is_empty() {
            bail!(
                "refusing to import {}, and nothing was written:\n  - {}",
                file.display(),
                refused.join("\n  - ")
            );
        }
        write(&store, &checked, &new).await?;
        for r in &checked.runs {
            match here.iter().any(|h| h.id == r.id) {
                true => println!("{}", line(r, "already in this store, as the file has it")),
                false => println!("{}", line(r, "imported")),
            }
        }
        println!(
            "\nimported {} of {} run(s). Each record says which machine made its run and when, as \
             whoever made {} recorded it.",
            new.len(),
            checked.runs.len(),
            file.display()
        );
        Ok(())
    })
}

/// One line about a run, as `trigon runs` lists it, and what was done with it.
fn line(r: &RunRecord, done: &str) -> String {
    let outcome = r.outcome.as_deref().unwrap_or(match r.guard_trips.len() {
        0 => "-",
        _ => "void",
    });
    format!("{}  {:<34} {:<24} {done}", r.id, r.target, outcome)
}

fn run_path(id: &str) -> String {
    format!("runs/{id}.json")
}

fn blob_path(d: &Digest) -> String {
    format!("blobs/sha256/{}", d.to_hex())
}

fn set_path(hex: &str) -> String {
    format!("stabilizers/sha256/{hex}.json")
}

/// A blob a record names: what it is, its digest, and whether the run is whole without it.
struct Named {
    what: &'static str,
    digest: Digest,
    /// `false` for the guard manifest and the rendered instructions, which runs recorded before
    /// either was kept name and do not hold.
    needed: bool,
}

/// Every blob `r` names.
fn named(r: &RunRecord) -> Vec<Named> {
    let mut out = Vec::new();
    let mut add = |what, digest, needed| {
        out.push(Named {
            what,
            digest,
            needed,
        })
    };
    if r.upstream.stored {
        add("published artifact", r.upstream.sha256, true);
    }
    if let Some(a) = r.rebuild.as_ref().filter(|a| a.stored) {
        add("rebuilt artifact", a.sha256, true);
    }
    for (what, d) in [
        ("comparison", r.comparison),
        ("strategy", r.strategy),
        ("build log", r.build_log),
        ("model exchange", r.transcript),
        ("network transcript", r.network_transcript),
    ] {
        if let Some(d) = d {
            add(what, d, true);
        }
    }
    if let Some(d) = r.instructions {
        add("rendered instructions", d, false);
    }
    // A digest that does not parse names no bytes, which is how `attest` reads it.
    let guard = r.environment.guard_manifest.as_deref();
    if let Some(d) = guard.and_then(|h| Digest::from_hex(h).ok()) {
        add("guard manifest", d, false);
    }
    out
}

/// The statements `r` names: the ones it is served by, and the ones set aside when it was attested
/// again under its own id.
fn statements_of(r: &RunRecord) -> impl Iterator<Item = &String> {
    r.attestations.iter().chain(&r.per_target_attestations)
}

/// Whether a statement's path files it with its run: in the run's own directory, below its
/// published artifact's name, as statements are filed now; or, filed per target before runs had
/// their own, in that artifact's.
fn filed_with(path: &str, r: &RunRecord) -> bool {
    let mut dirs = path.rsplit('/').skip(1);
    match (dirs.next(), dirs.next()) {
        (Some(dir), Some(above)) if dir == r.id => above == r.upstream.name,
        (Some(dir), _) => dir == r.upstream.name,
        _ => false,
    }
}

/// The blobs a statement signs as its evidence, by name, but its rebuilt artifact: the run names
/// that where the store keeps it, and a run pruned after it was signed keeps only its digest.
fn evidence(bytes: &[u8]) -> Result<Vec<(String, Digest)>> {
    let env: trigon_attest::Envelope =
        serde_json::from_slice(bytes).context("it is not a DSSE envelope")?;
    let st: trigon_attest::Statement = serde_json::from_slice(&env.decoded_payload()?)
        .context("its payload is not an in-toto statement")?;
    let Some(signed) = st.predicate.get("evidence") else {
        return Ok(Vec::new());
    };
    let signed = signed
        .as_object()
        .context("it signs `evidence` as something other than an object of digests")?;
    let mut out = Vec::new();
    for (name, value) in signed {
        if name == trigon_attest::evidence_key::REBUILT_ARTIFACT {
            continue;
        }
        let digest = value
            .get("sha256")
            .and_then(|h| h.as_str())
            .and_then(|h| Digest::from_hex(h).ok())
            .with_context(|| {
                format!(
                    "it signs its `{}` evidence as something other than a sha256",
                    printable(name)
                )
            })?;
        out.push((name.clone(), digest));
    }
    Ok(out)
}

/// The digest of the stabilizer set a comparison was made under, as hex, where the bytes are a
/// comparison.
fn set_of(comparison: &[u8]) -> Option<String> {
    serde_json::from_slice::<trigon_compare::Comparison>(comparison)
        .ok()
        .map(|c| c.upstream.set.1.to_hex())
}

/// Everything `r` names that an export carries, into `files` under the names the export gives
/// them; refused where the store has lost a file the run is not whole without.
async fn gather(store: &Store, r: &RunRecord, files: &mut BTreeMap<String, Vec<u8>>) -> Result<()> {
    let id = r.id.as_str();
    for n in named(r) {
        if !store.blobs().has(&n.digest).await? {
            if n.needed {
                return Err(StoreError::Missing {
                    run: id.to_string(),
                    what: n.what,
                    digest: n.digest.to_hex(),
                }
                .into());
            }
            continue;
        }
        // Fetched by hash and checked against it: an export never carries bytes that are not
        // what their name says.
        let bytes = store.blobs().get(&n.digest).await?;
        files.insert(blob_path(&n.digest), bytes.to_vec());
    }
    for path in statements_of(r) {
        if !Store::is_statement_path(path) || !filed_with(path, r) {
            bail!(
                "run `{id}` names the statement {path}, which is not filed under the run or its \
                 published artifact, and an import refuses a run that names one elsewhere"
            );
        }
        let Some(bytes) = store.statement_bytes(path).await? else {
            bail!(
                "run `{id}` names the statement {path}, and the store has no file there, so the \
                 run cannot be exported whole"
            );
        };
        let signed = evidence(&bytes)
            .with_context(|| format!("reading the statement {path} run `{id}` names"))?;
        for (name, d) in signed {
            if !store.blobs().has(&d).await? {
                bail!(
                    "the statement {path} of run `{id}` signs sha256:{} as its `{name}` evidence, \
                     and the store has no blob of it, so the run cannot be exported whole",
                    d.to_hex()
                );
            }
            files.insert(blob_path(&d), store.blobs().get(&d).await?.to_vec());
        }
        files.insert(path.clone(), bytes.to_vec());
    }
    let comparison = r.comparison.and_then(|d| files.get(&blob_path(&d)));
    if let Some(set) = comparison.and_then(|b| set_of(b)) {
        match store.get_stabilizer_set(&set).await {
            Ok(m) => {
                files.insert(set_path(&set), serde_json::to_vec_pretty(&m)?);
            }
            // `attest` publishes it, so a run never attested in this store has none; the
            // importing store's `attest` publishes it there.
            Err(StoreError::NoSuchSet(_)) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// A file read whole, refused unless it is a regular file of at most `limit` bytes.
fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let meta = f.metadata()?;
    if !meta.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    if meta.len() > limit {
        bail!(
            "it is {} bytes, over the {limit} an import reads: the most an artifact may expand to",
            meta.len()
        );
    }
    let mut bytes = Vec::new();
    // Bounded as it is read, whatever the length said a moment ago.
    f.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        bail!("it grew past the {limit} bytes an import reads while it was read");
    }
    Ok(bytes)
}

/// What an entry of an export is, by its whole path.
enum Kind {
    Manifest,
    Run(String),
    Blob(Digest),
    Set(String),
    Statement,
}

/// The kind of file an export writes at `path`, or `None` where it writes none.
fn kind(path: &str) -> Option<Kind> {
    // Lower case, as `to_hex` writes it: one digest, one name.
    let hex = |h: &str| Digest::from_hex(h).ok().filter(|d| d.to_hex() == h);
    if path == MANIFEST {
        return Some(Kind::Manifest);
    }
    if let Some(id) = path.strip_prefix("runs/") {
        let id = id.strip_suffix(".json")?;
        return Store::is_run_id(id).then(|| Kind::Run(id.to_string()));
    }
    if let Some(h) = path.strip_prefix("blobs/sha256/") {
        return hex(h).map(Kind::Blob);
    }
    if let Some(h) = path.strip_prefix("stabilizers/sha256/") {
        let h = h.strip_suffix(".json")?;
        return hex(h).map(|_| Kind::Set(h.to_string()));
    }
    Store::is_statement_path(path).then_some(Kind::Statement)
}

/// What an entry that is not a regular file is, for a refusal.
fn described(kind: &EntryKind, typeflag: u8) -> String {
    match kind {
        EntryKind::Symlink { .. } => "a symbolic link".into(),
        EntryKind::Hardlink { .. } => "a hard link".into(),
        EntryKind::Directory => "a directory".into(),
        EntryKind::CharDevice { .. } | EntryKind::BlockDevice { .. } => "a device".into(),
        EntryKind::Fifo => "a FIFO".into(),
        EntryKind::Regular | EntryKind::Other(_) => {
            format!("an entry of typeflag {:?}", typeflag as char)
        }
    }
}

/// What a run names that the file carries.
#[derive(Default)]
struct Carried {
    blobs: BTreeSet<Digest>,
    statements: BTreeSet<String>,
    sets: BTreeSet<String>,
}

/// An export, read whole and checked, with nothing written anywhere.
struct Checked {
    archive: Archive,
    /// The runs, in the order the manifest names them.
    runs: Vec<RunRecord>,
    /// Where in `archive` each blob is, by digest, and each statement, by path.
    blobs: BTreeMap<Digest, usize>,
    statements: BTreeMap<String, usize>,
    /// Each set's manifest, by its digest.
    sets: BTreeMap<String, SetManifest>,
    /// What each run names that the file carries, by id.
    carried: BTreeMap<String, Carried>,
}

impl Checked {
    fn body(&self, at: usize) -> Result<Cow<'_, [u8]>> {
        Ok(self.archive.entries[at].body_bytes()?)
    }
}

/// Read an export and check every part of it, touching no store: see the module's account of
/// what an import checks.
fn check(src: Arc<SourceMap>, limits: &Limits) -> Result<Checked> {
    if src.as_slice().starts_with(&[0x1f, 0x8b]) {
        bail!(
            "it is gzip-compressed, and an import never decompresses: a compressed file's size \
             says nothing of what it holds. Decompress it first, where you can see what it comes to"
        );
    }
    let mut notes = Vec::new();
    let archive = trigon_archive::tar::read(src, limits, &mut notes)
        .context("it is not a tar, so it is not an export `trigon runs export` wrote")?;
    if let Some(n) = notes.first() {
        let at = n
            .path
            .as_ref()
            .map(|p| format!(" at {p}"))
            .unwrap_or_default();
        bail!(
            "reading it as a tar noted {:?}{at}: {}, and an export holds nothing a reader has to \
             remark on",
            n.code,
            printable(&n.detail)
        );
    }
    if !archive.tar_trailing.is_empty() {
        bail!(
            "{} bytes follow the end of the archive, and an export writes none",
            archive.tar_trailing.len()
        );
    }
    match archive.entries.first() {
        Some(e) if e.path.as_bytes() == MANIFEST.as_bytes() => {}
        _ => bail!(
            "it does not begin with {MANIFEST}, so it is not an export `trigon runs export` wrote"
        ),
    }

    let mut manifest: Option<Manifest> = None;
    let mut records: BTreeMap<String, RunRecord> = BTreeMap::new();
    let mut blobs = BTreeMap::new();
    let mut statements = BTreeMap::new();
    let mut sets = BTreeMap::new();
    for (at, e) in archive.entries.iter().enumerate() {
        let path = std::str::from_utf8(e.path.as_bytes()).map_err(|_| {
            anyhow!("entry {at}'s name is not UTF-8, and every name an export writes is")
        })?;
        let shown = printable(path);
        let RawMeta::Tar(raw) = &e.raw else {
            bail!("{shown} is not a tar entry");
        };
        if e.kind != EntryKind::Regular || raw.typeflag != b'0' {
            bail!(
                "{shown} is {}, and an export holds regular files and nothing else: an import \
                 follows no link and makes no directory",
                described(&e.kind, raw.typeflag)
            );
        }
        if !raw.linkname.is_empty() || !raw.pax.is_empty() {
            bail!(
                "{shown} carries a link name or PAX records beyond its name, which an export \
                 never writes"
            );
        }
        let body = e.body_bytes()?;
        let document = || match body.len() as u64 > DOCUMENT_LIMIT {
            true => Err(anyhow!(
                "{shown} is {} bytes, over the {DOCUMENT_LIMIT} a JSON document of an export may \
                 be",
                body.len()
            )),
            false => Ok(()),
        };
        match kind(path) {
            Some(Kind::Manifest) if at == 0 => {
                document()?;
                manifest = Some(
                    serde_json::from_slice(&body)
                        .with_context(|| format!("{shown} is not an export's manifest"))?,
                );
            }
            Some(Kind::Run(id)) => {
                document()?;
                let r: RunRecord = serde_json::from_slice(&body)
                    .with_context(|| format!("{shown} is not a run record"))?;
                if r.id != id {
                    bail!("{shown} holds the record of run `{}`", printable(&r.id));
                }
                records.insert(id, r);
            }
            Some(Kind::Blob(d)) => {
                let actual = trigon_store::digest_of(&body);
                if actual != d {
                    bail!(
                        "{shown} hashes to sha256:{}, not to its name",
                        actual.to_hex()
                    );
                }
                blobs.insert(d, at);
            }
            Some(Kind::Set(hex)) => {
                document()?;
                let m: SetManifest = serde_json::from_slice(&body)
                    .with_context(|| format!("{shown} is not a stabilizer set's manifest"))?;
                if !m.self_consistent() || m.digest != hex {
                    bail!(
                        "{shown} does not recompute to the digest its name is: it describes some \
                         other set, or it has been edited"
                    );
                }
                sets.insert(hex, m);
            }
            Some(Kind::Statement) => {
                document()?;
                statements.insert(path.to_string(), at);
            }
            _ => bail!("{shown} is not a file an export writes"),
        }
    }

    let manifest = manifest.context("its manifest is missing")?;
    if manifest.schema != SCHEMA {
        bail!(
            "it is a `{}` file, and this Trigon imports `{SCHEMA}`",
            printable(&manifest.schema)
        );
    }
    let listed: BTreeSet<&String> = manifest.runs.iter().collect();
    if listed.len() != manifest.runs.len() || !listed.iter().copied().eq(records.keys()) {
        bail!(
            "its manifest names the runs {} and it holds the records of {}: each run once, and \
             every run it holds",
            printable(&manifest.runs.join(", ")),
            printable(&records.keys().cloned().collect::<Vec<_>>().join(", "))
        );
    }

    // What each run names, every part of it carried.
    let mut carried = BTreeMap::new();
    for r in records.values() {
        let id = printable(&r.id);
        let mut k = Carried::default();
        for n in named(r) {
            if blobs.contains_key(&n.digest) {
                k.blobs.insert(n.digest);
            } else if n.needed {
                bail!(
                    "run `{id}` names its {}, sha256:{}, and the file does not carry it",
                    n.what,
                    n.digest.to_hex()
                );
            }
        }
        for path in statements_of(r) {
            let shown = printable(path);
            if !Store::is_statement_path(path) || !filed_with(path, r) {
                bail!(
                    "run `{id}` names the statement {shown}, which is not filed under the run or \
                     its published artifact"
                );
            }
            let Some(&at) = statements.get(path) else {
                bail!("run `{id}` names the statement {shown}, and the file does not carry it");
            };
            let body = archive.entries[at].body_bytes()?;
            let signed =
                evidence(&body).with_context(|| format!("reading the statement {shown}"))?;
            for (name, d) in signed {
                if !blobs.contains_key(&d) {
                    bail!(
                        "the statement {shown} signs sha256:{} as its `{}` evidence, and the file \
                         does not carry it",
                        d.to_hex(),
                        printable(&name)
                    );
                }
                k.blobs.insert(d);
            }
            k.statements.insert(path.clone());
        }
        let comparison = r.comparison.and_then(|d| blobs.get(&d));
        let body = comparison.and_then(|&at| archive.entries[at].body_bytes().ok());
        if let Some(set) = body.and_then(|b| set_of(&b))
            && sets.contains_key(&set)
        {
            k.sets.insert(set);
        }
        carried.insert(r.id.clone(), k);
    }
    // And nothing carried that no run names, which an import would otherwise write.
    let named_by_none: Vec<String> = blobs
        .keys()
        .filter(|d| !carried.values().any(|k: &Carried| k.blobs.contains(*d)))
        .map(blob_path)
        .chain(
            statements
                .keys()
                .filter(|p| !carried.values().any(|k| k.statements.contains(*p)))
                .map(|p| printable(p)),
        )
        .chain(
            sets.keys()
                .filter(|s| !carried.values().any(|k| k.sets.contains(*s)))
                .map(|s| set_path(s)),
        )
        .collect();
    if !named_by_none.is_empty() {
        bail!(
            "it carries {}, which no run in it names, and an import writes nothing a record does \
             not name",
            named_by_none.join(", ")
        );
    }

    let runs = manifest
        .runs
        .iter()
        .map(|id| {
            records
                .remove(id)
                .expect("every listed run's record is held")
        })
        .collect();
    Ok(Checked {
        archive,
        runs,
        blobs,
        statements,
        sets,
        carried,
    })
}

/// What an import of `c` makes of `store`.
struct Against<'c> {
    /// The runs to write.
    new: Vec<&'c RunRecord>,
    /// Those already in the store as the file has them, left alone.
    here: Vec<&'c RunRecord>,
    /// Why the import is refused, every reason at once: a run already here that differs, and a
    /// statement at a path that holds another.
    refused: Vec<String>,
}

/// What an import of `c` would write to `store`, and what refuses it.
async fn against<'c>(store: &Store, c: &'c Checked) -> Result<Against<'c>> {
    let (mut new, mut here) = (Vec::new(), Vec::new());
    let mut refused = BTreeSet::new();
    for r in &c.runs {
        match store.get_run(&r.id).await {
            Ok(there) if there == *r => here.push(r),
            Ok(there) => {
                refused.insert(format!(
                    "run `{}` is in this store already, and its record here differs from the \
                     file's in {}. A run id names one run; this one is refused",
                    r.id,
                    differs(&there, r)
                ));
            }
            Err(StoreError::NoSuchRun(_)) => new.push(r),
            Err(e) => return Err(e.into()),
        }
    }
    for r in &new {
        for path in &c.carried[&r.id].statements {
            if let Some(there) = store.statement_bytes(path).await?
                && there[..] != c.body(c.statements[path])?[..]
            {
                refused.insert(format!(
                    "{path} holds another statement in this store, and statements are never \
                     overwritten"
                ));
            }
        }
    }
    Ok(Against {
        new,
        here,
        refused: refused.into_iter().collect(),
    })
}

/// The top-level fields in which two records of one run differ, for a refusal.
fn differs(a: &RunRecord, b: &RunRecord) -> String {
    let (Ok(serde_json::Value::Object(a)), Ok(serde_json::Value::Object(b))) =
        (serde_json::to_value(a), serde_json::to_value(b))
    else {
        return "what it records".into();
    };
    let keys: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
    let fields: Vec<String> = keys
        .into_iter()
        .filter(|k| a.get(*k) != b.get(*k))
        .map(|k| format!("`{k}`"))
        .collect();
    fields.join(", ")
}

/// Write what the runs `new` name, blobs first and each record last.
async fn write(store: &Store, c: &Checked, new: &[&RunRecord]) -> Result<()> {
    let (mut blobs, mut sets, mut statements) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    for r in new {
        let k = &c.carried[&r.id];
        blobs.extend(&k.blobs);
        sets.extend(&k.sets);
        statements.extend(&k.statements);
    }
    // Held from before the first blob goes in until the last record naming them is written, as a
    // run's own writer holds it: a prune in between would delete bytes a record is about to say
    // are kept.
    let keeping = store.keeping().await?;
    for d in blobs {
        let put = store.blobs().put(c.body(c.blobs[d])?.into_owned()).await?;
        if put != *d {
            bail!(
                "the blob checked as sha256:{} was stored as sha256:{}; nothing names it yet",
                d.to_hex(),
                put.to_hex()
            );
        }
    }
    for s in sets {
        store.put_stabilizer_set(&c.sets[s]).await?;
    }
    for path in statements {
        let body = c.body(c.statements[path])?.into_owned();
        store.put_statement(path, body).await?;
    }
    // Each a create, never a write over a record: `against` found none under the id, and a writer
    // may file one there since, which `keeping`, shared between writers, does not hold off.
    for r in new {
        store
            .create_run(r)
            .await
            .with_context(|| format!("writing the record of run `{}`", r.id))?;
    }
    drop(keeping);
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Runs moved between two stores on this machine, as they move between two: no podman, and
    //! records written as `record_run` and `attest` write them.

    use std::path::PathBuf;

    use super::*;
    use trigon_store::{ArtifactRef, CacheState, Environment, RunState};

    const PURL: &str = "pkg:npm/demo@1.0.0";
    const ARTIFACT: &str = "demo-1.0.0.tgz";

    /// The files of an export, by path, in the order it holds them.
    type Files = Vec<(String, Vec<u8>)>;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("trigon-transfer-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

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

    const STRATEGY: &str = "schema: 1\nkind: flow\nlocation:\n  repo: \
                            https://github.com/owner/demo\n  ref: \
                            ff8e7ba8b4122829cf66125ca8445cac7f073bce\nsrc:\n- uses: \
                            git-checkout\nbuild:\n- runs: npm pack\noutput_path: '*.tgz'\n";

    /// A run of `body` in the store at `dir`, made on `host`, as `record_run` records a match and
    /// `attest` files its verdict: both artifacts, the comparison, the strategy, the guard
    /// manifest, a build log and an empty network transcript in the blob store; a statement filed
    /// under the run, signing the set's manifest file and the comparison as evidence; and the set
    /// published under `stabilizers/`.
    fn recorded(dir: &Path, id: &str, body: &str, host: &str) -> RunRecord {
        recorded_as(dir, id, body, host, PURL, ARTIFACT)
    }

    /// [`recorded`], of the package `purl` and its artifact `artifact`.
    fn recorded_as(
        dir: &Path,
        id: &str,
        body: &str,
        host: &str,
        purl: &str,
        artifact: &str,
    ) -> RunRecord {
        rt().block_on(async {
            let store = Store::local(dir).unwrap();
            let blobs = store.blobs();
            let (upstream, rebuilt) = (tgz(body.as_bytes(), 1), tgz(body.as_bytes(), 2));
            let up = blobs.put(upstream.clone()).await.unwrap();
            let rb = blobs.put(rebuilt.clone()).await.unwrap();
            let set = trigon_stabilize::profile("tar-gzip").unwrap();
            let c = trigon_compare::compare_bytes(
                upstream.clone(),
                rebuilt.clone(),
                Format::TarGz,
                &set,
                &Limits::default(),
            )
            .unwrap();
            let comparison = blobs.put(serde_json::to_vec(&c).unwrap()).await.unwrap();
            let strategy = trigon_strategy::from_yaml(STRATEGY).unwrap();
            let canonical = trigon_strategy::canonical(&strategy).unwrap();
            let strategy_blob = blobs.put(canonical.into_bytes()).await.unwrap();
            let guard = format!(r#"{{"artifact":"{body}","members":["x"]}}"#);
            let guard = blobs.put(guard.into_bytes()).await.unwrap();
            let log = blobs.put(b"npm pack\n".to_vec()).await.unwrap();
            // Present and empty: a build that fetched nothing, which is a claim.
            let network = blobs.put(Vec::new()).await.unwrap();

            let mut r = RunRecord::new(
                id,
                purl,
                ArtifactRef {
                    name: artifact.into(),
                    sha256: up,
                    bytes: upstream.len() as u64,
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
                "2026-09-27T00:00:00Z",
            );
            r.state = RunState::Done;
            r.outcome = Some(c.outcome.to_string());
            r.comparison = Some(comparison);
            r.rebuild = Some(ArtifactRef {
                name: artifact.into(),
                sha256: rb,
                bytes: rebuilt.len() as u64,
                stored: true,
            });
            r.strategy = Some(strategy_blob);
            r.build_log = Some(log);
            r.network_transcript = Some(network);
            r.agreement = Some(c.agreement());
            r.host = Some(host.into());
            r.cache = Some(CacheState::default());
            r.costs = Some(trigon_store::Costs {
                build_seconds: Some(12.5),
                ..Default::default()
            });
            store.put_run(&r).await.unwrap();

            let manifest = set.manifest();
            store.put_stabilizer_set(&manifest).await.unwrap();
            let file = trigon_attest::set_manifest_file(&manifest).unwrap();
            let manifest_blob = blobs.put(file).await.unwrap();
            let statement = trigon_attest::Statement {
                type_: trigon_attest::STATEMENT_TYPE.into(),
                subject: Vec::new(),
                predicate_type: trigon_attest::EQUIVALENCE_V2.into(),
                predicate: serde_json::json!({ "evidence": {
                    "stabilizerSetManifest": { "sha256": manifest_blob.to_hex() },
                    "comparison": { "sha256": comparison.to_hex() },
                    "rebuiltArtifact": { "sha256": rb.to_hex() },
                }}),
            };
            let payload = serde_json::to_vec(&statement).unwrap();
            let env = trigon_attest::Envelope::new(&payload, vec![]);
            let target = trigon_core::Target::new(
                purl.parse().unwrap(),
                trigon_core::ArtifactId::new(artifact),
            );
            let predicate = trigon_attest::EQUIVALENCE_V2;
            let path = store
                .put_attestation(&target, id, artifact, predicate, &env)
                .await
                .unwrap();
            store.record_attestations(id, &[path]).await.unwrap()
        })
    }

    /// Every file under `dir` but the lock, by its path under `dir`.
    fn files(dir: &Path) -> BTreeMap<String, Vec<u8>> {
        let mut out = BTreeMap::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&d) else {
                continue;
            };
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.file_name().is_some_and(|n| n != "blobs.lock") {
                    let name = p.strip_prefix(dir).unwrap().to_string_lossy().into_owned();
                    out.insert(name, std::fs::read(&p).unwrap());
                }
            }
        }
        out
    }

    fn run_in(dir: &Path, id: &str) -> Option<RunRecord> {
        rt().block_on(Store::local(dir).unwrap().get_run(id)).ok()
    }

    /// A run exported from one store, imported into another, is the run it was: every file the
    /// first store holds for it, byte for byte, and a record that says which machine made it, when
    /// and how, as that machine recorded it and not as this one would.
    #[test]
    fn a_run_moves_whole_and_as_it_was_recorded() {
        let work = tmpdir("whole");
        let (a, b) = (work.join("a"), work.join("b"));
        let id = "1789000000-aaaa0001";
        let there = recorded(&a, id, "one", &format!("machine-id:{}", "a".repeat(64)));
        assert_eq!(run_in(&b, id), None);

        export(&a, &[id.to_string()], &work.join("run.tar")).unwrap();
        import(&work.join("run.tar"), &b).unwrap();

        let here = run_in(&b, id).expect("the run is imported");
        assert_eq!(here, there);
        assert_eq!(here.host, there.host, "the maker's machine, not this one");
        assert_eq!(here.started, there.started);
        let (from, to) = (files(&a), files(&b));
        assert_eq!(
            from.keys().collect::<Vec<_>>(),
            to.keys().collect::<Vec<_>>(),
            "every file the run names, and nothing else"
        );
        assert_eq!(from, to);
        assert!(
            to.keys().any(|p| p.starts_with("stabilizers/sha256/")),
            "{:?}",
            to.keys()
        );
        assert!(to.keys().any(|p| p.ends_with("equivalence.intoto.json")));
    }

    /// A statement filed at a path longer than the 100 bytes a tar header holds, as a scoped npm
    /// package's is, and one filed under a PEP 440 epoch's `!`, move as any other: the long name
    /// goes in a PAX `path` record, which an import reads as the name and not as a record it
    /// refuses.
    #[test]
    fn a_run_whose_statement_has_a_long_name_or_an_epoch_moves_whole() {
        let work = tmpdir("long-names");
        let (a, b) = (work.join("a"), work.join("b"));
        let mut ids = Vec::new();
        for (id, purl, artifact) in [
            (
                "1789000000-aaaa0001",
                "pkg:npm/@typescript-eslint/eslint-plugin@8.0.0-alpha.30",
                "eslint-plugin-8.0.0-alpha.30.tgz",
            ),
            (
                "1789000100-bbbb0002",
                "pkg:pypi/foo@1!2.0",
                "foo-1!2.0.tar.gz",
            ),
        ] {
            let r = recorded_as(&a, id, id, "machine-id:one", purl, artifact);
            assert_eq!(r.attestations.len(), 1, "{purl}");
            ids.push(r.id);
        }
        let long = &run_in(&a, &ids[0]).unwrap().attestations[0];
        assert!(long.len() > 100, "{long}");

        export(&a, &ids, &work.join("runs.tar")).unwrap();
        import(&work.join("runs.tar"), &b).unwrap();
        for id in &ids {
            assert_eq!(run_in(&b, id), run_in(&a, id));
        }
        assert_eq!(files(&a), files(&b));
    }

    /// The same runs make the same file, however they are named and whenever.
    #[test]
    fn the_same_runs_export_to_the_same_bytes() {
        let work = tmpdir("same-bytes");
        let a = work.join("a");
        let (one, two) = ("1789000000-aaaa0001", "1789000100-bbbb0002");
        recorded(&a, one, "one", "machine-id:one");
        recorded(&a, two, "two", "machine-id:one");
        let (first, second) = (work.join("first.tar"), work.join("second.tar"));
        export(&a, &[one.into(), two.into()], &first).unwrap();
        export(&a, &[two.into(), one.into(), two.into()], &second).unwrap();
        let first = std::fs::read(first).unwrap();
        assert_eq!(first, std::fs::read(second).unwrap());
        assert_eq!(files_of(&first)[0].0, MANIFEST);
        assert_eq!(
            files_of(&first)[0].1,
            format!(r#"{{"runs":["{one}","{two}"],"schema":"{SCHEMA}"}}"#).as_bytes()
        );
    }

    /// The files of an export, in order.
    fn files_of(tar: &[u8]) -> Files {
        let src = Arc::new(SourceMap::owned(tar.to_vec()));
        let a = trigon_archive::tar::read(src, &Limits::default(), &mut Vec::new()).unwrap();
        a.entries
            .iter()
            .map(|e| {
                let path = String::from_utf8(e.path.as_bytes().to_vec()).unwrap();
                (path, e.body_bytes().unwrap().into_owned())
            })
            .collect()
    }

    /// A tar of `entries`, which may be anything a tar holds.
    fn tar_of_entries(entries: Vec<Entry>) -> Vec<u8> {
        let mut a = Archive::new(Format::Tar, Trailer::Tar);
        a.entries = entries;
        let mut out = Vec::new();
        trigon_archive::tar::write(&a, &mut out).unwrap();
        out
    }

    /// These files as entries, as an export writes them.
    fn entries_of(files: &[(String, Vec<u8>)]) -> Vec<Entry> {
        let entry = |n: usize, (p, b): &(String, Vec<u8>)| {
            Entry::tar_file(EntryPath::from(p.as_str()), n as u32, b.clone())
        };
        files.iter().enumerate().map(|(n, f)| entry(n, f)).collect()
    }

    /// A tar of these files, as an export writes one.
    fn tar_of(files: &[(String, Vec<u8>)]) -> Vec<u8> {
        tar_of_entries(entries_of(files))
    }

    /// An entry of `kind` at `path`, as a tar made elsewhere could hold one.
    fn special(path: &str, kind: EntryKind, typeflag: u8, link: &[u8]) -> Entry {
        let mut e = Entry::tar_file(EntryPath::from(path), 99, Vec::new());
        e.kind = kind;
        if let RawMeta::Tar(t) = &mut e.raw {
            t.typeflag = typeflag;
            t.linkname = link.to_vec();
        }
        e
    }

    /// `bytes`, imported into a store of their own under `limits`: the refusal, and a store with
    /// nothing in it.
    fn refused_within(work: &Path, case: &str, bytes: &[u8], limits: &Limits) -> String {
        let file = work.join(format!("{case}.tar"));
        std::fs::write(&file, bytes).unwrap();
        let store = work.join(format!("store-{case}"));
        let e = import_within(&file, &store, limits).expect_err(case);
        let said = format!("{e:#}");
        assert!(said.contains("nothing was written"), "{case}: {said}");
        assert_eq!(files(&store), BTreeMap::new(), "{case}: nothing written");
        said
    }

    fn refused(work: &Path, case: &str, bytes: &[u8]) -> String {
        refused_within(work, case, bytes, &Limits::default())
    }

    /// Every check an import makes of the file, one at a time: each refuses the file, says why,
    /// and leaves the store without a file in it. The export itself goes in whole.
    #[test]
    fn an_import_is_checked_whole_before_anything_is_written() {
        let work = tmpdir("checked");
        let a = work.join("a");
        let id = "1789000000-aaaa0001";
        let r = recorded(&a, id, "one", "machine-id:one");
        export(&a, &[id.into()], &work.join("run.tar")).unwrap();
        let good = std::fs::read(work.join("run.tar")).unwrap();
        let fs = files_of(&good);
        assert_eq!(
            tar_of(&fs),
            good,
            "the cases below change only what they say"
        );

        let with = |f: &dyn Fn(&mut Files)| {
            let mut fs = fs.clone();
            f(&mut fs);
            tar_of(&fs)
        };
        let at =
            |fs: &[(String, Vec<u8>)], path: &str| fs.iter().position(|(p, _)| p == path).unwrap();
        let strategy = blob_path(&r.strategy.unwrap());
        let record = run_path(id);
        let statement = r.attestations[0].clone();

        // A blob that is not what its name says.
        let said = refused(
            &work,
            "forged-blob",
            &with(&|fs| {
                let i = at(fs, &strategy);
                fs[i].1.push(b' ');
            }),
        );
        assert!(said.contains("not to its name"), "{said}");
        // A blob the record needs, left out.
        let said = refused(
            &work,
            "missing-blob",
            &with(&|fs| {
                let i = at(fs, &strategy);
                fs.remove(i);
            }),
        );
        assert!(said.contains("names its strategy"), "{said}");
        // A statement the record names, left out.
        let said = refused(
            &work,
            "missing-statement",
            &with(&|fs| {
                let i = at(fs, &statement);
                fs.remove(i);
            }),
        );
        assert!(said.contains("does not carry it"), "{said}");
        // A record that is not one, and one filed under another run's id.
        let said = refused(
            &work,
            "not-a-record",
            &with(&|fs| {
                let i = at(fs, &record);
                fs[i].1 = b"{\"id\":".to_vec();
            }),
        );
        assert!(said.contains("is not a run record"), "{said}");
        let said = refused(
            &work,
            "record-elsewhere",
            &with(&|fs| {
                let i = at(fs, &record);
                fs[i].0 = run_path("1789000000-zzzz9999");
            }),
        );
        assert!(said.contains("holds the record of run"), "{said}");
        // Paths an export never writes, and ones that would climb out of a store.
        let upper = format!(
            "blobs/sha256/{}",
            r.comparison.unwrap().to_hex().to_uppercase()
        );
        for (case, path) in [
            ("dot-dot", "runs/../../../etc/passwd"),
            ("dot-dot-blob", "blobs/sha256/../../runs/x.json"),
            ("absolute", "/etc/passwd"),
            ("dot-slash", "./trigon-runs.json"),
            ("elsewhere", "derived/comparison/sha256/aa/x.json"),
            ("upper-case-blob", upper.as_str()),
        ] {
            let said = refused(
                &work,
                case,
                &with(&|fs| {
                    fs.push((path.to_string(), b"{}".to_vec()));
                }),
            );
            assert!(
                said.contains("is not a file an export writes"),
                "{case}: {said}"
            );
        }
        // A statement the record names outside its run's directory and its artifact's.
        let said = refused(
            &work,
            "statement-elsewhere",
            &with(&|fs| {
                let elsewhere = statement.replace(id, "1789000999-other");
                let i = at(fs, &record);
                let mut r: RunRecord = serde_json::from_slice(&fs[i].1).unwrap();
                r.attestations = vec![elsewhere.clone()];
                fs[i].1 = serde_json::to_vec_pretty(&r).unwrap();
                let s = at(fs, &statement);
                fs[s].0 = elsewhere;
                fs.sort_by(|x, y| (x.0 != MANIFEST, &x.0).cmp(&(y.0 != MANIFEST, &y.0)));
            }),
        );
        assert!(said.contains("not filed under the run"), "{said}");
        // Something no run names.
        let stray = trigon_store::digest_of(b"stray");
        let said = refused(
            &work,
            "stray",
            &with(&|fs| {
                fs.push((blob_path(&stray), b"stray".to_vec()));
            }),
        );
        assert!(said.contains("which no run in it names"), "{said}");
        // Each file once, the manifest first, and the manifest naming what is held.
        let said = refused(
            &work,
            "twice",
            &with(&|fs| {
                let dup = fs[at(fs, &strategy)].clone();
                fs.push(dup);
            }),
        );
        assert!(said.contains("DuplicateEntryPath"), "{said}");
        let said = refused(
            &work,
            "manifest-last",
            &with(&|fs| {
                let m = fs.remove(0);
                fs.push(m);
            }),
        );
        assert!(said.contains("does not begin with"), "{said}");
        let said = refused(
            &work,
            "other-schema",
            &with(&|fs| {
                fs[0].1 = format!(r#"{{"runs":["{id}"],"schema":"trigon.runs/v9"}}"#).into_bytes();
            }),
        );
        assert!(said.contains("trigon.runs/v9"), "{said}");
        let said = refused(
            &work,
            "unlisted",
            &with(&|fs| {
                fs[0].1 = format!(r#"{{"runs":[],"schema":"{SCHEMA}"}}"#).into_bytes();
            }),
        );
        assert!(said.contains("every run it holds"), "{said}");
        // A JSON document longer than a published record may be.
        let said = refused(
            &work,
            "long-record",
            &with(&|fs| {
                let i = at(fs, &record);
                let mut r: RunRecord = serde_json::from_slice(&fs[i].1).unwrap();
                r.declines = vec!["x".repeat(1 << 16); 70];
                fs[i].1 = serde_json::to_vec_pretty(&r).unwrap();
            }),
        );
        assert!(said.contains("a JSON document of an export"), "{said}");

        // Links, a directory and a device, none of them followed or made.
        let (etc, rec) = (b"/etc".to_vec(), record.clone().into_bytes());
        for (case, kind, flag, link) in [
            (
                "symlink",
                EntryKind::Symlink {
                    target: etc.clone(),
                },
                b'2',
                &etc[..],
            ),
            (
                "hardlink",
                EntryKind::Hardlink {
                    target: rec.clone(),
                },
                b'1',
                &rec[..],
            ),
            ("directory", EntryKind::Directory, b'5', &b""[..]),
            ("fifo", EntryKind::Fifo, b'6', &b""[..]),
        ] {
            let mut entries = entries_of(&fs);
            entries.push(special(&blob_path(&stray), kind, flag, link));
            let said = refused(&work, case, &tar_of_entries(entries));
            assert!(
                said.contains("regular files and nothing else"),
                "{case}: {said}"
            );
        }

        // Bytes after the end, and a compressed export, which is never inflated.
        let mut trailing = good.clone();
        trailing.extend_from_slice(b"more after the end");
        let said = refused(&work, "trailing", &trailing);
        assert!(said.contains("follow the end of the archive"), "{said}");
        let mut gz = Vec::new();
        {
            use std::io::Write as _;
            let mut e = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
            e.write_all(&good).unwrap();
            e.finish().unwrap();
        }
        let said = refused(&work, "gzip", &gz);
        assert!(said.contains("never decompresses"), "{said}");
        let said = refused(
            &work,
            "not-a-tar",
            b"this is not a tar at all, not even close",
        );
        assert!(
            said.contains("not a tar") || said.contains("does not begin"),
            "{said}"
        );

        // The whole within the ceiling, and the entries within their count.
        let small = Limits {
            total_expanded_bytes: good.len() as u64 - 1,
            ..Limits::default()
        };
        let said = refused_within(&work, "too-long", &good, &small);
        assert!(said.contains("over the"), "{said}");
        let few = Limits {
            max_entries: fs.len() as u32 - 1,
            ..Limits::default()
        };
        let said = refused_within(&work, "too-many", &good, &few);
        assert!(said.contains("EntryLimitReached"), "{said}");

        // And the export as it was made goes in.
        let store = work.join("store-good");
        import(&work.join("run.tar"), &store).unwrap();
        assert_eq!(run_in(&store, id), Some(r));
    }

    /// Importing the same runs again is nothing; a run already here that differs is refused, with
    /// the fields it differs in, and so is the whole import, a run new here included.
    #[test]
    fn a_run_already_here_is_left_alone_or_refused_and_nothing_else_is_written() {
        let work = tmpdir("already");
        let (a, b) = (work.join("a"), work.join("b"));
        let (one, two) = ("1789000000-aaaa0001", "1789000100-bbbb0002");
        let first = recorded(&a, one, "one", "machine-id:one");
        recorded(&a, two, "two", "machine-id:one");
        let (both, just_one) = (work.join("both.tar"), work.join("one.tar"));
        export(&a, &[one.into(), two.into()], &both).unwrap();
        export(&a, &[one.into()], &just_one).unwrap();

        import(&just_one, &b).unwrap();
        let before = files(&b);
        import(&just_one, &b).unwrap();
        assert_eq!(files(&b), before, "the same run again changes nothing");

        // The same id, another run: here it was made elsewhere.
        let mut other = first.clone();
        other.host = Some("machine-id:two".into());
        rt().block_on(Store::local(&b).unwrap().put_run(&other))
            .unwrap();
        let before = files(&b);
        let e = import(&both, &b).unwrap_err();
        let said = format!("{e:#}");
        assert!(
            said.contains(&format!("run `{one}` is in this store already")),
            "{said}"
        );
        assert!(said.contains("`host`"), "{said}");
        assert_eq!(files(&b), before, "nothing of the other run either");
        assert_eq!(run_in(&b, two), None);
        assert_eq!(run_in(&b, one), Some(other));
    }

    /// A statement at a path the file names, holding another, refuses the import: statements are
    /// never written over.
    #[test]
    fn a_statement_that_differs_where_the_run_names_it_refuses_the_import() {
        let work = tmpdir("statement-there");
        let (a, b) = (work.join("a"), work.join("b"));
        let id = "1789000000-aaaa0001";
        let r = recorded(&a, id, "one", "machine-id:one");
        export(&a, &[id.into()], &work.join("run.tar")).unwrap();
        let path = &r.attestations[0];
        rt().block_on(
            Store::local(&b)
                .unwrap()
                .put_statement(path, b"another".to_vec()),
        )
        .unwrap();
        let before = files(&b);
        let e = import(&work.join("run.tar"), &b).unwrap_err();
        let said = format!("{e:#}");
        assert!(said.contains("holds another statement"), "{said}");
        assert_eq!(files(&b), before);
    }

    /// A record another writer files under the run's id after the import looked at the store, and
    /// before it writes its own, is refused and left as it is, never written over; the same record
    /// there is the same run, and the import goes on.
    #[test]
    fn a_run_filed_here_after_the_import_looked_is_never_written_over() {
        let work = tmpdir("filed-meanwhile");
        let (a, b) = (work.join("a"), work.join("b"));
        let id = "1789000000-aaaa0001";
        let first = recorded(&a, id, "one", "machine-id:one");
        export(&a, &[id.into()], &work.join("run.tar")).unwrap();
        let bytes = std::fs::read(work.join("run.tar")).unwrap();
        let checked = check(Arc::new(SourceMap::owned(bytes)), &Limits::default()).unwrap();
        let mut other = first.clone();
        other.host = Some("machine-id:two".into());
        rt().block_on(async {
            let store = Store::local(&b).unwrap();
            let Against { new, refused, .. } = against(&store, &checked).await.unwrap();
            assert_eq!((new.len(), refused.len()), (1, 0));
            // Another writer, between the look and the write.
            store.put_run(&other).await.unwrap();
            let e = write(&store, &checked, &new).await.unwrap_err();
            let said = format!("{e:#}");
            assert!(
                said.contains(&format!("run `{id}` is in this store already")),
                "{said}"
            );
            assert_eq!(store.get_run(id).await.unwrap(), other);

            store.put_run(&first).await.unwrap();
            write(&store, &checked, &new).await.unwrap();
            assert_eq!(store.get_run(id).await.unwrap(), first);
        });
    }

    /// Blobs first, each record last: an import that fails writing leaves no record naming a
    /// blob that is not there. Here the store's blob directory cannot be made.
    #[test]
    fn a_failed_import_leaves_no_record_naming_blobs_that_are_not_there() {
        let work = tmpdir("record-last");
        let (a, b) = (work.join("a"), work.join("b"));
        let id = "1789000000-aaaa0001";
        recorded(&a, id, "one", "machine-id:one");
        export(&a, &[id.into()], &work.join("run.tar")).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        std::fs::write(b.join("blobs"), b"a file where the blob directory goes").unwrap();

        import(&work.join("run.tar"), &b).unwrap_err();
        assert!(!b.join("runs").exists(), "{:?}", files(&b).keys());
    }

    /// An export is refused whole where the store has lost a file the run names, and writes
    /// nothing.
    #[test]
    fn a_run_whose_store_lost_a_file_it_names_is_not_exported() {
        let work = tmpdir("lost");
        let a = work.join("a");
        let id = "1789000000-aaaa0001";
        let r = recorded(&a, id, "one", "machine-id:one");
        let hex = r.strategy.unwrap().to_hex();
        std::fs::remove_file(a.join("blobs/sha256").join(&hex[..2]).join(&hex)).unwrap();
        let out = work.join("run.tar");
        let e = export(&a, &[id.into()], &out).unwrap_err();
        assert!(format!("{e:#}").contains("the bytes are missing"), "{e:#}");
        assert!(!out.exists());
    }
}
