//! Upstream fetches, kept on disk between the mirror and the registry.
//!
//! [`ADR-0013`](../../../docs/adr/0013-a-cache-supplies-bytes-never-decisions.md) decides the shape
//! and this implements it. The rule it inherits from ADR-0012:
//!
//! > A cache may supply **bytes** the evidence does not pin. It may never supply a **decision** the
//! > evidence does pin — and where it must, the run says so.
//!
//! # Why it is here and not in front of the mirror
//!
//! The mirror is where the evidence is made: `guard.refuses` rejects a build fetching its own
//! published artifact before the request is issued, `guarded_stream` hashes every body as it passes
//! and writes the transcript row, and the time filter runs on every index request. A cache in front
//! of those would make the transcript's one claim — that it lists everything that crossed — false.
//!
//! Behind them, nothing changes. The guard still runs first, the bytes still flow through the same
//! hashing stream, and the transcript is byte for byte what it would have been. This answers "where
//! did the mirror get this", which the run record can hold, rather than "what did the build
//! receive", which it must never be vague about.
//!
//! # Two tiers, because they carry different things
//!
//! A `.tgz`, a wheel, a `.crate` and a Node tarball are **bytes**: immutable by registry policy,
//! named by a URL that already contains the version. Serving one from disk cannot change an answer,
//! and [`Tier::Bytes`] entries are permanent.
//!
//! A packument is a **decision** — it determines which versions exist, and therefore which a build
//! resolves. [`Tier::Index`] entries are scoped to one invocation of the tool rather than given a
//! lifetime, so staleness is bounded by construction instead of by a number somebody picked, and
//! every entry carries the instant it was fetched so the run record can say so.
//!
//! # What the digest check does and does not prove
//!
//! Every entry stores the SHA-256 of its body, and every read re-hashes the file and compares. A
//! mismatch is a **miss**, never a warning, and the entry is removed.
//!
//! That proves the bytes on disk are the bytes that were fetched. It does not prove they are the
//! bytes the registry would serve now — for that there would have to be a published digest to
//! compare against, and the mirror does not hold one for every URL a build asks for. The claim is
//! the narrower one, and it is the one the failure mode needs: a partially written entry served as
//! whole is exactly `trigon/client-corrupted-download`, which took three investigations to
//! attribute. Bodies are written to a temporary path and renamed, and read back through the hash.

use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

/// What a cached entry carries, and therefore what rules govern it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    /// An artifact or a toolchain: immutable, permanent, shared by every run on this machine.
    Bytes,
    /// An index document: a decision, scoped to one invocation and never read by another.
    Index,
}

impl Tier {
    fn dir(self) -> &'static str {
        match self {
            Tier::Bytes => "bytes",
            Tier::Index => "index",
        }
    }
}

/// One entry, read back and verified.
#[derive(Clone, Debug)]
pub struct Entry {
    pub body: Vec<u8>,
    pub content_type: String,
    /// Unix seconds at which these bytes were fetched from upstream.
    ///
    /// **The index tier's whole obligation.** Without it, "resolved against the index as it stood
    /// at moment M" quietly becomes "resolved against our copy of it from day D", and nothing in
    /// the record tells them apart. Seconds rather than a formatted string because this crate has
    /// no date formatter and the repository already carries five copies of the one it would need.
    pub fetched_at: u64,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Meta {
    url: String,
    sha256: String,
    bytes: u64,
    content_type: String,
    fetched_at: u64,
}

/// What the cache did, for the run record and the log.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub written: u64,
    /// Entries that failed their digest check on read and were treated as misses.
    ///
    /// Non-zero is a finding about this disk, not about any package, and it must not be silent: an
    /// entry that fails is the corruption this design exists to refuse.
    pub rejected: u64,
    /// The oldest `fetched_at` of any [`Tier::Index`] entry this run read.
    ///
    /// `None` where no index came from cache, which is not the same as "fresh": a run that read no
    /// cached index resolved entirely against the network.
    pub oldest_index_read: Option<u64>,
}

pub struct Cache {
    root: PathBuf,
    /// Index entries live under this, and a mirror with a different one cannot see them.
    scope: String,
    hits: AtomicU64,
    misses: AtomicU64,
    written: AtomicU64,
    rejected: AtomicU64,
    oldest_index_read: AtomicU64,
}

/// The sentinel for "no index entry was read", because `0` is a real unix second.
const NO_INDEX_READ: u64 = u64::MAX;

impl Cache {
    /// Open a cache rooted at `root`, with index entries scoped to `scope`.
    ///
    /// `scope` is the sweep's identifier where there is a sweep, and the run's otherwise — which
    /// gives a standalone rebuild its own scope and therefore no shared index cache at all. That is
    /// the conservative default and it is deliberate: the prize is across the targets of one sweep,
    /// and a single rebuild has nothing to share with anybody.
    pub fn open(root: PathBuf, scope: String) -> std::io::Result<Cache> {
        std::fs::create_dir_all(root.join("tmp"))?;
        Ok(Cache {
            root,
            scope,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            written: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            oldest_index_read: AtomicU64::new(NO_INDEX_READ),
        })
    }

    fn key(&self, tier: Tier, url: &str) -> PathBuf {
        use sha2::Digest as _;
        let hex = format!("{:x}", sha2::Sha256::digest(url.as_bytes()));
        let mut p = self.root.join(tier.dir());
        if tier == Tier::Index {
            p = p.join(&self.scope);
        }
        // Two levels, so a directory does not grow to fourteen thousand entries on one sweep.
        p.join(&hex[..2]).join(&hex[2..])
    }

    /// The entry for `url`, if there is one and its bytes are still what was written.
    pub fn get(&self, tier: Tier, url: &str) -> Option<Entry> {
        let path = self.key(tier, url);
        let meta: Meta = std::fs::read(path.with_extension("meta"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())?;
        let body = std::fs::read(&path).ok()?;

        use sha2::Digest as _;
        let actual = format!("{:x}", sha2::Sha256::digest(&body));
        // A miss, never a warning. Serving bytes that are not the bytes we wrote is the failure
        // this whole design is arranged around, and a cache that logs it and continues has chosen
        // to be the source of exactly that bug.
        if actual != meta.sha256 || meta.url != url {
            self.rejected.fetch_add(1, Ordering::Relaxed);
            self.misses.fetch_add(1, Ordering::Relaxed);
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(path.with_extension("meta"));
            tracing::warn!(url, "a cache entry failed its digest check and was removed");
            return None;
        }

        self.hits.fetch_add(1, Ordering::Relaxed);
        // Out through the log beside the requests, so the host can tell a sweep that asked npm
        // 143,000 times from one that asked 14,000 and read the rest off this disk — and, for an
        // index, how old the document it decided against was.
        crate::guard::Asked {
            host: host_of(url),
            cached: true,
            index_fetched_at: (tier == Tier::Index).then_some(meta.fetched_at),
        }
        .emit();
        if tier == Tier::Index {
            self.oldest_index_read
                .fetch_min(meta.fetched_at, Ordering::Relaxed);
        }
        Some(Entry {
            body,
            content_type: meta.content_type,
            fetched_at: meta.fetched_at,
        })
    }

    /// Record a miss. Called where [`get`](Self::get) was not consulted because there is no entry.
    pub fn note_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Write `body` under `url`.
    ///
    /// Temporary path then rename, which is atomic within a filesystem: a reader never sees a
    /// half-written body, and two lanes writing the same key both produce a complete entry. The
    /// meta file is renamed **after** the body, so an interrupted write leaves a body with no meta,
    /// which [`get`](Self::get) treats as absent rather than as an entry it cannot check.
    pub fn put(
        &self,
        tier: Tier,
        url: &str,
        body: &[u8],
        content_type: &str,
        fetched_at: u64,
    ) -> std::io::Result<()> {
        use sha2::Digest as _;
        let sha256 = format!("{:x}", sha2::Sha256::digest(body));
        let path = self.key(tier, url);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let stamp = format!("{}-{}", std::process::id(), sha256);
        let tmp_body = self.root.join("tmp").join(&stamp);
        let tmp_meta = self.root.join("tmp").join(format!("{stamp}.meta"));
        {
            let mut f = std::fs::File::create(&tmp_body)?;
            f.write_all(body)?;
            // The rename is atomic; the write behind it is not durable without this, and a machine
            // that loses power mid-sweep would leave entries whose meta says bytes the body does
            // not have. They would fail the check and be removed, which is correct but wasteful.
            f.sync_all()?;
        }
        let meta = Meta {
            url: url.to_string(),
            sha256,
            bytes: body.len() as u64,
            content_type: content_type.to_string(),
            fetched_at,
        };
        std::fs::write(&tmp_meta, serde_json::to_vec(&meta)?)?;
        std::fs::rename(&tmp_body, &path)?;
        std::fs::rename(&tmp_meta, path.with_extension("meta"))?;
        self.written.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// A writer that fills an entry as bytes stream past, rather than after they are all in hand.
    ///
    /// An artifact can be gigabytes and the mirror serves a whole fleet; buffering one to cache it
    /// would undo the reason the proxy streams at all. The temporary file is renamed into place
    /// only by [`CacheWriter::finish`], so a body that never completes leaves nothing behind that a
    /// reader could mistake for a whole one.
    pub fn writer(&self, tier: Tier, url: &str) -> Option<CacheWriter> {
        use sha2::Digest as _;
        let stamp = format!("{}-{:x}", std::process::id(), fastrand_u64());
        let tmp = self.root.join("tmp").join(stamp);
        let file = std::fs::File::create(&tmp).ok()?;
        Some(CacheWriter {
            file: Some(file),
            tmp,
            dest: self.key(tier, url),
            url: url.to_string(),
            hasher: sha2::Sha256::new(),
            bytes: 0,
        })
    }

    /// Record what [`CacheWriter::finish`] produced, so the counters cover writes it made.
    pub fn note_write(&self) {
        self.written.fetch_add(1, Ordering::Relaxed);
    }

    pub fn stats(&self) -> CacheStats {
        let oldest = self.oldest_index_read.load(Ordering::Relaxed);
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            written: self.written.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            oldest_index_read: (oldest != NO_INDEX_READ).then_some(oldest),
        }
    }

    /// Drop the least recently modified entries until the tree is under `max_bytes`.
    ///
    /// Called at startup rather than on every write: a sweep's lanes would otherwise each walk the
    /// tree, and the bound is about the disk over days rather than about any one request. Returns
    /// the bytes removed.
    ///
    /// The measured distinct artifact traffic of one 186-run sweep is 2.4 GB, so five thousand
    /// targets is tens of gigabytes — enough that an unbounded cache is a machine that fills up in
    /// a week, reported as builds failing.
    pub fn prune(&self, max_bytes: u64) -> std::io::Result<u64> {
        let mut entries: Vec<(std::time::SystemTime, u64, PathBuf)> = Vec::new();
        let mut total = 0u64;
        let mut stack = vec![self.root.clone()];
        while let Some(dir) = stack.pop() {
            let Ok(read) = std::fs::read_dir(&dir) else {
                continue;
            };
            for e in read.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                // The meta travels with its body and is counted with it.
                if p.extension().is_some_and(|x| x == "meta") {
                    continue;
                }
                let Ok(md) = e.metadata() else { continue };
                let size = md.len();
                total += size;
                entries.push((md.modified().unwrap_or(std::time::UNIX_EPOCH), size, p));
            }
        }
        if total <= max_bytes {
            return Ok(0);
        }
        entries.sort_by_key(|(t, ..)| *t);
        let mut freed = 0;
        for (_, size, path) in entries {
            if total - freed <= max_bytes {
                break;
            }
            let _ = std::fs::remove_file(path.with_extension("meta"));
            if std::fs::remove_file(&path).is_ok() {
                freed += size;
            }
        }
        Ok(freed)
    }
}

/// A streaming write into the cache, completed only when the body does.
pub struct CacheWriter {
    file: Option<std::fs::File>,
    tmp: PathBuf,
    dest: PathBuf,
    url: String,
    hasher: sha2::Sha256,
    bytes: u64,
}

impl CacheWriter {
    /// Take one chunk. A write that fails abandons the entry rather than failing the request: the
    /// build is being served from the network either way, and a cache is never a reason to break a
    /// build.
    pub fn write(&mut self, chunk: &[u8]) {
        use sha2::Digest as _;
        let Some(f) = &mut self.file else { return };
        if f.write_all(chunk).is_err() {
            self.file = None;
            let _ = std::fs::remove_file(&self.tmp);
            return;
        }
        self.hasher.update(chunk);
        self.bytes += chunk.len() as u64;
    }

    /// Rename the entry into place. Called only where the body reached its end.
    pub fn finish(mut self, content_type: &str, fetched_at: u64) -> bool {
        use sha2::Digest as _;
        let Some(f) = self.file.take() else {
            return false;
        };
        if f.sync_all().is_err() {
            let _ = std::fs::remove_file(&self.tmp);
            return false;
        }
        drop(f);
        let meta = Meta {
            url: std::mem::take(&mut self.url),
            sha256: format!("{:x}", std::mem::take(&mut self.hasher).finalize()),
            bytes: self.bytes,
            content_type: content_type.to_string(),
            fetched_at,
        };
        let ok = self.dest.parent().is_some_and(|p| std::fs::create_dir_all(p).is_ok())
            && std::fs::write(self.tmp.with_extension("meta"), serde_json::to_vec(&meta).unwrap_or_default()).is_ok()
            // The body first, so an interrupted rename leaves a body with no meta, which `get`
            // reads as absent rather than as an entry it cannot check.
            && std::fs::rename(&self.tmp, &self.dest).is_ok()
            && std::fs::rename(self.tmp.with_extension("meta"), self.dest.with_extension("meta")).is_ok();
        if !ok {
            let _ = std::fs::remove_file(&self.tmp);
            let _ = std::fs::remove_file(self.tmp.with_extension("meta"));
        }
        ok
    }
}

impl Drop for CacheWriter {
    /// An abandoned write leaves no temporary file behind. A build that hangs up mid-download is
    /// ordinary, and a `tmp` directory that grows by one file per abandoned fetch is a disk leak
    /// nobody would look for.
    fn drop(&mut self) {
        if self.file.is_some() {
            let _ = std::fs::remove_file(&self.tmp);
        }
    }
}

/// Enough randomness to name a temporary file, without a dependency for it.
///
/// Collisions cost one abandoned write, not a corrupt entry: every name also carries the process
/// id, and the rename into place is by content key rather than by this.
fn fastrand_u64() -> u64 {
    use std::hash::{BuildHasher as _, RandomState};
    RandomState::new().hash_one(std::time::Instant::now().elapsed().as_nanos() as u64)
}

/// The host a URL names, for the counters. A copy of `trigon_politeness::host_of` would be a second
/// thing to keep in step, so this is that function.
fn host_of(url: &str) -> String {
    trigon_politeness::host_of(url)
}

/// Unix seconds now, which is the only clock this crate needs.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache(name: &str, scope: &str) -> (Cache, PathBuf) {
        let root = std::env::temp_dir()
            .join(format!("trigon-cache-{}", std::process::id()))
            .join(name);
        let _ = std::fs::remove_dir_all(&root);
        (Cache::open(root.clone(), scope.to_string()).unwrap(), root)
    }

    #[test]
    fn a_body_round_trips_and_carries_when_it_was_fetched() {
        let (c, _) = cache("round-trip", "sweep-1");
        c.put(
            Tier::Bytes,
            "https://r/x.tgz",
            b"payload",
            "application/gzip",
            1_700_000_000,
        )
        .unwrap();
        let e = c.get(Tier::Bytes, "https://r/x.tgz").expect("a hit");
        assert_eq!(e.body, b"payload");
        assert_eq!(e.content_type, "application/gzip");
        assert_eq!(e.fetched_at, 1_700_000_000);
        assert_eq!(c.stats().hits, 1);
    }

    #[test]
    fn a_body_that_is_not_what_was_written_is_a_miss_and_not_a_warning() {
        // The failure this design is arranged around. A partially written entry served as whole is
        // `trigon/client-corrupted-download`, which presented as a broken mirror for months across
        // three investigations. A cache that logged this and served the bytes anyway would be a
        // new source of exactly that bug.
        let (c, _) = cache("corrupt", "sweep-1");
        c.put(
            Tier::Bytes,
            "https://r/y.tgz",
            b"good bytes",
            "application/gzip",
            1,
        )
        .unwrap();
        let path = c.key(Tier::Bytes, "https://r/y.tgz");
        std::fs::write(&path, b"different!").unwrap();

        assert!(
            c.get(Tier::Bytes, "https://r/y.tgz").is_none(),
            "served corruption"
        );
        let s = c.stats();
        assert_eq!((s.rejected, s.hits), (1, 0));
        // And it is gone, so the next run does not pay the check again.
        assert!(!path.exists());
    }

    #[test]
    fn a_body_with_no_meta_is_absent_rather_than_unverifiable() {
        // `put` renames the body first, so an interrupted write leaves exactly this. Treating it as
        // an entry we cannot check would be a decision; treating it as absent is a fetch.
        let (c, _) = cache("no-meta", "sweep-1");
        c.put(Tier::Bytes, "https://r/z", b"bytes", "text/plain", 1)
            .unwrap();
        std::fs::remove_file(c.key(Tier::Bytes, "https://r/z").with_extension("meta")).unwrap();
        assert!(c.get(Tier::Bytes, "https://r/z").is_none());
        assert_eq!(c.stats().rejected, 0, "absent is not corrupt");
    }

    #[test]
    fn an_index_entry_belongs_to_one_invocation_and_no_other() {
        // A packument decides which versions exist. Scoping the entry to one invocation bounds
        // staleness by construction rather than by a TTL somebody picked — and it is why a
        // standalone rebuild shares nothing with the sweep that ran before it.
        let (one, root) = cache("scope", "sweep-1");
        one.put(
            Tier::Index,
            "https://r/pkg",
            b"{\"versions\":{}}",
            "application/json",
            5,
        )
        .unwrap();
        assert!(one.get(Tier::Index, "https://r/pkg").is_some());

        let two = Cache::open(root, "sweep-2".into()).unwrap();
        assert!(
            two.get(Tier::Index, "https://r/pkg").is_none(),
            "a second invocation read the first one's decision"
        );
        // The bytes tier is shared across invocations, which is the whole point of it.
        one.put(
            Tier::Bytes,
            "https://r/a.tgz",
            b"immutable",
            "application/gzip",
            5,
        )
        .unwrap();
        assert!(two.get(Tier::Bytes, "https://r/a.tgz").is_some());
    }

    #[test]
    fn the_oldest_index_read_is_what_the_run_has_to_report() {
        // "Resolved against the index as it stood at moment M" and "resolved against our copy of it
        // from day D" are different claims, and the run record must not round one into the other.
        let (c, _) = cache("oldest", "sweep-1");
        assert_eq!(
            c.stats().oldest_index_read,
            None,
            "nothing read is not fresh"
        );
        c.put(Tier::Index, "https://r/a", b"a", "application/json", 900)
            .unwrap();
        c.put(Tier::Index, "https://r/b", b"b", "application/json", 500)
            .unwrap();
        c.get(Tier::Index, "https://r/a");
        c.get(Tier::Index, "https://r/b");
        assert_eq!(c.stats().oldest_index_read, Some(500));
    }

    #[test]
    fn pruning_drops_the_oldest_first_and_stops_at_the_bound() {
        let (c, _) = cache("prune", "sweep-1");
        for (i, name) in ["old", "mid", "new"].iter().enumerate() {
            c.put(
                Tier::Bytes,
                &format!("https://r/{name}"),
                &vec![b'x'; 1000],
                "b",
                i as u64,
            )
            .unwrap();
            // Distinct mtimes, which is what the order rests on.
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let freed = c.prune(2500).unwrap();
        assert!(freed >= 1000, "freed {freed}");
        assert!(
            c.get(Tier::Bytes, "https://r/old").is_none(),
            "the oldest survived"
        );
        assert!(
            c.get(Tier::Bytes, "https://r/new").is_some(),
            "the newest was dropped"
        );
        // Under the bound, pruning does nothing at all.
        assert_eq!(c.prune(1_000_000).unwrap(), 0);
    }
}
