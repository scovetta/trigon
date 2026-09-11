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
}

impl GuardManifest {
    /// Build a manifest from the published artifact's bytes.
    ///
    /// Filtering narrows what triggers a `Void` and changes nothing about the comparison: a dropped
    /// member is still compared member-for-member when the verdict is decided.
    pub fn for_artifact(bytes: &[u8], format: Format, url: Option<String>) -> Self {
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
                if !guardable(&e.path, body.len() as u64) {
                    filtered_out += 1;
                    continue;
                }
                members.insert(Digest::from_bytes(Sha256::digest(&body).into()));
            }
        }

        GuardManifest {
            artifact: Some(artifact),
            refuse_url: url,
            members,
            filtered_out,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.artifact.is_none() && self.members.is_empty()
    }
}

/// Whether a member is worth guarding.
///
/// Executables are guarded whatever their size: they are what an attacker wants to smuggle, and a
/// size threshold that let a small `.so` through would exempt the only case that matters.
fn guardable(path: &EntryPath, bytes: u64) -> bool {
    if bytes == 0 {
        return false;
    }
    match ContentKind::classify(path) {
        ContentKind::Executable => true,
        _ => bytes >= MIN_GUARDED_BYTES,
    }
}

/// Why a run is `Void`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trip {
    pub url: String,
    pub matched: GuardMatch,
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
}

/// The line a trip writes.
///
/// Distinctive on purpose: the mirror usually runs in a container, and reading its log is how the
/// process that started it finds out. A verdict that depends on parsing prose would be fragile, so
/// this is a fixed prefix.
pub const TRIP_MARKER: &str = "GUARD-TRIPPED";

impl Guard {
    pub fn new(manifest: GuardManifest) -> Self {
        Guard {
            manifest,
            trips: Mutex::new(Vec::new()),
        }
    }

    pub fn is_armed(&self) -> bool {
        !self.manifest.is_empty() || self.manifest.refuse_url.is_some()
    }

    /// Whether this URL is the run's own published artifact.
    pub fn refuses(&self, url: &str) -> bool {
        self.manifest
            .refuse_url
            .as_deref()
            .is_some_and(|r| same_artifact(r, url))
    }

    pub fn record_refusal(&self, url: &str) {
        self.record(Trip {
            url: url.to_string(),
            matched: GuardMatch::RefusedUrl,
        });
    }

    /// Check a response body that has finished streaming.
    pub fn observe(&self, url: &str, body_digest: Digest, body: Option<&[u8]>) {
        if self.manifest.artifact == Some(body_digest) {
            self.record(Trip {
                url: url.to_string(),
                matched: GuardMatch::WholeArtifact,
            });
            return;
        }
        // The interesting case: not the artifact under its own name, but one of its files arriving
        // inside something unrelated.
        let Some(body) = body else { return };
        if self.manifest.members.is_empty() || body.len() > MAX_DECOMPOSE_BYTES {
            return;
        }
        let Some(format) = sniff(body) else { return };
        let mut notes = Vec::new();
        let Ok(parsed) = trigon_archive::parse(
            body.to_vec(),
            format,
            &trigon_archive::Limits::default(),
            &mut notes,
        ) else {
            return;
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
                return;
            }
        }
    }

    pub fn trips(&self) -> Vec<Trip> {
        self.trips.lock().map(|t| t.clone()).unwrap_or_default()
    }

    fn record(&self, trip: Trip) {
        tracing::error!(
            url = %trip.url,
            matched = ?trip.matched,
            "{TRIP_MARKER}: the artifact under test reached the build over the network, so this \
             run is evidence of nothing"
        );
        if let Ok(mut t) = self.trips.lock() {
            t.push(trip);
        }
    }
}

/// Whether two URLs name the same artifact.
///
/// Compared on the path's last segment rather than the whole string, because the mirror rewrites
/// artifact URLs through itself and the build never sees the upstream form it was given.
fn same_artifact(a: &str, b: &str) -> bool {
    let file = |u: &str| {
        u.split('?')
            .next()
            .unwrap_or(u)
            .rsplit('/')
            .next()
            .unwrap_or("")
            .to_string()
    };
    let (a, b) = (file(a), file(b));
    !a.is_empty() && a == b
}

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
