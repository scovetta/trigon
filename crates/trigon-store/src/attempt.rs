//! What makes two runs attempts at the same thing, and what makes the second one a confirmation.
//!
//! ADR-0010's first safeguard is two agreeing attempts before anything publishes, "on different
//! workers at different times", because the risk that dominates is ambient nondeterminism. Three
//! facts decide whether a pair of runs is that, and each is written down here, by the run that
//! knows it, for a gate that cannot find out afterwards:
//!
//! - **The question.** [`cache_key`]: the target, the strategy digest and the stabilizer-set
//!   digest. Change any of them and a second run answers a different question.
//! - **The machine.** [`host_id`]: a stable id for the host, which names no host.
//! - **What it could reuse.** [`CacheState`]: which caches could have handed the second attempt
//!   the first one's answer, and whether its base image was pulled again by digest.
//!
//! The third fact that decides it, when each attempt began, is `RunRecord::started`.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// The version of [`cache_key`]'s input. In every key, so a change to what goes into one starts
/// new keys rather than colliding with the old ones.
pub const CACHE_KEY_VERSION: &str = "ck1";

/// What makes two runs attempts at the *same thing*: the one function every cache key is built by.
///
/// The target — the package, in canonical form, and which of its files — the strategy digest and
/// the stabilizer-set digest. Change any of them and the second run is a different question, not a
/// confirmation of the first, which is what `RunRecord::cache_key` has always said and what the
/// keys actually written did not: `trigon enqueue` keyed a job on the purl alone, the worker copied
/// that onto the record, and every CLI run recorded none (`docs/17-backlog.md` B31). Two attempts
/// straddling a stabilizer-set change measurably answer different questions — thirteen members of
/// one package move from `differs` to `identical` between two sets — and shared a key.
///
/// `None` where the purl has no canonical form, rather than a key built from the spelling it was
/// typed in: two spellings of one package would be two questions, and a partial key is how a run
/// comes to look like a confirmation of another. The inputs are canonical JSON, hashed, so no
/// separator inside a name can make two different inputs one key.
pub fn cache_key(
    target: &str,
    artifact: &str,
    strategy_digest: &str,
    set_digest: &str,
) -> Option<String> {
    let purl = trigon_core::purl::canonicalize(target).ok()?;
    let input = serde_json::json!({
        "artifact": artifact,
        "purl": purl.as_str(),
        "set": set_digest,
        "strategy": strategy_digest,
    });
    let canonical = trigon_core::jcs::canonicalize(&input).ok()?;
    let digest = Sha256::digest(canonical.as_bytes());
    Some(format!("{CACHE_KEY_VERSION}:{}", hex(&digest)))
}

/// What an attempt could have taken from an earlier one, and whether its base image was pulled
/// again.
///
/// **Which caches were allowed to supply it, not which did.** A layer cache that was consulted and
/// missed, and one that was not consulted, leave the same bytes behind, and only the second can be
/// stated as a fact by the run. So a cache is listed wherever the attempt let it answer, and an
/// empty list is a cold attempt: every build input was fetched or built again for it.
///
/// Recorded on every run, not only a confirming one, because the gate has to be able to tell a
/// warm second attempt from a cold one, and "not recorded" must not read as either.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheState {
    /// Every cache this attempt let supply something, by name: [`CacheState::LAYERS`],
    /// [`CacheState::FETCH`], [`CacheState::SOURCES`], [`CacheState::DERIVED_IMAGE`].
    ///
    /// **Written even when empty.** Empty is the claim that the attempt was cold, and a missing key
    /// would read as a record from before the field existed.
    #[serde(default)]
    pub warm: Vec<String>,
    /// Whether the base image was taken out of this machine's image store and pulled again from
    /// its registry, by digest, before the build. `false` where it was used as the store held it,
    /// which includes every image that exists only on this machine and has no registry to be
    /// pulled from.
    #[serde(default)]
    pub image_repulled: bool,
}

impl CacheState {
    /// Podman's build-layer cache. Two builds of one strategy share layers — and the file
    /// timestamps baked into them — unless the second builds with `--no-cache`, so a warm second
    /// build can be the first one replayed.
    pub const LAYERS: &'static str = "build-layers";
    /// The mirror's fetch cache (`--cache`, ADR-0013): upstream bytes served from disk rather than
    /// fetched for this attempt.
    pub const FETCH: &'static str = "fetch";
    /// A source checkout the build copied rather than fetched for this attempt: the source cache,
    /// or an operator's `--source`.
    pub const SOURCES: &'static str = "sources";
    /// A base image an earlier run derived and this one reused (`DerivedImage::built_here` false).
    pub const DERIVED_IMAGE: &'static str = "derived-image";

    /// Whether no cache was allowed to supply anything.
    pub fn cold(&self) -> bool {
        self.warm.is_empty()
    }

    /// What same-host confirmation asks of the confirming attempt (`docs/19` D8): an empty build
    /// cache, and the base image re-pulled by digest.
    pub fn independent(&self) -> bool {
        self.cold() && self.image_repulled
    }
}

/// The application key the host id is derived under.
///
/// `machine-id(5)` asks that an application needing a stable id derive it with a keyed hash under
/// a fixed, application-specific key, and never expose the machine id itself: it is the machine's
/// identity, and it is also what other software keys its own secrets on.
const HOST_KEY: &[u8] = b"trigon host id v1";

/// The prefix of a host id derived from a machine id, the only kind that tells two machines apart.
const FROM_MACHINE_ID: &str = "machine-id:";

/// A stable id for this machine that names no machine, or `None` where there is nothing to derive
/// one from.
///
/// HMAC-SHA256 of the machine id under a key of Trigon's own — `/etc/machine-id`, or D-Bus's
/// `/var/lib/dbus/machine-id` on a system without systemd, which is the same value where both
/// exist — or, on a machine with neither, of its hostname. **Never the hostname itself**: a
/// hostname is often a person's name. The prefix says which it was derived from, because the two
/// are not equally private — a machine id is 128 random bits and its hash reveals nothing, while a
/// hostname is guessable and its hash can be checked against a guess, which is why `trigon serve
/// --public` shows no reader the id at all — and not equally good at telling machines apart
/// ([`names_a_machine`]).
pub fn host_id() -> Option<String> {
    let read = |p: &str| std::fs::read_to_string(p).ok();
    host_id_from(
        read("/etc/machine-id")
            .filter(|m| !m.trim().is_empty())
            .or_else(|| read("/var/lib/dbus/machine-id"))
            .as_deref(),
        read("/proc/sys/kernel/hostname")
            .or_else(|| read("/etc/hostname"))
            .as_deref(),
    )
}

/// Whether two runs with different host ids, one of them this, can be taken to have run on two
/// machines.
///
/// Only where both ids were derived from machine ids. A machine id is written once, when a system
/// is installed, and podman and Docker give a container none of its own. They give every container
/// a hostname, so two workers in two containers on one machine — which share its kernel, its CPU
/// and, as often as not, its image store — have two hostnames, and a run on the machine beside a
/// run in a container on it has one id of each kind. Two ids that differ where either came from a
/// hostname are not shown to be two machines, and the gate holds such a pair to what it asks of
/// one.
pub fn names_a_machine(host: &str) -> bool {
    host.starts_with(FROM_MACHINE_ID)
}

/// [`host_id`] over values rather than files, so the derivation is testable.
pub fn host_id_from(machine_id: Option<&str>, hostname: Option<&str>) -> Option<String> {
    fn usable(s: Option<&str>) -> Option<&str> {
        s.map(str::trim).filter(|s| !s.is_empty())
    }
    if let Some(m) = usable(machine_id) {
        return Some(format!(
            "{FROM_MACHINE_ID}{}",
            hex(&hmac_sha256(HOST_KEY, m.as_bytes()))
        ));
    }
    usable(hostname).map(|h| format!("hostname:{}", hex(&hmac_sha256(HOST_KEY, h.as_bytes()))))
}

/// RFC 2104 over SHA-256. Written out rather than taken from a crate: it is eight lines over the
/// `sha2` this crate already links, and RFC 4231's vectors pin it below.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let (mut ipad, mut opad) = ([0x36u8; BLOCK], [0x5cu8; BLOCK]);
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let inner = Sha256::new()
        .chain_update(ipad)
        .chain_update(message)
        .finalize();
    Sha256::new()
        .chain_update(opad)
        .chain_update(inner)
        .finalize()
        .into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_rfc_4231() {
        // Test case 2: a short key, and the case most implementations get wrong first.
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // Test case 6: a key longer than the block, which is hashed first.
        assert_eq!(
            hex(&hmac_sha256(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn the_host_id_names_no_host() {
        let id = host_id_from(None, Some("mikes-laptop\n")).unwrap();
        assert!(id.starts_with("hostname:"), "{id}");
        assert!(!id.contains("mikes-laptop"), "{id}");
        // Stable: the same host is the same id on every run, which is the whole use of it.
        assert_eq!(host_id_from(None, Some("mikes-laptop")), Some(id.clone()));
        assert_ne!(host_id_from(None, Some("another-host")), Some(id));
    }

    #[test]
    fn the_machine_id_wins_and_a_blank_one_is_no_machine_id() {
        let m = "0123456789abcdef0123456789abcdef";
        let id = host_id_from(Some(m), Some("h")).unwrap();
        assert!(id.starts_with("machine-id:"), "{id}");
        assert!(
            !id.contains(m),
            "the machine id itself must never be written: {id}"
        );
        assert!(
            host_id_from(Some("  \n"), Some("h"))
                .unwrap()
                .starts_with("hostname:")
        );
        assert_eq!(host_id_from(None, None), None);
        assert_eq!(host_id_from(Some(""), Some("")), None);
    }

    #[test]
    fn only_a_machine_id_tells_two_machines_apart() {
        let machine = host_id_from(Some("0123456789abcdef0123456789abcdef"), None).unwrap();
        let named = host_id_from(None, Some("worker-7f9c")).unwrap();
        assert!(names_a_machine(&machine), "{machine}");
        // A container's hostname is its own, on whichever machine it runs.
        assert!(!names_a_machine(&named), "{named}");
    }

    #[test]
    fn a_key_is_a_function_of_every_part_of_the_question_and_of_nothing_else() {
        let base = cache_key("pkg:npm/left-pad@1.3.0", "left-pad-1.3.0.tgz", "s1", "set1").unwrap();
        assert!(base.starts_with("ck1:"), "{base}");
        // Two spellings of one package are one question.
        assert_eq!(
            cache_key("pkg:NPM/Left-Pad@1.3.0", "left-pad-1.3.0.tgz", "s1", "set1").as_ref(),
            Some(&base)
        );
        for (what, other) in [
            (
                "the version",
                cache_key("pkg:npm/left-pad@1.3.1", "left-pad-1.3.0.tgz", "s1", "set1"),
            ),
            (
                "the artifact",
                cache_key("pkg:npm/left-pad@1.3.0", "other.tgz", "s1", "set1"),
            ),
            (
                "the strategy",
                cache_key("pkg:npm/left-pad@1.3.0", "left-pad-1.3.0.tgz", "s2", "set1"),
            ),
            (
                "the stabilizer set",
                cache_key("pkg:npm/left-pad@1.3.0", "left-pad-1.3.0.tgz", "s1", "set2"),
            ),
        ] {
            assert_ne!(other.as_ref(), Some(&base), "{what} is not in the key");
        }
        // A target with no canonical form has no key, rather than one built from its spelling.
        assert_eq!(cache_key("left-pad 1.3.0", "a.tgz", "s1", "set1"), None);
    }

    #[test]
    fn a_cold_attempt_is_one_nothing_could_supply() {
        let cold = CacheState {
            warm: Vec::new(),
            image_repulled: true,
        };
        assert!(cold.cold() && cold.independent());
        let not_pulled = CacheState {
            image_repulled: false,
            ..cold.clone()
        };
        assert!(not_pulled.cold() && !not_pulled.independent());
        let warm = CacheState {
            warm: vec![CacheState::LAYERS.into()],
            ..cold
        };
        assert!(!warm.cold() && !warm.independent());
        // An empty list is written, because it is the claim.
        assert_eq!(
            serde_json::to_value(CacheState::default()).unwrap(),
            serde_json::json!({ "warm": [], "image_repulled": false })
        );
    }
}
