//! Checking fetched bytes against every digest the registry declared for them.
//!
//! **The rule every fetcher keeps** (`docs/19` §5): decode what the ecosystem declares, verify the
//! download against every declared digest this build can compute, refuse it on any mismatch, and
//! record what was declared and what came of it — including that nothing was, where nothing was.
//! Each fetcher only has to say what its registry declared, as [`DeclaredDigest`]s; the hashing,
//! the comparison and the refusal are here, once.
//!
//! This used to be a single optional sha256. npm declares sha512 and sha1 and never sha256, so
//! every npm download was checked against nothing while the code read as though it checked; PyPI's
//! md5 and NuGet's sha512 `packageHash` were never read at all.
//!
//! A declaration is never a subject digest. What a signed statement names is computed over the
//! bytes (`trigon_attest::Subject::of_bytes`); what is decided here is only whether the registry
//! vouches for them.

use sha2::{Digest as _, Sha256, Sha384, Sha512};
use trigon_core::{CheckResult, DeclaredDigest, Digest, DigestCheck};

use crate::client::Client;
use crate::error::{DigestMismatch, RegistryError};
use crate::model::{ArtifactMeta, BlobSink, Fetched};

/// Stream an artifact, hashing as it goes, and check it against everything the registry declared.
pub(crate) async fn fetch_verified(
    client: &Client,
    ecosystem: &str,
    meta: &ArtifactMeta,
    sink: &mut (dyn BlobSink + Send),
) -> Result<Fetched, RegistryError> {
    let mut response = client.get(&meta.url, ecosystem).await?;
    let mut hashers = Hashers::for_declared(&meta.declared);
    let mut bytes = 0u64;

    // Streamed rather than buffered: an artifact can be gigabytes, and a worker that holds one in
    // memory to hash it has a memory profile indistinguishable from a build failure.
    while let Some(chunk) = response.chunk().await? {
        hashers.update(&chunk);
        sink.write(&chunk)?;
        bytes += chunk.len() as u64;
    }
    let computed = hashers.finish();
    let fetched = verify(ecosystem, meta, computed, bytes)?;
    tracing::debug!(
        artifact = %meta.id,
        bytes,
        sha256 = %fetched.sha256,
        declared = meta.declared.len(),
        "fetched"
    );
    Ok(fetched)
}

/// What the bytes hashed to, under every algorithm this fetch computed.
pub(crate) struct Computed {
    sha256: [u8; 32],
    sha512: [u8; 64],
    sha1: [u8; 20],
    sha384: Option<[u8; 48]>,
    md5: Option<[u8; 16]>,
}

impl Computed {
    /// The digest under `algorithm`, as lowercase hex, or `None` for one this build cannot compute.
    fn hex(&self, algorithm: &str) -> Option<String> {
        Some(match algorithm {
            "sha256" => hex(&self.sha256),
            "sha512" => hex(&self.sha512),
            "sha1" => hex(&self.sha1),
            "sha384" => hex(self.sha384.as_ref()?),
            "md5" => hex(self.md5.as_ref()?),
            _ => return None,
        })
    }

    /// Every digest of these bytes, from a buffer already in memory.
    #[cfg(test)]
    fn of(bytes: &[u8]) -> Self {
        let mut h = Hashers::all();
        h.update(bytes);
        h.finish()
    }
}

/// One hasher per algorithm the fetch has a use for.
///
/// sha256, sha512 and sha1 always: sha256 is what the store addresses bytes by, and sha512 and sha1
/// are what a statement's subject carries, so every fetch computes them whether or not anything was
/// declared. sha384 and md5 only when a declaration needs one.
struct Hashers {
    sha256: Sha256,
    sha512: Sha512,
    sha1: sha1::Sha1,
    sha384: Option<Sha384>,
    md5: Option<md5::Md5>,
}

impl Hashers {
    fn for_declared(declared: &[DeclaredDigest]) -> Self {
        let wants = |a: &str| declared.iter().any(|d| d.algorithm == a);
        Hashers {
            sha256: Sha256::new(),
            sha512: Sha512::new(),
            sha1: sha1::Sha1::new(),
            sha384: wants("sha384").then(Sha384::new),
            md5: wants("md5").then(md5::Md5::new),
        }
    }

    #[cfg(test)]
    fn all() -> Self {
        Hashers {
            sha384: Some(Sha384::new()),
            md5: Some(md5::Md5::new()),
            ..Self::for_declared(&[])
        }
    }

    fn update(&mut self, chunk: &[u8]) {
        self.sha256.update(chunk);
        self.sha512.update(chunk);
        self.sha1.update(chunk);
        if let Some(h) = &mut self.sha384 {
            h.update(chunk);
        }
        if let Some(h) = &mut self.md5 {
            h.update(chunk);
        }
    }

    fn finish(self) -> Computed {
        Computed {
            sha256: self.sha256.finalize().into(),
            sha512: self.sha512.finalize().into(),
            sha1: self.sha1.finalize().into(),
            sha384: self.sha384.map(|h| h.finalize().into()),
            md5: self.md5.map(|h| h.finalize().into()),
        }
    }
}

/// Check every declaration against what the bytes hashed to.
///
/// **Every declaration must hold, not the strongest.** Subresource Integrity lets a resource pass
/// on any one digest of its strongest algorithm, which suits a CDN serving one of several builds; a
/// registry vouches for exactly one artifact, and two declarations that cannot both hold mean the
/// metadata is wrong or the bytes are, and either way the run would prove nothing. So the first
/// declaration that does not hold refuses the download, and names itself.
pub(crate) fn verify(
    ecosystem: &str,
    meta: &ArtifactMeta,
    computed: Computed,
    bytes: u64,
) -> Result<Fetched, RegistryError> {
    let mut checks = Vec::with_capacity(meta.declared.len());
    let mut unchecked = Vec::new();
    for d in &meta.declared {
        let result = match computed.hex(&d.algorithm) {
            Some(actual) if actual == d.value => CheckResult::Matched,
            Some(actual) => {
                return Err(RegistryError::DigestMismatch(Box::new(DigestMismatch {
                    ecosystem: ecosystem.to_string(),
                    artifact: meta.id.to_string(),
                    algorithm: d.algorithm.clone(),
                    field: d.source.clone(),
                    declared: d.value.clone(),
                    computed: actual,
                })));
            }
            None => {
                unchecked.push(format!("{} (`{}`)", d.algorithm, d.source));
                CheckResult::Unchecked
            }
        };
        checks.push(DigestCheck {
            declared: d.clone(),
            result,
        });
    }

    // Absence is recorded as absence: an empty list and a sentence saying why, never a zero and
    // never a silence a reader could take for a check that passed. That includes declarations that
    // were all of algorithms this build cannot compute: the list is not empty, and nothing in it
    // was checked, so the note has to say so rather than that the registry "also" declared them.
    let matched = checks.iter().any(|c| c.result == CheckResult::Matched);
    let note = if checks.is_empty() {
        Some(meta.declared_note.clone().unwrap_or_else(|| {
            format!(
                "{ecosystem} declared no digest for {}, so the bytes were hashed and checked \
                 against nothing",
                meta.id
            )
        }))
    } else if !matched {
        Some(format!(
            "{ecosystem} declared only {} for {}, which this build cannot compute, so the bytes \
             were hashed and checked against nothing",
            unchecked.join(" and "),
            meta.id
        ))
    } else if !unchecked.is_empty() {
        Some(format!(
            "{ecosystem} also declared {}, which this build cannot compute, so {} recorded and \
             not checked",
            unchecked.join(" and "),
            if unchecked.len() == 1 {
                "it is"
            } else {
                "they are"
            }
        ))
    } else {
        None
    };

    Ok(Fetched {
        sha256: Digest::from_bytes(computed.sha256),
        sha512: trigon_core::Sha512(computed.sha512),
        sha1: trigon_core::Sha1(computed.sha1),
        bytes,
        checks,
        note,
    })
}

/// How many bytes a digest under `algorithm` is, where this crate knows.
fn width(algorithm: &str) -> Option<usize> {
    Some(match algorithm {
        "md5" => 16,
        "sha1" => 20,
        "sha256" | "blake2b_256" => 32,
        "sha384" => 48,
        "sha512" => 64,
        _ => return None,
    })
}

/// A declaration from a registry that writes digests as hex, checked for shape.
///
/// A declaration that is not a digest is refused rather than dropped. Dropping it is how a
/// malformed checksum became a download checked against nothing, which reads the same as a
/// download the registry declared nothing for.
pub(crate) fn from_hex(
    algorithm: &str,
    value: &str,
    source: &str,
) -> Result<DeclaredDigest, String> {
    let algorithm = algorithm.to_ascii_lowercase();
    let value = value.trim().to_ascii_lowercase();
    let is_hex = !value.is_empty() && value.bytes().all(|b| b.is_ascii_hexdigit());
    let fits = width(&algorithm).is_none_or(|w| value.len() == 2 * w);
    if !is_hex || value.len() % 2 != 0 || !fits {
        return Err(format!(
            "`{source}` declares {algorithm} `{value}`, which is not a {algorithm} digest"
        ));
    }
    Ok(DeclaredDigest {
        algorithm,
        value,
        source: source.to_string(),
    })
}

/// A declaration from a registry that writes digests as base64, checked for shape.
pub(crate) fn from_base64(
    algorithm: &str,
    value: &str,
    source: &str,
) -> Result<DeclaredDigest, String> {
    let algorithm = algorithm.to_ascii_lowercase();
    let decoded = base64_decode(value.trim())
        .filter(|b| !b.is_empty())
        .filter(|b| width(&algorithm).is_none_or(|w| b.len() == w))
        .ok_or_else(|| {
            format!("`{source}` declares {algorithm} `{value}`, which is not a {algorithm} digest")
        })?;
    Ok(DeclaredDigest {
        algorithm,
        value: hex(&decoded),
        source: source.to_string(),
    })
}

/// Every digest in a Subresource Integrity string: whitespace-separated `<alg>-<base64>` tokens,
/// each optionally followed by `?<options>`.
///
/// npm writes one `sha512-` token today, and `sha1-` for entries published before it moved to
/// sha512. More than one token is legal, and each one is kept.
pub(crate) fn sri(integrity: &str, source: &str) -> Result<Vec<DeclaredDigest>, String> {
    let mut out = Vec::new();
    for token in integrity.split_whitespace() {
        let token = token.split('?').next().unwrap_or(token);
        let Some((algorithm, b64)) = token.split_once('-') else {
            return Err(format!(
                "`{source}` holds `{token}`, which is not an `<algorithm>-<base64>` digest"
            ));
        };
        out.push(from_base64(algorithm, b64, source)?);
    }
    if out.is_empty() {
        return Err(format!("`{source}` is present and empty"));
    }
    Ok(out)
}

/// Enough base64 to read a digest. Standard alphabet, padding optional, and nothing else.
///
/// Strict where the old decoder in `npm.rs` was lenient: a character outside the alphabet, or
/// padding in the middle, refuses the whole value rather than being skipped.
pub(crate) fn base64_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let body = s.trim_end_matches('=');
    if s.len() - body.len() > 2 || body.contains('=') {
        return None;
    }
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in body.bytes() {
        let v = ALPHABET.iter().position(|a| *a == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use trigon_core::ArtifactId;

    fn meta(declared: Vec<DeclaredDigest>) -> ArtifactMeta {
        ArtifactMeta {
            id: ArtifactId::new("left-pad-1.3.0.tgz"),
            url: "https://registry.invalid/left-pad-1.3.0.tgz".into(),
            declared,
            declared_note: None,
            size: None,
        }
    }

    #[test]
    fn an_npm_integrity_string_decodes_to_the_digest_it_names() {
        // left-pad 1.3.0's real `dist.integrity`, whose tarball's sha512 is known: the value
        // stored is hex, so it compares with a computed digest without knowing it was base64.
        const INTEGRITY: &str = concat!(
            "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy",
            "/aVx2HrNcqQGsdot8ghrjyrvMCoEA=="
        );
        let d = sri(INTEGRITY, "npm:dist.integrity").unwrap();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].algorithm, "sha512");
        assert_eq!(
            d[0].value,
            "5c8e4c3f354d0298c0ca1433a615fc06498ab0a5310f82ddc8adb88997901a29\
             c137dc93413ddb165081cbf695c761eb35ca901ac768b7c821ae3cabbcc0a810"
        );
        assert_eq!(d[0].source, "npm:dist.integrity");
    }

    #[test]
    fn every_token_of_an_integrity_string_is_kept_and_options_are_ignored() {
        let sha1 = "sha1-W4o6d2Xf4AEmHd6RVYnngvjJTR4=";
        let d = sri(
            &format!("{sha1}?opt  sha384-{}", "A".repeat(64)),
            "npm:dist.integrity",
        )
        .unwrap();
        assert_eq!(
            d.iter().map(|d| d.algorithm.as_str()).collect::<Vec<_>>(),
            ["sha1", "sha384"]
        );
        assert_eq!(d[0].value, "5b8a3a7765dfe001261dde915589e782f8c94d1e");
    }

    #[test]
    fn a_declaration_that_is_not_a_digest_is_refused_rather_than_dropped() {
        // Dropping it is how a download came to be checked against nothing while reading as
        // though it had been checked.
        for bad in [
            "sha512-",
            "sha512-not*base64",
            "sha512-AAAA",
            "nodash",
            "sha512-AA=A",
        ] {
            assert!(sri(bad, "npm:dist.integrity").is_err(), "{bad}");
        }
        assert!(from_hex("sha1", "5b8a3a77", "npm:dist.shasum").is_err());
        assert!(from_hex("sha256", &"zz".repeat(32), "cargo:checksum").is_err());
        assert!(from_hex("md5", &"ab".repeat(16), "pypi:digests.md5").is_ok());
    }

    #[test]
    fn every_declared_digest_is_checked_and_a_mismatch_names_both_values() {
        let bytes = b"the published bytes";
        let c = Computed::of(bytes);
        let sha1 = c.hex("sha1").unwrap();
        let md5 = c.hex("md5").unwrap();
        let declared = vec![
            from_hex("sha1", &sha1, "npm:dist.shasum").unwrap(),
            from_hex("md5", &md5, "pypi:digests.md5").unwrap(),
        ];
        let ok = verify("npm", &meta(declared.clone()), Computed::of(bytes), 19).unwrap();
        assert!(ok.checks.iter().all(|c| c.result == CheckResult::Matched));
        assert_eq!(ok.note, None);

        // The second declaration disagrees. Agreeing on the first is not a pass.
        let mut wrong = declared;
        wrong[1].value = "00".repeat(16);
        let e = verify("pypi", &meta(wrong), Computed::of(bytes), 19).unwrap_err();
        let msg = e.to_string();
        assert!(msg.contains("md5"), "{msg}");
        assert!(msg.contains(&"00".repeat(16)), "the declared value: {msg}");
        assert!(msg.contains(&md5), "the computed value: {msg}");
        assert!(msg.contains("proves nothing"), "{msg}");
        assert!(!trigon_core::Classify::is_retryable(&e));
    }

    #[test]
    fn nothing_declared_is_recorded_as_absence_with_a_reason() {
        let f = verify("nuget", &meta(Vec::new()), Computed::of(b"x"), 1).unwrap();
        assert!(f.checks.is_empty());
        assert!(f.note.unwrap().contains("declared no digest"));

        // And the resolver's own reason wins where it had one.
        let mut m = meta(Vec::new());
        m.declared_note = Some("the catalog carries no packageHash for this version".into());
        let f = verify("nuget", &m, Computed::of(b"x"), 1).unwrap();
        assert_eq!(
            f.note.as_deref(),
            Some("the catalog carries no packageHash for this version")
        );
    }

    #[test]
    fn declarations_this_build_cannot_compute_alone_say_that_nothing_was_checked() {
        // A PyPI file whose `digests` carries only blake2b_256. Accepted, because nothing declared
        // can be refused, and never recorded as though another declaration had been checked.
        let declared =
            vec![from_hex("blake2b_256", &"ab".repeat(32), "pypi:digests.blake2b_256").unwrap()];
        let f = verify("pypi", &meta(declared), Computed::of(b"x"), 1).unwrap();
        assert_eq!(f.checks[0].result, CheckResult::Unchecked);
        let note = f.note.expect("an unchecked download says so");
        assert!(note.contains("checked against nothing"), "{note}");
        assert!(note.contains("blake2b_256"), "{note}");
        assert!(!note.contains("also"), "{note}");
    }

    /// Hashed the way a fetch hashes: only what the declarations ask for beyond the three every
    /// fetch computes. `Computed::of` computes everything, so it cannot catch a hasher that
    /// `for_declared` forgot to make.
    fn fetched(declared: &[DeclaredDigest], bytes: &[u8]) -> Computed {
        let mut h = Hashers::for_declared(declared);
        h.update(bytes);
        h.finish()
    }

    #[test]
    fn a_declared_sha384_is_computed_and_checked_not_left_unchecked() {
        // pip's `--hash=sha384:`, and an SRI string may carry one beside npm's sha512. If the
        // fetch did not make a sha384 hasher for it, the declaration would come back `unchecked`
        // and the download would pass, which is the silent failure this pins.
        let bytes = b"the published bytes";
        let all = Computed::of(bytes);
        let sha384 = all.hex("sha384").unwrap();
        let declared = vec![
            from_hex("sha512", &all.hex("sha512").unwrap(), "npm:dist.integrity").unwrap(),
            from_hex("sha384", &sha384, "npm:dist.integrity").unwrap(),
        ];
        let ok = verify(
            "npm",
            &meta(declared.clone()),
            fetched(&declared, bytes),
            19,
        )
        .unwrap();
        assert_eq!(
            ok.checks.iter().map(|c| c.result).collect::<Vec<_>>(),
            [CheckResult::Matched, CheckResult::Matched]
        );

        let mut wrong = declared;
        wrong[1].value = "00".repeat(48);
        let e = verify("npm", &meta(wrong.clone()), fetched(&wrong, bytes), 19).unwrap_err();
        let RegistryError::DigestMismatch(m) = &e else {
            panic!("not a mismatch: {e}");
        };
        assert_eq!(m.algorithm, "sha384");
        assert_eq!(m.computed, sha384);

        // md5 is made on demand the same way.
        let md5 = vec![from_hex("md5", &all.hex("md5").unwrap(), "pypi:digests.md5").unwrap()];
        let f = verify("pypi", &meta(md5.clone()), fetched(&md5, bytes), 19).unwrap();
        assert_eq!(f.checks[0].result, CheckResult::Matched);
    }

    #[test]
    fn a_declaration_this_build_cannot_compute_is_recorded_unchecked_not_passed() {
        let c = Computed::of(b"x");
        let declared = vec![
            from_hex("sha256", &c.hex("sha256").unwrap(), "pypi:digests.sha256").unwrap(),
            from_hex("blake2b_256", &"ab".repeat(32), "pypi:digests.blake2b_256").unwrap(),
        ];
        let f = verify("pypi", &meta(declared), Computed::of(b"x"), 1).unwrap();
        assert_eq!(f.checks[0].result, CheckResult::Matched);
        assert_eq!(f.checks[1].result, CheckResult::Unchecked);
        assert!(f.note.unwrap().contains("blake2b_256"));
    }

    #[test]
    fn several_declarations_left_unchecked_are_each_named_in_the_note() {
        // A checked sha256 beside two algorithms this build has no hasher for. Both are named, and
        // the sentence agrees with its subject: a reader counting what was not checked must be
        // able to count it from the note.
        let c = Computed::of(b"x");
        let declared = vec![
            from_hex("sha256", &c.hex("sha256").unwrap(), "pypi:digests.sha256").unwrap(),
            from_hex("blake2b_256", &"ab".repeat(32), "pypi:digests.blake2b_256").unwrap(),
            from_hex("sha3_256", &"cd".repeat(32), "pypi:digests.sha3_256").unwrap(),
        ];
        let f = verify("pypi", &meta(declared), Computed::of(b"x"), 1).unwrap();
        assert_eq!(
            f.checks.iter().map(|c| c.result).collect::<Vec<_>>(),
            [
                CheckResult::Matched,
                CheckResult::Unchecked,
                CheckResult::Unchecked
            ]
        );
        let note = f.note.expect("what was not checked is said");
        assert!(note.contains("blake2b_256"), "{note}");
        assert!(note.contains("sha3_256"), "{note}");
        assert!(note.contains("they are recorded and not checked"), "{note}");
    }

    #[test]
    fn an_integrity_string_that_is_only_whitespace_is_refused_as_empty() {
        // Present and empty is not "declared nothing": the field was written, and whatever wrote
        // it meant something by it. Recording it as absence is how a check disappears.
        for blank in ["", "   ", "\t\n"] {
            let e = sri(blank, "npm:dist.integrity").unwrap_err();
            assert!(e.contains("present and empty"), "{blank:?}: {e}");
        }
    }

    #[test]
    fn an_algorithm_whose_width_is_unknown_is_checked_only_for_being_hex() {
        // Shape-checking by width needs to know the width. For an algorithm this crate has never
        // heard of the value is still refused when it is not hex, and kept, lowercased, when it
        // is: it is recorded unchecked rather than dropped.
        let d = from_hex("SHA3_256", " ABCD ", "pypi:digests.sha3_256").unwrap();
        assert_eq!(d.algorithm, "sha3_256");
        assert_eq!(d.value, "abcd");
        assert!(from_hex("sha3_256", "abc", "pypi:digests.sha3_256").is_err());
        assert!(from_hex("sha3_256", "wxyz", "pypi:digests.sha3_256").is_err());
        assert!(from_hex("sha3_256", "", "pypi:digests.sha3_256").is_err());
        assert!(from_base64("sha3_256", "", "x").is_err());
    }

    #[test]
    fn a_digest_of_the_wrong_width_for_its_algorithm_is_refused() {
        // A byte short or a byte over is not a digest of that algorithm, and a declaration that is
        // not one is refused rather than checked against bytes it can never match or recorded.
        for (algorithm, width) in [
            ("md5", 16),
            ("sha1", 20),
            ("sha256", 32),
            ("blake2b_256", 32),
            ("sha384", 48),
            ("sha512", 64),
        ] {
            assert!(
                from_hex(algorithm, &"ab".repeat(width), "x").is_ok(),
                "{algorithm}"
            );
            for wrong in [width - 1, width + 1] {
                assert!(
                    from_hex(algorithm, &"ab".repeat(wrong), "x").is_err(),
                    "{algorithm} of {wrong} bytes"
                );
            }
        }
    }

    #[test]
    fn base64_with_more_padding_than_a_value_can_have_is_refused() {
        // Padding is optional, and there is never more than two of it: a third `=` is not padding,
        // and a value carrying it is not a digest this reads.
        assert_eq!(base64_decode("AAAA"), Some(vec![0, 0, 0]));
        assert_eq!(base64_decode("AAA="), Some(vec![0, 0]));
        assert_eq!(base64_decode("AA=="), Some(vec![0]));
        assert_eq!(base64_decode("AA"), Some(vec![0]));
        for bad in ["AA===", "AAAA===", "AAAAAA====", "==="] {
            assert_eq!(base64_decode(bad), None, "{bad}");
        }
    }
}
