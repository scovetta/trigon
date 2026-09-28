//! What a registry declares an artifact's bytes hash to, and what came of checking it.
//!
//! Every registry publishes a digest of some kind beside each download, and none of them agree on
//! which: npm a sha512 `integrity` string and a sha1 `shasum`, PyPI sha256, md5 and blake2b_256,
//! crates.io a sha256 `checksum`, NuGet a sha512 `packageHash` in its catalog for the entries that
//! carry one. A fetcher that reads only the one it expects verifies nothing wherever the registry
//! publishes a different one, and says nothing about it — which is how every npm download went
//! unchecked while the code read as though it checked them (`docs/19` §5).
//!
//! So a declaration is kept as the registry made it, one entry per algorithm and per field, and the
//! check is recorded beside it. **A declaration is never a subject digest.** A subject's digests
//! are computed over the bytes; what a registry declared is a claim about those bytes, which the
//! fetch either confirmed or refused.

use serde::{Deserialize, Serialize};

/// One digest a registry declared for one artifact, as it declared it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclaredDigest {
    /// The algorithm, lowercased, in the registry's own spelling where it has one: `sha512`,
    /// `sha1`, `sha256`, `sha384`, `md5`, `blake2b_256`.
    pub algorithm: String,
    /// The declared value as lowercase hex, whatever encoding the registry used. npm's integrity
    /// string and NuGet's `packageHash` are base64 on the wire; one spelling here is what lets a
    /// reader compare a declaration with a digest without knowing where it came from.
    pub value: String,
    /// Where the registry said it, as `<ecosystem>:<field>` — `npm:dist.integrity`,
    /// `npm:dist.shasum`, `pypi:digests.md5`, `cargo:checksum`, `nuget:catalog.packageHash`.
    ///
    /// Kept per entry, because two fields can declare the same algorithm: an npm entry old enough
    /// to carry a `sha1-` integrity string also carries a `shasum`, and each is a separate claim.
    pub source: String,
}

/// What checking one declaration against the fetched bytes found.
///
/// There is no mismatch: a mismatch refuses the download, so no run exists to record one on. The
/// refusal names the algorithm and both values instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckResult {
    /// The bytes hash to the declared value under this algorithm.
    Matched,
    /// The declaration was recorded and nothing was checked against it, because this build has no
    /// implementation of the algorithm. PyPI's `blake2b_256` is the one met in practice.
    ///
    /// **Not a pass.** It is here so the record says the registry declared it, rather than reading
    /// as though the registry had not.
    Unchecked,
}

/// One declaration and what came of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestCheck {
    #[serde(flatten)]
    pub declared: DeclaredDigest,
    pub result: CheckResult,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_check_reads_as_one_flat_object() {
        // Flat, so a reader of a run file sees `algorithm`, `value`, `source` and `result` side by
        // side rather than a nested object whose name says nothing a reader needs.
        let c = DigestCheck {
            declared: DeclaredDigest {
                algorithm: "sha1".into(),
                value: "5b8a3a7765dfe001261dde915589e782f8c94d1e".into(),
                source: "npm:dist.shasum".into(),
            },
            result: CheckResult::Matched,
        };
        let v = serde_json::to_value(&c).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "algorithm": "sha1",
                "value": "5b8a3a7765dfe001261dde915589e782f8c94d1e",
                "source": "npm:dist.shasum",
                "result": "matched",
            })
        );
        assert_eq!(serde_json::from_value::<DigestCheck>(v).unwrap(), c);
    }
}
