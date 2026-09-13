use std::fmt;

use serde::{Deserialize, Serialize};

/// The container format of an artifact.
///
/// Recorded in the equivalence attestation, because a verifier holding an attestation and two
/// artifacts has no `EcosystemSpec` to ask. A verifier that guesses reads a `.gem` as a plain tar
/// and produces a different digest for a correct artifact. See `docs/09-attestations.md` §2.2.
/// **The serde name is the `Display` name.** `rename_all = "kebab-case"` gave `TarGz` the wire
/// spelling `tar-gz` while `Display` wrote `tar+gzip`, so one type had two names and three
/// hand-written parsers accepting different subsets of them. The attestation carries the `Display`
/// form, which is the one a verifier reads, so that is the one everything now uses.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub enum Format {
    /// tar wrapped in gzip: `.tgz`, `.tar.gz`, `.crate`.
    #[serde(rename = "tar+gzip")]
    TarGz,
    /// bare tar: `.tar`, and `.gem`, whose members are themselves gzipped.
    #[serde(rename = "tar")]
    Tar,
    /// zip: `.zip`, `.whl`, `.jar`, `.nupkg`, `.egg`.
    #[serde(rename = "zip")]
    Zip,
    /// gzip wrapping something that is not a tar.
    #[serde(rename = "gzip")]
    Gzip,
    /// Opaque bytes. Compared whole, never walked.
    #[serde(rename = "raw")]
    Raw,
}

impl Format {
    /// How many container layers this format unwraps before reaching members.
    pub const fn layers(self) -> u8 {
        match self {
            Format::TarGz => 2,
            Format::Tar | Format::Zip | Format::Gzip => 1,
            Format::Raw => 0,
        }
    }

    /// Whether a decompressed-container digest is meaningful for this format.
    ///
    /// Drives `Comparison::container_bit_identical`, which answers "same tar, different gzip
    /// framing", the most common near-miss for `.crate`, `.tgz` and `.gem`.
    pub const fn has_outer_codec(self) -> bool {
        matches!(self, Format::TarGz | Format::Gzip)
    }

    /// Format from a file name, by extension. Ambiguous cases stay `None` and the caller supplies
    /// the ecosystem: `.gem` is a tar, but only RubyGems knows that from the name alone.
    pub fn from_file_name(name: &str) -> Option<Self> {
        let lower = name.to_ascii_lowercase();
        let ends = |s: &str| lower.ends_with(s);
        if ends(".tar.gz") || ends(".tgz") || ends(".crate") {
            Some(Format::TarGz)
        } else if ends(".tar") || ends(".gem") {
            Some(Format::Tar)
        } else if ends(".zip") || ends(".whl") || ends(".jar") || ends(".nupkg") || ends(".egg") {
            Some(Format::Zip)
        } else if ends(".gz") {
            Some(Format::Gzip)
        } else {
            None
        }
    }
}

/// The one parser. `trigon`'s `resolve_format` and `trigon-attest`'s `parse_format` were two
/// hand-written tables over the same strings with different vocabularies — one took `tar.gz` and
/// `tgz`, the other took `tar-gz`, and neither took everything the other did. An alias belongs in
/// exactly one place.
impl std::str::FromStr for Format {
    type Err = UnknownFormat;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            // The canonical name, then every spelling that has ever been written down for it.
            "tar+gzip" | "tar-gz" | "tar-gzip" | "tar.gz" | "tgz" => Format::TarGz,
            "tar" => Format::Tar,
            "zip" => Format::Zip,
            "gzip" | "gz" => Format::Gzip,
            "raw" => Format::Raw,
            other => return Err(UnknownFormat(other.to_string())),
        })
    }
}

/// A format name nothing knows, carrying the name so the caller can say which.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownFormat(pub String);

impl fmt::Display for UnknownFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown format `{}`", self.0)
    }
}

impl std::error::Error for UnknownFormat {}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Format::TarGz => "tar+gzip",
            Format::Tar => "tar",
            Format::Zip => "zip",
            Format::Gzip => "gzip",
            Format::Raw => "raw",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffs_known_extensions() {
        assert_eq!(
            Format::from_file_name("left-pad-1.3.0.tgz"),
            Some(Format::TarGz)
        );
        assert_eq!(
            Format::from_file_name("syn-2.0.39.crate"),
            Some(Format::TarGz)
        );
        assert_eq!(Format::from_file_name("rails-7.1.3.gem"), Some(Format::Tar));
        assert_eq!(
            Format::from_file_name("pkg-1.0-py3-none-any.whl"),
            Some(Format::Zip)
        );
        assert_eq!(
            Format::from_file_name("Newtonsoft.Json.13.0.3.nupkg"),
            Some(Format::Zip)
        );
        assert_eq!(Format::from_file_name("mystery.bin"), None);
    }

    #[test]
    fn tar_gz_beats_gz() {
        // Order matters: ".tar.gz" must not fall through to the bare ".gz" arm.
        assert_eq!(Format::from_file_name("x.tar.gz"), Some(Format::TarGz));
        assert_eq!(Format::from_file_name("x.json.gz"), Some(Format::Gzip));
    }

    #[test]
    fn container_digest_only_where_there_is_a_codec() {
        assert!(Format::TarGz.has_outer_codec());
        assert!(!Format::Zip.has_outer_codec());
        assert!(!Format::Tar.has_outer_codec());
    }
}
