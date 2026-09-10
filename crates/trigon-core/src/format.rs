use std::fmt;

use serde::{Deserialize, Serialize};

/// The container format of an artifact.
///
/// Recorded in the equivalence attestation, because a verifier holding an attestation and two
/// artifacts has no `EcosystemSpec` to ask. A verifier that guesses reads a `.gem` as a plain tar
/// and produces a different digest for a correct artifact. See `docs/09-attestations.md` §2.2.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Format {
    /// tar wrapped in gzip: `.tgz`, `.tar.gz`, `.crate`.
    TarGz,
    /// bare tar: `.tar`, and `.gem`, whose members are themselves gzipped.
    Tar,
    /// zip: `.zip`, `.whl`, `.jar`, `.nupkg`, `.egg`.
    Zip,
    /// gzip wrapping something that is not a tar.
    Gzip,
    /// Opaque bytes. Compared whole, never walked.
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
