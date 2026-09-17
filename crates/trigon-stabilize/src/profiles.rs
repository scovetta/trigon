//! Named stabilizer profiles, one per artifact shape.
//!
//! A profile is chosen by **id** rather than by handing around a set of stabilizers, and that one
//! indirection is what severs the dependency from `trigon-core` to this crate and keeps the
//! judgement half free of anything that can perform I/O. See `docs/01-architecture.md` §3.1.
//!
//! The id is picked by `resolve_profile` in the binary, from the artifact's filename. This comment
//! used to name an `EcosystemSpec::stabilizer_profile` as the chooser; `docs/03-ecosystems.md` §7.2
//! records that no such trait was ever written. The severance is real, the mechanism named for it
//! was not.

use std::sync::Arc;

use trigon_core::Format;

use crate::passes::*;
use crate::{Stabilizer, StabilizerSet};

fn tar_set() -> Vec<Arc<dyn Stabilizer>> {
    vec![
        Arc::new(TarEntryOrder),
        Arc::new(TarTime),
        Arc::new(TarMode),
        Arc::new(TarOwners),
        Arc::new(TarXattrs),
        Arc::new(TarDevice),
    ]
}

fn zip_set() -> Vec<Arc<dyn Stabilizer>> {
    vec![
        Arc::new(ZipEntryOrder),
        Arc::new(ZipTime),
        Arc::new(ZipVersions),
        Arc::new(ZipMisc),
        Arc::new(ZipCompression),
    ]
}

fn gzip_set() -> Vec<Arc<dyn Stabilizer>> {
    vec![Arc::new(GzipMeta)]
}

/// Look up a profile by id.
pub fn profile(id: &str) -> Option<StabilizerSet> {
    let members: Vec<Arc<dyn Stabilizer>> = match id {
        "tar" => tar_set(),
        "tar-gzip" => [tar_set(), gzip_set()].concat(),
        "zip" => zip_set(),
        "gzip" => gzip_set(),
        "npm-tarball" => [
            tar_set(),
            gzip_set(),
            vec![Arc::new(NpmInstallFields) as Arc<dyn Stabilizer>],
        ]
        .concat(),
        "crate" => [
            tar_set(),
            gzip_set(),
            vec![Arc::new(CargoVcsHash) as Arc<dyn Stabilizer>],
        ]
        .concat(),
        "gem" => [
            tar_set(),
            gzip_set(),
            vec![
                Arc::new(GemExcludeChecksums) as Arc<dyn Stabilizer>,
                Arc::new(GemExcludeSignatures) as Arc<dyn Stabilizer>,
                Arc::new(GemMetadataDate) as Arc<dyn Stabilizer>,
                Arc::new(GemMetadataRubygemsVersion) as Arc<dyn Stabilizer>,
                Arc::new(GemMetadataCertChain) as Arc<dyn Stabilizer>,
            ],
        ]
        .concat(),
        // A `.nupkg` is an OPC zip. The payload compiles deterministically — Roslyn's deterministic
        // build is on by default for SDK projects, measured as byte-identical across two packs — so
        // what is left is packaging bookkeeping: the gallery's signature, a per-pack GUID in a
        // member name, and the name of the machine that packed it.
        "nupkg" => [
            // **Before the zip set.** This renames entries, and `zip-entry-order` sorts them; a
            // rename afterwards would leave the sort stale and the digest dependent on the order
            // the two spellings happened to arrive in.
            vec![Arc::new(NupkgPortableFolderName) as Arc<dyn Stabilizer>],
            zip_set(),
            vec![
                Arc::new(NupkgSignature) as Arc<dyn Stabilizer>,
                Arc::new(NupkgPackagingNames) as Arc<dyn Stabilizer>,
                Arc::new(NupkgPackagerVersion) as Arc<dyn Stabilizer>,
            ],
        ]
        .concat(),
        "wheel" => [
            zip_set(),
            vec![
                Arc::new(WheelDirectUrl) as Arc<dyn Stabilizer>,
                Arc::new(PycHeader) as Arc<dyn Stabilizer>,
                Arc::new(WheelMetadataEol) as Arc<dyn Stabilizer>,
                // Finalize: RECORD is a manifest of membership, and the passes above change it.
                Arc::new(WheelRecord) as Arc<dyn Stabilizer>,
            ],
        ]
        .concat(),
        "raw" => vec![],
        _ => return None,
    };
    Some(StabilizerSet::new(id, members))
}

/// Every profile this build knows, for `trigon stabilizers` and for the registry.
///
/// **Must list exactly what [`profile`] answers to.** `wheel` was missing, and the omission was not
/// cosmetic: the WASM parity test iterates this list to prove an archived set reproduces the
/// compiled one's digest, so the single profile PyPI uses — and the only one carrying a `Finalize`
/// pass — was the one never checked. A `stabilizers` listing and an "unknown profile" message that
/// under-report are the visible half; the unchecked parity was the half that mattered.
pub fn all_profiles() -> Vec<&'static str> {
    vec![
        "tar",
        "tar-gzip",
        "zip",
        "gzip",
        "npm-tarball",
        "crate",
        "gem",
        "wheel",
        "nupkg",
        "raw",
    ]
}

/// The profile to use when nothing more specific is known.
pub fn default_for(format: Format) -> StabilizerSet {
    let id = match format {
        Format::Tar => "tar",
        Format::TarGz => "tar-gzip",
        Format::Zip => "zip",
        Format::Gzip => "gzip",
        Format::Raw => "raw",
    };
    profile(id).expect("builtin profile")
}

#[cfg(test)]
mod profile_coverage {
    #[test]
    fn every_listed_profile_resolves_and_every_resolving_profile_is_listed() {
        // The second half is what `wheel` failed. A profile that resolves but is unlisted is
        // invisible to every consumer that enumerates, including the parity test that proves an
        // archived stabilizer set still reproduces the digest a claim was signed under.
        for id in super::all_profiles() {
            assert!(
                super::profile(id).is_some(),
                "all_profiles lists `{id}` and profile() refuses it"
            );
        }
        for id in [
            "tar",
            "tar-gzip",
            "zip",
            "gzip",
            "npm-tarball",
            "crate",
            "gem",
            "wheel",
            "raw",
        ] {
            assert!(
                super::all_profiles().contains(&id),
                "profile() answers to `{id}` and all_profiles() omits it"
            );
        }
    }
}
