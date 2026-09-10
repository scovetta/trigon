//! Named stabilizer profiles, one per artifact shape.
//!
//! `EcosystemSpec::stabilizer_profile` returns one of these ids rather than a set of stabilizers.
//! That one indirection is what severs the dependency from `trigon-core` to this crate and keeps the
//! judgement half free of anything that can perform I/O. See `docs/01-architecture.md` §3.1.

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
            ],
        ]
        .concat(),
        "raw" => vec![],
        _ => return None,
    };
    Some(StabilizerSet::new(id, members))
}

/// Every profile this build knows, for `trigon stabilizers` and for the registry.
pub fn all_profiles() -> Vec<&'static str> {
    vec![
        "tar",
        "tar-gzip",
        "zip",
        "gzip",
        "npm-tarball",
        "crate",
        "gem",
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
