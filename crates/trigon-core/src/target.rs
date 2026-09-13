//! Identifying a package, a version, and the artifact a run is actually about.
//!
//! The distinction matters more than it looks. A version can ship a dozen artifacts, a pure wheel
//! and eleven platform wheels, and they do not reproduce alike: one is a zip of Python files and
//! the others contain compiled extensions built on eleven different machines. A verdict about
//! "cryptography 42.0.5" is not a claim anybody can check. A verdict about
//! `cryptography-42.0.5-cp39-abi3-manylinux_2_28_x86_64.whl` is.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The registry an artifact came from.
///
/// **Every name here is written out, not derived.** `rename_all = "snake_case"` looked right and
/// was not: it renders `PyPI` as `py_p_i`, `CratesIo` as `crates_io`, `NuGet` as `nu_get` and
/// `GitHub` as `git_hub` — five of six variants under a spelling that appears nowhere else in the
/// system and that `from_purl_type` refuses. `trigon resolve --output json` printed those names.
/// The serde name is the PURL type, which is also what `Display`, `from_purl_type` and
/// `trigon-store`'s path layout use, and a test asserts the two stay equal for every variant.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub enum Ecosystem {
    #[serde(rename = "npm")]
    Npm,
    #[serde(rename = "pypi")]
    PyPI,
    #[serde(rename = "cargo")]
    CratesIo,
    #[serde(rename = "gem")]
    RubyGems,
    #[serde(rename = "nuget")]
    NuGet,
    #[serde(rename = "maven")]
    Maven,
    /// A repository rather than a registry. Its artifact is a release asset or a source archive,
    /// which is why it needs no special case anywhere else.
    #[serde(rename = "github")]
    GitHub,
}

impl Ecosystem {
    /// The `pkg:` type, as the PURL spec spells it.
    pub const fn purl_type(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::PyPI => "pypi",
            Ecosystem::CratesIo => "cargo",
            Ecosystem::RubyGems => "gem",
            Ecosystem::NuGet => "nuget",
            Ecosystem::Maven => "maven",
            Ecosystem::GitHub => "github",
        }
    }

    pub fn from_purl_type(s: &str) -> Option<Self> {
        Some(match s {
            "npm" => Ecosystem::Npm,
            "pypi" => Ecosystem::PyPI,
            "cargo" | "crates.io" => Ecosystem::CratesIo,
            "gem" | "rubygems" => Ecosystem::RubyGems,
            "nuget" => Ecosystem::NuGet,
            "maven" => Ecosystem::Maven,
            "github" => Ecosystem::GitHub,
            _ => return None,
        })
    }

    pub const fn all() -> &'static [Ecosystem] {
        &[
            Ecosystem::Npm,
            Ecosystem::PyPI,
            Ecosystem::CratesIo,
            Ecosystem::RubyGems,
            Ecosystem::NuGet,
            Ecosystem::Maven,
            Ecosystem::GitHub,
        ]
    }
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.purl_type())
    }
}

/// A package coordinate: everything but which file.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct TargetRef {
    pub ecosystem: Ecosystem,
    /// An npm scope, a maven group, a GitHub owner. `None` where the ecosystem has no such concept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    pub name: String,
    /// Held as a string. Ordering is ecosystem-specific and belongs to whatever compares versions,
    /// not to the identifier: parsing it here would mean picking one ecosystem's grammar for all
    /// of them.
    pub version: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub qualifiers: BTreeMap<String, String>,
}

impl TargetRef {
    pub fn new(ecosystem: Ecosystem, name: impl Into<String>, version: impl Into<String>) -> Self {
        TargetRef {
            ecosystem,
            namespace: None,
            name: name.into(),
            version: version.into(),
            qualifiers: BTreeMap::new(),
        }
    }

    pub fn with_namespace(mut self, ns: impl Into<String>) -> Self {
        self.namespace = Some(ns.into());
        self
    }

    /// The name as the ecosystem's own registry spells it.
    ///
    /// npm rejoins the scope with a slash; everything else keeps them apart. A PURL splits
    /// `@babel/core` into namespace and name, and asking npm for `core` finds a different package.
    pub fn registry_name(&self) -> String {
        match (&self.namespace, self.ecosystem) {
            (Some(ns), Ecosystem::Npm) => format!("{ns}/{}", self.name),
            (Some(ns), Ecosystem::Maven) => format!("{ns}:{}", self.name),
            (Some(ns), Ecosystem::GitHub) => format!("{ns}/{}", self.name),
            _ => self.name.clone(),
        }
    }
}

impl fmt::Display for TargetRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pkg:{}/", self.ecosystem.purl_type())?;
        if let Some(ns) = &self.namespace {
            write!(f, "{ns}/")?;
        }
        write!(f, "{}@{}", self.name, self.version)?;
        for (i, (k, v)) in self.qualifiers.iter().enumerate() {
            f.write_str(if i == 0 { "?" } else { "&" })?;
            write!(f, "{k}={v}")?;
        }
        Ok(())
    }
}

fn known() -> String {
    Ecosystem::all()
        .iter()
        .map(|e| e.purl_type())
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PurlError {
    #[error("a package URL starts with `pkg:`; got `{0}`")]
    NotAPurl(String),
    #[error("unknown ecosystem `{found}`. Known: {}", known())]
    UnknownEcosystem { found: String },
    #[error("no name in `{0}`")]
    NoName(String),
    #[error(
        "no version in `{0}`. A run is about one version: without it there is nothing to compare."
    )]
    NoVersion(String),
}

impl FromStr for TargetRef {
    type Err = PurlError;

    /// Parse a package URL.
    ///
    /// Deliberately small. The full spec has percent-encoding rules and subpath syntax that nothing
    /// here uses, and implementing half of a spec silently is worse than implementing a stated
    /// subset: this handles `pkg:type/namespace/name@version?k=v`, rejects anything without a
    /// version, and says so.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rest = s
            .strip_prefix("pkg:")
            .ok_or_else(|| PurlError::NotAPurl(s.to_string()))?;

        let (rest, qualifiers) = match rest.split_once('?') {
            Some((head, q)) => {
                let mut map = BTreeMap::new();
                for pair in q.split('&').filter(|p| !p.is_empty()) {
                    let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                    map.insert(k.to_string(), v.to_string());
                }
                (head, map)
            }
            None => (rest, BTreeMap::new()),
        };

        // The LAST `@`, which is what makes a scoped npm name work: splitting on the first would
        // turn `pkg:npm/@babel/core@7.24.0` into a package called `babel/core@7.24.0`. An
        // unencoded `@` inside a version mis-splits as a result; the spec requires it encoded.
        let (path, version) = rest
            .rsplit_once('@')
            .ok_or_else(|| PurlError::NoVersion(s.to_string()))?;
        if version.is_empty() {
            return Err(PurlError::NoVersion(s.to_string()));
        }

        let mut parts = path.splitn(2, '/');
        let ty = parts.next().unwrap_or_default();
        let ecosystem =
            Ecosystem::from_purl_type(ty).ok_or_else(|| PurlError::UnknownEcosystem {
                found: ty.to_string(),
            })?;
        let remainder = parts.next().unwrap_or_default();
        if remainder.is_empty() {
            return Err(PurlError::NoName(s.to_string()));
        }

        // Everything before the last slash is the namespace, which is what makes
        // `pkg:maven/org.apache.commons/commons-lang3` and `pkg:npm/@babel/core` both work.
        let (namespace, name) = match remainder.rsplit_once('/') {
            Some((ns, n)) => (Some(ns.to_string()), n.to_string()),
            None => (None, remainder.to_string()),
        };
        if name.is_empty() {
            return Err(PurlError::NoName(s.to_string()));
        }

        Ok(TargetRef {
            ecosystem,
            namespace,
            name,
            version: version.to_string(),
            qualifiers,
        })
    }
}

/// One file of one version.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct ArtifactId(pub String);

impl ArtifactId {
    pub fn new(s: impl Into<String>) -> Self {
        ArtifactId(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// What kind of artifact the filename says this is.
    ///
    /// From the name because that is what the registry gives us, and because the extension is the
    /// only part that is reliably meaningful across every registry's metadata.
    pub fn kind(&self) -> ArtifactKind {
        let n = self.0.to_ascii_lowercase();
        if n.ends_with(".whl") {
            ArtifactKind::Wheel
        } else if n.ends_with(".crate") {
            ArtifactKind::Crate
        } else if n.ends_with(".gem") {
            ArtifactKind::Gem
        } else if n.ends_with(".nupkg") {
            ArtifactKind::Nupkg
        } else if n.ends_with(".jar") {
            ArtifactKind::Jar
        } else if n.ends_with(".tgz") {
            ArtifactKind::Tarball
        } else if n.ends_with(".tar.gz") || n.ends_with(".zip") {
            // A PyPI sdist and a GitHub source archive share these extensions. The caller knows
            // which registry it asked, and `Sdist` is the reading that matters for reproduction.
            ArtifactKind::Sdist
        } else {
            ArtifactKind::Other
        }
    }
}

impl fmt::Display for ArtifactId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Sdist,
    Wheel,
    Tarball,
    Crate,
    Gem,
    Nupkg,
    Jar,
    ReleaseAsset,
    SourceArchive,
    Other,
}

/// What a run is about.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct Target {
    pub reference: TargetRef,
    pub artifact: ArtifactId,
}

impl Target {
    pub fn new(reference: TargetRef, artifact: ArtifactId) -> Self {
        Target {
            reference,
            artifact,
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.reference, self.artifact)
    }
}
