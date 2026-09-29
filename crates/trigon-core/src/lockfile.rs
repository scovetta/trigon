//! Reading a lockfile, and the five things that can be said about what it names.
//!
//! Lives here rather than beside either consumer because there are two: `trigon check` on the
//! command line and `POST /v1/check` in the management API. A lockfile parser written twice is two
//! answers to "what does this file depend on", and a seam with an implementation on each side of
//! it is the defect this tree keeps finding.
//!
//! **Parsing only.** Deciding what a *run* says about a package needs a `RunRecord`, which lives a
//! crate up; that mapping is `trigon_store::RunRecord::status`.
//!
//! **What a lockfile pins, not only what it names.** A purl names a package; the digest a lockfile
//! declares names the artifact it will install, which is what a record is about (`docs/19` §1, §5).
//! So every digest is kept — npm's `integrity`, each `--hash` of a requirement, an SBOM's
//! `checksums` — in hex, beside npm's `resolved`, and `trigon check` looks a package up by digest
//! first and by purl second (§6). A digest is a declaration here, as it is from a registry
//! ([`crate::DeclaredDigest`]): nothing has checked it against any bytes.

use std::collections::BTreeSet;
use std::path::Path;

use base64::Engine as _;

use crate::DeclaredDigest;

/// A lockfile this can read.
///
/// Chosen by file name rather than sniffed, so a file pointed at by mistake is refused instead of
/// reported as zero packages — which would read as "nothing to worry about".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    NpmLock,
    Requirements,
    Spdx,
}

impl Kind {
    pub fn of_file_name(name: &str) -> Option<Kind> {
        let n = name.to_ascii_lowercase();
        if n == "package-lock.json" || n == "npm-shrinkwrap.json" {
            Some(Kind::NpmLock)
        } else if n.ends_with("requirements.txt") || n == "requirements.in" {
            Some(Kind::Requirements)
        } else if n.ends_with(".spdx.json") || n.ends_with("sbom.json") {
            Some(Kind::Spdx)
        } else {
            None
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LockfileError {
    #[error(
        "`{0}` is not a lockfile this reads. It knows package-lock.json, npm-shrinkwrap.json, \
         requirements.txt and *.spdx.json. Naming the format rather than guessing it means a file \
         pointed at by mistake is refused instead of reported as zero packages."
    )]
    UnknownKind(String),
    #[error("{0}")]
    Malformed(String),
    #[error("reading {0}: {1}")]
    Io(String, String),
}

/// One package a lockfile names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Package {
    /// Its purl. Empty for a package an SBOM names without one, which is kept rather than dropped:
    /// it is looked up by its checksums alone, and reported as never checked where nothing answers
    /// for it.
    pub purl: String,
    pub name: String,
    pub version: String,
    /// 1-based line it was found on, so a code-scanning UI can point at it. 0 when unknown.
    pub line: usize,
    /// Every digest the file declares for the artifact it pins, as it declared it, in lowercase
    /// hex: npm's `integrity`, one entry per hash in it; every `--hash` of a requirement, which pip
    /// accepts any one of; an SBOM's `checksums`. Empty where it declares none.
    pub digests: Vec<DeclaredDigest>,
    /// npm's `resolved`: where the lockfile says the artifact is fetched from. Said, never
    /// fetched.
    pub resolved: Option<String>,
}

/// Where each kind of file declares a digest, as [`DeclaredDigest::source`] says it.
const NPM_INTEGRITY: &str = "package-lock:integrity";
const PIP_HASH: &str = "requirements:--hash";
const SPDX_CHECKSUM: &str = "spdx:checksums";

/// What we can say about one package in a lockfile.
///
/// Ordered as the summary prints them, best first, with the two non-verdicts last.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Status {
    Reproduced,
    Caveats,
    Divergent,
    /// We ran it and could not reach a verdict: a void run, a guard trip, a build that failed for
    /// our reasons. **Not** a statement about the package.
    Unsupported,
    /// No run exists. Not a judgement at all.
    NeverChecked,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::Reproduced => "reproduced",
            Status::Caveats => "caveats",
            Status::Divergent => "divergent",
            Status::Unsupported => "unsupported",
            Status::NeverChecked => "never checked",
        }
    }

    /// The glyph the terminal table uses. `?` for never-checked, deliberately not a blank.
    pub fn glyph(self) -> &'static str {
        match self {
            Status::Reproduced => "✔",
            Status::Caveats => "◐",
            Status::Divergent => "✖",
            Status::Unsupported => "⊘",
            Status::NeverChecked => "?",
        }
    }

    /// SARIF level. Never-checked is a `note` and never absent: a finding nobody filed is a
    /// finding nobody sees.
    pub fn sarif_level(self) -> &'static str {
        match self {
            Status::Divergent => "error",
            Status::Caveats => "warning",
            Status::Unsupported | Status::NeverChecked => "note",
            Status::Reproduced => "none",
        }
    }

    pub fn rule_id(self) -> &'static str {
        match self {
            Status::Reproduced => "trigon/reproduced",
            Status::Caveats => "trigon/caveats",
            Status::Divergent => "trigon/divergent",
            Status::Unsupported => "trigon/unsupported",
            Status::NeverChecked => "trigon/never-checked",
        }
    }
}


/// Every package a lockfile names, in purl order.
pub fn parse(text: &str, kind: Kind) -> Result<Vec<Package>, LockfileError> {
    match kind {
        Kind::NpmLock => npm_lock(text),
        Kind::Requirements => Ok(requirements(text)),
        Kind::Spdx => spdx(text),
    }
}

/// The same, from a path, choosing the parser by file name.
pub fn read(path: &Path) -> Result<Vec<Package>, LockfileError> {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let kind = Kind::of_file_name(&name)
        .ok_or_else(|| LockfileError::UnknownKind(path.display().to_string()))?;
    let text = std::fs::read_to_string(path)
        .map_err(|e| LockfileError::Io(path.display().to_string(), e.to_string()))?;
    parse(&text, kind)
}

/// Where a string first appears in the file, as a 1-based line. 0 when it does not.
fn line_of(text: &str, needle: &str) -> usize {
    text.lines()
        .position(|l| l.contains(needle))
        .map(|i| i + 1)
        .unwrap_or(0)
}

/// Where an SPDX element's id is declared: the line that carries its `SPDXID`, and not the first
/// that names it, which may be `documentDescribes` above the packages. The first line that names
/// it where none carries both.
fn line_of_id(text: &str, id: &str) -> usize {
    let quoted = format!("\"{id}\"");
    text.lines()
        .position(|l| l.contains("\"SPDXID\"") && l.contains(&quoted))
        .map(|i| i + 1)
        .unwrap_or_else(|| line_of(text, &quoted))
}

fn npm_lock(text: &str) -> Result<Vec<Package>, LockfileError> {
    let v: serde_json::Value =
        serde_json::from_str(text)
        .map_err(|e| LockfileError::Malformed(format!("package-lock.json is not JSON: {e}")))?;
    let mut out = Vec::new();

    // v2 and v3: a flat `packages` map keyed by install path. The root is "" and is the project
    // itself, not a dependency.
    if let Some(map) = v.get("packages").and_then(|p| p.as_object()) {
        for (path, entry) in map {
            if path.is_empty() {
                continue;
            }
            // `node_modules/a/node_modules/b` names `b`. The last segment is the package.
            let Some(name) = path.rsplit("node_modules/").next().filter(|s| !s.is_empty()) else {
                continue;
            };
            // A link entry points at a workspace and has no published version to check.
            if entry.get("link").and_then(|l| l.as_bool()) == Some(true) {
                continue;
            }
            let Some(version) = entry.get("version").and_then(|x| x.as_str()) else {
                continue;
            };
            out.push(Package {
                purl: format!("pkg:npm/{name}@{version}"),
                name: name.to_string(),
                version: version.to_string(),
                line: line_of(text, &format!("\"{path}\"")),
                digests: integrity(entry),
                resolved: resolved(entry),
            });
        }
    } else if let Some(map) = v.get("dependencies").and_then(|p| p.as_object()) {
        // v1: a recursive `dependencies` tree.
        fn walk(
            map: &serde_json::Map<String, serde_json::Value>,
            text: &str,
            out: &mut Vec<Package>,
        ) {
            for (name, entry) in map {
                if let Some(version) = entry.get("version").and_then(|x| x.as_str()) {
                    out.push(Package {
                        purl: format!("pkg:npm/{name}@{version}"),
                        name: name.clone(),
                        version: version.to_string(),
                        line: line_of(text, &format!("\"{name}\"")),
                        digests: integrity(entry),
                        resolved: resolved(entry),
                    });
                }
                if let Some(inner) = entry.get("dependencies").and_then(|d| d.as_object()) {
                    walk(inner, text, out);
                }
            }
        }
        walk(map, text, &mut out);
    } else {
        return Err(LockfileError::Malformed(
            "this package-lock.json has neither a `packages` nor a `dependencies` object".into(),
        ));
    }

    Ok(dedupe(out))
}

/// An npm entry's `integrity`, Subresource Integrity: one or more `<algorithm>-<base64>` separated
/// by whitespace, each possibly followed by `?<options>`, as hex. An entry this cannot read is left
/// out rather than guessed at; the package is then looked up by its purl.
fn integrity(entry: &serde_json::Value) -> Vec<DeclaredDigest> {
    let Some(sri) = entry.get("integrity").and_then(|i| i.as_str()) else {
        return Vec::new();
    };
    sri.split_whitespace()
        .filter_map(|one| {
            let (algorithm, rest) = one.split_once('-')?;
            let b64 = rest.split('?').next().unwrap_or(rest);
            let raw = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
            Some(DeclaredDigest {
                algorithm: algorithm.to_ascii_lowercase(),
                value: raw.iter().map(|b| format!("{b:02x}")).collect(),
                source: NPM_INTEGRITY.into(),
            })
        })
        .collect()
}

/// An npm entry's `resolved`, where it has one.
fn resolved(entry: &serde_json::Value) -> Option<String> {
    entry
        .get("resolved")
        .and_then(|r| r.as_str())
        .map(str::to_string)
}

/// A digest written `<algorithm>:<hex>`, as a `--hash` is, or `None` where it is not one.
fn hex_digest(algorithm: &str, hex: &str, source: &str) -> Option<DeclaredDigest> {
    let hex = hex.trim().to_ascii_lowercase();
    (!algorithm.is_empty() && !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| DeclaredDigest {
            algorithm: algorithm.trim().to_ascii_lowercase(),
            value: hex,
            source: source.into(),
        })
}

/// A requirements file's logical lines, as pip reads them: a line ending in `\` goes on in the
/// next — pip-compile writes each `--hash` of a pin on a line of its own after it — and a comment
/// runs from a `#` at the start or after whitespace. Each with the line it began on.
///
/// A line that is a comment never goes on, whatever it ends in, and one that comes where a line
/// goes on ends it, as pip's `join_lines` has it: joined to the next line, `# pinned for a reason
/// \` would take the requirement after it into the comment, and out of the check.
fn logical_lines(text: &str) -> Vec<(usize, String)> {
    let mut out: Vec<(usize, String)> = Vec::new();
    let mut open: Option<(usize, String)> = None;
    for (i, raw) in text.lines().enumerate() {
        let comment = raw.trim_start().starts_with('#');
        let (start, mut joined) = open.take().unwrap_or((i + 1, String::new()));
        match raw.strip_suffix('\\') {
            Some(head) if !comment => {
                joined.push_str(head);
                joined.push(' ');
                open = Some((start, joined));
            }
            _ => {
                // After whitespace, so the comment is cut below wherever it was joined.
                if comment {
                    joined.push(' ');
                }
                joined.push_str(raw);
                out.push((start, joined));
            }
        }
    }
    out.extend(open);
    out.into_iter()
        .map(|(n, l)| {
            let cut = l
                .char_indices()
                .find(|&(i, c)| c == '#' && (i == 0 || l[..i].ends_with(char::is_whitespace)))
                .map_or(l.len(), |(i, _)| i);
            (n, l[..cut].to_string())
        })
        .collect()
}

fn requirements(text: &str) -> Vec<Package> {
    let mut out = Vec::new();
    for (line, logical) in logical_lines(text) {
        // pip's own split: the words up to the first that begins with `-` are the requirement,
        // and the rest are its options. Reading `==` over the whole line took `3.0.0
        // --hash=sha256:…` for the version.
        let words: Vec<&str> = logical.split_whitespace().collect();
        let at = words
            .iter()
            .position(|w| w.starts_with('-'))
            .unwrap_or(words.len());
        let (spec, options) = (words[..at].join(" "), &words[at..]);
        // An environment marker is cut, and so is a line that is only options: `-r other.txt`,
        // `-e .`, `--index-url …`.
        let spec = spec.split(';').next().unwrap_or("").trim();
        if spec.is_empty() {
            continue;
        }
        // Only `==` (and `===`) pins a version. `>=` names a range, and a range is not a thing
        // we can have checked: skipping it is honest, and it lands in `never checked` by being
        // absent.
        let Some((name, version)) = spec.split_once("==") else {
            continue;
        };
        // `name[extra]` — the extras do not change which artifact was published.
        let name = name.split('[').next().unwrap_or(name).trim();
        let version = version.trim_start_matches('=').trim();
        if name.is_empty() || version.is_empty() || version.contains(char::is_whitespace) {
            continue;
        }
        let mut digests = Vec::new();
        let mut rest = options.iter();
        while let Some(o) = rest.next() {
            let value = match o.strip_prefix("--hash") {
                Some(v) if v.starts_with('=') => Some(&v[1..]),
                Some("") => rest.next().copied(),
                _ => None,
            };
            if let Some(d) = value
                .and_then(|v| v.split_once(':'))
                .and_then(|(a, h)| hex_digest(a, h, PIP_HASH))
            {
                digests.push(d);
            }
        }
        out.push(Package {
            purl: format!("pkg:pypi/{name}@{version}"),
            name: name.to_string(),
            version: version.to_string(),
            line,
            digests,
            resolved: None,
        });
    }
    dedupe(out)
}

/// Every package an SPDX document names, whatever its ecosystem, and whether or not it carries a
/// purl. A package no source can answer for is reported as never checked, which is the truth; one
/// left out would read as a package nobody needs to worry about. Phase 0 found this dropping
/// every purl that was not npm or PyPI (`docs/19` §10 phase 6).
fn spdx(text: &str) -> Result<Vec<Package>, LockfileError> {
    let v: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| LockfileError::Malformed(format!("the SBOM is not JSON: {e}")))?;
    let Some(packages) = v.get("packages").and_then(|p| p.as_array()) else {
        return Err(LockfileError::Malformed(
            "this SPDX document has no `packages` array".into(),
        ));
    };
    let mut out = Vec::new();
    for p in packages {
        let field = |k: &str| p.get(k).and_then(|x| x.as_str()).map(str::to_string);
        // The purl an SBOM carries names the ecosystem, which a name and version alone do not.
        let given = p
            .get("externalRefs")
            .and_then(|r| r.as_array())
            .and_then(|refs| {
                refs.iter()
                    .find(|r| r.get("referenceType").and_then(|t| t.as_str()) == Some("purl"))
                    .and_then(|r| r.get("referenceLocator").and_then(|l| l.as_str()))
            })
            .map(str::to_string);
        let version_info = field("versionInfo").filter(|v| !v.trim().is_empty());
        // A purl with no version, where `versionInfo` names one, is that version of the package.
        // Looked up as the purl alone it would be every version, and two versions of one package
        // in one SBOM would be one package, answered by the records of either.
        let built = match (&given, &version_info) {
            (Some(p), Some(v)) => with_version(p, v),
            _ => None,
        };
        let versioned = given
            .as_deref()
            .filter(|p| crate::purl::canonicalize(p).is_ok_and(|c| c.has_version()));
        let (name, version) = match (&built, versioned.and_then(|p| p.rsplit_once('@'))) {
            (None, Some((head, v))) => (
                head.rsplit('/').next().unwrap_or(head).to_string(),
                v.split(['?', '#']).next().unwrap_or(v).to_string(),
            ),
            (Some(_), _) | (None, None) => (
                field("name").unwrap_or_default(),
                version_info.clone().unwrap_or_default(),
            ),
        };
        let purl = built.or_else(|| given.clone());
        let digests = p
            .get("checksums")
            .and_then(|c| c.as_array())
            .map(|cs| {
                cs.iter()
                    .filter_map(|c| {
                        let a = c.get("algorithm")?.as_str()?;
                        let h = c.get("checksumValue")?.as_str()?;
                        hex_digest(a, h, SPDX_CHECKSUM)
                    })
                    .collect()
            })
            .unwrap_or_default();
        // Found by its SPDX id wherever it has one, since an id names one package and a purl may
        // name several: a versionless purl every version the SBOM lists, a versioned one two
        // artifacts of that version. Without an id, by its purl whole, as the JSON string it is:
        // unquoted, `pkg:npm/a@1.0` is found on the line of `pkg:npm/a@1.0.1`.
        let line = match (field("SPDXID"), &given) {
            (Some(id), _) => line_of_id(text, &id),
            (None, Some(p)) => line_of(text, &format!("\"{p}\"")),
            (None, None) => 0,
        };
        out.push(Package {
            purl: purl.unwrap_or_default(),
            name,
            version,
            line,
            digests,
            resolved: None,
        });
    }
    Ok(dedupe(out))
}

/// One entry per artifact. Entries of one purl and version are merged where their digests are one
/// artifact's — the same, or one declaring part of what the other does, as a nested copy of an
/// npm package with the same `integrity`, or with none, is — and kept apart where they differ:
/// two tarballs of one name and version are two artifacts the lockfile installs, a registry's and
/// a substitute's, and merged, one's record would answer for the other, which nothing checked.
/// Entries without a purl are merged only where everything about them is one, since two packages
/// an SBOM names without a purl are two packages unless nothing tells them apart.
fn dedupe(mut v: Vec<Package>) -> Vec<Package> {
    v.sort_by(|a, b| {
        (&a.purl, &a.name, &a.version, a.line).cmp(&(&b.purl, &b.name, &b.version, b.line))
    });
    let declared = |p: &Package| -> BTreeSet<(String, String)> {
        p.digests
            .iter()
            .map(|d| (d.algorithm.clone(), d.value.clone()))
            .collect()
    };
    let mut out: Vec<Package> = Vec::with_capacity(v.len());
    for p in v {
        // Sorted by purl, so every entry this one could be merged into is at the end.
        let same = out
            .iter()
            .enumerate()
            .rev()
            .take_while(|(_, a)| a.purl == p.purl)
            .find(|(_, a)| match p.purl.is_empty() {
                false => {
                    let (x, y) = (declared(a), declared(&p));
                    a.version == p.version && (x.is_subset(&y) || y.is_subset(&x))
                }
                true => (&a.name, &a.version, &a.digests) == (&p.name, &p.version, &p.digests),
            })
            .map(|(i, _)| i);
        match same {
            Some(i) => {
                let last = &mut out[i];
                for d in p.digests {
                    if !last.digests.contains(&d) {
                        last.digests.push(d);
                    }
                }
                last.resolved = last.resolved.take().or(p.resolved);
            }
            None => out.push(p),
        }
    }
    out
}

/// `purl` at `version`, canonical, where `purl` names no version: an SBOM that gives a package's
/// version only in `versionInfo`. The version is percent-encoded whole, as the purl spec encodes
/// one, so no character in it is read as a separator. `None` where `purl` is not one, or names a
/// version already.
fn with_version(purl: &str, version: &str) -> Option<String> {
    let c = crate::purl::canonicalize(purl).ok()?;
    if c.has_version() {
        return None;
    }
    // Canonical, so the first `?` or `#` is where the qualifiers or the subpath begin: the name
    // and namespace carry either only percent-encoded.
    let s = c.as_str();
    let at = s.find(['?', '#']).unwrap_or(s.len());
    let encoded: String = version
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                char::from(b).to_string()
            }
            b => format!("%{b:02X}"),
        })
        .collect();
    let built = crate::purl::canonicalize(&format!("{}@{encoded}{}", &s[..at], &s[at..])).ok()?;
    built.has_version().then(|| built.as_str().to_string())
}

impl Package {
    /// Whether its digests are of alternatives, any one of which may be what is installed — a
    /// requirement's `--hash`es, which pip accepts any one of — rather than of one artifact, as
    /// npm's `integrity` and an SBOM's `checksums` are.
    pub fn alternatives(&self) -> bool {
        !self.digests.is_empty() && self.digests.iter().all(|d| d.source == PIP_HASH)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(who: &str, name: &str, body: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("trigon-check-{}-{who}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn an_npm_lockfile_v3_names_its_packages_and_where_they_are() {
        let p = tmp(
            "v3",
            "package-lock.json",
            r#"{
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "demo", "version": "1.0.0" },
    "node_modules/left-pad": { "version": "1.3.0" },
    "node_modules/a/node_modules/b": { "version": "2.0.0" },
    "node_modules/ws": { "link": true },
    "node_modules/no-version": { "resolved": "x" }
  }
}"#,
        );
        let got = read(&p).expect("parse");
        let purls: Vec<&str> = got.iter().map(|p| p.purl.as_str()).collect();
        assert_eq!(purls, ["pkg:npm/b@2.0.0", "pkg:npm/left-pad@1.3.0"]);
        // A nested install path names the innermost package, not the path.
        assert!(purls.contains(&"pkg:npm/b@2.0.0"), "{purls:?}");
        // A workspace link has no published version to check, and an entry without one is not a
        // package we can name. Both are absent rather than reported as version-less.
        assert!(!purls.iter().any(|p| p.contains("ws")), "{purls:?}");
        assert!(!purls.iter().any(|p| p.contains("no-version")), "{purls:?}");
        // Every one carries the line it was found on, so a code-scanning UI can point at it.
        assert!(got.iter().all(|p| p.line > 0), "{got:?}");
    }

    #[test]
    fn an_npm_lockfile_v1_is_read_too() {
        let p = tmp(
            "v1",
            "package-lock.json",
            r#"{
  "lockfileVersion": 1,
  "dependencies": {
    "left-pad": { "version": "1.3.0" },
    "outer": { "version": "2.0.0", "dependencies": { "inner": { "version": "3.0.0" } } }
  }
}"#,
        );
        let purls: Vec<String> = read(&p)
            .expect("parse")
            .into_iter()
            .map(|p| p.purl)
            .collect();
        assert!(purls.contains(&"pkg:npm/inner@3.0.0".to_string()), "{purls:?}");
        assert_eq!(purls.len(), 3, "{purls:?}");
    }

    #[test]
    fn requirements_reads_pins_and_skips_what_is_not_one() {
        let p = tmp(
            "reqs",
            "requirements.txt",
            "# comment\n\
             click==8.3.3\n\
             requests>=2.0\n\
             urllib3[socks]==2.5.0 ; python_version > \"3.8\"\n\
             -r other.txt\n\
             -e .\n\
             flask==3.0.0  # trailing comment\n",
        );
        let got = read(&p).expect("parse");
        let purls: Vec<&str> = got.iter().map(|p| p.purl.as_str()).collect();
        assert_eq!(
            purls,
            [
                "pkg:pypi/click@8.3.3",
                "pkg:pypi/flask@3.0.0",
                "pkg:pypi/urllib3@2.5.0"
            ],
            "extras are stripped, markers and comments are cut, and a `>=` range is not a pin"
        );
    }

    #[test]
    fn a_file_this_does_not_read_is_refused_by_name() {
        // The alternative is reporting zero packages, which reads as "nothing to worry about".
        let p = tmp("cargo", "Cargo.lock", "[[package]]\nname = \"x\"\n");
        let e = read(&p).expect_err("Cargo.lock is not supported");
        assert!(format!("{e}").contains("not a lockfile this reads"), "{e}");
    }

    #[test]
    fn an_sbom_keeps_every_package_it_names_with_its_checksums() {
        let p = tmp(
            "spdx",
            "x.spdx.json",
            r#"{ "packages": [
                 { "SPDXID": "SPDXRef-a", "name": "left-pad", "externalRefs": [
                     { "referenceType": "purl", "referenceLocator": "pkg:npm/left-pad@1.3.0" } ],
                   "checksums": [ { "algorithm": "SHA512", "checksumValue": "ABCD" } ] },
                 { "SPDXID": "SPDXRef-b", "name": "openssl", "externalRefs": [
                     { "referenceType": "purl", "referenceLocator": "pkg:deb/debian/openssl@3.0.11" } ] },
                 { "SPDXID": "SPDXRef-c", "name": "vendored", "versionInfo": "2.1",
                   "checksums": [ { "algorithm": "SHA256", "checksumValue": "0a1b" } ] } ] }"#,
        );
        let got = read(&p).expect("parse");
        let purls: Vec<&str> = got.iter().map(|p| p.purl.as_str()).collect();
        // Every package, whatever its ecosystem and whether it carries a purl: one this cannot
        // answer for is reported as never checked, which is the truth, and one left out reads as a
        // package nobody needs to worry about. The parser used to keep npm and PyPI alone.
        assert_eq!(purls, ["", "pkg:deb/debian/openssl@3.0.11", "pkg:npm/left-pad@1.3.0"]);
        let vendored = &got[0];
        assert_eq!((vendored.name.as_str(), vendored.version.as_str()), ("vendored", "2.1"));
        assert!(vendored.line > 0, "{vendored:?}");
        assert_eq!(vendored.digests[0].algorithm, "sha256");
        assert_eq!(vendored.digests[0].value, "0a1b");
        assert_eq!(vendored.digests[0].source, "spdx:checksums");
        assert_eq!(got[2].digests[0].value, "abcd", "hex is kept lowercase");
        assert!(got[1].digests.is_empty());
    }

    /// `--hash` is an option of the requirement, as pip reads it, and never part of its version:
    /// `flask==3.0.0 --hash=sha256:…` was read as version `3.0.0 --hash=sha256:…`, and a pin that
    /// pip-compile continues onto hash lines as version `8.1.7 \`.
    #[test]
    fn a_requirements_hash_is_kept_and_never_read_as_part_of_the_version() {
        let a = "a".repeat(64);
        let b = "B".repeat(64);
        let text = format!(
            "flask==3.0.0 --hash=sha256:{a}\n\
             click==8.1.7 \\\n    --hash=sha256:{a} \\\n    --hash sha256:{b}\n\
             # via flask\n\
             colorama==0.4.6 ; platform_system == \"Windows\" \\\n    --hash=sha256:{a}\n\
             plain==1.0  # a comment\n"
        );
        let got = parse(&text, Kind::Requirements).expect("parse");
        let by = |n: &str| got.iter().find(|p| p.name == n).unwrap_or_else(|| panic!("{got:?}"));
        assert_eq!(by("flask").version, "3.0.0");
        assert_eq!(by("flask").purl, "pkg:pypi/flask@3.0.0");
        assert_eq!(by("click").version, "8.1.7");
        assert_eq!(by("click").line, 2, "the line the requirement began on");
        let hashes: Vec<&str> = by("click").digests.iter().map(|d| d.value.as_str()).collect();
        assert_eq!(hashes, [a.clone(), b.to_ascii_lowercase()], "every hash, lowercase");
        assert!(by("click").digests.iter().all(|d| d.algorithm == "sha256"
            && d.source == "requirements:--hash"));
        assert_eq!(by("colorama").version, "0.4.6");
        assert_eq!(by("colorama").digests.len(), 1);
        assert_eq!(by("plain").version, "1.0");
        assert!(by("plain").digests.is_empty());
        assert_eq!(got.len(), 4, "{got:?}");
    }

    /// npm's `integrity`, in every lockfile version, is kept as hex beside `resolved`: the
    /// sha512 a record is found by.
    #[test]
    fn an_npm_lockfile_keeps_its_integrity_and_where_it_resolved() {
        use base64::Engine as _;
        let raw: Vec<u8> = (0..64u8).collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&raw);
        let sha1 = base64::engine::general_purpose::STANDARD.encode([7u8; 20]);
        let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        for (name, body) in [
            (
                "v3",
                format!(
                    r#"{{"lockfileVersion": 3, "packages": {{"": {{}},
                       "node_modules/left-pad": {{"version": "1.3.0",
                         "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                         "integrity": "sha512-{b64} sha1-{sha1}"}}}}}}"#
                ),
            ),
            (
                "v1",
                format!(
                    r#"{{"lockfileVersion": 1, "dependencies": {{"left-pad": {{"version": "1.3.0",
                         "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                         "integrity": "sha512-{b64} sha1-{sha1}"}}}}}}"#
                ),
            ),
        ] {
            let got = parse(&body, Kind::NpmLock).expect(name);
            assert_eq!(got.len(), 1, "{name}: {got:?}");
            let p = &got[0];
            assert_eq!(p.digests[0].algorithm, "sha512", "{name}");
            assert_eq!(p.digests[0].value, hex, "{name}");
            assert_eq!(p.digests[0].source, "package-lock:integrity");
            assert_eq!(p.digests[1].algorithm, "sha1", "{name}");
            assert_eq!(p.digests[1].value, "07".repeat(20), "{name}");
            assert_eq!(
                p.resolved.as_deref(),
                Some("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"),
                "{name}"
            );
        }
    }

    /// A comment never goes on into the next line, whatever it ends in, as pip reads one: joined,
    /// the requirement after `# pinned for a reason \` was cut out with the comment, and a package
    /// pip installs was missing from the check. A comment where a line goes on ends it.
    #[test]
    fn a_comment_ending_in_a_backslash_does_not_swallow_the_next_requirement() {
        let a = "a".repeat(64);
        let text = format!(
            "# pinned for a reason \\\n\
             flask==3.0.0\n\
             click==8.1.7\n\
             attrs==23.1.0 \\\n    # a comment where the line goes on \\\n\
             idna==3.4 --hash=sha256:{a}\n"
        );
        let got = parse(&text, Kind::Requirements).expect("parse");
        let purls: Vec<&str> = got.iter().map(|p| p.purl.as_str()).collect();
        assert_eq!(
            purls,
            [
                "pkg:pypi/attrs@23.1.0",
                "pkg:pypi/click@8.1.7",
                "pkg:pypi/flask@3.0.0",
                "pkg:pypi/idna@3.4"
            ]
        );
        let flask = got.iter().find(|p| p.name == "flask").unwrap();
        assert_eq!(flask.line, 2, "{flask:?}");
        let idna = got.iter().find(|p| p.name == "idna").unwrap();
        assert_eq!(idna.line, 6, "the comment ended attrs' line: {idna:?}");
        assert_eq!(idna.digests.len(), 1);
    }

    /// An SBOM package whose purl names no version and whose `versionInfo` does is that version:
    /// looked up as the purl alone it was every version of the package, and two versions of it
    /// one package.
    #[test]
    fn an_sbom_purl_without_a_version_takes_the_version_the_sbom_gives() {
        let got = parse(
            r#"{ "packages": [
                 { "SPDXID": "SPDXRef-1", "name": "foo", "versionInfo": "1.0.0",
                   "externalRefs": [ { "referenceType": "purl",
                                       "referenceLocator": "pkg:npm/foo" } ] },
                 { "SPDXID": "SPDXRef-2", "name": "foo", "versionInfo": "2.0.0+build.1",
                   "externalRefs": [ { "referenceType": "purl",
                                       "referenceLocator": "pkg:npm/foo" } ] },
                 { "SPDXID": "SPDXRef-3", "name": "core", "versionInfo": "7.24.0",
                   "externalRefs": [ { "referenceType": "purl",
                                       "referenceLocator": "pkg:npm/@babel/core?x=y" } ] },
                 { "SPDXID": "SPDXRef-4", "name": "bare",
                   "externalRefs": [ { "referenceType": "purl",
                                       "referenceLocator": "pkg:npm/bare" } ] } ] }"#,
            Kind::Spdx,
        )
        .expect("parse");
        let rows: Vec<(&str, &str, &str)> = got
            .iter()
            .map(|p| (p.purl.as_str(), p.name.as_str(), p.version.as_str()))
            .collect();
        assert_eq!(
            rows,
            [
                ("pkg:npm/%40babel/core@7.24.0?x=y", "core", "7.24.0"),
                ("pkg:npm/bare", "bare", ""),
                ("pkg:npm/foo@1.0.0", "foo", "1.0.0"),
                ("pkg:npm/foo@2.0.0%2Bbuild.1", "foo", "2.0.0+build.1"),
            ]
        );
        // Each found by the id that names it, since the purl it was given names two.
        let text_line = |id: &str| {
            got.iter()
                .find(|p| p.version == id)
                .map(|p| p.line)
                .unwrap()
        };
        assert!(text_line("1.0.0") > 0 && text_line("1.0.0") < text_line("2.0.0+build.1"));
    }

    /// Two entries of one name and version with different digests are two artifacts the lockfile
    /// installs, and two packages; with the same digests, or one declaring none, one.
    #[test]
    fn two_artifacts_of_one_name_and_version_are_two_packages() {
        use base64::Engine as _;
        let sri = |b: u8| {
            format!(
                "sha512-{}",
                base64::engine::general_purpose::STANDARD.encode([b; 64])
            )
        };
        let (a, b) = (sri(1), sri(2));
        let got = parse(
            &format!(
                r#"{{"lockfileVersion": 3, "packages": {{"": {{}},
                   "node_modules/foo": {{"version": "1.0.0", "integrity": "{a}"}},
                   "node_modules/x/node_modules/foo": {{"version": "1.0.0", "integrity": "{b}",
                     "resolved": "https://elsewhere.example/foo-1.0.0.tgz"}},
                   "node_modules/y/node_modules/foo": {{"version": "1.0.0", "integrity": "{a}"}},
                   "node_modules/z/node_modules/foo": {{"version": "1.0.0"}}}}}}"#
            ),
            Kind::NpmLock,
        )
        .expect("parse");
        assert_eq!(got.len(), 2, "{got:?}");
        assert!(got.iter().all(|p| p.purl == "pkg:npm/foo@1.0.0"));
        let values: Vec<&str> = got.iter().map(|p| p.digests[0].value.as_str()).collect();
        assert_eq!(values, ["01".repeat(64), "02".repeat(64)]);
        assert_eq!(got.iter().map(|p| p.digests.len()).sum::<usize>(), 2);
        assert!(!got[0].alternatives(), "npm's integrity is one artifact's");
        let reqs = parse(
            &format!(
                "x==1.0 --hash=sha256:{} --hash=sha256:{}\n",
                "a".repeat(64),
                "b".repeat(64)
            ),
            Kind::Requirements,
        )
        .unwrap();
        assert!(
            reqs[0].alternatives(),
            "a requirement's hashes are pip's alternatives"
        );
    }

    /// A package's line is 1-based, as a code-scanning UI counts them: the line its entry is
    /// written on, in every kind of file, and not the one before it.
    #[test]
    fn a_package_is_reported_on_the_line_its_entry_is_written_on() {
        let v3 = "{\n  \"lockfileVersion\": 3,\n  \"packages\": {\n    \"\": {},\n    \
                  \"node_modules/left-pad\": { \"version\": \"1.3.0\" }\n  }\n}\n";
        let v1 = "{\n  \"lockfileVersion\": 1,\n  \"dependencies\": {\n    \
                  \"left-pad\": { \"version\": \"1.3.0\" }\n  }\n}\n";
        let sbom = "{ \"packages\": [\n  { \"SPDXID\": \"SPDXRef-a\", \"name\": \"a\" },\n  \
                    { \"name\": \"b\", \"externalRefs\": [ { \"referenceType\": \"purl\",\n    \
                    \"referenceLocator\": \"pkg:npm/b@1.0.0\" } ] }\n] }\n";
        for (text, kind, want) in [
            (v3, Kind::NpmLock, vec![("pkg:npm/left-pad@1.3.0", 5)]),
            (v1, Kind::NpmLock, vec![("pkg:npm/left-pad@1.3.0", 4)]),
            (sbom, Kind::Spdx, vec![("", 2), ("pkg:npm/b@1.0.0", 4)]),
        ] {
            let got = parse(text, kind).expect("parse");
            let lines: Vec<(&str, usize)> =
                got.iter().map(|p| (p.purl.as_str(), p.line)).collect();
            assert_eq!(lines, want, "{text}");
        }
    }

    /// A package found by its SPDX id is found where the id is declared, not wherever the document
    /// first names it: a document may list `documentDescribes` above its packages, and that line
    /// is no package's, so a code-scanning UI pointed there points at nothing the finding is about.
    #[test]
    fn a_package_found_by_its_spdx_id_is_found_where_the_id_is_declared() {
        let text = r#"{
  "documentDescribes": [ "SPDXRef-a", "SPDXRef-b" ],
  "packages": [
    { "name": "vendored", "versionInfo": "1.0",
      "SPDXID": "SPDXRef-a" },
    { "name": "foo", "versionInfo": "2.0",
      "SPDXID" : "SPDXRef-b",
      "externalRefs": [ { "referenceType": "purl", "referenceLocator": "pkg:npm/foo" } ] },
    { "name": "split", "versionInfo": "3.0", "SPDXID":
      "SPDXRef-c" }
  ]
}"#;
        let got = parse(text, Kind::Spdx).expect("parse");
        let lines: Vec<(&str, usize)> = got.iter().map(|p| (p.name.as_str(), p.line)).collect();
        // The last writes its id's key and value on two lines, and is found by the line that
        // names it.
        assert_eq!(lines, [("split", 10), ("vendored", 5), ("foo", 7)]);
    }

    /// A package is reported on its own entry's line and never on another's, though another entry
    /// writes its purl too: two artifacts of one version are two packages, and a purl may begin
    /// another's (`pkg:npm/a@1.0` begins `pkg:npm/a@1.0.1`). The first line naming the purl was
    /// the other package's, and a code-scanning UI pointed there points at a package the finding
    /// is not about.
    #[test]
    fn a_package_whose_purl_another_entry_writes_is_reported_on_its_own_entry() {
        let text = r#"{
  "packages": [
    { "SPDXID": "SPDXRef-newer", "name": "a",
      "externalRefs": [ { "referenceType": "purl", "referenceLocator": "pkg:npm/a@1.0.1" } ] },
    { "SPDXID": "SPDXRef-older", "name": "a",
      "externalRefs": [ { "referenceType": "purl", "referenceLocator": "pkg:npm/a@1.0" } ] },
    { "SPDXID": "SPDXRef-registry", "name": "b",
      "externalRefs": [ { "referenceType": "purl", "referenceLocator": "pkg:npm/b@2.0.0" } ],
      "checksums": [ { "algorithm": "SHA256", "checksumValue": "aa" } ] },
    { "SPDXID": "SPDXRef-fork", "name": "b",
      "externalRefs": [ { "referenceType": "purl", "referenceLocator": "pkg:npm/b@2.0.0" } ],
      "checksums": [ { "algorithm": "SHA256", "checksumValue": "bb" } ] },
    { "name": "c",
      "externalRefs": [ { "referenceType": "purl", "referenceLocator": "pkg:npm/c@3.0.1" } ] },
    { "name": "c",
      "externalRefs": [ { "referenceType": "purl", "referenceLocator": "pkg:npm/c@3.0" } ] }
  ]
}"#;
        let got = parse(text, Kind::Spdx).expect("parse");
        // Each entry by its purl and its checksum, and the lines it is written on.
        let entries = [
            ("pkg:npm/a@1.0.1", "", 3..=4),
            ("pkg:npm/a@1.0", "", 5..=6),
            ("pkg:npm/b@2.0.0", "aa", 7..=9),
            ("pkg:npm/b@2.0.0", "bb", 10..=12),
            ("pkg:npm/c@3.0.1", "", 13..=14),
            ("pkg:npm/c@3.0", "", 15..=16),
        ];
        assert_eq!(got.len(), entries.len(), "{got:?}");
        for (purl, digest, lines) in entries {
            let p = got
                .iter()
                .find(|p| {
                    p.purl == purl && p.digests.first().map_or("", |d| d.value.as_str()) == digest
                })
                .unwrap_or_else(|| panic!("no {purl} {digest}: {got:?}"));
            assert!(
                lines.contains(&p.line),
                "{purl} {digest} is reported on line {}, outside its entry's {lines:?}",
                p.line
            );
        }
    }

    /// The terminal table's glyphs are the ones `docs/11-interfaces.md` §4 draws, never-checked's
    /// a `?` and not a blank, which reads as green; and no two statuses print the same label,
    /// since two printed alike are one row to a reader.
    #[test]
    fn every_status_prints_a_glyph_and_a_label_of_its_own() {
        let all = [
            Status::Reproduced,
            Status::Caveats,
            Status::Divergent,
            Status::Unsupported,
            Status::NeverChecked,
        ];
        let glyphs: Vec<&str> = all.iter().map(|s| s.glyph()).collect();
        assert_eq!(glyphs, ["✔", "◐", "✖", "⊘", "?"]);
        let labels: BTreeSet<&str> = all.iter().map(|s| s.label()).collect();
        assert_eq!(labels.len(), all.len(), "{labels:?}");
        assert!(labels.iter().all(|l| !l.trim().is_empty()), "{labels:?}");
        assert_eq!(Status::NeverChecked.label(), "never checked");
    }

    /// A `--hash` or an SBOM checksum that is not `<algorithm>:<hex>` names no digest, and is left
    /// out rather than kept as one: a package is looked up by what it declares, and a declaration
    /// that is not a digest, or is one under no algorithm, finds nothing or the wrong thing.
    #[test]
    fn a_declared_digest_that_is_not_hex_under_a_named_algorithm_is_left_out() {
        let a = "a".repeat(64);
        let got = parse(
            &format!(
                "x==1.0 --hash=sha256:not-hex --hash=:{a} --hash=sha256: --hash=sha256:{a}\n"
            ),
            Kind::Requirements,
        )
        .expect("parse");
        let kept: Vec<(&str, &str)> = got[0]
            .digests
            .iter()
            .map(|d| (d.algorithm.as_str(), d.value.as_str()))
            .collect();
        assert_eq!(kept, [("sha256", a.as_str())]);

        let got = parse(
            r#"{ "packages": [ { "name": "v", "versionInfo": "1", "checksums": [
                 { "algorithm": "SHA256", "checksumValue": "zz" },
                 { "algorithm": "", "checksumValue": "ab" },
                 { "algorithm": "SHA1", "checksumValue": "" },
                 { "algorithm": "SHA1", "checksumValue": "CD" } ] } ] }"#,
            Kind::Spdx,
        )
        .expect("parse");
        let kept: Vec<(&str, &str)> = got[0]
            .digests
            .iter()
            .map(|d| (d.algorithm.as_str(), d.value.as_str()))
            .collect();
        assert_eq!(kept, [("sha1", "cd")]);
    }

    /// A `#` begins a comment only at the start of a line or after whitespace, as pip reads one
    /// (`(^|\s+)#`). Inside a word it is part of the word, and what follows it is still read.
    #[test]
    fn a_hash_sign_inside_a_word_does_not_begin_a_comment() {
        let a = "a".repeat(64);
        let got = parse(
            &format!("x==1.0 --config-settings=a#b --hash=sha256:{a}\n"),
            Kind::Requirements,
        )
        .expect("parse");
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].purl, "pkg:pypi/x@1.0");
        assert_eq!(got[0].digests.len(), 1, "the hash after the `#` was cut: {got:?}");
    }

    /// Two packages an SBOM names without a purl are two packages unless nothing tells them apart:
    /// merged on a name alone, the answer for one would stand for the other, which nothing checked.
    #[test]
    fn packages_without_a_purl_are_merged_only_where_nothing_tells_them_apart() {
        let got = parse(
            r#"{ "packages": [
                 { "name": "vendored", "versionInfo": "1.0" },
                 { "name": "vendored", "versionInfo": "1.0" },
                 { "name": "vendored", "versionInfo": "2.0" },
                 { "name": "other", "versionInfo": "1.0" },
                 { "name": "vendored", "versionInfo": "1.0",
                   "checksums": [ { "algorithm": "SHA256", "checksumValue": "ab" } ] } ] }"#,
            Kind::Spdx,
        )
        .expect("parse");
        let rows: Vec<(&str, &str, usize)> = got
            .iter()
            .map(|p| (p.name.as_str(), p.version.as_str(), p.digests.len()))
            .collect();
        assert_eq!(
            rows,
            [
                ("other", "1.0", 0),
                ("vendored", "1.0", 0),
                ("vendored", "1.0", 1),
                ("vendored", "2.0", 0),
            ]
        );
        assert!(got.iter().all(|p| p.purl.is_empty()), "{got:?}");
    }
}
