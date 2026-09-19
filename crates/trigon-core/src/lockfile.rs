//! Reading a lockfile, and the five things that can be said about what it names.
//!
//! Lives here rather than beside either consumer because there are two: `trigon check` on the
//! command line and `POST /v1/check` in the management API. A lockfile parser written twice is two
//! answers to "what does this file depend on", and a seam with an implementation on each side of
//! it is the defect this tree keeps finding.
//!
//! **Parsing only.** Deciding what a *run* says about a package needs a `RunRecord`, which lives a
//! crate up; that mapping is `trigon_store::RunRecord::status`.

use std::path::Path;

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
    pub purl: String,
    pub name: String,
    pub version: String,
    /// 1-based line it was found on, so a code-scanning UI can point at it. 0 when unknown.
    pub line: usize,
}

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

    dedupe(out)
}

fn requirements(text: &str) -> Vec<Package> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        // Strip a comment, then an environment marker, then whitespace.
        let line = raw.split('#').next().unwrap_or("").trim();
        let line = line.split(';').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('-') {
            continue;
        }
        // Only `==` pins a version. `>=` names a range, and a range is not a thing we can have
        // checked: skipping it is honest, and it lands in `never checked` by being absent.
        let Some((name, version)) = line.split_once("==") else {
            continue;
        };
        // `name[extra]` — the extras do not change which artifact was published.
        let name = name.split('[').next().unwrap_or(name).trim();
        let version = version.trim();
        if name.is_empty() || version.is_empty() {
            continue;
        }
        out.push(Package {
            purl: format!("pkg:pypi/{name}@{version}"),
            name: name.to_string(),
            version: version.to_string(),
            line: i + 1,
        });
    }
    out.sort_by(|a, b| a.purl.cmp(&b.purl));
    out.dedup_by(|a, b| a.purl == b.purl);
    out
}

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
        // Prefer the purl an SBOM carries: it names the ecosystem, which a name and version alone
        // do not. Fall back to name+version only when we can tell the ecosystem another way.
        let purl = p
            .get("externalRefs")
            .and_then(|r| r.as_array())
            .and_then(|refs| {
                refs.iter()
                    .find(|r| r.get("referenceType").and_then(|t| t.as_str()) == Some("purl"))
                    .and_then(|r| r.get("referenceLocator").and_then(|l| l.as_str()))
            });
        let Some(purl) = purl else { continue };
        if !(purl.starts_with("pkg:npm/") || purl.starts_with("pkg:pypi/")) {
            continue;
        }
        let (name, version) = match purl.rsplit_once('@') {
            Some((head, v)) => (
                head.rsplit('/').next().unwrap_or(head).to_string(),
                v.to_string(),
            ),
            None => continue,
        };
        out.push(Package {
            purl: purl.to_string(),
            name,
            version,
            line: line_of(text, purl),
        });
    }
    dedupe(out)
}

fn dedupe(
    mut v: Vec<Package>,
) -> Result<Vec<Package>, LockfileError> {
    v.sort_by(|a, b| a.purl.cmp(&b.purl).then(a.line.cmp(&b.line)));
    v.dedup_by(|a, b| a.purl == b.purl);
    Ok(v)
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
    fn an_sbom_is_read_through_its_purls() {
        let p = tmp(
            "spdx",
            "x.spdx.json",
            r#"{ "packages": [
                 { "name": "left-pad", "externalRefs": [
                     { "referenceType": "purl", "referenceLocator": "pkg:npm/left-pad@1.3.0" } ] },
                 { "name": "openssl", "externalRefs": [
                     { "referenceType": "purl", "referenceLocator": "pkg:deb/openssl@3" } ] },
                 { "name": "no-refs" } ] }"#,
        );
        let purls: Vec<String> = read(&p)
            .expect("parse")
            .into_iter()
            .map(|p| p.purl)
            .collect();
        // The ecosystems this can rebuild, and nothing else: a deb is not a thing we check, and
        // listing it as `never checked` would imply we might.
        assert_eq!(purls, ["pkg:npm/left-pad@1.3.0"]);
    }

}
