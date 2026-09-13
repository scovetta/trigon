//! npm.
//!
//! The useful thing npm gives us for free is `gitHead`: the commit the publisher's working tree
//! was at. That is the resolver's top rung and it arrives in the same request as the tarball URL,
//! which makes source discovery for most of npm a lookup rather than a search.
//!
//! It is also not proof. `gitHead` is whatever the publishing client reported, so a rebuild from it
//! that matches is evidence the artifact corresponds to that commit, and a rebuild that does not
//! match is not evidence the publisher lied. The framing matters for npm in particular: tarballs
//! are close to universally reproducible at the byte level and carry no source linkage, so the
//! question worth answering is not "does it rebuild" but "does the published tarball correspond to
//! the claimed source".

use async_trait::async_trait;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use trigon_core::{
    ArtifactId, Claim, Confidence, Digest, Ecosystem, Evidence, Intrinsics, RegistryMoment,
    SourceDiscovery, SourceProvenance, TargetRef,
};

use crate::client::Client;
use crate::error::RegistryError;
use crate::model::{ArtifactMeta, BlobSink, ResolvedTarget};
use crate::registry::Registry;

const ECO: &str = "npm";

pub struct NpmRegistry {
    client: Client,
    base: String,
}

impl NpmRegistry {
    pub fn new(client: Client) -> Self {
        NpmRegistry {
            client,
            base: "https://registry.npmjs.org".into(),
        }
    }

    /// Point at a different registry, which is how the time-filtering mirror gets used.
    pub fn with_base(mut self, base: impl Into<String>) -> Self {
        self.base = base.into().trim_end_matches('/').to_string();
        self
    }
}

#[async_trait]
impl Registry for NpmRegistry {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }

    async fn resolve(&self, target: &TargetRef) -> Result<ResolvedTarget, RegistryError> {
        let name = target.registry_name();
        // The version document rather than the full packument. A popular package's packument is
        // megabytes of every version ever published, and we want one.
        let url = format!("{}/{}/{}", self.base, encode(&name), target.version);
        let doc: Value = match self.client.get(&url, ECO).await {
            Ok(r) => r.json().await?,
            Err(RegistryError::Http { status: 404, .. }) => {
                return Err(self.not_found(target).await);
            }
            Err(e) => return Err(e),
        };

        let dist = doc.get("dist").ok_or_else(|| RegistryError::Malformed {
            ecosystem: ECO.into(),
            what: format!("{name}@{}", target.version),
            detail: "no `dist` block".into(),
        })?;
        let url = dist
            .get("tarball")
            .and_then(Value::as_str)
            .ok_or_else(|| RegistryError::Malformed {
                ecosystem: ECO.into(),
                what: format!("{name}@{}", target.version),
                detail: "no `dist.tarball`".into(),
            })?
            .to_string();

        let file = url.rsplit('/').next().unwrap_or("artifact.tgz").to_string();
        let artifact = ArtifactMeta {
            id: ArtifactId::new(file),
            url,
            // npm publishes sha1 in `dist.shasum` and, for newer entries, a subresource-integrity
            // string that is usually sha512. Neither is sha256, so there is nothing to compare the
            // computed digest against, and saying so beats a check that always passes.
            declared_sha256: integrity_sha256(dist),
            size: dist.get("unpackedSize").and_then(Value::as_u64),
        };

        let publish_time = self.publish_time(&name, &target.version).await;
        let mut evidence = Vec::new();
        let mut source = None;

        if let Some(repo) = repo_url(&doc) {
            evidence.push(Evidence::new(
                Claim::RepoIs { url: repo.clone() },
                Confidence::Strong,
                "npm:package.json:repository",
            ));
            if let Some(commit) = doc.get("gitHead").and_then(Value::as_str) {
                source = Some(SourceProvenance {
                    repo_url: repo,
                    commit: commit.to_string(),
                    ref_name: None,
                    subdir: None,
                    how: SourceDiscovery::RegistryCommit,
                });
            }
        }
        if let Some(t) = &publish_time {
            evidence.push(Evidence::new(
                Claim::RegistryMomentIs {
                    moment: RegistryMoment::Timestamp { rfc3339: t.clone() },
                },
                Confidence::Certain,
                "npm:time",
            ));
        }

        // The toolchain the publisher actually used, recorded by the registry at publish time.
        // Certain, because this is not an inference: it is what the publishing client reported.
        // It is also the difference between npm inference being a transcription and a guess, since
        // a 2026 npm packs a tarball a 2018 npm would not have.
        for (field, tool, source) in [
            ("_nodeVersion", "node", "npm:_nodeVersion"),
            ("_npmVersion", "npm", "npm:_npmVersion"),
        ] {
            if let Some(v) = doc.get(field).and_then(Value::as_str) {
                evidence.push(Evidence::new(
                    Claim::ToolchainExact {
                        tool: tool.into(),
                        version: v.to_string(),
                    },
                    Confidence::Certain,
                    source,
                ));
            }
        }

        // A build step nothing in the recipe will run.
        //
        // `docs/07-ai.md` calls this `needs-build-inference`, and until now it was a label on a
        // corpus rather than something the system could see: the registry's version document
        // carries `scripts`, and this resolver was discarding it.
        if let Some((name, command)) = unrun_build_script(&doc) {
            evidence.push(Evidence::new(
                Claim::UnrunScript { name, command },
                Confidence::Certain,
                "npm:scripts",
            ));
        }

        Ok(ResolvedTarget {
            reference: target.clone(),
            artifacts: vec![artifact],
            intrinsics: Intrinsics {
                publish_time: publish_time.clone(),
                declared_repo: repo_url(&doc),
                registry_moment: publish_time.map(|rfc3339| RegistryMoment::Timestamp { rfc3339 }),
                evidence,
            },
            source,
        })
    }

    async fn fetch(
        &self,
        meta: &ArtifactMeta,
        sink: &mut (dyn BlobSink + Send),
    ) -> Result<Digest, RegistryError> {
        fetch_verified(&self.client, ECO, meta, sink).await
    }
}

impl NpmRegistry {
    /// Turn a 404 into a message that says whether the package or the version is missing.
    async fn not_found(&self, target: &TargetRef) -> RegistryError {
        let name = target.registry_name();
        let url = format!("{}/{}", self.base, encode(&name));
        let Ok(resp) = self.client.get(&url, ECO).await else {
            return RegistryError::NoSuchPackage {
                ecosystem: ECO.into(),
                name,
            };
        };
        let Ok(doc) = resp.json::<Value>().await else {
            return RegistryError::NoSuchPackage {
                ecosystem: ECO.into(),
                name,
            };
        };
        let mut available: Vec<String> = doc
            .get("versions")
            .and_then(Value::as_object)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();
        available.sort();
        RegistryError::NoSuchVersion {
            ecosystem: ECO.into(),
            name,
            version: target.version.clone(),
            available,
        }
    }

    /// The publish timestamp, from the packument's `time` map.
    ///
    /// Best effort: this is a second request and a package whose metadata omits it is unusual but
    /// not broken. Absent means we cannot pin the registry moment, which is a caveat on the
    /// verdict rather than a reason to refuse.
    async fn publish_time(&self, name: &str, version: &str) -> Option<String> {
        let url = format!("{}/{}", self.base, encode(name));
        let doc: Value = self.client.get(&url, ECO).await.ok()?.json().await.ok()?;
        doc.get("time")?.get(version)?.as_str().map(str::to_owned)
    }
}

fn repo_url(doc: &Value) -> Option<String> {
    let repo = doc.get("repository")?;
    let raw = repo
        .as_str()
        .or_else(|| repo.get("url").and_then(Value::as_str))?;
    Some(canonicalize_repo(raw))
}

/// Normalize the many spellings of a GitHub URL into one clonable HTTPS form.
///
/// package.json carries `git+ssh://git@github.com/a/b.git`, `git://github.com/a/b`, `github:a/b`
/// and plain `a/b`. Left alone, the first would have us clone over SSH with credentials we do not
/// have, and the cache would hold four entries for one repository.
pub(crate) fn canonicalize_repo(raw: &str) -> String {
    let s = raw.trim();
    let s = s.strip_prefix("git+").unwrap_or(s);
    let s = s.strip_suffix(".git").unwrap_or(s);
    if let Some(rest) = s.strip_prefix("github:") {
        return format!("https://github.com/{rest}");
    }
    if let Some(rest) = s.strip_prefix("git@github.com:") {
        return format!("https://github.com/{rest}");
    }
    if let Some(rest) = s.strip_prefix("ssh://git@github.com/") {
        return format!("https://github.com/{rest}");
    }
    if let Some(rest) = s.strip_prefix("git://github.com/") {
        return format!("https://github.com/{rest}");
    }
    if s.starts_with("http://") || s.starts_with("https://") {
        return s.replace("http://", "https://");
    }
    // A bare `owner/repo`, which npm accepts and means GitHub by convention.
    if s.split('/').count() == 2 && !s.contains(' ') && !s.contains(':') {
        return format!("https://github.com/{s}");
    }
    s.to_string()
}

/// A sha256 out of npm's subresource-integrity string, when it happens to be one.
fn integrity_sha256(dist: &Value) -> Option<Digest> {
    let integrity = dist.get("integrity").and_then(Value::as_str)?;
    let b64 = integrity.strip_prefix("sha256-")?;
    let bytes = base64_decode(b64)?;
    Some(Digest::from_bytes(
        <[u8; 32]>::try_from(bytes.as_slice()).ok()?,
    ))
}

/// Enough base64 to read an integrity string. Standard alphabet, padding optional.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in s.bytes().filter(|c| *c != b'=') {
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

/// Percent-encode the one character that matters: the `/` in a scoped name.
fn encode(name: &str) -> String {
    name.replace('/', "%2f")
}

/// Stream an artifact, hashing as it goes, and check the result against what was declared.
pub(crate) async fn fetch_verified(
    client: &Client,
    ecosystem: &str,
    meta: &ArtifactMeta,
    sink: &mut (dyn BlobSink + Send),
) -> Result<Digest, RegistryError> {
    let mut response = client.get(&meta.url, ecosystem).await?;
    let mut hasher = Sha256::new();
    let mut bytes = 0u64;

    // Streamed rather than buffered: an artifact can be gigabytes, and a worker that holds one in
    // memory to hash it has a memory profile indistinguishable from a build failure.
    while let Some(chunk) = response.chunk().await? {
        hasher.update(&chunk);
        sink.write(&chunk)?;
        bytes += chunk.len() as u64;
    }
    let actual = Digest::from_bytes(hasher.finalize().into());

    if let Some(expected) = &meta.declared_sha256
        && *expected != actual
    {
        return Err(RegistryError::DigestMismatch {
            name: meta.id.to_string(),
            artifact: meta.id.to_string(),
            expected: expected.to_string(),
            actual: actual.to_string(),
        });
    }
    tracing::debug!(
        artifact = %meta.id,
        bytes,
        sha256 = %actual,
        verified = meta.declared_sha256.is_some(),
        "fetched"
    );
    Ok(actual)
}

/// A build this package declares and its packaging tool will not run.
///
/// Returns the script name and its command, or `None` — and `None` is the common and correct
/// answer. Every condition below exists to make the claim mean exactly one thing: *`npm pack` will
/// produce a tarball missing whatever this script would have written*.
///
/// 1. A `build` script, and only that name. `compile` and `bundle` are the same semantic class and
///    are not conventional enough to assume; a docs build and a deploy answer to those names too.
///    Narrow first, and widen on a measurement rather than on an argument.
/// 2. **No** `prepare`, `prepack`, `prepublish` or `prepublishOnly` declared at all. Not "none that
///    this npm runs" — none at all. A package that declares one builds at pack time under some npm,
///    and a separate `build` script alongside it is probably a different job. Requiring all four
///    absent also means the claim holds under *every* npm version, so there is no lifecycle
///    boundary to get wrong for a package published in 2017.
/// 3. No `install`, `preinstall` or `postinstall`. That is node-gyp, which compiles, and whatever
///    it downloads while doing so.
/// 4. The command's first token is a key of `dependencies` or `devDependencies`. `npm install` has
///    therefore already put it in `node_modules/.bin`, so nothing that acts on this claim needs a
///    socket the dependency phase did not already open.
///
/// What it deliberately does not say is whether running the script is a good idea. That is the
/// question a rung answers with the repository in hand; this is the fact it answers it from.
fn unrun_build_script(doc: &Value) -> Option<(String, String)> {
    let scripts = doc.get("scripts")?.as_object()?;
    const PACK_HOOKS: &[&str] = &["prepare", "prepack", "prepublish", "prepublishOnly"];
    const INSTALL_HOOKS: &[&str] = &["install", "preinstall", "postinstall"];
    if PACK_HOOKS
        .iter()
        .chain(INSTALL_HOOKS)
        .any(|h| scripts.contains_key(*h))
    {
        return None;
    }
    let command = scripts.get("build")?.as_str()?.trim();
    let program = command.split_whitespace().next()?;
    let declared = |field: &str| {
        doc.get(field)
            .and_then(Value::as_object)
            .is_some_and(|d| d.contains_key(program))
    };
    if !declared("devDependencies") && !declared("dependencies") {
        return None;
    }
    Some(("build".to_string(), command.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(v: serde_json::Value) -> Option<(String, String)> {
        unrun_build_script(&v)
    }

    #[test]
    fn a_build_nothing_will_run_is_recorded_as_evidence() {
        // escalade 3.2.0's real manifest. `npm pack` runs neither `build` nor `pretest`, so the
        // published `dist/` is output no rebuild of the plain recipe can contain — the whole
        // content of the `needs-build-inference` label, and invisible to every rung until the
        // resolver stopped discarding `scripts`.
        let got = doc(serde_json::json!({
            "scripts": {
                "build": "bundt",
                "pretest": "npm run build",
                "test": "uvu -r esm test -i fixtures",
            },
            "devDependencies": { "bundt": "1.1.1", "uvu": "0.5.6" },
        }));
        assert_eq!(got, Some(("build".into(), "bundt".into())));
    }

    #[test]
    fn a_package_that_builds_at_pack_time_is_not_claimed() {
        // The distinction the claim rests on. This package builds and `npm pack` builds it, so a
        // rebuild is missing nothing.
        for hook in ["prepare", "prepack", "prepublish", "prepublishOnly"] {
            let got = doc(serde_json::json!({
                "scripts": { "build": "tsc", hook: "npm run build" },
                "devDependencies": { "tsc": "2.0.0" },
            }));
            assert_eq!(
                got, None,
                "a declared `{hook}` means something already builds"
            );
        }
    }

    #[test]
    fn a_native_package_is_left_alone() {
        // node-gyp compiles, and downloads a toolchain while doing it. Whatever this package needs,
        // it is not a rung guessing that `npm run build` is the missing step.
        let got = doc(serde_json::json!({
            "scripts": { "build": "node-gyp rebuild", "install": "node-gyp rebuild" },
            "devDependencies": { "node-gyp": "10.0.0" },
        }));
        assert_eq!(got, None);
    }

    #[test]
    fn a_build_tool_the_package_did_not_declare_is_not_claimed() {
        // `chokidar` is the real case: its build script is `tsc`, a bare token, but the package it
        // comes from is `typescript`, so `npm install` does not put it in `node_modules/.bin`.
        // Anything acting on this claim would have to fetch it, which is a socket the dependency
        // phase did not open. A real miss, and the right way to miss.
        let got = doc(serde_json::json!({
            "scripts": { "build": "tsc" },
            "devDependencies": { "typescript": "5.0.0" },
        }));
        assert_eq!(got, None);

        // Declared as a direct dependency rather than a dev one is just as good: it is installed.
        let got = doc(serde_json::json!({
            "scripts": { "build": "rollup -c" },
            "dependencies": { "rollup": "4.0.0" },
        }));
        assert_eq!(got, Some(("build".into(), "rollup -c".into())));
    }

    #[test]
    fn a_package_with_no_build_says_nothing() {
        assert_eq!(
            doc(serde_json::json!({ "scripts": { "test": "mocha" } })),
            None
        );
        assert_eq!(doc(serde_json::json!({})), None);
        // Present but empty, or not a string: absent, not a claim about an empty command.
        assert_eq!(doc(serde_json::json!({ "scripts": { "build": "" } })), None);
        assert_eq!(doc(serde_json::json!({ "scripts": { "build": 7 } })), None);
    }
}
