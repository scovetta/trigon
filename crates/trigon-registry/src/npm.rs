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
use serde_json::{Map, Value};
use trigon_core::{
    ArtifactId, Claim, Confidence, DeclaredDigest, Ecosystem, Evidence, Intrinsics, RegistryMoment,
    SourceDiscovery, SourceProvenance, TargetRef,
};

use crate::client::Client;
use crate::declared::fetch_verified;
use crate::error::RegistryError;
use crate::model::{ArtifactMeta, BlobSink, Fetched, ResolvedTarget};
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
        let (declared, declared_note) =
            declared_digests(dist).map_err(|detail| RegistryError::Malformed {
                ecosystem: ECO.into(),
                what: format!("{name}@{}", target.version),
                detail,
            })?;
        let artifact = ArtifactMeta {
            id: ArtifactId::new(file),
            url,
            declared,
            declared_note,
            size: dist.get("unpackedSize").and_then(Value::as_u64),
        };

        let publish_time = self.publish_time(&name, &target.version).await;
        let mut evidence = Vec::new();
        let mut source = None;

        if let Some((repo, declared)) = repo_url(&doc) {
            evidence.push(Evidence::new(
                Claim::RepoIs { url: repo.clone() },
                Confidence::Strong,
                "npm:package.json:repository",
            ));
            // **A repository with no commit is still a source location.** `gitHead` is written by
            // the publishing client and the tools that publish monorepos mostly do not write it —
            // `@babel/core` and `@vue/reactivity` carry `repository.directory` and no `gitHead`.
            // Returning `None` here made the inferrer decline in a second and the target report
            // `no-strategy`, which says we could not infer a recipe when what happened is that the
            // registry did not record a commit. The rung resolves the version's tag instead.
            let commit = doc.get("gitHead").and_then(Value::as_str);
            source = Some(SourceProvenance {
                declared_url: (declared != repo).then(|| declared.clone()),
                repo_url: repo,
                commit: commit.unwrap_or_default().to_string(),
                ref_name: None,
                subdir: repo_subdir(&doc),
                how: match commit {
                    Some(_) => SourceDiscovery::RegistryCommit,
                    // The registry told us the repository and not the commit. Overwritten by
                    // whatever the tag rung finds, so this is never the discovery a verdict
                    // carries — it says only where the *repository* came from.
                    None => SourceDiscovery::RegistryMetadata,
                },
            });
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
                declared_repo: repo_url(&doc).map(|(canonical, _)| canonical),
                registry_moment: publish_time.map(|rfc3339| RegistryMoment::Timestamp { rfc3339 }),
                evidence,
            },
            source,
            about: None,
        })
    }

    async fn fetch(
        &self,
        meta: &ArtifactMeta,
        sink: &mut (dyn BlobSink + Send),
    ) -> Result<Fetched, RegistryError> {
        fetch_verified(&self.client, ECO, meta, sink).await
    }
}

/// Every digest npm declares for a version's tarball.
///
/// `dist.integrity` is a Subresource Integrity string — sha512 for anything published since
/// 2017, `sha1-` before that — and `dist.shasum` is the tarball's sha1 in hex, on every version.
/// **Neither is sha256**, and this used to read a `sha256-` integrity string alone, which npm never
/// sends: so every npm download was checked against nothing, and the code said it was careful.
///
/// Both fields are kept, each as its own declaration: they are two claims, and an old entry that
/// carries `sha1-` in both is two chances to find that one of them is wrong.
fn declared_digests(dist: &Value) -> Result<(Vec<DeclaredDigest>, Option<String>), String> {
    let mut out = Vec::new();
    if let Some(integrity) = dist.get("integrity").and_then(Value::as_str) {
        out.extend(crate::declared::sri(integrity, "npm:dist.integrity")?);
    }
    if let Some(shasum) = dist.get("shasum").and_then(Value::as_str) {
        let sha1 = crate::declared::from_hex("sha1", shasum, "npm:dist.shasum")?;
        out.push(sha1);
    }
    let note = out.is_empty().then(|| {
        "npm declared neither `dist.integrity` nor `dist.shasum` for this version, so the \
         tarball was checked against nothing"
            .to_string()
    });
    Ok((out, note))
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

/// The repository, and the string the package actually declared.
///
/// Both, because canonicalizing is lossy and the canonical form is what everything downstream sees.
/// `git+ssh://git@github.com/a/b.git`, `github:a/b` and a `tree/` URL all collapse to the same
/// `https://github.com/a/b`, and a record holding only the result cannot be checked against what
/// the package said. See [`SourceProvenance::declared_url`].
fn repo_url(doc: &Value) -> Option<(String, String)> {
    let repo = doc.get("repository")?;
    let raw = repo
        .as_str()
        .or_else(|| repo.get("url").and_then(Value::as_str))?;
    Some((canonicalize_repo(raw), raw.to_string()))
}

/// Where in the repository this package lives, from `repository.directory`.
///
/// **npm's own answer to the monorepo question, and we were ignoring it.** `@babel/core` says
/// `packages/babel-core`; `@typescript-eslint/parser` says `packages/parser`. Without it a rebuild
/// checks out the repository and builds at the root, which for a monorepo member is a different
/// package — it fails on `Unsupported URL Type "workspace:"` when npm meets a sibling dependency,
/// or it packs the wrong thing. Four of the M1 npm corpus's twenty-three unnamed failures were
/// this, and the monorepo stratum exists to surface it.
///
/// `SourceProvenance::subdir` has been plumbed to the strategy's `Location` and its `output_path`
/// the whole time ([`crate::heuristic`]); nothing ever set it. A field that is threaded through
/// three layers and always `None` is the dead configuration `docs/16-findings.md` §3.15 is about.
///
/// Refused rather than trusted where it is not a plain relative path: this value reaches a shell
/// command line through the rendered strategy, and `..` or a leading `/` in it is a package's
/// metadata choosing a directory outside the checkout.
fn repo_subdir(doc: &Value) -> Option<String> {
    let raw = doc
        .get("repository")?
        .get("directory")
        .and_then(Value::as_str)?
        .trim()
        .trim_matches('/');
    let safe = !raw.is_empty()
        && !raw.starts_with('-')
        && raw
            .split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
        && !raw.contains(char::is_whitespace)
        && !raw.contains('\0');
    safe.then(|| raw.to_string())
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
        return trim_to_repo(&s.replace("http://", "https://"));
    }
    // A bare `owner/repo`, which npm accepts and means GitHub by convention.
    if s.split('/').count() == 2 && !s.contains(' ') && !s.contains(':') {
        return format!("https://github.com/{s}");
    }
    s.to_string()
}

/// Cut a forge URL back to the repository it names.
///
/// Registry metadata routinely carries a link to a *file* where a repository is asked for —
/// `tomli`'s PyPI entry gives `https://github.com/hukkin/tomli/blob/master/CHANGELOG.md`, because
/// the project listed its changelog under a key we read as the source. Cloning that fails with
/// `fatal: unable to access …`, which reads as a network problem and cost a target on every corpus
/// run.
///
/// Cut at the first path segment no repository has. The segments are forge routes rather than a
/// guess about names: everything before `/blob/`, `/tree/`, `/raw/`, `/blame/`, `/commit/`,
/// `/releases/`, `/issues/`, `/wiki/` or `/-/` is the repository and everything after is a view of
/// it. GitLab's `/-/` covers its whole family in one.
///
/// Conservative in the direction that matters: a URL with none of these is returned untouched, so
/// an unfamiliar forge is left alone rather than truncated to something that does not exist.
fn trim_to_repo(url: &str) -> String {
    // The segment names a view of a repository rather than part of its path. Written without
    // slashes and matched as whole segments, because the first version wrote them as `"/issues/"`
    // and so only matched a view with something *after* it: `…/python-engineio/issues` — which is
    // what PyPI's `project_urls` actually contains — went untrimmed and was cloned as a repository.
    // Fifteen of fifty targets came back `no-strategy` and this was most of them.
    const VIEWS: &[&str] = &[
        "blob",
        "tree",
        "raw",
        "blame",
        "commit",
        "commits",
        "releases",
        "release",
        "issues",
        "pull",
        "pulls",
        "wiki",
        "tags",
        "compare",
        "archive",
        "tarball",
        "zipball",
        "discussions",
        "actions",
        "-",
    ];
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.trim_end_matches('/').to_string();
    };
    let mut kept: Vec<&str> = Vec::new();
    for (i, seg) in rest.split('/').filter(|s| !s.is_empty()).enumerate() {
        // The first three segments are host, owner and repository: a view can only appear after
        // them, and `github.com/tree/x` is a repository called `x` owned by someone called `tree`.
        if i >= 3 && VIEWS.contains(&seg) {
            break;
        }
        kept.push(seg);
    }
    format!("{scheme}://{}", kept.join("/"))
}

/// The subdirectory a forge URL points into, when it points into one.
///
/// **PyPI has no `repository.directory`**, so a monorepo member has nowhere to declare where it
/// lives — except that its own `project_urls` often say it in passing:
/// `github.com/googleapis/google-cloud-python/tree/main/packages/google-auth` names the branch and
/// the path. Everything after `tree/<ref>/` is that path.
///
/// Refused on the same terms as npm's `repository.directory`: this reaches a shell command line, so
/// `..`, a leading dash and empty segments are not trusted.
pub(crate) fn subdir_from_view(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let segs: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    // host / owner / repo / tree / ref / path…
    //
    // `tree` only. A `blob` link names a *file*, and reading `…/tomli/blob/master/CHANGELOG.md`
    // as a subdirectory would send the build into a changelog.
    let at = segs.iter().skip(3).position(|s| *s == "tree")? + 3;
    let path: Vec<&str> = segs.get(at + 2..)?.to_vec();
    if path.is_empty() {
        return None;
    }
    let joined = path.join("/");
    let safe = !joined.starts_with('-')
        && path
            .iter()
            .all(|s| *s != "." && *s != ".." && !s.contains(char::is_whitespace));
    safe.then_some(joined)
}

/// Percent-encode the one character that matters: the `/` in a scoped name.
fn encode(name: &str) -> String {
    name.replace('/', "%2f")
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
/// 2. **No** `prepare`, `prepack` or `prepublish` declared. Not "none that this npm runs" — none at
///    all. A package that declares one builds at pack time under some npm, and a separate `build`
///    script alongside it is probably a different job. `prepublish` stays on this list even though
///    modern npm runs it on *install* rather than publish, because npm 4 and earlier did run it at
///    publish time and a package from 2017 is exactly the case this conservatism is for.
///
///    **`prepublishOnly` came off it, and that is a correction.** The rule was written to hold
///    under every npm version, and for this hook that argument runs the other way: the name means
///    what it says, `npm pack` has never run it, and npm 11.16.0 confirms it — a package declaring
///    all four hooks packs the output of `prepack` and `prepare` and neither of the other two. So a
///    package whose build hangs off `prepublishOnly` publishes output no `npm pack` can contain,
///    which is precisely the claim this function exists to make. It was suppressing the claim
///    instead. Measured cost: 13 of 16 divergences in the npm TypeScript and monorepo strata, every
///    one of them "every shared file byte-identical, compiled output missing entirely".
/// 3. No `install`, `preinstall` or `postinstall`. That is node-gyp, which compiles, and whatever
///    it downloads while doing so.
/// 4. The command reaches a program the dependency phase already installed — its first token is a
///    key of `dependencies` or `devDependencies`, so `npm install` has put it in
///    `node_modules/.bin` and nothing acting on this claim needs a socket that phase did not open.
///
///    **A package manager counts as available**, and one level of `npm run <script>` is resolved
///    before the check. The commonest shape in this ecosystem is composite —
///    `npm run clean && npm run compile && npm run lint` — whose first token is `npm`, which no
///    package declares as a dependency of itself. Checking that token rejected every such package:
///    `fast-glob`, `marked`, `@tanstack/react-query` and `@typescript-eslint/parser` in one corpus
///    sample.
///
/// What it deliberately does not say is whether running the script is a good idea. That is the
/// question a rung answers with the repository in hand; this is the fact it answers it from.
fn unrun_build_script(doc: &Value) -> Option<(String, String)> {
    let scripts = doc.get("scripts")?.as_object()?;
    const PACK_HOOKS: &[&str] = &["prepare", "prepack", "prepublish"];
    const INSTALL_HOOKS: &[&str] = &["install", "preinstall", "postinstall"];
    if PACK_HOOKS
        .iter()
        .chain(INSTALL_HOOKS)
        .any(|h| scripts.contains_key(*h))
    {
        return None;
    }
    // `prepublishOnly` first, because where both exist it is the one the publisher ran: it wraps
    // the build and `npm pack` runs neither.
    let (name, command) = ["prepublishOnly", "build"]
        .iter()
        .find_map(|n| Some((*n, scripts.get(*n)?.as_str()?.trim())))?;
    if command.is_empty() {
        return None;
    }
    reaches_an_installed_program(doc, scripts, command)
        .then(|| (name.to_string(), command.to_string()))
}

/// Whether this command's first real program is one the dependency phase will have installed.
///
/// One level of `npm run <script>` is followed, because the first token of a composite command is
/// the package manager rather than a tool — and the package manager is always there. Only one
/// level: a script that runs a script that runs a script is a shape worth declining on rather than
/// chasing, and the recursion would need a cycle check for no measured benefit.
fn reaches_an_installed_program(doc: &Value, scripts: &Map<String, Value>, command: &str) -> bool {
    // The runners themselves. `npm pack` will have `npm` and `npx`; `node` is the interpreter the
    // toolchain phase installed. A package declaring any of these as a *dependency* is unusual and
    // is still covered by the `declared` check below.
    const RUNNERS: &[&str] = &["npm", "npx", "yarn", "pnpm", "bun", "node"];

    let first = command.split_whitespace().next().unwrap_or_default();
    let declared = |program: &str| {
        ["devDependencies", "dependencies"].iter().any(|field| {
            doc.get(field)
                .and_then(Value::as_object)
                .is_some_and(|d| d.contains_key(program))
        })
    };
    if declared(first) {
        return true;
    }
    if !RUNNERS.contains(&first) {
        return false;
    }
    // `<runner> run <script>` — follow it once, to whatever that script's own first token is.
    let mut parts = command.split_whitespace();
    let referenced = match (parts.next(), parts.next(), parts.next()) {
        (Some(_), Some("run"), Some(script)) => script,
        // `npm test`, `yarn build` and friends name the script directly.
        (Some(_), Some(script), _) if scripts.contains_key(script) => script,
        _ => return true, // a bare runner invocation, which will run
    };
    match scripts.get(referenced).and_then(Value::as_str) {
        Some(inner) => {
            let program = inner.split_whitespace().next().unwrap_or_default();
            declared(program) || RUNNERS.contains(&program)
        }
        // A script the manifest does not define. `npm run` would fail, so claiming it builds
        // anything would be worse than saying nothing.
        None => false,
    }
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
        //
        // `prepublish` is here despite modern npm running it on *install* rather than publish:
        // npm 4 and earlier did run it at publish time, and a package from 2017 is the case this
        // conservatism exists for.
        for hook in ["prepare", "prepack", "prepublish"] {
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
    fn prepublish_only_is_the_one_hook_the_packer_does_not_run() {
        // **Measured, not read.** A package declaring all four hooks, packed with npm 11.16.0,
        // contains the output of `prepack` and `prepare` and nothing from `prepublish` or
        // `prepublishOnly`. The name means what it says.
        //
        // This test used to assert the opposite, in a loop with the three above, under a comment
        // that said "`npm pack` builds it". That was true of three of the four, and the fourth cost
        // 13 of 16 divergences in the npm TypeScript and monorepo strata — every one of them with
        // every shared file byte-identical and the compiled output missing entirely.
        let got = doc(serde_json::json!({
            "scripts": { "build": "tsc", "prepublishOnly": "npm run build" },
            "devDependencies": { "tsc": "2.0.0" },
        }));
        assert_eq!(
            got,
            Some(("prepublishOnly".into(), "npm run build".into())),
            "the hook the publisher ran and the packer will not"
        );

        // And it is preferred over `build` where both exist, because it is the one that ran.
        let wrapped = doc(serde_json::json!({
            "scripts": { "build": "tsc", "prepublishOnly": "npm run build && npm run docs" },
            "devDependencies": { "tsc": "2.0.0" },
        }));
        assert_eq!(wrapped.unwrap().1, "npm run build && npm run docs");
    }

    #[test]
    fn a_composite_command_is_followed_to_a_real_program() {
        // The commonest shape in this ecosystem, and the first token is never a dependency:
        // `fast-glob`, `marked`, `@tanstack/react-query` and `@typescript-eslint/parser` all look
        // like this, and all four were rejected for it.
        let got = doc(serde_json::json!({
            "scripts": {
                "build": "npm run clean && npm run compile",
                "clean": "rimraf out",
                "compile": "tsc",
            },
            "devDependencies": { "tsc": "2.0.0", "rimraf": "5.0.0" },
        }));
        assert_eq!(got.unwrap().1, "npm run clean && npm run compile");

        // pnpm and yarn name the script without `run`.
        let pnpm = doc(serde_json::json!({
            "scripts": { "build": "pnpm compile", "compile": "tsc" },
            "devDependencies": { "tsc": "2.0.0" },
        }));
        assert!(pnpm.is_some(), "pnpm <script> is the same shape");
    }

    #[test]
    fn a_runner_pointing_at_nothing_is_not_a_build() {
        // `npm run` a script the manifest does not define would fail, so claiming it builds
        // anything is worse than saying nothing — and following it is how a typo in a manifest
        // would otherwise become a confident recipe.
        let got = doc(serde_json::json!({
            "scripts": { "build": "npm run compile" },
            "devDependencies": { "tsc": "2.0.0" },
        }));
        assert_eq!(got, None);

        // And a program that is neither declared nor a runner stays rejected, which is the check
        // this widening must not have removed.
        let unknown = doc(serde_json::json!({
            "scripts": { "build": "rollup -c" },
            "devDependencies": { "tsc": "2.0.0" },
        }));
        assert_eq!(unknown, None);
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

    #[test]
    fn a_link_to_a_file_in_a_repository_is_cut_back_to_the_repository() {
        // Registry metadata routinely gives a link to a *file* where a repository is asked for.
        // `tomli`'s PyPI entry is `https://github.com/hukkin/tomli/blob/master/CHANGELOG.md`, and
        // cloning that fails with `fatal: unable to access …` — which reads as a network problem,
        // clustered with one, and cost a target on every corpus run.
        let c = super::canonicalize_repo;
        assert_eq!(
            c("https://github.com/hukkin/tomli/blob/master/CHANGELOG.md"),
            "https://github.com/hukkin/tomli"
        );
        assert_eq!(
            c("https://github.com/certifi/python-certifi/tree/master/certifi"),
            "https://github.com/certifi/python-certifi"
        );
        // GitLab routes every view through `/-/`, so one entry covers the family.
        assert_eq!(
            c("https://gitlab.com/a/b/-/blob/main/README.md"),
            "https://gitlab.com/a/b"
        );

        // Untouched where there is nothing to cut, including a forge nobody taught it about: an
        // unfamiliar URL is left alone rather than truncated to something that does not exist.
        assert_eq!(
            c("https://github.com/hukkin/tomli"),
            "https://github.com/hukkin/tomli"
        );
        assert_eq!(
            c("https://codeberg.org/owner/repo"),
            "https://codeberg.org/owner/repo"
        );
        // And the shorthands still work, since they never reach the trimmer.
        assert_eq!(c("github:a/b"), "https://github.com/a/b");
        assert_eq!(c("git@github.com:a/b.git"), "https://github.com/a/b");
    }
}

#[cfg(test)]
mod canonical_repo_tests {
    use super::canonicalize_repo;

    #[test]
    fn every_spelling_package_json_uses_for_a_github_repository_is_one_https_url() {
        // Left alone, the SSH spellings would have us clone with credentials we do not have, and
        // the cache would hold four entries for one repository.
        for raw in [
            "git+ssh://git@github.com/a/b.git",
            "ssh://git@github.com/a/b",
            "git://github.com/a/b.git",
            "git+https://github.com/a/b.git",
            "http://github.com/a/b",
            "https://github.com/a/b/",
            "github:a/b",
            "git@github.com:a/b.git",
            "a/b",
            "  a/b  ",
        ] {
            assert_eq!(canonicalize_repo(raw), "https://github.com/a/b", "{raw:?}");
        }
    }

    #[test]
    fn a_spelling_it_does_not_recognise_is_left_as_written() {
        // Not guessed at: a string that is not plainly a GitHub shorthand is not rewritten into
        // one, and what it is stays visible to whatever refuses it next.
        for raw in [
            "bitbucket:a/b",
            "git@gitlab.com:a/b",
            "a/b/c",
            "just words/here",
            "file:///srv/repo",
        ] {
            assert_eq!(canonicalize_repo(raw), raw, "{raw:?}");
        }
    }
}

#[cfg(test)]
mod subdir_tests {
    use super::repo_subdir;
    use serde_json::json;

    fn with(directory: serde_json::Value) -> serde_json::Value {
        json!({"repository": {"type": "git", "url": "git+https://github.com/babel/babel.git",
                              "directory": directory}})
    }

    #[test]
    fn npms_own_answer_to_the_monorepo_question_is_read() {
        // Both taken from the live registry: without them a rebuild of a monorepo member checks out
        // the repository and builds at the root, which is a different package.
        assert_eq!(
            repo_subdir(&with(json!("packages/babel-core"))).as_deref(),
            Some("packages/babel-core")
        );
        assert_eq!(
            repo_subdir(&with(json!("packages/parser"))).as_deref(),
            Some("packages/parser")
        );
        // Surrounding slashes are noise, not structure.
        assert_eq!(
            repo_subdir(&with(json!("/packages/parser/"))).as_deref(),
            Some("packages/parser")
        );
    }

    #[test]
    fn a_package_at_the_root_says_nothing_and_that_is_not_an_error() {
        assert_eq!(repo_subdir(&json!({"repository": {"url": "x"}})), None);
        assert_eq!(repo_subdir(&json!({})), None);
        assert_eq!(repo_subdir(&with(json!(""))), None);
        assert_eq!(repo_subdir(&with(json!(42))), None);
    }

    #[test]
    fn a_directory_that_leaves_the_checkout_is_refused() {
        // This value is attacker-controlled — it is whatever the publisher put in package.json —
        // and it reaches a shell command line through the rendered strategy and an output-path
        // glob. `..` climbs out of the checkout; a leading dash is the argument-injection case the
        // repository URL check already refuses.
        for bad in [
            json!("../../etc"),
            json!("packages/../../.."),
            json!(".."),
            json!("."),
            json!("-rf"),
            json!("packages/ core"),
            json!("packages//core"),
        ] {
            assert_eq!(repo_subdir(&with(bad.clone())), None, "{bad}");
        }
    }
}

#[cfg(test)]
mod view_trimming_tests {
    use super::{subdir_from_view, trim_to_repo};

    /// Every URL here is what a real PyPI project declares, taken from the M1 corpus run where
    /// fifteen of fifty targets came back `no-strategy`.
    #[test]
    fn a_view_at_the_end_of_a_url_is_still_a_view() {
        // The bug: these were written as `"/issues/"` and matched only a view with something after
        // it, so a URL *ending* in the view went untrimmed and was cloned as a repository.
        for (url, want) in [
            (
                "https://github.com/miguelgrinberg/python-engineio/issues",
                "https://github.com/miguelgrinberg/python-engineio",
            ),
            (
                "https://github.com/AzureAD/microsoft-authentication-library-for-python/releases",
                "https://github.com/AzureAD/microsoft-authentication-library-for-python",
            ),
            (
                "https://github.com/lark-parser/lark/tarball/master",
                "https://github.com/lark-parser/lark",
            ),
            (
                "https://github.com/googleapis/google-cloud-python/tree/main/packages/google-auth",
                "https://github.com/googleapis/google-cloud-python",
            ),
            (
                "https://github.com/hukkin/tomli/blob/master/CHANGELOG.md",
                "https://github.com/hukkin/tomli",
            ),
        ] {
            assert_eq!(trim_to_repo(url), want, "{url}");
        }
    }

    #[test]
    fn a_repository_is_left_alone_and_so_is_an_owner_named_like_a_view() {
        assert_eq!(
            trim_to_repo("https://github.com/asweigart/pyperclip"),
            "https://github.com/asweigart/pyperclip"
        );
        // The first three segments are host, owner and repository. A project owned by someone
        // called `tree` is not a view of anything.
        assert_eq!(
            trim_to_repo("https://github.com/tree/releases"),
            "https://github.com/tree/releases"
        );
    }

    #[test]
    fn a_tree_url_carries_the_subdirectory_pypi_has_no_field_for() {
        // npm says `repository.directory`; PyPI has nowhere to put it, and says it in passing.
        assert_eq!(
            subdir_from_view(
                "https://github.com/googleapis/google-cloud-python/tree/main/packages/google-auth"
            )
            .as_deref(),
            Some("packages/google-auth")
        );
        // A plain repository points into nothing, and a tree of the root is not a subdirectory.
        assert_eq!(subdir_from_view("https://github.com/a/b"), None);
        assert_eq!(subdir_from_view("https://github.com/a/b/tree/main"), None);
        // A `blob` link names a file. `tomli` declares one, and its subdirectory is not
        // `CHANGELOG.md`; the repository still has to be trimmed out of it.
        assert_eq!(
            subdir_from_view("https://github.com/hukkin/tomli/blob/master/CHANGELOG.md"),
            None
        );
        // Publisher-controlled, and it reaches a shell command line.
        assert_eq!(
            subdir_from_view("https://github.com/a/b/tree/main/../etc"),
            None
        );
        assert_eq!(
            subdir_from_view("https://github.com/a/b/tree/main/-rf"),
            None
        );
    }
}
