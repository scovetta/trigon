//! Rebuilt artifacts as release assets of the evidence repository (`docs/19` §2.3, §4.1, §10
//! phase 5 step 3), when `[publish] rebuilt_artifacts = "github-release"` (D4).
//!
//! A rebuilt artifact never goes into git. It is a release asset named `sha256-<hex>` by the digest
//! the verdict signs, in one release per month, `rebuilt-YYYY-MM`, continued as
//! `rebuilt-YYYY-MM.2`, `.3` when a release holds GitHub's limit of 1,000 assets; no record names a
//! release, so a reader finds the asset by its name in whichever release holds it. An asset is
//! uploaded before the commit that references it, and one of that name already there — a retry of
//! a publication that failed after its upload, or a race lost — is reused only where GitHub
//! reports its digest and its size and digest are the artifact's; one GitHub reports no digest for
//! is uploaded again in its place, since its size alone cannot tell it from another artifact's. An
//! asset over GitHub's 2 GiB is refused before anything is written.
//!
//! **GitHub's REST API, not git**, so this is the one part of publishing that takes a credential of
//! its own (`docs/19` §2.4): a token with contents-write on the repository, from `GITHUB_TOKEN` or
//! `GH_TOKEN`, read from the environment and nowhere else — never argv, never a file — held in a
//! type whose `Debug` shows nothing of it, sent only in the `Authorization` header, only to the API
//! and to the upload host GitHub names for it, and never over plain text except to loopback. No
//! message quotes it, even where the server echoed it back. The repository is the publish
//! location's, which must be on github.com.
//!
//! `TRIGON_GITHUB_API` replaces `https://api.github.com`, so that the tests speak to a server of
//! their own on `127.0.0.1:0`; an upload URL is then held to that server's origin instead.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, anyhow, bail};
use serde::Deserialize;
use trigon_attest::location::{Location, Transport, printable};
use trigon_core::Digest;
use trigon_store::Store;

/// GitHub's limit on one release asset: each must be under 2 GiB, so one of exactly this size is
/// refused too.
pub(crate) const ASSET_LIMIT: u64 = 2 << 30;

/// GitHub's limit on the assets of one release, after which the month's series continues.
pub(crate) const PER_RELEASE: usize = 1000;

/// The API a token is sent to when `TRIGON_GITHUB_API` names no other.
const DEFAULT_API: &str = "https://api.github.com";

/// The host GitHub's own API names for uploads.
const DEFAULT_UPLOADS: &str = "uploads.github.com";

/// What every release series is named by, before its month.
const SERIES: &str = "rebuilt-";

/// How many pages of releases, or of one release's assets, are read before a listing is taken to
/// be something other than GitHub: ten thousand releases, or ten thousand assets.
const PAGES: u32 = 100;

/// A rebuilt artifact a publication names, to be found or uploaded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Asset {
    /// The rebuilt artifact's sha256, as the verdict signs it.
    pub digest: Digest,
    /// Its size, as the run recorded it.
    pub size: u64,
    /// The run it is the rebuilt artifact of.
    pub run: String,
}

impl Asset {
    /// The asset's name: `sha256-<hex>`.
    pub(crate) fn name(&self) -> String {
        format!("sha256-{}", self.digest.to_hex())
    }
}

/// Where an asset is now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Placed {
    pub name: String,
    pub release: String,
    /// Whether it was there already, from an earlier attempt.
    pub reused: bool,
}

/// `owner/repo` where `location` is a repository on github.com, as an HTTPS or SSH URL names one.
/// `None` for any other location, which publishing rebuilt artifacts refuses.
pub(crate) fn on_github(location: &Location) -> Option<String> {
    let url = location.as_git_arg();
    let path = match location.transport() {
        Transport::Https | Transport::Http => url
            .split_once("://")
            .and_then(|(_, r)| r.strip_prefix("github.com/")),
        Transport::Ssh => url
            .strip_prefix("git@github.com:")
            .or_else(|| url.strip_prefix("ssh://git@github.com/")),
        _ => None,
    }?;
    let mut parts = path.trim_matches('/').split('/');
    let (owner, repo) = (parts.next()?, parts.next()?);
    let repo = repo.strip_suffix(".git").unwrap_or(repo);
    let plain = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    };
    (plain(owner) && plain(repo) && parts.next().is_none()).then(|| format!("{owner}/{repo}"))
}

/// A token for GitHub's API. Its `Debug` and `Display` show nothing of it, so no error, log line
/// or panic that prints the client prints the token.
#[derive(Clone)]
struct Token(String);

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Token(***)")
    }
}

/// The token from the environment: `GITHUB_TOKEN`, a workflow's own, else `GH_TOKEN`, the GitHub
/// CLI's. An empty variable is unset.
fn token_from_env() -> Option<Token> {
    ["GITHUB_TOKEN", "GH_TOKEN"]
        .iter()
        .find_map(|v| std::env::var(v).ok().filter(|t| !t.trim().is_empty()))
        .map(|t| Token(t.trim().to_string()))
}

/// Whether a token is in the environment, for a dry run to say so without needing one.
pub(crate) fn token_is_set() -> bool {
    token_from_env().is_some()
}

/// The GitHub API the repository's releases are asked of.
#[derive(Debug)]
pub(crate) struct GitHub {
    /// The API's base URL, with no trailing slash.
    api: reqwest::Url,
    /// `owner/repo`.
    repository: String,
    token: Token,
    client: reqwest::Client,
}

/// The API's base: `TRIGON_GITHUB_API`, or GitHub's own.
pub(crate) fn api_base() -> Result<reqwest::Url> {
    let given = std::env::var("TRIGON_GITHUB_API")
        .ok()
        .filter(|v| !v.is_empty());
    api_base_from(given.as_deref())
}

/// The API's base from what `TRIGON_GITHUB_API` names, or GitHub's own where it names none: HTTPS,
/// or plain HTTP to loopback only, since the token crosses it, and with no user or password in it.
fn api_base_from(given: Option<&str>) -> Result<reqwest::Url> {
    let text = given.unwrap_or(DEFAULT_API);
    let url = reqwest::Url::parse(text.trim_end_matches('/')).map_err(|e| {
        anyhow!(
            "TRIGON_GITHUB_API is `{}`, which is not a URL ({e})",
            printable(text)
        )
    })?;
    let loopback = url.host_str().is_some_and(|h| {
        matches!(h, "localhost" | "[::1]")
            || h.parse::<std::net::Ipv4Addr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    match url.scheme() {
        "https" => {}
        "http" if loopback => {}
        _ => bail!(
            "TRIGON_GITHUB_API is `{}`: the token is sent there, so it is an https:// URL, or \
             http:// to this machine alone",
            printable(text)
        ),
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("TRIGON_GITHUB_API carries a user or a password; the token goes in a header");
    }
    Ok(url)
}

impl GitHub {
    /// The API for the repository `location` names, which must be on github.com, with the token
    /// from the environment. Refused, before anything is written, where either is missing.
    pub(crate) fn for_location(location: &Location) -> Result<GitHub> {
        let repository = repository_of(location)?;
        let token = token_from_env().ok_or_else(|| {
            anyhow!(
                "`[publish] rebuilt_artifacts = \"github-release\"` uploads each rebuilt artifact \
                 to a release of {repository} with GitHub's API, which takes a token, and neither \
                 GITHUB_TOKEN nor GH_TOKEN is set. Export one with contents-write on that \
                 repository — a fine-grained token, or a workflow's GITHUB_TOKEN — or set \
                 `rebuilt_artifacts = \"none\"`. Nothing was written"
            )
        })?;
        let client = reqwest::Client::builder()
            .user_agent(trigon_politeness::user_agent())
            // A token is never carried to another host by a redirect: the API is not expected to
            // send one, and one that does is refused rather than followed.
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(30))
            .build()
            .context("building the HTTP client for GitHub's API")?;
        Ok(GitHub {
            api: api_base()?,
            repository,
            token,
            client,
        })
    }

    pub(crate) fn repository(&self) -> &str {
        &self.repository
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.api.as_str().trim_end_matches('/'))
    }

    /// What GitHub said to a refused request, as a message says it: [`refusal`], with the token
    /// taken out of anything the server echoed back.
    fn refused(&self, status: reqwest::StatusCode, body: &[u8]) -> String {
        refusal(status, body).replace(&self.token.0, "***")
    }

    /// Whether `url` may be sent the token: an upload host GitHub names for its own API, or, where
    /// `TRIGON_GITHUB_API` names another, that server itself.
    fn may_carry_token(&self, url: &reqwest::Url) -> bool {
        if self.api.as_str().trim_end_matches('/') == DEFAULT_API {
            return url.scheme() == "https" && url.host_str() == Some(DEFAULT_UPLOADS);
        }
        url.scheme() == self.api.scheme()
            && url.host_str() == self.api.host_str()
            && url.port_or_known_default() == self.api.port_or_known_default()
    }

    /// A request carrying the token, which gives up after a minute: an upload sets its own time.
    fn request(&self, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
        self.client
            .request(method, url)
            .timeout(std::time::Duration::from_secs(60))
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .bearer_auth(&self.token.0)
    }

    /// Send a request and read its JSON, or say what GitHub said. `what` names the request for a
    /// person.
    async fn json<T: serde::de::DeserializeOwned>(
        &self,
        req: reqwest::RequestBuilder,
        what: &str,
    ) -> Result<T> {
        let resp = req
            .send()
            .await
            .map_err(|e| anyhow!("{what}: GitHub's API could not be reached: {}", shown(e)))?;
        let status = resp.status();
        let body = resp
            .bytes()
            .await
            .map_err(|e| anyhow!("{what}: reading GitHub's answer: {}", shown(e)))?;
        if !status.is_success() {
            bail!("{what}: {}", self.refused(status, &body));
        }
        serde_json::from_slice(&body)
            .map_err(|e| anyhow!("{what}: GitHub answered {status} with something unreadable: {e}"))
    }

    /// Every release of the repository.
    async fn releases(&self) -> Result<Vec<Release>> {
        let mut out = Vec::new();
        for page in 1..=PAGES {
            let url = self.url(&format!(
                "/repos/{}/releases?per_page=100&page={page}",
                self.repository
            ));
            let got: Vec<Release> = self
                .json(
                    self.request(reqwest::Method::GET, &url),
                    &format!("listing the releases of {}", self.repository),
                )
                .await?;
            let last = got.len() < 100;
            out.extend(got);
            if last {
                return Ok(out);
            }
        }
        bail!(
            "listing the releases of {}: more than {} pages; that is not a repository this reads",
            self.repository,
            PAGES
        )
    }

    /// Every asset of one release.
    async fn assets(&self, release: &Release) -> Result<Vec<ReleaseAsset>> {
        let mut out = Vec::new();
        for page in 1..=PAGES {
            let url = self.url(&format!(
                "/repos/{}/releases/{}/assets?per_page=100&page={page}",
                self.repository, release.id
            ));
            let got: Vec<ReleaseAsset> = self
                .json(
                    self.request(reqwest::Method::GET, &url),
                    &format!("listing the assets of release {}", release.tag_name),
                )
                .await?;
            let last = got.len() < 100;
            out.extend(got);
            if last {
                return Ok(out);
            }
        }
        bail!(
            "listing the assets of release {}: more than {} pages",
            release.tag_name,
            PAGES
        )
    }

    async fn create(&self, tag: &str, branch: &str) -> Result<Release> {
        let url = self.url(&format!("/repos/{}/releases", self.repository));
        let body = serde_json::json!({
            "tag_name": tag,
            "target_commitish": branch,
            "name": tag,
            "body": "Rebuilt artifacts that records of this evidence repository name, each as the \
                     asset `sha256-<hex>` of its digest (docs/19 §2.3). Written by `trigon \
                     publish`; no record names this release.",
            "draft": false,
            "prerelease": false,
            "make_latest": "false",
        });
        self.json(
            self.request(reqwest::Method::POST, &url).json(&body),
            &format!("creating release {tag} in {}", self.repository),
        )
        .await
    }

    async fn delete(&self, asset: &ReleaseAsset) -> Result<()> {
        let url = self.url(&format!(
            "/repos/{}/releases/assets/{}",
            self.repository, asset.id
        ));
        let resp = self
            .request(reqwest::Method::DELETE, &url)
            .send()
            .await
            .map_err(|e| {
                anyhow!(
                    "removing the asset {} to upload it again: {}",
                    asset.name,
                    shown(e)
                )
            })?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.bytes().await.unwrap_or_default();
            bail!(
                "removing the asset {} to upload it again: {}",
                asset.name,
                self.refused(status, &body)
            );
        }
        Ok(())
    }

    async fn upload(&self, release: &Release, name: &str, bytes: Vec<u8>) -> Result<Upload> {
        let base = release.upload_url.split('{').next().unwrap_or_default();
        let mut url = reqwest::Url::parse(base).map_err(|e| {
            anyhow!(
                "release {}'s upload URL `{}` is not a URL: {e}",
                release.tag_name,
                printable(base)
            )
        })?;
        if !self.may_carry_token(&url) {
            bail!(
                "release {} names `{}` to upload to, which is not GitHub's upload host for this \
                 API, and the token is sent nowhere else",
                release.tag_name,
                printable(url.as_str())
            );
        }
        url.query_pairs_mut().clear().append_pair("name", name);
        // Five minutes, and a second more for every 256 KiB: a 2 GiB asset gets two and a half
        // hours, and a server that has stopped answering does not get for ever.
        let time = std::time::Duration::from_secs(300 + bytes.len() as u64 / (256 << 10));
        let resp = self
            .request(reqwest::Method::POST, url.as_str())
            .timeout(time)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(bytes)
            .send()
            .await
            .map_err(|e| anyhow!("uploading {name}: {}", shown(e)))?;
        let status = resp.status();
        let body = resp
            .bytes()
            .await
            .map_err(|e| anyhow!("uploading {name}: reading GitHub's answer: {}", shown(e)))?;
        if status == reqwest::StatusCode::UNPROCESSABLE_ENTITY {
            return Ok(Upload::NameTaken);
        }
        if !status.is_success() {
            bail!("uploading {name}: {}", self.refused(status, &body));
        }
        let asset: ReleaseAsset = serde_json::from_slice(&body).map_err(|e| {
            anyhow!("uploading {name}: GitHub answered {status} with something unreadable: {e}")
        })?;
        Ok(Upload::Done(asset))
    }

    /// Find or upload every asset, before anything that names one is written: step 3.
    ///
    /// The month's series, and the previous month's for a retry across the turn of a month, are
    /// read first. An asset of the right name there is reused only where GitHub reports its digest
    /// and it and the size are the artifact's; one of another size or digest is refused; and one
    /// GitHub left unfinished, or reports no digest for — which its size alone cannot tell from
    /// another artifact of that size — is removed and uploaded again from the store. Anything else
    /// goes to the month's series: its first release with room, or a new one after the last.
    pub(crate) async fn put(
        &self,
        assets: &[Asset],
        time: u64,
        branch: &str,
        store: &Store,
    ) -> Result<Vec<Placed>> {
        let month = month_of(time);
        let months = [month.clone(), previous_month(&month)];
        let mut releases: Vec<(String, u32, Release)> = Vec::new();
        for r in self.releases().await? {
            if let Some((m, n)) = series_of(&r.tag_name)
                && months.contains(&m)
                && !r.draft
            {
                releases.push((m, n, r));
            }
        }
        // This month's first, each series by its number: an asset is reused from the first
        // release that holds it, and uploaded to the first of this month's with room.
        releases.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        // Every asset of those releases, by name, with the release it is in.
        let mut found: BTreeMap<String, (usize, ReleaseAsset)> = BTreeMap::new();
        let mut counts: Vec<usize> = Vec::new();
        for (i, (_, _, r)) in releases.iter().enumerate() {
            let listed = self.assets(r).await?;
            counts.push(listed.len());
            for a in listed {
                found.entry(a.name.clone()).or_insert((i, a));
            }
        }

        let mut placed = Vec::new();
        for asset in assets {
            let name = asset.name();
            // An asset of the name to remove before this one is uploaded, and the release it is in.
            let mut replaced = None;
            if let Some((i, there)) = found.get(&name).cloned() {
                let tag = &releases[i].2.tag_name;
                match (there.state.as_str(), &there.digest) {
                    ("uploaded", Some(_)) => {
                        same(&there, asset, tag)?;
                        placed.push(Placed {
                            name,
                            release: tag.clone(),
                            reused: true,
                        });
                        continue;
                    }
                    // Finished, with no digest GitHub reports: another artifact of the same size
                    // would pass for this one, so it is uploaded again in its place — of another
                    // size, it is refused as any other artifact under the name is.
                    ("uploaded", None) => {
                        same(&there, asset, tag)?;
                        replaced = Some((i, there));
                    }
                    // Begun and never finished: GitHub keeps it, under the name, until it is
                    // removed.
                    _ => replaced = Some((i, there)),
                }
            }
            let bytes = store.blobs().get(&asset.digest).await.map_err(|e| {
                anyhow!(
                    "run `{}`: its rebuilt artifact, sha256:{}, is not a release asset of {} yet, \
                     and it is not in the store to upload ({e}). A pruned artifact cannot be \
                     published as an asset; set `rebuilt_artifacts = \"none\"` to publish the \
                     record without it",
                    asset.run,
                    asset.digest.to_hex(),
                    self.repository
                )
            })?;
            if bytes.len() as u64 != asset.size || bytes.len() as u64 >= ASSET_LIMIT {
                bail!(
                    "run `{}`: its rebuilt artifact is {} bytes in the store and {} as the run \
                     recorded it; one of them is wrong, or it is not under GitHub's 2 GiB ({} \
                     bytes) for a release asset",
                    asset.run,
                    bytes.len(),
                    asset.size,
                    ASSET_LIMIT
                );
            }
            // Only now, with the bytes to put in its place in hand: an asset removed for an
            // artifact the store no longer holds would be gone for good.
            if let Some((i, there)) = replaced {
                self.delete(&there).await?;
                counts[i] -= 1;
            }
            // The month's series is `releases`' current-month rows, in order of their number.
            let at = match (0..releases.len())
                .find(|&i| releases[i].0 == month && counts[i] < PER_RELEASE)
            {
                Some(i) => i,
                None => {
                    let next = releases
                        .iter()
                        .filter(|r| r.0 == month)
                        .map(|r| r.1)
                        .max()
                        .map_or(1, |n| n + 1);
                    let tag = tag(&month, next);
                    let created = match self.create(&tag, branch).await {
                        Ok(r) => r,
                        // Made meanwhile by another writer, or by an attempt that stopped after
                        // making it: read it back. Never a draft, which the public cannot see: a
                        // record naming an asset in one names an asset nobody can fetch.
                        Err(e) => {
                            let tagged: Vec<Release> = self
                                .releases()
                                .await?
                                .into_iter()
                                .filter(|r| r.tag_name == tag)
                                .collect();
                            match tagged.iter().find(|r| !r.draft) {
                                Some(r) => r.clone(),
                                None if !tagged.is_empty() => bail!(
                                    "creating release {tag} of {}: {e:#}. A draft release of that \
                                     tag is there, which only the repository's writers can see, \
                                     and no asset a record names is put in one: publish the draft, \
                                     or delete it, and publish again. Nothing was committed",
                                    self.repository
                                ),
                                None => return Err(e),
                            }
                        }
                    };
                    let listed = self.assets(&created).await?.len();
                    releases.push((month.clone(), next, created));
                    counts.push(listed);
                    releases.len() - 1
                }
            };
            let release = &releases[at].2;
            let uploaded = match self.upload(release, &name, bytes.to_vec()).await? {
                Upload::Done(a) => a,
                // Taken between the listing and the upload: whatever is there is held to the
                // artifact as any asset found is, and one with no digest is not taken on its size.
                Upload::NameTaken => {
                    let there = self
                        .assets(release)
                        .await?
                        .into_iter()
                        .find(|a| a.name == name)
                        .ok_or_else(|| {
                            anyhow!(
                                "uploading {name}: GitHub refused it as already there, and \
                                 release {} lists no asset of that name",
                                release.tag_name
                            )
                        })?;
                    if there.digest.is_none() {
                        bail!(
                            "uploading {name}: another upload of that name reached release {} \
                             first, and GitHub reports no digest for it, so it cannot be told \
                             from another artifact of its size. Nothing was committed; the next \
                             `trigon publish` uploads the artifact again in its place",
                            release.tag_name
                        );
                    }
                    there
                }
            };
            if uploaded.state != "uploaded" {
                bail!(
                    "uploading {name}: GitHub reports its state as `{}`, not uploaded; nothing was \
                     committed, and the next `trigon publish` removes it and uploads it again",
                    printable(&uploaded.state)
                );
            }
            same(&uploaded, asset, &release.tag_name)?;
            counts[at] += 1;
            placed.push(Placed {
                name,
                release: release.tag_name.clone(),
                reused: false,
            });
        }
        Ok(placed)
    }
}

/// `owner/repo` of the publish location, or the refusal when it is not on github.com.
pub(crate) fn repository_of(location: &Location) -> Result<String> {
    on_github(location).ok_or_else(|| {
        anyhow!(
            "`[publish] rebuilt_artifacts = \"github-release\"` publishes each rebuilt artifact as \
             a release asset of the evidence repository, and {location} is not a repository on \
             github.com (an https://github.com/<owner>/<repo> or git@github.com:<owner>/<repo> \
             URL), so it has no releases to hold them. Publish to the GitHub repository, or set \
             `rebuilt_artifacts = \"none\"`"
        )
    })
}

/// Hold an asset found under an artifact's name to the artifact: an asset is named by its digest,
/// so one of another size, or whose digest GitHub reports as another, is not it, and is refused
/// rather than taken for it. Where GitHub reports no digest this holds it to its size alone, which
/// is why such an asset is never reused.
fn same(there: &ReleaseAsset, asset: &Asset, release: &str) -> Result<()> {
    let want = format!("sha256:{}", asset.digest.to_hex());
    let digest_differs = there.digest.as_deref().is_some_and(|d| d != want);
    if there.size != asset.size || digest_differs {
        bail!(
            "release {release} holds an asset named {} of {} bytes{}, and the rebuilt artifact of \
             run `{}` is {} bytes, {want}: an asset is named by its digest, so that one is not the \
             artifact. Remove it from the release, and publish again",
            there.name,
            there.size,
            there
                .digest
                .as_deref()
                .map(|d| format!(" with digest {}", printable(d)))
                .unwrap_or_default(),
            asset.run,
            asset.size
        );
    }
    Ok(())
}

enum Upload {
    Done(ReleaseAsset),
    NameTaken,
}

#[derive(Clone, Debug, Deserialize)]
struct Release {
    id: u64,
    tag_name: String,
    #[serde(default)]
    upload_url: String,
    #[serde(default)]
    draft: bool,
}

#[derive(Clone, Debug, Deserialize)]
struct ReleaseAsset {
    id: u64,
    name: String,
    size: u64,
    #[serde(default)]
    state: String,
    /// `sha256:<hex>`, where GitHub reports one.
    #[serde(default)]
    digest: Option<String>,
}

/// What GitHub said to a refused request: its status and its `message`, escaped.
fn refusal(status: reqwest::StatusCode, body: &[u8]) -> String {
    let message = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("message").and_then(|m| m.as_str()).map(printable));
    match (status.as_u16(), message) {
        (401, _) => "GitHub refused the token (401). Check that GITHUB_TOKEN or GH_TOKEN is \
                     current"
            .into(),
        (403 | 404, m) => format!(
            "GitHub answered {status}{}. The token needs contents-write on the repository, and a \
             private repository answers 404 to a token that cannot see it",
            m.map(|m| format!(": {m}")).unwrap_or_default()
        ),
        (_, Some(m)) => format!("GitHub answered {status}: {m}"),
        (_, None) => format!("GitHub answered {status}"),
    }
}

/// A transport error as a message shows it: without its URL, which holds nothing secret but is
/// already said by the message around it, and escaped.
fn shown(e: reqwest::Error) -> String {
    printable(&e.without_url().to_string())
}

/// The `YYYY-MM` of a Unix time, UTC.
pub(crate) fn month_of(time: u64) -> String {
    crate::rfc3339_from_unix(time)[..7].to_string()
}

fn previous_month(month: &str) -> String {
    let (y, m) = month.split_once('-').unwrap_or(("1970", "01"));
    let (y, m): (i64, i64) = (y.parse().unwrap_or(1970), m.parse().unwrap_or(1));
    match m {
        1 => format!("{:04}-12", y - 1),
        _ => format!("{y:04}-{:02}", m - 1),
    }
}

/// The tag of the `n`-th release of a month: `rebuilt-YYYY-MM`, then `rebuilt-YYYY-MM.2`.
pub(crate) fn tag(month: &str, n: u32) -> String {
    match n {
        1 => format!("{SERIES}{month}"),
        _ => format!("{SERIES}{month}.{n}"),
    }
}

/// The month and number of a release of a series, from its tag.
fn series_of(tag: &str) -> Option<(String, u32)> {
    let rest = tag.strip_prefix(SERIES)?;
    let (month, n) = match rest.split_once('.') {
        Some((m, n)) if !n.starts_with('0') => (m, n.parse::<u32>().ok().filter(|n| *n >= 2)?),
        Some(_) => return None,
        None => (rest, 1),
    };
    let b = month.as_bytes();
    let shaped = b.len() == 7
        && b[4] == b'-'
        && b.iter()
            .enumerate()
            .all(|(i, c)| i == 4 || c.is_ascii_digit());
    shaped.then(|| (month.to_string(), n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn a_github_location_names_its_repository_and_no_other_does() {
        let at = |s: &str| Location::parse(s, Path::new("/cwd"), None).unwrap();
        for l in [
            "https://github.com/owner/trigon-evidence.git",
            "https://github.com/owner/trigon-evidence",
            "git@github.com:owner/trigon-evidence.git",
            "ssh://git@github.com/owner/trigon-evidence.git",
        ] {
            assert_eq!(
                on_github(&at(l)).as_deref(),
                Some("owner/trigon-evidence"),
                "{l}"
            );
        }
        for l in [
            "/srv/trigon-evidence.git",
            "file:///srv/trigon-evidence.git",
            "https://gitlab.com/owner/trigon-evidence.git",
            "https://github.com/owner",
            "https://github.com/owner/repo/extra",
            "https://github.com.example.org/owner/repo.git",
        ] {
            assert_eq!(on_github(&at(l)), None, "{l}");
        }
        let e = repository_of(&at("/srv/trigon-evidence.git"))
            .unwrap_err()
            .to_string();
        assert!(e.contains("is not a repository on github.com"), "{e}");
    }

    #[test]
    fn a_months_series_is_named_and_read_back() {
        // 2026-09-28T00:00:00Z.
        assert_eq!(month_of(1_790_553_600), "2026-09");
        assert_eq!(tag("2026-09", 1), "rebuilt-2026-09");
        assert_eq!(tag("2026-09", 3), "rebuilt-2026-09.3");
        assert_eq!(series_of("rebuilt-2026-09"), Some(("2026-09".into(), 1)));
        assert_eq!(series_of("rebuilt-2026-09.2"), Some(("2026-09".into(), 2)));
        for other in [
            "rebuilt-2026-9",
            "rebuilt-2026-09.1",
            "rebuilt-2026-09.02",
            "rebuilt-2026-09.x",
            "v1.0.0",
            "rebuilt-",
        ] {
            assert_eq!(series_of(other), None, "{other}");
        }
        assert_eq!(previous_month("2026-01"), "2025-12");
        assert_eq!(previous_month("2026-09"), "2026-08");
    }

    /// The client for `api`, as `for_location` makes it, with a token of its own.
    fn github(api: Option<&str>) -> GitHub {
        GitHub {
            api: api_base_from(api).unwrap(),
            repository: "owner/trigon-evidence".into(),
            token: Token("ghp_secret_token_1234".into()),
            client: reqwest::Client::new(),
        }
    }

    /// The token is never printed: not by the client's `Debug`, and not in a refusal, even one
    /// whose server echoed it back in what it said.
    #[test]
    fn the_token_is_in_no_print_and_no_refusal() {
        let gh = github(None);
        assert_eq!(format!("{:?}", gh.token), "Token(***)");
        assert!(!format!("{gh:?}").contains("ghp_secret"), "{gh:?}");
        for status in [401, 403, 404, 422, 500] {
            let body = br#"{"message": "you sent Authorization: Bearer ghp_secret_token_1234"}"#;
            let said = gh.refused(reqwest::StatusCode::from_u16(status).unwrap(), body);
            assert!(!said.contains("ghp_secret"), "{status}: {said}");
        }
        let said = gh.refused(
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            br#"{"message": "echo ghp_secret_token_1234"}"#,
        );
        assert!(said.contains("echo ***"), "{said}");
    }

    /// The token crosses the API's connection, so the API is HTTPS, or plain HTTP to this machine
    /// alone, and carries no user or password of its own.
    #[test]
    fn the_api_is_https_or_loopback_and_names_no_user() {
        assert_eq!(
            api_base_from(None).unwrap().as_str(),
            "https://api.github.com/"
        );
        for fine in [
            "https://github.example.com/api/v3",
            "http://127.0.0.1:8080",
            "http://127.9.9.9",
            "http://localhost:1234/",
            "http://[::1]:1234",
        ] {
            assert!(api_base_from(Some(fine)).is_ok(), "{fine}");
        }
        for refused in [
            "http://example.com",
            "http://192.168.1.10:8080",
            "http://127.0.0.1.example.com",
            "ftp://127.0.0.1",
            "https://user:pass@github.example.com",
            "https://user@github.example.com",
            "not a url",
        ] {
            assert!(api_base_from(Some(refused)).is_err(), "{refused}");
        }
    }

    /// The token goes to an upload URL only on GitHub's upload host, over HTTPS, for GitHub's own
    /// API; and only to the overridden API's own origin — scheme, host and port — for another.
    #[test]
    fn the_token_goes_only_to_the_apis_upload_host() {
        let url = |u: &str| reqwest::Url::parse(u).unwrap();
        let gh = github(None);
        assert!(gh.may_carry_token(&url(
            "https://uploads.github.com/repos/o/r/releases/1/assets"
        )));
        for other in [
            "http://uploads.github.com/repos/o/r/releases/1/assets",
            "https://uploads.github.com.example.org/x",
            "https://api.github.com/x",
            "https://example.com/x",
        ] {
            assert!(!gh.may_carry_token(&url(other)), "{other}");
        }
        let gh = github(Some("http://127.0.0.1:4000"));
        assert!(gh.may_carry_token(&url("http://127.0.0.1:4000/uploads/x")));
        for other in [
            "http://127.0.0.1:4001/uploads/x",
            "http://127.0.0.2:4000/uploads/x",
            "https://127.0.0.1:4000/uploads/x",
            "https://uploads.github.com/x",
        ] {
            assert!(!gh.may_carry_token(&url(other)), "{other}");
        }
    }

    /// Against GitHub itself, with `TRIGON_LIVE=1`, `TRIGON_LIVE_GITHUB_REPO=<owner>/<repo>` — a
    /// scratch repository the person running it names — and a token in `GITHUB_TOKEN` or
    /// `GH_TOKEN`: an artifact uploaded as `sha256-<hex>` to the month's release, and found and
    /// reused on a second attempt. Skipped otherwise; never in CI.
    #[test]
    fn live_an_asset_is_uploaded_to_github_and_reused() {
        if std::env::var("TRIGON_LIVE").as_deref() != Ok("1") {
            eprintln!("skipped: set TRIGON_LIVE=1 and TRIGON_LIVE_GITHUB_REPO to run");
            return;
        }
        let repo = std::env::var("TRIGON_LIVE_GITHUB_REPO")
            .expect("TRIGON_LIVE_GITHUB_REPO names the scratch repository, <owner>/<repo>");
        let location = Location::parse(
            &format!("https://github.com/{repo}.git"),
            Path::new("/"),
            None,
        )
        .unwrap();
        let gh = GitHub::for_location(&location).unwrap();
        let dir = std::env::temp_dir().join(format!("trigon-live-release-{}", std::process::id()));
        let store = Store::local(&dir).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let bytes = format!("trigon live test {}\n", std::process::id()).into_bytes();
        let digest = rt.block_on(store.blobs().put(bytes.clone())).unwrap();
        let asset = Asset {
            digest,
            size: bytes.len() as u64,
            run: "live".into(),
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let first = rt
            .block_on(gh.put(std::slice::from_ref(&asset), now, "main", &store))
            .unwrap();
        assert!(!first[0].reused);
        let again = rt
            .block_on(gh.put(std::slice::from_ref(&asset), now, "main", &store))
            .unwrap();
        assert!(again[0].reused);
        assert_eq!(again[0].release, first[0].release);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
