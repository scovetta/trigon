//! The shared HTTP client.
//!
//! What breaks first at scale is not our compute, it is upstream reputation
//! (`docs/10-scale.md` §3). You do not get slowed down by a registry that decides you are abusive,
//! you get blocked, and unblocking is a human process measured in days. So the politeness is part
//! of the client rather than something each implementation remembers:
//!
//! - a **User-Agent naming the tool and a contact URL**, so that whoever notices the traffic can
//!   reach someone instead of guessing,
//! - a **per-host request spacing** floor,
//! - **retry on the transient statuses only**, with the delay the server asked for, and
//! - a **`Retry-After`-aware 429 path**, because ignoring that header is what turns throttling
//!   into a ban.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::error::RegistryError;

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub user_agent: String,
    /// Minimum gap between requests to the same host.
    pub min_interval: Duration,
    pub timeout: Duration,
    /// How many times a transient failure is retried before giving up.
    pub max_retries: u32,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            // Names the tool, the version, and somewhere to complain. An anonymous crawler is the
            // thing registries block first.
            user_agent: format!(
                "trigon/{} (+https://github.com/trigon-dev/trigon; rebuild verification)",
                env!("CARGO_PKG_VERSION")
            ),
            min_interval: Duration::from_millis(100),
            timeout: Duration::from_secs(60),
            max_retries: 3,
        }
    }
}

/// What this process has asked of each host, and what each host said about it.
///
/// **Upstream reputation is what breaks first at scale** (`docs/10-scale.md` §3) and until now
/// nothing counted. A sweep that exhausts a rate limit does not slow down: it starts failing, each
/// failure lands on a different target, and the run reports a reproduction rate containing
/// infrastructure faults. Counting is what lets a sweep say "GitHub stopped answering after 60
/// requests" instead of "140 packages have no strategy".
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HostTraffic {
    pub requests: u64,
    /// Times the host told us to slow down: a 429, or a 403 that carried an exhausted rate-limit
    /// header. Non-zero means the numbers from this run are about our politeness, not the packages.
    pub throttled: u64,
    /// Requests that failed after every retry.
    pub failed: u64,
}

#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    config: ClientConfig,
    /// Last request time per host. `HashMap` is fine here: nothing about iteration order reaches a
    /// digest, which is the only reason the judgement half bans it.
    last: Arc<Mutex<HashMap<String, Instant>>>,
}

/// Per host, for the whole **process**, not per client.
///
/// A sweep builds a fresh `Client` for every target (`crates/trigon/src/main.rs:2392`), so a
/// per-instance counter would reset four hundred times and report that we asked GitHub for two
/// things. The question "what have we asked of this host" belongs to the process, because the rate
/// limit does: GitHub counts our requests, not our structs.
///
/// `BTreeMap` so a report reads the same way twice.
static TRAFFIC: std::sync::Mutex<std::collections::BTreeMap<String, HostTraffic>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

/// What this process has asked of each host so far.
pub fn traffic() -> std::collections::BTreeMap<String, HostTraffic> {
    TRAFFIC.lock().map(|t| t.clone()).unwrap_or_default()
}

/// Record one request to a host this client did not make.
///
/// **Git is egress too.** A sweep opens roughly two connections to a forge per target — an
/// `ls-remote` to resolve a tag and a `fetch` to get the commit — which at 400 targets is more
/// conversations with github.com than with either registry, and none of them go through this
/// client. Counting them here rather than somewhere new means one table answers "what did we ask
/// of whom", which is the question a throttled run needs answered.
pub fn note_request(host: &str) {
    count(host, |t| t.requests += 1);
}

/// Record one request to a host that refused or failed, for the same reason.
pub fn note_failure(host: &str) {
    count(host, |t| t.failed += 1);
}

fn count(host: &str, f: impl FnOnce(&mut HostTraffic)) {
    if let Ok(mut t) = TRAFFIC.lock() {
        f(t.entry(host.to_string()).or_default());
    }
}

impl Client {
    pub fn new(config: ClientConfig) -> Result<Self, RegistryError> {
        let http = reqwest::Client::builder()
            .user_agent(config.user_agent.clone())
            .timeout(config.timeout)
            .build()?;
        Ok(Client {
            http,
            config,
            last: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// A GET with whatever credentials this host warrants.
    ///
    /// Only `api.github.com`, and only a token the operator already had. Nothing else here is
    /// authenticated: a registry index is public, and sending a credential to a host that did not
    /// ask for one is how a token ends up in somebody's access log.
    fn authorized(&self, url: &str, host: &str) -> reqwest::RequestBuilder {
        let req = self.http.get(url);
        match (host, github_token()) {
            ("api.github.com", Some(token)) => req.bearer_auth(token),
            _ => req,
        }
    }

    /// GET, with pacing and retries.
    pub async fn get(
        &self,
        url: &str,
        ecosystem: &str,
    ) -> Result<reqwest::Response, RegistryError> {
        let host = host_of(url);
        let mut attempt = 0;

        loop {
            self.pace(&host).await;
            tracing::debug!(url, attempt, "GET");

            count(&host, |t| t.requests += 1);
            let result = self.authorized(url, &host).send().await;
            let response = match result {
                Ok(r) => r,
                Err(e) if attempt < self.config.max_retries && is_transient(&e) => {
                    let delay = backoff(attempt);
                    tracing::warn!(url, attempt, delay_s = delay.as_secs_f64(), "{e}; retrying");
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                    continue;
                }
                Err(e) => return Err(e.into()),
            };

            let status = response.status();
            if status.is_success() {
                return Ok(response);
            }

            // **A GitHub rate limit is a 403, not a 429.** The primary limit answers
            // `403 Forbidden` with `X-RateLimit-Remaining: 0`, and without this it fell through to
            // the generic error below: `resolve_version_tag` logged "resolving the tag failed" and
            // returned `None`, so the target came back `no-strategy`. Unauthenticated GitHub allows
            // 60 requests an hour and a 200-target PyPI corpus needs several hundred — so the run
            // would have reported that Trigon cannot infer strategies for most of PyPI, which is a
            // statement about our request budget wearing the costume of a finding about packages.
            let exhausted = status.as_u16() == 403
                && response
                    .headers()
                    .get("x-ratelimit-remaining")
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v.trim() == "0");

            if status.as_u16() == 429 || exhausted {
                // The header, when they sent one. Guessing our own backoff against a server that
                // told us what it wanted is how throttling becomes a ban.
                count(&host, |t| t.throttled += 1);
                // `Retry-After` when they sent one, and GitHub's `X-RateLimit-Reset` — an absolute
                // unix time rather than a duration — when they sent that instead. Guessing our own
                // backoff against a server that told us what it wanted is how throttling becomes a
                // ban.
                let retry_after = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok())
                    .or_else(|| reset_in(&response));
                if attempt >= self.config.max_retries {
                    return Err(RegistryError::RateLimited {
                        ecosystem: ecosystem.to_string(),
                        retry_after_s: retry_after,
                    });
                }
                let delay = retry_after
                    .map(Duration::from_secs)
                    .unwrap_or_else(|| backoff(attempt));
                tracing::warn!(url, delay_s = delay.as_secs_f64(), "rate limited; waiting");
                tokio::time::sleep(delay).await;
                attempt += 1;
                continue;
            }

            if status.is_server_error() && attempt < self.config.max_retries {
                let delay = backoff(attempt);
                tracing::warn!(url, status = status.as_u16(), "server error; retrying");
                tokio::time::sleep(delay).await;
                attempt += 1;
                continue;
            }

            // **A 404 is an answer, not a failure.** Resolving a version to a tag probes up to four
            // spellings and expects most of them to miss; counting those as failures put "2 failed"
            // against `api.github.com` on a sweep where all four targets reproduced. A number that
            // reports trouble on a healthy run is worse than no number, because the next real one
            // is read as noise.
            if status.as_u16() != 404 {
                count(&host, |t| t.failed += 1);
            }
            return Err(RegistryError::Http {
                ecosystem: ecosystem.to_string(),
                url: url.to_string(),
                status: status.as_u16(),
            });
        }
    }

    /// Wait until this host may be asked again.
    async fn pace(&self, host: &str) {
        let wait = {
            let mut last = self.last.lock().await;
            let now = Instant::now();
            let wait = last
                .get(host)
                .map(|t| {
                    self.config
                        .min_interval
                        .saturating_sub(now.duration_since(*t))
                })
                .unwrap_or_default();
            last.insert(host.to_string(), now + wait);
            wait
        };
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }
}

/// The GitHub API token, when the environment carries one.
///
/// **Unauthenticated GitHub allows 60 requests an hour; a token raises it to 5,000.** That gap
/// decides whether a corpus can run at all: resolving a version to a tag costs one API request per
/// spelling tried, so 200 PyPI targets need several hundred, and without a token the run exhausts
/// its budget in the first few minutes and attributes the rest to the packages.
///
/// Read once. `GH_TOKEN` as well as `GITHUB_TOKEN` because the `gh` CLI sets the former and a
/// machine that can already talk to GitHub should not need a second variable.
fn github_token() -> Option<&'static str> {
    static TOKEN: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    TOKEN
        .get_or_init(|| {
            std::env::var("GITHUB_TOKEN")
                .or_else(|_| std::env::var("GH_TOKEN"))
                .ok()
                .filter(|t| !t.trim().is_empty())
        })
        .as_deref()
}

/// Whether a GitHub token is configured, for a report that has to explain a throttled run.
pub fn github_token_present() -> bool {
    github_token().is_some()
}

/// Seconds until GitHub's rate limit resets, from `X-RateLimit-Reset`.
///
/// An absolute unix timestamp rather than a duration, which is why it cannot just be parsed as a
/// `Retry-After`. Clamped to an hour: the limit window is an hour, so a larger number is a clock
/// disagreement rather than a wait anybody should honour.
fn reset_in(response: &reqwest::Response) -> Option<u64> {
    let at = response
        .headers()
        .get("x-ratelimit-reset")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some(at.saturating_sub(now).min(3600))
}

fn host_of(url: &str) -> String {
    url.split("://")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .unwrap_or(url)
        .to_string()
}

/// Exponential, capped. Not jittered here because the per-host pacing already spreads a fleet's
/// requests; jitter matters once many workers retry the same URL at once, which is a fleet concern.
fn backoff(attempt: u32) -> Duration {
    Duration::from_millis(500 * 2u64.pow(attempt.min(4)))
}

fn is_transient(e: &reqwest::Error) -> bool {
    e.is_timeout() || e.is_connect() || e.is_request()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_user_agent_names_the_tool_and_a_contact() {
        // An anonymous crawler is the thing registries block first, and the block is a human
        // process to undo.
        let ua = ClientConfig::default().user_agent;
        assert!(ua.starts_with("trigon/"), "{ua}");
        assert!(
            ua.contains("https://"),
            "it must say where to complain: {ua}"
        );
    }

    #[test]
    fn hosts_are_extracted_for_pacing() {
        assert_eq!(
            host_of("https://registry.npmjs.org/left-pad"),
            "registry.npmjs.org"
        );
        assert_eq!(host_of("https://pypi.org/pypi/x/json"), "pypi.org");
    }

    #[test]
    fn backoff_grows_and_stops_growing() {
        assert!(backoff(0) < backoff(1));
        assert!(backoff(1) < backoff(2));
        assert_eq!(backoff(9), backoff(4), "capped rather than unbounded");
    }
}

#[cfg(test)]
mod rate_limit_tests {
    #[test]
    fn a_github_rate_limit_is_a_403_and_must_not_read_as_a_missing_tag() {
        // The distinction this makes, stated as the thing it prevents. GitHub's primary limit
        // answers `403` with `X-RateLimit-Remaining: 0`. Read as an ordinary failure it becomes
        // "resolving the tag failed", then `None`, then `no-strategy` — a statement about our
        // request budget wearing the costume of a finding about the package. 200 PyPI targets need
        // several hundred API requests against an unauthenticated allowance of 60 an hour, so this
        // is the difference between a corpus run and a corpus run that reports nonsense.
        fn exhausted(status: u16, remaining: Option<&str>) -> bool {
            status == 403 && remaining.is_some_and(|v| v.trim() == "0")
        }
        assert!(exhausted(403, Some("0")));
        assert!(exhausted(403, Some(" 0 ")));
        // A real 403 — a private repository, a bad token — is not a rate limit and must stay an
        // error, or a permissions problem waits an hour and then fails anyway.
        assert!(!exhausted(403, Some("57")));
        assert!(!exhausted(403, None));
        assert!(!exhausted(404, Some("0")));
    }

    #[test]
    fn traffic_counts_what_a_sweep_needs_to_disown_its_own_numbers() {
        // A non-zero `throttled` is what lets a sweep say the rate it measured is about our
        // politeness rather than about the packages.
        let mut t = super::HostTraffic::default();
        t.requests += 1;
        t.throttled += 1;
        assert_eq!(t.requests, 1);
        assert_eq!(t.throttled, 1);
        assert_eq!(t.failed, 0);
    }
}
