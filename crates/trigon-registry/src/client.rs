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

#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    config: ClientConfig,
    /// Last request time per host. `HashMap` is fine here: nothing about iteration order reaches a
    /// digest, which is the only reason the judgement half bans it.
    last: Arc<Mutex<HashMap<String, Instant>>>,
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

            let result = self.http.get(url).send().await;
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

            if status.as_u16() == 429 {
                // The header, when they sent one. Guessing our own backoff against a server that
                // told us what it wanted is how throttling becomes a ban.
                let retry_after = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok());
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
