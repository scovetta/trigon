//! `trigon serve`: bind a socket and hand the corpus to a browser.

use crate::{Api, Index, Principal, Switches};
use std::sync::Arc;

/// How the site was asked to run.
pub struct Config {
    pub bind: String,
    /// What an unauthenticated caller counts as.
    pub unauthenticated: Principal,
    pub switches: Switches,
    /// How often to look for runs that arrived since startup. The index is additive, so a refresh
    /// costs one `LIST` plus a `GET` per new id and not a re-read of the corpus.
    pub refresh_seconds: u64,
}

/// Serve until interrupted.
///
/// Builds the index before binding, so the first request is answered rather than raced. A corpus
/// that cannot be listed is a failure to start and not a site that serves an empty page: an empty
/// corpus and an unreachable one look identical to a reader, and only one of them is our fault.
pub async fn run(store: trigon_store::Store, cfg: Config) -> Result<(), String> {
    let store = Arc::new(store);
    let index = Index::new();
    let n = index.refresh(&store, cfg.switches).await?;

    let api = Arc::new(Api {
        store: store.clone(),
        index: index.clone(),
        switches: cfg.switches,
        unauthenticated: cfg.unauthenticated,
    });

    if cfg.refresh_seconds > 0 {
        let (store, index, switches) = (store.clone(), index.clone(), cfg.switches);
        let every = cfg.refresh_seconds;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(every)).await;
                match index.refresh(&store, switches).await {
                    Ok(0) => {}
                    Ok(n) => tracing::info!(added = n, "new runs"),
                    // A refresh that fails leaves the index as it was. A reader looking at a
                    // corpus that has stopped growing is better served than one looking at a
                    // process that exited because a bucket blinked.
                    Err(e) => tracing::warn!(error = %e, "refresh failed; serving what we have"),
                }
            }
        });
    }

    let listener = tokio::net::TcpListener::bind(&cfg.bind)
        .await
        .map_err(|e| format!("binding {}: {e}", cfg.bind))?;

    let mode = match cfg.unauthenticated {
        Principal::Anonymous => {
            "public: an unauthenticated reader sees only what the publication gate released, and \
             no unredacted bytes"
        }
        Principal::Operator => {
            "operator: everything in the store is shown, including build logs. Keep this on \
             loopback"
        }
    };
    println!("serving {n} run(s) on http://{}  ({mode})", cfg.bind);
    if cfg.switches.stop_divergences {
        println!("  divergence publication is STOPPED (ADR-0010 safeguard 5)");
    }

    axum::serve(listener, crate::router(api))
        .await
        .map_err(|e| format!("serving: {e}"))
}
