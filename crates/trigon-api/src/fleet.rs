//! The three views M4's fourth criterion asks for that the corpus browser did not have: the
//! lockfile check, failure clusters, and fleet health.
//!
//! Each answers a question a different person arrives with.
//! [`docs/11-interfaces.md`](../../../docs/11-interfaces.md) §3 names them: the lockfile check is
//! the only view that starts from something the reader already has; clusters are "the operator's
//! home screen", and what turns five hundred failures into twelve tickets; fleet health is what
//! says whether the thing is running at all.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use trigon_core::Status;

use crate::evidence::{Class, admits};
use crate::routes::{json, refuse};
use crate::{Api, Principal};

/// The largest lockfile this will read.
///
/// A lockfile is a body somebody else composed, and every cap in this crate exists because one of
/// them was measured in the wrong unit. Eight MiB is a 40,000-package `package-lock.json` with
/// room over; the parse holds the text and one `Package` per entry, both linear in it.
const MAX_LOCKFILE: usize = 8 << 20;

/// `POST /v1/check` — a lockfile in, a verdict table out.
///
/// The same five rows as `trigon check`, from the same parser and the same mapping: the lockfile
/// reading is `trigon_core::lockfile` and the record-to-status rule is `RunRecord::status`, so the
/// command line and the web page cannot drift into two answers.
///
/// **Anonymous.** It reports verdicts that are already public and adds nothing about any run the
/// gate withholds — a withheld run simply is not in the index, so its packages land in
/// `never checked`, which is the truth from where the reader stands.
pub async fn check(State(api): State<Arc<Api>>, body: String) -> Response {
    if body.len() > MAX_LOCKFILE {
        return refuse(
            StatusCode::PAYLOAD_TOO_LARGE,
            "lockfile_too_large",
            &format!(
                "that lockfile is {} and this reads up to {}.",
                crate::member::human(body.len() as u64),
                crate::member::human(MAX_LOCKFILE as u64)
            ),
        );
    }

    // The shape is sniffed here and only here, because a POST carries no file name. Ambiguity is
    // refused rather than guessed: a body we read as the wrong format reports zero packages, and
    // zero packages reads as nothing to worry about.
    let trimmed = body.trim_start();
    let kind = if trimmed.starts_with('{') {
        if trimmed.contains("\"spdxVersion\"") || trimmed.contains("\"SPDXID\"") {
            trigon_core::Kind::Spdx
        } else {
            trigon_core::Kind::NpmLock
        }
    } else {
        trigon_core::Kind::Requirements
    };

    let packages = match trigon_core::parse_lockfile(&body, kind) {
        Ok(p) => p,
        Err(e) => {
            return refuse(
                StatusCode::BAD_REQUEST,
                "unreadable_lockfile",
                &format!("{e}"),
            );
        }
    };

    let mut rows = Vec::with_capacity(packages.len());
    let mut tally: BTreeMap<&'static str, usize> = BTreeMap::new();
    for s in ALL {
        tally.insert(s.label(), 0);
    }

    for p in packages {
        let (status, detail, run) = match api.index.newest_for(&p.purl) {
            Some(r) => {
                let (s, d) = r.status();
                (s, d, Some(r.id.clone()))
            }
            None => (Status::NeverChecked, None, None),
        };
        *tally.entry(status.label()).or_default() += 1;
        rows.push(serde_json::json!({
            "purl": p.purl,
            "name": p.name,
            "version": p.version,
            "line": p.line,
            "status": status.label(),
            "detail": detail,
            "run": run,
        }));
    }

    json(serde_json::json!({
        "packages": rows.len(),
        // Counts, never a rate: `unsupported` and `never checked` have different denominators from
        // the three verdicts and from each other, so one percentage over the lot would be a number
        // with no meaning. See docs/02-domain-model.md §4.
        "tally": tally,
        "results": rows,
    }))
}

const ALL: [Status; 5] = [
    Status::Reproduced,
    Status::Caveats,
    Status::Divergent,
    Status::Unsupported,
    Status::NeverChecked,
];

/// `GET /v1/clusters` — failed runs grouped by what went wrong.
///
/// The operator's home screen. Five hundred failures are twelve causes, and the signature is what
/// says which twelve: it is the same string that keys the repair cache, so a cluster here is
/// exactly the set of runs one fix would move.
///
/// **Class-gated.** A failure signature is derived from a build log, and a build log is
/// unredacted — `FailureSignature::subject` carries paths and, despite the rule its own doc states,
/// sometimes package names. The count is not the sensitive part; the subject is.
pub async fn clusters(State(api): State<Arc<Api>>) -> Response {
    if !admits(api.principal(), Class::BuildLog) {
        return refuse(StatusCode::FORBIDDEN, "class_gated", Class::BuildLog.refusal());
    }

    struct Cluster {
        code: String,
        runs: Vec<String>,
        ecosystems: std::collections::BTreeSet<String>,
        first_seen: String,
        last_seen: String,
    }
    let mut by_key: BTreeMap<String, Cluster> = BTreeMap::new();

    for r in api.index.records() {
        let Some(f) = r.failure.as_ref() else { continue };
        let key = f.key();
        let eco = r
            .target
            .strip_prefix("pkg:")
            .and_then(|t| t.split('/').next())
            .unwrap_or("unknown")
            .to_string();
        let when = r.finished.clone().unwrap_or_else(|| r.started.clone());
        let c = by_key.entry(key).or_insert_with(|| Cluster {
            code: f.code.to_string(),
            runs: Vec::new(),
            ecosystems: Default::default(),
            first_seen: when.clone(),
            last_seen: when.clone(),
        });
        // Capped, because a cluster of four thousand runs is still one ticket and the page does
        // not become more useful for carrying all of them.
        if c.runs.len() < 25 {
            c.runs.push(r.id.clone());
        }
        c.ecosystems.insert(eco);
        if when < c.first_seen {
            c.first_seen = when.clone();
        }
        if when > c.last_seen {
            c.last_seen = when;
        }
    }

    let mut out: Vec<serde_json::Value> = by_key
        .into_iter()
        .map(|(key, c)| {
            serde_json::json!({
                "key": key,
                "code": c.code,
                "count": c.runs.len(),
                "ecosystems": c.ecosystems,
                "first_seen": c.first_seen,
                "last_seen": c.last_seen,
                "runs": c.runs,
            })
        })
        .collect();
    // Biggest first: the point of the view is which fix moves the most.
    out.sort_by(|a, b| {
        b["count"]
            .as_u64()
            .cmp(&a["count"].as_u64())
            .then_with(|| a["key"].as_str().cmp(&b["key"].as_str()))
    });

    json(serde_json::json!({ "clusters": out }))
}

/// `GET /v1/fleet` — is the thing running, and is anything stuck.
///
/// Queue depth by state, who holds a lease and how close it is to expiring, and what the corpus
/// has reached. A worker whose lease is nearly up is either very slow or dead, and from here the
/// two are indistinguishable until it renews — so the number is reported rather than interpreted.
pub async fn fleet(State(api): State<Arc<Api>>) -> Response {
    // `public` matches the principal, so an operator's fleet page counts the whole corpus and an
    // anonymous one counts what the gate released. Two different true answers to one question.
    let public = api.principal() == Principal::Anonymous;
    let stats = api.index.stats(public);

    let queue = match api.queue.as_ref() {
        None => serde_json::json!(null),
        Some(q) => {
            let (depth, workers) = (q.depth().await, q.workers().await);
            match (depth, workers) {
                (Ok(depth), Ok(workers)) => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as i64)
                        .unwrap_or(0);
                    serde_json::json!({
                        "depth": depth.into_iter().collect::<BTreeMap<_, _>>(),
                        "workers": workers.into_iter().map(|(name, held, soonest)| {
                            serde_json::json!({
                                "worker": name,
                                "jobs_held": held,
                                // Negative means the lease has already lapsed and the job is
                                // redeliverable. Reported as a number rather than as "dead",
                                // because this cannot tell a dead worker from a slow one.
                                "lease_expires_in_seconds": (soonest - now) / 1000,
                            })
                        }).collect::<Vec<_>>(),
                    })
                }
                (Err(e), _) | (_, Err(e)) => serde_json::json!({ "error": e.to_string() }),
            }
        }
    };

    json(serde_json::json!({
        "queue": queue,
        "corpus": {
            "runs": stats.runs,
            "evidence": stats.evidence,
            // The two denominators, side by side and never added. See docs/02-domain-model.md §4:
            // a package that did not reproduce and a build we could not run are different facts,
            // and one number over both would answer neither question.
            "by_outcome": stats.by_outcome,
            "by_fault": stats.by_fault,
            "withheld": stats.by_withheld,
        },
        "principal": match api.principal() {
            Principal::Anonymous => "anonymous",
            Principal::Operator => "operator",
        },
    }))
}
