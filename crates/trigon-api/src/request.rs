//! The write path: identity, quota, and the one thing a visitor may ask for.
//!
//! **This is the only part of the API that writes anything, and it writes a *job*.** It cannot
//! express a verdict — there is no field for one in what it accepts and no code path here that
//! could produce one — so it cannot launder one. `docs/22-management-layer.md` §5.4 lists what is
//! deliberately absent and why; the short version is that an editable `outcome` column is how you
//! break invariant 2 without touching the comparator.
//!
//! Three things a reader of this file should not have to infer:
//!
//! - **A request names a target and nothing else.** No strategy, no stabilizer, no base image, no
//!   platform, and above all **no egress tier**. The shipped default elsewhere is `open`, which
//!   adds no network isolation at all, and a payload that could name a tier would make the request
//!   button a way to run arbitrary code unsandboxed. The tier is a property of the worker.
//! - **The quota is charged inside the enqueue transaction.** A limiter in front of the API is a
//!   different process reading a different number, and the gap between its check and the insert is
//!   exactly where a burst of clicks gets through.
//! - **A repeat costs nothing and builds nothing.** Somebody clicking twice wants their answer, not
//!   two builds of it.

use crate::{Api, Principal};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use std::sync::Arc;
use trigon_store::queue::Requested;

/// What a caller may ask for. One field, on purpose.
#[derive(Debug, Deserialize)]
pub struct RunRequest {
    /// A package URL.
    pub target: String,
    /// Free text, recorded in the audit row. Not validated, not acted on, and not part of any
    /// claim: it exists so that a person reading the audit months later knows why somebody asked.
    #[serde(default)]
    pub purpose: Option<String>,
}

fn refuse(status: StatusCode, code: &str, detail: &str) -> Response {
    (
        status,
        axum::Json(serde_json::json!({ "error": code, "detail": detail })),
    )
        .into_response()
}

/// Resolve the bearer token to a principal.
///
/// Returns `None` for anonymous, which every read route already handles. A *wrong* token is not
/// anonymous: it is a 401, because somebody who presented a credential and was treated as the
/// public would spend a long time wondering why their quota never moved.
async fn who(api: &Api, headers: &HeaderMap) -> Result<Option<trigon_store::Principal>, Response> {
    let Some(raw) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        // The scheme is case-insensitive (RFC 9110 §11.1). Matched as `Bearer ` alone, `bearer`
        // presented a credential and was read as none — its holder treated as the public.
        .and_then(|v| v.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("Bearer"))
        .map(|(_, token)| token)
    else {
        return Ok(None);
    };
    let Some(queue) = api.queue.as_ref() else {
        return Err(refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "no_queue",
            "this instance serves a corpus and has no queue, so it has no identities either",
        ));
    };
    match queue.principal_for(raw.trim()).await {
        Ok(Some(p)) => Ok(Some(p)),
        Ok(None) => Err(refuse(
            StatusCode::UNAUTHORIZED,
            "unknown_token",
            "that credential is not one this instance knows, or it has been revoked",
        )),
        Err(e) => Err(refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "identity_unavailable",
            &format!("the identity store could not be reached: {e}"),
        )),
    }
}

/// `POST /v1/runs` — ask for a rebuild.
pub async fn request_run(
    State(api): State<Arc<Api>>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<RunRequest>,
) -> Response {
    let principal = match who(&api, &headers).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            return refuse(
                StatusCode::UNAUTHORIZED,
                "authentication_required",
                "asking for a rebuild spends our compute and our standing with a registry, so it \
                 needs a principal with a quota. Reading is anonymous; asking is not.",
            );
        }
        Err(r) => return r,
    };
    if !principal.may("request") {
        return refuse(
            StatusCode::FORBIDDEN,
            "out_of_scope",
            "that principal may read but not ask",
        );
    }
    let Some(queue) = api.queue.as_ref() else {
        return refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "no_queue",
            "this instance serves a corpus and has no queue to put work on",
        );
    };

    // A purl and nothing else. Rejected here rather than handed to a worker, because a target a
    // worker cannot parse becomes a dead job and a row somebody has to read.
    let target = body.target.trim();
    if !target.starts_with("pkg:") || target.len() > 512 || target.contains(char::is_whitespace) {
        return refuse(
            StatusCode::BAD_REQUEST,
            "malformed_target",
            "a target is a package URL, like `pkg:npm/left-pad@1.3.0`",
        );
    }

    match queue.request_rebuild(&principal, target, &today()).await {
        Ok(Requested::Queued { job, spent, quota }) => (
            StatusCode::ACCEPTED,
            axum::Json(serde_json::json!({
                "state": "queued",
                "job": job,
                "target": target,
                "purpose": body.purpose,
                "quota": { "spent": spent, "daily": quota },
                "detail": "a worker will pick this up. Nothing publishes until a second, \
                           independent attempt agrees with the first."
            })),
        )
            .into_response(),
        Ok(Requested::Already { job, spent, quota }) => axum::Json(serde_json::json!({
            "state": "already",
            "job": job,
            "target": target,
            "quota": { "spent": spent, "daily": quota },
            "detail": "this is already queued or already answered, so nothing was charged and \
                       nothing will be built twice."
        }))
        .into_response(),
        Ok(Requested::OverQuota { spent, quota }) => (
            StatusCode::TOO_MANY_REQUESTS,
            axum::Json(serde_json::json!({
                "error": "over_quota",
                "quota": { "spent": spent, "daily": quota },
                "detail": "out of requests for today. The bound is enforced where the work is \
                           admitted rather than reported afterwards, so nothing was queued."
            })),
        )
            .into_response(),
        Err(e) => refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "queue_unavailable",
            &format!("the queue could not be reached: {e}"),
        ),
    }
}

/// `GET /v1/queue` — what is waiting and what is running.
///
/// Anonymous, and it names targets. That is a deliberate call: the queue says what we are *about
/// to look at*, which is not a finding about anybody and is the thing a visitor who just asked for
/// a rebuild most wants to see. Nothing here says whether a package reproduced.
pub async fn queue_state(State(api): State<Arc<Api>>) -> Response {
    let Some(queue) = api.queue.as_ref() else {
        return axum::Json(serde_json::json!({
            "queue": null,
            "detail": "this instance serves a corpus read from storage and has no queue."
        }))
        .into_response();
    };
    let (depth, flight) = (queue.depth().await, queue.in_flight(50).await);
    match (depth, flight) {
        (Ok(depth), Ok(flight)) => axum::Json(serde_json::json!({
            "depth": depth.into_iter().collect::<std::collections::BTreeMap<_, _>>(),
            "in_flight": flight
                .into_iter()
                .map(|(id, target, state, attempt)| serde_json::json!({
                    "job": id, "target": target, "state": state, "attempt": attempt,
                }))
                .collect::<Vec<_>>(),
        }))
        .into_response(),
        (Err(e), _) | (_, Err(e)) => refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "queue_unavailable",
            &format!("{e}"),
        ),
    }
}

/// `GET /v1/jobs/{id}/events` — where a job has got to.
///
/// Read from the events table, **never proxied to the worker**. The reader has to survive the
/// producer's death — the property that makes `trigon watch` correct when a sweep crashes — and
/// with several workers the API has no filesystem in common with the build anyway.
///
/// **An anonymous reader is told where the job has got to, and none of the notes.** A note is free
/// text the worker writes as it goes, before `decide` has run and with no link from the job to the
/// run it recorded, so the gate cannot be asked about one. The worker's `outcome` note is the
/// comparison's label, written for every attempt: a first divergence awaiting confirmation and an
/// open-egress one the gate turns into a void both reached anybody here as `divergent`, and
/// `/v1/queue` hands out the job ids. A failure's note can carry the label too (`divergent
/// produced no record`), and the rest is error text from the build, which is a build log's
/// problem. So the phases and their times are the page, and the run it recorded is read through
/// the routes that ask the gate. An operator keeps every note.
pub async fn job_events(
    State(api): State<Arc<Api>>,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Response {
    let Some(queue) = api.queue.as_ref() else {
        return refuse(
            StatusCode::NOT_FOUND,
            "no_queue",
            "this instance has no queue",
        );
    };
    let public = api.principal() == Principal::Anonymous;
    match queue.events(id).await {
        Ok(events) if public => axum::Json(serde_json::json!({
            "job": id,
            "events": events
                .into_iter()
                .map(|(at, phase, _)| serde_json::json!({ "at": at, "phase": phase }))
                .collect::<Vec<_>>(),
            // Said, so an absent note is not read as a job that had nothing to say.
            "detail": "the worker's notes are not shown to an anonymous reader: they are written \
                       before the publication gate has decided anything, and one of them is the \
                       comparison's outcome. What this run found is published on its own page \
                       once the gate releases it.",
        }))
        .into_response(),
        Ok(events) => axum::Json(serde_json::json!({
            "job": id,
            "events": events
                .into_iter()
                .map(|(at, phase, detail)| serde_json::json!({
                    "at": at, "phase": phase, "detail": detail,
                }))
                .collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(e) => refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "queue_unavailable",
            &format!("{e}"),
        ),
    }
}

/// `GET /v1/me` — what this credential can do.
///
/// So a front-end can show or hide the request form from a fact rather than from a guess, and so a
/// person can check what they hold without having to try something and read the refusal.
pub async fn me(State(api): State<Arc<Api>>, headers: HeaderMap) -> Response {
    match who(&api, &headers).await {
        Ok(Some(p)) => axum::Json(serde_json::json!({
            "principal": p.id,
            "name": p.name,
            "scopes": p.scopes,
            "daily_quota": p.daily_quota,
        }))
        .into_response(),
        Ok(None) => axum::Json(serde_json::json!({
            "principal": null,
            "scopes": [],
            "detail": match api.principal() {
                Principal::Anonymous => "anonymous: published verdicts and signed statements, no bytes",
                Principal::Operator => "operator: this instance treats unauthenticated callers as local",
            },
        }))
        .into_response(),
        Err(r) => r,
    }
}

/// Today, UTC, as `YYYY-MM-DD`. The quota window.
///
/// Computed from the epoch rather than pulled from a date library: a day is 86,400 seconds here and
/// the civil-date arithmetic below is Howard Hinnant's `civil_from_days`. One dependency avoided on
/// a value that only ever groups rows.
fn today() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let z = secs / 86_400 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    format!("{:04}-{:02}-{:02}", y + i64::from(m <= 2), m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_quota_window_is_a_utc_day() {
        let d = today();
        assert_eq!(d.len(), 10, "{d}");
        let parts: Vec<&str> = d.split('-').collect();
        assert_eq!(parts.len(), 3);
        let (y, m, day): (i64, i64, i64) = (
            parts[0].parse().unwrap(),
            parts[1].parse().unwrap(),
            parts[2].parse().unwrap(),
        );
        assert!((2024..2100).contains(&y), "{d}");
        assert!((1..=12).contains(&m), "{d}");
        assert!((1..=31).contains(&day), "{d}");
    }
}
