//! `trigon worker`: lease a job from the queue and rebuild what it names.
//!
//! The thin half of M4 Stage B. `trigon-engine` owns the loop — the lease, the heartbeat, the
//! outbox, the backoff, the confirmation attempt and the cap refusal — and this owns the one thing
//! the engine deliberately does not know: how to rebuild a package. It is the same `run_one` that
//! `trigon rebuild` and `trigon sweep` call, which is the point. A worker that rebuilt differently
//! from the CLI would make every local reproduction of a fleet result a coincidence.

use anyhow::{Context as _, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use trigon_engine::{Config, Done, Engine, Failed, Progress, Work};
use trigon_store::Store;
use trigon_store::queue::{Job, Queue};

/// What a job carries beyond its target.
///
/// Small, and inline in the row: everything here is a short string, well under the 8 KB above which
/// ADR-0005 sends a payload to blob storage.
///
/// **No egress tier.** `docs/22-management-layer.md` §2.4: the shipped default is `open`, which
/// adds no network isolation at all, and a payload that could name a tier would let whoever
/// enqueued the job choose one. The worker decides, from its own command line, and a visitor's
/// request therefore cannot be a request to run a build unsandboxed.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Payload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timewarp: Option<String>,
    /// A content-addressed transform overlay, where a reviewer has approved one. The engine refuses
    /// to record a `normalized` verdict from a job carrying this — see its module documentation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overlay: Option<String>,
    /// The run this job is the confirmation of, which the engine names when it enqueues one.
    ///
    /// The worker repeats that run exactly as `trigon rebuild --confirm` does — its strategy, its
    /// set, its image and tier, with every cache emptied — rather than inferring a strategy that
    /// may differ, which would make the second attempt a different question.
    ///
    /// **A run id, and nothing a requester chooses.** The tier comes from the record of a run this
    /// fleet ran, in its own store, and only the engine writes this field, from the job it has
    /// just finished; a visitor's request carries no payload at all. So the rule above — the
    /// worker decides the tier, never whoever enqueued — holds: the tier a confirmation repeats is
    /// one a worker already chose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm: Option<String>,
}

/// How this worker is configured to build.
pub struct Builder {
    pub image: String,
    pub egress: String,
    pub work: PathBuf,
    pub store: PathBuf,
    pub timeout: u64,
    pub definitions: Option<PathBuf>,
    pub mirror_image: String,
    pub model: Option<String>,
    pub source_cache: Option<PathBuf>,
    pub verbose: bool,
}

impl std::fmt::Debug for Builder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Builder")
            .field("image", &self.image)
            .field("egress", &self.egress)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl Work for Builder {
    fn kinds(&self) -> Vec<String> {
        vec!["rebuild".into()]
    }

    async fn run(&self, job: &Job, progress: &Progress) -> Result<Done, Failed> {
        progress.phase("rebuild").await;
        let payload: Payload = job
            .payload
            .as_deref()
            .and_then(|p| serde_json::from_str(p).ok())
            .unwrap_or_default();

        // A directory per job **and per attempt**. Two attempts at the same package are the whole
        // point of the confirmation, and sharing a work directory between them would let the first
        // attempt's checkout and layer cache decide the second's answer — which is precisely the
        // independence safeguard 1 is asking for.
        let work = self
            .work
            .join(format!("job-{}-attempt-{}", job.id, job.attempt));
        if let Err(e) = std::fs::create_dir_all(&work) {
            return Err(Failed {
                why: format!("could not make a work directory: {e}"),
                retryable: true,
            });
        }

        let args = crate::rebuild::Args {
            purl: job.target.clone(),
            artifact: payload.artifact.clone(),
            image: self.image.clone(),
            work: work.clone(),
            egress: self.egress.clone(),
            timeout: self.timeout,
            definitions: self.definitions.clone(),
            mirror_image: self.mirror_image.clone(),
            timewarp: payload.timewarp.clone(),
            source: None,
            attest: None,
            key: None,
            store: Some(self.store.clone()),
            model: self.model.clone(),
            source_cache: self.source_cache.clone(),
            fetch_cache: None,
            phases: None,
            // **Not the job's key.** The run keys its record on what it ran — the target, the
            // strategy and the set — which is what lets the two attempts this run may be half of
            // recognise each other. The job's key names the request: the purl alone, for a first
            // attempt, which put two attempts straddling a change of strategy or set under one key.
            attempt: job.attempt.max(1) as u32,
            confirm: payload.confirm.clone(),
        };

        // `run_one` is synchronous and builds containers, so it goes to a blocking thread rather
        // than parking a reactor worker for the length of a build.
        let verbose = self.verbose;
        let ran = tokio::task::spawn_blocking(move || crate::rebuild::run_one(args, verbose))
            .await
            .map_err(|e| Failed {
                why: format!("the build task panicked: {e}"),
                // A panic is ours and it is not a property of the package, so it is worth trying
                // again on another worker before the job is called dead.
                retryable: true,
            })?;

        let ran = match ran {
            Ok(r) => r,
            Err(e) => {
                return Err(Failed {
                    why: format!("{e:#}"),
                    // Our error, the registry's, or a policy's — `run_one` returns `Err` only for
                    // those, never for a package that failed to build — and each can answer
                    // differently on another worker or an hour later. Except a confirmation's
                    // refusal to repeat its run: that is a fact about the stored record or this
                    // binary, and every worker running this Trigon gives it again, so it goes dead
                    // at once for somebody to read rather than after three leases.
                    retryable: e.downcast_ref::<crate::rebuild::Unrepeatable>().is_none(),
                });
            }
        };

        progress.note("outcome", &ran.outcome.label()).await;

        // **An outcome is not the same thing as a successful job.**
        //
        // `run_one` returns `Ok` for every terminal outcome, including the ones that say *we* could
        // not test this package — a registry that would not answer, a podman that is not usable, a
        // tier name we got wrong. The first version of this treated every `Ok` as work completed,
        // so a worker on a broken machine acknowledged every job it was handed and drained the
        // queue without building anything. It was found by running it: one worker, one target, one
        // `done` row, and an `error:infra` record beside it.
        //
        // A run that is *about the package* is finished work whatever it concluded — a divergence,
        // a build that failed, a package we have no recipe for. A run that is about us goes back.
        if let crate::rebuild::Outcome::Failed { fault, detail } = &ran.outcome {
            use trigon_core::Fault;
            return Err(Failed {
                why: detail.clone(),
                // `Infra` and `Upstream` can answer differently on another worker or an hour
                // later. `Policy` and `Bug` cannot: a refused egress tier and a bug in our own
                // code both produce the same answer every time, and retrying them spends builds to
                // reach the same row three times instead of once.
                retryable: matches!(fault, Fault::Infra | Fault::Upstream),
            });
        }

        let Some(id) = ran.record_id else {
            // No record means the run died before it had an artifact to be a record about — a
            // resolve or a fetch. There is nothing to hand the outbox, so the job is given back.
            return Err(Failed {
                why: format!("{} produced no record", ran.outcome.label()),
                retryable: true,
            });
        };

        match read_back(&self.store, &id).await {
            Ok((record, record_ref)) => Ok(Done { record, record_ref }),
            Err(e) => Err(Failed {
                why: format!("the run recorded {id} and it could not be read back: {e:#}"),
                // Not retryable: the build already happened and the bytes are somewhere. Running
                // it again would spend a second build to hit the same broken store.
                retryable: false,
            }),
        }
    }

    /// A void, by the gate's own clauses (`trigon_api::publication::voided`), which the attempt
    /// that would repeat it refuses: a void makes no claim a second attempt could confirm.
    fn unconfirmable(&self, record: &trigon_store::RunRecord) -> Option<String> {
        unconfirmable(record)
    }
}

/// [`Builder`]'s answer to [`Work::unconfirmable`], free of a builder so it can be tested.
fn unconfirmable(record: &trigon_store::RunRecord) -> Option<String> {
    trigon_api::publication::voided(record).map(|because| {
        format!(
            "run `{}` is void ({}), which a second attempt could not confirm",
            record.id,
            because.key()
        )
    })
}

/// Read the record back and put its canonical bytes in the blob store.
///
/// The row keeps `record_ref`; the blob is the record. Written *before* the transaction, because
/// blobs are content-addressed and idempotent — writing the same bytes twice is a no-op, so doing
/// it outside the transaction is safe in a way writing the row would not be.
async fn read_back(store: &std::path::Path, id: &str) -> Result<(trigon_store::RunRecord, String)> {
    let store = Store::local(store)?;
    let record = store.get_run(id).await.context("reading the run back")?;
    let bytes = serde_json::to_vec(&record)?;
    let digest = store
        .blobs()
        .put(bytes)
        .await
        .context("storing the record")?;
    Ok((record, digest.to_hex()))
}

/// Run until interrupted.
pub fn serve(
    queue_url: &str,
    builder: Builder,
    cfg: Config,
    migrate: bool,
    once: bool,
) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let queue = Queue::open(queue_url).await.map_err(anyhow::Error::from)?;
        if migrate {
            queue.migrate().await.map_err(anyhow::Error::from)?;
        }
        println!(
            "{} {} {} {}",
            crate::style::heading("worker"),
            crate::style::ident(&cfg.worker),
            crate::style::muted("on"),
            crate::style::ident(queue_url),
        );
        crate::field(
            "building",
            format!(
                "{} {} {}",
                crate::style::ident(&crate::short_ref(&builder.image)),
                crate::style::muted("at egress"),
                crate::style::ident(&builder.egress.to_string()),
            ),
        );
        // Said at start, because on a fleet of one machine the default means no confirmation is
        // ever made, and the queue shows only jobs that wait.
        crate::field(
            "confirming",
            crate::style::muted(if !cfg.confirm {
                "no second attempts (--no-confirm), so nothing this worker does can publish"
            } else if cfg.same_host_confirmation {
                "each verdict, on any machine, cold (same_host_confirmation is on)"
            } else {
                "each verdict, on a machine other than the one that reached it"
            }),
        );
        let engine = Engine::new(queue, cfg);
        if once {
            let n = engine.tick(&builder).await?;
            println!(
                "{} {} job(s)",
                crate::style::heading("handled"),
                crate::style::good(&n.to_string())
            );
            return anyhow::Ok(());
        }

        let stop = Arc::new(AtomicBool::new(false));
        let signal = stop.clone();
        tokio::spawn(async move {
            // Between jobs, never during one. A build killed halfway leaves a leased job, a
            // half-written work directory and no record; waiting costs one build's latency.
            if tokio::signal::ctrl_c().await.is_ok() {
                println!(
                    "\n{}",
                    crate::style::warn("finishing the current job, then stopping")
                );
                signal.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        });
        engine.run(Arc::new(builder), stop).await;
        anyhow::Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use trigon_store::{ArtifactRef, Environment, RunRecord, RunState};

    /// A verdict as a worker records one, at `egress`.
    fn verdict(id: &str, egress: &str) -> RunRecord {
        let mut r = RunRecord::new(
            id,
            "pkg:npm/left-pad@1.3.0",
            ArtifactRef {
                name: "left-pad-1.3.0.tgz".into(),
                sha256: trigon_core::Digest::from_bytes([3u8; 32]),
                bytes: 1,
                stored: true,
            },
            Environment {
                base_image: "docker.io/library/node@sha256:00".into(),
                derived_image: None,
                egress: egress.into(),
                isolation: "user_ns".into(),
                attestable: true,
                registry_moment: None,
                pin: None,
                guard_manifest: None,
                guarded_members: None,
            },
            "2026-09-28T10:00:00Z",
        );
        r.state = RunState::Done;
        r.outcome = Some("divergent".into());
        r.cache_key = Some("ck1:the-work".into());
        r.non_builtin_stabilizer = Some(false);
        r
    }

    #[test]
    fn a_void_verdict_is_not_worth_a_second_attempt_and_a_clean_one_is() {
        let void = verdict("1790000000-aaaaaaaa", "open");
        let why = unconfirmable(&void).expect("a void is not worth confirming");
        assert!(why.contains("open_egress"), "{why}");
        let mut hand_written = verdict("1790000001-aaaaaaaa", "mirror-only");
        hand_written.non_builtin_stabilizer = Some(true);
        assert!(unconfirmable(&hand_written).is_some());
        assert_eq!(
            unconfirmable(&verdict("1790000002-aaaaaaaa", "mirror-only")),
            None
        );
    }

    fn builder(root: &std::path::Path) -> Builder {
        Builder {
            image: "docker.io/library/node@sha256:00".into(),
            egress: "mirror-only".into(),
            work: root.join("work"),
            store: root.join("store"),
            timeout: 1,
            definitions: None,
            mirror_image: "localhost/trigon-mirror".into(),
            model: None,
            source_cache: None,
            verbose: false,
        }
    }

    /// The engine asks the builder, and the builder answers as the gate does.
    #[test]
    fn the_builder_refuses_to_confirm_what_the_gate_calls_void() {
        let b = builder(std::path::Path::new("/nonexistent"));
        let void = verdict("1790000000-aaaaaaaa", "open");
        assert_eq!(Work::unconfirmable(&b, &void), unconfirmable(&void));
        assert!(Work::unconfirmable(&b, &void).is_some());
        let clean = verdict("1790000002-aaaaaaaa", "mirror-only");
        assert_eq!(Work::unconfirmable(&b, &clean), None);
        assert_eq!(b.kinds(), vec!["rebuild".to_string()]);
        // What a log line shows of it: the image it builds in and the tier it builds at.
        let shown = format!("{b:?}");
        assert!(shown.contains("mirror-only") && shown.contains("node@sha256:00"), "{shown}");
    }

    /// The record the job hands the outbox is the one the run wrote, and the reference it hands
    /// with it names that record's canonical bytes in the blob store.
    #[tokio::test]
    async fn a_run_is_read_back_and_kept_as_the_blob_its_reference_names() {
        let dir = std::env::temp_dir().join(format!("trigon-worker-back-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = dir.join("store");
        let r = verdict("1790000003-aaaaaaaa", "mirror-only");
        Store::local(&store).unwrap().put_run(&r).await.unwrap();

        let (record, record_ref) = read_back(&store, &r.id).await.unwrap();
        assert_eq!(record.id, r.id);
        assert_eq!(record.outcome.as_deref(), Some("divergent"));
        let bytes = serde_json::to_vec(&record).unwrap();
        assert_eq!(record_ref, trigon_store::digest_of(&bytes).to_hex());
        let kept = Store::local(&store)
            .unwrap()
            .blobs()
            .get(&trigon_store::digest_of(&bytes))
            .await
            .unwrap();
        assert_eq!(&kept[..], &bytes[..]);

        // A run the store does not hold is an error, said as the reading of it.
        let e = read_back(&store, "1790000009-ffffffff").await.unwrap_err();
        assert!(format!("{e:#}").starts_with("reading the run back"), "{e:#}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A confirmation whose run cannot be repeated goes dead at once, rather than being leased,
    /// refused and backed off until it has failed three times: the refusal is a fact about the
    /// stored record, and every worker running this Trigon gives it again.
    ///
    /// Through the engine and the real builder, on a run the gate calls void. No podman: the
    /// refusal comes before anything is fetched or built.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_run_a_confirmation_cannot_repeat_goes_dead_at_once() {
        let dir = std::env::temp_dir().join(format!("trigon-worker-dead-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = dir.join("store");
        let void = verdict("1790000000-aaaaaaaa", "open");
        Store::local(&store).unwrap().put_run(&void).await.unwrap();

        let q = Queue::open(&format!("sqlite://{}?mode=rwc", dir.join("q.db").display()))
            .await
            .unwrap();
        q.migrate().await.unwrap();
        q.enqueue(&trigon_store::NewJob {
            attempt: 2,
            payload: Some(format!(r#"{{"confirm":"{}"}}"#, void.id)),
            ..trigon_store::NewJob::rebuild(
                void.target.clone(),
                "ck1:the-work",
                trigon_store::Tier::Regression,
            )
        })
        .await
        .unwrap();

        let builder = Builder {
            image: "docker.io/library/node@sha256:00".into(),
            egress: "mirror-only".into(),
            work: dir.join("work"),
            store,
            timeout: 1,
            definitions: None,
            mirror_image: "localhost/trigon-mirror".into(),
            model: None,
            source_cache: None,
            verbose: false,
        };
        let engine = Engine::new(
            q.clone(),
            Config {
                worker: "w".into(),
                ..Default::default()
            },
        );
        assert_eq!(engine.tick(&builder).await.unwrap(), 1);
        assert_eq!(
            q.depth().await.unwrap(),
            vec![("dead".to_string(), 1)],
            "a refusal every worker gives again was retried"
        );
    }
}
