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
            // The job's own identity, so the two attempts this run is half of can recognise each
            // other. Without it every record corroborates nothing and the publication gate holds
            // the whole corpus back for ever.
            cache_key: Some(job.cache_key.clone()),
            attempt: job.attempt.max(1) as u32,
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
                    // those, never for a package that failed to build. All three can answer
                    // differently on another worker or an hour later.
                    retryable: true,
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
            "worker {} on {queue_url}, building with {} at egress {}",
            cfg.worker, builder.image, builder.egress
        );
        let engine = Engine::new(queue, cfg);
        if once {
            let n = engine.tick(&builder).await?;
            println!("handled {n} job(s)");
            return anyhow::Ok(());
        }

        let stop = Arc::new(AtomicBool::new(false));
        let signal = stop.clone();
        tokio::spawn(async move {
            // Between jobs, never during one. A build killed halfway leaves a leased job, a
            // half-written work directory and no record; waiting costs one build's latency.
            if tokio::signal::ctrl_c().await.is_ok() {
                println!("\nfinishing the current job, then stopping");
                signal.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        });
        engine.run(Arc::new(builder), stop).await;
        anyhow::Ok(())
    })
}
