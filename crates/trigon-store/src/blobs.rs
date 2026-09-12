//! Content-addressed blob storage.
//!
//! Everything large a run produces lives here and is referred to elsewhere by digest: build logs,
//! rendered instructions, the comparison, and the artifacts themselves. Two consequences follow from
//! addressing by content rather than by name, and both are load-bearing rather than tidy:
//!
//! - **The attestor can be a separate process that never executes anything.** The sandbox writes
//!   blobs; the attestor reads them by hash, re-derives the equivalence claim, and signs. It needs
//!   no access to the sandbox, the network, or the strategy that produced any of it —
//!   `docs/09-attestations.md` §6. A path-addressed store would leave the attestor trusting whoever
//!   chose the path.
//! - **A digest that is already present is already correct.** Writing the same bytes twice is a
//!   no-op, so retries, resumed sweeps and two targets that share a dependency all converge without
//!   a deduplication pass.
//!
//! Backed by `object_store`, which serves local filesystem, S3, GCS, Azure and memory behind one
//! interface. `docs/17` says to use it directly rather than wrap it in a `BlobStore` trait of our
//! own, and that is what this does: the cloud backends are a cargo feature away and need no code.

use std::sync::Arc;

use bytes::Bytes;
use object_store::{ObjectStore, ObjectStoreExt as _, PutPayload, path::Path as ObjPath};
use sha2::{Digest as _, Sha256};
use trigon_core::Digest;

use crate::StoreError;

/// The blob half of a store.
#[derive(Clone, Debug)]
pub struct Blobs {
    inner: Arc<dyn ObjectStore>,
}

impl Blobs {
    pub fn new(inner: Arc<dyn ObjectStore>) -> Self {
        Blobs { inner }
    }

    /// `blobs/sha256/<first two hex>/<digest>`.
    ///
    /// The two-character shard is not decoration. A flat directory of a hundred thousand entries is
    /// slow to list on a local filesystem and is a hot prefix on object storage, where throughput is
    /// partitioned by key prefix; both bite exactly when the store is worth having.
    fn path(d: &Digest) -> ObjPath {
        let hex = d.to_hex();
        ObjPath::from(format!("blobs/sha256/{}/{hex}", &hex[..2]))
    }

    /// Store bytes, returning what they are addressed by.
    ///
    /// Idempotent: identical bytes give an identical path, so a re-run overwrites itself with the
    /// same content and concurrent writers cannot disagree about what is there.
    pub async fn put(&self, bytes: impl Into<Bytes>) -> Result<Digest, StoreError> {
        let bytes: Bytes = bytes.into();
        let digest = Digest::from_bytes(Sha256::digest(&bytes).into());
        let path = Self::path(&digest);
        // Checked first because a blob store is overwhelmingly a cache: at fleet scale most puts
        // are bytes some other run already stored, and a HEAD is far cheaper than a PUT.
        if self.inner.head(&path).await.is_ok() {
            return Ok(digest);
        }
        self.inner.put(&path, PutPayload::from_bytes(bytes)).await?;
        Ok(digest)
    }

    /// Read a blob back, **verifying it against the digest it was asked for**.
    ///
    /// The check is the point of the whole design and costs one hash of bytes already in memory. An
    /// attestor that trusted the store would be trusting whatever wrote to it, and the store is
    /// exactly the thing a compromised worker can write to. Without this, a run's artifacts could be
    /// swapped between the build and the signature and the statement would still be produced.
    pub async fn get(&self, d: &Digest) -> Result<Bytes, StoreError> {
        let bytes = self.inner.get(&Self::path(d)).await?.bytes().await?;
        let actual = Digest::from_bytes(Sha256::digest(&bytes).into());
        if actual != *d {
            return Err(StoreError::Corrupt {
                asked: d.to_hex(),
                found: actual.to_hex(),
            });
        }
        Ok(bytes)
    }

    pub async fn has(&self, d: &Digest) -> Result<bool, StoreError> {
        Ok(self.inner.head(&Self::path(d)).await.is_ok())
    }

    /// Forget a blob.
    ///
    /// The retention rule this exists for: **never keep the rebuilt artifact on a match** — keep its
    /// digests, which are what anyone re-deriving the claim actually compares against the file they
    /// already have. At roughly 3 MB a run over a hundred thousand targets that is the difference
    /// between a few hundred gigabytes and tens of terabytes per sweep
    /// ([`10-scale.md`](../../../docs/10-scale.md) §1.1). Bytes are kept on a divergence, where
    /// somebody has to look at them.
    ///
    /// Ordering matters and is not enforceable here: attestation reads these bytes, so pruning
    /// before signing destroys the evidence the signature is about. [`crate::Store::prune_rebuild`]
    /// is the safe entry point and refuses a run that has not been attested.
    pub async fn delete(&self, d: &Digest) -> Result<(), StoreError> {
        self.inner.delete(&Self::path(d)).await?;
        Ok(())
    }
}
