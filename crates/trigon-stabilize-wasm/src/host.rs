//! Running an archived stabilizer set.
//!
//! `trigon verify` refuses to compare across differing stabilizer-set digests and re-derives
//! instead. That is correct — the digests answer different questions — and it leaves a verifier
//! holding an older attestation unable to check it at all, because the set it was made under is not
//! in their binary. The manifest says what that set was. This runs it.
//!
//! Behind the `host` feature and off by default, and it lives in the same crate as the guest so the
//! ABI has exactly one definition: two crates agreeing on a packed return value and a format
//! numbering by convention is two things to keep in step, and one crate is none. `wasmtime` adds about forty crates to a tree of a
//! hundred, and the small tree is the thing a sceptic checks instead of trusting us
//! (`docs/01-architecture.md` §4.1). A verifier who only ever checks claims made under their own
//! set never needs this and should not pay for it; `xtask policy` fails if the default build
//! acquires `wasmtime` by accident.
//!
//! The guest is pure: no WASI, no imports at all. That is not a convenience — a stabilizer that
//! could read a clock or a socket could make a comparison depend on something outside the two
//! artifacts, and the whole design rests on it not being able to.

use anyhow::{Context, Result, bail};
use std::path::Path;
use trigon_core::{Digest, Format};
use wasmtime::{Engine, Instance, Module, Store, TypedFunc};

/// An archived stabilizer set, loaded and ready to run.
pub struct ArchivedSet {
    store: Store<()>,
    memory: wasmtime::Memory,
    alloc: TypedFunc<u32, u32>,
    stabilize: TypedFunc<(u32, u32, u32, u32, u32), u64>,
    set_digest: TypedFunc<(u32, u32), u64>,
}

impl ArchivedSet {
    /// Load a module from disk.
    ///
    /// No WASI, no host functions, no imports satisfied at all: if the module asks for anything,
    /// instantiation fails here rather than at some later point where the failure would be harder
    /// to attribute. A stabilizer set that wants an import is not a stabilizer set.
    pub fn load(path: &Path) -> Result<Self> {
        let engine = Engine::default();
        let module = Module::from_file(&engine, path)
            .with_context(|| format!("loading {}", path.display()))?;
        if module.imports().len() != 0 {
            let names: Vec<String> = module
                .imports()
                .map(|i| format!("{}::{}", i.module(), i.name()))
                .collect();
            bail!(
                "this module imports {}. A stabilizer set is pure by construction: one that needs \
                 an import could make a comparison depend on something outside the two artifacts.",
                names.join(", ")
            );
        }

        let mut store = Store::new(&engine, ());
        let instance = Instance::new(&mut store, &module, &[])
            .context("instantiating the stabilizer module")?;
        Ok(ArchivedSet {
            memory: instance
                .get_memory(&mut store, "memory")
                .context("the module exports no memory")?,
            alloc: typed(&instance, &mut store, "trigon_alloc")?,
            stabilize: typed(&instance, &mut store, "trigon_stabilize")?,
            set_digest: typed(&instance, &mut store, "trigon_set_digest")?,
            store,
        })
    }

    /// The set digest this module implements, for the named profile.
    ///
    /// A zero here means one thing and not the other three. `trigon_set_digest` returns zero for a
    /// profile it does not implement or for profile bytes that are not UTF-8 — and the bytes came
    /// from `&str`, so they are UTF-8. The module does not implement the profile. Saying that,
    /// rather than the generic refusal, is the whole difference between a verifier looking at their
    /// module and a verifier looking at the package.
    pub fn digest(&mut self, profile: &str) -> Result<Digest> {
        let p = self.write(profile.as_bytes())?;
        let packed = self
            .set_digest
            .call(&mut self.store, (p, profile.len() as u32))
            .context("calling trigon_set_digest")?;
        if packed == 0 {
            bail!(
                "this module does not implement the profile `{profile}`. It was archived before \
                 that profile existed, or it is a set that never had it. Either way the artifact \
                 is not the problem."
            );
        }
        let bytes = self.read(packed)?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("the module returned a digest that is not 32 bytes"))?;
        Ok(Digest::from_bytes(bytes))
    }

    /// Stabilize one artifact through the archived set.
    ///
    /// `trigon_stabilize` returns zero for an unknown profile, an unparseable artifact, and a
    /// failed serialize alike, and the ABI is archival — it may only be appended to, so the guest
    /// cannot start distinguishing them without orphaning every module already written. The host
    /// can, though: it asks `trigon_set_digest` about the same profile, which answers that one
    /// question on its own.
    pub fn stabilize(&mut self, profile: &str, format: Format, data: &[u8]) -> Result<Vec<u8>> {
        let p = self.write(profile.as_bytes())?;
        let d = self.write(data)?;
        let packed = self
            .stabilize
            .call(
                &mut self.store,
                (
                    p,
                    profile.len() as u32,
                    crate::format_to_u32(format),
                    d,
                    data.len() as u32,
                ),
            )
            .context("calling trigon_stabilize")?;
        if packed == 0 {
            // Re-ask the one question the sentinel merged away. If the module has the profile, the
            // refusal really was about these bytes.
            self.digest(profile)?;
        }
        self.read(packed)
    }

    /// Check the module implements the set the attestation names, before trusting its output.
    ///
    /// Without this a verifier runs *a* stabilizer set and assumes it was *the* one — the mistake
    /// the set-digest mechanism exists to prevent, reintroduced at the point where it is hardest to
    /// notice, since a wrong set produces a plausible digest rather than an error.
    pub fn check(&mut self, profile: &str, expected: &str) -> Result<()> {
        let actual = self.digest(profile)?.to_hex();
        if actual != expected {
            bail!(
                "this module implements `{profile}@{}` and the attestation was made under \
                 `{profile}@{}`. Running it would answer a different question than the one asked.",
                &actual[..12.min(actual.len())],
                &expected[..12.min(expected.len())],
            );
        }
        Ok(())
    }

    fn write(&mut self, bytes: &[u8]) -> Result<u32> {
        let ptr = self
            .alloc
            .call(&mut self.store, bytes.len() as u32)
            .context("calling trigon_alloc")?;
        self.memory
            .write(&mut self.store, ptr as usize, bytes)
            .context("writing into the module's memory")?;
        Ok(ptr)
    }

    /// Unpack `(ptr << 32) | len` and copy the bytes out.
    fn read(&mut self, packed: u64) -> Result<Vec<u8>> {
        if packed == 0 {
            bail!(
                "the module refused these bytes under a profile it does implement: it could not \
                 parse them as that format, or could not serialize the result"
            );
        }
        let (ptr, len) = ((packed >> 32) as usize, (packed & 0xffff_ffff) as usize);
        let data = self.memory.data(&self.store);
        let end = ptr
            .checked_add(len)
            .context("the module returned a range that overflows")?;
        // Bounds-checked against the guest's own memory. The guest is ours, but a module read off a
        // disk somebody else wrote is exactly the thing not to take on trust.
        data.get(ptr..end)
            .map(<[u8]>::to_vec)
            .context("the module returned a range outside its memory")
    }
}

fn typed<P, R>(instance: &Instance, store: &mut Store<()>, name: &str) -> Result<TypedFunc<P, R>>
where
    P: wasmtime::WasmParams,
    R: wasmtime::WasmResults,
{
    instance
        .get_typed_func::<P, R>(&mut *store, name)
        .with_context(|| format!("the module exports no `{name}` with the expected signature"))
}

/// The archived set, as `trigon-attest` asks for it.
///
/// Implemented here rather than there so the judgement half never links a WebAssembly runtime: a
/// trait it defines and something below the line implements is how a verifier gets this capability
/// without every verifier paying for it.
impl trigon_attest::ArchivedStabilizer for ArchivedSet {
    fn digest(&mut self, profile: &str) -> Result<Digest, String> {
        ArchivedSet::digest(self, profile).map_err(|e| e.to_string())
    }

    fn stabilize(
        &mut self,
        profile: &str,
        format: Format,
        bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        ArchivedSet::stabilize(self, profile, format, bytes).map_err(|e| e.to_string())
    }
}
