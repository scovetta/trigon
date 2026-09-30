//! Running an archived stabilizer set.
//!
//! `trigon verify` refuses to compare across differing stabilizer-set digests and re-derives
//! instead. That is correct — the digests answer different questions — and it leaves a verifier
//! holding an older attestation unable to check it at all, because the set it was made under is not
//! in their binary. The manifest says what that set was. This runs it.
//!
//! Behind the `host` feature, which this crate leaves off, and it lives in the same crate as the
//! guest so the ABI has exactly one definition: two crates agreeing on a packed return value and a
//! format numbering by convention is two things to keep in step, and one crate is none. `wasmtime`
//! adds about forty crates to a tree of a hundred, and the small tree is the thing a sceptic checks
//! instead of trusting us (`docs/01-architecture.md` §4.1). The full `trigon` build enables `host`
//! through its `wasm` feature, since `attest` runs the module it names in a verdict and
//! `verify-attestation` the one a verdict under a set the binary lacks names. The verifier build
//! (`--no-default-features`) leaves it out unless built `--features wasm`: a verifier who only ever
//! checks claims made under their own set never needs it and should not pay for it, and `xtask
//! policy` fails if the verifier build acquires `wasmtime` by accident.
//!
//! The guest is pure: no WASI, no imports at all. That is not a convenience — a stabilizer that
//! could read a clock or a socket could make a comparison depend on something outside the two
//! artifacts, and the whole design rests on it not being able to.

use anyhow::{Context, Result, bail};
use std::path::Path;
use trigon_core::{Digest, Format};
use wasmtime::{Engine, Instance, Module, Store, TypedFunc};

/// An archived stabilizer set, compiled and ready to run.
///
/// Compiled once, which is the expensive step (Cranelift, about 0.6 s for the set this checkout
/// builds), and instantiated afresh for every artifact it stabilizes ([`Self::stabilize`]), which
/// is not.
pub struct ArchivedSet {
    module: Module,
    /// The instance the module's questions about itself are asked of: the set digest a profile
    /// has, and the commit it was built from. Neither allocates more than a profile's name.
    own: Running,
}

/// One instance of the module, and the functions the ABI names in it.
struct Running {
    store: Store<()>,
    memory: wasmtime::Memory,
    alloc: TypedFunc<u32, u32>,
    stabilize: TypedFunc<(u32, u32, u32, u32, u32), u64>,
    set_digest: TypedFunc<(u32, u32), u64>,
    /// Appended to the ABI after the three above, so a module built before it has none.
    source_commit: Option<TypedFunc<(), u64>>,
}

impl ArchivedSet {
    /// Load a module from disk.
    ///
    /// No WASI, no host functions, no imports satisfied at all: if the module asks for anything,
    /// instantiation fails here rather than at some later point where the failure would be harder
    /// to attribute. A stabilizer set that wants an import is not a stabilizer set.
    pub fn load(path: &Path) -> Result<Self> {
        let engine = Engine::default();
        // `wasmtime::Error` is wasmtime's own type, and not a `std::error::Error`, so `anyhow`'s
        // `Context` reaches it only once it is an `anyhow::Error`: here, and at each call below.
        let module = Module::from_file(&engine, path)
            .map_err(anyhow::Error::from)
            .with_context(|| format!("loading {}", path.display()))?;
        Self::compiled(module)
    }

    /// Load a module from its bytes, as the caller read and hashed them.
    ///
    /// For a caller that holds a module to a digest before running it: `attest`, which signs the
    /// digest of the bytes it checked, and `verify-attestation`, which runs only the bytes whose
    /// digest the verdict signs. Reading the file again to load it would run bytes nobody hashed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let engine = Engine::default();
        let module = Module::new(&engine, bytes)
            .map_err(anyhow::Error::from)
            .context("reading the bytes as a WebAssembly module")?;
        Self::compiled(module)
    }

    fn compiled(module: Module) -> Result<Self> {
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
        let own = Running::new(&module)?;
        Ok(ArchivedSet { module, own })
    }

    /// The set digest this module implements, for the named profile.
    ///
    /// A zero here means one thing and not the other three. `trigon_set_digest` returns zero for a
    /// profile it does not implement or for profile bytes that are not UTF-8 — and the bytes came
    /// from `&str`, so they are UTF-8. The module does not implement the profile. Saying that,
    /// rather than the generic refusal, is the whole difference between a verifier looking at their
    /// module and a verifier looking at the package.
    pub fn digest(&mut self, profile: &str) -> Result<Digest> {
        let own = &mut self.own;
        let p = own.write(profile.as_bytes())?;
        let packed = own
            .set_digest
            .call(&mut own.store, (p, profile.len() as u32))
            .map_err(anyhow::Error::from)
            .context("calling trigon_set_digest")?;
        if packed == 0 {
            bail!(
                "this module does not implement the profile `{profile}`. It was archived before \
                 that profile existed, or it is a set that never had it. Either way the artifact \
                 is not the problem."
            );
        }
        let bytes = own.read(packed)?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("the module returned a digest that is not 32 bytes"))?;
        Ok(Digest::from_bytes(bytes))
    }

    /// Stabilize one artifact through the archived set, in an instance of the module made for it.
    ///
    /// **A fresh instance for every artifact.** The guest never frees: every buffer
    /// `trigon_alloc` hands out and every result stays in its linear memory, which wasm32 caps at
    /// 4 GiB. One instance for both artifacts of a comparison held the first's input, its copy and
    /// its stabilized form while the second ran, so an artifact that stabilized alone could fail
    /// beside another. Instantiating a compiled module costs nothing measurable beside stabilizing
    /// (`docs/16-findings.md` §3.109), and each artifact gets the whole address space.
    ///
    /// `trigon_stabilize` returns zero for an unknown profile, an unparseable artifact, and a
    /// failed serialize alike, and the ABI is archival — it may only be appended to, so the guest
    /// cannot start distinguishing them without orphaning every module already written. The host
    /// can, though: it asks `trigon_set_digest` about the same profile, which answers that one
    /// question on its own.
    pub fn stabilize(&mut self, profile: &str, format: Format, data: &[u8]) -> Result<Vec<u8>> {
        let mut fresh = Running::new(&self.module)?;
        let p = fresh.write(profile.as_bytes())?;
        let d = fresh.write(data)?;
        let packed = fresh
            .stabilize
            .call(
                &mut fresh.store,
                (
                    p,
                    profile.len() as u32,
                    crate::format_to_u32(format),
                    d,
                    data.len() as u32,
                ),
            )
            .map_err(anyhow::Error::from)
            .context("calling trigon_stabilize")?;
        if packed == 0 {
            // Re-ask the one question the sentinel merged away. If the module has the profile, the
            // refusal really was about these bytes.
            self.digest(profile)?;
        }
        fresh.read(packed)
    }

    /// The commit the module says it was built from: 40 hex digits, with `.dirty` after them where
    /// the tree it was built from had changes the commit does not, as `scripts/build-set-module.sh`
    /// names it (`trigon_source_commit`). `None` for a module that names none: one built by a plain
    /// `cargo build`, or before the ABI asked.
    ///
    /// **The module's word about itself**, as its set digest is. It says where a verifier who would
    /// rather not run the module starts rebuilding it; the sha256 of what that rebuild gives,
    /// compared with the one the verdict signs, is the check, and a module that named another
    /// commit than its own is caught by exactly that. An answer in any other form is refused rather
    /// than passed on: it is text from a module, and whoever prints it would print bytes nobody
    /// checked.
    pub fn source_commit(&mut self) -> Result<Option<String>> {
        let own = &mut self.own;
        let Some(f) = own.source_commit.clone() else {
            return Ok(None);
        };
        let packed = f
            .call(&mut own.store, ())
            .map_err(anyhow::Error::from)
            .context("calling trigon_source_commit")?;
        if packed == 0 {
            return Ok(None);
        }
        let not_one = || {
            anyhow::anyhow!(
                "the module names the commit it was built from as something that is not a commit"
            )
        };
        if packed & 0xffff_ffff > LONGEST_COMMIT {
            return Err(not_one());
        }
        let commit = String::from_utf8(own.read(packed)?).map_err(|_| not_one())?;
        let hex = commit.strip_suffix(".dirty").unwrap_or(&commit);
        if hex.len() != 40 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(not_one());
        }
        Ok(Some(commit))
    }

    /// Check the module implements the set the attestation names, before trusting its output.
    ///
    /// Without this a verifier runs *a* stabilizer set and assumes it was *the* one — the mistake
    /// the set-digest mechanism exists to prevent, reintroduced at the point where it is hardest to
    /// notice, since a wrong set produces a plausible digest rather than an error.
    ///
    /// **It is the module's word about itself**, so it catches the wrong module and not one built
    /// to lie: any module can return any 32 bytes here. What makes a module worth running is that
    /// its sha256 is the `stabilizerSetModule` the verdict signs, which the caller holds its bytes
    /// to before loading them ([`Self::from_bytes`]); this answer is checked as well, never
    /// instead.
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
}

/// The longest answer `trigon_source_commit` can honestly give: 40 hex digits and `.dirty`.
const LONGEST_COMMIT: u64 = 46;

impl Running {
    /// A new instance of `module`, its memory as the module declares it and nothing else.
    fn new(module: &Module) -> Result<Self> {
        let mut store = Store::new(module.engine(), ());
        let instance = Instance::new(&mut store, module, &[])
            .map_err(anyhow::Error::from)
            .context("instantiating the stabilizer module")?;
        // Absent from a module built before the ABI asked, and read as naming no commit. Present
        // with another signature, it is not the ABI's function, and the module is refused.
        let source_commit = match instance.get_func(&mut store, "trigon_source_commit") {
            None => None,
            Some(f) => Some(
                f.typed::<(), u64>(&store)
                    .map_err(anyhow::Error::from)
                    .context(
                        "the module exports `trigon_source_commit` with another signature than \
                         the ABI's",
                    )?,
            ),
        };
        Ok(Running {
            memory: instance
                .get_memory(&mut store, "memory")
                .context("the module exports no memory")?,
            alloc: typed(&instance, &mut store, "trigon_alloc")?,
            stabilize: typed(&instance, &mut store, "trigon_stabilize")?,
            set_digest: typed(&instance, &mut store, "trigon_set_digest")?,
            source_commit,
            store,
        })
    }

    fn write(&mut self, bytes: &[u8]) -> Result<u32> {
        let ptr = self
            .alloc
            .call(&mut self.store, bytes.len() as u32)
            .map_err(anyhow::Error::from)
            .context("calling trigon_alloc")?;
        self.memory
            .write(&mut self.store, ptr as usize, bytes)
            .context("writing into the module's memory")?;
        Ok(ptr)
    }

    /// Unpack `(ptr << 32) | len` and copy the bytes out.
    ///
    /// A zero is a refusal the guest does not explain. Running out of memory is one of its causes
    /// and not the least likely: inflating stops with an error, not a trap, when the module's
    /// memory cannot grow, which in a guest that addresses at most 4 GiB happens to an artifact
    /// that expands to 1 GiB (`docs/16-findings.md` §3.109).
    fn read(&mut self, packed: u64) -> Result<Vec<u8>> {
        if packed == 0 {
            bail!(
                "the module refused these bytes under a profile it does implement: it could not \
                 parse them as that format, or could not serialize the result, or ran out of the \
                 memory a module can address doing either"
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
        .map_err(anyhow::Error::from)
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
