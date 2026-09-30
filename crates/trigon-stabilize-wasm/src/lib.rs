//! A stabilizer set, archived as a WebAssembly module.
//!
//! `trigon verify` refuses to compare across differing stabilizer-set digests and re-derives
//! instead, which is right and leaves a verifier holding an older attestation unable to check it at
//! all: the set the claim was made under no longer exists anywhere they can run. The manifest
//! (`trigon_stabilize::SetManifest`) tells them *what* that set was. This lets them *run* it.
//!
//! **A core module, not a component.** `docs/09-attestations.md` §7.1 planned a "WASM component",
//! which means `wasm32-wasip2`, WIT definitions and `cargo-component`. A core module compiled for
//! `wasm32-unknown-unknown` gets the whole benefit — an archived set that executes — with a host
//! that needs no WASI implementation and a toolchain that is one `rustup target add`. What it gives
//! up is a typed interface for guests written in other languages, which matters only once somebody
//! writes one. The substitution is recorded in `docs/16-findings.md`.
//!
//! **Every published verdict names one**, by the sha256 of its bytes
//! (`evidence.stabilizerSetModule`), and `scripts/build-set-module.sh` builds it reproducibly, so
//! anyone can rebuild the module a verdict names from the commit it says it was built from
//! ([`trigon_source_commit`]) and compare.
//!
//! The guest is pure and total by construction: no clock, no network, no filesystem, no ambient
//! anything. That is what made stabilizers the right first WASM guest
//! ([`01-architecture.md`](../../../docs/01-architecture.md) §4), and it is why the ABI below can be
//! three functions over the module's exported memory rather than an interface description, with a
//! fourth appended since: the commit the module was built from.

#![forbid(unsafe_op_in_unsafe_fn)]

// The host that runs this module lives here too, behind a feature, so the ABI below has exactly one
// definition. Two crates agreeing on a packed return value and a format numbering by convention is
// two things to keep in step; one crate is none.
#[cfg(feature = "host")]
mod host;
#[cfg(feature = "host")]
pub use host::ArchivedSet;

use trigon_archive::Limits;
use trigon_core::Format;

/// Reserve `len` bytes in the guest and return a pointer the host can write to.
///
/// The host cannot allocate inside the guest's linear memory itself, so every call starts here.
/// `Vec::leak` rather than `into_raw_parts` because the guest never frees: the host makes an
/// instance for each artifact it stabilizes and drops it after, and an allocator that tracked
/// ownership across the boundary would be a second thing to get wrong for no benefit.
#[unsafe(no_mangle)]
pub extern "C" fn trigon_alloc(len: u32) -> u32 {
    let v = vec![0u8; len as usize];
    Box::leak(v.into_boxed_slice()).as_mut_ptr() as u32
}

/// Stabilize an artifact and return `(ptr << 32) | len`, or `0` for a failure.
///
/// One packed return value because the C ABI over wasm32 gives one, and a pair would mean either an
/// out-parameter the host must allocate or a second call to fetch the length. The length fits in 32
/// bits by construction: it indexes the guest's own 32-bit linear memory.
///
/// `0` is unambiguous as a failure: a successful result always has a non-zero pointer, because
/// `trigon_alloc` never returns the null page.
///
/// # Safety
///
/// `profile` and `data` must point at `profile_len` and `data_len` readable bytes in this module's
/// memory, which they do when the host wrote them through [`trigon_alloc`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn trigon_stabilize(
    profile: u32,
    profile_len: u32,
    format: u32,
    data: u32,
    data_len: u32,
) -> u64 {
    let profile =
        unsafe { core::slice::from_raw_parts(profile as *const u8, profile_len as usize) };
    let data = unsafe { core::slice::from_raw_parts(data as *const u8, data_len as usize) };
    let Ok(profile) = core::str::from_utf8(profile) else {
        return 0;
    };
    let Some(format) = format_from_u32(format) else {
        return 0;
    };
    match stabilize(profile, format, data.to_vec()) {
        Some(out) => {
            let len = out.len() as u64;
            let ptr = Box::leak(out.into_boxed_slice()).as_mut_ptr() as u64;
            (ptr << 32) | len
        }
        None => 0,
    }
}

/// The set digest this module implements, as 32 raw bytes at the returned pointer.
///
/// The host checks it against the digest in the attestation before trusting anything this module
/// produces. Without it a verifier would be running *a* stabilizer set and assuming it was *the*
/// one — which is the mistake the whole set-digest mechanism exists to prevent, reintroduced at the
/// point where it is hardest to notice.
///
/// # Safety
///
/// As [`trigon_stabilize`], for `profile`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn trigon_set_digest(profile: u32, profile_len: u32) -> u64 {
    let profile =
        unsafe { core::slice::from_raw_parts(profile as *const u8, profile_len as usize) };
    let Ok(profile) = core::str::from_utf8(profile) else {
        return 0;
    };
    let Some(set) = trigon_stabilize::profile(profile) else {
        return 0;
    };
    let bytes = set.digest().as_bytes().to_vec();
    let len = bytes.len() as u64;
    let ptr = Box::leak(bytes.into_boxed_slice()).as_mut_ptr() as u64;
    (ptr << 32) | len
}

/// The commit this module was built from, as UTF-8 at the returned pointer, or `0` where its build
/// named none.
///
/// `scripts/build-set-module.sh` names it in `TRIGON_SET_MODULE_COMMIT`, as `git rev-parse HEAD`
/// gives it, with `.dirty` after it when the tree has changes the commit does not, as the binary's
/// own version does; a plain `cargo build` names none. Appended to the ABI after the three above,
/// so a module built before it exports no such function, and a host reads the absence as no commit
/// named.
///
/// It is the module's word about itself, as its set digest is, and it says where to start: a
/// verifier who would rather not run the module a verdict names rebuilds it from this commit and
/// compares the sha256 with the one the verdict signs. A module that named another commit than the
/// one it was built from is caught by exactly that comparison.
#[unsafe(no_mangle)]
pub extern "C" fn trigon_source_commit() -> u64 {
    match option_env!("TRIGON_SET_MODULE_COMMIT") {
        Some(commit) if !commit.is_empty() => {
            ((commit.as_ptr() as u64) << 32) | commit.len() as u64
        }
        _ => 0,
    }
}

/// The shared implementation, callable natively so the equality test has something to compare
/// against that is not a second transcription of the same steps.
pub fn stabilize(profile: &str, format: Format, bytes: Vec<u8>) -> Option<Vec<u8>> {
    let set = trigon_stabilize::profile(profile)?;
    let mut notes = Vec::new();
    let mut parsed = trigon_archive::parse(bytes, format, &Limits::default(), &mut notes).ok()?;
    trigon_stabilize::apply(&set, &mut parsed.archive);
    trigon_archive::serialize(&parsed.archive, true).ok()
}

/// Formats as small integers, because the ABI carries no strings it does not have to.
///
/// The mapping is part of the ABI and may only be appended to: a module archived today is read by a
/// host built later, and renumbering would make an old set silently stabilize the wrong way.
pub fn format_from_u32(n: u32) -> Option<Format> {
    Some(match n {
        0 => Format::TarGz,
        1 => Format::Tar,
        2 => Format::Zip,
        3 => Format::Gzip,
        4 => Format::Raw,
        _ => return None,
    })
}

/// The inverse, for the host.
pub fn format_to_u32(f: Format) -> u32 {
    match f {
        Format::TarGz => 0,
        Format::Tar => 1,
        Format::Zip => 2,
        Format::Gzip => 3,
        Format::Raw => 4,
    }
}
