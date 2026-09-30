//! Stabilizer-set modules for the tests that need one: the module `scripts/build-set-module.sh`
//! builds from this checkout, and modules assembled here that answer the ABI however a test asks.
//!
//! The built one is needed wherever a verdict is published, since `trigon publish` refuses a
//! verdict that names no module and `trigon attest` names only a module that reproduces the run.
//! It is looked for where the script puts it, beside the binary under test, and a test that needs
//! it and finds none fails saying how to build it, as the parity tests of `trigon-stabilize-wasm`
//! do: a test that skipped would be a green tick for a check nobody made.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// The module `scripts/build-set-module.sh` builds, in the target directory the binary under test
/// was built in.
pub fn built() -> PathBuf {
    let target = Path::new(env!("CARGO_BIN_EXE_trigon"))
        .parent()
        .and_then(Path::parent)
        .expect("the binary is in <target>/<profile>/");
    let module = target.join("wasm32-unknown-unknown/release/trigon_stabilize_wasm.wasm");
    assert!(
        module.is_file(),
        "no stabilizer-set module at {}. Build it with:\n  scripts/build-set-module.sh\n(with the \
         same CARGO_TARGET_DIR as the tests, and `rustup target add wasm32-unknown-unknown` once). \
         Publishing a verdict needs one, and a test that skipped would pass without checking \
         anything.",
        module.display()
    );
    module
}

/// A module assembled here, pure as the real one is — no imports — that reports `set_digest` for
/// every profile and stabilizes every artifact to `output`, whatever its bytes: the ABI of
/// `trigon-stabilize-wasm`, answered by a module no source of ours builds.
///
/// A fake with the right set digest is the dishonest or mistaken module the set digest cannot
/// catch; one with another digest is a module of a set this binary does not carry, which is what
/// a verifier holding an old verdict has.
pub fn fake(set_digest: [u8; 32], output: &[u8]) -> Vec<u8> {
    fake_naming(set_digest, output, None)
}

/// [`fake`], naming `commit` as the commit it was built from (`trigon_source_commit`), as a module
/// `scripts/build-set-module.sh` builds names one; `None` exports no such function, as a module
/// built before the ABI asked.
pub fn fake_naming(set_digest: [u8; 32], output: &[u8], commit: Option<&str>) -> Vec<u8> {
    const DIGEST_AT: u32 = 16;
    const COMMIT_AT: u32 = 64;
    const OUTPUT_AT: u32 = 128;
    // Allocations start past all three, and the memory is 16 MiB, far beyond any artifact here.
    let heap = OUTPUT_AT + output.len() as u32 + 1024;
    let pages = 256;

    let mut types = vec![4];
    types.extend([0x60, 1, 0x7f, 1, 0x7f]); // (i32) -> i32: trigon_alloc
    types.extend([0x60, 5, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7e]); // trigon_stabilize
    types.extend([0x60, 2, 0x7f, 0x7f, 1, 0x7e]); // trigon_set_digest
    types.extend([0x60, 0, 1, 0x7e]); // () -> i64: trigon_source_commit

    let mut functions = vec![0, 1, 2];
    if commit.is_some() {
        functions.push(3);
    }
    functions.insert(0, functions.len() as u8);

    let mut memory = vec![1, 0];
    memory.extend(uleb(pages));

    // One mutable i32, the allocator's next free byte.
    let mut globals = vec![1, 0x7f, 1, 0x41];
    globals.extend(sleb(i64::from(heap)));
    globals.push(0x0b);

    let mut names = vec![
        ("memory", 2u8, 0u8),
        ("trigon_alloc", 0, 0),
        ("trigon_stabilize", 0, 1),
        ("trigon_set_digest", 0, 2),
    ];
    if commit.is_some() {
        names.push(("trigon_source_commit", 0, 3));
    }
    let mut exports = vec![names.len() as u8];
    for (name, kind, index) in names {
        exports.extend(uleb(name.len() as u64));
        exports.extend(name.as_bytes());
        exports.extend([kind, index]);
    }

    // trigon_alloc: return the next free byte, and move it on by `len`.
    let alloc = vec![
        0x23, 0, // global.get 0
        0x23, 0, // global.get 0
        0x20, 0,    // local.get 0
        0x6a, // i32.add
        0x24, 0, // global.set 0
        0x0b,
    ];
    let packed = |at: u32, len: usize| {
        let mut b = vec![0x42];
        b.extend(sleb(((at as i64) << 32) | len as i64));
        b.push(0x0b);
        b
    };
    let mut bodies = vec![
        alloc,
        packed(OUTPUT_AT, output.len()),
        packed(DIGEST_AT, 32),
    ];
    if let Some(c) = commit {
        bodies.push(packed(COMMIT_AT, c.len()));
    }
    let mut code = vec![bodies.len() as u8];
    for body in bodies {
        let mut f = vec![0]; // no locals
        f.extend(body);
        code.extend(uleb(f.len() as u64));
        code.extend(f);
    }

    let mut data = vec![3];
    let commit = commit.unwrap_or_default().as_bytes();
    for (at, bytes) in [
        (DIGEST_AT, &set_digest[..]),
        (COMMIT_AT, commit),
        (OUTPUT_AT, output),
    ] {
        data.extend([0, 0x41]);
        data.extend(sleb(i64::from(at)));
        data.push(0x0b);
        data.extend(uleb(bytes.len() as u64));
        data.extend(bytes);
    }

    let mut m = b"\0asm\x01\0\0\0".to_vec();
    for (id, body) in [
        (1u8, types),
        (3, functions),
        (5, memory),
        (6, globals),
        (7, exports),
        (10, code),
        (11, data),
    ] {
        m.push(id);
        m.extend(uleb(body.len() as u64));
        m.extend(body);
    }
    m
}

/// The set digest [`retire`] signs a run's statements under, which no binary carries.
pub const RETIRED: [u8; 32] = [0x11; 32];

/// Sign run `id`'s verdict and its `rebuild` statement again with `key`, as they would have been
/// signed had the run compared under [`RETIRED`], and named `module`, which stabilizes every
/// artifact to `stable`, as its stabilizer-set module; and keep the module in the store, as
/// `attest` keeps one. An old verdict, as a binary that no longer carries its set meets it.
pub fn retire(store: &Path, id: &str, key: &trigon_attest::LocalKey, module: &[u8], stable: &[u8]) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let s = trigon_store::Store::local(store).unwrap();
    rt.block_on(s.blobs().put(module.to_vec())).unwrap();
    let run = rt.block_on(s.get_run(id)).unwrap();
    let set = RETIRED
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    for path in &run.attestations {
        let file = store.join(path);
        let env: trigon_attest::Envelope =
            serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        let mut st: trigon_attest::Statement =
            serde_json::from_slice(&env.decoded_payload().unwrap()).unwrap();
        let verdict = trigon_attest::is_verdict(&st.predicate_type);
        let p = &mut st.predicate;
        if verdict {
            p["stabilized"]["upstream"]["sha256"] = sha256(stable).into();
            p["stabilized"]["rebuild"]["sha256"] = sha256(stable).into();
            p["evidence"]["stabilizerSetModule"] = serde_json::json!({ "sha256": sha256(module) });
        }
        if p.get("stabilizerSet").is_some() {
            p["stabilizerSet"]["digest"]["sha256"] = set.clone().into();
        }
        let env = trigon_attest::sign_statement(&st, key).unwrap();
        std::fs::write(&file, serde_json::to_vec_pretty(&env).unwrap()).unwrap();
    }
}

/// The sha256 of `bytes`, in hex.
pub fn sha256(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn uleb(mut n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

fn sleb(mut n: i64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        let done = (n == 0 && byte & 0x40 == 0) || (n == -1 && byte & 0x40 != 0);
        if done {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}
