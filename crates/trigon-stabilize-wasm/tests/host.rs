//! The host, against modules assembled here: how it instantiates a module, and what it makes of the
//! commit a module names.
//!
//! Hand-assembled rather than compiled, as the parity tests' module with an import is: each is a
//! module our own toolchain would never produce, a few dozen bytes that answer the ABI exactly as a
//! test needs, and none of them needs the real module built.

#![cfg(feature = "host")]

use trigon_core::Format;
use trigon_stabilize_wasm::ArchivedSet;

/// Where the allocator starts, past the digest and the commit.
const HEAP: u32 = 1024;
const DIGEST_AT: u32 = 16;
const COMMIT_AT: u32 = 64;

/// A module of one 64 KiB page that never grows, with a bump allocator that never frees, as the
/// real guest never frees: `trigon_stabilize` hands back the artifact it was given, and
/// `trigon_set_digest` 32 bytes of `0x22`. `commit` is what `trigon_source_commit` answers: no
/// such export for `None`, `0` for an empty answer, and otherwise the bytes given.
fn echo(commit: Option<&[u8]>) -> Vec<u8> {
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

    let memory = vec![1, 0, 1]; // one memory, no maximum, one page

    // One mutable i32, the allocator's next free byte.
    let mut globals = vec![1, 0x7f, 1, 0x41];
    globals.extend(sleb(i64::from(HEAP)));
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
        exports.push(name.len() as u8);
        exports.extend(name.as_bytes());
        exports.extend([kind, index]);
    }

    let packed = |at: u32, len: usize| {
        let mut b = vec![0x42];
        b.extend(sleb((i64::from(at) << 32) | len as i64));
        b.push(0x0b);
        b
    };
    let mut bodies = vec![
        // trigon_alloc: return the next free byte, and move it on by `len`.
        vec![0x23, 0, 0x23, 0, 0x20, 0, 0x6a, 0x24, 0, 0x0b],
        // trigon_stabilize: `(data << 32) | data_len`, the artifact it was given.
        vec![0x20, 3, 0xad, 0x42, 32, 0x86, 0x20, 4, 0xad, 0x84, 0x0b],
        packed(DIGEST_AT, 32),
    ];
    match commit {
        Some([]) => bodies.push(vec![0x42, 0, 0x0b]),
        Some(c) => bodies.push(packed(COMMIT_AT, c.len())),
        None => {}
    }
    let mut code = vec![bodies.len() as u8];
    for body in bodies {
        code.extend(uleb(body.len() as u64 + 1));
        code.push(0); // no locals
        code.extend(body);
    }

    let mut data = vec![2];
    let digest = [0x22; 32];
    for (at, bytes) in [
        (DIGEST_AT, &digest[..]),
        (COMMIT_AT, commit.unwrap_or_default()),
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

/// The guest never frees, so every artifact is stabilized in an instance of its own. In one
/// instance, the second of two artifacts that each fit found the first's buffer still held, and an
/// artifact that stabilized alone failed beside another: here, the second 40,000 bytes would have
/// run past the module's one page.
#[test]
fn each_artifact_is_stabilized_in_an_instance_of_its_own() {
    let mut set = ArchivedSet::from_bytes(&echo(None)).unwrap();
    let artifact = vec![7u8; 40_000];
    for n in 0..3 {
        let out = set.stabilize("tar-gzip", Format::TarGz, &artifact);
        assert_eq!(
            out.map_err(|e| format!("{e:#}")),
            Ok(artifact.clone()),
            "artifact {n}"
        );
    }
    // The module's questions about itself are asked of an instance kept for them, beside.
    assert_eq!(set.digest("tar-gzip").unwrap().as_bytes(), &[0x22; 32]);
    let too_big = vec![7u8; 70_000];
    let e = set
        .stabilize("tar-gzip", Format::TarGz, &too_big)
        .unwrap_err();
    assert!(
        format!("{e:#}").contains("writing into the module's memory"),
        "{e:#}"
    );
}

/// The commit a module names is 40 hex digits, with `.dirty` where its tree had changes the commit
/// does not. A module built before the ABI asked, or by a plain `cargo build`, names none; and an
/// answer in any other form is refused, never passed on to be printed.
#[test]
fn a_module_names_the_commit_it_was_built_from_or_none() {
    let commit = |answer: Option<&[u8]>| {
        ArchivedSet::from_bytes(&echo(answer))
            .unwrap()
            .source_commit()
            .map_err(|e| format!("{e:#}"))
    };
    let hex = "0123456789abcdef0123456789abcdef01234567";
    assert_eq!(commit(Some(hex.as_bytes())), Ok(Some(hex.to_string())));
    let dirty = format!("{hex}.dirty");
    assert_eq!(commit(Some(dirty.as_bytes())), Ok(Some(dirty.clone())));
    assert_eq!(commit(None), Ok(None));
    assert_eq!(commit(Some(b"")), Ok(None));

    for bad in [
        &b"0123456789ABCDEF0123456789ABCDEF01234567"[..],
        &hex.as_bytes()[..39],
        b"0123456789abcdef0123456789abcdef01234567-dirty",
        b"\x1b[31mv1.0\x1b[0m",
        b"0123456789abcdef0123456789abcdef0123456\xff",
    ] {
        let e = commit(Some(bad)).unwrap_err();
        assert!(e.contains("is not a commit"), "{bad:?}: {e}");
    }
    // Longer than any commit can be: refused before it is read.
    let long = format!("{hex}.dirty.dirty");
    let e = commit(Some(long.as_bytes())).unwrap_err();
    assert!(e.contains("is not a commit"), "{e}");
}
