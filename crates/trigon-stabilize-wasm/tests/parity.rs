//! The archived stabilizer set produces the same bytes as the one compiled into the binary.
//!
//! This is what makes running an old set worth anything. A verifier who loads an archived module
//! and gets a different answer than a native build would has not checked the claim — they have
//! produced a second, unrelated one. `docs/13-roadmap.md` makes the equality a milestone criterion
//! for exactly that reason.
//!
//! Skipped unless the module has been built, because it needs a second toolchain target:
//!
//! ```text
//! cargo build -p trigon-stabilize-wasm --target wasm32-unknown-unknown --release
//! cargo test -p trigon-stabilize-wasm --features host
//! ```
//!
//! Skipping loudly rather than silently: a parity test that quietly passes when it did not run is
//! worse than no parity test, because it is a green tick standing in for an unchecked claim.

#![cfg(feature = "host")]

use std::io::Write as _;
use std::path::PathBuf;

use trigon_archive::Limits;
use trigon_core::Format;

fn module() -> Option<PathBuf> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/wasm32-unknown-unknown/release/trigon_stabilize_wasm.wasm");
    p.exists().then_some(p)
}

/// The same work the guest does, done natively.
fn native(profile: &str, format: Format, bytes: Vec<u8>) -> Vec<u8> {
    let set = trigon_stabilize::profile(profile).expect("profile");
    let mut notes = Vec::new();
    let mut parsed = trigon_archive::parse(bytes, format, &Limits::default(), &mut notes).unwrap();
    trigon_stabilize::apply(&set, &mut parsed.archive);
    trigon_archive::serialize(&parsed.archive, true).unwrap()
}

fn tar_gz(mtime: u64, uid: u64) -> Vec<u8> {
    let mut b = ::tar::Builder::new(Vec::new());
    for (name, body) in [("pkg/a.txt", &b"hello"[..]), ("pkg/b.txt", &b"world"[..])] {
        let mut h = ::tar::Header::new_ustar();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(mtime);
        h.set_uid(uid);
        h.set_cksum();
        b.append_data(&mut h, name, body).unwrap();
    }
    let tar = b.into_inner().unwrap();
    let mut gz = Vec::new();
    let mut e = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
    e.write_all(&tar).unwrap();
    e.finish().unwrap();
    gz
}

fn wheel(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = zip_crate::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts: zip_crate::write::FileOptions<'_, ()> = zip_crate::write::FileOptions::default()
        .compression_method(zip_crate::CompressionMethod::Stored);
    for (name, body) in members {
        w.start_file(*name, opts).unwrap();
        w.write_all(body).unwrap();
    }
    w.finish().unwrap().into_inner()
}

#[test]
fn the_archived_set_and_the_compiled_one_agree_byte_for_byte() {
    let Some(path) = module() else {
        panic!(
            "the stabilizer module is not built. Run:\n  cargo build -p trigon-stabilize-wasm \
             --target wasm32-unknown-unknown --release\nA parity test that skips silently is a \
             green tick standing in for an unchecked claim."
        );
    };
    let mut archived = trigon_stabilize_wasm::ArchivedSet::load(&path).unwrap();

    let cases: Vec<(&str, Format, Vec<u8>)> = vec![
        ("tar-gzip", Format::TarGz, tar_gz(1, 0)),
        ("tar-gzip", Format::TarGz, tar_gz(1_700_000_000, 501)),
        (
            "wheel",
            Format::Zip,
            wheel(&[
                ("demo/__init__.py", b"x = 1\n"),
                (
                    "demo-1.0.dist-info/METADATA",
                    b"Name: demo\r\nVersion: 1.0\r\n",
                ),
                ("demo-1.0.dist-info/RECORD", b""),
            ]),
        ),
        (
            "zip",
            Format::Zip,
            wheel(&[("a.txt", b"one"), ("b.txt", b"two")]),
        ),
    ];

    for (profile, format, bytes) in cases {
        let want = native(profile, format, bytes.clone());
        let got = archived.stabilize(profile, format, &bytes).unwrap();
        assert_eq!(
            got, want,
            "`{profile}` stabilized differently in wasm than natively"
        );
    }
}

#[test]
fn the_module_reports_the_set_digest_the_native_build_computes() {
    // The check that makes the rest safe. A verifier who does not compare digests is running *a*
    // stabilizer set and assuming it was *the* one, and a wrong set yields a plausible digest
    // rather than an error.
    let Some(path) = module() else {
        panic!("the stabilizer module is not built; see the sibling test");
    };
    let mut archived = trigon_stabilize_wasm::ArchivedSet::load(&path).unwrap();
    for profile in trigon_stabilize::all_profiles() {
        let native = trigon_stabilize::profile(profile).unwrap().digest();
        assert_eq!(
            archived.digest(profile).unwrap(),
            native,
            "`{profile}` digest differs between wasm and native"
        );
        archived.check(profile, &native.to_hex()).unwrap();
    }
}

#[test]
fn a_module_implementing_a_different_set_is_refused() {
    let Some(path) = module() else {
        panic!("the stabilizer module is not built; see the sibling test");
    };
    let mut archived = trigon_stabilize_wasm::ArchivedSet::load(&path).unwrap();
    let e = archived.check("wheel", &"ab".repeat(32)).unwrap_err();
    assert!(e.to_string().contains("different question"), "{e}");
}

#[test]
fn an_unparseable_artifact_is_a_refusal_rather_than_a_plausible_answer() {
    // `0` from the guest is unambiguous, and the host turns it into an error. Returning empty bytes
    // would stabilize to a digest that looks like an answer.
    let Some(path) = module() else {
        panic!("the stabilizer module is not built; see the sibling test");
    };
    let mut archived = trigon_stabilize_wasm::ArchivedSet::load(&path).unwrap();
    let e = archived
        .stabilize("wheel", Format::Zip, b"not a zip at all")
        .unwrap_err();
    assert!(e.to_string().contains("refused"), "{e}");
}

#[test]
fn a_module_that_wants_an_import_is_refused_at_load() {
    // The security-relevant path, and the reason this guest is worth running at all. A stabilizer
    // that could reach a clock, a socket or a file could make a comparison depend on something
    // outside the two artifacts — and the whole design rests on it being unable to. Refused at
    // instantiation rather than at first call, so the failure names the module rather than
    // appearing later as a strange result.
    //
    // Hand-assembled rather than compiled: the point is a module our own toolchain would never
    // produce, and the bytes are the specification.
    #[rustfmt::skip]
    let with_import: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic, version 1
        0x01, 0x04, 0x01, 0x60, 0x00, 0x00,             // type section: one () -> ()
        0x02, 0x07, 0x01,                               // import section, one entry
        0x01, b'e',                                     //   module "e"
        0x01, b'f',                                     //   name "f"
        0x00, 0x00,                                     //   a function of type 0
    ];
    let dir = std::env::temp_dir().join(format!("trigon-wasm-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("imports.wasm");
    std::fs::write(&path, with_import).unwrap();

    let text = match trigon_stabilize_wasm::ArchivedSet::load(&path) {
        Ok(_) => panic!("a module declaring an import must not load"),
        Err(e) => e.to_string(),
    };
    assert!(
        text.contains("e::f"),
        "the refusal should name what it wanted: {text}"
    );
    assert!(
        text.contains("pure by construction"),
        "and say why it is refused: {text}"
    );
}

#[test]
fn a_file_that_is_not_wasm_at_all_fails_with_its_path() {
    // A verifier points `--stabilizers` at the wrong file eventually. The error should say which
    // file, because "failed to parse" with no path is the same message for every mistake.
    let dir = std::env::temp_dir().join(format!("trigon-wasm-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("not-a-module.wasm");
    std::fs::write(&path, b"{\"id\":\"wheel\"}").unwrap();

    let text = match trigon_stabilize_wasm::ArchivedSet::load(&path) {
        Ok(_) => panic!("a JSON file must not load as a module"),
        Err(e) => format!("{e:#}"),
    };
    assert!(text.contains("not-a-module.wasm"), "{text}");
}
