//! The archived stabilizer set produces the same bytes as the one compiled into the binary.
//!
//! This is what makes running an old set worth anything. A verifier who loads an archived module
//! and gets a different answer than a native build would has not checked the claim — they have
//! produced a second, unrelated one. `docs/13-roadmap.md` makes the equality a milestone criterion
//! for exactly that reason.
//!
//! The module needs a second toolchain target, and these fail, saying how to build it, where it has
//! not been built into the target directory the tests are built in. The script builds it as it is
//! published, reproducibly, naming the commit it was built from:
//!
//! ```text
//! scripts/build-set-module.sh
//! cargo test -p trigon-stabilize-wasm --features host
//! ```
//!
//! The one test about the script's own module, the commit it names, runs the script itself, into a
//! target directory of its own: the module beside the tests is whichever build of it ran last.
//!
//! Failing loudly rather than skipping silently: a parity test that quietly passes when it did not
//! run is worse than no parity test, because it is a green tick standing in for an unchecked claim.

#![cfg(feature = "host")]

use std::io::Write as _;
use std::path::PathBuf;

use trigon_archive::Limits;
use trigon_core::Format;

/// The module `scripts/build-set-module.sh` builds, in the target directory this test was built in:
/// `CARGO_TARGET_DIR`'s where it is set, as the script's is, and not the checkout's `target/`,
/// which may hold a module built from other sources.
fn module() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    // <target>/<profile>/deps/<this test>
    let target = exe.parent()?.parent()?.parent()?;
    let p = target.join("wasm32-unknown-unknown/release/trigon_stabilize_wasm.wasm");
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
            "the stabilizer module is not built. Run:\n  scripts/build-set-module.sh\nwith the \
             same CARGO_TARGET_DIR as the tests. A parity test that skips silently is a green \
             tick standing in for an unchecked claim."
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

/// The module the script builds names the commit it was built from, which is where a verifier who
/// rebuilds it to compare digests starts; built outside a git checkout, it names none.
///
/// The script is run here, into a target directory no other build uses. A plain `cargo build` of
/// the module names no commit, and the module beside the tests is whichever build of it ran last,
/// so reading that one tested the order the builds ran in rather than the script: it failed after
/// any plain build of the module. The first run compiles the module, about ten seconds; after that
/// cargo has nothing to do until a source or the commit changes.
#[test]
fn the_module_the_script_builds_names_the_commit_it_was_built_from() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let target = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("build-set-module");
    let built = std::process::Command::new("bash")
        .arg(root.join("scripts/build-set-module.sh"))
        .env("CARGO_TARGET_DIR", &target)
        // From what cargo has already fetched: a test does not touch the network.
        .env("CARGO_NET_OFFLINE", "true")
        .output()
        .expect("bash runs");
    let said = String::from_utf8_lossy(&built.stdout).into_owned();
    assert!(
        built.status.success(),
        "scripts/build-set-module.sh failed:\n{said}{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let path = target.join("wasm32-unknown-unknown/release/trigon_stabilize_wasm.wasm");
    assert!(
        said.contains(&format!("module  {}\n", path.display())),
        "{said}"
    );

    // Asked as the script asks it, with nothing in the environment pointing git elsewhere.
    let top = std::process::Command::new("git")
        .arg("-C")
        .arg(&root)
        .args(["rev-parse", "--show-toplevel"])
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| {
            PathBuf::from(String::from_utf8(o.stdout).ok()?.trim())
                .canonicalize()
                .ok()
        });
    let in_a_checkout = top.as_deref() == Some(root.as_path());
    let named = trigon_stabilize_wasm::ArchivedSet::load(&path)
        .unwrap()
        .source_commit()
        .unwrap();
    assert_eq!(
        named.is_some(),
        in_a_checkout,
        "the module the script built at {} names {named:?}, and {} a git checkout",
        path.display(),
        if in_a_checkout {
            "this is"
        } else {
            "this is not"
        }
    );
    // The commit it names is the one the script says it named.
    let printed = said
        .lines()
        .find_map(|l| l.strip_prefix("commit  "))
        .unwrap_or_else(|| panic!("the script printed no commit: {said}"));
    match &named {
        Some(named) => assert_eq!(printed, named, "{said}"),
        None => assert!(printed.starts_with("none: "), "{said}"),
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
    // The zero merges running out of memory in with the rest, and the refusal says so: an artifact
    // that expands past what a module can address is refused this way, not as malformed alone.
    assert!(
        e.to_string()
            .contains("or ran out of the memory a module can address"),
        "{e}"
    );
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

/// A module loaded from its bytes is the module its file holds. It is the form `trigon attest` and
/// `verify-attestation` load, since each runs exactly the bytes it held to a digest; reading the
/// file again to load it would run bytes nobody hashed. Bytes that are no module are refused as
/// such, and so is a module that wants an import, whichever way it is loaded.
#[test]
fn a_module_loaded_from_its_bytes_is_the_module_its_file_holds() {
    let Some(path) = module() else {
        panic!("the stabilizer module is not built; see the sibling test");
    };
    let bytes = std::fs::read(&path).unwrap();
    let mut from_file = trigon_stabilize_wasm::ArchivedSet::load(&path).unwrap();
    let mut from_bytes = trigon_stabilize_wasm::ArchivedSet::from_bytes(&bytes).unwrap();
    for profile in trigon_stabilize::all_profiles() {
        assert_eq!(
            from_bytes.digest(profile).unwrap(),
            from_file.digest(profile).unwrap(),
            "{profile}"
        );
    }
    let artifact = tar_gz(1_700_000_000, 501);
    assert_eq!(
        from_bytes
            .stabilize("tar-gzip", Format::TarGz, &artifact)
            .unwrap(),
        from_file
            .stabilize("tar-gzip", Format::TarGz, &artifact)
            .unwrap()
    );

    let refused = |bytes: &[u8]| match trigon_stabilize_wasm::ArchivedSet::from_bytes(bytes) {
        Ok(_) => panic!("{bytes:?} loaded as a module"),
        Err(e) => format!("{e:#}"),
    };
    let e = refused(b"{\"id\":\"wheel\"}");
    assert!(e.contains("WebAssembly module"), "{e}");
    #[rustfmt::skip]
    let with_import: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
        0x02, 0x07, 0x01, 0x01, b'e', 0x01, b'f', 0x00, 0x00,
    ];
    let e = refused(with_import);
    assert!(e.contains("pure by construction"), "{e}");
}

/// A module that predates a profile must say so, rather than blame the artifact.
///
/// Found by running this file's own parity test against a module built four days earlier: `nupkg`
/// had been added to the native set in the meantime, and asking the old module for it produced
/// "the module refused: it could not parse the artifact under that profile". The artifact was a
/// well-formed `.nupkg`. A verifier reading that goes and looks at the package.
///
/// The cause is a sentinel doing double duty: the guest returns `0` for an unknown profile, for an
/// unparseable artifact, and for a failed serialize alike, and the host turned every one of them
/// into the middle sentence. Which is [`docs/16-findings.md` §3.42] again — three reasons a thing
/// has no bytes, reported as one — in a second crate.
///
/// The ABI is archival and may only be appended to, so the fix is on the host side: it re-asks
/// `trigon_set_digest`, which answers the profile question by itself.
#[test]
fn a_profile_the_module_does_not_have_blames_the_module_not_the_artifact() {
    let Some(path) = module() else {
        panic!("the stabilizer module is not built; see the sibling test");
    };
    let mut archived = trigon_stabilize_wasm::ArchivedSet::load(&path).unwrap();

    // A profile no set has ever implemented stands in for one archived before it existed: the
    // guest cannot tell those apart either, and returns the same zero for both.
    let e = archived.digest("no-such-profile").unwrap_err().to_string();
    assert!(
        e.contains("does not implement the profile `no-such-profile`"),
        "asking for a missing profile must name the profile: {e}"
    );
    // One sentence after another, as a reader sees them: a literal joined across source lines
    // without a continuation kept each line's indentation in the middle of the message.
    assert!(
        !e.contains("  "),
        "a run of spaces inside the message: {e:?}"
    );
    assert!(
        !e.contains("parse"),
        "and must not blame the artifact, which was never passed: {e}"
    );

    // The same question reached through `stabilize`, where the sentinel is genuinely ambiguous and
    // the host has to go and disambiguate it.
    let e = archived
        .stabilize("no-such-profile", Format::Zip, &wheel(&[("a.txt", b"one")]))
        .unwrap_err()
        .to_string();
    assert!(
        e.contains("does not implement the profile"),
        "a valid artifact under an unknown profile is a module problem: {e}"
    );

    // And the converse still reports what it used to, or the fix has just moved the confusion.
    let e = archived
        .stabilize("wheel", Format::Zip, b"not a zip at all")
        .unwrap_err()
        .to_string();
    assert!(
        e.contains("refused these bytes"),
        "a profile the module has, with bytes it cannot read, is an artifact problem: {e}"
    );

    // `check` is the control that stops a verifier running the wrong set, so its diagnosis is the
    // one that most needs to point at the right thing.
    let e = archived
        .check("no-such-profile", &"ab".repeat(32))
        .unwrap_err()
        .to_string();
    assert!(
        e.contains("does not implement the profile"),
        "check must distinguish `this module lacks the profile` from `this module has a different \
         set`, because the two have different remedies: {e}"
    );
}

// --- a managed assembly whose header values overflow 32 bits -------------------------------------

/// Where [`assembly`] wrote what the cases below overwrite, as file offsets.
struct Fields {
    /// The section header's PointerToRawData.
    section_raw: usize,
    /// The metadata root's `BSJB`.
    metadata: usize,
    version_len: usize,
    /// Each stream header's offset field, in the order `#~`, `#Strings`, `#GUID`, `#Blob`.
    streams: [usize; 4],
    typeref_count: usize,
}

fn put16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn put32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn set16(v: &mut [u8], at: usize, x: u16) {
    v[at..at + 2].copy_from_slice(&x.to_le_bytes());
}
fn set32(v: &mut [u8], at: usize, x: u32) {
    v[at..at + 4].copy_from_slice(&x.to_le_bytes());
}
fn align4(v: &mut Vec<u8>) {
    while v.len() % 4 != 0 {
        v.push(0);
    }
}

/// A managed PE both .NET passes read whole (ECMA-335 §II.24–§II.25): one section, mapped at
/// `rva` with `vsize` bytes of address space, holding the CLI header, one method body and, `pad`
/// bytes further on, the metadata, with a row each in Module, TypeRef, TypeDef and MethodDef.
fn assembly(rva: u32, vsize: u32, pad: usize) -> (Vec<u8>, Fields) {
    const RAW: usize = 0x200;
    let mut sec = vec![0u8; 72];
    // `Run`: a tiny header, then `nop; ret`.
    let body = sec.len();
    sec.extend_from_slice(&[(2 << 2) | 0x02, 0x00, 0x2a, 0x00]);
    sec.extend(std::iter::repeat_n(0, pad));

    // The table stream: version 2.0, narrow heaps, and Module, TypeRef, TypeDef and MethodDef.
    let mut t = Vec::new();
    put32(&mut t, 0);
    t.extend_from_slice(&[2, 0, 0, 1]);
    t.extend_from_slice(&0b100_0111u64.to_le_bytes());
    t.extend_from_slice(&0u64.to_le_bytes());
    put32(&mut t, 1);
    let typeref_count = t.len();
    for _ in 0..3 {
        put32(&mut t, 1);
    }
    // Module: Generation, Name, Mvid, EncId, EncBaseId.
    for x in [0, 10, 1, 0, 0] {
        put16(&mut t, x);
    }
    // TypeRef: ResolutionScope (AssemblyRef 1), TypeName, TypeNamespace.
    for x in [(1 << 2) | 2, 1, 0] {
        put16(&mut t, x);
    }
    // TypeDef: Flags, Name, Namespace, Extends, FieldList, MethodList.
    put32(&mut t, 0);
    for x in [1, 0, 0, 1, 1] {
        put16(&mut t, x);
    }
    // MethodDef: RVA, ImplFlags, Flags, Name, Signature (`void ()`), ParamList.
    put32(&mut t, rva + body as u32);
    for x in [0, 0x0086, 19, 1, 1] {
        put16(&mut t, x);
    }
    let streams: [(&str, Vec<u8>); 4] = [
        ("#~", t),
        ("#Strings", b"\0<Module>\0Demo.dll\0Run\0".to_vec()),
        ("#GUID", vec![0x11; 16]),
        ("#Blob", vec![0, 3, 0x00, 0x00, 0x01]),
    ];

    // The metadata root and its stream headers.
    let md_at = sec.len();
    let mut md = b"BSJB".to_vec();
    put16(&mut md, 1);
    put16(&mut md, 1);
    put32(&mut md, 0);
    let version_len = RAW + md_at + md.len();
    put32(&mut md, 12);
    md.extend_from_slice(b"v4.0.30319\0\0");
    put16(&mut md, 0);
    put16(&mut md, streams.len() as u16);
    let header_len = md.len()
        + streams
            .iter()
            .map(|(name, _)| 8 + ((name.len() + 1 + 3) & !3))
            .sum::<usize>();
    let mut off = header_len;
    let mut headers = [0; 4];
    for (i, (name, data)) in streams.iter().enumerate() {
        headers[i] = RAW + md_at + md.len();
        put32(&mut md, off as u32);
        put32(&mut md, data.len() as u32);
        md.extend_from_slice(name.as_bytes());
        md.push(0);
        align4(&mut md);
        off += (data.len() + 3) & !3;
    }
    for (_, data) in &streams {
        md.extend_from_slice(data);
        align4(&mut md);
    }
    sec.extend_from_slice(&md);

    // The CLI header: its size, runtime 2.5, the metadata's RVA and size, ILONLY.
    set32(&mut sec, 0, 72);
    set16(&mut sec, 4, 2);
    set16(&mut sec, 6, 5);
    set32(&mut sec, 8, rva + md_at as u32);
    set32(&mut sec, 12, md.len() as u32);
    set32(&mut sec, 16, 1);

    // DOS stub, PE signature, COFF header, PE32 optional header and the one section header.
    let mut f = vec![0u8; RAW];
    f[0..2].copy_from_slice(b"MZ");
    set32(&mut f, 0x3c, 0x80);
    f[0x80..0x84].copy_from_slice(b"PE\0\0");
    set16(&mut f, 0x84, 0x014c);
    set16(&mut f, 0x86, 1);
    set32(&mut f, 0x88, 0x6543_2100);
    set16(&mut f, 0x94, 96 + 16 * 8);
    set16(&mut f, 0x96, 0x2102);
    let opt = 0x98;
    set16(&mut f, opt, 0x10b);
    set32(&mut f, opt + 64, 0x0001_2345);
    set32(&mut f, opt + 92, 16);
    set32(&mut f, opt + 96 + 14 * 8, rva);
    set32(&mut f, opt + 96 + 14 * 8 + 4, 72);
    let sh = opt + 96 + 16 * 8;
    f[sh..sh + 5].copy_from_slice(b".text");
    set32(&mut f, sh + 8, vsize);
    set32(&mut f, sh + 12, rva);
    set32(&mut f, sh + 16, sec.len() as u32);
    set32(&mut f, sh + 20, RAW as u32);
    set32(&mut f, sh + 36, 0x6000_0020);
    f.extend_from_slice(&sec);
    let fields = Fields {
        section_raw: sh + 20,
        metadata: RAW + md_at,
        version_len,
        streams: headers,
        typeref_count: RAW + md_at + header_len + typeref_count,
    };
    (f, fields)
}

fn nupkg(dll: &[u8]) -> Vec<u8> {
    wheel(&[
        (
            "Demo.nuspec",
            b"<package><metadata><id>Demo</id></metadata></package>",
        ),
        ("lib/net8.0/Demo.dll", dll),
    ])
}

/// The passes that fired, natively, over `bytes` under `profile`.
fn native_applied(profile: &str, bytes: Vec<u8>) -> Vec<String> {
    let set = trigon_stabilize::profile(profile).expect("profile");
    let mut notes = Vec::new();
    let mut parsed =
        trigon_archive::parse(bytes, Format::Zip, &Limits::default(), &mut notes).unwrap();
    trigon_stabilize::apply(&set, &mut parsed.archive)
        .iter()
        .map(|a| a.id.as_str().to_string())
        .collect()
}

/// Stabilizers are total, and the archived set is the same set. But the guest is wasm32: its
/// `usize` is 32 bits, and release builds keep overflow checks, so a header value the publisher
/// chose that overflows a sum there traps the guest where the native build returns bytes, and the
/// archived set cannot re-check that artifact at all. Each assembly below puts one such value
/// where a PE walker adds to it.
#[test]
fn the_archived_set_reads_an_assembly_whose_offsets_overflow_32_bits_as_the_native_one_does() {
    let Some(path) = module() else {
        panic!("the stabilizer module is not built; see the sibling test");
    };
    let mut archived = trigon_stabilize_wasm::ArchivedSet::load(&path).unwrap();

    let (high, _) = assembly(0xffff_f000, 0x2000, 0);
    let (base, at) = assembly(0x2000, 0x1000, 0);
    // The metadata two bytes off a 4-byte boundary, as nothing but the publisher's word puts it.
    let (skewed, skewed_at) = assembly(0x2000, 0x1000, 2);
    // Each is an assembly both .NET passes read, so each case below changes one value and
    // nothing else about what the walkers reach.
    for (what, dll) in [
        ("mapped at 0x2000", &base),
        ("mapped at 0xffff_f000", &high),
        ("with its metadata off a 4-byte boundary", &skewed),
    ] {
        let applied = native_applied("nupkg", nupkg(dll));
        for id in ["dotnet-assembly-identity-v2", "dotnet-il-canonical-v3"] {
            assert!(
                applied.iter().any(|a| a == id),
                "{what}: `{id}` did not read the fixture: {applied:?}"
            );
        }
    }
    let patched = |dll: &[u8], edits: &[(usize, u32)]| {
        let mut b = dll.to_vec();
        for &(at, x) in edits {
            set32(&mut b, at, x);
        }
        b
    };
    // A version-string length that puts the stream directory at `end` bytes into the address
    // space, for a metadata root at `md`.
    let directory_at = |md: usize, end: u64| {
        let len = end - (md as u64 + 16);
        assert_eq!(len % 4, 0, "the reader pads the length to 4");
        u32::try_from(len).unwrap()
    };
    let [tables, strings, guid, blob] = at.streams;
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "a section whose address range ends past 4 GiB",
            high.clone(),
        ),
        (
            "a section whose raw data starts 8 bytes short of 4 GiB",
            patched(&base, &[(at.section_raw, 0xffff_fff8)]),
        ),
        (
            "a PE header 2 bytes short of 4 GiB",
            patched(&base, &[(0x3c, 0xffff_fffe)]),
        ),
        (
            "0x3000_0000 TypeRef rows",
            patched(&base, &[(at.typeref_count, 0x3000_0000)]),
        ),
        (
            "a metadata version string u32::MAX bytes long",
            patched(&base, &[(at.version_len, u32::MAX)]),
        ),
        (
            "a metadata version string that ends past 4 GiB",
            patched(&base, &[(at.version_len, 0xffff_fff0)]),
        ),
        (
            "a stream directory 4 bytes short of 4 GiB",
            patched(
                &base,
                &[(at.version_len, directory_at(at.metadata, 0xffff_fffc))],
            ),
        ),
        (
            "a stream directory 2 bytes short of 4 GiB",
            patched(
                &skewed,
                &[(
                    skewed_at.version_len,
                    directory_at(skewed_at.metadata, 0xffff_fffe),
                )],
            ),
        ),
        (
            "a #~ stream 0xffff_ff00 past the metadata",
            patched(&base, &[(tables, 0xffff_ff00)]),
        ),
        (
            "a #Strings stream 0xffff_ff00 past the metadata",
            patched(&base, &[(strings, 0xffff_ff00)]),
        ),
        (
            "a #Blob stream 0xffff_ff00 past the metadata",
            patched(&base, &[(blob, 0xffff_ff00)]),
        ),
        (
            // Only the identity pass reads `#GUID`, where it adds the stream's offset to the
            // metadata's to place the heap it would zero. Placed past the file, the heap is not
            // shown to be one and the pass declines, and `dotnet-il-canonical-v3`, which never
            // reads `#GUID`, reads the assembly as it would without it.
            "a #GUID stream 0xffff_ff00 past the metadata",
            patched(&base, &[(guid, 0xffff_ff00)]),
        ),
    ];
    for (what, dll) in cases {
        let bytes = nupkg(&dll);
        let want = native("nupkg", Format::Zip, bytes.clone());
        let got = archived
            .stabilize("nupkg", Format::Zip, &bytes)
            .unwrap_or_else(|e| {
                panic!("{what}: the archived set failed where native did not: {e:#}")
            });
        assert!(
            got == want,
            "{what}: stabilized differently in wasm than natively"
        );
    }
}
