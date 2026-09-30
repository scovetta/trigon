//! `verify-attestation <bundle> --rerun-comparison`, where the claim does not simply hold: a
//! statement made under a stabilizer set this binary does not carry, a manifest that is or is not
//! that set, arguments that cannot rerun anything, and a statement whose outcome re-derives while
//! what it says the comparison found does not.
//!
//! The set case is the one `--stabilizers` exists for. A verifier told only that two digests
//! disagree has no way to learn what the first one was; a published manifest turns that dead end
//! into something a person can act on — and only a manifest that is self-consistent and is the
//! claim's set may be believed, since a correct document for some other set is the wrong answer.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use base64::Engine as _;

mod set_module;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_trigon")
}

fn dir(what: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "trigon-verify-attestation-sets-{}-{what}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_tgz(path: &Path, body: &[u8], mtime: u64) {
    let mut b = ::tar::Builder::new(Vec::new());
    let mut h = ::tar::Header::new_ustar();
    h.set_size(body.len() as u64);
    h.set_mode(0o644);
    h.set_mtime(mtime);
    h.set_cksum();
    b.append_data(&mut h, "package/index.js", body).unwrap();
    let tar = b.into_inner().unwrap();
    let mut gz = Vec::new();
    {
        use std::io::Write as _;
        let mut e = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
        e.write_all(&tar).unwrap();
        e.finish().unwrap();
    }
    std::fs::write(path, gz).unwrap();
}

fn trigon(args: &[&std::ffi::OsStr]) -> Output {
    Command::new(bin())
        .env("NO_COLOR", "1")
        .args(args)
        .output()
        .unwrap()
}

/// Two tarballs that differ only in their mtime, and the unsigned bundle `trigon verify` writes
/// about them: a `normalized` claim under this binary's `tar-gzip`.
struct Claim {
    upstream: PathBuf,
    rebuild: PathBuf,
    bundle: PathBuf,
}

fn claim(d: &Path) -> Claim {
    let upstream = d.join("up.tgz");
    let rebuild = d.join("rb.tgz");
    write_tgz(&upstream, b"module.exports = 1;\n", 1_700_000_000);
    write_tgz(&rebuild, b"module.exports = 1;\n", 1_800_000_000);
    let bundle = d.join("claim.json");
    let out = Command::new(bin())
        .arg("verify")
        .arg(&upstream)
        .arg(&rebuild)
        .arg("--attest")
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    Claim {
        upstream,
        rebuild,
        bundle,
    }
}

/// Rewrite the statement inside an unsigned bundle. An unsigned bundle carries no signature to
/// break, which is exactly why re-deriving it is the only check it gets.
fn edit(bundle: &Path, change: impl FnOnce(&mut serde_json::Value)) {
    let engine = base64::engine::general_purpose::STANDARD;
    let mut env: serde_json::Value =
        serde_json::from_slice(&std::fs::read(bundle).unwrap()).unwrap();
    let payload = engine.decode(env["payload"].as_str().unwrap()).unwrap();
    let mut st: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    change(&mut st);
    env["payload"] = engine.encode(serde_json::to_vec(&st).unwrap()).into();
    std::fs::write(bundle, serde_json::to_vec(&env).unwrap()).unwrap();
}

/// A set digest, by the rule a manifest documents: its rows, sorted, one per line.
fn set_digest(members: &[trigon_stabilize::SetMember]) -> String {
    use sha2::Digest as _;
    let mut rows: Vec<String> = members
        .iter()
        .map(|m| format!("{}|{}|{}|{}", m.id, m.stage, m.risk, m.provenance))
        .collect();
    rows.sort();
    let mut h = sha2::Sha256::new();
    for r in rows {
        h.update(r.as_bytes());
        h.update(b"\n");
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// An older `tar-gzip`: today's without its last pass, self-consistent, under its own digest.
fn retired_set() -> trigon_stabilize::SetManifest {
    let mut m = trigon_stabilize::profile("tar-gzip").unwrap().manifest();
    m.members.pop().expect("tar-gzip has passes");
    m.digest = set_digest(&m.members);
    m
}

fn rerun(c: &Claim, extra: &[&std::ffi::OsStr]) -> Output {
    let mut args: Vec<&std::ffi::OsStr> = vec![
        "verify-attestation".as_ref(),
        c.bundle.as_os_str(),
        "--rerun-comparison".as_ref(),
        "--upstream".as_ref(),
        c.upstream.as_os_str(),
        "--rebuild".as_ref(),
        c.rebuild.as_os_str(),
    ];
    args.extend_from_slice(extra);
    trigon(&args)
}

#[test]
fn the_rule_this_file_computes_set_digests_by_is_the_manifests_own() {
    // Everything below depends on building a manifest another binary would have published; a
    // digest rule that drifted from the real one would make every test here describe nothing.
    let m = trigon_stabilize::profile("tar-gzip").unwrap().manifest();
    assert_eq!(set_digest(&m.members), m.digest);
    assert!(retired_set().self_consistent());
}

/// A claim made under a set this binary does not carry is not checked here — and the refusal says
/// which set it was and where its manifest is published, then, given that manifest, what the set
/// contained.
#[test]
fn a_claim_under_another_set_names_it_and_its_manifest_says_what_it_held() {
    let d = dir("described");
    let c = claim(&d);
    let old = retired_set();
    edit(&c.bundle, |st| {
        st["predicate"]["stabilizerSet"]["digest"]["sha256"] = old.digest.clone().into();
    });

    let out = rerun(&c, &[]);
    assert!(!out.status.success(), "a claim under another set passed");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains(&format!(
            "The set this claim was made under is `tar-gzip@{}`",
            &old.digest[..12]
        )),
        "{err}"
    );
    assert!(
        err.contains(&format!("stabilizers/sha256/{}.json", old.digest)),
        "{err}"
    );

    let manifest = d.join("retired.json");
    std::fs::write(&manifest, serde_json::to_vec(&old).unwrap()).unwrap();
    let out = rerun(&c, &["--stabilizers".as_ref(), manifest.as_os_str()]);
    assert!(
        !out.status.success(),
        "describing the set is not checking it"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("the claim was made under `tar-gzip`, which contained:"),
        "{err}"
    );
    for m in &old.members {
        assert!(
            err.lines().any(|l| {
                let row: Vec<&str> = l.split_whitespace().collect();
                row.first() == Some(&m.id.as_str()) && row.get(1) == Some(&m.risk.as_str())
            }),
            "{} is not listed:\n{err}",
            m.id
        );
    }
    let dropped = trigon_stabilize::profile("tar-gzip")
        .unwrap()
        .manifest()
        .members
        .pop()
        .unwrap();
    assert!(
        !err.lines()
            .any(|l| l.split_whitespace().next() == Some(dropped.id.as_str())),
        "the manifest's set did not have {}, and the listing says it did:\n{err}",
        dropped.id
    );
}

/// A manifest is believed only when it recomputes its own digest and that digest is the claim's.
/// Anything else is said to be what it is and ignored, never listed as the claim's set.
#[test]
fn a_manifest_that_is_not_the_claims_set_is_not_believed() {
    let d = dir("disbelieved");
    let c = claim(&d);
    let old = retired_set();
    edit(&c.bundle, |st| {
        st["predicate"]["stabilizerSet"]["digest"]["sha256"] = old.digest.clone().into();
    });
    let said = |manifest: &Path| -> String {
        let out = rerun(&c, &["--stabilizers".as_ref(), manifest.as_os_str()]);
        assert!(!out.status.success());
        String::from_utf8_lossy(&out.stderr).into_owned()
    };

    // Claims the right digest and does not recompute to it: a document that merely claims one.
    let mut forged = old.clone();
    forged.members.pop();
    let path = d.join("forged.json");
    std::fs::write(&path, serde_json::to_vec(&forged).unwrap()).unwrap();
    let err = said(&path);
    assert!(
        err.contains("that manifest does not recompute the digest it claims; ignoring it"),
        "{err}"
    );
    assert!(!err.contains("which contained"), "{err}");

    // A faithful manifest of some other set: a correct document and the wrong answer.
    let current = trigon_stabilize::profile("tar-gzip").unwrap().manifest();
    let path = d.join("current.json");
    std::fs::write(&path, serde_json::to_vec(&current).unwrap()).unwrap();
    let err = said(&path);
    assert!(
        err.contains(&format!(
            "that manifest describes set {} and the claim was made under {}",
            current.digest, old.digest
        )),
        "{err}"
    );
    assert!(!err.contains("which contained"), "{err}");

    // Not a manifest at all, and not there at all.
    let path = d.join("notes.json");
    std::fs::write(&path, b"{\"these\": \"are notes\"}").unwrap();
    let err = said(&path);
    assert!(err.contains("is not a stabilizer set manifest"), "{err}");
    let err = said(&d.join("missing.json"));
    assert!(err.contains("could not read"), "{err}");
}

/// A `.wasm` stabilizer set is run, not read, and this build cannot run one: it says so rather
/// than reading the module as a manifest or checking the claim under its own set instead.
#[cfg(not(feature = "wasm"))]
#[test]
fn a_stabilizer_module_needs_the_build_that_can_run_one() {
    let d = dir("wasm");
    let c = claim(&d);
    let module = d.join("tar-gzip.wasm");
    std::fs::write(&module, b"\0asm\x01\0\0\0").unwrap();
    let out = rerun(&c, &["--stabilizers".as_ref(), module.as_os_str()]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("this build cannot run a stabilizer module"),
        "{err}"
    );
    assert!(err.contains("--features wasm"), "{err}");
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("claim holds"),
        "it checked the claim anyway"
    );
}

/// Edit the claim so it was made under a set no binary carries, `11…11`, whose module `module`
/// stabilizes every artifact to `stable`, and sign that module as its stabilizer-set module.
fn under_a_retired_set(c: &Claim, module: &[u8], stable: &[u8]) {
    let stable = set_module::sha256(stable);
    let module = set_module::sha256(module);
    edit(&c.bundle, |st| {
        let p = &mut st["predicate"];
        p["stabilizerSet"]["digest"]["sha256"] = "11".repeat(32).into();
        p["stabilized"]["upstream"]["sha256"] = stable.clone().into();
        p["stabilized"]["rebuild"]["sha256"] = stable.clone().into();
        p["evidence"] = serde_json::json!({ "stabilizerSetModule": { "sha256": module } });
    });
}

/// A claim made under a set this binary does not carry is re-derived through the module the
/// verdict names, once the module given is that one by its digest. The claim is `normalized` and
/// its stabilized forms re-derive equal, which a module cannot show to be `normalized` rather than
/// `normalized_with_caveats`: consistent, exit 0, and never promoted. Without the module it says
/// where to get it; with another module, whatever set digest it reports, nothing runs.
#[cfg(feature = "wasm")]
#[test]
fn a_claim_under_a_set_this_binary_lacks_is_re_derived_through_the_module_it_signs() {
    let d = dir("module-retired");
    let c = claim(&d);
    let module = set_module::fake([0x11; 32], b"stable");
    under_a_retired_set(&c, &module, b"stable");
    let path = d.join("retired.wasm");
    std::fs::write(&path, &module).unwrap();

    let out = rerun(&c, &["--stabilizers".as_ref(), path.as_os_str()]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{text}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.contains(&format!(
            "module    through the module given, sha256:{}, which the verdict signs",
            set_module::sha256(&module)
        )),
        "{text}"
    );
    assert!(
        text.contains("as its stabilizer-set module; it names no commit it was built from"),
        "{text}"
    );
    assert!(
        text.contains(
            "rederived normalized_with_caveats under tar-gzip@111111111111, and the statement \
             claims normalized — consistent: the stabilized forms are equal, as the claim says; an \
             archived set cannot show which tier of pass fired, so the claim's strength is not \
             re-derived"
        ),
        "{text}"
    );
    assert!(!text.contains("does NOT hold"), "{text}");

    let out = rerun(
        &c,
        &[
            "--stabilizers".as_ref(),
            path.as_os_str(),
            "--output".as_ref(),
            "json".as_ref(),
        ],
    );
    assert_eq!(out.status.code(), Some(0));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let r = &doc["rederived"];
    assert_eq!(r["holds"], false, "{doc}");
    assert_eq!(r["consistent"], true, "{doc}");
    assert_eq!(r["actual"], "normalized_with_caveats", "{doc}");
    assert!(
        r["module"].as_str().is_some_and(|m| m.contains("sha256:")),
        "{doc}"
    );

    // No module: a bundle carries no evidence, so it is asked for, and nothing is re-derived under
    // this binary's own set instead.
    let out = rerun(&c, &[]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("A bundle carries no evidence: pass the module with --stabilizers"),
        "{err}"
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains("rederived"));

    // Another module, reporting the same set: refused by its digest, before it runs. The bundle
    // form exits 1 for it, as for anything that stops it.
    let other = d.join("other.wasm");
    std::fs::write(&other, set_module::fake([0x11; 32], b"other")).unwrap();
    let out = rerun(&c, &["--stabilizers".as_ref(), other.as_os_str()]);
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("the stabilizer-set module given is not the one this statement names"),
        "{err}"
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains("rederived"));
}

/// The module line says which commit the module says it was built from: where a verifier who
/// would rather rebuild the module than run it starts. It is the module's word, and an answer that
/// is not a commit is said to be one and never printed; the claim is re-derived either way.
#[cfg(feature = "wasm")]
#[test]
fn the_module_line_says_which_commit_the_module_names() {
    let d = dir("module-commit");
    let c = claim(&d);
    let commit = format!("{}.dirty", "b".repeat(40));
    let path = d.join("retired.wasm");
    for (named, says) in [
        (
            commit.as_str(),
            format!(
                "which the verdict signs as its stabilizer-set module; it says it was built from \
                 commit {commit}\n"
            ),
        ),
        (
            "\x1b[31mred",
            "which the verdict signs as its stabilizer-set module; the module names the commit it \
             was built from as something that is not a commit\n"
                .to_string(),
        ),
    ] {
        let module = set_module::fake_naming([0x11; 32], b"stable", Some(named));
        under_a_retired_set(&c, &module, b"stable");
        std::fs::write(&path, &module).unwrap();
        let out = rerun(&c, &["--stabilizers".as_ref(), path.as_os_str()]);
        let text = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "{named:?}: {text}");
        assert!(text.contains(&says), "{named:?}: {text}");
        assert!(text.contains("— consistent:"), "{named:?}: {text}");
        assert!(!text.contains('\x1b'), "{named:?}: {text}");
    }
}

/// `--stabilizers <module>` is run whatever this binary carries, which is how a module is checked
/// while the set it implements can still be compared with it; a statement that signs no module
/// binds none, and the output says the module is held only to its own word and the digests. One
/// that signs another module refuses this one.
#[cfg(feature = "wasm")]
#[test]
fn a_module_given_is_run_whatever_this_binary_carries() {
    let d = dir("module-forced");
    let c = claim(&d);
    let module = set_module::built();
    let hex = set_module::sha256(&std::fs::read(&module).unwrap());
    let out = rerun(&c, &["--stabilizers".as_ref(), module.as_os_str()]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{text}");
    assert!(
        text.contains(&format!(
            "the module given, sha256:{hex}. The statement signs no module, so this one is held \
             only to the set digest it reports of itself"
        )),
        "{text}"
    );
    assert!(text.contains("— consistent:"), "{text}");

    edit(&c.bundle, |st| {
        st["predicate"]["evidence"] =
            serde_json::json!({ "stabilizerSetModule": { "sha256": hex.clone() } });
    });
    let out = rerun(&c, &["--stabilizers".as_ref(), module.as_os_str()]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{text}");
    assert!(text.contains("which the verdict signs"), "{text}");

    edit(&c.bundle, |st| {
        st["predicate"]["evidence"] =
            serde_json::json!({ "stabilizerSetModule": { "sha256": "ab".repeat(32) } });
    });
    let out = rerun(&c, &["--stabilizers".as_ref(), module.as_os_str()]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("is not the one this statement names"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The verifier build carries no module host. Meeting a verdict under a set it does not carry that
/// names the module implementing it, it says exactly what would run it, and checks nothing under
/// its own set instead.
#[cfg(not(feature = "wasm"))]
#[test]
fn the_verifier_says_how_to_run_the_module_a_verdict_names() {
    let d = dir("module-verifier");
    let c = claim(&d);
    under_a_retired_set(&c, &set_module::fake([0x11; 32], b"stable"), b"stable");
    let out = rerun(&c, &[]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("which this binary does not carry, and it names the stabilizer-set module"),
        "{err}"
    );
    assert!(err.contains("This build cannot run a module"), "{err}");
    assert!(
        err.contains("cargo build -p trigon --no-default-features --features wasm"),
        "{err}"
    );
    assert!(
        err.contains("the full build, `cargo build -p trigon`"),
        "{err}"
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains("rederived"));
}

/// A verdict under a set this binary does not carry, naming its module, where the module cannot be
/// run here — a bundle carries none, and the verifier build runs none — is refused saying how to
/// run it; and a manifest given for the set still says what the set held first, as it does for a
/// verdict that names no module, so the refusal is not a dead end either.
#[test]
fn a_manifest_still_says_what_the_set_held_where_its_module_cannot_run() {
    let d = dir("module-described");
    let c = claim(&d);
    let old = retired_set();
    let module = set_module::sha256(b"a module this bundle does not carry");
    edit(&c.bundle, |st| {
        st["predicate"]["stabilizerSet"]["digest"]["sha256"] = old.digest.clone().into();
        st["predicate"]["evidence"] =
            serde_json::json!({ "stabilizerSetModule": { "sha256": module.clone() } });
    });
    let manifest = d.join("retired.json");
    std::fs::write(&manifest, serde_json::to_vec(&old).unwrap()).unwrap();

    let out = rerun(&c, &["--stabilizers".as_ref(), manifest.as_os_str()]);
    assert!(
        !out.status.success(),
        "describing the set is not checking it"
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains("rederived"));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("the claim was made under `tar-gzip`, which contained:"),
        "{err}"
    );
    for m in &old.members {
        assert!(
            err.lines()
                .any(|l| l.split_whitespace().next() == Some(m.id.as_str())),
            "{} is not listed:\n{err}",
            m.id
        );
    }
    assert!(
        err.contains(&format!(
            "which this binary does not carry, and it names the stabilizer-set module \
             sha256:{module} that implements it"
        )),
        "{err}"
    );

    // Without the manifest, the refusal alone: nothing is described from a file nobody gave.
    let out = rerun(&c, &[]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!err.contains("which contained"), "{err}");
    assert!(err.contains(&format!("sha256:{module}")), "{err}");
}

/// Re-deriving needs both artifacts, and one alone is refused rather than half-checked.
#[test]
fn rerunning_the_comparison_needs_both_artifacts() {
    let d = dir("one-side");
    let c = claim(&d);
    let out = trigon(&[
        "verify-attestation".as_ref(),
        c.bundle.as_os_str(),
        "--rerun-comparison".as_ref(),
        "--upstream".as_ref(),
        c.upstream.as_os_str(),
    ]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--rerun-comparison needs both --upstream and --rebuild"),
        "{err}"
    );
}

/// The outcome and the digests re-derive, and what the statement says the comparison found does
/// not: a statement hiding a pass that fired is refuted like one that got the outcome wrong, and
/// the output says which field, not that `normalized` disagrees with `normalized`.
#[test]
fn a_statement_that_misreports_the_passes_does_not_hold_though_its_outcome_does() {
    let d = dir("found");
    let c = claim(&d);
    edit(&c.bundle, |st| {
        assert!(
            st["predicate"]["applied"]
                .as_array()
                .is_some_and(|a| !a.is_empty()),
            "a normalized claim names the passes that fired: {}",
            st["predicate"]
        );
        st["predicate"]["applied"] = serde_json::json!([]);
    });
    let out = rerun(&c, &[]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{text}");
    assert!(
        text.contains(
            "but not what the statement says the comparison found — the claim does NOT hold"
        ),
        "{text}"
    );
    assert!(text.contains("`applied` says []"), "{text}");
    assert!(!text.contains("but the statement claims"), "{text}");

    let out = rerun(&c, &["--output".as_ref(), "json".as_ref()]);
    assert_eq!(out.status.code(), Some(1));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let r = &doc["rederived"];
    assert_eq!(r["holds"], false, "{doc}");
    assert_eq!(r["claimed"], r["actual"], "{doc}");
    assert_eq!(r["disagreements"][0]["field"], "applied", "{doc}");
}

/// A pinned key is a check that the bundle was signed by it, and a bundle signed by nobody fails
/// it: were it reported `unsigned` and passed, stripping the signature would get any bundle past a
/// check that pinned the key it was stripped of. Without a key, unsigned is reported as unsigned.
#[test]
fn a_pinned_key_refuses_a_bundle_that_is_not_signed_at_all() {
    let d = dir("unsigned");
    let key = d.join("signing.key");
    let out = trigon(&["keygen".as_ref(), "--out".as_ref(), key.as_os_str()]);
    assert!(out.status.success());
    let public = trigon(&["public-key".as_ref(), key.as_os_str()]);
    let public = String::from_utf8_lossy(&public.stdout).trim().to_string();

    // Signed, then stripped of its signature, as someone between the signer and the reader would.
    let upstream = d.join("up.tgz");
    write_tgz(&upstream, b"module.exports = 1;\n", 1);
    let bundle = d.join("claim.json");
    let out = Command::new(bin())
        .arg("verify")
        .arg(&upstream)
        .arg(&upstream)
        .arg("--attest")
        .arg(&bundle)
        .arg("--key")
        .arg(&key)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let signed = trigon(&[
        "verify-attestation".as_ref(),
        bundle.as_os_str(),
        "--public-key".as_ref(),
        public.as_ref(),
    ]);
    assert!(signed.status.success());
    assert!(String::from_utf8_lossy(&signed.stdout).contains("signature verified"));

    let mut env: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&bundle).unwrap()).unwrap();
    env["signatures"] = serde_json::json!([]);
    std::fs::write(&bundle, serde_json::to_vec(&env).unwrap()).unwrap();

    for output in ["text", "json"] {
        let out = trigon(&[
            "verify-attestation".as_ref(),
            bundle.as_os_str(),
            "--public-key".as_ref(),
            public.as_ref(),
            "--output".as_ref(),
            output.as_ref(),
        ]);
        assert!(!out.status.success(), "{output}: a stripped bundle passed");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("this bundle carries no signature"), "{err}");
        assert!(err.contains("--public-key"), "{err}");
        assert!(!err.contains("bug in trigon"), "{err}");
        assert!(!String::from_utf8_lossy(&out.stdout).contains("claims"));
    }

    // With no key named, it is what it is: unsigned, said so, and still read.
    let out = trigon(&["verify-attestation".as_ref(), bundle.as_os_str()]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{text}");
    assert!(text.contains("signature unsigned"), "{text}");
}

/// A verdict that supersedes a record says so beside its claim, with the reason, so a reader of
/// the statement is not left to find the supersession in the raw JSON.
#[test]
fn a_superseding_statement_says_what_it_supersedes() {
    let d = dir("supersedes");
    let c = claim(&d);
    let record = format!("sha256:{}", "ab".repeat(32));
    edit(&c.bundle, |st| {
        st["predicate"]["supersedes"] = record.clone().into();
        st["predicate"]["reason"] = "set_changed".into();
    });
    let out = trigon(&["verify-attestation".as_ref(), c.bundle.as_os_str()]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{text}");
    assert!(text.contains("claims    normalized"), "{text}");
    assert!(
        text.contains(&format!("supersedes {record} (set_changed)")),
        "{text}"
    );
}
