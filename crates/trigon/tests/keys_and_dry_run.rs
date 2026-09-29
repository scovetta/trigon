//! Making a signing key, and what other code and people depend on the binary to say.
//!
//! A key is the one file here that cannot be regenerated, so the tests that matter for it are the
//! refusals, not the happy paths. The rest pin what is read back: the columns of `trigon runs`, the
//! fix commands a failing build prints, and a repair that must not cost a run its answer.
//!
//! The file's name is older than its contents. It held the preview of an external log entry until
//! ADR-0014 removed the log; the preview returns with `trigon publish` (docs/19 §10 phase 5).

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_trigon")
}

fn dir(what: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("trigon-keys-{}-{what}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn keygen(out: &Path) -> std::process::Output {
    Command::new(bin())
        .args(["keygen", "--out"])
        .arg(out)
        .output()
        .unwrap()
}

#[test]
fn a_generated_key_is_usable_and_only_by_its_owner() {
    let d = dir("gen");
    let key = d.join("signing.key");
    let out = keygen(&key);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&out.stderr)
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "a signing key readable by anyone else is not a signing key"
        );
    }

    // The public half is printed, because a signature nobody pinned a key for is worth nothing and
    // the moment to say so is the moment the key is made.
    let hex = text
        .lines()
        .find_map(|l| l.trim_start().strip_prefix("public key "))
        .expect("keygen prints the public key")
        .trim()
        .to_string();
    assert_eq!(
        hex.len(),
        64,
        "an ed25519 public key is 32 bytes of hex: {hex:?}"
    );
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()), "{hex:?}");

    // And it is the right public half: sign something and check it against what was printed. A
    // keygen that printed a plausible but unrelated key would pass every test above.
    let a = d.join("a.bin");
    let b = d.join("b.bin");
    std::fs::write(&a, b"same").unwrap();
    std::fs::write(&b, b"same").unwrap();
    let bundle = d.join("claim.json");
    let made = Command::new(bin())
        .args(["verify", "--format", "raw"])
        .arg(&a)
        .arg(&b)
        .arg("--attest")
        .arg(&bundle)
        .arg("--key")
        .arg(&key)
        .output()
        .unwrap();
    assert!(
        made.status.success(),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );

    let checked = Command::new(bin())
        .arg("verify-attestation")
        .arg(&bundle)
        .args(["--public-key", &hex])
        .output()
        .unwrap();
    assert!(
        checked.status.success(),
        "the printed public key does not check a signature the private key made:\n{}{}",
        String::from_utf8_lossy(&checked.stdout),
        String::from_utf8_lossy(&checked.stderr)
    );
}

#[test]
fn keygen_will_not_overwrite_a_key_that_exists() {
    // The destructive case, and the reason there is no `--force`. Overwriting makes every
    // statement ever signed with the old key unattributable, with no way back and no warning at the
    // time it happens — a second run of the same command must not be able to do that.
    let d = dir("clobber");
    let key = d.join("signing.key");
    assert!(keygen(&key).status.success());
    let before = std::fs::read(&key).unwrap();

    let again = keygen(&key);
    assert!(
        !again.status.success(),
        "a second keygen overwrote the first"
    );
    assert_eq!(
        std::fs::read(&key).unwrap(),
        before,
        "the existing key was modified"
    );
    let err = String::from_utf8_lossy(&again.stderr);
    assert!(
        err.contains("already exists") && err.contains("unattributable"),
        "the refusal has to say what would be lost, not just that the file is there:\n{err}"
    );
}

#[test]
fn the_public_pem_is_written_where_asked() {
    let d = dir("pem");
    let key = d.join("signing.key");
    let pem = d.join("public.pem");
    let out = Command::new(bin())
        .args(["keygen", "--out"])
        .arg(&key)
        .arg("--public-out")
        .arg(&pem)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = std::fs::read_to_string(&pem).unwrap();
    assert!(
        text.starts_with("-----BEGIN PUBLIC KEY-----"),
        "an evidence repository publishes its key as SPKI PEM, so that is what this writes: \
         {text:?}"
    );
}

#[test]
fn keygen_says_its_key_is_the_one_records_are_published_under_until_a_root_exists() {
    // ADR-0014 Decision 8 publishes under a single pinned ed25519 key until a root exists, and
    // docs/19 D6 decides whether a root is built at all. A keygen that still told the operator
    // making that key it was for development only, and that a trusted-root key was needed
    // instead, would send them looking for B21 steps 4-5, which may never exist.
    let d = dir("public-use");
    let out = keygen(&d.join("signing.key"));
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let help = Command::new(bin())
        .args(["keygen", "--help"])
        .output()
        .unwrap();
    assert!(help.status.success());

    // Both are free to wrap, so compare with the whitespace folded.
    let fold = |b: &[u8]| {
        String::from_utf8_lossy(b)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    };
    for (what, text) in [
        ("what keygen prints", fold(&out.stdout)),
        ("keygen --help", fold(&help.stdout)),
    ] {
        assert!(
            text.contains("until a root exists") && text.contains("ADR-0014 Decision 8"),
            "{what} has to say this key is what records are published under until a root \
             exists:\n{text}"
        );
        assert!(
            !text.contains("wants a key under a trusted root instead")
                && !text.contains("what a public instance should use"),
            "{what} still calls a bare key development-only, against ADR-0014:\n{text}"
        );
    }
}

// --- A store with a run in it ------------------------------------------------------------------

/// A store holding one real run: two identical tarballs, compared for real, with the comparison
/// and both artifacts in the blob store, so what is read back is what a rebuild would have
/// written rather than a record written to suit the test.
async fn store_with_a_run(root: &Path) -> String {
    use trigon_store::{ArtifactRef, Environment, RunRecord, RunState, Store};

    let tgz = {
        let mut b = ::tar::Builder::new(Vec::new());
        let body = b"module.exports = 1\n";
        let mut h = ::tar::Header::new_ustar();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(1_700_000_000);
        h.set_cksum();
        b.append_data(&mut h, "package/index.js", &body[..])
            .unwrap();
        let tar = b.into_inner().unwrap();
        let mut gz = Vec::new();
        {
            use std::io::Write as _;
            let mut e = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
            e.write_all(&tar).unwrap();
            e.finish().unwrap();
        }
        gz
    };

    let store = Store::local(root).unwrap();
    let up_digest = store.blobs().put(tgz.clone()).await.unwrap();
    let rb_digest = store.blobs().put(tgz.clone()).await.unwrap();

    let set = trigon_stabilize::profile("tar-gzip").expect("the default tar profile");
    let comparison = trigon_compare::compare_bytes(
        tgz.clone(),
        tgz.clone(),
        trigon_core::Format::TarGz,
        &set,
        &trigon_archive::Limits::default(),
    )
    .unwrap();
    let outcome = comparison.outcome.to_string();
    let cmp_digest = store
        .blobs()
        .put(serde_json::to_vec(&comparison).unwrap())
        .await
        .unwrap();

    let mut record = RunRecord::new(
        "run-dry",
        "pkg:npm/demo@1.0.0",
        ArtifactRef {
            name: "demo-1.0.0.tgz".into(),
            sha256: up_digest,
            bytes: tgz.len() as u64,
            stored: true,
        },
        Environment {
            base_image: "docker.io/library/debian@sha256:aa".into(),
            derived_image: None,
            egress: "mirror-only".into(),
            isolation: "UserNs".into(),
            guard_manifest: None,
            guarded_members: None,
            attestable: false,
            registry_moment: None,
            pin: None,
        },
        "2026-09-16T00:00:00Z",
    );
    record.state = RunState::Done;
    record.outcome = Some(outcome);
    record.comparison = Some(cmp_digest);
    record.rebuild = Some(ArtifactRef {
        name: "demo-1.0.0.tgz".into(),
        sha256: rb_digest,
        bytes: tgz.len() as u64,
        stored: true,
    });
    store.put_run(&record).await.unwrap();
    record.id
}

// --- Commands we tell people to run ------------------------------------------------------------

#[test]
fn the_fix_command_a_failing_build_prints_is_one_this_binary_accepts() {
    // Twice now a build has failed with a suggestion that the suggesting program then rejected:
    // once over `--from sha256:<id>`, and once over `--packages a b`, which clap read as one value
    // and a stray argument. A suggestion nobody can paste is worse than no suggestion, so the
    // shapes that get printed are pinned here.
    //
    // `--print` renders the Containerfile from its arguments and touches neither podman nor the
    // local image store, so this asserts the argument contract on any machine. It used to name a
    // digest that happened to be in one developer's store, which passed there and failed in CI
    // with `no image with id … is in the local store` — a test that was reading the machine rather
    // than the parser it was written for.
    //
    // Synthetic on purpose: well-formed enough for `is_pinned`, and obviously not a real image.
    let digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    for packages in [
        // The form `dockerfile.rs` prints: a space-separated list after one flag.
        vec!["python3", "python3-venv"],
        // The form `failure.rs` prints, which is the longer builtin union.
        vec!["ca-certificates", "git", "libatomic1", "wget"],
        // And the two ways someone might reasonably type it instead.
        vec!["python3,python3-venv"],
        vec!["python3"],
    ] {
        let out = Command::new(bin())
            .args(["base-image", "--from", digest, "--packages"])
            .args(&packages)
            .arg("--print")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "`--packages {}` is a form we print but do not accept:\n{}",
            packages.join(" "),
            String::from_utf8_lossy(&out.stderr)
        );
        let printed = String::from_utf8_lossy(&out.stdout);
        for p in packages.iter().flat_map(|p| p.split(',')) {
            assert!(
                printed.contains(p),
                "{p} was accepted and then not installed:\n{printed}"
            );
        }
    }
}

#[test]
fn runs_prints_the_id_first_and_the_target_second() {
    // `scripts/rebuild-and-attest.sh` decides *which run to sign* by reading these two columns:
    // `$1` to tell the run this invocation made from the ones the store already held, and `$2` to
    // check it is about the package that was asked for. Both are load-bearing — before that check
    // existed, asking for a NuGet package that produced no record signed a statement about
    // whatever ran last. If this output ever grows a column on the left, that script silently goes
    // back to signing the wrong thing, so the order is pinned here rather than left to notice.
    let d = dir("runs");
    let store = d.join("store");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let id = rt.block_on(store_with_a_run(&store));

    let out = Command::new(bin())
        .args(["runs", "--store"])
        .arg(&store)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().next().expect("one run");
    let mut fields = line.split_whitespace();
    assert_eq!(
        fields.next(),
        Some(id.as_str()),
        "column 1 is the run id: {line}"
    );
    assert_eq!(
        fields.next(),
        Some("pkg:npm/demo@1.0.0"),
        "column 2 is the target: {line}"
    );
    // Then the outcome and whether it was signed, and nothing after them: the fifth column, which
    // showed an external log's entry for the run, went with the log (ADR-0014).
    assert_eq!(
        fields.next(),
        Some("exact"),
        "column 3 is the outcome: {line}"
    );
    assert_eq!(
        fields.next(),
        Some("unattested"),
        "column 4 says whether it was signed: {line}"
    );
    assert_eq!(fields.next(), None, "a fifth column: {line}");
}

// --- a repair must never cost the run the answer it already has ---------------------------------

/// A strategy naming a tool parameter that does not exist, of the kind a model proposes.
const BAD_REPAIR: &str = r#"
schema: 1
kind: flow
location:
  repo: https://github.com/JamesNK/Newtonsoft.Json
  ref: d50b912e9948472e122cfaf24ffeebbf77032806
  subdir: Src/Newtonsoft.Json
src:
- uses: git-checkout
deps:
- uses: nuget/restore
build:
- uses: nuget/build/pack
  with:
    project: Src/Newtonsoft.Json
    version: 11.0.1
output_dir: trigon-pack
"#;

/// The same strategy with the parameter the tool actually declares.
const GOOD_REPAIR: &str = r#"
schema: 1
kind: flow
location:
  repo: https://github.com/JamesNK/Newtonsoft.Json
  ref: d50b912e9948472e122cfaf24ffeebbf77032806
  subdir: Src/Newtonsoft.Json
src:
- uses: git-checkout
deps:
- uses: nuget/restore
build:
- uses: nuget/build/pack
  with:
    dir: Src/Newtonsoft.Json
    version: 11.0.1
output_dir: trigon-pack
"#;

#[test]
fn a_proposal_naming_a_parameter_that_does_not_exist_is_caught_before_it_is_run() {
    // **The failure this guards.** A model proposed `project:` for a tool whose parameter is `dir`.
    // It parsed, so the loop accepted it, and the rejection then happened inside the *next* build
    // as a fatal error — destroying a run that had already computed a complete comparison. A repair
    // is an attempt to do better than an answer we already have; it must not be able to cost us
    // that answer.
    let bad = trigon_strategy::from_yaml(BAD_REPAIR).expect("this is valid YAML and a valid shape");
    let tools = trigon_strategy::ToolRegistry::builtin().unwrap();
    let cx = trigon_strategy::Context::default();
    let err = trigon_strategy::render(&bad, &cx, &tools)
        .expect_err("`project` is not a parameter of nuget/build/pack");
    let msg = err.to_string();
    assert!(
        msg.contains("has no parameter") && msg.contains("project"),
        "the rejection should name the parameter: {msg}"
    );
    // And it should say what the tool does declare, so the next proposal can be right.
    assert!(msg.contains("dir"), "{msg}");
}

#[test]
fn the_corrected_proposal_renders() {
    // The other half: the check must not reject a usable recipe, or a working repair would be
    // discarded as readily as a broken one.
    let good = trigon_strategy::from_yaml(GOOD_REPAIR).unwrap();
    let tools = trigon_strategy::ToolRegistry::builtin().unwrap();
    trigon_strategy::render(&good, &trigon_strategy::Context::default(), &tools)
        .expect("`dir` is what the tool declares");
}
