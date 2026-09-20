//! Making a signing key, and previewing what would go on an append-only log.
//!
//! Both are about the same thing from opposite ends: a key is the one file here that cannot be
//! regenerated, and a transparency log entry is the one write that cannot be taken back. The tests
//! that matter are therefore the refusals, not the happy paths.

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
        .find_map(|l| l.strip_prefix("public key  "))
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
        "the log entry carries SPKI PEM, so that is what this writes: {text:?}"
    );
}

#[test]
fn dry_run_without_a_log_to_dry_run_against_is_rejected() {
    // `--dry-run` previews one thing: the POST. On its own it would read as "attest without
    // writing", which it is not, so clap refuses it rather than let the name mislead.
    let out = Command::new(bin())
        .args(["attest", "--dry-run"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("rekor"),
        "the error should name what is missing:\n{err}"
    );
}

// --- The preview itself ------------------------------------------------------------------------

/// A store holding one real run: two identical tarballs, compared for real, with the comparison
/// and both artifacts in the blob store. Hand-writing a record would test the printer; this tests
/// the thing that would actually be posted.
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

#[test]
fn a_dry_run_prints_the_entry_and_writes_nothing() {
    let d = dir("preview");
    let store = d.join("store");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(store_with_a_run(&store));

    let key = d.join("signing.key");
    assert!(keygen(&key).status.success());

    // What the store looks like before, so "wrote nothing" is checked rather than asserted.
    let before = tree(&store);

    let out = Command::new(bin())
        .args(["attest", "--store"])
        .arg(&store)
        .arg("--key")
        .arg(&key)
        .args(["--rekor", "https://rekor.sigstage.dev", "--dry-run"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(
        text.contains("https://rekor.sigstage.dev/api/v1/log/entries"),
        "the preview has to name where it would go:\n{text}"
    );

    // The printed entry is a real one: parse it and check the shape the log is given, because that
    // exact shape is the reason to look before posting to something append-only.
    let json = text
        .split_once("log/entries:\n")
        .expect("the entry follows the URL")
        .1
        // Bounded at the readable section rather than run to the end of the output: the two are
        // both JSON, and a parser that swallowed both would be checking the wrong document.
        .split("\nwhat that says, decoded")
        .next()
        .unwrap();
    let end = json.rfind('}').expect("the entry is JSON") + 1;
    let entry: serde_json::Value = serde_json::from_str(&json[..end]).expect("the preview parses");

    assert_eq!(entry["kind"], "intoto");
    assert_eq!(
        entry["apiVersion"], "0.0.1",
        "v0.0.2 takes the envelope as an object; this must stay the string form"
    );
    let spec = &entry["spec"];
    assert!(
        spec["content"]["envelope"].is_string(),
        "v0.0.1 carries the envelope as a serialized JSON string, not an object: {spec}"
    );
    assert!(
        spec["publicKey"].is_string(),
        "the certificate is a sibling of `content`, not inside it: {spec}"
    );

    // The envelope really is ours, signed with the key we just made.
    let envelope: serde_json::Value =
        serde_json::from_str(spec["content"]["envelope"].as_str().unwrap()).unwrap();
    assert_eq!(envelope["payloadType"], "application/vnd.in-toto+json");
    assert!(
        !envelope["signatures"][0]["sig"]
            .as_str()
            .unwrap()
            .is_empty(),
        "a dry run signs for real; only the POST is skipped"
    );

    // The claim is shown in readable form as well, because an entry nobody can read is not a
    // preview — and it has to be the *same* claim, not a second rendering that could drift.
    let decoded = text
        .split_once("decoded — the statement inside the envelope, not part of the entry:\n")
        .expect("the preview decodes the payload")
        .1;
    let shown: serde_json::Value =
        serde_json::from_str(&decoded[..decoded.rfind('}').unwrap() + 1]).unwrap();
    let actual: serde_json::Value = serde_json::from_slice(
        &base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            envelope["payload"].as_str().unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        shown, actual,
        "the readable section is not the payload that would be posted"
    );
    assert_eq!(shown["predicateType"], "https://trigon.dev/equivalence/v1");

    assert!(
        text.contains("Nothing was posted") && text.contains("this command wrote nothing"),
        "the preview has to say it did not publish:\n{text}"
    );
    // And it must not overclaim: the rebuild that produced this run really did write to the store,
    // and a flat "nothing was written" would be read as covering that too.
    assert!(
        text.contains("wrote its record and blobs earlier"),
        "the message should scope its claim to this command:\n{text}"
    );
    assert_eq!(
        tree(&store),
        before,
        "a dry run wrote to the store; `--dry-run` has to mean nothing was written, without \
         qualification"
    );
}

/// Every path under a directory, sorted, with file sizes — enough to catch a write.
fn tree(root: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(p) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&p) else {
            continue;
        };
        for e in entries.flatten() {
            let path = e.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let len = e.metadata().map(|m| m.len()).unwrap_or(0);
                found.push(format!("{} {len}", path.display()));
            }
        }
    }
    found.sort();
    found
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
