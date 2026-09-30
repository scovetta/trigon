//! The binary's contract: exit codes, output shape, and the errors it gives a person.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_trigon")
}

fn tmp() -> PathBuf {
    let d = std::env::temp_dir().join(format!("trigon-cli-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_tgz(name: &str, body: &[u8], mtime: u64) -> PathBuf {
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
    let p = tmp().join(name);
    std::fs::write(&p, gz).unwrap();
    p
}

#[test]
fn a_match_exits_zero_and_says_which_kind() {
    let a = write_tgz("a.tgz", b"same", 1_700_000_000);
    let b = write_tgz("b.tgz", b"same", 1_500_000_000);
    let out = Command::new(bin())
        .args(["verify"])
        .arg(&a)
        .arg(&b)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("normalized"), "{text}");
    // The report has to name what fired and what it touched, or a verdict is unauditable.
    assert!(text.contains("tar-time"), "{text}");
    assert!(text.contains("applied"), "{text}");
}

#[test]
fn a_divergence_exits_nonzero_and_names_the_member() {
    let a = write_tgz("c.tgz", b"upstream", 1);
    let b = write_tgz("d.tgz", b"rebuilt!", 1);
    let out = Command::new(bin())
        .args(["verify"])
        .arg(&a)
        .arg(&b)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "divergence must exit non-zero for a pipeline"
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("divergent"), "{text}");
    assert!(text.contains("package/index.js"), "{text}");
}

#[test]
fn json_output_is_machine_readable() {
    let a = write_tgz("e.tgz", b"same", 1);
    let out = Command::new(bin())
        .args(["verify"])
        .arg(&a)
        .arg(&a)
        .args(["--output", "json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid json");
    assert_eq!(v["outcome"], "exact");
    assert!(v["upstream"]["raw"]["sha256"].as_str().unwrap().len() == 64);
    assert!(
        v["upstream"]["set"][1].as_str().is_some(),
        "the stabilizer set digest must be present"
    );
}

#[test]
fn an_unknown_profile_lists_what_it_could_have_been() {
    let a = write_tgz("f.tgz", b"x", 1);
    let out = Command::new(bin())
        .args(["verify"])
        .arg(&a)
        .arg(&a)
        .args(["--profile", "not-a-profile"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("not-a-profile"), "{err}");
}

#[test]
fn an_unguessable_format_says_to_pass_one() {
    let p = tmp().join("mystery.bin");
    std::fs::write(&p, b"\x00\x01\x02").unwrap();
    let out = Command::new(bin())
        .args(["verify"])
        .arg(&p)
        .arg(&p)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    // Refusing to guess is the point: a .gem is a tar, and only the ecosystem knows that.
    assert!(err.contains("--format"), "{err}");
}

#[test]
fn stabilizers_lists_a_profile_with_its_set_digest() {
    let out = Command::new(bin())
        .args(["stabilizers", "--profile", "wheel"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("wheel-record-v3"), "{text}");
    assert!(
        text.contains("finalize"),
        "RECORD regeneration must show as a finalize pass: {text}"
    );
    assert!(
        text.lines().next().unwrap().len() > 64,
        "the set digest belongs on the first line"
    );
}

#[test]
fn listing_the_profiles_names_the_one_nothing_selects() {
    let out = Command::new(bin())
        .args(["stabilizers", "--list-profiles"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    for id in [
        "tar",
        "tar-gzip",
        "zip",
        "gzip",
        "npm-tarball",
        "crate",
        "gem",
        "wheel",
        "nupkg",
        "raw",
    ] {
        assert!(text.contains(id), "{id} is missing from:\n{text}");
    }
    // The fact the command exists to surface. `npm-tarball` is a profile the selector cannot
    // reach, so `npm-install-fields` has never run on anything this tool verified.
    assert!(
        text.contains("Nothing selects one profile: npm-tarball"),
        "an unreachable profile has to be named as one:\n{text}"
    );
    // And the cap is described as conditional, because `compare` reads it off the passes that
    // fired rather than off the profile.
    assert!(text.contains("wheel-record-v3 (content)"), "{text}");
    assert!(
        text.contains("caps nothing on a run where it found nothing to do"),
        "{text}"
    );
}

#[test]
fn stabilize_writes_a_file_and_honours_pass_selection() {
    let a = write_tgz("g.tgz", b"payload", 1_700_000_000);
    let full = tmp().join("full.out");
    let none = tmp().join("none.out");

    for (out_path, passes) in [(&full, "all"), (&none, "none")] {
        let out = Command::new(bin())
            .args(["stabilize", "--infile"])
            .arg(&a)
            .arg("--outfile")
            .arg(out_path)
            .args(["--enable-passes", passes])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let with = std::fs::read(&full).unwrap();
    let without = std::fs::read(&none).unwrap();
    assert_ne!(with, without, "disabling every pass must change the output");
    assert!(!with.is_empty() && !without.is_empty());
}

#[test]
fn piping_into_head_does_not_panic() {
    // Rust masks SIGPIPE at startup, so a write to a closed pipe returns EPIPE and `println!`
    // panics on it. `trigon verify a b | head -3` then exits 101 with a backtrace. That is worse
    // here than in most tools because the exit code carries the verdict, and a panic mid-pipeline
    // is indistinguishable from a real failure.
    let a = write_tgz("pipe-a.tgz", b"hello", 1_700_000_000);
    let b = write_tgz("pipe-b.tgz", b"hello", 1_800_000_000);

    let out = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "{} verify {} {} | head -2",
            bin(),
            a.display(),
            b.display()
        ))
        .output()
        .expect("sh runs");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("panicked"),
        "the CLI panicked when its reader went away:\n{stderr}"
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("normalized"),
        "the first lines should still arrive"
    );
}

#[test]
fn strategy_render_lowers_and_renders_a_definition() {
    let src = r#"
flow:
  location:
    repo: https://github.com/a/b
    ref: cafebabe
  src:
    - uses: git-checkout
  deps:
    - uses: pypi/deps/basic
      with:
        venv: /deps
        registryTime: "2023-05-01T04:11:28Z"
        requirements: '["wheel==0.40.0"]'
  build:
    - runs: /deps/bin/python3 -m build --wheel -n
  output_dir: dist
custom_stabilizers:
  - replace_pattern:
      paths: ["*/METADATA"]
      pattern: "\r\n"
      replace: "\n"
    reason: |
      Upstream built on Windows; METADATA embeds a CRLF README.
"#;
    let p = tmp().join("import-me.yaml");
    std::fs::write(&p, src).unwrap();

    let out = Command::new(bin())
        .args(["strategy", "render", "--import"])
        .arg(&p)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);

    assert!(text.contains("git checkout --force 'cafebabe'"), "{text}");
    // A config file rather than an exported variable, and the assertion names both halves because
    // each was once missing and neither failure is visible at run time: without `trusted-host` pip
    // ignores a plain-HTTP index after one warning, and an `export` does not survive into the build
    // phase where the frontend populates its isolated environment.
    assert!(
        text.contains("index-url = http://pypi:2023-05-01T04:11:28Z@timewarp/simple"),
        "{text}"
    );
    assert!(text.contains("trusted-host = timewarp"), "{text}");
    assert!(text.contains("/etc/pip.conf"), "{text}");
    assert!(
        text.contains("/deps/bin/pip install 'wheel==0.40.0'"),
        "{text}"
    );
    // A custom stabilizer is surfaced with its reason, never silently dropped: the definition says
    // the comparison needs it, so a run without it reports a divergence its author explained.
    assert!(
        text.contains("custom stabilizer: replace_pattern"),
        "{text}"
    );
    assert!(text.contains("not yet executed"), "{text}");
    assert!(text.contains("built on Windows"), "{text}");
}

#[test]
fn strategy_render_reports_a_bad_document_with_its_path() {
    let p = tmp().join("bad.yaml");
    std::fs::write(
        &p,
        "kind: flow\nlocation: { repo: r, ref: c }\nbuild:\n  - needs: [git]\n",
    )
    .unwrap();
    let out = Command::new(bin())
        .args(["strategy", "render"])
        .arg(&p)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("build[0]"), "the path locates the step: {err}");
    assert!(err.contains("exactly one of"), "{err}");
}

/// The pinned base image the container tests use. Pinned by digest because `build` refuses a tag.
const ALPINE: &str = "docker.io/library/alpine@sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e";

fn podman_usable() -> bool {
    let ok = std::process::Command::new("podman")
        .args(["image", "exists", ALPINE])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("skipped: podman or the pinned base image is unavailable");
    }
    ok
}

#[cfg(feature = "build")]
#[test]
fn build_produces_an_artifact_the_verifier_can_compare() {
    if !podman_usable() {
        return;
    }
    // The whole M1 loop in one test: a strategy renders, a container builds it with no network at
    // all, and the judgement half compares two independent runs. The two builds differ byte for
    // byte because tar records mtimes, and they must still compare as normalized.
    let strategy = r#"
schema: 1
kind: flow
location:
  repo: https://example.invalid/not-cloned
  ref: cafebabecafebabecafebabecafebabecafebabe
src:
  - runs: |
      mkdir -p pkg
      printf 'module.exports = 1;\n' > pkg/index.js
build:
  - runs: |
      mkdir -p dist
      tar -C pkg -cf dist/demo.tar .
output_dir: dist
"#;
    let s = tmp().join("e2e.yaml");
    std::fs::write(&s, strategy).unwrap();

    let mut artifacts = Vec::new();
    for run in ["e2e-a", "e2e-b"] {
        let out = tmp().join(run);
        let status = Command::new(bin())
            .arg("build")
            .arg(&s)
            // **Independent builds, or this test proves nothing.** Podman caches build layers by
            // content, so the second build of an identical strategy reuses the first one's — file
            // timestamps included — and the two artifacts come out byte-identical. The assertion
            // below says exactly that: two builds must differ, or normalization was never
            // exercised. It began failing once deferred image removal let those layers survive
            // between runs, which is the same reason a clean re-run needs this
            // (`docs/09-attestations.md` §5).
            .env("TRIGON_NO_BUILD_CACHE", "1")
            .args([
                "--image",
                ALPINE,
                "--egress",
                "deny-all",
                "--timeout",
                "300",
            ])
            .arg("--out")
            .arg(&out)
            .output()
            .unwrap();
        assert!(
            status.status.success(),
            "build failed:\n{}",
            String::from_utf8_lossy(&status.stderr)
        );
        let found = walk_for_tar(&out).expect("the build collected an artifact");
        artifacts.push(found);
    }

    assert_ne!(
        std::fs::read(&artifacts[0]).unwrap(),
        std::fs::read(&artifacts[1]).unwrap(),
        "two container builds should differ byte for byte, or this proves nothing"
    );

    let v = Command::new(bin())
        .arg("verify")
        .arg(&artifacts[0])
        .arg(&artifacts[1])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&v.stdout);
    assert!(
        v.status.success(),
        "{text}\n{}",
        String::from_utf8_lossy(&v.stderr)
    );
    assert!(text.contains("normalized"), "{text}");
}

#[cfg(feature = "build")]
#[test]
fn build_refuses_an_unpinned_image_before_running_anything() {
    let s = tmp().join("unpinned.yaml");
    std::fs::write(
        &s,
        "schema: 1\nkind: flow\nlocation: { repo: r, ref: c }\nbuild:\n  - runs: \"true\"\n",
    )
    .unwrap();
    let out = Command::new(bin())
        .arg("build")
        .arg(&s)
        .args(["--image", "docker.io/library/alpine:3.20"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("not pinned by digest"), "{err}");
}

fn walk_for_tar(dir: &Path) -> Option<PathBuf> {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).ok()?.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "tar") {
                return Some(p);
            }
        }
    }
    None
}

#[test]
fn a_wheel_gets_the_wheel_profile_not_the_zip_one() {
    // A wheel and an arbitrary zip are both Format::Zip, and the container format alone picked the
    // zip set, so wheel-record never ran: a rebuilt wheel's RECORD was compared against the
    // published one line for line rather than regenerated from the members actually present, and
    // one differing member reported as two. Found by rebuilding sniffio from source.
    let whl = tmp().join("demo-1.0-py3-none-any.whl");
    write_zip(&whl, &[("demo/__init__.py", b"x = 1\n")]);
    let out = Command::new(bin())
        .arg("verify")
        .arg(&whl)
        .arg(&whl)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stabilizer_set(&text).as_deref(), Some("wheel"), "{text}");

    // .tgz stays generic on purpose: an npm tarball is a .tgz and so is a great deal else, and
    // nothing in the name says which.
    let a = write_tgz("kind-a.tgz", b"hello", 1);
    let out = Command::new(bin())
        .arg("verify")
        .arg(&a)
        .arg(&a)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("tar+gzip"), "{text}");
    // Positively, not "not npm": a check for the absence of one label passes just as well when
    // the label is renamed, which is how this one went vacuous once already.
    assert_eq!(stabilizer_set(&text).as_deref(), Some("tar-gzip"), "{text}");
}

/// The set `trigon verify` says it compared under: the first word after the `stabilizers` label.
fn stabilizer_set(text: &str) -> Option<String> {
    text.lines()
        .find_map(|l| l.trim_start().strip_prefix("stabilizers "))
        .and_then(|rest| rest.split_whitespace().next())
        .map(str::to_string)
}

fn write_zip(path: &Path, members: &[(&str, &[u8])]) {
    use std::io::Write as _;
    let mut w = zip_crate::ZipWriter::new(std::fs::File::create(path).unwrap());
    let opts: zip_crate::write::FileOptions<'_, ()> = zip_crate::write::FileOptions::default()
        .compression_method(zip_crate::CompressionMethod::Stored);
    for (n, b) in members {
        w.start_file(*n, opts).unwrap();
        w.write_all(b).unwrap();
    }
    w.finish().unwrap();
}

#[test]
fn logs_go_to_stderr_so_stdout_stays_machine_readable() {
    // `--output json | jq` must not have log lines in it.
    let a = write_tgz("log-a.tgz", b"hello", 1_700_000_000);
    let b = write_tgz("log-b.tgz", b"hello", 1_800_000_000);
    let out = Command::new(bin())
        .arg("verify")
        .arg(&a)
        .arg(&b)
        .args(["--output", "json", "-v"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str::<serde_json::Value>(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be parseable JSON: {e}\n{stdout}"));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("compared"),
        "and the log must still have happened"
    );
}

#[test]
fn the_default_is_quiet() {
    // A tool that chatters by default gets its output redirected to /dev/null, and then the
    // warnings that matter go there too.
    let a = write_tgz("quiet-a.tgz", b"hello", 1_700_000_000);
    let out = Command::new(bin())
        .arg("verify")
        .arg(&a)
        .arg(&a)
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&out.stderr).trim().is_empty(),
        "stderr should be empty on a clean run: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn log_json_emits_one_object_per_line() {
    let a = write_tgz("j-a.tgz", b"hello", 1_700_000_000);
    let out = Command::new(bin())
        .arg("verify")
        .arg(&a)
        .arg(&a)
        .args(["-v", "--log-json"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    let mut seen = 0;
    for line in stderr.lines().filter(|l| !l.trim().is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("every log line must be one JSON object: {e}\n{line}"));
        // Fields are flattened, not nested under "fields", so a log pipeline can index on them
        // without knowing our subscriber's shape.
        if v["message"] == "compared" {
            assert!(v["outcome"].is_string(), "{line}");
            seen += 1;
        }
    }
    assert_eq!(seen, 1, "the comparison should be reported exactly once");
}

#[test]
fn a_failure_says_whose_fault_it_was() {
    // Fault exists so a sweep's numbers mean something: a hundred failures is a different
    // situation depending on whether they are our infrastructure, the packages' builds, or a
    // policy. It was implemented and never called, which made it documentation.
    let bad = tmp().join("not-an-archive.tgz");
    std::fs::write(&bad, b"this is not a gzip stream at all").unwrap();
    let out = Command::new(bin())
        .arg("verify")
        .arg(&bad)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("fault=Upstream"),
        "a malformed artifact is not our fault: {err}"
    );
    assert!(err.contains("the published artifact's"), "{err}");
}

#[cfg(feature = "build")]
#[test]
fn resolve_refuses_a_purl_with_no_version() {
    // Offline: the parse fails before anything is asked of a registry.
    let out = Command::new(bin())
        .args(["resolve", "pkg:npm/left-pad"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("nothing to compare"), "{err}");
}

#[cfg(feature = "build")]
#[test]
fn resolve_names_the_supported_ecosystems() {
    // **The example moved from `nuget` to `gem` because `nuget` started working.** That is the
    // right way for this test to fail: it is about the *shape* of the refusal — named ecosystem,
    // named alternatives, `Policy` rather than a crash — and not about which four we happen to
    // speak. Picking a still-unsupported one keeps it testing that.
    let out = Command::new(bin())
        .args(["resolve", "pkg:gem/rails@7.1.3"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("does not speak gem"), "{err}");
    assert!(err.contains("npm, pypi, cargo, nuget"), "{err}");
    assert!(
        err.contains("fault=Policy"),
        "declining is policy, not breakage: {err}"
    );
}

#[cfg(feature = "build")]
#[test]
fn resolve_reports_a_live_package() {
    if std::env::var("TRIGON_LIVE").as_deref() != Ok("1") {
        eprintln!("skipped: set TRIGON_LIVE=1");
        return;
    }
    let out = Command::new(bin())
        .args(["resolve", "pkg:npm/left-pad@1.3.0"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("github.com/stevemao/left-pad"), "{text}");
    // The rung is printed alongside the commit. A registry-recorded commit and a fuzzy tag match
    // are both "a commit" and must not be read alike.
    assert!(text.contains("found by   RegistryCommit"), "{text}");
}

#[cfg(feature = "build")]
#[test]
fn a_closed_network_peer_does_not_kill_the_process() {
    // The first fix for the piping case restored SIGPIPE to its default, which is process-wide and
    // applies to every write, sockets included. The mirror proxies to a build container; the
    // container finishes and closes its connection; the mirror writes one more chunk and the whole
    // run dies with status 141 having printed nothing. It killed a twenty-target sweep twice at the
    // same target before anyone read the exit code.
    //
    // Reproduced without containers: serve, start a request, drop it mid-body.
    let out = Command::new(bin()).args(["mirror", "--port", "0"]).spawn();
    let Ok(mut child) = out else {
        eprintln!("skipped: could not start the mirror");
        return;
    };
    std::thread::sleep(std::time::Duration::from_millis(400));
    // Still running: nothing has written to a closed peer yet, and more importantly the process
    // must not have died from arming the signal.
    assert!(
        child.try_wait().unwrap().is_none(),
        "the mirror exited immediately"
    );
    let _ = child.kill();
    let _ = child.wait();
}

// ---------------------------------------------------------------------------
// Attestations, from the command line a person actually types.

#[test]
fn attest_writes_a_bundle_that_verify_attestation_re_derives() {
    let a = write_tgz("att-a.tgz", b"hello", 1_700_000_000);
    let b = write_tgz("att-b.tgz", b"hello", 1_800_000_000);
    let bundle = tmp().join("att.json");

    let out = Command::new(bin())
        .args(["verify"])
        .arg(&a)
        .arg(&b)
        .arg("--attest")
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(out.status.success());
    // Unsigned by default, and it says so rather than letting a bundle pass as verified.
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("unsigned"), "{err}");

    let out = Command::new(bin())
        .args(["verify-attestation"])
        .arg(&bundle)
        .arg("--rerun-comparison")
        .arg("--upstream")
        .arg(&a)
        .arg("--rebuild")
        .arg(&b)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("the claim holds"), "{text}");
}

#[test]
fn verify_attestation_json_carries_exactly_the_keys_its_help_names() {
    // Scripts read this with `jq`, so its keys are an interface. It lost one when ADR-0014 removed
    // the external log, and the help says so; this pins what is left, so that a key going or
    // coming is a decision somebody made rather than a diff nobody read.
    let a = write_tgz("json-a.tgz", b"hello", 1_700_000_000);
    let b = write_tgz("json-b.tgz", b"hello", 1_800_000_000);
    let bundle = tmp().join("json.json");
    let out = Command::new(bin())
        .args(["verify"])
        .arg(&a)
        .arg(&b)
        .arg("--attest")
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(out.status.success());

    let out = Command::new(bin())
        .args(["verify-attestation"])
        .arg(&bundle)
        .arg("--rerun-comparison")
        .arg("--upstream")
        .arg(&a)
        .arg("--rebuild")
        .arg(&b)
        .args(["--output", "json"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).expect("the output is JSON");
    let mut keys: Vec<&str> = doc
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "outcome",
            "predicateType",
            "rederived",
            "signature",
            "subject"
        ],
        "{doc}"
    );
    assert_eq!(doc["rederived"]["holds"], true, "{doc}");
}

#[test]
fn reading_an_attestation_is_not_checking_it_and_the_output_says_so() {
    // The distinction the whole subcommand exists for. Without `--rerun-comparison` we have
    // repeated what the statement says, which is worth nothing against a producer who lied.
    let a = write_tgz("read-a.tgz", b"hello", 1);
    let bundle = tmp().join("read.json");
    Command::new(bin())
        .args(["verify"])
        .arg(&a)
        .arg(&a)
        .arg("--attest")
        .arg(&bundle)
        .output()
        .unwrap();

    let out = Command::new(bin())
        .args(["verify-attestation"])
        .arg(&bundle)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("not attempted"), "{text}");
    assert!(text.contains("--rerun-comparison"), "{text}");
}

#[test]
fn an_overstated_claim_exits_nonzero() {
    let a = write_tgz("lie-a.tgz", b"hello", 1_700_000_000);
    let b = write_tgz("lie-b.tgz", b"hello", 1_800_000_000);
    let bundle = tmp().join("lie.json");
    Command::new(bin())
        .args(["verify"])
        .arg(&a)
        .arg(&b)
        .arg("--attest")
        .arg(&bundle)
        .output()
        .unwrap();

    // Edit the claim upward, the way a dishonest rebuilder would.
    let mut env: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&bundle).unwrap()).unwrap();
    let payload = env["payload"].as_str().unwrap();
    let mut st: serde_json::Value = serde_json::from_slice(&base64_decode(payload)).unwrap();
    st["predicate"]["outcome"] = serde_json::Value::String("exact".into());
    env["payload"] = serde_json::Value::String(base64_encode(
        serde_json::to_string(&st).unwrap().as_bytes(),
    ));
    std::fs::write(&bundle, serde_json::to_vec(&env).unwrap()).unwrap();

    let out = Command::new(bin())
        .args(["verify-attestation"])
        .arg(&bundle)
        .arg("--rerun-comparison")
        .arg("--upstream")
        .arg(&a)
        .arg("--rebuild")
        .arg(&b)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        !out.status.success(),
        "an overstated claim must not exit zero: {text}"
    );
    assert!(text.contains("does NOT hold"), "{text}");
}

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

fn base64_encode(b: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(b)
}

#[test]
fn an_unknown_model_provider_fails_before_anything_touches_the_network() {
    // A typo in `--model` should cost nothing and read as a typo. Before this was checked first,
    // the run resolved the package, started a mirror, and then died on the spec — which reads as
    // the registry's fault, and takes seconds to say so.
    let out = Command::new(bin())
        .args(["rebuild", "pkg:npm/left-pad@1.3.0"])
        .args(["--image", "unused", "--work"])
        .arg(tmp().join("model-typo"))
        .args(["--model", "gpt-4o"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("not a provider this build knows"), "{err}");
    // And says what it does know, rather than leaving the reader to guess the spelling.
    assert!(err.contains("replay:"), "{err}");
}

#[test]
fn a_rebuild_asks_no_model_unless_one_is_named() {
    // The default matters more than it looks: `docs/07-ai.md` §6 measures the model-invocation rate
    // precisely because a run that quietly called one is a run whose cost and derivation are a
    // surprise. `--help` is where an operator finds out it is opt-in.
    let out = Command::new(bin())
        .args(["rebuild", "--help"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("--model"), "{text}");
    assert!(
        text.contains("nothing deterministic produced one"),
        "the help does not say when the model is asked: {text}"
    );
}

#[test]
fn a_sweep_comparison_names_what_a_change_broke_as_well_as_what_it_fixed() {
    // The question a promoted rule has to answer. An aggregate rate is exactly what hides a change
    // that fixes one package and breaks another — both sweeps here score 2/3.
    let d = tmp().join("flips");
    std::fs::create_dir_all(&d).unwrap();
    let write = |name: &str, body: &str| {
        let p = d.join(name);
        std::fs::write(&p, body).unwrap();
        p
    };
    let before = write(
        "before.tsv",
        "pkg:npm/a@1\tdivergent\t1.0\t\t0\npkg:npm/b@1\texact\t1.0\t\t0\npkg:npm/c@1\tnormalized\t1.0\t\t0\n",
    );
    let after = write(
        "after.tsv",
        "pkg:npm/a@1\tnormalized\t1.0\t\t0\npkg:npm/b@1\tdivergent\t1.0\t\t0\npkg:npm/c@1\tnormalized\t1.0\t\t0\n",
    );
    let labels = write(
        "labels.json",
        r#"{"labels":[
            {"purl":"pkg:npm/a@1","capability":"needs-build-inference","reason":"x"},
            {"purl":"pkg:npm/b@1","capability":"trivial-deterministic","reason":"x"},
            {"purl":"pkg:npm/c@1","capability":"trivial-deterministic","reason":"x"}]}"#,
    );

    let out = Command::new(bin())
        .args(["score"])
        .arg(&after)
        .arg("--labels")
        .arg(&labels)
        .arg("--baseline")
        .arg(&before)
        .arg("--fail-on-regression")
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("1 now reproduces"), "{text}");
    assert!(text.contains("pkg:npm/a@1"), "{text}");
    assert!(text.contains("NO LONGER REPRODUCES"), "{text}");
    assert!(text.contains("pkg:npm/b@1"), "{text}");
    assert!(text.contains("NOT a net gain"), "{text}");
    // The gate is what makes this usable as a promotion check rather than a report.
    assert!(!out.status.success(), "a regression must fail the gate");

    // And without the gate it is a report: same finding, exit zero, because a person reading a
    // comparison should not be told their shell command failed.
    let out = Command::new(bin())
        .args(["score"])
        .arg(&after)
        .arg("--labels")
        .arg(&labels)
        .arg("--baseline")
        .arg(&before)
        .output()
        .unwrap();
    assert!(out.status.success());
}
