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
    assert!(text.contains("wheel-record"), "{text}");
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
    assert!(
        text.contains("PIP_INDEX_URL=http://pypi:2023-05-01T04:11:28Z@timewarp/simple"),
        "{text}"
    );
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
    assert!(text.contains("stabilizer set wheel"), "{text}");

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
    assert!(!text.contains("stabilizer set npm"), "{text}");
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
