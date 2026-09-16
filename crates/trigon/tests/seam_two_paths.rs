//! Two code paths, one answer.
//!
//! Every test here holds one decision that this binary makes in more than one place, and asserts
//! that the places agree. Nothing here is a unit test: each of these units was correct on its own
//! when the seam between them was broken.
//!
//! The shape is the one that produced five real defects in a single day, all of them in code that
//! "had tests":
//!
//! > **Two things that had to agree, and nothing asserting they did.**
//!
//! The instance this file is named for is finding 2 in `docs/16-findings.md`: `stabilize_one`
//! picked its stabilizer set with `default_for(fmt)`, which sees only the container format, while
//! `verify` called `resolve_profile`, which sees the artifact kind. A `.whl` and an arbitrary
//! `.zip` are both `Format::Zip`, so `trigon stabilize` ran the plain zip set on a wheel and
//! skipped `pyc-header`, `wheel-metadata-eol` and `wheel-record` — and the two commands in one
//! binary computed **different stabilized digests for the same file**. That is the one thing the
//! judgement half must never do: the stabilized digest is the value a claim is signed under, and a
//! tool that produces two of them has no claim to make.
//!
//! It is fixed. These tests exist so it stays fixed, and so the next decision that grows a second
//! implementation is caught by a failing assertion rather than by rebuilding `sniffio`.
//!
//! Everything is driven through the compiled binary rather than through the functions. That is not
//! a limitation to apologize for — `trigon` is a binary crate with no library target, so an
//! integration test *cannot* reach `resolve_profile` — it is the right altitude anyway: the claim
//! under test is about what two commands do, and calling one shared helper twice would prove
//! nothing about whether both commands call it.

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_trigon")
}

/// A directory per test. Tests in one binary share a process, so the pid alone is not unique
/// enough, and two tests writing `demo.whl` into the same directory would race.
fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir()
        .join(format!("trigon-seam-two-paths-{}", std::process::id()))
        .join(name);
    std::fs::create_dir_all(&d).unwrap();
    d
}

// ---------------------------------------------------------------------------------------------
// Fixtures. Small, hand-built, and deliberately shaped so the kind-specific passes actually fire:
// a profile that is selected and then does nothing proves only that nothing happened.
// ---------------------------------------------------------------------------------------------

/// A wheel whose `METADATA` and `WHEEL` carry CRLF (so `wheel-metadata-eol` fires) and whose
/// `RECORD` is wrong (so `wheel-record` regenerates it). Under the plain zip set both are inert,
/// which is exactly what makes this the fixture that separates the two profiles.
const WHEEL_MEMBERS: &[(&str, &[u8])] = &[
    ("demo/__init__.py", b"x = 1\n"),
    (
        "demo-1.0.dist-info/METADATA",
        b"Name: demo\r\nVersion: 1.0\r\n",
    ),
    ("demo-1.0.dist-info/WHEEL", b"Wheel-Version: 1.0\r\n"),
    ("demo-1.0.dist-info/RECORD", b"this-is-not-the-manifest,,\n"),
];

fn write_zip(path: &Path, members: &[(&str, &[u8])]) {
    let mut w = zip_crate::ZipWriter::new(std::fs::File::create(path).unwrap());
    let opts: zip_crate::write::FileOptions<'_, ()> = zip_crate::write::FileOptions::default()
        .compression_method(zip_crate::CompressionMethod::Stored);
    for (n, b) in members {
        w.start_file(*n, opts).unwrap();
        w.write_all(b).unwrap();
    }
    w.finish().unwrap();
}

fn tar_bytes(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = ::tar::Builder::new(Vec::new());
    for (n, body) in members {
        let mut h = ::tar::Header::new_ustar();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(1_700_000_000);
        h.set_cksum();
        b.append_data(&mut h, n, *body).unwrap();
    }
    b.into_inner().unwrap()
}

fn gz(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut e = flate2::write::GzEncoder::new(&mut out, flate2::Compression::default());
    e.write_all(body).unwrap();
    e.finish().unwrap();
    out
}

fn write_tar(path: &Path, members: &[(&str, &[u8])]) {
    std::fs::write(path, tar_bytes(members)).unwrap();
}

fn write_tar_gz(path: &Path, members: &[(&str, &[u8])]) {
    std::fs::write(path, gz(&tar_bytes(members))).unwrap();
}

/// A `.gem` is a bare tar whose members are themselves gzipped. `checksums.yaml.gz` is here so
/// `gem-exclude-checksums` has something to drop.
fn write_gem(path: &Path) {
    let metadata = gz(b"--- !ruby/object:Gem::Specification\nname: demo\n");
    let checksums = gz(b"---\nSHA256:\n  data.tar.gz: abc\n");
    write_tar(
        path,
        &[
            ("metadata.gz", metadata.as_slice()),
            ("checksums.yaml.gz", checksums.as_slice()),
        ],
    );
}

// ---------------------------------------------------------------------------------------------
// What each command says about the set it chose and the bytes it produced.
// ---------------------------------------------------------------------------------------------

/// The answer to "which stabilizer set, and what did it produce" — the part of a run that has to be
/// identical whichever command asked, because it is the part a signature covers.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Chosen {
    set_id: String,
    set_digest: String,
    stabilized: String,
    /// Pass ids in the order they fired. Digest equality could in principle survive two different
    /// sets reaching the same bytes on a small fixture; the applied list cannot.
    applied: Vec<String>,
}

fn json_of(out: &std::process::Output, what: &str) -> serde_json::Value {
    assert!(
        out.status.success(),
        "{what} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "{what} did not print JSON ({e}): {}",
            String::from_utf8_lossy(&out.stdout)
        )
    })
}

/// What `trigon stabilize --report` chose.
fn stabilize_chose(infile: &Path, extra: &[&str]) -> Chosen {
    let outfile = infile.with_extension("stabilized.out");
    let out = Command::new(bin())
        .arg("stabilize")
        .arg("--infile")
        .arg(infile)
        .arg("--outfile")
        .arg(&outfile)
        .arg("--report")
        .args(extra)
        .output()
        .unwrap();
    let v = json_of(&out, "stabilize --report");
    Chosen {
        set_id: v["set"]["id"].as_str().unwrap().to_string(),
        set_digest: v["set"]["digest"].as_str().unwrap().to_string(),
        stabilized: v["stabilized"].as_str().unwrap().to_string(),
        applied: v["applied"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["id"].as_str().unwrap().to_string())
            .collect(),
    }
}

/// What `trigon verify` chose for its upstream side. Compared against itself, so the verdict is
/// `exact` and the command exits zero — the outcome is not what this is asking about.
fn verify_chose(infile: &Path, extra: &[&str]) -> Chosen {
    let out = Command::new(bin())
        .arg("verify")
        .arg(infile)
        .arg(infile)
        .arg("--output")
        .arg("json")
        .args(extra)
        .output()
        .unwrap();
    let v = json_of(&out, "verify --output json");
    let u = &v["upstream"];
    Chosen {
        set_id: u["set"][0].as_str().unwrap().to_string(),
        set_digest: u["set"][1].as_str().unwrap().to_string(),
        stabilized: u["stabilized"]["sha256"].as_str().unwrap().to_string(),
        applied: u["applied"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["id"].as_str().unwrap().to_string())
            .collect(),
    }
}

// ---------------------------------------------------------------------------------------------
// 1. The seam finding 2 lived in.
// ---------------------------------------------------------------------------------------------

#[test]
fn stabilize_and_verify_choose_the_same_set_and_reach_the_same_digest_for_every_artifact_kind() {
    // Finding 2, pinned. `stabilize_one` used `default_for(fmt)` and `verify` used
    // `resolve_profile`; the two disagreed for every artifact kind whose profile is not implied by
    // its container format, which is all four of them. The digest is the load-bearing half — it is
    // what a claim is signed under — but the applied list is asserted too, because two sets can
    // coincidentally agree on a small fixture's bytes and can never agree on which passes ran.
    //
    // Every kind, not just the wheel: the wheel is where it was found, and a table with one row is
    // a table that grows a second row nobody checks.
    let d = dir("kinds");

    let whl = d.join("demo-1.0-py3-none-any.whl");
    write_zip(&whl, WHEEL_MEMBERS);
    let zip = d.join("demo.zip");
    write_zip(&zip, WHEEL_MEMBERS);
    let nupkg = d.join("demo.nupkg");
    write_zip(&nupkg, WHEEL_MEMBERS);
    let krate = d.join("demo-1.0.crate");
    write_tar_gz(
        &krate,
        &[
            ("demo-1.0/src/lib.rs", b"fn main() {}\n"),
            (
                "demo-1.0/.cargo_vcs_info.json",
                b"{\"git\":{\"sha1\":\"0\"}}",
            ),
        ],
    );
    let gem = d.join("demo-1.0.gem");
    write_gem(&gem);
    let tgz = d.join("demo-1.0.tgz");
    write_tar_gz(&tgz, &[("package/index.js", b"module.exports = 1\n")]);

    for f in [&whl, &zip, &nupkg, &krate, &gem, &tgz] {
        let s = stabilize_chose(f, &[]);
        let v = verify_chose(f, &[]);
        assert_eq!(
            s,
            v,
            "`trigon stabilize` and `trigon verify` disagree about {}. \
             Two commands in one binary must not compute two stabilized digests for one file.",
            f.display()
        );
    }
}

#[test]
fn a_wheel_runs_the_wheel_passes_from_stabilize_and_not_only_from_verify() {
    // The specific damage finding 2 did, stated as the thing that must not come back. Under
    // `default_for(fmt)` a `.whl` got the plain zip set, so `wheel-record` never ran and a rebuilt
    // wheel's RECORD was compared against the published one line for line rather than regenerated
    // from the members actually present — one differing member reported as two.
    //
    // `tests/cli.rs` already asserts that `verify` picks the wheel profile. Nothing asserted it for
    // `stabilize`, which is the command that had the bug.
    let d = dir("wheel-passes");
    let whl = d.join("demo-1.0-py3-none-any.whl");
    write_zip(&whl, WHEEL_MEMBERS);

    let s = stabilize_chose(&whl, &[]);
    assert_eq!(s.set_id, "wheel", "a .whl must not get the plain zip set");
    for pass in ["wheel-metadata-eol", "wheel-record"] {
        assert!(
            s.applied.contains(&pass.to_string()),
            "`trigon stabilize` on a wheel did not run `{pass}`; it applied {:?}",
            s.applied
        );
    }

    // And the contrast that gives the assertion above its teeth: the same bytes under a name that
    // says nothing get the zip set and a different answer. If this ever stops being true the test
    // above is passing for the wrong reason — because the two profiles became the same profile.
    let zip = d.join("demo.zip");
    write_zip(&zip, WHEEL_MEMBERS);
    assert_eq!(std::fs::read(&whl).unwrap(), std::fs::read(&zip).unwrap());
    let z = stabilize_chose(&zip, &[]);
    assert_eq!(z.set_id, "zip");
    assert_ne!(
        s.stabilized, z.stabilized,
        "the wheel set and the zip set reached the same digest, so this fixture proves nothing"
    );

    // Both commands move together, in both directions. A fix that taught `stabilize` the artifact
    // kind but left `verify` sniffing the container would be the same bug mirrored.
    assert_eq!(verify_chose(&whl, &[]).stabilized, s.stabilized);
    assert_eq!(verify_chose(&zip, &[]).stabilized, z.stabilized);
}

#[test]
fn an_explicit_profile_or_format_flag_reaches_both_commands_the_same_way() {
    // `resolve_profile` has two branches — the requested id and the inferred kind — and finding 2
    // was a divergence in the second. The first is worth a line because it is the escape hatch a
    // person reaches for when the inference is wrong, and an escape hatch that only one command
    // honours is worse than none: they would be *told* both runs used `--profile zip`.
    let d = dir("explicit");
    let whl = d.join("demo-1.0-py3-none-any.whl");
    write_zip(&whl, WHEEL_MEMBERS);

    for flags in [
        ["--profile", "zip"].as_slice(),
        ["--profile", "gzip"].as_slice(),
        ["--format", "zip"].as_slice(),
    ] {
        assert_eq!(
            stabilize_chose(&whl, flags),
            verify_chose(&whl, flags),
            "the two commands disagree under {flags:?}"
        );
    }

    // An explicit profile really does override the kind, in both. Otherwise the equality above
    // would hold trivially because neither command listened.
    assert_eq!(stabilize_chose(&whl, &["--profile", "zip"]).set_id, "zip");
    assert_eq!(verify_chose(&whl, &["--profile", "zip"]).set_id, "zip");
}

#[test]
fn every_artifact_kind_the_binary_dispatches_on_names_a_profile_this_binary_knows() {
    // The same two-halves shape one level down. The binary carries a table mapping a filename
    // extension to a stabilizer profile *id*, and `trigon-stabilize` carries the registry those ids
    // are looked up in. Nothing checks that the first only names things the second has, and the
    // lookup is an `and_then` that turns an unknown id into the container default without a word.
    //
    // `.nupkg` used to be in the table while `nupkg` was not in the registry, and the lookup
    // swallowed the miss: a NuGet package was compared with its `.signature.p7s` intact and its OPC
    // parts unordered, which is the comparison `docs/03-ecosystems.md` §NuGet says it must not get,
    // and nothing said so. The arm is gone until `docs/17-backlog.md` B8 adds the profile, so a
    // `.nupkg` now takes the container default deliberately rather than by a failed lookup, and
    // `resolve_profile` panics if the table ever again names an id the registry lacks.
    //
    // So `demo.nupkg` expects `zip` here. **That expectation is the thing to change when B8
    // lands** — not by adding an arm and leaving this alone, which would put the silence back.
    let d = dir("kind-table");
    let cases: &[(&str, &str)] = &[
        ("demo-1.0-py3-none-any.whl", "wheel"),
        ("demo-1.0.crate", "crate"),
        ("demo-1.0.gem", "gem"),
        // Was `zip`, the documented fallback while no `nupkg` profile existed. The profile landed,
        // and this line is the half the old comment said to change when it did — updating the arm
        // and leaving this alone would have put the silence back.
        ("demo.nupkg", "nupkg"),
    ];
    let mut wrong = Vec::new();
    for (name, expected) in cases {
        let p = d.join(name);
        if name.ends_with(".gem") {
            write_gem(&p);
        } else if name.ends_with(".crate") {
            write_tar_gz(&p, &[("demo-1.0/src/lib.rs", b"fn main() {}\n")]);
        } else {
            write_zip(&p, WHEEL_MEMBERS);
        }
        let got = stabilize_chose(&p, &[]).set_id;

        // The profile the binary settled on has to be one the binary will also describe. A set id
        // that `trigon stabilizers` refuses is an id nobody can audit a signed claim against.
        let listed = Command::new(bin())
            .args(["stabilizers", "--profile", &got])
            .output()
            .unwrap();
        assert!(
            listed.status.success(),
            "a {name} stabilized under set `{got}`, which `trigon stabilizers` does not know"
        );

        if got != *expected {
            wrong.push(format!(
                "{name} asks for profile `{expected}` and silently gets `{got}`"
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "the extension table names profiles the registry does not have:\n  {}",
        wrong.join("\n  ")
    );
}

// ---------------------------------------------------------------------------------------------
// 2. The verdict, displayed and decided.
// ---------------------------------------------------------------------------------------------

#[test]
fn the_exit_code_and_the_named_verdict_agree_in_text_and_in_json() {
    // The outcome is computed once and then consumed twice: printed for a person and turned into
    // an exit code for a pipeline. Those must not be able to disagree, and neither may depend on
    // `--output`: a CI job that switched to `--output json` for parseability and silently stopped
    // failing on divergence would be the worst possible version of this bug, because the pipeline
    // would go green.
    let d = dir("verdict");
    let a = d.join("a.tgz");
    let b = d.join("b.tgz");
    let c = d.join("c.tgz");
    write_tar_gz(&a, &[("package/index.js", b"same\n")]);
    write_tar_gz(&b, &[("package/index.js", b"same\n")]);
    write_tar_gz(&c, &[("package/index.js", b"different\n")]);

    for (upstream, rebuild, divergent) in [(&a, &b, false), (&a, &c, true)] {
        let text = Command::new(bin())
            .arg("verify")
            .arg(upstream)
            .arg(rebuild)
            .output()
            .unwrap();
        let json = Command::new(bin())
            .arg("verify")
            .arg(upstream)
            .arg(rebuild)
            .args(["--output", "json"])
            .output()
            .unwrap();

        assert_eq!(
            text.status.code(),
            json.status.code(),
            "the exit code must be the verdict, not a property of the output format"
        );
        assert_eq!(
            text.status.code() == Some(1),
            divergent,
            "a divergence must exit 1 and a match must exit 0, or no pipeline can use this"
        );

        // The same word, spelled the same way, in both renderings. `Match`'s `Display` and its
        // serde representation are two independent spellings of one enum, and `Match::from_str` is
        // the inverse of only one of them — a sweep's resume path once spelled
        // `normalized_with_caveats` with hyphens and dropped every caveated match from its rate.
        let outcome = serde_json::from_slice::<serde_json::Value>(&json.stdout).unwrap()["outcome"]
            .as_str()
            .unwrap()
            .to_string();
        let printed = String::from_utf8_lossy(&text.stdout);
        assert!(
            printed.lines().next().unwrap_or("").contains(&outcome),
            "the text output's verdict line does not name `{outcome}`: {printed}"
        );
    }
}

#[test]
fn a_signed_claim_re_derives_to_the_same_verdict_from_files_whose_names_say_nothing() {
    // The producer and the checker are two paths to one verdict, and they are given different
    // information on purpose. `trigon verify` picks the profile from the artifact's name;
    // `trigon verify-attestation --rerun-comparison` has only the statement, because a third party
    // holding a bundle and two files has no ecosystem to ask. If the checker re-sniffed the name it
    // would agree with the producer by accident, and disagree the moment anyone renamed a file on
    // the way — which is the normal fate of a downloaded artifact.
    //
    // Renaming both files to `.bin` is the test of that independence: `.bin` infers no format at
    // all, so a checker that looked would fail outright rather than quietly.
    let d = dir("attest");
    let up = d.join("demo-1.0-py3-none-any.whl");
    write_zip(&up, WHEEL_MEMBERS);
    // Same content, LF instead of CRLF and a different RECORD: a real `normalized_with_caveats`,
    // which is the interesting verdict because it is the one the provenance cap governs.
    let rb = d.join("rebuilt-1.0-py3-none-any.whl");
    write_zip(
        &rb,
        &[
            ("demo/__init__.py", b"x = 1\n"),
            ("demo-1.0.dist-info/METADATA", b"Name: demo\nVersion: 1.0\n"),
            ("demo-1.0.dist-info/WHEEL", b"Wheel-Version: 1.0\n"),
            ("demo-1.0.dist-info/RECORD", b"also-wrong,,\n"),
        ],
    );

    let bundle = d.join("claim.json");
    let made = Command::new(bin())
        .arg("verify")
        .arg(&up)
        .arg(&rb)
        .args(["--output", "json"])
        .arg("--attest")
        .arg(&bundle)
        .output()
        .unwrap();
    let claimed = serde_json::from_slice::<serde_json::Value>(&made.stdout).unwrap()["outcome"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        claimed, "normalized_with_caveats",
        "fixture drifted: this test wants a caveated match to re-derive"
    );

    let anon_up = d.join("upstream.bin");
    let anon_rb = d.join("rebuild.bin");
    std::fs::copy(&up, &anon_up).unwrap();
    std::fs::copy(&rb, &anon_rb).unwrap();

    for (u, r, how) in [
        (&up, &rb, "under their own names"),
        (&anon_up, &anon_rb, "renamed to .bin"),
    ] {
        let out = Command::new(bin())
            .arg("verify-attestation")
            .arg(&bundle)
            .arg("--rerun-comparison")
            .arg("--upstream")
            .arg(u)
            .arg("--rebuild")
            .arg(r)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && text.contains("the claim holds"),
            "re-deriving {how} did not reproduce the signed verdict:\n{text}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            text.contains("under wheel@"),
            "the checker used a set other than the one the statement names, {how}:\n{text}"
        );
        assert!(text.contains(&claimed), "{text}");
    }
}

// ---------------------------------------------------------------------------------------------
// 3. Two readers of one sweep.
// ---------------------------------------------------------------------------------------------

/// A `trigon watch` server on a port nobody else has, killed when this drops.
#[cfg(feature = "build")]
struct Board(std::process::Child, u16);

#[cfg(feature = "build")]
impl Drop for Board {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(feature = "build")]
impl Board {
    fn watching(work: &Path) -> Board {
        // Ask the OS for a free port and hand it straight back. A fixed port would collide with
        // whatever else is on this machine, including another test in this file.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let child = Command::new(bin())
            .arg("watch")
            .arg(work)
            .arg("--bind")
            .arg(format!("127.0.0.1:{port}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Board(child, port)
    }

    /// The board's own view model, as it serves it to a page or a script.
    fn state(&self) -> serde_json::Value {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let mut last = String::new();
        while std::time::Instant::now() < deadline {
            match self.get("/api/state") {
                Ok(body) => return serde_json::from_str(&body).unwrap(),
                Err(e) => last = e,
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!("`trigon watch` never answered on port {}: {last}", self.1);
    }

    fn get(&self, path: &str) -> Result<String, String> {
        let addr = format!("127.0.0.1:{}", self.1);
        let mut s = std::net::TcpStream::connect(&addr).map_err(|e| e.to_string())?;
        s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        s.write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .map_err(|e| e.to_string())?;
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&raw).into_owned();
        text.split_once("\r\n\r\n")
            .map(|(_, body)| body.to_string())
            .ok_or_else(|| format!("no HTTP body in {text:?}"))
    }
}

/// The rate `trigon score` reports, as (reproduced, evidence).
#[cfg(feature = "build")]
fn score_rate(results: &Path, labels: &Path) -> (u64, u64) {
    let out = Command::new(bin())
        .arg("score")
        .arg(results)
        .arg("--labels")
        .arg(labels)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    // "  needs-build-inference     3/4  reproduced (75%)   of 8 labelled"
    for line in text.lines() {
        if !line.contains("reproduced") {
            continue;
        }
        for tok in line.split_whitespace() {
            if let Some((a, b)) = tok.split_once('/')
                && let (Ok(a), Ok(b)) = (a.parse::<u64>(), b.parse::<u64>())
            {
                return (a, b);
            }
        }
    }
    panic!("`trigon score` reported no rate:\n{text}");
}

/// A sweep work directory holding exactly these `results.tsv` lines, plus the label file that
/// `trigon score` needs to say anything about them.
#[cfg(feature = "build")]
fn sweep_dir(name: &str, results: &str, purls: &[&str]) -> (PathBuf, PathBuf) {
    let d = dir(name);
    let work = d.join("work");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(work.join("results.tsv"), results).unwrap();
    let labels: Vec<serde_json::Value> = purls
        .iter()
        .map(|p| {
            serde_json::json!({
                "purl": p,
                "capability": "needs-build-inference",
                "reason": "a fixture, not a judgement about any package",
            })
        })
        .collect();
    let labels_path = d.join("labels.json");
    std::fs::write(
        &labels_path,
        serde_json::to_vec(&serde_json::json!({ "labels": labels })).unwrap(),
    )
    .unwrap();
    (work, labels_path)
}

#[cfg(feature = "build")]
#[test]
fn score_and_watch_read_one_results_file_to_the_same_reproduction_rate() {
    // `trigon score` and `trigon watch` are two readers of `results.tsv` with two independent
    // parsers and two independent notions of what counts as evidence — `read_results` asks whether
    // the label parses as a `Match`, `Rates::of` asks `Family::of(label).is_evidence()`. They are
    // reporting the same number about the same sweep to the same person, ten minutes apart, and a
    // reproduction rate that depends on which command you typed is not a measurement.
    //
    // One row per label the outcome taxonomy can produce, so a new label that one reader buckets
    // and the other does not is caught here rather than in a sweep summary nobody can reconcile.
    let rows = "\
pkg:npm/a@1\texact\t1.0\t\t0
pkg:npm/b@1\tnormalized\t1.0\t\t0
pkg:npm/c@1\tnormalized_with_caveats\t1.0\t\t0
pkg:npm/d@1\tdivergent\t1.0\t\t0
pkg:npm/e@1\tbuild-failed:deps\t1.0\tcc/missing-header:python.h\t0
pkg:npm/f@1\terror:infra\t1.0\terror: the mirror did not start\t0
pkg:npm/g@1\tvoid\t1.0\t\t0
pkg:npm/h@1\tno-strategy\t1.0\t\t0
";
    let purls: Vec<String> = "abcdefgh"
        .chars()
        .map(|c| format!("pkg:npm/{c}@1"))
        .collect();
    let refs: Vec<&str> = purls.iter().map(String::as_str).collect();
    let (work, labels) = sweep_dir("rates", rows, &refs);

    let (reproduced, evidence) = score_rate(&work.join("results.tsv"), &labels);
    let board = Board::watching(&work).state();

    assert_eq!(
        (reproduced, evidence),
        (
            board["reproduced"].as_u64().unwrap(),
            board["evidence"].as_u64().unwrap()
        ),
        "`trigon score` says {reproduced}/{evidence} and `trigon watch` says {}/{} of the same file",
        board["reproduced"],
        board["evidence"]
    );
    // And the denominator is the one the design insists on: three of the eight labels say something
    // about the package, and five say something about us or about scope.
    assert_eq!((reproduced, evidence), (3, 4));
}

#[cfg(feature = "build")]
#[test]
fn a_half_written_final_row_is_evidence_to_neither_reader_or_to_both() {
    // The sweep writes each row with one `writeln!` to an unbuffered `File` and flushes per target
    // precisely because the process may die mid-sweep. `writeln!` is not one syscall: `write_fmt`
    // forwards every literal and every argument separately, so `"{purl}\t{}\t{secs:.1}\t{}\t{}"`
    // is eight `write(2)` calls — measured, under strace: `pkg:npm/c@1`, `\t`, `exact`, `\t`, `1`,
    // `.`, `0`, `\t\t0\n`. A kill after the third leaves exactly the last line of this fixture,
    // and `watch::parse_results` documents that case and drops the row.
    //
    // `read_results`, which is what `trigon score` and the `--fail-on-regression` promotion gate
    // use, requires only the purl and the label. So the same file reads as two different sweeps:
    // the board drops the partial row and reports a rate over what finished, while `score` counts
    // a target the sweep never finished recording, as reproduced, and says nothing about it. The
    // sweep's own resume path (`completed`) requires the seconds too, which makes `read_results`
    // the odd one of three.
    //
    // Either rule is defensible. Two rules in one binary is not.
    let rows = "\
pkg:npm/a@1\texact\t1.0\t\t0
pkg:npm/b@1\tdivergent\t1.0\t\t0
pkg:npm/c@1\texact";
    let (work, labels) = sweep_dir(
        "partial-row",
        rows,
        &["pkg:npm/a@1", "pkg:npm/b@1", "pkg:npm/c@1"],
    );

    let (reproduced, evidence) = score_rate(&work.join("results.tsv"), &labels);
    let board = Board::watching(&work).state();
    let seen = (
        board["reproduced"].as_u64().unwrap(),
        board["evidence"].as_u64().unwrap(),
    );

    assert_eq!(
        board["dropped_rows"].as_u64().unwrap(),
        1,
        "fixture drifted: the last row is meant to be the partial one"
    );
    assert_eq!(
        (reproduced, evidence),
        seen,
        "`trigon score` counted the half-written row and `trigon watch` dropped it: \
         score says {reproduced}/{evidence}, the board says {}/{}. One sweep, one file, \
         two reproduction rates.",
        seen.0,
        seen.1
    );
}
