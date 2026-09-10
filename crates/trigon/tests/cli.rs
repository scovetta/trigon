//! The binary's contract: exit codes, output shape, and the errors it gives a person.

use std::path::PathBuf;
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
