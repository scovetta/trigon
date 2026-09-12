//! What a published wheel says about the toolchain that made it.
//!
//! A deterministic read from the artifact under test, and the highest-value one available for PyPI.
//! Measured on the M1 smoke corpus: **nine of ten divergences touched only `dist-info/` metadata** —
//! `METADATA`, `WHEEL` and the `RECORD` that follows from them — with every source file byte for
//! byte identical. One cause, one fix.
//!
//! The cause is that the build frontend installs whatever backend the project declares, resolved
//! today, while the publisher used whatever was current when they published:
//!
//! ```text
//! six-1.17.0             published: setuptools (75.6.0)    rebuilt: setuptools (84.0.0)
//! attrs-26.1.0           published: hatchling 1.29.0       rebuilt: hatchling 1.32.0
//! packaging-26.3         published: flit 3.12.0            rebuilt: flit 4.0.2
//! py_cpuinfo-9.0.0       published: bdist_wheel (0.37.1)   rebuilt: setuptools (84.0.0)
//! ```
//!
//! `attrs` diverges on exactly two lines: `Generator` and `Metadata-Version: 2.4` against `2.5`.
//!
//! The heuristic used to say "nothing in PyPI's metadata says what the build needed", which is true
//! of the *metadata* and not of the *artifact*: every wheel carries `Generator` in its own
//! `.dist-info/WHEEL`. Reading it is an algorithm, not a search, and it beats anything a model could
//! infer from the source tree — which is the same argument `docs/07-ai.md` §2.1 makes for tree-hash
//! scoring over prompting.

use trigon_core::{Claim, Confidence, Evidence, Format};

/// The build backend a wheel records, as `(name, version)`.
///
/// `None` for anything that is not a wheel, or a wheel whose `WHEEL` file names no generator. Both
/// are ordinary rather than exceptional: an sdist has no such file, and a hand-assembled wheel need
/// not fill the field in.
pub fn generator(bytes: &[u8]) -> Option<(String, String)> {
    let mut notes = Vec::new();
    let parsed = trigon_archive::parse(
        bytes.to_vec(),
        Format::Zip,
        &trigon_archive::Limits::default(),
        &mut notes,
    )
    .ok()?;

    let entry = parsed.archive.entries.iter().find(|e| {
        let p = e.path.to_string();
        p.ends_with(".dist-info/WHEEL")
    })?;
    let body = entry.body_bytes().ok()?;
    let text = std::str::from_utf8(&body).ok()?;
    parse_generator(text)
}

/// `Generator: setuptools (75.6.0)` and `Generator: flit 3.12.0` are both real.
///
/// Two spellings because two conventions exist and neither is going away: `bdist_wheel` and
/// setuptools parenthesise the version, flit and hatchling do not. Reading only one of them would
/// silently skip half the corpus, and a pin that silently does not happen is worse than no pin —
/// the divergence still appears and the evidence says it should not have.
fn parse_generator(wheel_file: &str) -> Option<(String, String)> {
    let line = wheel_file
        .lines()
        .find_map(|l| l.strip_prefix("Generator:"))?
        .trim();

    if let Some((name, rest)) = line.split_once(" (") {
        let version = rest.trim_end_matches(')').trim();
        return non_empty(name.trim(), version);
    }
    let (name, version) = line.rsplit_once(' ')?;
    non_empty(name.trim(), version.trim())
}

fn non_empty(name: &str, version: &str) -> Option<(String, String)> {
    (!name.is_empty() && !version.is_empty()).then(|| (name.to_string(), version.to_string()))
}

/// The generator as evidence, for the intrinsics of a target.
///
/// `Certain` because it is not an inference. The artifact says so, in a field its own builder wrote,
/// and the only way it is wrong is if the publisher edited the wheel by hand — in which case the
/// rebuild was never going to match anyway.
pub fn generator_evidence(bytes: &[u8]) -> Vec<Evidence> {
    let Some((tool, version)) = generator(bytes) else {
        return Vec::new();
    };
    vec![
        Evidence {
            claim: Claim::BuildBackend {
                backend: normalize_backend(&tool),
            },
            confidence: Confidence::Certain,
            source: "wheel:Generator".into(),
        },
        Evidence {
            claim: Claim::ToolchainExact {
                tool: normalize_backend(&tool),
                version,
            },
            confidence: Confidence::Certain,
            source: "wheel:Generator".into(),
        },
    ]
}

/// The name the wheel records is not always the name that installs.
///
/// `bdist_wheel` is the setuptools command that wrote the file, not a distribution anyone can pin;
/// its version is the `wheel` package's. Pinning `bdist_wheel==0.37.1` fails to resolve, which
/// would turn a divergence we understand into a build failure we do not.
fn normalize_backend(tool: &str) -> String {
    match tool {
        "bdist_wheel" => "wheel".to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_spellings_of_the_generator_line_are_read() {
        // Every one of these came off a real wheel in the M1 corpus. Reading only the parenthesised
        // form would have silently skipped flit and hatchling, and a pin that silently does not
        // happen is worse than none: the divergence appears anyway and the evidence says it should
        // not have.
        for (line, want) in [
            ("Generator: setuptools (75.6.0)", ("setuptools", "75.6.0")),
            ("Generator: bdist_wheel (0.37.1)", ("bdist_wheel", "0.37.1")),
            ("Generator: flit 3.12.0", ("flit", "3.12.0")),
            ("Generator: hatchling 1.29.0", ("hatchling", "1.29.0")),
        ] {
            let doc = format!("Wheel-Version: 1.0\n{line}\nRoot-Is-Purelib: true\n");
            let (name, version) = parse_generator(&doc).unwrap_or_else(|| panic!("{line}"));
            assert_eq!((name.as_str(), version.as_str()), want);
        }
    }

    #[test]
    fn a_wheel_that_names_no_generator_yields_nothing() {
        assert!(parse_generator("Wheel-Version: 1.0\nRoot-Is-Purelib: true\n").is_none());
        assert!(parse_generator("Generator:\n").is_none());
        assert!(parse_generator("Generator: setuptools\n").is_none());
    }

    #[test]
    fn bdist_wheel_is_recorded_as_the_package_that_can_actually_be_pinned() {
        // `bdist_wheel` is a setuptools command, not a distribution. Pinning it by name fails to
        // resolve, turning a divergence we understand into a build failure we do not.
        let doc = "Generator: bdist_wheel (0.37.1)\n";
        let (tool, _) = parse_generator(doc).unwrap();
        assert_eq!(normalize_backend(&tool), "wheel");
    }

    #[test]
    fn the_evidence_is_certain_because_it_is_not_an_inference() {
        // The artifact says so, in a field its own builder wrote. Marking this anything less would
        // make the toolchain resolution treat a fact as a guess.
        let mut w = ::zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts: ::zip::write::FileOptions<'_, ()> = ::zip::write::FileOptions::default()
            .compression_method(::zip::CompressionMethod::Stored);
        use std::io::Write as _;
        w.start_file("demo-1.0.dist-info/WHEEL", opts).unwrap();
        w.write_all(b"Wheel-Version: 1.0\nGenerator: hatchling 1.29.0\n")
            .unwrap();
        let bytes = w.finish().unwrap().into_inner();

        let ev = generator_evidence(&bytes);
        assert_eq!(ev.len(), 2);
        assert!(ev.iter().all(|e| e.confidence == Confidence::Certain));
        assert!(ev.iter().any(|e| matches!(
            &e.claim,
            Claim::ToolchainExact { tool, version } if tool == "hatchling" && version == "1.29.0"
        )));
    }

    #[test]
    fn an_sdist_is_not_an_error() {
        // A tarball has no `.dist-info/WHEEL`, and neither does a wheel somebody assembled by hand.
        // Both are ordinary.
        assert!(generator_evidence(b"not a zip at all").is_empty());
    }
}
