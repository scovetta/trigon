//! Turn a managed assembly back into C#, as a reading aid — never as part of a verdict.
//!
//! For an executable member a byte diff says only "these differ", which is true and useless: a
//! reader cannot tell a renamed local from a rewritten method, and neither can the diff-opinion
//! model, which reads "binary differences in all DLLs" as substantive because binary differences
//! *look* substantive. `ilspycmd` decompiles each side to C#, and the diff of *that* is where the
//! difference becomes legible — `castle.core@5.1.1`'s four assemblies differ by ~1% of their bytes,
//! scattered, and decompile to identical code but for three version attributes. The 3,690-byte
//! binary diff is four lines of C#.
//!
//! **Display only, the same rule as the opinion it feeds** ([`trigon_core::opinion`]): a decompiler
//! turns bytes into something readable, never into a decision. ILSpy normalises compiler codegen,
//! so two assemblies built from the same source decompile the same even when their bytes differ —
//! which is the whole point for a reader, and exactly why it must not reach the comparison outcome,
//! the publication gate, or any signed statement. What the C# diff shows is a hypothesis about
//! *why* bytes differ, not a second opinion about *whether* they do.
//!
//! Best effort throughout. The tool runs in a container, and a run that cannot start one — no
//! podman, no network to build the image the first time — loses an explanation, not a result: the
//! caller falls back to naming the member and its size.

use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Pinned, because the diff of two decompilations is only meaningful when the same decompiler
/// produced both — a version difference would show as source noise that is really tool noise. Both
/// sides always go through one image, so the pin is what keeps a *stored* reading comparable to a
/// later one, not what makes a single diff valid.
const ILSPY_VERSION: &str = "9.1.0.7988";

/// The .NET SDK the tool runs on. A tag rather than a digest on purpose: this image compiles no
/// artifact and signs nothing, so which SDK patch decompiles the bytes changes only the phrasing of
/// an aid, and pinning it by digest would be a maintenance cost bought for a property nobody reads.
const ILSPY_BASE: &str = "mcr.microsoft.com/dotnet/sdk:8.0";

fn image_tag() -> String {
    format!("localhost/trigon-ilspy:{ILSPY_VERSION}")
}

/// A `podman` command wrapped in a host-side wall-clock bound.
///
/// **Because the decompile is best effort on the run's critical path.** The `timeout` inside the
/// decompile container bounds `ilspycmd`, but not `podman build` reaching the network for a cold
/// image, nor a `podman run` that stalls before the entrypoint. Those are host processes, so a host
/// `timeout` bounds them; without it a stalled pull could hang a run whose record is an aid this
/// step only decorates. `timeout` is coreutils and present wherever podman runs; if it is somehow
/// absent the command fails to spawn and the caller falls back, which is the same best-effort path
/// as no podman at all.
fn podman(secs: u32) -> std::process::Command {
    let mut c = std::process::Command::new("timeout");
    c.arg("-k").arg("5").arg(secs.to_string()).arg("podman");
    c
}

/// Decompile two assemblies to C# through one container, or `None` if either cannot be read.
///
/// Both-or-nothing: the caller wants a *diff*, and a diff needs both sides. One container for the
/// pair, because container startup dominates and there is no reason to pay it twice. `--network
/// none`: the image already carries the tool, and decompilation reaches nothing.
pub fn sources(a: &[u8], b: &[u8]) -> Option<(String, String)> {
    let image = ensure_image()?;
    let dir = scratch_dir()?;
    let result = (|| {
        std::fs::write(dir.join("a.dll"), a).ok()?;
        std::fs::write(dir.join("b.dll"), b).ok()?;
        // Two files out of one run. `ilspycmd` writes to stdout, so redirect each into the mounted
        // directory and read them back on the host — the container has no other channel here.
        //
        // **Bounded in time, memory and processes, because the bytes are the published artifact's
        // and a crafted assembly must not be able to stall the run.** This runs on the divergent
        // path, right where an accusation is about to be recorded, and the sandbox's build timeout
        // (threat-model P29) does not reach it — it is a separate container after the build. A
        // `timeout` around each `ilspycmd` caps a decompiler that spins; `--memory`/`--pids-limit`
        // cap one that allocates or forks. `&&`, not `;`, so a first side that times out or fails
        // does not leave a truncated `a.cs` for the second side's exit code to paper over.
        let out = podman(180)
            .args([
                "run",
                "--rm",
                "--network",
                "none",
                "--memory",
                "2g",
                "--pids-limit",
                "256",
                "-v",
            ])
            .arg(format!("{}:/w:Z", dir.display()))
            .args([
                image.as_str(),
                "sh",
                "-c",
                "timeout -k 5 120 ilspycmd /w/a.dll > /w/a.cs 2>/dev/null \
                 && timeout -k 5 120 ilspycmd /w/b.dll > /w/b.cs 2>/dev/null",
            ])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let a_cs = std::fs::read_to_string(dir.join("a.cs")).ok()?;
        let b_cs = std::fs::read_to_string(dir.join("b.cs")).ok()?;
        // A native DLL, or anything ilspycmd could not read, leaves an empty file behind rather
        // than an error the exit code shows — the redirect swallowed the message. An empty
        // decompilation is not a decompilation, and a blank-versus-blank diff would read as
        // "identical source" about two files nobody decompiled.
        (!a_cs.trim().is_empty() && !b_cs.trim().is_empty()).then_some((a_cs, b_cs))
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result
}

/// Decompile a single assembly to C#, or `None`.
///
/// The one-sided form of [`sources`], for reading rather than diffing — the version reconstruction
/// rung asks it for the published assembly's attribute lines.
pub fn source(dll: &[u8]) -> Option<String> {
    let image = ensure_image()?;
    let dir = scratch_dir()?;
    let result = (|| {
        std::fs::write(dir.join("a.dll"), dll).ok()?;
        let out = podman(180)
            .args([
                "run",
                "--rm",
                "--network",
                "none",
                "--memory",
                "2g",
                "--pids-limit",
                "256",
                "-v",
            ])
            .arg(format!("{}:/w:Z", dir.display()))
            .args([
                image.as_str(),
                "sh",
                "-c",
                "timeout -k 5 120 ilspycmd /w/a.dll > /w/a.cs 2>/dev/null",
            ])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let cs = std::fs::read_to_string(dir.join("a.cs")).ok()?;
        (!cs.trim().is_empty()).then_some(cs)
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result
}

/// The value inside `[assembly: <attr>("...")]`, or `None` if this line is not that attribute or
/// its literal does not spell a value exactly.
///
/// **The value, not its spelling.** ILSpy writes C#, so the literal is escaped as C# needs: `\"`
/// and `\\`, the control characters, and `\uXXXX` for a non-breaking space or a format character.
/// Taken verbatim, those reached the build as the escapes themselves, and a rung that exists to
/// reproduce the published stamps set ones the assembly never carried.
fn assembly_attr(line: &str, attr: &str) -> Option<String> {
    let head = format!("[assembly: {attr}(\"");
    csharp_literal(line.trim().strip_prefix(&head)?.strip_suffix("\")]")?)
}

/// The value a C# regular string literal's body spells, or `None` where it spells none exactly.
///
/// Every escape C# has is decoded, and a UTF-16 surrogate pair becomes the one character it
/// encodes. `None` for an escape C# does not have or that is cut short, a surrogate with no
/// partner, a bare `"` — which is not one literal — and a NUL, which no command line carries:
/// `None` is "not found, do not set it", and a stamp half-read is a wrong one.
fn csharp_literal(body: &str) -> Option<String> {
    let mut units: Vec<u16> = Vec::with_capacity(body.len());
    let mut chars = body.chars().peekable();
    // Up to `max` hex digits, at least `min`, as one number.
    let hex = |chars: &mut std::iter::Peekable<std::str::Chars<'_>>, min: usize, max: usize| {
        let mut n = 0u32;
        let mut taken = 0;
        while taken < max
            && let Some(d) = chars.peek().and_then(|c| c.to_digit(16))
        {
            n = n * 16 + d;
            chars.next();
            taken += 1;
        }
        (taken >= min).then_some(n)
    };
    while let Some(c) = chars.next() {
        let unit = match c {
            '"' => return None,
            '\\' => match chars.next()? {
                '\'' => u32::from('\''),
                '"' => u32::from('"'),
                '\\' => u32::from('\\'),
                '0' => 0,
                'a' => 0x07,
                'b' => 0x08,
                'f' => 0x0c,
                'n' => u32::from('\n'),
                'r' => u32::from('\r'),
                't' => u32::from('\t'),
                'v' => 0x0b,
                'u' => hex(&mut chars, 4, 4)?,
                'x' => hex(&mut chars, 1, 4)?,
                'U' => {
                    let c = char::from_u32(hex(&mut chars, 8, 8)?)?;
                    units.extend_from_slice(c.encode_utf16(&mut [0; 2]));
                    continue;
                }
                _ => return None,
            },
            c => {
                units.extend_from_slice(c.encode_utf16(&mut [0; 2]));
                continue;
            }
        };
        // Every escape but `\U` names one UTF-16 unit, `\u` and `\x` a surrogate among them.
        units.push(u16::try_from(unit).ok()?);
    }
    let value = String::from_utf16(&units).ok()?;
    (!value.contains('\0')).then_some(value)
}

/// Read a published assembly's version stamps by decompiling it and parsing the assembly-level
/// attributes ILSpy emits at the top of the module.
///
/// Parsing the decompilation rather than the metadata tables reuses the one decompiler this binary
/// already carries and keeps the reader out of the business of walking custom-attribute blobs.
/// `None` when the assembly cannot be decompiled or carries no version attribute at all.
pub fn assembly_version_info(dll: &[u8]) -> Option<trigon_strategy::AssemblyVersionInfo> {
    version_info_in(&source(dll)?)
}

/// The version stamps a decompilation's assembly-level attributes carry, or `None` if it carries
/// none. Apart from [`assembly_version_info`] so the reading can be tested without a container.
fn version_info_in(cs: &str) -> Option<trigon_strategy::AssemblyVersionInfo> {
    let mut info = trigon_strategy::AssemblyVersionInfo::default();
    // The attributes sit in the first dozens of lines; a bound keeps a pathological decompilation
    // from being scanned in full.
    for line in cs.lines().take(400) {
        if let Some(v) = assembly_attr(line, "AssemblyVersion") {
            info.assembly_version = Some(v);
        } else if let Some(v) = assembly_attr(line, "AssemblyFileVersion") {
            info.file_version = Some(v);
        } else if let Some(v) = assembly_attr(line, "AssemblyInformationalVersion") {
            info.informational_version = Some(v);
        } else if let Some(v) = assembly_attr(line, "AssemblyCopyright") {
            info.copyright = Some(v);
        }
    }
    // The package version prop: the informational version is what a `.csproj` `Version` becomes,
    // and the file version is the fallback where a build set no informational one.
    info.version = info
        .informational_version
        .clone()
        .or_else(|| info.file_version.clone());
    (info != trigon_strategy::AssemblyVersionInfo::default()).then_some(info)
}

/// The image tag if it is present or can be built, else `None`.
///
/// Built at most once per process: the first divergent run with managed members pays the tool
/// install, every one after reuses the layer. The `Once` guards the build, not the existence check
/// — a check is cheap and an image an earlier process built is usable immediately.
fn ensure_image() -> Option<String> {
    let tag = image_tag();
    if image_exists(&tag) {
        return Some(tag);
    }
    static BUILT: std::sync::Once = std::sync::Once::new();
    BUILT.call_once(|| build_image(&tag));
    image_exists(&tag).then_some(tag)
}

fn image_exists(tag: &str) -> bool {
    std::process::Command::new("podman")
        .args(["image", "exists", tag])
        .status()
        .is_ok_and(|s| s.success())
}

/// Build the decompiler image: the SDK, plus the pinned `ilspycmd` on the path.
///
/// The one step that reaches the network, and only the first time. Best effort — a failure here is
/// how a machine with no podman or no route to the tool feed ends up with no decompilation, which
/// is a missing aid and not a failed run.
fn build_image(tag: &str) {
    let Some(dir) = scratch_dir() else { return };
    let containerfile = format!(
        "FROM {ILSPY_BASE}\n\
         ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_ROLL_FORWARD=Major \
         PATH=/root/.dotnet/tools:$PATH\n\
         RUN dotnet tool install --global ilspycmd --version {ILSPY_VERSION}\n"
    );
    let build = (|| -> Option<()> {
        let mut f = std::fs::File::create(dir.join("Containerfile")).ok()?;
        f.write_all(containerfile.as_bytes()).ok()?;
        tracing::info!(%tag, "building the decompiler image (once)");
        let status = podman(600)
            .args(["build", "--tag", tag, "--file"])
            .arg(dir.join("Containerfile"))
            .arg(&dir)
            .status()
            .ok()?;
        status.success().then_some(())
    })();
    if build.is_none() {
        tracing::warn!("could not build the decompiler image; diffs stay at the byte level");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A fresh temp directory, unique across the concurrent decompiles of one run.
fn scratch_dir() -> Option<PathBuf> {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "trigon-ilspy-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

/// Whether a member name is a managed assembly worth trying to decompile.
///
/// By extension, and best effort past it: a native `.dll` gets a container that produces nothing
/// and falls back, which costs one decompile attempt and never a wrong answer.
pub fn looks_like_assembly(name: &str) -> bool {
    trigon_core::is_managed_assembly(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_managed_assembly_extensions_are_offered_to_the_decompiler() {
        for yes in ["Castle.Core.dll", "lib/net6.0/A.DLL", "tool.exe"] {
            assert!(looks_like_assembly(yes), "{yes}");
        }
        for no in [
            "Castle.Core.nuspec",
            "a.xml",
            "readme.txt",
            "A.dll.config",
            "x.pdb",
        ] {
            assert!(!looks_like_assembly(no), "{no}");
        }
    }

    /// The top of a decompilation as ILSpy writes one, `castle.core`'s shape: the assembly-level
    /// attributes, among others, indented or not.
    const CASTLE: &str = "using System.Reflection;\n\
        [assembly: CompilationRelaxations(8)]\n\
        [assembly: AssemblyCompany(\"Castle Project Contributors\")]\n\
        [assembly: AssemblyCopyright(\"Copyright (c) 2004-2022 Castle Project\")]\n\
        [assembly: AssemblyFileVersion(\"5.1.1\")]\n    \
        [assembly: AssemblyInformationalVersion(\"5.1.1+2dc1b1b\")]\n\
        [assembly: AssemblyTitle(\"Castle Core\")]\n\
        [assembly: AssemblyVersion(\"5.0.0.0\")]\n\
        namespace Castle.Core { }\n";

    #[test]
    fn the_version_stamps_are_read_from_the_attributes_ilspy_emits() {
        assert!(
            CASTLE.contains("\n    [assembly: AssemblyInformationalVersion"),
            "the fixture"
        );
        let info = version_info_in(CASTLE).unwrap();
        assert_eq!(info.assembly_version.as_deref(), Some("5.0.0.0"));
        assert_eq!(info.file_version.as_deref(), Some("5.1.1"));
        assert_eq!(info.informational_version.as_deref(), Some("5.1.1+2dc1b1b"));
        assert_eq!(
            info.copyright.as_deref(),
            Some("Copyright (c) 2004-2022 Castle Project")
        );
        // The package version is what a `.csproj` `Version` becomes: the informational version.
        assert_eq!(info.version.as_deref(), Some("5.1.1+2dc1b1b"));
    }

    #[test]
    fn the_file_version_stands_in_where_no_informational_version_was_set() {
        let cs = "[assembly: AssemblyFileVersion(\"2.3.4.0\")]\n\
                  [assembly: AssemblyVersion(\"2.0.0.0\")]\n";
        let info = version_info_in(cs).unwrap();
        assert_eq!(info.version.as_deref(), Some("2.3.4.0"));
        assert_eq!(info.informational_version, None);
        // Only an assembly version: stamped, and no package version to infer from it.
        let info = version_info_in("[assembly: AssemblyVersion(\"1.0.0.0\")]").unwrap();
        assert_eq!(info.assembly_version.as_deref(), Some("1.0.0.0"));
        assert_eq!(info.version, None);
    }

    #[test]
    fn a_decompilation_with_no_version_attribute_has_nothing_to_offer() {
        assert_eq!(version_info_in("public class C { }\n"), None);
        assert_eq!(version_info_in(""), None);
        // Other attributes are not version stamps.
        assert_eq!(
            version_info_in("[assembly: AssemblyTitle(\"Castle Core\")]\n"),
            None
        );
        // Nor is an attribute ILSpy did not finish, or one that is not assembly-level.
        assert_eq!(
            version_info_in("[assembly: AssemblyVersion(\"1.0.0.0\"\n"),
            None
        );
        assert_eq!(version_info_in("[AssemblyVersion(\"1.0.0.0\")]\n"), None);
    }

    /// ILSpy writes each value as a C# string literal, escaped as C# needs it, and the stamp is the
    /// value the literal spells, not its spelling: `\"` and `\\`, the control characters, and the
    /// `\uXXXX` it uses for a non-breaking space or a format character are decoded.
    #[test]
    fn a_stamp_is_the_value_the_literal_spells_not_its_spelling() {
        let copyright = |literal: &str| {
            version_info_in(&format!("[assembly: AssemblyCopyright(\"{literal}\")]\n"))
                .and_then(|i| i.copyright)
        };
        assert_eq!(copyright(r"A\u00a0B\tC").as_deref(), Some("A\u{a0}B\tC"));
        assert_eq!(
            copyright(r#"say \"hi\" from C:\\x"#).as_deref(),
            Some(r#"say "hi" from C:\x"#)
        );
        assert_eq!(
            copyright(r"\a\b\f\n\r\v\'").as_deref(),
            Some("\u{7}\u{8}\u{c}\n\r\u{b}'")
        );
        // A character outside the basic plane is a surrogate pair in C#, and one character here.
        assert_eq!(
            copyright(r"\uD83D\uDE00 \U0001F600").as_deref(),
            Some("😀 😀")
        );
        // `\x` takes one to four hex digits, as many as there are.
        assert_eq!(copyright(r"\x41\x4Z").as_deref(), Some("A\u{4}Z"));
        // A literal whose value ends in what looks like the attribute's close is still one literal.
        assert_eq!(copyright(r#"a\")]"#).as_deref(), Some(r#"a")]"#));
        // Characters ILSpy leaves alone are left alone, `$` and the backtick among them.
        assert_eq!(
            copyright("© 2004–2022 $HOME `id`").as_deref(),
            Some("© 2004–2022 $HOME `id`")
        );
    }

    /// A literal that does not spell a value a build can be given exactly is not read at all:
    /// `None` is "not found, do not set it", and a stamp set to its escapes, or to half of it, is a
    /// stamp the published assembly never carried.
    #[test]
    fn a_literal_that_spells_no_exact_value_is_not_read() {
        for literal in [
            // Not an escape C# has, or one cut short.
            r"a\qb",
            r"a\",
            r"a\u00",
            r"a\xZ",
            r"a\U0011FFFF",
            // A surrogate with no partner is no character at all.
            r"a\uD83D",
            r"a\uDE00b",
            // No command line carries a NUL.
            r"a\0b",
            // Two literals, or a quote C# would not have left bare.
            r#"a", "b"#,
        ] {
            let cs = format!("[assembly: AssemblyCopyright(\"{literal}\")]\n");
            assert_eq!(version_info_in(&cs), None, "{literal}");
        }
        // One stamp that cannot be read leaves the others as they were.
        let info = version_info_in(
            "[assembly: AssemblyCopyright(\"a\\qb\")]\n[assembly: AssemblyVersion(\"1.0.0.0\")]\n",
        )
        .unwrap();
        assert_eq!(info.copyright, None);
        assert_eq!(info.assembly_version.as_deref(), Some("1.0.0.0"));
    }

    /// The attributes sit at the top; a pathological decompilation is not scanned in full.
    #[test]
    fn only_the_top_of_a_decompilation_is_read() {
        let at = |line: usize| {
            let mut cs = "// filler\n".repeat(line - 1);
            cs.push_str("[assembly: AssemblyVersion(\"9.9.9.9\")]\n");
            version_info_in(&cs)
        };
        assert!(at(400).is_some());
        assert_eq!(at(401), None);
    }

    /// The whole path — build the image, decompile two real assemblies, diff the C# — proves that
    /// a difference that is *in the source* survives to the reader, and that ILSpy normalises the
    /// rest. Two assemblies that differ only in a returned constant must decompile to C# that
    /// differs in that constant and nowhere else.
    ///
    /// Gated on the environment, in the repository's `refuse_to_skip` spirit: podman and a route to
    /// the tool feed are things the machine has or does not, so this skips where they are missing
    /// and fails there only when `TRIGON_TESTS_MUST_RUN=1` says the setup was promised.
    #[test]
    fn a_source_level_difference_survives_decompilation_and_the_rest_is_normalised() {
        let must = std::env::var("TRIGON_TESTS_MUST_RUN").as_deref() == Ok("1");
        let skip = |why: &str| {
            if must {
                panic!("TRIGON_TESTS_MUST_RUN=1 but this test skipped: {why}");
            } else {
                eprintln!("skipped: {why}");
            }
        };
        if !podman_healthy() {
            return skip("podman is not available");
        }
        // Two assemblies whose only difference is a returned constant, compiled offline with the
        // SDK's own Roslyn — no restore, no network, 3 KB each.
        let Some((a, b)) = compile_pair() else {
            return skip("could not compile the fixture assemblies");
        };
        let Some((a_cs, b_cs)) = sources(&a, &b) else {
            return skip("the decompiler image could not be built or run");
        };
        assert!(
            a_cs.contains("return 1") || a_cs.contains("return 1;"),
            "a: {a_cs}"
        );
        assert!(
            b_cs.contains("return 2") || b_cs.contains("return 2;"),
            "b: {b_cs}"
        );
        // And the difference is *localised*: the two decompilations are identical but for the
        // lines carrying the constant. This is the property the feature sells — the compiler noise
        // is gone and only the source difference is left.
        let a_lines: Vec<&str> = a_cs.lines().filter(|l| l.trim() != "").collect();
        let b_lines: Vec<&str> = b_cs.lines().filter(|l| l.trim() != "").collect();
        let differing = a_lines.iter().zip(&b_lines).filter(|(x, y)| x != y).count();
        assert!(
            a_lines.len() == b_lines.len() && differing <= 2,
            "the decompilations should differ only in the changed return: {differing} lines differ"
        );
    }

    fn podman_healthy() -> bool {
        std::process::Command::new("podman")
            .arg("info")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    /// Compile `return 1` and `return 2` into two library assemblies, offline, via the SDK image's
    /// own `csc`. `-nostdlib` with explicit references keeps it to the shared framework already in
    /// the image, so nothing is restored.
    fn compile_pair() -> Option<(Vec<u8>, Vec<u8>)> {
        let dir = scratch_dir()?;
        std::fs::write(
            dir.join("a.cs"),
            "public class C { public static int F() { return 1; } }",
        )
        .ok()?;
        std::fs::write(
            dir.join("b.cs"),
            "public class C { public static int F() { return 2; } }",
        )
        .ok()?;
        let script = "set -eu\n\
             CSC=$(find /usr/share/dotnet/sdk -name csc.dll -path '*Roslyn*' | head -1)\n\
             RD=$(dirname \"$(find /usr/share/dotnet/shared/Microsoft.NETCore.App -name System.Runtime.dll | head -1)\")\n\
             for n in a b; do dotnet \"$CSC\" -nostdlib -target:library -out:$n.dll \
               -r:\"$RD/System.Runtime.dll\" -r:\"$RD/System.Private.CoreLib.dll\" $n.cs >/dev/null 2>&1; done";
        let ok = std::process::Command::new("podman")
            .args(["run", "--rm", "--network", "none", "-v"])
            .arg(format!("{}:/w:Z", dir.display()))
            .args(["-w", "/w", ILSPY_BASE, "sh", "-c", script])
            .status()
            .ok()?
            .success();
        let out = ok
            .then(|| {
                Some((
                    std::fs::read(dir.join("a.dll")).ok()?,
                    std::fs::read(dir.join("b.dll")).ok()?,
                ))
            })
            .flatten();
        let _ = std::fs::remove_dir_all(&dir);
        out
    }
}
