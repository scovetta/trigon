//! `trigon`, the single binary.
//!
//! M0 ships `verify` and `stabilizers`. The verify path links no network client and no model code:
//! `cargo build -p trigon --no-default-features` produces a binary that reproduces a verdict from
//! two artifacts and nothing else, which is the claim a sceptic can check for themselves.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use trigon_archive::Limits;
use trigon_compare::{Comparison, compare_bytes};
use trigon_core::{Format, Match};
use trigon_stabilize::{default_for, profile};

#[derive(Parser, Debug)]
#[command(
    name = "trigon",
    version,
    about = "Semantic rebuild verification for open-source packages."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Compare two artifacts and report how far they agree.
    Verify {
        /// The published artifact.
        upstream: PathBuf,
        /// The rebuilt artifact.
        rebuild: PathBuf,
        /// Container format. Inferred from the upstream file name when omitted.
        #[arg(long)]
        format: Option<String>,
        /// Stabilizer profile. Defaults to the one implied by the format.
        #[arg(long)]
        profile: Option<String>,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        output: OutputFormat,
        /// List every differing member rather than the first few.
        #[arg(long)]
        explain: bool,
    },
    /// Stabilize one artifact and write the result.
    ///
    /// Flags mirror the reference implementation's, so a differential run can enable one pass at a
    /// time on both sides and localize a digest mismatch to the pass that caused it.
    Stabilize {
        #[arg(long)]
        infile: PathBuf,
        #[arg(long)]
        outfile: PathBuf,
        #[arg(long)]
        format: Option<String>,
        #[arg(long)]
        profile: Option<String>,
        /// Comma-separated pass ids, or `all`, or `none`.
        #[arg(long, value_delimiter = ',', default_value = "all")]
        enable_passes: Vec<String>,
        /// Comma-separated pass ids, or `all`, or `none`.
        #[arg(long, value_delimiter = ',', default_value = "none")]
        disable_passes: Vec<String>,
        /// Print a JSON summary of the result to stdout.
        #[arg(long)]
        report: bool,
    },
    /// List the stabilizers in a profile, with risk tiers and the set digest.
    Stabilizers {
        #[arg(long, default_value = "tar-gzip")]
        profile: String,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, clap::ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Verify {
            upstream,
            rebuild,
            format,
            profile: prof,
            output,
            explain,
        } => verify(
            &upstream,
            &rebuild,
            format.as_deref(),
            prof.as_deref(),
            output,
            explain,
        ),
        Cmd::Stabilize {
            infile,
            outfile,
            format,
            profile: prof,
            enable_passes,
            disable_passes,
            report,
        } => stabilize_one(
            &infile,
            &outfile,
            format.as_deref(),
            prof.as_deref(),
            &enable_passes,
            &disable_passes,
            report,
        ),
        Cmd::Stabilizers { profile: prof } => stabilizers(&prof),
    }
}

fn verify(
    upstream: &Path,
    rebuild: &Path,
    format: Option<&str>,
    prof: Option<&str>,
    output: OutputFormat,
    explain: bool,
) -> Result<()> {
    let fmt = resolve_format(upstream, format)?;
    let set = match prof {
        Some(p) => profile(p).with_context(|| format!("unknown profile `{p}`"))?,
        None => default_for(fmt),
    };

    let a = std::fs::read(upstream).with_context(|| format!("reading {}", upstream.display()))?;
    let b = std::fs::read(rebuild).with_context(|| format!("reading {}", rebuild.display()))?;

    let c = compare_bytes(a, b, fmt, &set, &Limits::default())?;
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&c)?),
        OutputFormat::Text => print_text(&c, explain),
    }
    // Exit non-zero on divergence so this drops into a pipeline without a wrapper.
    if c.outcome == Match::Divergent {
        std::process::exit(1);
    }
    Ok(())
}

fn stabilize_one(
    infile: &Path,
    outfile: &Path,
    format: Option<&str>,
    prof: Option<&str>,
    enable: &[String],
    disable: &[String],
    report: bool,
) -> Result<()> {
    let fmt = resolve_format(infile, format)?;
    let base = match prof {
        Some(p) => profile(p).with_context(|| format!("unknown profile `{p}`"))?,
        None => default_for(fmt),
    };
    let set = base.filtered(enable, disable);

    let bytes = std::fs::read(infile).with_context(|| format!("reading {}", infile.display()))?;
    let mut notes = Vec::new();
    let mut parsed = trigon_archive::parse(bytes, fmt, &Limits::default(), &mut notes)?;
    let applied = trigon_stabilize::apply(&set, &mut parsed.archive);
    let out = trigon_archive::serialize(&parsed.archive, true)?;
    std::fs::write(outfile, &out).with_context(|| format!("writing {}", outfile.display()))?;

    if report {
        // Machine-readable, so `xtask golden` can group a digest move by the pass that moved it
        // instead of by guesswork.
        let summary = serde_json::json!({
            "stabilized": trigon_core::Digest::from_bytes(
                <[u8; 32]>::from(<sha2::Sha256 as sha2::Digest>::digest(&out))
            ).to_hex(),
            "bytes": out.len(),
            "set": { "id": set.id.as_str(), "digest": set.digest().to_hex() },
            "applied": applied.iter().map(|a| serde_json::json!({
                "id": a.id.as_str(),
                "risk": format!("{:?}", a.risk).to_lowercase(),
                "entries_touched": a.entries_touched,
                "bytes_changed": a.bytes_changed,
            })).collect::<Vec<_>>(),
            "notes": notes.iter().map(|n| format!("{:?}", n.code)).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string(&summary)?);
    } else {
        for a in &applied {
            eprintln!("applied {} ({} entries)", a.id, a.entries_touched);
        }
    }
    Ok(())
}

fn resolve_format(path: &Path, explicit: Option<&str>) -> Result<Format> {
    if let Some(s) = explicit {
        return match s {
            "tar+gzip" | "tar.gz" | "tgz" => Ok(Format::TarGz),
            "tar" => Ok(Format::Tar),
            "zip" => Ok(Format::Zip),
            "gzip" | "gz" => Ok(Format::Gzip),
            "raw" => Ok(Format::Raw),
            other => bail!("unknown format `{other}`"),
        };
    }
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    Format::from_file_name(&name).with_context(|| {
        format!(
            "cannot infer a format from `{name}`; pass --format. A .gem is a tar, and only the \
                 ecosystem knows that from the name alone."
        )
    })
}

fn print_text(c: &Comparison, explain: bool) {
    let mark = match c.outcome {
        Match::Exact | Match::Normalized => "✔",
        Match::NormalizedWithCaveats => "◐",
        Match::Divergent => "✖",
    };
    println!("{mark} {}", c.outcome);
    println!();
    println!("  format         {}", c.upstream.format);
    println!(
        "  stabilizer set {} ({})",
        c.upstream.set.0,
        short(&c.upstream.set.1.to_hex())
    );
    println!();
    println!("  {:<12} {:<18} {:<18}", "", "upstream", "rebuild");
    row(
        "raw",
        &c.upstream.raw.sha256.to_hex(),
        &c.rebuild.raw.sha256.to_hex(),
    );
    if let (Some(u), Some(r)) = (&c.upstream.container, &c.rebuild.container) {
        row("container", &u.sha256.to_hex(), &r.sha256.to_hex());
    }
    row(
        "stabilized",
        &c.upstream.stabilized.sha256.to_hex(),
        &c.rebuild.stabilized.sha256.to_hex(),
    );

    if let Some(false) = c.container_bit_identical() {
        println!();
        println!("  containers differ as well as the framing");
    } else if c.container_bit_identical() == Some(true) && c.outcome != Match::Exact {
        println!();
        println!("  same container, different outer framing");
    }

    let applied = c.applied();
    if !applied.is_empty() {
        println!();
        println!("  applied");
        let mut seen: Vec<String> = Vec::new();
        for a in applied {
            let key = a.id.to_string();
            if seen.contains(&key) {
                continue;
            }
            seen.push(key);
            println!(
                "    {:<24} {:<10} {:>6} entries",
                a.id.as_str(),
                format!("{:?}", a.risk).to_lowercase(),
                a.entries_touched
            );
        }
    }

    if let Some(reason) = c.cap_reason() {
        println!();
        println!("  capped below `normalized`: {reason}");
    }

    let notes: Vec<_> = c
        .upstream
        .notes
        .iter()
        .chain(&c.rebuild.notes)
        .filter(|n| n.code.is_noteworthy())
        .collect();
    if !notes.is_empty() {
        println!();
        println!("  notes");
        for n in notes {
            let at = n.path.as_ref().map(|p| format!(" {p}")).unwrap_or_default();
            println!("    {:?}{at}: {}", n.code, n.detail);
        }
    }

    if let Some(d) = &c.diff {
        println!();
        println!(
            "  members  {} identical, {} differ, {} upstream-only, {} rebuild-only",
            d.identical, d.differs, d.only_upstream, d.only_rebuild
        );
        if d.executable_differs > 0 {
            println!(
                "  {} executable member(s) differ, which is never benign",
                d.executable_differs
            );
        }
        let interesting: Vec<_> = d
            .files
            .iter()
            .filter(|f| f.status != trigon_compare::FileStatus::Identical)
            .collect();
        let limit = if explain {
            interesting.len()
        } else {
            10.min(interesting.len())
        };
        for f in &interesting[..limit] {
            println!(
                "    {:<16} {}",
                format!("{:?}", f.status).to_lowercase(),
                f.path
            );
        }
        if interesting.len() > limit {
            println!("    … {} more, pass --explain", interesting.len() - limit);
        }
    }
}

fn row(label: &str, a: &str, b: &str) {
    let same = a == b;
    println!(
        "  {:<12} {:<18} {:<18} {}",
        label,
        short(a),
        short(b),
        if same { "=" } else { "≠" }
    );
}

fn short(hex: &str) -> String {
    format!("{}…", &hex[..hex.len().min(12)])
}

fn stabilizers(prof: &str) -> Result<()> {
    let set = profile(prof).with_context(|| {
        format!(
            "unknown profile `{prof}`; known: {}",
            trigon_stabilize::all_profiles().join(", ")
        )
    })?;
    println!("{} ({})", set.id, set.digest());
    println!();
    for m in &set.members {
        println!(
            "  {:<24} {:<11} {:<9} {:?}",
            m.id().as_str(),
            format!("{:?}", m.risk()).to_lowercase(),
            format!("{:?}", m.stage()).to_lowercase(),
            m.provenance()
        );
    }
    Ok(())
}
