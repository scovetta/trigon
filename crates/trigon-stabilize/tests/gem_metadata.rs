//! The three gemspec fields that carry build noise, and the one we decline to touch.

use trigon_archive::{Body, Limits, parse, serialize};
use trigon_core::{Format, Note, RiskTier};
use trigon_stabilize::{apply, profile};

const SPEC: &str = "\
--- !ruby/object:Gem::Specification
name: rake
version: !ruby/object:Gem::Version
  version: 13.2.1
authors:
- Jim Weirich
date: 2024-03-15 00:00:00.000000000 Z
cert_chain:
- |
  -----BEGIN CERTIFICATE-----
  MIIDxjCCAq6gAwIBAgIBATANBgkq
  -----END CERTIFICATE-----
- |
  -----BEGIN CERTIFICATE-----
  AnotherCertificateEntirely==
  -----END CERTIFICATE-----
description: Rake is a Make-like program
rubygems_version: 3.5.6
summary: Rake is a Make-like program implemented in Ruby
";

/// A gem: an outer tar whose `metadata.gz` holds the gemspec.
fn gem(spec: &str, rubygems_version: &str) -> Vec<u8> {
    let spec = spec.replace("3.5.6", rubygems_version);
    let mut meta_gz = Vec::new();
    trigon_archive::gzip::write(
        &trigon_archive::GzipHeader::default(),
        spec.as_bytes(),
        flate2::Compression::default(),
        &mut meta_gz,
    )
    .unwrap();

    let mut outer = ::tar::Builder::new(Vec::new());
    let mut h = ::tar::Header::new_ustar();
    h.set_size(meta_gz.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    outer.append_data(&mut h, "metadata.gz", &meta_gz[..]).unwrap();
    outer.into_inner().unwrap()
}

fn stabilized_spec(bytes: Vec<u8>) -> String {
    let mut notes: Vec<Note> = Vec::new();
    let mut p = parse(bytes, Format::Tar, &Limits::default(), &mut notes).unwrap();
    apply(&profile("gem").unwrap(), &mut p.archive);
    let meta = p.archive.entries.iter().find(|e| e.path.to_lossy() == "metadata.gz").unwrap();
    let Body::Nested(inner) = &meta.body else { panic!("metadata.gz should be nested") };
    String::from_utf8_lossy(&inner.entries[0].body_bytes().unwrap()).into_owned()
}

#[test]
fn the_build_date_is_replaced_with_the_reference_value() {
    let out = stabilized_spec(gem(SPEC, "3.5.6"));
    assert!(out.contains("date: 1980-01-02 00:00:00.000000000 Z"), "{out}");
    assert!(!out.contains("2024-03-15"));
}

#[test]
fn the_packaging_tool_version_is_replaced() {
    let out = stabilized_spec(gem(SPEC, "3.5.6"));
    assert!(out.contains("rubygems_version: 0.0.0"), "{out}");
}

#[test]
fn the_certificate_chain_becomes_empty() {
    let out = stabilized_spec(gem(SPEC, "3.5.6"));
    assert!(out.contains("cert_chain: []"), "{out}");
    assert!(!out.contains("BEGIN CERTIFICATE"), "the chain body must go too:\n{out}");
    // The block ends where the indented lines end, so what follows must survive intact.
    assert!(out.contains("description: Rake is a Make-like program"), "{out}");
}

#[test]
fn the_surrounding_document_is_left_alone() {
    // The deviation we defend: we change the fields we name and reformat nothing. The reference
    // round-trips the whole gemspec through a YAML serializer, which re-indents every list.
    let out = stabilized_spec(gem(SPEC, "3.5.6"));
    assert!(out.starts_with("--- !ruby/object:Gem::Specification"), "document marker kept:\n{out}");
    assert!(out.contains("\n- Jim Weirich\n"), "list indentation kept as authored:\n{out}");

    // The property, rather than an arithmetic guess about it: every line outside the cert block
    // survives verbatim and in order, with only `date` and `rubygems_version` substituted.
    // The block is found by position, not by prefix: `--- !ruby/...` also starts with a dash, and
    // an indented field also starts with a space.
    let lines: Vec<&str> = SPEC.lines().collect();
    let start = lines.iter().position(|l| l.starts_with("cert_chain:")).unwrap();
    let mut end = start + 1;
    while end < lines.len() && lines[end].starts_with([' ', '-']) {
        end += 1;
    }
    let kept: Vec<String> = lines[..start]
        .iter()
        .chain(&lines[end..])
        .map(|l| {
            if l.starts_with("date:") {
                "date: 1980-01-02 00:00:00.000000000 Z".to_string()
            } else if l.starts_with("rubygems_version:") {
                "rubygems_version: 0.0.0".to_string()
            } else {
                l.to_string()
            }
        })
        .collect();
    let got: Vec<String> =
        out.lines().filter(|l| *l != "cert_chain: []").map(str::to_string).collect();
    assert_eq!(got, kept, "a line outside the cert block changed");
}

#[test]
fn two_gems_packaged_by_different_rubygems_versions_agree() {
    let a = gem(SPEC, "3.5.6");
    let b = gem(SPEC, "3.6.9");

    let out = |bytes: Vec<u8>| {
        let mut notes: Vec<Note> = Vec::new();
        let mut p = parse(bytes, Format::Tar, &Limits::default(), &mut notes).unwrap();
        apply(&profile("gem").unwrap(), &mut p.archive);
        serialize(&p.archive, true).unwrap()
    };
    assert_eq!(out(a), out(b), "the packaging tool version must stabilize away");
}

#[test]
fn the_gem_profile_still_reaches_the_clean_tier() {
    // The tier is about what is normalized, not where it is stored. A gemspec `date` is a build
    // timestamp that happens to live inside a file, so it is Metadata like any other timestamp.
    let set = profile("gem").unwrap();
    let worst = set.members.iter().map(|m| m.risk()).max().unwrap();
    assert!(worst <= RiskTier::Metadata, "a {worst:?} pass would deny every gem a clean tier");
}

#[test]
fn a_spec_with_nothing_to_change_is_left_untouched() {
    let already = SPEC
        .replace("date: 2024-03-15 00:00:00.000000000 Z", "date: 1980-01-02 00:00:00.000000000 Z")
        .replace("rubygems_version: 3.5.6", "rubygems_version: 0.0.0");
    let mut notes: Vec<Note> = Vec::new();
    let mut p = parse(gem(&already, "0.0.0"), Format::Tar, &Limits::default(), &mut notes).unwrap();
    let applied = apply(&profile("gem").unwrap(), &mut p.archive);
    let ids: Vec<&str> = applied.iter().map(|a| a.id.as_str()).collect();
    assert!(!ids.contains(&"gem-metadata-date"), "a no-op pass must stay out of applied: {ids:?}");
    assert!(!ids.contains(&"gem-metadata-rubygems-version"), "{ids:?}");
    // The cert chain is still there, so that one does fire.
    assert!(ids.contains(&"gem-metadata-cert-chain"), "{ids:?}");
}
