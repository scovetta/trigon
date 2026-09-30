//! Every pass that edits a member as text leaves one that is not valid UTF-8 exactly as it is.
//!
//! The seven decoded lossily before their `-v2` ids: each invalid sequence became U+FFFD, and a
//! pass that went on to rewrite the member wrote the replacement back. Two members that differed
//! only in an invalid byte then stabilized to the same bytes. Two gems whose gemspecs differed in
//! one byte, 0xFF against 0xFE, verified as a clean `normalized` (`docs/16-findings.md` §3.106).
//!
//! Each case is a member the pass rewrites when its text is valid, so the pass is shown to reach
//! it; then the same member with 0xFF and with 0xFE in place of one character, which must neither
//! be rewritten nor come out alike.

use std::io::Write as _;

use trigon_archive::{Limits, parse, serialize};
use trigon_core::{Format, Note};
use trigon_stabilize::{Applied, apply, profile};

fn tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = ::tar::Builder::new(Vec::new());
    for (name, body) in entries {
        let mut h = ::tar::Header::new_ustar();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, name, *body).unwrap();
    }
    b.into_inner().unwrap()
}

fn gzip(body: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(body).unwrap();
    e.finish().unwrap()
}

fn zip(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = zip_crate::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts: zip_crate::write::FileOptions<'_, ()> = zip_crate::write::FileOptions::default()
        .compression_method(zip_crate::CompressionMethod::Stored);
    for (name, body) in members {
        w.start_file(*name, opts).unwrap();
        w.write_all(body).unwrap();
    }
    w.finish().unwrap().into_inner()
}

/// One text pass, and an artifact that holds a member it rewrites, with `byte` in place of one
/// character of the member's text.
struct Case {
    profile: &'static str,
    pass: &'static str,
    format: Format,
    artifact: fn(u8) -> Vec<u8>,
}

/// `text`, with its one `@` replaced by `byte`.
fn with(text: &str, byte: u8) -> Vec<u8> {
    let at = text.find('@').expect("a place for the byte");
    let mut v = text.as_bytes().to_vec();
    v[at] = byte;
    v
}

const GEMSPEC: &str = "--- !ruby/object:Gem::Specification\nname: x\n\
                       date: 2024-03-15 00:00:00.000000000 Z\ncert_chain:\n- |\n  a certificate\n\
                       rubygems_version: 3.5.6\nsummary: a@b\n";

fn gem(byte: u8) -> Vec<u8> {
    tar(&[("metadata.gz", &gzip(&with(GEMSPEC, byte)))])
}

const CASES: &[Case] = &[
    Case {
        profile: "crate",
        pass: "cargo-vcs-hash-v2",
        format: Format::TarGz,
        artifact: |byte| {
            let vcs = with(
                r#"{"git":{"sha1":"0123456789abcdef0123456789abcdef01234567"},"path_in_vcs":"a@"}"#,
                byte,
            );
            gzip(&tar(&[("x-1.0.0/.cargo_vcs_info.json", &vcs)]))
        },
    },
    Case {
        profile: "npm-tarball",
        pass: "npm-install-fields-v2",
        format: Format::TarGz,
        artifact: |byte| {
            let json = with(
                "{\n  \"name\": \"x@\",\n  \"_resolved\": \"https://registry/x.tgz\"\n}\n",
                byte,
            );
            gzip(&tar(&[("package/package.json", &json)]))
        },
    },
    Case {
        profile: "gem",
        pass: "gem-metadata-date-v2",
        format: Format::Tar,
        artifact: gem,
    },
    Case {
        profile: "gem",
        pass: "gem-metadata-rubygems-version-v2",
        format: Format::Tar,
        artifact: gem,
    },
    Case {
        profile: "gem",
        pass: "gem-metadata-cert-chain-v2",
        format: Format::Tar,
        artifact: gem,
    },
    Case {
        profile: "nupkg",
        pass: "nupkg-repository-branch-v2",
        format: Format::Zip,
        artifact: |byte| {
            let nuspec = with(
                "<package><metadata><description>a@b</description>\
                 <repository type=\"git\" branch=\"v1.0\" commit=\"abc\" /></metadata></package>",
                byte,
            );
            zip(&[("x.nuspec", &nuspec)])
        },
    },
    Case {
        profile: "nupkg",
        pass: "nupkg-readme-markers-v2",
        format: Format::Zip,
        artifact: |byte| {
            let readme = with("# x\n<!-- include docs/intro.md -->\nSee a@b.\n", byte);
            zip(&[("README.md", &readme)])
        },
    },
];

/// The case's artifact with `byte`, stabilized by its pass alone.
fn stabilized(case: &Case, byte: u8) -> (Vec<u8>, Vec<Applied>) {
    let set = profile(case.profile)
        .unwrap()
        .filtered(&[case.pass.to_string()], &[]);
    assert_eq!(
        set.members.len(),
        1,
        "no `{}` in `{}`",
        case.pass,
        case.profile
    );
    let mut notes: Vec<Note> = Vec::new();
    let mut p = parse(
        (case.artifact)(byte),
        case.format,
        &Limits::default(),
        &mut notes,
    )
    .unwrap();
    let applied = apply(&set, &mut p.archive);
    (serialize(&p.archive, true).unwrap(), applied)
}

#[test]
fn every_text_pass_is_one_the_registry_has() {
    // A case for a pass that was renamed again would pass here by running nothing.
    let every: Vec<String> = trigon_stabilize::all_builtin()
        .iter()
        .map(|s| s.id().to_string())
        .collect();
    for case in CASES {
        assert!(every.iter().any(|id| id == case.pass), "{}", case.pass);
    }
}

#[test]
fn each_text_pass_rewrites_the_member_when_its_text_is_valid() {
    // Without this the cases below would prove the fixture, not the pass.
    for case in CASES {
        let (_, applied) = stabilized(case, b'@');
        assert!(
            applied.iter().any(|a| a.id.as_str() == case.pass),
            "`{}` did not rewrite its fixture: {applied:?}",
            case.pass
        );
    }
}

#[test]
fn members_differing_only_in_an_invalid_byte_do_not_match() {
    for case in CASES {
        let (ff, applied) = stabilized(case, 0xff);
        let (fe, _) = stabilized(case, 0xfe);
        assert!(
            ff != fe,
            "`{}`: two members differing in one invalid byte stabilized alike",
            case.pass
        );
        assert!(
            applied.is_empty(),
            "`{}` rewrote a member that is not valid UTF-8: {applied:?}",
            case.pass
        );
    }
}

#[test]
fn a_member_that_is_not_valid_utf8_is_left_exactly_as_it_is() {
    // Not a pass that rewrote the rest and kept the invalid byte: nothing is touched.
    for case in CASES {
        let (out, _) = stabilized(case, 0xff);
        let artifact = (case.artifact)(0xff);
        let mut notes: Vec<Note> = Vec::new();
        let set = profile(case.profile)
            .unwrap()
            .filtered(&["none".to_string()], &[]);
        let mut p = parse(artifact, case.format, &Limits::default(), &mut notes).unwrap();
        apply(&set, &mut p.archive);
        assert!(
            out == serialize(&p.archive, true).unwrap(),
            "`{}` changed a member it could not read as text",
            case.pass
        );
    }
}
