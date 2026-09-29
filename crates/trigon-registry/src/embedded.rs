//! Where the artifact itself says its source is.
//!
//! [`crate::wheel`] reads a published wheel for the *toolchain* that made it. This reads a published
//! artifact for the **repository and commit** it was built from, which two of the four ecosystems
//! record inside the package and none of them record in their API.
//!
//! That makes it the strongest source-discovery rung available for either one, and for NuGet it is
//! close to the only one. Measured over twelve popular packages, **three** declare a forge in
//! `projectUrl`; the rest point at a documentation site. Resolving NuGet from registry metadata
//! alone would decline three targets in four, and the `.nuspec` sitting inside the package has been
//! carrying `<repository url commit>` the whole time.
//!
//! It is not an inference. The publishing tool wrote the field during the build being reproduced,
//! which is why both arms below report `SourceDiscovery::PublishedProvenance` rather than a guess
//! — the same tier as npm's `gitHead` and a trusted-publishing attestation.

use trigon_core::{Format, SourceDiscovery, SourceProvenance};

/// The repository and commit a `.nupkg` records in its `.nuspec`.
///
/// `<repository type="git" url="…" commit="…"/>` is written by `dotnet pack` from the project's own
/// SourceLink configuration. A package built without SourceLink has the element with a `url` and no
/// `commit`, or no element at all, and both are ordinary.
pub fn nupkg_source(bytes: &[u8]) -> Option<SourceProvenance> {
    let mut notes = Vec::new();
    let parsed = trigon_archive::parse(
        bytes.to_vec(),
        Format::Zip,
        &trigon_archive::Limits::default(),
        &mut notes,
    )
    .ok()?;
    // At the archive root, and exactly one — a `.nuspec` deeper in the tree belongs to something
    // the package vendored rather than to the package.
    let entry = parsed.archive.entries.iter().find(|e| {
        let p = e.path.to_string();
        p.ends_with(".nuspec") && !p.contains('/')
    })?;
    let body = entry.body_bytes().ok()?;
    parse_nuspec_repository(std::str::from_utf8(&body).ok()?)
}

/// `<repository …/>` out of a `.nuspec`, without an XML parser.
///
/// The element is a single self-closing tag with attributes in no guaranteed order, so this reads
/// the attributes rather than the shape. A real parser would be better and is not worth a
/// dependency in the judgement half's neighbourhood for one element — but it does mean a `url`
/// containing `"` or a comment containing `<repository` would fool it, which is why everything it
/// returns still has to look like a repository URL.
fn parse_nuspec_repository(xml: &str) -> Option<SourceProvenance> {
    let start = xml.find("<repository")?;
    let rest = &xml[start..];
    let end = rest.find('>')?;
    let tag = &rest[..end];

    let attr = |name: &str| -> Option<String> {
        let at = tag.find(&format!("{name}=\""))?;
        let after = &tag[at + name.len() + 2..];
        let close = after.find('"')?;
        Some(after[..close].trim().to_string())
    };

    let url = attr("url").filter(|u| u.starts_with("http"))?;
    let commit = attr("commit")
        .filter(|c| c.len() == 40 && c.chars().all(|ch| ch.is_ascii_hexdigit()))
        .unwrap_or_default();
    let repo_url = crate::npm::canonicalize_repo(&url);
    Some(SourceProvenance {
        declared_url: (url != repo_url).then_some(url),
        // A commit the publishing tool recorded is exact; a bare repository still needs the tag
        // ladder, and saying which is the difference between a verdict a reader can weigh and one
        // they cannot.
        how: match commit.is_empty() {
            true => SourceDiscovery::RegistryMetadata,
            false => SourceDiscovery::PublishedProvenance,
        },
        repo_url,
        commit,
        ref_name: attr("branch").filter(|b| !b.is_empty()),
        subdir: None,
    })
}

/// The commit a `.crate` records in `.cargo_vcs_info.json`.
///
/// `cargo package` writes it when the package is inside a git checkout and leaves it out when it is
/// not, so its absence means "packaged from no tree", which is worth knowing and is not an error.
/// A checkout with uncommitted changes still gets the file, with `"dirty": true` beside the commit
/// (older Cargo left the file out instead). What that flag should mean here is not settled, and
/// until it is this reads `sha1` without looking at it. The file gives no repository URL, only the
/// commit, so this returns the commit for a caller that already has a repository from the API.
pub fn crate_commit(bytes: &[u8]) -> Option<String> {
    let mut notes = Vec::new();
    let parsed = trigon_archive::parse(
        bytes.to_vec(),
        Format::TarGz,
        &trigon_archive::Limits::default(),
        &mut notes,
    )
    .ok()?;
    // `<name>-<version>/.cargo_vcs_info.json`: one directory down, and the directory is the
    // package rather than something inside it. A crate that vendors another carries that crate's
    // file deeper in the tree, and its commit is somebody else's.
    let entry = parsed.archive.entries.iter().find(|e| {
        let p = e.path.to_string();
        p.ends_with("/.cargo_vcs_info.json") && p.matches('/').count() == 1
    })?;
    let body = entry.body_bytes().ok()?;
    let doc: serde_json::Value = serde_json::from_slice(&body).ok()?;
    let sha = doc.get("git")?.get("sha1")?.as_str()?;
    (sha.len() == 40 && sha.chars().all(|c| c.is_ascii_hexdigit())).then(|| sha.to_string())
}

#[cfg(test)]
mod tests {
    use super::{SourceDiscovery, parse_nuspec_repository};

    const WITH_COMMIT: &str = r#"<?xml version="1.0"?>
<package><metadata>
  <id>Polly</id>
  <repository type="git" url="https://github.com/App-vNext/Polly" commit="a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4" />
</metadata></package>"#;

    #[test]
    fn a_nuspec_with_a_commit_is_published_provenance() {
        // The strongest source statement any of the four ecosystems makes, and it is sitting inside
        // the package rather than in the API. `dotnet pack` writes it from SourceLink during the
        // build being reproduced.
        let s = parse_nuspec_repository(WITH_COMMIT).expect("a repository element");
        assert_eq!(s.repo_url, "https://github.com/App-vNext/Polly");
        assert_eq!(s.commit, "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4");
        assert_eq!(s.how, SourceDiscovery::PublishedProvenance);
    }

    #[test]
    fn a_repository_without_a_commit_still_needs_the_tag_ladder() {
        // A package built without SourceLink. Saying so is the difference between a verdict a
        // reader can weigh and one they cannot: `RegistryMetadata` means something still has to
        // find the commit.
        let xml = WITH_COMMIT.replace(r#" commit="a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4""#, "");
        let s = parse_nuspec_repository(&xml).expect("a repository element");
        assert!(s.commit.is_empty());
        assert_eq!(s.how, SourceDiscovery::RegistryMetadata);
    }

    #[test]
    fn attributes_are_read_by_name_rather_than_by_position() {
        // No order is guaranteed, and `type` sits before `url` about as often as after it.
        let xml = r#"<repository commit="0000000000000000000000000000000000000000"
            url="https://github.com/a/b" type="git" branch="main"/>"#;
        let s = parse_nuspec_repository(xml).expect("a repository element");
        assert_eq!(s.repo_url, "https://github.com/a/b");
        assert_eq!(s.ref_name.as_deref(), Some("main"));
    }

    #[test]
    fn nothing_that_is_not_a_repository_is_read_as_one() {
        for xml in [
            "<package><metadata><id>X</id></metadata></package>", // no element
            r#"<repository type="git" commit="abc"/>"#,           // no url
            r#"<repository type="git" url="not-a-url"/>"#,        // not a URL
            // A commit that is not a commit. A short or non-hex value is a field somebody filled in
            // by hand, and carrying it would send `git checkout` after something that does not
            // exist.
            r#"<repository url="https://github.com/a/b" commit="HEAD"/>"#,
        ] {
            match parse_nuspec_repository(xml) {
                None => {}
                Some(s) => assert!(s.commit.is_empty(), "{xml} -> {s:?}"),
            }
        }
    }
}
