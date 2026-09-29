//! Filtering a PyPI simple index to a moment.
//!
//! The upstream request is always for the **JSON** simple API, whatever the client asked for. The
//! HTML form carries no upload times at all, so it cannot be filtered by date: a mirror that
//! proxied HTML would pass every file through and quietly do nothing. Where the client wanted HTML
//! it is rendered back from the filtered JSON.

use serde_json::Value;

use crate::moment::published_by;

/// Filter a simple-API document in place. Returns how many files were removed.
pub fn filter_simple(doc: &mut Value, moment: &str) -> usize {
    let Some(files) = doc.get_mut("files").and_then(Value::as_array_mut) else {
        return 0;
    };
    let before = files.len();
    files.retain(|f| {
        // `upload-time` is the simple API's spelling; the JSON project API uses
        // `upload_time_iso_8601`. A file with neither cannot be dated and is excluded.
        match f
            .get("upload-time")
            .or_else(|| f.get("upload_time_iso_8601"))
            .and_then(Value::as_str)
        {
            Some(ts) => published_by(ts, moment),
            None => false,
        }
    });
    before - files.len()
}

/// Drop every file belonging to the one version this run is rebuilding.
///
/// Returns how many files were removed, and zero whenever this index is for another project.
///
/// **Why the index and not the download.** The guard refuses the target's own artifact URL, which
/// is the control that defeats the forged-attestation attack. But a resolver that has been told a
/// version exists and is then denied the file does not look for another one: it fails, and the
/// build dies. That is what happened to every package that is part of the machinery that builds
/// packages — `python -m build` needs `packaging` and `pyproject-hooks`, so rebuilding either made
/// pip ask for the target and hit the wall.
///
/// A version that was never offered is a different thing entirely. `packaging>=24.0` resolves to
/// `24.2` and installs, because `25.0` is simply not in the index. The target's bytes still never
/// cross — nothing about the refusal changes — but the resolver routes around the hole instead of
/// dying in it.
///
/// Counted separately from the moment filter on purpose. `versions_withheld` is the evidence that
/// the registry pin applied, and folding a policy removal into it would make an index where only
/// the target was dropped report `withheld=1` and read as the pin doing work it did not do.
pub fn withhold_version(doc: &mut Value, w: &crate::Withheld) -> usize {
    // Only this project's index. The `name` field is the simple API's own statement of what it is
    // about; an index without one is left alone rather than filtered on a filename guess.
    let named = doc
        .get("name")
        .and_then(Value::as_str)
        .is_some_and(|n| normalized(n) == normalized(&w.project));
    if !named {
        return 0;
    }

    // Both places a version can appear. `files` is what a resolver installs from; `versions` is the
    // 1.1 listing, and leaving the target in it offers a version with no files behind it.
    if let Some(versions) = doc.get_mut("versions").and_then(Value::as_array_mut) {
        versions.retain(|v| v.as_str() != Some(w.version.as_str()));
    }
    let Some(files) = doc.get_mut("files").and_then(Value::as_array_mut) else {
        return 0;
    };
    let before = files.len();
    files.retain(|f| match f.get("filename").and_then(Value::as_str) {
        Some(name) => !is_version_of(name, &w.project, &w.version),
        None => true,
    });
    before - files.len()
}

/// Whether a distribution filename names this project at this version.
///
/// Two shapes, because sdists and wheels spell the same thing differently. A wheel is
/// `{name}-{version}-{python}-{abi}-{platform}.whl` with the version always second, so it is read
/// positionally. An sdist is `{name}-{version}.tar.gz` and the name may itself contain a `-`, so
/// the version is matched as a *suffix* and whatever precedes it has to normalize to the project.
/// Matching the known version rather than parsing the name out sidesteps the boundary entirely.
///
/// Conservative where it is unsure: a filename that does not clearly name this version is kept.
/// The cost of keeping one is that the build asks for the artifact and the guard refuses it, which
/// is the behaviour that already exists; the cost of dropping one wrongly is a version silently
/// missing from an index we claim reflects the registry.
fn is_version_of(filename: &str, project: &str, version: &str) -> bool {
    const EXTENSIONS: &[&str] = &[
        ".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip", ".whl", ".egg",
    ];
    let wheel = filename.ends_with(".whl") || filename.ends_with(".egg");
    let Some(stem) = EXTENSIONS.iter().find_map(|e| filename.strip_suffix(e)) else {
        return false;
    };

    if wheel {
        let mut parts = stem.split('-');
        return match (parts.next(), parts.next()) {
            (Some(n), Some(v)) => normalized(n) == normalized(project) && v == version,
            _ => false,
        };
    }
    match stem.strip_suffix(&format!("-{version}")) {
        Some(name) => normalized(name) == normalized(project),
        None => false,
    }
}

/// A project name in PEP 503 normalized form: runs of `-`, `_` and `.` become one `-`, lowercased.
///
/// Both sides of every comparison go through this, because a project is spelled one way in a purl,
/// another in its own index, and a third in the filenames it publishes — `pyproject-hooks`,
/// `pyproject_hooks`.
fn normalized(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_was_separator = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !last_was_separator {
                out.push('-');
            }
            last_was_separator = true;
        } else {
            out.extend(c.to_lowercase());
            last_was_separator = false;
        }
    }
    out
}

/// Render a filtered simple-API document as PEP 503 HTML.
///
/// For clients that asked for HTML. Only the anchor list matters to a resolver: the filename is
/// its text and the hash rides in the fragment.
pub fn render_html(doc: &Value, project: &str) -> String {
    let mut out = String::from("<!DOCTYPE html><html><head><meta charset=\"utf-8\">");
    out.push_str(&format!("<title>Links for {project}</title></head><body>"));
    out.push_str(&format!("<h1>Links for {project}</h1>"));
    for f in doc
        .get("files")
        .and_then(Value::as_array)
        .unwrap_or(&vec![])
    {
        let (Some(name), Some(url)) = (
            f.get("filename").and_then(Value::as_str),
            f.get("url").and_then(Value::as_str),
        ) else {
            continue;
        };
        let hash = f
            .get("hashes")
            .and_then(|h| h.get("sha256"))
            .and_then(Value::as_str)
            .map(|h| format!("#sha256={h}"))
            .unwrap_or_default();
        let requires = f
            .get("requires-python")
            .and_then(Value::as_str)
            .map(|r| format!(" data-requires-python=\"{}\"", escape(r)))
            .unwrap_or_default();
        out.push_str(&format!(
            "<a href=\"{}{hash}\"{requires}>{}</a><br/>",
            escape(url),
            escape(name)
        ));
    }
    out.push_str("</body></html>");
    out
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn simple() -> Value {
        serde_json::json!({
            "name": "demo",
            "files": [
                {"filename": "demo-1.0.tar.gz", "url": "https://files/demo-1.0.tar.gz",
                 "upload-time": "2018-01-01T00:00:00.000000Z",
                 "hashes": {"sha256": "aaa"}},
                {"filename": "demo-2.0-py3-none-any.whl", "url": "https://files/demo-2.0.whl",
                 "upload-time": "2020-06-01T12:00:00.000000Z",
                 "hashes": {"sha256": "bbb"}}
            ],
            "meta": {"api-version": "1.0"}
        })
    }

    /// A real project whose name, index and filenames each spell it differently.
    fn hooks() -> Value {
        serde_json::json!({
            "name": "pyproject_hooks",
            "versions": ["1.1.0", "1.2.0"],
            "files": [
                {"filename": "pyproject_hooks-1.1.0.tar.gz", "upload-time": "2024-04-01T00:00:00Z"},
                {"filename": "pyproject_hooks-1.1.0-py3-none-any.whl", "upload-time": "2024-04-01T00:00:00Z"},
                {"filename": "pyproject_hooks-1.2.0.tar.gz", "upload-time": "2024-10-01T00:00:00Z"},
                {"filename": "pyproject_hooks-1.2.0-py3-none-any.whl", "upload-time": "2024-10-01T00:00:00Z"}
            ]
        })
    }

    #[test]
    fn every_file_of_the_version_under_test_is_withheld() {
        // The bug this closes. `python -m build` needs `pyproject-hooks`, so rebuilding it made pip
        // ask for the target and the guard refused the download. A resolver denied a file it was
        // told exists does not pick another one — it fails.
        let mut d = hooks();
        let w = crate::Withheld {
            project: "pyproject-hooks".into(),
            version: "1.2.0".into(),
        };
        assert_eq!(withhold_version(&mut d, &w), 2, "the sdist and the wheel");
        let files = d["files"].as_array().unwrap();
        assert_eq!(files.len(), 2);
        assert!(
            files
                .iter()
                .all(|f| f["filename"].as_str().unwrap().contains("1.1.0"))
        );
        assert_eq!(
            d["versions"].as_array().unwrap(),
            &vec![Value::String("1.1.0".into())],
            "the 1.1 listing too, or the index offers a version with no files behind it"
        );
    }

    #[test]
    fn the_project_name_is_matched_in_normalized_form() {
        // `pyproject-hooks` in a purl, `pyproject_hooks` in its own index and in every filename it
        // publishes. Three spellings of one project, and a literal comparison matches none of them.
        assert!(is_version_of(
            "pyproject_hooks-1.2.0.tar.gz",
            "pyproject-hooks",
            "1.2.0"
        ));
        assert!(is_version_of(
            "zope.interface-5.4.0-cp39-cp39-linux_x86_64.whl",
            "zope-interface",
            "5.4.0"
        ));
    }

    #[test]
    fn a_name_that_contains_the_version_string_is_not_a_match() {
        // The version is matched as a suffix of the stem, not anywhere in the filename, so a
        // project whose name happens to contain the digits is unaffected.
        assert!(!is_version_of("demo-1.0.1.tar.gz", "demo", "1.0"));
        assert!(!is_version_of("demo-1.0-extra.tar.gz", "demo", "1.0"));
    }

    #[test]
    fn a_neighbouring_version_survives() {
        // The whole point: `packaging>=24.0` has to resolve to something. Withholding 25.0 leaves
        // 24.2 in the index, so pip installs that instead of failing.
        assert!(!is_version_of(
            "packaging-24.2-py3-none-any.whl",
            "packaging",
            "25.0"
        ));
    }

    #[test]
    fn another_projects_index_is_left_alone() {
        let mut d = hooks();
        let w = crate::Withheld {
            project: "elsewhere".into(),
            version: "1.2.0".into(),
        };
        assert_eq!(withhold_version(&mut d, &w), 0);
        assert_eq!(d["files"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn an_unrecognised_filename_is_kept() {
        // Conservative in the direction that matters. Keeping one costs a refused download, which
        // is the behaviour that already exists; dropping one wrongly silently removes a release
        // from an index we claim reflects the registry.
        assert!(!is_version_of("demo-1.0.exe", "demo", "1.0"));
        assert!(!is_version_of("demo", "demo", "1.0"));
    }

    #[test]
    fn files_uploaded_later_are_removed() {
        let mut d = simple();
        assert_eq!(filter_simple(&mut d, "2019-01-01T00:00:00"), 1);
        let files = d["files"].as_array().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0]["filename"], "demo-1.0.tar.gz");
    }

    #[test]
    fn a_file_with_no_upload_time_is_excluded() {
        let mut d = simple();
        d["files"].as_array_mut().unwrap().push(serde_json::json!({
            "filename": "demo-3.0.whl", "url": "https://files/demo-3.0.whl"
        }));
        filter_simple(&mut d, "2025-01-01T00:00:00");
        assert!(
            !d["files"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["filename"] == "demo-3.0.whl"),
            "a file we cannot date must not be resolvable"
        );
    }

    #[test]
    fn html_is_rendered_from_the_filtered_json() {
        // The HTML simple API carries no upload times, so it cannot be filtered directly. A mirror
        // that proxied it would pass every file through and quietly do nothing.
        let mut d = simple();
        filter_simple(&mut d, "2019-01-01T00:00:00");
        let html = render_html(&d, "demo");
        assert!(html.contains("demo-1.0.tar.gz"), "{html}");
        assert!(
            !html.contains("demo-2.0"),
            "the filtered file must not reappear: {html}"
        );
        assert!(html.contains("#sha256=aaa"), "{html}");
    }

    #[test]
    fn html_escapes_what_it_interpolates() {
        let d = serde_json::json!({"files": [
            {"filename": "a<b>.whl", "url": "https://x/a?q=1&r=2", "hashes": {}}
        ]});
        let html = render_html(&d, "demo");
        assert!(html.contains("a&lt;b&gt;.whl"), "{html}");
        assert!(html.contains("q=1&amp;r=2"), "{html}");
    }

    #[test]
    fn an_index_with_no_files_removes_nothing_and_still_drops_the_version_listing() {
        // The 1.1 `versions` listing is withheld from as well as `files`: leaving the target there
        // offers a version with no files behind it.
        let mut d = serde_json::json!({ "name": "demo", "versions": ["1.0", "2.0"] });
        assert_eq!(filter_simple(&mut d, "2020-01-01T00:00:00"), 0);
        let w = crate::Withheld {
            project: "demo".into(),
            version: "2.0".into(),
        };
        assert_eq!(withhold_version(&mut d, &w), 0);
        assert_eq!(d["versions"], serde_json::json!(["1.0"]));
    }

    #[test]
    fn a_file_whose_name_is_missing_is_kept_rather_than_guessed_at() {
        let mut d = serde_json::json!({ "name": "demo", "files": [
            { "url": "https://x/unnamed" },
            { "filename": "demo-1.0.tar.gz", "url": "https://x/demo-1.0.tar.gz" },
        ] });
        let w = crate::Withheld {
            project: "demo".into(),
            version: "1.0".into(),
        };
        assert_eq!(withhold_version(&mut d, &w), 1);
        assert_eq!(d["files"].as_array().unwrap().len(), 1);
        assert_eq!(d["files"][0]["url"], "https://x/unnamed");
    }

    #[test]
    fn a_wheel_name_with_no_version_segment_names_no_version() {
        // Conservative where it is unsure: a filename that does not clearly name the version is
        // kept, because dropping one wrongly silently removes a version from the index.
        assert!(!is_version_of("demo.whl", "demo", "1.0"));
        assert!(is_version_of("demo-1.0-py3-none-any.whl", "demo", "1.0"));
    }

    #[test]
    fn a_file_with_no_url_is_not_rendered_as_a_link() {
        let d = serde_json::json!({"files": [
            {"filename": "demo-1.0.tar.gz", "hashes": {"sha256": "aaa"}},
            {"filename": "demo-1.1.tar.gz", "url": "https://x/demo-1.1.tar.gz",
             "requires-python": ">=3.8"}
        ]});
        let html = render_html(&d, "demo");
        assert!(!html.contains("demo-1.0.tar.gz"), "{html}");
        assert!(html.contains("data-requires-python=\"&gt;=3.8\""), "{html}");
    }
}
