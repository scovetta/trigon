//! What a package's manifest promises, and whether its repository contains it.
//!
//! The deterministic half of `needs-build-inference`. A manifest that names `dist/index.js` as its
//! entry point, in a repository with no `dist/`, is a package whose published tarball holds files
//! something built — and `npm pack` is not going to build them.
//!
//! This is the condition that separates the packages worth running a build script for from the
//! ones that would be harmed by it. A package that declares a `build` script *and commits its
//! output* is common, and running its build re-generates files the repository already holds
//! correctly — under whatever versions today's floating ranges resolve to, which is how a rule
//! meant to fix a divergence creates one. Here that package has an empty shortfall and is left
//! exactly as it was.
//!
//! Read from the **repository's** manifest and file list, never from the published artifact. A
//! shortfall computed as "published members minus repository tree" would give the same answer for
//! the target in hand and would be fitting the recipe to the answer key — the reasoning
//! `corpora/m1-npm-smoke.labels.json` rules out for labels, and it applies the same way here.

use std::collections::BTreeSet;

use serde_json::Value;

/// Fields whose string values name a file the package promises to ship.
///
/// `exports` and `bin` are walked rather than read, because both are trees whose leaves are paths.
const ENTRY_FIELDS: &[&str] = &[
    "main", "module", "types", "typings", "unpkg", "jsdelivr", "browser",
];

/// Paths the manifest says exist, that the file list does not account for.
///
/// Empty is the answer for most packages and the one that changes nothing.
pub fn shortfall(manifest: &Value, tracked: &[String]) -> BTreeSet<String> {
    let have: BTreeSet<&str> = tracked.iter().map(String::as_str).collect();
    promised(manifest)
        .into_iter()
        .filter(|p| !resolves(p, &have))
        .collect()
}

/// Every path the manifest names as something it ships.
pub fn promised(manifest: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for field in ENTRY_FIELDS {
        if let Some(v) = manifest.get(field) {
            walk(v, &mut out);
        }
    }
    // `bin` is either a string or a map of name to path; `exports` is a tree of conditions whose
    // leaves are paths. Walking both covers every shape without enumerating the condition names,
    // which are open-ended by design.
    for field in ["bin", "exports"] {
        if let Some(v) = manifest.get(field) {
            walk(v, &mut out);
        }
    }
    out
}

fn walk(v: &Value, out: &mut BTreeSet<String>) {
    match v {
        Value::String(s) => {
            if let Some(p) = clean(s) {
                out.insert(p);
            }
        }
        Value::Array(a) => a.iter().for_each(|v| walk(v, out)),
        Value::Object(o) => o
            .iter()
            // A key beginning with `#` is an internal import, not a file this package ships, and
            // its *value* is still a path — so the value is walked and the key ignored, which is
            // what walking values rather than keys already does.
            .for_each(|(_, v)| walk(v, out)),
        _ => {}
    }
}

/// A manifest string reduced to a repository-relative path, or `None` if it is not one.
fn clean(s: &str) -> Option<String> {
    let s = s.trim().trim_start_matches("./");
    // A subpath pattern names a family rather than a file. `./dist/*` tells us nothing about which
    // file to look for, and treating it as one would report a shortfall for every package that
    // uses the modern `exports` shape.
    if s.is_empty() || s.contains('*') || s.starts_with('#') || s.starts_with('/') {
        return None;
    }
    // Anything that is not plainly a relative path: a URL, a condition name that slipped through,
    // a Windows path. Refusing is the safe direction — a promise we cannot read is not a shortfall.
    if s.contains("..") || s.contains(':') || s.contains('\\') {
        return None;
    }
    Some(s.to_string())
}

/// Whether a promised path is accounted for by the repository's file list.
///
/// npm resolves a bare path through a handful of fallbacks before giving up, so a manifest saying
/// `main: "lib/thing"` is satisfied by `lib/thing.js`. Not applying them would report a shortfall
/// for a package that ships exactly what it promises.
fn resolves(promise: &str, tracked: &BTreeSet<&str>) -> bool {
    if tracked.contains(promise) {
        return true;
    }
    for ext in [".js", ".json", ".node"] {
        if tracked.contains(format!("{promise}{ext}").as_str()) {
            return true;
        }
    }
    for index in ["index.js", "index.json", "index.node"] {
        if tracked.contains(format!("{}/{index}", promise.trim_end_matches('/')).as_str()) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tracked(paths: &[&str]) -> Vec<String> {
        paths.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_package_that_ships_what_it_builds_has_a_shortfall() {
        // escalade 3.2.0's real manifest against its real tree: sources in `src/`, nothing in
        // `dist/` or `sync/`, and `index.d.mts` committed only because `.gitignore`'s `/*.d.ts`
        // glob does not match `.d.mts`.
        let manifest = serde_json::json!({
            "main": "dist/index.js",
            "module": "dist/index.mjs",
            "types": "index.d.ts",
            "exports": {
                ".": [{
                    "import": { "types": "./index.d.mts", "default": "./dist/index.mjs" },
                    "require": { "types": "./index.d.ts", "default": "./dist/index.js" },
                }, "./dist/index.js"],
                "./sync": [{
                    "import": { "types": "./sync/index.d.mts", "default": "./sync/index.mjs" },
                    "require": { "types": "./sync/index.d.ts", "default": "./sync/index.js" },
                }, "./sync/index.js"],
            },
        });
        let repo = tracked(&[
            "build.ts",
            "index.d.mts",
            "package.json",
            "readme.md",
            "src/async.d.mts",
            "src/async.d.ts",
            "src/async.js",
            "src/sync.d.mts",
            "src/sync.d.ts",
            "src/sync.js",
        ]);

        let missing = shortfall(&manifest, &repo);
        assert!(missing.contains("dist/index.js"), "{missing:?}");
        assert!(missing.contains("dist/index.mjs"), "{missing:?}");
        assert!(missing.contains("sync/index.mjs"), "{missing:?}");
        assert!(missing.contains("index.d.ts"), "{missing:?}");
        // Committed, and therefore not missing — the one entry point this repository does hold.
        assert!(!missing.contains("index.d.mts"), "{missing:?}");
    }

    #[test]
    fn a_package_that_commits_its_build_output_has_none() {
        // The case a blanket "run the build script" rule harms: the repository already contains
        // what the manifest promises, byte for byte, and re-generating it under today's floating
        // dependency versions is how a rule meant to fix a divergence creates one.
        let manifest = serde_json::json!({ "main": "dist/axios.js", "types": "index.d.ts" });
        let repo = tracked(&[
            "dist/axios.js",
            "index.d.ts",
            "lib/axios.js",
            "package.json",
        ]);
        assert!(shortfall(&manifest, &repo).is_empty());
    }

    #[test]
    fn npms_own_resolution_fallbacks_are_not_a_shortfall() {
        // `main: "lib/thing"` is satisfied by `lib/thing.js`, and a bare directory by its
        // `index.js`. A rule that missed this would report a shortfall for packages that ship
        // exactly what they promise — which is most of them.
        let repo = tracked(&["lib/thing.js", "other/index.js", "data/x.json"]);
        for main in ["lib/thing", "other", "other/", "data/x"] {
            let manifest = serde_json::json!({ "main": main });
            assert!(
                shortfall(&manifest, &repo).is_empty(),
                "`{main}` should resolve"
            );
        }
    }

    #[test]
    fn a_pattern_names_a_family_and_is_not_a_promise() {
        // `./dist/*` says nothing about which file to look for. Reading it as a path would report
        // a shortfall for every package using the modern `exports` shape.
        let manifest = serde_json::json!({
            "exports": { "./*": "./dist/*.js", ".": "./index.js" },
            "imports": { "#internal": "./src/internal.js" },
        });
        let missing = shortfall(&manifest, &tracked(&["index.js"]));
        assert!(missing.is_empty(), "{missing:?}");

        // And `imports` is not read at all: it names what the package resolves for itself, not
        // what it ships.
        assert!(!promised(&manifest).iter().any(|p| p.contains("internal")));
    }

    #[test]
    fn anything_that_is_not_plainly_a_relative_path_is_ignored() {
        // A promise we cannot read is not a shortfall. Refusing is the safe direction: the cost is
        // a package left on the plain recipe, and the alternative cost is a build run on a guess.
        let manifest = serde_json::json!({
            "browser": "https://cdn.example/x.js",
            "main": "../outside/x.js",
            "module": "/abs/x.js",
            "types": "",
        });
        assert!(promised(&manifest).is_empty(), "{:?}", promised(&manifest));
    }

    #[test]
    fn bin_is_read_in_both_of_its_shapes() {
        // A CLI's entry point is a file it ships, and `bin` is a string for one and a map for many.
        let one = serde_json::json!({ "bin": "cli.js" });
        assert!(promised(&one).contains("cli.js"));
        let many = serde_json::json!({ "bin": { "a": "./bin/a.js", "b": "./bin/b.js" } });
        assert_eq!(promised(&many).len(), 2);
        assert!(shortfall(&many, &tracked(&["bin/a.js"])).contains("bin/b.js"));
    }

    #[test]
    fn a_value_that_is_not_a_path_promises_nothing() {
        // A publisher can write anything in these fields. A number, a boolean or a null names no
        // file, and reading one as a promise would send a build after a file nobody declared.
        let manifest = serde_json::json!({
            "main": 7,
            "browser": false,
            "types": null,
            "exports": { ".": [1, true, "./index.js"] },
        });
        assert_eq!(
            promised(&manifest).into_iter().collect::<Vec<_>>(),
            ["index.js"]
        );
    }
}
