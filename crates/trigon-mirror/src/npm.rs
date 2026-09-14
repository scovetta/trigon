//! Filtering an npm packument to a moment.
//!
//! A packument lists every version ever published plus a `time` map dating each one, so the filter
//! is a join between the two. What makes this more than a filter is `dist-tags`: npm resolvers read
//! `latest` to decide what a floating range means, and a packument whose versions are filtered but
//! whose `latest` still names a removed version makes every install fail on a version that is not
//! there. So `latest` is recomputed as the newest version that survived.

use serde_json::{Map, Value};

use crate::moment::published_by;

/// Filter a packument in place. Returns how many versions were removed.
pub fn filter_packument(doc: &mut Value, moment: &str) -> usize {
    let Some(obj) = doc.as_object_mut() else {
        return 0;
    };

    // Which versions survive, and which of those is newest. Both come from the `time` map, which
    // is the only place npm records when a version was published.
    let mut keep: Vec<String> = Vec::new();
    let mut latest: Option<(String, String)> = None;
    if let Some(times) = obj.get("time").and_then(Value::as_object) {
        for (version, ts) in times {
            // `created` and `modified` are package-level, not versions.
            if version == "created" || version == "modified" {
                continue;
            }
            let Some(ts) = ts.as_str() else { continue };
            if published_by(ts, moment) {
                keep.push(version.clone());
                if latest.as_ref().is_none_or(|(_, t)| ts > t.as_str()) {
                    latest = Some((version.clone(), ts.to_string()));
                }
            }
        }
    }

    let removed = match obj.get_mut("versions").and_then(Value::as_object_mut) {
        Some(versions) => {
            let before = versions.len();
            versions.retain(|v, _| keep.iter().any(|k| k == v));
            before - versions.len()
        }
        None => 0,
    };

    if let Some(times) = obj.get_mut("time").and_then(Value::as_object_mut) {
        times.retain(|k, _| k == "created" || k == "modified" || keep.iter().any(|kept| kept == k));
    }

    recompute_latest(obj);

    removed
}

/// Drop the one version this run is rebuilding, whatever its date.
///
/// Returns how many versions were removed — at most one, and zero whenever this packument is for
/// some other package.
///
/// **Why the index and not the download.** The guard refuses the target's own artifact URL, which
/// is the control that defeats the forged-attestation attack. But a resolver that has been told a
/// version exists and is then denied the file does not look for another one: it fails, and the
/// build dies. That is what happened to every package that is part of the machinery that builds
/// packages — npm's own installer needs `object-assign` and `strip-ansi`, so rebuilding either
/// made the install ask for the target and hit the wall.
///
/// A version that was never offered is a different thing entirely. `object-assign@4.1.1` simply is
/// not in the index, so npm resolves the range to `4.1.0` and installs it. The target's bytes still
/// never cross — nothing about the refusal changes — but the resolver routes around the hole
/// instead of dying in it.
///
/// Counted separately from the moment filter on purpose. `versions_withheld` is the evidence that
/// the registry pin applied, and folding a policy removal into it would make a packument where
/// only the target was dropped report `withheld=1` and read as the pin doing work it did not do.
pub fn withhold_version(doc: &mut Value, w: &crate::Withheld) -> usize {
    let Some(obj) = doc.as_object_mut() else {
        return 0;
    };
    let named = obj
        .get("name")
        .and_then(Value::as_str)
        .is_some_and(|n| n == w.project);
    if !named {
        return 0;
    }

    let removed = match obj.get_mut("versions").and_then(Value::as_object_mut) {
        Some(versions) => usize::from(versions.remove(&w.version).is_some()),
        None => 0,
    };
    if let Some(times) = obj.get_mut("time").and_then(Value::as_object_mut) {
        times.remove(&w.version);
    }
    // After the removal, never before: `latest` is read off the `time` map, and leaving it naming
    // the version we just withheld reintroduces exactly the failure this function exists to avoid.
    recompute_latest(obj);
    removed
}

/// Rewrite `dist-tags` so `latest` names the newest version still in the document.
///
/// The part that matters. A resolver reads `latest` to resolve a floating range, and a tag naming
/// a version that is no longer in the document makes every install fail. Newest by *publish time*,
/// which is what npm itself means by `latest`; a version sort would name a prerelease.
///
/// Every other tag is dropped rather than repaired: a tag pointing into the removed set has no
/// honest value to take, and inventing one would answer a question about the registry with a guess.
fn recompute_latest(obj: &mut Map<String, Value>) {
    let mut latest: Option<(String, String)> = None;
    if let Some(times) = obj.get("time").and_then(Value::as_object) {
        for (version, ts) in times {
            if version == "created" || version == "modified" {
                continue;
            }
            let Some(ts) = ts.as_str() else { continue };
            if latest.as_ref().is_none_or(|(_, t)| ts > t.as_str()) {
                latest = Some((version.clone(), ts.to_string()));
            }
        }
    }
    let mut tags = Map::new();
    if let Some((v, t)) = &latest {
        tags.insert("latest".into(), Value::String(v.clone()));
        // `modified` should describe the index as the client sees it, not as it is today — and it
        // is derived here rather than by the caller so that a version removed *after* the moment
        // filter cannot leave it naming something the document no longer holds. Same hazard as the
        // dangling `latest` above, reached a different way.
        if let Some(times) = obj.get_mut("time").and_then(Value::as_object_mut) {
            times.insert("modified".into(), Value::String(t.clone()));
        }
    }
    obj.insert("dist-tags".into(), Value::Object(tags));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packument() -> Value {
        serde_json::json!({
            "name": "demo",
            "dist-tags": { "latest": "2.0.0", "next": "3.0.0-beta" },
            "versions": {
                "1.0.0": {"version": "1.0.0"},
                "1.5.0": {"version": "1.5.0"},
                "2.0.0": {"version": "2.0.0"},
                "3.0.0-beta": {"version": "3.0.0-beta"}
            },
            "time": {
                "created": "2018-01-01T00:00:00.000Z",
                "modified": "2020-01-01T00:00:00.000Z",
                "1.0.0": "2018-01-01T00:00:00.000Z",
                "1.5.0": "2019-06-01T00:00:00.000Z",
                "2.0.0": "2020-01-01T00:00:00.000Z",
                "3.0.0-beta": "2019-12-01T00:00:00.000Z"
            }
        })
    }

    #[test]
    fn versions_published_later_are_removed() {
        let mut d = packument();
        assert_eq!(filter_packument(&mut d, "2019-07-01T00:00:00"), 2);
        let versions = d["versions"].as_object().unwrap();
        assert!(versions.contains_key("1.0.0"));
        assert!(versions.contains_key("1.5.0"));
        assert!(!versions.contains_key("2.0.0"));
    }

    #[test]
    fn latest_is_recomputed_rather_than_left_dangling() {
        // The failure this prevents: a resolver reads `latest`, asks for 2.0.0, and the packument
        // no longer contains it. Every install of a floating range fails on a missing version.
        let mut d = packument();
        filter_packument(&mut d, "2019-07-01T00:00:00");
        assert_eq!(d["dist-tags"]["latest"], "1.5.0");
        assert!(
            d["dist-tags"].as_object().unwrap().get("next").is_none(),
            "a tag pointing at a removed version is dropped, not kept"
        );
    }

    #[test]
    fn latest_follows_publish_order_not_version_order() {
        // 3.0.0-beta was published before 2.0.0. `latest` means most recently published, which is
        // what npm itself means by it, and a version sort would name a prerelease.
        let mut d = packument();
        filter_packument(&mut d, "2019-12-15T00:00:00");
        assert_eq!(d["dist-tags"]["latest"], "3.0.0-beta");
    }

    fn withheld(version: &str) -> crate::Withheld {
        crate::Withheld {
            project: "demo".into(),
            version: version.into(),
        }
    }

    #[test]
    fn the_version_under_test_is_never_offered() {
        // The bug this closes. `object-assign` is a dependency of npm's own installer, so
        // rebuilding it made the install ask for the target, and the guard refused the download.
        // A resolver denied a file it was told exists does not pick another one — it fails.
        let mut d = packument();
        assert_eq!(withhold_version(&mut d, &withheld("1.5.0")), 1);
        let versions = d["versions"].as_object().unwrap();
        assert!(!versions.contains_key("1.5.0"));
        assert!(versions.contains_key("1.0.0"), "the others are untouched");
        assert!(!d["time"].as_object().unwrap().contains_key("1.5.0"));
    }

    #[test]
    fn withholding_repoints_latest() {
        // Same hazard as the moment filter's, reached a different way: `latest` naming the version
        // we just removed makes every floating range fail on a version that is not there.
        let mut d = packument();
        withhold_version(&mut d, &withheld("2.0.0"));
        assert_eq!(d["dist-tags"]["latest"], "3.0.0-beta");
    }

    #[test]
    fn withholding_repoints_modified_too() {
        // Same hazard as `latest` and reached the same way: `modified` is derived from the version
        // set, and a removal after the moment filter would otherwise leave it dating a version the
        // document no longer holds.
        let mut d = packument();
        filter_packument(&mut d, "2020-06-01T00:00:00");
        assert_eq!(d["time"]["modified"], "2020-01-01T00:00:00.000Z");
        withhold_version(&mut d, &withheld("2.0.0"));
        assert_eq!(d["time"]["modified"], "2019-12-01T00:00:00.000Z");
    }

    #[test]
    fn another_packument_is_left_alone() {
        // The mirror serves every index the build asks for. Dropping `1.5.0` from whichever
        // packument happened to arrive would quietly remove an unrelated package's release.
        let mut d = packument();
        let other = crate::Withheld {
            project: "elsewhere".into(),
            version: "1.5.0".into(),
        };
        assert_eq!(withhold_version(&mut d, &other), 0);
        assert!(d["versions"].as_object().unwrap().contains_key("1.5.0"));
    }

    #[test]
    fn withholding_a_version_that_is_not_there_removes_nothing() {
        let mut d = packument();
        assert_eq!(withhold_version(&mut d, &withheld("9.9.9")), 0);
        assert_eq!(d["versions"].as_object().unwrap().len(), 4);
    }

    #[test]
    fn the_moment_filter_and_the_withholding_compose() {
        // Both run on every index response, in that order, and the count each reports is its own:
        // `versions_withheld` is evidence the pin applied, and a policy removal folded into it
        // would read as the pin doing work it did not do.
        let mut d = packument();
        assert_eq!(filter_packument(&mut d, "2019-12-15T00:00:00"), 1);
        assert_eq!(withhold_version(&mut d, &withheld("1.5.0")), 1);
        let versions = d["versions"].as_object().unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(d["dist-tags"]["latest"], "3.0.0-beta");
    }

    #[test]
    fn the_time_map_is_filtered_too() {
        let mut d = packument();
        filter_packument(&mut d, "2019-07-01T00:00:00");
        let times = d["time"].as_object().unwrap();
        assert!(!times.contains_key("2.0.0"));
        assert!(times.contains_key("created"), "package-level keys survive");
        assert_eq!(times["modified"], "2019-06-01T00:00:00.000Z");
    }

    #[test]
    fn a_moment_before_the_first_release_leaves_nothing() {
        let mut d = packument();
        filter_packument(&mut d, "2017-01-01T00:00:00");
        assert!(d["versions"].as_object().unwrap().is_empty());
        assert!(d["dist-tags"].as_object().unwrap().is_empty());
    }

    #[test]
    fn a_version_with_no_timestamp_is_excluded() {
        // Including what we cannot date would let a rebuild resolve a version we could not place
        // in time, which is the failure the whole mechanism exists to prevent.
        let mut d = packument();
        d["versions"]["9.9.9"] = serde_json::json!({"version": "9.9.9"});
        filter_packument(&mut d, "2025-01-01T00:00:00");
        assert!(!d["versions"].as_object().unwrap().contains_key("9.9.9"));
    }
}
