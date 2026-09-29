//! Reconstruct a .NET assembly's version stamps into the build, from what the feed served.
//!
//! A deterministic repair rung, the same shape as [`crate::without_yarn`]: a rule that answers a
//! divergence outright, before any model is asked. The divergence it answers is the common one for
//! a signed .NET package built by CI — the code reproduces, but `AssemblyVersion`, `FileVersion`,
//! `AssemblyInformationalVersion` and the copyright differ, because the publisher's CI stamped them
//! from an environment a checkout does not carry (`castle.core` reads `APPVEYOR_BUILD_VERSION` into
//! a `<BuildVersion>` property, and its copyright from the build year).
//!
//! **Reconstruct, not normalize.** These are consumer-meaningful — `AssemblyVersion` is a binding
//! identity — so the honest move is to build the assembly *with* the published version rather than
//! to erase the difference. The values are read from the published assembly itself and passed to
//! `nuget/build/pack` as standard MSBuild properties, which override whatever the project derived
//! them from. What remains after this is the build-identity residual (signature, MVID, debug
//! layout) that `dotnet-assembly-identity` and the build environment handle.

use crate::model::{Step, StepBody, Strategy};

/// The version stamps of a published assembly, as read back from it.
///
/// Every field optional: a decompiler may surface some and not others, and a `None` means "not
/// found, do not set it" rather than "set it empty".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AssemblyVersionInfo {
    pub version: Option<String>,
    pub assembly_version: Option<String>,
    pub file_version: Option<String>,
    pub informational_version: Option<String>,
    pub copyright: Option<String>,
}

impl AssemblyVersionInfo {
    fn is_empty(&self) -> bool {
        self.version.is_none()
            && self.assembly_version.is_none()
            && self.file_version.is_none()
            && self.informational_version.is_none()
            && self.copyright.is_none()
    }

    /// The (tool-parameter, value) pairs this carries.
    fn params(&self) -> Vec<(&'static str, &str)> {
        [
            ("version", &self.version),
            ("assembly_version", &self.assembly_version),
            ("file_version", &self.file_version),
            ("informational_version", &self.informational_version),
            ("copyright", &self.copyright),
        ]
        .into_iter()
        .filter_map(|(k, v)| v.as_deref().map(|v| (k, v)))
        .collect()
    }
}

/// Set the version stamps on the strategy's `nuget/build/pack` step, or `None` if there is nothing
/// to change — no such step, no version info, or the step already carries these exact values.
///
/// `None` is what keeps the rung from looping: once the props are set, a second pass produces the
/// same strategy, and the caller's `changes_anything` guard sees it.
pub fn with_assembly_version(strategy: &Strategy, info: &AssemblyVersionInfo) -> Option<Strategy> {
    if info.is_empty() {
        return None;
    }
    let Strategy::Flow(_) = strategy else {
        // Only the flow DSL names a `nuget/build/pack` step; a manual strategy is raw script.
        return None;
    };
    let mut next = strategy.clone();
    let Strategy::Flow(f) = &mut next else {
        unreachable!("just matched Flow")
    };
    let mut changed = false;
    for step in build_and_deps(f) {
        if let StepBody::Uses { tool, with } = &mut step.body
            && tool == "nuget/build/pack"
        {
            for (k, v) in info.params() {
                if with.get(k).map(String::as_str) != Some(v) {
                    with.insert(k.to_string(), v.to_string());
                    changed = true;
                }
            }
        }
    }
    changed.then_some(next)
}

fn build_and_deps(f: &mut crate::model::FlowStrategy) -> impl Iterator<Item = &mut Step> {
    f.build.iter_mut()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn castle() -> Strategy {
        crate::from_yaml(
            "schema: 1\nkind: flow\nlocation:\n  repo: https://example.invalid/x\n  ref: aa\n\
             \x20 subdir: src/Castle.Core\n\
             build:\n  - uses: nuget/build/pack\n    with:\n      version: 5.1.1\n\
             output_dir: trigon-pack\noutput_path: trigon-pack/*.nupkg\n",
        )
        .expect("parses")
    }

    fn info() -> AssemblyVersionInfo {
        AssemblyVersionInfo {
            version: Some("5.1.1".into()),
            assembly_version: Some("5.0.0.0".into()),
            file_version: Some("5.1.1".into()),
            informational_version: Some("5.1.1".into()),
            copyright: Some("Copyright (c) 2004-2022 Castle Project".into()),
        }
    }

    #[test]
    fn the_pack_step_gains_the_published_version_stamps() {
        let next = with_assembly_version(&castle(), &info()).expect("changed");
        let Strategy::Flow(f) = &next else { panic!("flow") };
        let StepBody::Uses { with, .. } = &f.build[0].body else {
            panic!("uses")
        };
        assert_eq!(with.get("assembly_version").unwrap(), "5.0.0.0");
        assert_eq!(with.get("copyright").unwrap(), "Copyright (c) 2004-2022 Castle Project");
        assert_eq!(with.get("file_version").unwrap(), "5.1.1");
    }

    #[test]
    fn a_second_pass_changes_nothing_so_the_rung_does_not_loop() {
        let once = with_assembly_version(&castle(), &info()).expect("changed");
        assert!(
            with_assembly_version(&once, &info()).is_none(),
            "the props are already set; the second pass must be a no-op"
        );
    }

    #[test]
    fn a_strategy_with_no_pack_step_is_left_alone() {
        let s = crate::from_yaml(
            "schema: 1\nkind: flow\nlocation:\n  repo: https://example.invalid/x\n  ref: aa\n\
             build:\n  - runs: make\noutput_path: '*.tgz'\n",
        )
        .unwrap();
        assert!(with_assembly_version(&s, &info()).is_none());
    }

    #[test]
    fn empty_info_is_a_no_op() {
        assert!(with_assembly_version(&castle(), &AssemblyVersionInfo::default()).is_none());
    }

    #[test]
    fn a_manual_strategy_names_no_pack_step_and_is_left_alone() {
        // Raw script has no `nuget/build/pack` step to hand the properties to, and splicing them
        // into a script is not this rung's to guess at.
        let s = crate::from_yaml(
            "kind: manual\nlocation: { repo: https://example.invalid/x, ref: aa }\n\
             build: dotnet pack -c Release\n",
        )
        .unwrap();
        assert!(with_assembly_version(&s, &info()).is_none());
    }
}
