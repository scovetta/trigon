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
//! them from — as the step's literals, because they are the publisher's text and a template would
//! evaluate it. What remains after this is the build-identity residual (signature, MVID, debug
//! layout) that `dotnet-assembly-identity` and the build environment handle.

use crate::model::{Step, StepBody, Strategy};
use crate::render::renders_as_itself;

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
/// **As literals, never as `with` values.** A `with` value is a template, and a stamp is the
/// publisher's own text, read out of their assembly: a copyright carrying `{{`, `{%` or `{#` —
/// ILSpy writes it as the attribute holds it, braces and all — would be evaluated as the template
/// it looks like, or fail the render on a name that is not defined, so the package under test
/// would be choosing what its own build recipe says. A literal reaches the tool as written,
/// whatever it holds. This used to wrap such a stamp in a raw block and leave out one that would
/// close the block early, which kept the text out of the evaluator only as long as the wrapping
/// was spelled right, and set no copyright at all for a publisher whose copyright said `endraw`.
///
/// A template the step already gave the same parameter gives way to the stamp — a parameter is a
/// template or a literal, never both — unless it is the stamp already, as plain text the engine
/// renders to itself: a definition's `version: 5.1.1`, or a stamp this rung set in `with` before
/// stamps were literals. That one stays where it is. Moving it would change the strategy digest and
/// nothing the tool receives, and the caller's `changes_anything` guard compares digests, so it
/// would rebuild an identical recipe and record a repair that changed nothing.
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
                // Plain text that is the stamp already renders to it, so it says what the literal
                // would, and moving it would change the digest and nothing the tool receives.
                if with.get(k).is_some_and(|w| w == v && renders_as_itself(w))
                    && !step.literal.contains_key(k)
                {
                    continue;
                }
                if with.remove(k).is_some() {
                    changed = true;
                }
                if step.literal.get(k).map(String::as_str) != Some(v) {
                    step.literal.insert(k.to_string(), v.to_string());
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
    use std::collections::BTreeMap;

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

    /// The pack step of a strategy, as its `with` and its literals.
    fn pack(s: &Strategy) -> (&BTreeMap<String, String>, &BTreeMap<String, String>) {
        let Strategy::Flow(f) = s else { panic!("flow") };
        let StepBody::Uses { with, .. } = &f.build[0].body else {
            panic!("uses")
        };
        (with, &f.build[0].literal)
    }

    #[test]
    fn the_pack_step_gains_the_published_version_stamps() {
        let next = with_assembly_version(&castle(), &info()).expect("changed");
        let (_, literal) = pack(&next);
        assert_eq!(literal.get("assembly_version").unwrap(), "5.0.0.0");
        assert_eq!(literal.get("copyright").unwrap(), "Copyright (c) 2004-2022 Castle Project");
        assert_eq!(literal.get("file_version").unwrap(), "5.1.1");
    }

    #[test]
    fn a_second_pass_changes_nothing_so_the_rung_does_not_loop() {
        let once = with_assembly_version(&castle(), &info()).expect("changed");
        assert!(
            with_assembly_version(&once, &info()).is_none(),
            "the props are already set; the second pass must be a no-op"
        );
    }

    /// The stamps are read out of the published assembly, so they are the package's text, and a
    /// `with` value is a template: set there, `{{ 7*7 }}` would be built into the assembly as `49`,
    /// and `{% if %}` would fail the render. Set as literals, each is the text the assembly holds.
    #[test]
    fn a_stamp_that_reads_as_a_template_is_set_as_written_and_does_not_loop() {
        let braced = AssemblyVersionInfo {
            copyright: Some("Copyright {{ 7*7 }} {% if %} {# y".into()),
            ..info()
        };
        let once = with_assembly_version(&castle(), &braced).expect("changed");
        let (with, literal) = pack(&once);
        assert_eq!(
            literal.get("copyright").unwrap(),
            "Copyright {{ 7*7 }} {% if %} {# y"
        );
        // The definition's own `version: 5.1.1` is the stamp already, as plain text, and stays;
        // nothing the assembly said is a template.
        assert_eq!(
            with,
            &BTreeMap::from([("version".to_string(), "5.1.1".to_string())]),
            "no stamp is a template"
        );
        assert!(with_assembly_version(&once, &braced).is_none());
    }

    /// The raw block this used to wrap a braced stamp in could be closed by the stamp, so one that
    /// said `endraw` was left out, and the build set no copyright at all. A literal has no end to
    /// reach.
    #[test]
    fn a_stamp_that_says_endraw_is_set_like_any_other() {
        let closing = AssemblyVersionInfo {
            copyright: Some("{{ a }}{% endraw %}{{ b }}".into()),
            ..info()
        };
        let next = with_assembly_version(&castle(), &closing).expect("changed");
        let (_, literal) = pack(&next);
        assert_eq!(
            literal.get("copyright").unwrap(),
            "{{ a }}{% endraw %}{{ b }}"
        );
        assert_eq!(literal.get("assembly_version").unwrap(), "5.0.0.0");
    }

    /// A definition can give a stamped parameter as a template that is not the stamp —
    /// `version: "{{ target.version }}"`, or a version the project's own file says. The stamp
    /// replaces it rather than sitting beside it, since a parameter given both ways is refused, and
    /// which of two values a tool received would otherwise be a question.
    #[test]
    fn a_template_the_step_gave_a_stamp_gives_way_to_the_literal() {
        // The last is the stamp with a newline after it, which the engine trims: in `with` it
        // renders to the stamp, but it is not plain text that says so.
        for given in ["'{{ target.version }}'", "5.1.0", r#""5.1.1\n""#] {
            let s = crate::from_yaml(&format!(
                "schema: 1\nkind: flow\nlocation:\n  repo: https://example.invalid/x\n  ref: aa\n\
                 build:\n  - uses: nuget/build/pack\n    with:\n      version: {given}\n\
                 output_path: trigon-pack/*.nupkg\n",
            ))
            .expect("parses");
            let next = with_assembly_version(&s, &info()).expect("changed");
            let (with, literal) = pack(&next);
            assert!(!with.contains_key("version"), "{given}: {with:?}");
            assert_eq!(literal.get("version").unwrap(), "5.1.1", "{given}");
            let Strategy::Flow(f) = &next else {
                panic!("flow")
            };
            assert_eq!(f.build[0].given_twice(), None);
            // And it survives a round trip through the text a reviewer reads.
            let text = crate::to_yaml(&next).unwrap();
            assert_eq!(crate::from_yaml(&text).unwrap(), next, "{text}");
        }
    }

    /// **A step that already says every stamp is left alone.** A strategy written before the
    /// stamps were literals — by this rung, which set them in `with`, and kept as a definitions
    /// entry or by hand — carries each as plain text equal to the stamp, which renders to exactly
    /// what the literal would. Moving them anyway changed the strategy digest and nothing the tool
    /// received, and the repair loop's `changes_anything` guard compares digests: it rebuilt an
    /// identical recipe, and recorded a repair that changed nothing.
    #[test]
    fn a_step_already_carrying_the_stamps_as_plain_values_is_left_alone() {
        let all_in_with = crate::from_yaml(
            "schema: 1\nkind: flow\nlocation:\n  repo: https://example.invalid/x\n  ref: aa\n\
             build:\n  - uses: nuget/build/pack\n    with:\n      version: 5.1.1\n      \
             assembly_version: 5.0.0.0\n      file_version: 5.1.1\n      \
             informational_version: 5.1.1\n      \
             copyright: Copyright (c) 2004-2022 Castle Project\n\
             output_path: trigon-pack/*.nupkg\n",
        )
        .expect("parses");
        assert_eq!(with_assembly_version(&all_in_with, &info()), None);

        // Plain text that is not every stamp: the ones it lacks are set, and the ones it says stay.
        let next = with_assembly_version(&castle(), &info()).expect("changed");
        let (with, literal) = pack(&next);
        assert_eq!(with.get("version").map(String::as_str), Some("5.1.1"));
        assert!(!literal.contains_key("version"), "{literal:?}");
        assert_eq!(literal.len(), 4, "{literal:?}");

        // Text equal to the stamp that the engine would read is not the stamp once rendered, so a
        // braced copyright given in `with` still moves.
        let braced = AssemblyVersionInfo {
            copyright: Some("{{ 7*7 }}".into()),
            ..AssemblyVersionInfo::default()
        };
        let in_with = crate::from_yaml(
            "schema: 1\nkind: flow\nlocation:\n  repo: https://example.invalid/x\n  ref: aa\n\
             build:\n  - uses: nuget/build/pack\n    with:\n      copyright: '{{ 7*7 }}'\n\
             output_path: trigon-pack/*.nupkg\n",
        )
        .expect("parses");
        let next = with_assembly_version(&in_with, &braced).expect("changed");
        let (with, literal) = pack(&next);
        assert!(with.is_empty(), "{with:?}");
        assert_eq!(literal.get("copyright").unwrap(), "{{ 7*7 }}");
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
