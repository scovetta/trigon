//! Named, composable, parameterized fragments.
//!
//! A tool is what stops every PyPI definition from repeating the same nine lines of venv setup, and
//! it is what makes "adding an ecosystem is YAML plus a `Registry` implementation" true rather than
//! aspirational. Tools may use other tools, forwarding parameters as templates, so the registry
//! resolves a small composition graph.
//!
//! Two load-time checks rather than run-time surprises: a cycle is a load error, not a hang, and a
//! step naming a tool nobody registered fails validation rather than rendering to nothing. The
//! second matters more than it sounds. A `uses:` that silently produces an empty fragment gives a
//! build that runs, does less than it was asked to, and can still match, which is a false pass.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::error::StrategyError;
use crate::model::{Step, StepBody};

/// One declared parameter of a tool.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolParam {
    #[serde(default)]
    pub required: bool,
    /// Used when the caller supplies nothing. A missing optional parameter renders as the empty
    /// string, which templates test with `{% if %}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    pub id: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, ToolParam>,
    /// System packages every step of this tool needs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub needs: Vec<String>,
    pub steps: Vec<Step>,
}

/// The set of tools a strategy may reference.
#[derive(Clone, Debug, Default)]
pub struct ToolRegistry {
    tools: BTreeMap<String, Tool>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// The tools shipped with the binary, before any definitions repo is consulted.
    ///
    /// Data rather than Rust, and embedded rather than read from disk, so `trigon` works with no
    /// definitions checkout and the tools stay reviewable as text.
    pub fn builtin() -> Result<Self, StrategyError> {
        let mut r = Self::new();
        for src in BUILTIN_TOOLS {
            r.add(serde_yaml_ng::from_str(src)?)?;
        }
        r.validate()?;
        Ok(r)
    }

    pub fn add(&mut self, t: Tool) -> Result<(), StrategyError> {
        // Look before inserting. `insert` returns the *evicted* value, so the old code had already
        // replaced the builtin by the time it decided to refuse — the registry kept the shadowing
        // definition it had just rejected, and the message named the tool it had thrown away. A
        // refusal that leaves the thing it refused in place is worse than no check, and
        // `docs/threat-model.md` P27 claims this seam is where an unknown or duplicate tool is a
        // hard error rather than a silent substitution.
        if self.tools.contains_key(&t.id) {
            return Err(StrategyError::Invalid(format!(
                "tool `{}` is registered twice. A definitions repo overriding a builtin has to say \
                 so explicitly rather than shadowing it by load order.",
                t.id
            )));
        }
        self.tools.insert(t.id.clone(), t);
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&Tool> {
        self.tools.get(id)
    }

    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.tools.keys().map(String::as_str)
    }

    /// Every `uses:` resolves, and the composition graph is acyclic.
    pub fn validate(&self) -> Result<(), StrategyError> {
        for t in self.tools.values() {
            for (i, s) in t.steps.iter().enumerate() {
                if let StepBody::Uses { tool, .. } = &s.body
                    && !self.tools.contains_key(tool)
                {
                    return Err(StrategyError::Invalid(format!(
                        "tool `{}` step {i} uses `{tool}`, which is not registered. Known: {}",
                        t.id,
                        self.ids().collect::<Vec<_>>().join(", ")
                    )));
                }
            }
        }
        for id in self.tools.keys() {
            self.check_acyclic(id, &mut Vec::new())?;
        }
        Ok(())
    }

    fn check_acyclic(&self, id: &str, path: &mut Vec<String>) -> Result<(), StrategyError> {
        if path.iter().any(|p| p == id) {
            path.push(id.to_string());
            return Err(StrategyError::Invalid(format!(
                "tools form a cycle: {}. Resolution would not terminate.",
                path.join(" -> ")
            )));
        }
        let Some(t) = self.tools.get(id) else {
            return Ok(());
        };
        path.push(id.to_string());
        for s in &t.steps {
            if let StepBody::Uses { tool, .. } = &s.body {
                self.check_acyclic(tool, path)?;
            }
        }
        path.pop();
        Ok(())
    }

    /// Parameters a caller supplied that the tool does not declare, and required ones it omitted.
    ///
    /// A misspelled parameter is otherwise invisible: the tool reads its own name for the value,
    /// gets nothing, and renders a command with a hole in it.
    pub fn check_params(
        &self,
        tool: &Tool,
        with: &BTreeMap<String, String>,
    ) -> Result<(), StrategyError> {
        let declared: BTreeSet<&str> = tool.params.keys().map(String::as_str).collect();
        // A tool that declares no parameters at all is taking whatever it is given: the prior art's
        // tools are untyped, and rejecting their callers would make the ported set unusable.
        if !declared.is_empty() {
            let unknown: Vec<&str> = with
                .keys()
                .map(String::as_str)
                .filter(|k| !declared.contains(k))
                .collect();
            if !unknown.is_empty() {
                return Err(StrategyError::Invalid(format!(
                    "tool `{}` has no parameter {}. It declares: {}",
                    tool.id,
                    unknown.join(", "),
                    declared.into_iter().collect::<Vec<_>>().join(", ")
                )));
            }
        }
        let missing: Vec<&str> = tool
            .params
            .iter()
            // Present *and* non-empty. This asked only whether the key existed, so
            // `with: { venv: "" }` satisfied a required parameter and `pypi/deps/basic` rendered
            // `/bin/pip install build` — a path with its root missing, failing three steps from its
            // cause. A required parameter supplied as nothing was not supplied.
            .filter(|(k, p)| {
                p.required
                    && p.default.is_none()
                    && with.get(*k).is_none_or(|v| v.trim().is_empty())
            })
            .map(|(k, _)| k.as_str())
            .collect();
        if !missing.is_empty() {
            return Err(StrategyError::Invalid(format!(
                "tool `{}` requires {}",
                tool.id,
                missing.join(", ")
            )));
        }
        Ok(())
    }
}

/// Where a PyPI build's virtualenv goes.
///
/// **Not under `/`.** The root directory of a Debian image is mode 0555, and root writes there only
/// through `CAP_DAC_OVERRIDE` — which the sandbox drops, deliberately and by name. So
/// `python3 -m venv /deps` is `Permission denied` for root, and only at an enforced tier:
/// `defer_deps` moves the deps phase out of the image build and into the container run, so the same
/// recipe worked at `--egress open` with full capabilities and failed at `mirror-only` with none. A
/// build that succeeds at one tier and fails at another, for a reason that has nothing to do with
/// the package, reported as the package's fault.
///
/// `/trigon` is ours and already in the image — the phase scripts are copied there — so it exists at
/// run time, is owned by root at 0755, and needs no capability to write into. `/tmp` would work
/// today and is the worse choice: it is world-writable, and a tmpfs mounted over it (which
/// `docs/12-security.md` §5 wants) would empty it between the image build and the run with nothing
/// saying so.
///
/// A constant because five places have to agree on it: the venv the deps phase creates, the
/// interpreter the build phase looks for, the constraints file written between them, the CI rung's
/// copy of the same recipe, and the default in `tools/pypi/deps-basic.yaml`. They were five
/// literals agreeing by eye.
pub const VENV: &str = "/trigon/deps";

const BUILTIN_TOOLS: &[&str] = &[
    include_str!("../tools/git-checkout.yaml"),
    include_str!("../tools/cargo/install-rust.yaml"),
    include_str!("../tools/cargo/build-package.yaml"),
    include_str!("../tools/pypi/setup-venv.yaml"),
    include_str!("../tools/pypi/setup-registry.yaml"),
    include_str!("../tools/pypi/install-deps.yaml"),
    include_str!("../tools/pypi/deps-basic.yaml"),
    include_str!("../tools/pypi/build-wheel.yaml"),
    include_str!("../tools/npm/install-node.yaml"),
    include_str!("../tools/npm/setup-registry.yaml"),
    include_str!("../tools/npm/npx.yaml"),
    include_str!("../tools/npm/version-override.yaml"),
    include_str!("../tools/npm/install.yaml"),
    include_str!("../tools/npm/deps-custom.yaml"),
    include_str!("../tools/npm/build-pack.yaml"),
    include_str!("../tools/npm/build-custom.yaml"),
];
