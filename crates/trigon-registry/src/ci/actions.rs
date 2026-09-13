//! The allowlist of `uses:` steps we are willing to interpret.
//!
//! `docs/06` §3.2 and ADR-0009 are the policy: we expand a curated set of well-known setup actions
//! and record everything else as an `UnmodelledStep`, because interpreting arbitrary JavaScript
//! actions is a project of its own and executing one to find out what it does is the thing we
//! specifically decline to do.
//!
//! **Matching is on the name before `@`, never on the ref.** Every modern workflow pins actions by
//! commit SHA with the tag in a trailing comment — `actions/checkout@3d3c42e5…  # v7.0.1` — so a
//! ref match would recognise nothing at all. The cost of that is real and worth stating plainly: a
//! fork published at an attacker-chosen SHA under the name `actions/setup-python` would be read as
//! `setup-python`. What contains it is that we only ever read *declared inputs* and never execute
//! anything, so the worst outcome is a strategy lowered from a lie, which produces a divergence
//! rather than a false pass. It is stated here rather than defended against because nothing
//! offline can tell the fork from the original.

/// An action we will read inputs off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Known {
    /// `fetch-depth`, `submodules`, `ref`, `path`.
    Checkout,
    /// `python-version`, `python-version-file`, `architecture`.
    SetupPython,
    /// `node-version`, `node-version-file`, `registry-url`. `cache:` is read and dropped.
    SetupNode,
    /// `version`, `version-file`, `python-version`.
    SetupUv,
    /// The package manager, which for us is a decline rather than a tool.
    SetupPnpm,
    /// Carries the build-to-publish edge, and the output directory with it. Not a build step.
    UploadArtifact,
    DownloadArtifact,
    /// A PyPI publish marker. `repository-url` is what separates a real release from a TestPyPI
    /// one, and `attrs` has both jobs in one file.
    PyPiPublish,
    /// An npm publish marker.
    NpmPublish,
    /// Ignored on purpose, and recorded as ignored rather than as unmodelled: caching cannot change
    /// output, so an `unmodelled` entry here would depress a candidate's confidence for nothing.
    Cache,
    /// A toolchain for an ecosystem we have no registry client for. The version is worth extracting
    /// as evidence; it can never produce a candidate.
    OtherToolchain(&'static str),
    /// The manylinux story. Read as evidence only in v1: `CIBW_MANYLINUX_*_IMAGE` is a real
    /// container pin and `FlowStrategy` has nowhere to put it.
    CiBuildWheel,
    /// A GitHub-release marker. Adds rank, never qualifies a job on its own — `flask`'s
    /// `create-release` job proves nothing about what reached PyPI.
    GithubRelease,
}

/// Classify a `uses:` by its action name, case-insensitively.
///
/// GitHub treats `Actions/Checkout` and `actions/checkout` as the same action, so a table keyed on
/// the exact spelling would miss a workflow that capitalised it. A local reusable workflow
/// (`./.github/workflows/x.yml`) and a remote one both return `None` and land in `unmodelled`.
pub fn classify(action: &str) -> Option<Known> {
    let a = action.trim().trim_end_matches('/').to_ascii_lowercase();
    // A path inside an action repository (`org/repo/subdir`) still identifies the repository.
    let head: String = a.split('/').take(2).collect::<Vec<_>>().join("/");
    Some(match head.as_str() {
        "actions/checkout" => Known::Checkout,
        "actions/setup-python" => Known::SetupPython,
        "actions/setup-node" => Known::SetupNode,
        "astral-sh/setup-uv" => Known::SetupUv,
        "pnpm/action-setup" => Known::SetupPnpm,
        "actions/upload-artifact" => Known::UploadArtifact,
        "actions/download-artifact" => Known::DownloadArtifact,
        "pypa/gh-action-pypi-publish" => Known::PyPiPublish,
        "js-devtools/npm-publish" => Known::NpmPublish,
        "actions/cache" | "swatinem/rust-cache" | "actions/cache-restore" => Known::Cache,
        "actions/setup-java" => Known::OtherToolchain("java"),
        "actions/setup-dotnet" => Known::OtherToolchain("dotnet"),
        "actions/setup-go" => Known::OtherToolchain("go"),
        "ruby/setup-ruby" => Known::OtherToolchain("ruby"),
        "dtolnay/rust-toolchain" | "actions-rs/toolchain" => Known::OtherToolchain("rust"),
        "pypa/cibuildwheel" => Known::CiBuildWheel,
        "softprops/action-gh-release" | "ncipollo/release-action" => Known::GithubRelease,
        _ => return None,
    })
}

/// Whether an unrecognised action should depress confidence or be passed over in silence.
///
/// Housekeeping actions that cannot affect build output — a concurrency guard, a label bot — would
/// otherwise make every recipe look worse than it is. Kept deliberately short: the default is to
/// record, because `docs/06` §3.2 argues an unmodelled step is where the next inference failure
/// comes from and hiding it is the worst available option.
pub fn is_inert(action: &str) -> bool {
    // **Exact on the `org/repo`, never a prefix.** `starts_with` made this a second allowlist with
    // looser rules than the real one: `actions/labeler-does-anything` matched `actions/labeler`,
    // so anyone naming an action after an inert one inherited its silence.
    //
    // `actions/github-script` used to be on this list and is the reason the rest of it is now
    // short. It runs arbitrary JavaScript with a GitHub client and `exec`, which is to say it can
    // do anything a `run:` step can — treating it as unable to affect build output was the widest
    // hole in the rung. `step-security/harden-runner` came off too: it installs an egress filter,
    // so it changes what the build can reach and therefore what it resolves.
    //
    // What is left is pull-request housekeeping that cannot touch the working tree, the toolchain
    // or the network. The default is still to record: `docs/06` §3.2 argues an unmodelled step is
    // where the next inference failure comes from, and hiding one is the worst option available.
    let a = action.to_ascii_lowercase();
    let repo = a.split('@').next().unwrap_or(&a);
    matches!(
        repo,
        "styfle/cancel-workflow-action" | "actions/labeler" | "actions/stale"
    )
}

#[cfg(test)]
mod inert_tests {
    #[test]
    fn an_action_that_can_run_code_is_never_inert() {
        // The whole point of the allowlist is that an unrecognised action depresses confidence and
        // names itself. An action that can execute arbitrary code must never be waved through, and
        // `actions/github-script` — arbitrary JS with `exec` — was.
        for a in [
            "actions/github-script@v7",
            "step-security/harden-runner@v2",
            "actions/checkout@v4",
            "some/unknown-action@v1",
        ] {
            assert!(
                !super::is_inert(a),
                "`{a}` was treated as unable to affect the build"
            );
        }
    }

    #[test]
    fn the_inert_list_matches_the_whole_name_rather_than_a_prefix() {
        // `starts_with` let anyone inherit an inert entry's silence by naming an action after it.
        assert!(super::is_inert("actions/labeler@v5"));
        assert!(!super::is_inert("actions/labeler-with-a-shell@v1"));
        assert!(!super::is_inert("evil/actions/labeler@v1"));
    }
}
