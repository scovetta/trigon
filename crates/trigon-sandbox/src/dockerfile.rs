//! The container pattern, rendered.
//!
//! Setup, source and deps run at **image-build** time; the build itself is written to `/build` and
//! run afterwards. Taken from the prior art, because it is right, and it buys three things:
//!
//! 1. **Layer caching** across sibling versions of a package, which is often the difference between
//!    a 20-second build and a 200-second one.
//! 2. **Clean phase boundaries** for timing. Each phase is a layer, so per-phase durations come
//!    from layer metadata rather than from instrumenting the build.
//! 3. **A retained image and container** an agent can `exec` into and a human can pull when
//!    triaging.
//!
//! Where this departs from the prior art is *how* a phase's script reaches the image. They inline
//! it in a heredoc (`RUN <<'EOF' | sh`), which is a BuildKit parser feature. Podman 4.x builds with
//! `imagebuilder`, which does not implement it and parses the heredoc body as Dockerfile
//! instructions: the first line of a build script becomes an unknown instruction and the error
//! names it. Requiring BuildKit would make "runs on a laptop with Podman" false, so each phase is
//! a file in the build context instead, copied in and run.
//!
//! That turns out to be the better shape anyway. There is no shell quoting to get wrong, the
//! scripts are inspectable files rather than bytes embedded in a Dockerfile, and the whole context
//! hashes as a unit for the run key.
//!
//! Rendering is a pure function of the plan, with no clock and no environment, so the bytes that
//! describe a build can be read before anything executes.

use std::collections::BTreeMap;

use crate::model::OciPlan;

/// Everything needed to build the image: the Dockerfile and the files it copies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildContext {
    pub dockerfile: String,
    /// Relative path to contents. `BTreeMap` so the context hashes the same every time.
    pub files: BTreeMap<String, String>,
}

impl BuildContext {
    /// Write the context to a directory.
    pub fn write(&self, dir: &std::path::Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        std::fs::write(dir.join("Dockerfile"), &self.dockerfile)?;
        for (name, body) in &self.files {
            std::fs::write(dir.join(name), body)?;
        }
        Ok(())
    }
}

/// The command that checks these packages are already present, without a network.
///
/// What the setup phase becomes at an enforced tier. The image build has no network there, so
/// installing is impossible — but *verifying* is not, because every package manager can answer
/// "is this installed" from its own on-disk database.
///
/// **What belongs in a base image at all** is settled by ADR-0012: an image supplies *bytes* the
/// evidence does not pin — a compiler, `ca-certificates`, `git` — and never a *decision* it does,
/// which is why Node, npm and the .NET SDK are installed per run from the version the registry
/// recorded rather than baked in. A `needs:` entry that names one of those is asking the image to
/// answer a question the package already answered.
///
/// This is better than refusing the run before it starts, which was the first design: a pre-flight
/// refusal cannot know what a base image contains, so it has to refuse every strategy that declares
/// a package even when the image carries all of them. The check knows, and it names the ones that
/// are actually missing.
///
/// `command -v` would not do. `ca-certificates` and `libatomic1` provide no binary, and a check
/// that silently passes for them is not a check.
pub fn verify_command(base_image: &str, deps: &[String]) -> String {
    let family = Family::of(base_image);
    let query = family.query();
    let list = family.packages(deps).join(" ");
    // The real reference, not a placeholder. This printed the literal `<this image>`, so the one
    // command a reader needs at the moment they need it was the one thing they had to go and
    // assemble by hand — from a digest scrolled off the top of the same output. `is_pinned` has
    // already refused anything but a digest reference or a bare image id by the time this renders,
    // so there is nothing here that can break out of the quoting.
    let from_ref = base_image;
    format!(
        "missing=\"\"\n\
         for p in {list}; do\n\
        \x20 {query} \"$p\" >/dev/null 2>&1 || missing=\"$missing $p\"\n\
         done\n\
         if [ -n \"$missing\" ]; then\n\
        \x20 echo \"this base image is missing:$missing\"\n\
        \x20 echo \"an enforced egress tier gives the image build no network, so the packages a\"\n\
        \x20 echo \"strategy needs have to be in the image already. Build one with:\"\n\
        \x20 echo \"    trigon base-image --from {from_ref} --packages$missing\"\n\
        \x20 exit 1\n\
         fi\n\
         echo \"base image carries: {list}\""
    )
}

/// Install only what is not already there.
///
/// The same names `install_command` would install and the same query `verify_command` would ask,
/// composed: collect the missing ones, and run the installer only if the list is non-empty. A
/// separate function rather than a flag on either, because both of those are used elsewhere for
/// their own reasons — `base-image` installs unconditionally on purpose, since it is building an
/// image *to* carry them.
pub fn install_missing_command(base_image: &str, deps: &[String]) -> String {
    let family = Family::of(base_image);
    let (query, install) = (family.query(), family.install());
    let list = family.packages(deps).join(" ");
    format!(
        "missing=\"\"\n\
         for p in {list}; do\n\
        \x20 {query} \"$p\" >/dev/null 2>&1 || missing=\"$missing $p\"\n\
         done\n\
         if [ -n \"$missing\" ]; then\n\
        \x20 echo \"installing:$missing\"\n\
        \x20 {install}$missing\n\
         else\n\
        \x20 echo \"this image already carries every package this build needs\"\n\
         fi\n"
    )
}

/// The command that installs these packages on this base image's distribution.
///
/// Public because an enforced tier refuses to run it and has to tell the operator what to put in a
/// base image instead. The refusal is only actionable if it prints the line.
pub fn install_command(base_image: &str, deps: &[String]) -> String {
    let family = Family::of(base_image);
    let install = family.install();
    format!("{install} {}", family.packages(deps).join(" "))
}

/// The package manager for a base image, chosen by what the image name says it is.
///
/// A guess, and it is allowed to be: a wrong guess fails in the setup phase with the package
/// manager's own error, which is a legible failure. Silently skipping the install is not, because
/// the build then fails later for a reason that looks like the package's fault.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    Debian,
    Alpine,
    Fedora,
}

impl Family {
    /// Which package manager's names an image speaks, from the image reference.
    ///
    /// **One sniff.** This test lived in four places — the three command builders and the public
    /// `family_of` — each with its own copy of the same `contains` chain and its own payload
    /// beside it. Four readings of one string is four chances for them to disagree about an image,
    /// and the disagreement would show up as a build installing Debian names on Fedora rather than
    /// as anything that looks like a bug here.
    ///
    /// It is a guess from a string and always has been; the probe each command builds is what
    /// decides.
    fn of(base_image: &str) -> Family {
        let img = base_image.to_ascii_lowercase();
        if img.contains("alpine") {
            Family::Alpine
        } else if img.contains("fedora") || img.contains("rocky") || img.contains("almalinux") {
            Family::Fedora
        } else {
            Family::Debian
        }
    }

    /// Ask whether one package is present. Exit status is the answer.
    fn query(self) -> &'static str {
        match self {
            Family::Alpine => "apk info -e",
            Family::Fedora => "rpm -q",
            Family::Debian => "dpkg -s",
        }
    }

    /// Install the packages named after it, with no prompt and no recommendations.
    fn install(self) -> &'static str {
        match self {
            Family::Alpine => "apk add --no-cache",
            Family::Fedora => "dnf install -y",
            Family::Debian => "apt-get update && apt-get install -y --no-install-recommends",
        }
    }

    /// The family's own name, for a label on the built image.
    fn name(self) -> &'static str {
        match self {
            Family::Alpine => "alpine",
            Family::Fedora => "fedora",
            Family::Debian => "debian",
        }
    }

    /// Every distribution package these logical dependencies expand to, in order, without repeats.
    ///
    /// Order matters and a `HashSet` would lose it: the list reaches a shell command, and a command
    /// whose arguments reorder between runs makes an image layer that will not cache.
    fn packages(self, deps: &[String]) -> Vec<String> {
        let mut names: Vec<String> = Vec::new();
        for d in deps {
            for n in expand(d, self) {
                if !names.contains(&n) {
                    names.push(n);
                }
            }
        }
        names
    }
}

/// Which package manager's names an image speaks, from the image reference.
///
/// The same sniff `verify_command` does, exposed so a label can record the answer rather than
/// leaving a reader of the image to redo it. It is a guess from a string and always has been; the
/// probe is what decides.
pub fn family_of(base_image: &str) -> &'static str {
    Family::of(base_image).name()
}

/// Whether automation may put a logical dependency into an image.
///
/// # The line, and the test that decides which side a name falls on
///
/// [`ADR-0012`](../../../docs/adr/0012-base-images-supply-bytes-not-decisions.md) says an image may
/// supply **bytes** the evidence does not pin and never a **decision** it does. Automation inherits
/// that exactly: *it may add bytes, never a decision.* The useful operational form of that, because
/// "is a compiler a decision" is an argument nobody wins:
///
/// > **Does adding this to the image override something a strategy has already pinned?**
///
/// A strategy pins the npm the registry recorded, the Node that published, the .NET SDK, the Rust
/// toolchain. Debian's copy of any of those shadows the pinned one, and the run then measures a
/// toolchain nobody chose. Nothing pins `git`, `wget`, `ssh`, a C compiler or `pkg-config`: without
/// them the build fails, with them it proceeds identically, and no version of them reaches a
/// verdict.
///
/// That test is not a matter of taste and it has already cost this project a corpus.
/// `npx.yaml`'s own comment records it in bold: Debian's `npm` drags in Node 18 plus a tree under
/// `/usr/share/nodejs` that a system-wide `NODE_PATH` puts ahead of everything, so a pinned Node 10
/// loads modules written for 18 and aborts with `SIGABRT` — `env/toolchain-crashed` on the M1
/// corpus was that, not vintage. An auto-installer acting on `needs: [npm]` would reproduce it on
/// demand.
///
/// # Unknown is the side that matters
///
/// A name with no verdict is **refused**, and told that it has no verdict. New entries land there
/// by default, so the failure mode of forgetting to classify something is a refusal rather than an
/// installation. `every_name_the_tree_can_ask_for_has_a_verdict` fails the build if a `needs:` or
/// an `expand()` arm names something this table does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// Bytes. Automation may add it.
    Bytes,
    /// A decision, with the reason. Never added automatically, at any tier, with or without a flag.
    Decision(&'static str),
    /// No verdict. Refused, and said to have none.
    Unknown,
}

impl Admission {
    pub fn is_bytes(self) -> bool {
        matches!(self, Admission::Bytes)
    }

    /// What to tell an operator who asked for this and cannot have it.
    pub fn refusal(self, dep: &str) -> Option<String> {
        match self {
            Admission::Bytes => None,
            Admission::Decision(why) => Some(format!(
                "`{dep}` will not be added to an image automatically: {why} An image supplies \
                 bytes, never a decision the evidence pins — see ADR-0012. Install it in the build \
                 from the version the registry recorded, which is what the ecosystem's tools \
                 already do."
            )),
            Admission::Unknown => Some(format!(
                "`{dep}` has no admission verdict, so it is refused rather than installed. Add it \
                 to `admission()` in trigon-sandbox as `Bytes` or `Decision`, with the reason. A \
                 name nobody has classified is not a name to put in an image on a guess."
            )),
        }
    }
}

/// The verdict for one logical dependency name.
///
/// Neutral names, the same vocabulary `needs:` and `DEFAULT_PACKAGES` speak, because the
/// distribution package is a function of the family and the question here is not about Debian.
/// Why an image may not be derived for this set, or `None` if it may.
///
/// **One implementation, because there were two and only one of them ran in time.** `resolve_auto`
/// asked this question at image-resolution time, which is after a repair proposal has already been
/// accepted and the previous attempt's evidence discarded. The repair gate asked whether a proposal
/// *renders* and whether it is *executable* and never whether an image may supply what it needs —
/// so a model answer of `needs: [npm]` passed the gate, replaced a working strategy, and refused
/// three steps later where the refusal could no longer be turned into another attempt.
///
/// The message is here too, not just the rule. A refusal worded at one call site and re-worded at
/// the other is the same defect one level down.
pub fn inadmissible<'a>(deps: impl IntoIterator<Item = &'a str>) -> Option<String> {
    let refused: Vec<String> = deps
        .into_iter()
        .filter_map(|d| admission(d).refusal(d))
        .collect();
    if refused.is_empty() {
        return None;
    }
    Some(format!(
        "this strategy asks for something an image may not supply automatically:\n\n  - {}\n\n\
         Build an image yourself with `trigon base-image` if you have decided to, and pass it \
         with `--image`.",
        refused.join("\n  - ")
    ))
}

pub fn admission(dep: &str) -> Admission {
    match dep {
        // ---- Bytes: nothing pins them, and no version of them reaches a verdict. ----
        //
        // Trust anchors and fetchers. A build that cannot verify a TLS certificate or retrieve a
        // tarball fails at the boundary; neither changes what is retrieved.
        "ca-certificates" | "wget" | "curl" => Admission::Bytes,
        // The source is fetched by us and copied in at an enforced tier, but a build may still run
        // `git describe` — and `hatch-vcs` and `setuptools-scm` take the version from it.
        "git" => Admission::Bytes,
        // npm shells out to it for a `git+ssh://` dependency. The dependency resolved is the same
        // either way; without it the clone cannot happen at all. Two of the 125-target random
        // sweep's five `unknown`s were this.
        "ssh" => Admission::Bytes,
        // A C/C++ toolchain and what an extension build looks for. Five of the M1 corpus's ten
        // unnamed PyPI failures were a missing `gcc`. The compiler version does reach the bytes of
        // a compiled extension — and that is already true of every image, recorded as
        // `Environment.base_image`, rather than something automation introduces.
        "cc" | "pkg-config" | "libatomic" | "python3-dev" => Admission::Bytes,
        // Named in `DEFAULT_PACKAGES`' own comment as real gaps. They build; they do not resolve.
        "meson" | "ninja" => Admission::Bytes,
        // **The one Bytes entry that is a decision in a weaker sense**, and it is written down
        // rather than waved past. The interpreter decides a wheel's tag and its bytecode. But
        // `pypi/setup-venv.yaml` uses it only on the branch where the strategy pinned *no*
        // `python_version` — "whichever one the image has", in the tool's own words — so adding it
        // overrides nothing. Where a version is pinned, `uv` fetches that one instead. The real fix
        // is a per-target interpreter the way npm has a per-target Node; until then this is a
        // decision the image has always made and the record has always carried.
        "python3" => Admission::Bytes,
        // Not a resolver anywhere in this tree: its single use is `uv venv --python <pinned>`, the
        // mechanism that *honours* a strategy's pin rather than one that overrides it.
        "uv" => Admission::Bytes,

        // ---- Decisions: adding them overrides a pin the strategy already made. ----
        "npm" => Admission::Decision(
            "Debian's npm pulls in its own Node — 18 on bookworm — plus a tree under \
             /usr/share/nodejs that a system-wide NODE_PATH puts ahead of everything, so a pinned \
             Node 10 loads modules written for 18 and aborts. `env/toolchain-crashed` on the M1 \
             corpus was exactly this.",
        ),
        "node" | "nodejs" => Admission::Decision(
            "the registry records the Node that published the package and the strategy installs \
             that one; an image's Node would shadow it and the run would measure a toolchain \
             nobody chose.",
        ),
        "yarn" | "pnpm" => {
            Admission::Decision("which resolver builds the dependency tree changes the tree.")
        }
        "rustc" | "cargo" => Admission::Decision(
            "the toolchain window is the whole question for a crate — see B20 — and a rustc from \
             the distribution is not the one the crate was published with.",
        ),
        "dotnet" | "dotnet-sdk" => Admission::Decision(
            "the SDK version decides the assembly, and it is not a distribution package anyway: \
             it arrives as a different parent image.",
        ),
        "go" => Admission::Decision(
            "the toolchain is recorded in the module and stamped into the binary.",
        ),
        "just" => Admission::Decision(
            "a task runner whose recipes are the build: installing it decides what runs.",
        ),

        // ---- Everything else. Fail closed. ----
        _ => Admission::Unknown,
    }
}

/// A strategy's logical system dependency, as this base image's packages.
///
/// A strategy names what it needs, not what a particular distribution calls it, because a strategy
/// that named Debian packages would be a strategy that only builds on Debian. The mapping is small
/// and only covers the cases where a logical name is not one package: `python3 -m venv` on Debian
/// needs `python3-venv` for ensurepip, which is not part of `python3` there and does not exist as a
/// separate package anywhere else. Without it the venv fails with Debian's own advice to run
/// `apt install python3.11-venv`, inside a container, which is not advice anyone can take.
fn expand(dep: &str, family: Family) -> Vec<String> {
    match (dep, family) {
        ("python3", Family::Debian) => vec!["python3".into(), "python3-venv".into()],
        // Debian names this after the soname, Alpine after the library. A strategy should not have
        // to know which distribution it will land on.
        ("libatomic", Family::Debian) => vec!["libatomic1".into()],

        // A C and C++ toolchain, under one neutral name for the same reason. Every distribution
        // ships this as a bundle and every one calls it something else; a strategy asking for
        // `gcc` on Alpine gets a compiler with no `make` and fails at the second step.
        ("cc", Family::Debian) => vec!["build-essential".into()],
        ("cc", Family::Alpine) => vec!["build-base".into()],
        ("cc", Family::Fedora) => vec!["gcc".into(), "gcc-c++".into(), "make".into()],

        // `Python.h`. Without it a C extension fails on a missing header rather than on a missing
        // package, which reads as the package being broken.
        ("python3-dev", Family::Fedora) => vec!["python3-devel".into()],

        ("pkg-config", Family::Alpine) => vec!["pkgconf".into()],
        ("pkg-config", Family::Fedora) => vec!["pkgconf-pkg-config".into()],

        ("ssh", Family::Debian | Family::Alpine) => vec!["openssh-client".into()],
        ("ssh", Family::Fedora) => vec!["openssh-clients".into()],

        _ => vec![dep.to_string()],
    }
}

/// Render the build context for a plan.
///
/// `defer_deps` moves the deps phase out of the image and into the container run. It exists for one
/// reason: rootless `podman build` cannot attach to a named network, refusing with "cannot use
/// networks as rootless", while `podman run` can. Under `mirror-only` egress the build's only route
/// out is a container on a named network, so the deps phase, which is exactly where a package
/// manager talks to the mirror, has to happen at run time.
///
/// The cost is real and worth stating: deps stops being a cached layer, so sibling versions of a
/// package no longer share one. That is the trade for an enforceable egress boundary on a laptop,
/// and it goes away wherever the builder can join a network, which is every fleet runner.
/// Printed after the deferred deps script and before the build, so a failure in one container can
/// be attributed to the phase it happened in. See where it is written for why `set -e` makes it a
/// fact rather than a guess.
pub const DEPS_DONE: &str = "trigon-deps-ok";

pub fn render(plan: &OciPlan, defer_deps: bool) -> BuildContext {
    let mut files = BTreeMap::new();
    let mut f = String::new();
    f.push_str(&format!("FROM {}\n\n", plan.base_image));

    let phase = |f: &mut String, files: &mut BTreeMap<String, String>, name: &str, body: &str| {
        if body.trim().is_empty() {
            return;
        }
        let file = format!("{name}.sh");
        // `set -eu` on every phase. Without `-e` a failing command in the middle of a phase leaves
        // the build running with a half-prepared tree, and the failure surfaces somewhere else.
        files.insert(file.clone(), format!("set -eu\n{}\n", body.trim()));
        f.push_str(&format!(
            "# {name}\nCOPY {file} /trigon/{file}\nRUN /bin/sh /trigon/{file}\n\n"
        ));
    };

    if !plan.system_deps.is_empty() {
        let deps: Vec<String> = plan.system_deps.iter().cloned().collect();
        // Install where there is a network to install from; verify where there is not. An enforced
        // tier has no network in the image build — that is what makes the tier mean what it says —
        // so the setup phase stops being an installation and becomes the check that somebody
        // already did it.
        // Install where there is a network to install from, verify where there is not — and at
        // `open`, **check before installing**, which is not the same thing as installing anyway.
        //
        // `apt-get update` is not free and on some images it is not possible: the .NET Core 3.1
        // SDK is built on Debian buster, whose archive has moved, so `update` exits 100. A package
        // published in 2019 therefore could not be built on the SDK that existed when it was
        // published — with every package it needed already in the image. Running the installer
        // only for what is genuinely absent costs one `dpkg -s` per name and removes that whole
        // class.
        let script = if plan.egress == crate::EgressTier::Open {
            install_missing_command(&plan.base_image, &deps)
        } else {
            verify_command(&plan.base_image, &deps)
        };
        phase(&mut f, &mut files, "setup", &script);
    }

    // The source, where the host fetched it. `COPY` rather than a clone is what lets the image
    // build run with no network at all — the source phase is a layer, and rootless `podman build`
    // cannot join the island, so a phase that needs the repository can only run inside the boundary
    // if the repository is already there.
    //
    // `.git` comes with it. The source phase's `git checkout --force <sha>` then stops being a
    // fetch and becomes the check that the copy landed on the commit the strategy names.
    if plan.source_tree.is_some() {
        f.push_str("COPY src /src\nRUN mkdir -p /out\nWORKDIR /src\n\n");
    } else {
        f.push_str("RUN mkdir -p /src /out\nWORKDIR /src\n\n");
    }

    phase(&mut f, &mut files, "source", &plan.source);
    if !defer_deps {
        phase(&mut f, &mut files, "deps", &plan.deps);
    } else if !plan.deps.trim().is_empty() {
        // Carried into the image but not run there.
        files.insert("deps.sh".into(), format!("set -eu\n{}\n", plan.deps.trim()));
        f.push_str("# deps: copied, run at container start (see `defer_deps`)\nCOPY deps.sh /trigon/deps.sh\n\n");
    }

    // The build is written, not run. This is the whole point of the pattern: everything above is a
    // cacheable layer, and only this happens fresh under the runtime's isolation.
    let mut build = String::from("set -eux\n");
    if defer_deps && !plan.deps.trim().is_empty() {
        build.push_str("/bin/sh /trigon/deps.sh\n");
        // **The phase boundary, as a fact rather than an inference.** With deps deferred both
        // phases run in one container and one log, and the attribution asked whether the deps
        // script had been *invoked* — true of every run that got that far — so every failure in
        // that container was reported as a deps failure. `stub42/pytz` installed its build frontend
        // successfully and then failed in `python -m build`, and the record said
        // `build-failed:deps`.
        //
        // `set -e` is what makes this a fact: the line below is unreachable if the deps script
        // exits non-zero. A phase label rather than a security control — a package that printed
        // this string during its own deps phase would relabel its failure as a build failure, and
        // the direction of that is harmless.
        build.push_str(&format!("echo {DEPS_DONE}\n"));
    }
    build.push_str(plan.build.trim());
    build.push('\n');
    build.push_str("mkdir -p /out\n");
    // Unquoted on purpose: `output_path` is frequently a glob such as `dist/*`, and quoting it
    // would make the shell look for a file with an asterisk in its name.
    build.push_str(&format!("cp -r /src/{} /out/\n", plan.output_path));
    files.insert("build.sh".into(), build);
    f.push_str("# build: written, not run\nCOPY build.sh /build\n");
    f.push_str("ENTRYPOINT [\"/bin/sh\", \"/build\"]\n");

    BuildContext {
        dockerfile: f,
        files,
    }
}

#[cfg(test)]
mod toolchain_expansion_tests {
    use super::install_command;

    /// The M1 corpus's most expensive cluster, as a package list.
    ///
    /// Five targets failed `command 'x86_64-linux-gnu-gcc' failed: No such file or directory`, one
    /// on `g++`, eight on `ssh: not found`. At an enforced tier the image build has no network, so
    /// none of them could be installed at the time they were wanted: the base image carries them or
    /// the target is unbuildable, and the failure reads as the package's fault either way.
    #[test]
    fn a_neutral_name_becomes_the_right_package_on_each_distribution() {
        let deps = [
            "cc".to_string(),
            "ssh".to_string(),
            "pkg-config".to_string(),
        ];

        let debian = install_command("docker.io/library/debian@sha256:abc", &deps);
        assert!(debian.contains("build-essential"), "{debian}");
        assert!(debian.contains("openssh-client"), "{debian}");
        assert!(debian.contains("apt-get"), "{debian}");

        let alpine = install_command("docker.io/library/alpine@sha256:abc", &deps);
        assert!(alpine.contains("build-base"), "{alpine}");
        assert!(alpine.contains("pkgconf"), "{alpine}");
        assert!(alpine.contains("apk add"), "{alpine}");

        let fedora = install_command("quay.io/fedora/fedora@sha256:abc", &deps);
        assert!(fedora.contains("gcc-c++"), "{fedora}");
        assert!(fedora.contains("openssh-clients"), "{fedora}");
        assert!(fedora.contains("dnf install"), "{fedora}");
    }

    #[test]
    fn a_c_toolchain_brings_make_with_it() {
        // `gcc` alone is the trap: a compiler with no `make` fails at the second step of every
        // extension build, which is why this is one neutral name and not three.
        for (img, want) in [
            ("docker.io/library/debian@sha256:a", "build-essential"),
            ("docker.io/library/alpine@sha256:a", "build-base"),
        ] {
            let cmd = install_command(img, &["cc".to_string()]);
            assert!(cmd.contains(want), "{img}: {cmd}");
        }
        let fedora = install_command("quay.io/fedora/fedora@sha256:a", &["cc".to_string()]);
        assert!(fedora.contains("make"), "{fedora}");
    }
}

#[cfg(test)]
mod admission_table {
    use super::*;

    /// Every logical name the strategy tree or `expand()` can produce must have a verdict.
    ///
    /// **The fail-closed side, asserted rather than hoped for.** `Unknown` refuses, so a name
    /// nobody classified cannot be installed — but a refusal discovered by an operator mid-sweep is
    /// a worse way to learn than a build failure here. This walks the real `needs:` lists rather
    /// than a copy of them, because a copy is the second thing that has to agree.
    #[test]
    fn every_name_the_tree_can_ask_for_has_a_verdict() {
        let tools = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crates/")
            .join("trigon-strategy")
            .join("tools");
        assert!(tools.is_dir(), "{} is not there", tools.display());

        let mut names: std::collections::BTreeSet<String> = Default::default();
        let mut stack = vec![tools];
        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(&dir).expect("readable").flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                if p.extension().is_none_or(|x| x != "yaml") {
                    continue;
                }
                let text = std::fs::read_to_string(&p).expect("readable");
                for line in text.lines() {
                    let t = line.trim();
                    // A line that explains why a `needs:` is wrong is documentation, not a need.
                    let Some(rest) = t.strip_prefix("needs:") else {
                        continue;
                    };
                    if t.starts_with('#') {
                        continue;
                    }
                    for n in rest.trim().trim_matches(['[', ']']).split(',') {
                        let n = n.trim();
                        if !n.is_empty() {
                            names.insert(n.to_string());
                        }
                    }
                }
            }
        }
        assert!(
            names.len() >= 5,
            "found only {names:?} — the walk is not reading the tree"
        );

        let unclassified: Vec<&String> = names
            .iter()
            .filter(|n| admission(n) == Admission::Unknown)
            .collect();
        assert!(
            unclassified.is_empty(),
            "these names appear in a `needs:` list and have no admission verdict: {unclassified:?}. \
             Add each to `admission()` as `Bytes` or `Decision`, with the reason — a name nobody \
             has classified must not reach an installer."
        );
    }

    #[test]
    fn the_default_package_floor_is_all_bytes() {
        // Whatever `trigon base-image` installs with no `--packages` is what automation would also
        // be asked for on a bare target. If any of it were a decision, `auto` would refuse the
        // common case and the two mechanisms would disagree about the same list.
        for dep in [
            "ca-certificates",
            "git",
            "libatomic",
            "python3",
            "wget",
            "cc",
            "python3-dev",
            "pkg-config",
            "ssh",
        ] {
            assert!(
                admission(dep).is_bytes(),
                "{dep} is in the default floor and is not admissible"
            );
        }
    }

    #[test]
    fn a_toolchain_the_registry_pinned_is_refused_with_its_reason() {
        // The hazard `docs/21` says must be closed before any apply path exists: `needs: [npm]`
        // appears in the tree, and an installer acting on it drags Debian's Node in behind it.
        let npm = admission("npm");
        assert!(matches!(npm, Admission::Decision(_)));
        let said = npm.refusal("npm").expect("a refusal");
        assert!(said.contains("NODE_PATH"), "{said}");
        assert!(said.contains("ADR-0012"), "{said}");

        for dep in [
            "node", "yarn", "pnpm", "rustc", "cargo", "dotnet", "go", "just",
        ] {
            assert!(
                !admission(dep).is_bytes(),
                "{dep} would be installed automatically"
            );
        }
    }

    #[test]
    fn a_name_nobody_classified_is_refused_rather_than_installed() {
        let v = admission("libpq-dev");
        assert_eq!(v, Admission::Unknown);
        let said = v.refusal("libpq-dev").expect("a refusal");
        assert!(said.contains("no admission verdict"), "{said}");
        // And `Bytes` is the only verdict that yields no refusal, so a caller that checks for
        // `None` cannot accidentally admit a `Decision`.
        assert!(admission("git").refusal("git").is_none());
    }
}

#[cfg(test)]
mod image_labels {
    use super::*;

    #[test]
    fn the_family_on_the_label_is_the_one_the_probe_would_use() {
        // The label is an index and the probe is the authority, but an index that disagreed with
        // the authority would be worse than no index — a selector would read `debian` off an
        // Alpine image and offer `dpkg -s` names for it.
        for (img, want) in [
            ("docker.io/library/debian@sha256:aa", "debian"),
            ("docker.io/library/alpine@sha256:bb", "alpine"),
            ("quay.io/fedora/fedora@sha256:cc", "fedora"),
            ("localhost/rocky@sha256:dd", "fedora"),
            ("mcr.microsoft.com/dotnet/sdk@sha256:ee", "debian"),
        ] {
            assert_eq!(family_of(img), want, "{img}");
            // And the probe agrees, which is the pairing that matters.
            let probe = verify_command(img, &["cc".to_string()]);
            let expected_query = match want {
                "alpine" => "apk info -e",
                "fedora" => "rpm -q",
                _ => "dpkg -s",
            };
            assert!(probe.contains(expected_query), "{img}: {probe}");
        }
    }
}

#[cfg(test)]
mod installing_only_what_is_absent {
    use super::*;

    /// At `open` egress the setup phase used to `apt-get update` whatever the image held.
    ///
    /// That is not merely wasteful. The .NET Core 3.1 SDK image — which a package published in
    /// 2019 correctly resolves to — is built on Debian buster, whose archive has moved, so
    /// `apt-get update` exits 100. The build failed with every package it needed already present.
    #[test]
    fn a_package_that_is_already_there_is_not_installed() {
        let script = install_missing_command(
            "docker.io/library/debian@sha256:aa",
            &["git".to_string(), "cc".to_string()],
        );
        // The check comes first and the installer is inside the branch, so an image that has
        // everything never reaches a package manager at all.
        let check_at = script.find("dpkg -s").expect("a check");
        let install_at = script.find("apt-get update").expect("an installer");
        assert!(check_at < install_at, "{script}");
        assert!(script.contains("if [ -n \"$missing\" ]"), "{script}");
        assert!(
            script.contains("already carries every package this build needs"),
            "{script}"
        );
        // The same expansion `install_command` would use, so the two cannot disagree about what a
        // logical name means.
        assert!(script.contains("build-essential"), "{script}");
    }

    #[test]
    fn the_family_decides_both_the_query_and_the_installer() {
        let alpine = install_missing_command("x/alpine@sha256:bb", &["cc".to_string()]);
        assert!(
            alpine.contains("apk info -e") && alpine.contains("apk add"),
            "{alpine}"
        );
        assert!(alpine.contains("build-base"), "{alpine}");

        let fedora = install_missing_command("x/fedora@sha256:cc", &["cc".to_string()]);
        assert!(
            fedora.contains("rpm -q") && fedora.contains("dnf install"),
            "{fedora}"
        );
    }
}

#[cfg(test)]
mod one_sniff {
    //! The distribution is read from the image reference once.
    //!
    //! It used to be read in four places — `verify_command`, `install_missing_command`,
    //! `install_command` and the public `family_of` — each carrying its own copy of the same
    //! `contains` chain with a different payload beside it. Four readings of one string is four
    //! chances to disagree, and a disagreement would surface as a build installing Debian package
    //! names on Fedora rather than as anything that looks like a bug in this file.

    use super::*;

    const IMAGES: &[(&str, &str)] = &[
        ("docker.io/library/alpine@sha256:aa", "alpine"),
        ("registry.fedoraproject.org/fedora:41", "fedora"),
        ("docker.io/rockylinux/rockylinux:9", "fedora"),
        ("quay.io/almalinux/almalinux:9", "fedora"),
        ("docker.io/library/debian:bookworm", "debian"),
        ("mcr.microsoft.com/dotnet/sdk:8.0", "debian"),
    ];

    #[test]
    fn every_builder_reads_the_same_family_from_one_image() {
        let deps = vec!["cc".to_string()];
        for (image, want) in IMAGES {
            assert_eq!(family_of(image), *want, "{image}");

            // Each builder emits its family's own package manager, so the command text is a
            // readable proxy for which family it decided on.
            let family = Family::of(image);
            let (query, install) = (family.query(), family.install());

            let verify = verify_command(image, &deps);
            assert!(verify.contains(query), "{image}: verify used another query");

            let missing = install_missing_command(image, &deps);
            assert!(missing.contains(query), "{image}: probe disagreed");
            assert!(missing.contains(install), "{image}: install disagreed");

            assert!(
                install_command(image, &deps).contains(install),
                "{image}: install_command disagreed"
            );
        }
    }

    /// An unrecognised image is Debian, and that is a decision rather than an accident.
    #[test]
    fn an_image_nobody_recognises_is_debian() {
        assert_eq!(family_of("example.invalid/something:1"), "debian");
    }

    /// The expansion keeps its order and drops repeats.
    ///
    /// Order is load-bearing: the list becomes a shell command, and arguments that reorder between
    /// runs produce an image layer that will not cache.
    #[test]
    fn packages_are_deduplicated_and_keep_their_order() {
        let family = Family::of("docker.io/library/debian:bookworm");
        let once = family.packages(&["cc".to_string()]);
        let twice = family.packages(&["cc".to_string(), "cc".to_string()]);
        assert_eq!(
            once, twice,
            "a repeated dependency added a repeated package"
        );
        assert!(
            !once.is_empty(),
            "`cc` should expand to something on Debian"
        );
    }
}
