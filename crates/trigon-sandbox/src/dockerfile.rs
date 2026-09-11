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

/// The package manager for a base image, chosen by what the image name says it is.
///
/// A guess, and it is allowed to be: a wrong guess fails in the setup phase with the package
/// manager's own error, which is a legible failure. Silently skipping the install is not, because
/// the build then fails later for a reason that looks like the package's fault.
fn install_command(base_image: &str, deps: &[String]) -> String {
    let img = base_image.to_ascii_lowercase();
    let (family, install) = if img.contains("alpine") {
        (Family::Alpine, "apk add --no-cache")
    } else if img.contains("fedora") || img.contains("rocky") || img.contains("almalinux") {
        (Family::Fedora, "dnf install -y")
    } else {
        (
            Family::Debian,
            "apt-get update && apt-get install -y --no-install-recommends",
        )
    };
    let mut names: Vec<String> = Vec::new();
    for d in deps {
        for n in expand(d, family) {
            if !names.contains(&n) {
                names.push(n);
            }
        }
    }
    format!("{install} {}", names.join(" "))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    Debian,
    Alpine,
    Fedora,
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
        phase(
            &mut f,
            &mut files,
            "setup",
            &install_command(&plan.base_image, &deps),
        );
    }

    f.push_str("RUN mkdir -p /src /out\nWORKDIR /src\n\n");

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
