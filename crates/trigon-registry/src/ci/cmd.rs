//! What a `run:` block is actually doing, at the granularity a strategy can act on.
//!
//! A workflow's `run:` is a shell script, and we are not going to interpret a shell. What we do is
//! recognise the handful of shapes that carry meaning for a rebuild — a PEP 517 frontend, an npm
//! pack, a dependency install, a publish — and classify everything else as [`Cmd::Unknown`], which
//! is the input to a decline rather than to a guess.
//!
//! The asymmetry is deliberate. A fragment we misclassify as incidental disappears silently and the
//! rebuild is missing a step; a fragment we classify as unknown produces a decline and the
//! heuristic rung below answers instead. The second failure costs a rung, the first costs a wrong
//! verdict, so the `Incidental` list is short, explicit, and confined to commands that cannot
//! change what ends up in the artifact.

/// One recognised shell fragment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cmd {
    /// `python -m build`, `pyproject-build`.
    PyBuild {
        wheel: bool,
        sdist: bool,
        outdir: Option<String>,
        dir: Option<String>,
    },
    /// `uv build`. A different PEP 517 frontend driving the same backend, which is why lowering it
    /// to our `pypi/build/wheel` is an approximation worth stating rather than a transcription.
    UvBuild {
        wheel: bool,
        sdist: bool,
        outdir: Option<String>,
        python: Option<String>,
        dir: Option<String>,
    },
    NpmPack,
    NpmRun(String),
    NpmInstall {
        /// `npm ci` resolves nothing: the lockfile is the answer. That makes it the one npm case
        /// where `Claim::RegistryMomentIs { Lockfile }` is true rather than aspirational.
        frozen: bool,
    },
    /// Installing Python packages. Not a build, and not incidental either: it reaches the network.
    PyDeps(String),
    /// System packages, which `FlowStrategy`'s `Step::needs` can actually carry.
    SystemDeps(Vec<String>),
    /// The step that made it public. Identified here so job selection and build analysis agree on
    /// which step is the publish step and neither has to re-derive it.
    Publish(String),
    /// pnpm, yarn, bun. Recognised precisely so the rung can decline for a stated reason instead of
    /// lowering `pnpm build` to `npm run build` and calling the difference an approximation.
    PackageManager(&'static str),
    /// `echo X=… >> $GITHUB_ENV`, which sets an environment variable for every later step.
    GithubEnv {
        name: String,
        value: String,
    },
    /// A fetch from somewhere. Feeds `Claim::RequiresNetwork` and the egress tier.
    Network(String),
    /// Cannot change what ends up in the artifact.
    Incidental,
    /// Everything else. The input to `Decline::NoToolForBuildCommand`.
    Unknown(String),
}

impl Cmd {
    /// Whether this fragment is the thing that produces the artifact.
    pub fn is_build(&self) -> bool {
        matches!(
            self,
            Cmd::PyBuild { .. } | Cmd::UvBuild { .. } | Cmd::NpmPack | Cmd::NpmRun(_)
        )
    }
}

/// Split a shell script into fragments and classify each one.
///
/// Splitting is on newlines and on the unquoted operators `&&`, `||`, `;` and `|`. Quote tracking
/// is single-level and deliberately naive; it exists so that `echo "a && b"` does not split, not so
/// that this becomes a shell. A construct it gets wrong produces extra fragments, which produce
/// `Unknown`, which produces a decline — the safe direction.
pub fn classify_script(script: &str) -> Vec<Cmd> {
    fragments(script).iter().map(|f| classify(f)).collect()
}

fn fragments(script: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut chars = script.chars().peekable();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), c) if c == q => {
                quote = None;
                cur.push(c);
            }
            (Some(_), c) => cur.push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                cur.push(c);
            }
            (None, '\n' | ';') => {
                out.push(std::mem::take(&mut cur));
            }
            (None, '&') if chars.peek() == Some(&'&') => {
                chars.next();
                out.push(std::mem::take(&mut cur));
            }
            (None, '|') => {
                if chars.peek() == Some(&'|') {
                    chars.next();
                }
                out.push(std::mem::take(&mut cur));
            }
            (None, c) => cur.push(c),
        }
    }
    out.push(cur);
    out.into_iter()
        .map(|f| f.trim().to_string())
        .filter(|f| !f.is_empty() && !f.starts_with('#'))
        .collect()
}

/// Split a fragment into argv, honouring quotes well enough to keep a quoted path together.
fn argv(fragment: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    for c in fragment.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => cur.push(c),
            (None, '\'' | '"') => quote = Some(c),
            (None, c) if c.is_whitespace() => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            (None, c) => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Shell keywords and commands that cannot change the artifact.
///
/// Short on purpose. `git` and `gh` are here because a release workflow uses them to read the tag
/// and cut a GitHub release, neither of which is the package build; a `git apply` would slip
/// through, which is the known cost and the reason the list is reviewed rather than grown casually.
const INCIDENTAL: &[&str] = &[
    "if", "then", "else", "elif", "fi", "for", "while", "do", "done", "case", "esac", "exit",
    "true", "false", ":", "[", "[[", "test", "echo", "printf", "export", "unset", "set", "shopt",
    "source", ".", "cd", "pwd", "ls", "cat", "head", "tail", "sort", "tee", "grep", "sed", "awk",
    "tr", "wc", "mkdir", "rmdir", "touch", "chmod", "find", "sleep", "env", "git", "gh", "which",
    "type", "id", "umask", "df", "free", "uname",
];

fn classify(fragment: &str) -> Cmd {
    let all = argv(fragment);
    // `NAME=value cmd …` runs `cmd` with one variable set, and the variable is not the command.
    // Without this, a build step written as `SOURCE_DATE_EPOCH=0 python -m build` classifies as
    // `Unknown` and the whole recipe declines over a shell idiom — which is how the fixture with a
    // secret in front of `python -m build` first read as "this job builds nothing" rather than as
    // the secret decline it is.
    let env_prefixes = all
        .iter()
        .take_while(|a| {
            a.split_once('=').is_some_and(|(n, _)| {
                !n.is_empty() && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            })
        })
        .count();
    let args = &all[env_prefixes.min(all.len().saturating_sub(1))..];
    let Some(head) = args.first().map(String::as_str) else {
        return Cmd::Incidental;
    };
    let rest: Vec<&str> = args[1..].iter().map(String::as_str).collect();

    // `echo NAME=value >> $GITHUB_ENV` before the incidental check, because an `echo` into
    // `GITHUB_ENV` is the one echo that changes every later step. `flask` sets `SOURCE_DATE_EPOCH`
    // this way, and treating it as incidental would silently drop the single most consequential
    // environment variable in Python packaging reproducibility.
    if fragment.contains("GITHUB_ENV")
        && let Some(assign) = all.iter().find(|a| a.contains('='))
        && let Some((name, value)) = assign.split_once('=')
        && !name.is_empty()
    {
        return Cmd::GithubEnv {
            name: name.trim().to_string(),
            value: value.trim().to_string(),
        };
    }

    match head {
        "python" | "python3" | "py" => python(&rest, fragment),
        h if h.starts_with("python3.") => python(&rest, fragment),
        "pip" | "pip3" | "pipx" => match rest.first() {
            Some(&"install") => Cmd::PyDeps(fragment.to_string()),
            _ => Cmd::Incidental,
        },
        "pyproject-build" => Cmd::PyBuild {
            wheel: flag(&rest, "--wheel") || flag(&rest, "-w"),
            sdist: flag(&rest, "--sdist") || flag(&rest, "-s"),
            outdir: opt(&rest, "--outdir").or_else(|| opt(&rest, "-o")),
            dir: positional(&rest),
        },
        "twine" => Cmd::Publish(fragment.to_string()),
        "uv" => uv(&rest, fragment),
        "npm" => npm(&rest, fragment),
        "pnpm" => Cmd::PackageManager("pnpm"),
        "yarn" => Cmd::PackageManager("yarn"),
        "bun" => Cmd::PackageManager("bun"),
        "curl" | "wget" => Cmd::Network(fragment.to_string()),
        "apt-get" | "apt" | "sudo" => system_deps(args),
        h if INCIDENTAL.contains(&h) => Cmd::Incidental,
        _ => Cmd::Unknown(fragment.to_string()),
    }
}

fn python(rest: &[&str], fragment: &str) -> Cmd {
    match rest {
        ["-m", "build", tail @ ..] => Cmd::PyBuild {
            wheel: flag(tail, "--wheel") || flag(tail, "-w"),
            sdist: flag(tail, "--sdist") || flag(tail, "-s"),
            outdir: opt(tail, "--outdir").or_else(|| opt(tail, "-o")),
            dir: positional(tail),
        },
        ["-m", "pip", "install", ..] => Cmd::PyDeps(fragment.to_string()),
        ["-m", "pip", ..] => Cmd::Incidental,
        ["-m", "twine", ..] => Cmd::Publish(fragment.to_string()),
        ["-m", "venv", ..] => Cmd::Incidental,
        // Checks rather than builds. A test suite that writes into the source tree would slip
        // through here; that is a narrower hazard than declining every release workflow that lints
        // before it publishes, which is most of them.
        [
            "-m",
            "pytest" | "mypy" | "flake8" | "ruff" | "black" | "isort",
            ..,
        ] => Cmd::Incidental,
        ["-c", ..] => Cmd::Incidental,
        _ => Cmd::Unknown(fragment.to_string()),
    }
}

fn uv(rest: &[&str], fragment: &str) -> Cmd {
    match rest.first() {
        Some(&"build") => {
            let tail = &rest[1..];
            Cmd::UvBuild {
                wheel: flag(tail, "--wheel"),
                sdist: flag(tail, "--sdist"),
                outdir: opt(tail, "--out-dir").or_else(|| opt(tail, "-o")),
                python: opt(tail, "--python").or_else(|| opt(tail, "-p")),
                dir: positional(tail),
            }
        }
        Some(&"publish") => Cmd::Publish(fragment.to_string()),
        Some(&"pip") | Some(&"sync") | Some(&"lock") => Cmd::PyDeps(fragment.to_string()),
        Some(&"venv") => Cmd::Incidental,
        _ => Cmd::Unknown(fragment.to_string()),
    }
}

fn npm(rest: &[&str], fragment: &str) -> Cmd {
    match rest {
        ["publish", ..] => Cmd::Publish(fragment.to_string()),
        ["pack", ..] => Cmd::NpmPack,
        ["ci", ..] => Cmd::NpmInstall { frozen: true },
        ["install" | "i" | "install-ci-test", ..] => Cmd::NpmInstall { frozen: false },
        ["run" | "run-script", script, ..] => Cmd::NpmRun((*script).to_string()),
        [
            "config" | "whoami" | "version" | "test" | "audit" | "ping",
            ..,
        ] => Cmd::Incidental,
        _ => Cmd::Unknown(fragment.to_string()),
    }
}

/// `apt-get install -y a b c`, whose package names `FlowStrategy` can carry on `Step::needs`.
fn system_deps(args: &[String]) -> Cmd {
    let mut it = args.iter().map(String::as_str).peekable();
    // Step over `sudo` and the tool name.
    while matches!(it.peek(), Some(&"sudo") | Some(&"apt-get") | Some(&"apt")) {
        it.next();
    }
    if it.peek() != Some(&"install") {
        return Cmd::Incidental;
    }
    it.next();
    let names: Vec<String> = it
        .filter(|a| !a.starts_with('-'))
        .map(|a| a.to_string())
        .collect();
    if names.is_empty() {
        Cmd::Incidental
    } else {
        Cmd::SystemDeps(names)
    }
}

fn flag(args: &[&str], name: &str) -> bool {
    args.contains(&name)
}

/// `--name value` or `--name=value`.
fn opt(args: &[&str], name: &str) -> Option<String> {
    let eq = format!("{name}=");
    for (i, a) in args.iter().enumerate() {
        if let Some(v) = a.strip_prefix(&eq) {
            return Some(v.to_string());
        }
        if *a == name {
            return args.get(i + 1).map(|v| (*v).to_string());
        }
    }
    None
}

/// The first argument that is not a flag and is not a flag's value.
///
/// `uv build --python 3.14 --python-preference only-managed --sdist --wheel . --out-dir dist` has
/// exactly one, and it is `.`. Getting this wrong would read `only-managed` as the project
/// directory, so the scan skips the value after any `--flag` that is known to take one.
fn positional(args: &[&str]) -> Option<String> {
    const TAKES_VALUE: &[&str] = &[
        "--outdir",
        "-o",
        "--out-dir",
        "--python",
        "-p",
        "--python-preference",
        "--config-setting",
        "-C",
        "--installer",
        "--index",
        "--build-constraint",
    ];
    let mut skip = false;
    for a in args {
        if skip {
            skip = false;
            continue;
        }
        if a.starts_with('-') {
            skip = TAKES_VALUE.contains(a);
            continue;
        }
        return Some((*a).to_string());
    }
    None
}
