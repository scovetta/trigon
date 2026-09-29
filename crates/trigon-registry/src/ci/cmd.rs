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
    /// Rewrites the working tree in place, before or between the modelled build steps.
    ///
    /// Separate from `Unknown` because the two say different things. `Unknown` is "we could not
    /// read this fragment"; this is "we read it, and it edited the source the build is about". A
    /// recipe that omits it describes a build of the tree as checked out, which is not the tree
    /// that was built.
    MutatesTree(String),
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
///
/// The keywords that run a command after them (`then sed -i …`) are here only for the line that
/// holds the keyword alone; with a command after it, the command is what [`classify_argv`] reads.
/// `read` is here for `while read -r f`, which sets a shell variable and nothing else. `env`,
/// `find`, `tee`, `touch` and `chmod` used to be here and are not: each can write into the tree,
/// and each has its own reader.
const INCIDENTAL: &[&str] = &[
    "if", "then", "else", "elif", "fi", "for", "while", "do", "done", "case", "esac", "exit",
    "true", "false", ":", "[", "[[", "test", "echo", "printf", "export", "unset", "set", "shopt",
    "source", ".", "cd", "pwd", "ls", "cat", "head", "tail", "sort", "grep", "awk", "tr", "wc",
    "mkdir", "rmdir", "sleep", "gh", "which", "type", "id", "umask", "df", "free", "uname", "read",
];

/// Classify one fragment, and then ask where its output goes.
///
/// `echo "__version__ = '1.2.3'" > pkg/_version.py` is an `echo` that rewrites a source file, and
/// is a common release-workflow idiom. The shell creates the file before the command runs, so a
/// build or an install redirected into the checkout has written there before the backend collects
/// the tree, and a backend that packs every file git does not ignore packs that one. Read as the
/// build, the write would vanish from the recipe, which is the direction this module refuses.
///
/// A publish keeps its reading, because it is how the publish step is found and it runs after the
/// artifact exists; so does a fragment already declined for a reason of its own, whose reason says
/// more than this one would.
fn classify(fragment: &str) -> Cmd {
    let c = classify_argv(&argv(fragment), fragment);
    let keeps_its_reading = matches!(
        c,
        Cmd::Publish(_)
            | Cmd::Unknown(_)
            | Cmd::PackageManager(_)
            | Cmd::GithubEnv { .. }
            | Cmd::MutatesTree(_)
    );
    match !keeps_its_reading && redirect_targets(fragment).iter().any(|t| in_tree(t)) {
        true => Cmd::MutatesTree(fragment.to_string()),
        false => c,
    }
}

/// `NAME=value`, a shell assignment rather than a command.
fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(n, _)| {
        !n.is_empty() && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    })
}

/// Where each unquoted `>` in a fragment sends its output, unquoted.
///
/// `>`, `>>`, `>|`, `2>`, `&>` all name a file. `2>&1` and `>&2` duplicate a descriptor and name
/// none. Inside `[[ … ]]` and `(( … ))` a `>` compares rather than writes.
fn redirect_targets(fragment: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut quote: Option<char> = None;
    // How deep inside `[[`/`((` we are, where `>` is a comparison.
    let mut test = 0usize;
    let mut chars = fragment.chars().peekable();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '\'' | '"') => quote = Some(c),
            (None, '\\') => {
                chars.next();
            }
            (None, '[' | '(') if chars.peek() == Some(&c) => {
                chars.next();
                test += 1;
            }
            (None, ']' | ')') if chars.peek() == Some(&c) && test > 0 => {
                chars.next();
                test -= 1;
            }
            (None, '>') if test == 0 => {
                if matches!(chars.peek(), Some('>' | '|')) {
                    chars.next();
                }
                if chars.peek() == Some(&'&') {
                    chars.next();
                    let descriptor = |c: &char| c.is_ascii_digit() || *c == '-';
                    if chars.peek().is_some_and(descriptor) {
                        while chars.peek().is_some_and(descriptor) {
                            chars.next();
                        }
                        continue;
                    }
                }
                while chars.peek().is_some_and(|c| c.is_whitespace()) {
                    chars.next();
                }
                let mut word = String::new();
                let mut q: Option<char> = None;
                while let Some(&c) = chars.peek() {
                    match (q, c) {
                        (Some(open), c) if c == open => q = None,
                        (Some(_), c) => word.push(c),
                        (None, '\'' | '"') => q = Some(c),
                        (None, c) if c.is_whitespace() || "<>|&;()".contains(c) => break,
                        (None, c) => word.push(c),
                    }
                    chars.next();
                }
                out.push(word);
            }
            (None, _) => {}
        }
    }
    out
}

/// Whether a path a command writes to lies in the checkout the build reads.
///
/// A relative path does, and so does `$GITHUB_WORKSPACE`; so does a variable this does not know,
/// which could be anywhere and is read on the side where a wrong answer costs a rung rather than a
/// verdict. A device and the runner's command files (`$GITHUB_OUTPUT` and the rest) do not. Nor,
/// here, does what is plainly outside the checkout — an absolute path, the home directory, the
/// runner's temporary directory — which is read as it was before this looked at writes at all:
/// whether a write there can reach the artifact (a `pip.conf` in the home directory can, a
/// `.pypirc` cannot) is not settled.
fn in_tree(path: &str) -> bool {
    match path.strip_prefix('$') {
        Some(var) => {
            let var = var.strip_prefix('{').unwrap_or(var);
            let name: String = var
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            !matches!(
                name.as_str(),
                "GITHUB_ENV"
                    | "GITHUB_OUTPUT"
                    | "GITHUB_PATH"
                    | "GITHUB_STATE"
                    | "GITHUB_STEP_SUMMARY"
                    | "HOME"
                    | "RUNNER_TEMP"
                    | "RUNNER_TOOL_CACHE"
                    | "TMPDIR"
            )
        }
        None => !path.starts_with('/') && !path.starts_with('~'),
    }
}

/// [`classify`], over a fragment already split into argv. `fragment` is what a message quotes.
fn classify_argv(all: &[String], fragment: &str) -> Cmd {
    // `NAME=value cmd …` runs `cmd` with one variable set, and the variable is not the command.
    // Without this, a build step written as `SOURCE_DATE_EPOCH=0 python -m build` classifies as
    // `Unknown` and the whole recipe declines over a shell idiom — which is how the fixture with a
    // secret in front of `python -m build` first read as "this job builds nothing" rather than as
    // the secret decline it is.
    let env_prefixes = all.iter().take_while(|a| is_assignment(a)).count();
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
        "twine" => twine(&rest, fragment),
        "uv" => uv(&rest, fragment),
        "npm" => npm(&rest, fragment),
        "pnpm" => Cmd::PackageManager("pnpm"),
        "yarn" => Cmd::PackageManager("yarn"),
        "bun" => Cmd::PackageManager("bun"),
        "sed" | "perl" => match in_place(&rest) {
            true => Cmd::MutatesTree(fragment.to_string()),
            false => Cmd::Incidental,
        },
        "patch" => Cmd::MutatesTree(fragment.to_string()),
        "git" => git(&rest, fragment),
        "curl" | "wget" => Cmd::Network(fragment.to_string()),
        "apt-get" | "apt" => system_deps(args),
        "sudo" => sudo(&args[1..], fragment),
        "env" => env(&args[1..], fragment),
        // A keyword that runs the command after it. `if [ -n "$V" ]; then sed -i … setup.py; fi`
        // on one line puts `then sed -i … setup.py` in one fragment, and read by its keyword the
        // rewrite was incidental.
        "if" | "then" | "else" | "elif" | "do" | "while" | "until" | "!" if args.len() > 1 => {
            classify_argv(&args[1..], fragment)
        }
        "find" => find(&rest, fragment),
        "tee" => writes_to(&rest, &[], fragment),
        "touch" => writes_to(
            &rest,
            &["-d", "-t", "-r", "--date", "--reference"],
            fragment,
        ),
        "chmod" => chmod(&rest, fragment),
        // Arithmetic, which sets shell variables at most: `while (( n > 0 ))`.
        h if h.starts_with("((") => Cmd::Incidental,
        h if INCIDENTAL.contains(&h) => Cmd::Incidental,
        _ => Cmd::Unknown(fragment.to_string()),
    }
}

/// Whether `sed`/`perl` was told to edit files rather than write to stdout.
///
/// `-i`, `--in-place`, and the bundled short forms `-Ei`, `-i.bak`, `-ni`. A long option taking a
/// value (`--expression=…`) is not scanned for an `i`.
fn in_place(rest: &[&str]) -> bool {
    rest.iter().any(|a| {
        if let Some(long) = a.strip_prefix("--") {
            return long == "in-place" || long.starts_with("in-place=");
        }
        match a.strip_prefix('-') {
            // `-` alone is stdin, and `--` alone ends the options.
            Some(short) if !short.is_empty() && !short.starts_with('-') => {
                short.split('=').next().unwrap_or(short).contains('i')
            }
            _ => false,
        }
    })
}

/// `git`, which is incidental when it reports and a tree rewrite when it writes.
///
/// The prior art's definitions directory has
/// `git checkout 'da0306d^' -- requests_toolbelt/adapters/appengine.py` as a *build instruction*,
/// with a comment explaining that the published wheel was built from a working tree still holding
/// a file deleted two commits earlier. That is exactly the shape that must not read as incidental.
fn git(rest: &[&str], fragment: &str) -> Cmd {
    const WRITES: &[&str] = &[
        "checkout",
        "apply",
        "am",
        "cherry-pick",
        "revert",
        "reset",
        "restore",
        "merge",
        "rebase",
        "stash",
        "clean",
        "submodule",
        "switch",
    ];
    // Global options come before the subcommand, and these take their value as the next argument.
    // Read as the subcommand, the value hid it: `git -C src apply fix.patch` found `src`, which is
    // no subcommand at all, and the rewrite was dropped as incidental.
    const TAKES_VALUE: &[&str] = &[
        "-C",
        "-c",
        "--git-dir",
        "--work-tree",
        "--namespace",
        "--config-env",
    ];
    let mut args = rest.iter();
    let sub = loop {
        match args.next() {
            Some(a) if TAKES_VALUE.contains(a) => {
                args.next();
            }
            Some(a) if a.starts_with('-') => {}
            other => break other,
        }
    };
    match sub {
        Some(sub) if WRITES.contains(sub) => Cmd::MutatesTree(fragment.to_string()),
        _ => Cmd::Incidental,
    }
}

/// `twine`, which is a publisher only when it is uploading.
///
/// The subcommand is the whole of it. `twine check dist/*` validates the long description renders
/// and touches no index, and the packaging guide tells people to write it immediately before the
/// upload — so classifying every `twine` as a publish made the *check* the first publish marker in
/// the job. The real upload then fell on the build side of that boundary, which put its token in
/// `secrets_in_build` (a decline) and, worse, put `twine upload` itself into the recipe's steps:
/// a rebuild lowered from it would publish to PyPI.
///
/// Anything else stays `Unknown` rather than becoming `Incidental`. `twine register` contacts the
/// index, and a subcommand we have not seen is not one we can call harmless.
fn twine(rest: &[&str], fragment: &str) -> Cmd {
    match rest.iter().find(|a| !a.starts_with('-')) {
        Some(&"upload") => Cmd::Publish(fragment.to_string()),
        Some(&"check") => Cmd::Incidental,
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
        ["-m", "twine", tail @ ..] => twine(tail, fragment),
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

/// `sudo`, which runs the command after it: that command is what gets classified.
///
/// `sudo` used to go to [`system_deps`] whole, which answers `Incidental` for anything that is not
/// an install — so `sudo sed -i …`, `sudo git apply …` and `sudo python setup.py install` all
/// disappeared from the recipe, which is the silent direction this module exists to avoid. With
/// nothing after the options there is no command to read, and that is `Unknown` rather than a
/// guess.
fn sudo(rest: &[String], fragment: &str) -> Cmd {
    // The options that take a separate value, so the value is not read as the command.
    const TAKES_VALUE: &[&str] = &["-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-T", "-U"];
    let mut i = 0;
    while let Some(a) = rest.get(i).filter(|a| a.starts_with('-')) {
        i += if TAKES_VALUE.contains(&a.as_str()) {
            2
        } else {
            1
        };
    }
    match rest.get(i..) {
        Some(command) if !command.is_empty() => classify_argv(command, fragment),
        _ => Cmd::Unknown(fragment.to_string()),
    }
}

/// `env`, which like [`sudo`] runs the command after it once its options and assignments are read.
///
/// `env` was on the incidental list whole, so `env SOURCE_DATE_EPOCH=0 git apply fix.patch` left
/// the recipe the way `sudo git apply` used to. With no command after them, `env` prints the
/// environment and is incidental. `-S` hides the command inside one argument, which this does not
/// split, so it is `Unknown`.
fn env(rest: &[String], fragment: &str) -> Cmd {
    const TAKES_VALUE: &[&str] = &["-u", "--unset", "-C", "--chdir"];
    let mut i = 0;
    while let Some(a) = rest.get(i) {
        if a.starts_with("-S") || a.starts_with("--split-string") {
            return Cmd::Unknown(fragment.to_string());
        }
        if TAKES_VALUE.contains(&a.as_str()) {
            i += 2;
        } else if a.starts_with('-') || is_assignment(a) {
            i += 1;
        } else {
            break;
        }
    }
    match rest.get(i..) {
        Some(command) if !command.is_empty() => classify_argv(command, fragment),
        _ => Cmd::Incidental,
    }
}

/// `find`, which reads until it is told to act: `-delete` removes files, `-fprint` and its kin
/// write one, and `-exec` runs a command that is read as if it stood alone.
fn find(rest: &[&str], fragment: &str) -> Cmd {
    // The starting points come before the first expression, and `.` when there are none.
    let starts: Vec<&str> = rest
        .iter()
        .take_while(|a| !a.starts_with('-') && !matches!(**a, "(" | ")" | "!" | "\\(" | "\\!"))
        .copied()
        .collect();
    let starts_in_tree = starts.is_empty() || starts.iter().any(|s| in_tree(s));
    let mut i = starts.len();
    while let Some(a) = rest.get(i) {
        i += 1;
        match *a {
            "-delete" if starts_in_tree => return Cmd::MutatesTree(fragment.to_string()),
            "-fprint" | "-fprint0" | "-fprintf" | "-fls" => {
                if rest.get(i).is_some_and(|f| in_tree(f)) {
                    return Cmd::MutatesTree(fragment.to_string());
                }
            }
            "-exec" | "-execdir" | "-ok" | "-okdir" => {
                let command: Vec<String> = rest[i..]
                    .iter()
                    .take_while(|a| !matches!(**a, ";" | "\\;" | "\\" | "+"))
                    .map(|a| (*a).to_string())
                    .collect();
                i += command.len();
                match classify_argv(&command, fragment) {
                    Cmd::Incidental => {}
                    other => return other,
                }
            }
            _ => {}
        }
    }
    Cmd::Incidental
}

/// A command whose operands are files it writes: `tee`, `touch`. Into the tree is a rewrite; to
/// stdout alone, or only outside the checkout, it is read as before (see [`in_tree`]).
fn writes_to(rest: &[&str], takes_value: &[&str], fragment: &str) -> Cmd {
    let mut files = Vec::new();
    let mut args = rest.iter();
    while let Some(a) = args.next() {
        if takes_value.contains(a) {
            args.next();
        } else if !a.starts_with('-') {
            files.push(*a);
        }
    }
    match files.iter().any(|f| in_tree(f)) {
        true => Cmd::MutatesTree(fragment.to_string()),
        false => Cmd::Incidental,
    }
}

/// `chmod MODE FILE…`. A mode is part of the tree as git records it, and of every tar member.
///
/// The mode is the first operand, and may start with `-` (`chmod -x f`), so it is told from an
/// option by its letters rather than by its dash; `--reference=F` stands in for it.
fn chmod(rest: &[&str], fragment: &str) -> Cmd {
    let is_mode = |a: &str| {
        a.strip_prefix('-').is_some_and(|m| {
            !m.is_empty() && m.chars().all(|c| "rwxXstugoa+-=,01234567".contains(c))
        })
    };
    let mut mode_given = rest.iter().any(|a| a.starts_with("--reference"));
    let mut files = Vec::new();
    for a in rest {
        if a.starts_with('-') && !is_mode(a) {
            continue;
        }
        if mode_given {
            files.push(*a);
        } else {
            mode_given = true;
        }
    }
    match files.iter().any(|f| in_tree(f)) {
        true => Cmd::MutatesTree(fragment.to_string()),
        false => Cmd::Incidental,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn one(script: &str) -> Cmd {
        let mut got = classify_script(script);
        assert_eq!(got.len(), 1, "{script:?} split into {got:?}");
        got.remove(0)
    }

    #[test]
    fn a_script_splits_on_unquoted_operators_and_not_on_quoted_ones() {
        // Splitting inside quotes would turn one command into two fragments, and a half-command is
        // `Unknown`. Comments and blank lines are not fragments at all.
        let got = classify_script(
            "# build it\necho \"a && b; c | d\" && python -m build\n\nnpm pack || true ; twine check dist/*",
        );
        assert_eq!(got.len(), 5, "{got:?}");
        assert_eq!(got[0], Cmd::Incidental);
        assert!(matches!(got[1], Cmd::PyBuild { .. }), "{got:?}");
        assert_eq!(got[2], Cmd::NpmPack);
        assert_eq!(got[3], Cmd::Incidental);
        assert_eq!(got[4], Cmd::Incidental, "`twine check` touches no index");
        // A single `&` backgrounds rather than chains, and is kept inside the fragment.
        assert_eq!(classify_script("sleep 1 & wait").len(), 1);
    }

    #[test]
    fn the_python_frontends_are_read_with_their_options() {
        assert_eq!(
            one("python -m build --sdist --outdir out pkg/sub"),
            Cmd::PyBuild {
                wheel: false,
                sdist: true,
                outdir: Some("out".into()),
                dir: Some("pkg/sub".into()),
            }
        );
        assert_eq!(
            one("python3.12 -m build -w -o=wheelhouse"),
            Cmd::PyBuild {
                wheel: true,
                sdist: false,
                outdir: Some("wheelhouse".into()),
                dir: None,
            }
        );
        assert_eq!(
            one("pyproject-build --wheel ."),
            Cmd::PyBuild {
                wheel: true,
                sdist: false,
                outdir: None,
                dir: Some(".".into()),
            }
        );
        // The value after `--python` and `--python-preference` is not the project directory.
        assert_eq!(
            one(
                "uv build --python 3.14 --python-preference only-managed --sdist --wheel . --out-dir dist"
            ),
            Cmd::UvBuild {
                wheel: true,
                sdist: true,
                outdir: Some("dist".into()),
                python: Some("3.14".into()),
                dir: Some(".".into()),
            }
        );
        assert_eq!(
            one("uv build -p 3.12 -o out"),
            Cmd::UvBuild {
                wheel: false,
                sdist: false,
                outdir: Some("out".into()),
                python: Some("3.12".into()),
                dir: None,
            }
        );
    }

    #[test]
    fn installs_publishes_and_checks_are_told_apart() {
        for (script, want) in [
            ("pip install -r requirements.txt", "deps"),
            ("python -m pip install build", "deps"),
            ("uv pip install .", "deps"),
            ("uv sync --frozen", "deps"),
            ("pip --version", "incidental"),
            ("python -m pip list", "incidental"),
            ("python -m venv .venv", "incidental"),
            ("python -m pytest -q", "incidental"),
            ("python -c 'print(1)'", "incidental"),
            ("uv venv", "incidental"),
            ("npm test", "incidental"),
            ("twine upload dist/*", "publish"),
            ("python -m twine upload --skip-existing dist/*", "publish"),
            ("uv publish", "publish"),
            ("npm publish --provenance", "publish"),
            ("twine register dist/x.whl", "unknown"),
            ("python setup.py sdist", "unknown"),
            ("uv tool run nox", "unknown"),
            ("npm dedupe", "unknown"),
            ("make dist", "unknown"),
        ] {
            let got = one(script);
            let kind = match &got {
                Cmd::PyDeps(_) => "deps",
                Cmd::Incidental => "incidental",
                Cmd::Publish(f) => {
                    assert_eq!(f, script, "the publish fragment is quoted whole");
                    "publish"
                }
                Cmd::Unknown(f) => {
                    assert_eq!(f, script);
                    "unknown"
                }
                other => panic!("{script}: {other:?}"),
            };
            assert_eq!(kind, want, "{script}");
        }
    }

    #[test]
    fn npm_commands_are_read_for_what_the_release_ran() {
        assert_eq!(one("npm ci"), Cmd::NpmInstall { frozen: true });
        assert_eq!(one("npm install"), Cmd::NpmInstall { frozen: false });
        assert_eq!(one("npm i --no-audit"), Cmd::NpmInstall { frozen: false });
        assert_eq!(one("npm run build -- --prod"), Cmd::NpmRun("build".into()));
        assert_eq!(one("npm run-script compile"), Cmd::NpmRun("compile".into()));
        assert!(one("npm run build").is_build());
        assert!(!one("npm ci").is_build());
        for (script, manager) in [
            ("pnpm build", "pnpm"),
            ("yarn build", "yarn"),
            ("bun run x", "bun"),
        ] {
            assert_eq!(one(script), Cmd::PackageManager(manager), "{script}");
        }
    }

    #[test]
    fn an_environment_prefix_is_not_the_command() {
        // `SOURCE_DATE_EPOCH=0 python -m build` is a build. Read as `Unknown`, the recipe declined
        // over a shell idiom.
        assert!(matches!(
            one("SOURCE_DATE_EPOCH=0 PYTHONHASHSEED=0 python -m build"),
            Cmd::PyBuild { .. }
        ));
        // A fragment that is nothing but assignments is not a command either.
        assert_eq!(one("FOO=bar"), Cmd::Unknown("FOO=bar".into()));
    }

    #[test]
    fn an_export_into_github_env_is_kept_rather_than_dropped_as_an_echo() {
        // `flask` sets `SOURCE_DATE_EPOCH` this way, and it changes every later step.
        assert_eq!(
            one("echo \"SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)\" >> $GITHUB_ENV"),
            Cmd::GithubEnv {
                name: "SOURCE_DATE_EPOCH".into(),
                value: "$(git log -1 --pretty=%ct)".into(),
            }
        );
    }

    #[test]
    fn a_command_that_rewrites_the_tree_is_never_incidental() {
        for script in [
            "sed -i 's/0.0.0/1.2.3/' setup.py",
            "sed -Ei.bak s/a/b/ f",
            "sed --in-place=.orig s/a/b/ f",
            "perl -pi -e 's/a/b/' f",
            "patch -p1 < fix.diff",
            "git checkout 'da0306d^' -- requests_toolbelt/adapters/appengine.py",
            "git apply fix.patch",
            "git -c core.autocrlf=false checkout -- .",
            // `env` runs the command after it, as `sudo` does.
            "env git apply fix.patch",
            "env FOO=1 sed -i s/a/b/ f",
            "env -u HOME -i SOURCE_DATE_EPOCH=0 git apply fix.patch",
            // `find` acts on what it finds.
            "find . -name x -exec sed -i s/a/b/ {} +",
            "find src -name '*.pyc' -delete",
            "find -name '*.orig' -delete",
            "find . -name '*.py' -fprint pkg/FILES",
            // A write into the checkout, by whatever program makes it.
            "echo \"__version__ = '1'\" > pkg/_version.py",
            "echo 1.2.3>>pkg/VERSION",
            "printf '[metadata]\\nversion = 1\\n' > setup.cfg",
            "cat > setup.cfg",
            "echo 1.2.3 2> pkg/VERSION",
            "tee pkg/VERSION",
            "tee -a CHANGELOG.md /dev/null",
            "touch pkg/py.typed",
            "touch -d 2024-01-01 pkg/__init__.py",
            "chmod +x pkg/bin/tool",
            "chmod -x pkg/bin/tool",
            "chmod -R u+w .",
            "chmod --reference=setup.py pkg/bin/tool",
        ] {
            assert_eq!(one(script), Cmd::MutatesTree(script.into()), "{script}");
        }
        // And the read-only shapes of the same programs stay incidental.
        for script in [
            "sed -n 1p setup.py",
            "sed --expression=s/i/j/ f",
            "sed - f",
            "git describe --tags",
            "git status",
            "env",
            "env FOO=1",
            "find . -name '*.whl'",
            "find dist -name '*.whl' -exec ls -l {} +",
            "tee",
        ] {
            assert_eq!(one(script), Cmd::Incidental, "{script}");
        }
    }

    #[test]
    fn a_write_is_a_rewrite_where_it_lands_in_the_checkout_and_not_where_the_runner_reads_it() {
        // The runner's command files and the null device are where an `echo` goes in every release
        // workflow, and none of them is the tree.
        for script in [
            "echo \"tag=$(git tag --points-at HEAD)\" >> \"$GITHUB_OUTPUT\"",
            "echo x >> $GITHUB_OUTPUT",
            "echo x >> ${GITHUB_STEP_SUMMARY}",
            "echo \"$HOME/.local/bin\" >> $GITHUB_PATH",
            "tee -a \"$GITHUB_STEP_SUMMARY\"",
            "echo done > /dev/null 2>&1",
            "echo oops >&2",
            "echo oops 1>&2",
            "echo x &> /dev/null",
            // Quoted, a `>` is text.
            "echo 'a > b'",
            "echo \"a > b\"",
            // Escaped, it is text too.
            "echo a \\> b",
        ] {
            assert_eq!(one(script), Cmd::Incidental, "{script}");
        }
        // Inside `[[ … ]]` and `(( … ))` it compares.
        assert_eq!(one("if [[ \"$A\" > \"$B\" ]]"), Cmd::Incidental);
        assert_eq!(one("while (( n > 0 ))"), Cmd::Incidental);
        // A build or an install whose output lands in the checkout wrote there before the backend
        // collected the tree; whose output is thrown away, it is still the build.
        for script in [
            "python -m build --sdist > build.log 2>&1",
            "npm pack --json > pack.json",
            "pip install -r requirements.txt > pip.log",
            "curl -sSL https://example.invalid/data.json > src/pkg/data.json",
        ] {
            assert_eq!(one(script), Cmd::MutatesTree(script.into()), "{script}");
        }
        assert!(matches!(
            one("python -m build --sdist > /dev/null 2>&1"),
            Cmd::PyBuild { sdist: true, .. }
        ));
        // A publish is still the publish, which is how its step is found, and it runs once the
        // artifact exists.
        assert_eq!(
            one("twine upload dist/* > upload.log"),
            Cmd::Publish("twine upload dist/* > upload.log".into())
        );
    }

    #[test]
    fn env_and_the_shell_keywords_are_read_as_the_command_they_run() {
        // `then sed -i …` on one line was read by its keyword, and the rewrite was incidental.
        assert_eq!(
            one("then sed -i s/a/b/ setup.py"),
            Cmd::MutatesTree("then sed -i s/a/b/ setup.py".into())
        );
        assert_eq!(
            one("do git apply \"$p\""),
            Cmd::MutatesTree("do git apply \"$p\"".into())
        );
        assert!(matches!(
            one("then python -m build --wheel"),
            Cmd::PyBuild { wheel: true, .. }
        ));
        assert!(matches!(
            one("env SOURCE_DATE_EPOCH=0 python -m build"),
            Cmd::PyBuild { .. }
        ));
        // What the keyword or `env` runs is read with the same rules as standing alone: a command
        // nobody recognises is `Unknown` there too, rather than incidental for having a prefix.
        for script in [
            "then python setup.py sdist",
            "else ./build.sh",
            "env -i PATH=/usr/bin python setup.py sdist",
            "if make dist",
            // The command is inside one argument, which is not split.
            "env -S 'git apply fix.patch'",
        ] {
            assert_eq!(one(script), Cmd::Unknown(script.into()), "{script}");
        }
        // And the harmless shapes stay harmless.
        for script in [
            "if [ -n \"$V\" ]",
            "if ! git diff --quiet",
            "while read -r f",
            "until test -f done",
            "then",
            "else",
            "do echo \"$f\"",
            "if gh release view \"$V\" > /dev/null 2>&1",
        ] {
            assert_eq!(one(script), Cmd::Incidental, "{script}");
        }
    }

    #[test]
    fn a_git_option_value_is_not_read_as_the_subcommand() {
        // `git -C <dir> apply` found `<dir>` as the subcommand, which is no subcommand at all, and
        // the patch was dropped from the recipe as incidental: a rebuild of the tree as checked
        // out, reported as a rebuild of the tree that was built.
        for script in [
            "git -C src apply ../fix.patch",
            "git -C . checkout -- setup.py",
            "git --git-dir .git --work-tree pkg restore setup.py",
            "git -c advice.detachedHead=false -C vendor/lib reset --hard v1.0",
        ] {
            assert_eq!(one(script), Cmd::MutatesTree(script.into()), "{script}");
        }
        assert_eq!(one("git -C src log -1"), Cmd::Incidental);
        assert_eq!(one("git -C src"), Cmd::Incidental);
    }

    #[test]
    fn sudo_is_read_as_the_command_it_runs() {
        // `sudo` went to the apt reader whole, which answers `Incidental` for anything that is not
        // an install: `sudo sed -i` rewrote the tree and the recipe never knew.
        assert_eq!(
            one("sudo sed -i s/a/b/ setup.py"),
            Cmd::MutatesTree("sudo sed -i s/a/b/ setup.py".into())
        );
        assert_eq!(
            one("sudo -E git apply fix.patch"),
            Cmd::MutatesTree("sudo -E git apply fix.patch".into())
        );
        assert_eq!(
            one("sudo -u builder python setup.py install"),
            Cmd::Unknown("sudo -u builder python setup.py install".into())
        );
        assert_eq!(
            one("sudo pip install cffi"),
            Cmd::PyDeps("sudo pip install cffi".into())
        );
        // The apt shapes it was written for still read as they did.
        assert_eq!(
            one("sudo apt-get install -y libffi-dev pkg-config"),
            Cmd::SystemDeps(vec!["libffi-dev".into(), "pkg-config".into()])
        );
        assert_eq!(
            one("sudo -E apt-get install -y libxml2-dev"),
            Cmd::SystemDeps(vec!["libxml2-dev".into()])
        );
        assert_eq!(one("sudo apt-get update"), Cmd::Incidental);
        assert_eq!(
            one("apt install -y"),
            Cmd::Incidental,
            "an install of nothing"
        );
        // With nothing after the options there is no command to read.
        assert_eq!(one("sudo -v"), Cmd::Unknown("sudo -v".into()));
    }

    #[test]
    fn a_fetch_is_network_and_the_rest_is_unknown() {
        assert_eq!(
            classify_script("curl -sSL https://example.invalid/x.tgz | tar xz"),
            [
                Cmd::Network("curl -sSL https://example.invalid/x.tgz".into()),
                Cmd::Unknown("tar xz".into())
            ]
        );
        assert_eq!(
            one("wget -q https://example.invalid/tool"),
            Cmd::Network("wget -q https://example.invalid/tool".into())
        );
        assert_eq!(
            one("./build.sh --release"),
            Cmd::Unknown("./build.sh --release".into())
        );
    }
}
