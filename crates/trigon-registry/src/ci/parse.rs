//! GitHub Actions YAML into an intermediate the rest of the module can reason about.
//!
//! Walked by hand off `serde_yaml_ng::Value` rather than through a derived `Deserialize`, and that
//! is not a style choice. The schema is polymorphic in the places that matter: `on:` is a string, a
//! sequence or a mapping; `runs-on:` is a string, a sequence or a mapping with a `labels` key;
//! `strategy.matrix` is open-ended by design; `with:` values are whatever the action's author
//! wrote. A derived struct would either refuse half the real workflows in
//! `tests/fixtures/workflows/` or be a wall of `#[serde(untagged)]` enums that report "data did not
//! match any variant" with no path when they fail, which is the message `docs/04` §2.2 spends a
//! page arguing against.
//!
//! The one rule the walk enforces everywhere: **a version field is a YAML string or an integer and
//! never a float.** `python-version: 3.10` unquoted parses as the float `3.1` in every YAML 1.2
//! parser, `serde_yaml_ng` included — checked, not assumed. Reading a version through a parsed
//! number would claim Python 3.1 with CI authority behind it.

use std::collections::{BTreeMap, BTreeSet};

use serde_yaml_ng::Value;

use super::recipe::TriggerKind;

/// How many matrix cells we will expand before giving up on a job.
///
/// A cross product is multiplicative and a workflow can write a large one by accident;
/// `pyca/cryptography`'s wheel matrix runs to dozens of cells. The cap is not a correctness
/// boundary — a job we truncate simply produces fewer candidate recipes — but an unbounded product
/// over a file a package controls is a memory bomb in a sweep.
const MAX_MATRIX_CELLS: usize = 48;

/// A `with:` value, keeping the distinction between "the author wrote a string" and "the author
/// wrote a number", because for version fields those are different claims.
#[derive(Clone, Debug, PartialEq)]
pub enum Scalar {
    Str(String),
    Int(i64),
    /// Kept as the raw text we would have had to print, not as an `f64`, so a caller can quote what
    /// the author actually wrote when it refuses to use it.
    Float(String),
    Bool(bool),
    /// A sequence or a mapping. Carried so `python-version: [3.11, 3.12]` is visibly a list rather
    /// than silently absent.
    Compound,
}

impl Scalar {
    /// The value as text, for a field where text is all that is wanted.
    pub fn text(&self) -> Option<String> {
        match self {
            Scalar::Str(s) => Some(s.clone()),
            Scalar::Int(i) => Some(i.to_string()),
            Scalar::Bool(b) => Some(b.to_string()),
            Scalar::Float(_) | Scalar::Compound => None,
        }
    }

    /// The value as a version, refusing a float.
    ///
    /// Returns `Err(raw)` for a float so the caller can say why it declined rather than behaving as
    /// if the field were absent. The difference shows up in `six`'s `python-version: '3.13'`
    /// (quoted, fine) against the many workflows that write `python-version: 3.10` (a float, and
    /// `3.1` by the time it reaches us).
    pub fn version_text(&self) -> Result<Option<String>, String> {
        match self {
            Scalar::Float(raw) => Err(raw.clone()),
            other => Ok(other.text()),
        }
    }
}

fn scalar(v: &Value) -> Scalar {
    match v {
        Value::String(s) => Scalar::Str(s.clone()),
        Value::Bool(b) => Scalar::Bool(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Scalar::Int(i)
            } else {
                Scalar::Float(n.to_string())
            }
        }
        Value::Null => Scalar::Str(String::new()),
        _ => Scalar::Compound,
    }
}

fn get<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    v.get(Value::String(key.to_string()))
}

/// String-valued mapping entries, dropping anything that is not a scalar.
fn string_map(v: Option<&Value>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Some(Value::Mapping(m)) = v else {
        return out;
    };
    for (k, val) in m {
        let (Value::String(k), Some(text)) = (k, scalar(val).text()) else {
            continue;
        };
        out.insert(k.clone(), text);
    }
    out
}

/// A scalar, a sequence of scalars, or a mapping's keys — all flattened to a list of strings.
fn as_list(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Sequence(seq)) => seq.iter().filter_map(|x| scalar(x).text()).collect(),
        Some(Value::Mapping(m)) => m
            .keys()
            .filter_map(|k| match k {
                Value::String(s) => Some(s.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

#[derive(Clone, Debug)]
pub struct RawStep {
    pub name: Option<String>,
    /// The whole `org/repo@ref`, unsplit. Splitting is the allowlist's job.
    pub uses: Option<String>,
    pub run: Option<String>,
    pub with: BTreeMap<String, Scalar>,
    pub env: BTreeMap<String, String>,
    pub working_directory: Option<String>,
    pub if_expr: Option<String>,
}

impl RawStep {
    /// `(action, ref)`. An action with no `@` (a local `./path`) reports an empty ref.
    pub fn action(&self) -> Option<(String, String)> {
        let u = self.uses.as_ref()?;
        Some(match u.split_once('@') {
            Some((a, r)) => (a.to_string(), r.to_string()),
            None => (u.clone(), String::new()),
        })
    }

    /// A human-facing label for this step, for a message.
    pub fn label(&self) -> String {
        self.name
            .clone()
            .or_else(|| self.uses.clone())
            .or_else(|| {
                self.run
                    .as_ref()
                    .map(|r| r.lines().next().unwrap_or("").trim().to_string())
            })
            .unwrap_or_else(|| "(unnamed step)".into())
    }
}

#[derive(Clone, Debug)]
pub struct Job {
    pub id: String,
    pub needs: Vec<String>,
    /// Raw labels, possibly containing `${{ matrix.os }}`. Resolved per cell.
    pub runs_on: Vec<String>,
    pub container: Option<String>,
    pub env: BTreeMap<String, String>,
    /// Expanded matrix cells. Always at least one entry; a job with no matrix has one empty cell,
    /// so every downstream loop is the same loop.
    pub cells: Vec<BTreeMap<String, String>>,
    /// `outputs:` verbatim, expressions and all. Needed to answer "which job produced this
    /// artifact id", which is how `flask` joins its build job to its publish job.
    pub outputs: BTreeMap<String, String>,
    pub defaults_working_directory: Option<String>,
    pub steps: Vec<RawStep>,
}

impl Workflow {
    /// What to call this file in a message.
    ///
    /// The declared `name:` where there is one, because that is what a person sees in the Actions
    /// UI and what they will search for; the path otherwise.
    pub fn title(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.path)
    }
}

#[derive(Clone, Debug)]
pub struct Workflow {
    pub path: String,
    pub name: Option<String>,
    pub triggers: Vec<TriggerKind>,
    pub env: BTreeMap<String, String>,
    /// Defaults declared for `workflow_dispatch` / `workflow_call` inputs, which is the only part
    /// of `inputs.*` that is knowable without observing a run.
    pub input_defaults: BTreeMap<String, String>,
    pub jobs: Vec<Job>,
}

/// Parse one workflow file. A file that is not a mapping, or has no `jobs:`, yields `None`.
///
/// Never an error. A `.github/workflows` directory holds whatever someone put there — a README, a
/// half-written file, a template with Jinja in it — and a rung that failed the whole read because
/// one file did not parse would lose the release workflow sitting next to it.
pub fn parse_workflow(path: &str, text: &str) -> Option<Workflow> {
    let doc: Value = serde_yaml_ng::from_str(text).ok()?;
    let jobs_val = get(&doc, "jobs")?;
    let Value::Mapping(job_map) = jobs_val else {
        return None;
    };

    // `on:` normally survives as the string key "on" under YAML 1.2 core, which is what
    // `serde_yaml_ng` implements. A YAML 1.1 parser would fold it to the boolean `true`, and the
    // workflows in the wild are written for whichever GitHub uses — so both spellings are looked
    // for rather than one, because a missing `on:` silently costs every trigger-rank point a job
    // could have earned and the failure looks like bad ranking rather than a parse miss.
    let on = get(&doc, "on").or_else(|| doc.get(Value::Bool(true)));

    let mut jobs = Vec::new();
    for (id, j) in job_map {
        let Value::String(id) = id else { continue };
        jobs.push(parse_job(id, j));
    }

    Some(Workflow {
        path: path.to_string(),
        name: get(&doc, "name").and_then(|v| scalar(v).text()),
        triggers: parse_triggers(on),
        env: string_map(get(&doc, "env")),
        input_defaults: parse_input_defaults(on),
        jobs,
    })
}

/// `on:` in each of its three shapes.
fn parse_triggers(on: Option<&Value>) -> Vec<TriggerKind> {
    let mut out = Vec::new();
    match on {
        Some(Value::String(s)) => out.push(named_trigger(s)),
        Some(Value::Sequence(seq)) => {
            for v in seq {
                if let Some(s) = scalar(v).text() {
                    out.push(named_trigger(&s));
                }
            }
        }
        Some(Value::Mapping(m)) => {
            for (k, v) in m {
                let Value::String(k) = k else { continue };
                match k.as_str() {
                    // `push` splits by what it is filtered on. A push to a tag is a release path
                    // and a push to a branch is CI, and they are different enough that collapsing
                    // them loses the discriminator: `attrs` filters on both in one entry, and
                    // `vercel/ms` publishes on a branch push, which is why `BranchPush` still ranks
                    // above nothing at all.
                    "push" => {
                        let tags = !as_list(get(v, "tags")).is_empty()
                            || !as_list(get(v, "tags-ignore")).is_empty();
                        let branches = !as_list(get(v, "branches")).is_empty();
                        if tags {
                            out.push(TriggerKind::TagPush);
                        }
                        if branches || !tags {
                            out.push(TriggerKind::BranchPush);
                        }
                    }
                    "release" => {
                        let types = as_list(get(v, "types"));
                        if types.is_empty() || types.iter().any(|t| t == "published") {
                            out.push(TriggerKind::ReleasePublished);
                        } else {
                            out.push(TriggerKind::Other(format!("release:{}", types.join("+"))));
                        }
                    }
                    other => out.push(named_trigger(other)),
                }
            }
        }
        _ => {}
    }
    out.sort();
    out.dedup();
    out
}

fn named_trigger(name: &str) -> TriggerKind {
    match name {
        "push" => TriggerKind::BranchPush,
        "pull_request" | "pull_request_target" => TriggerKind::PullRequest,
        "release" => TriggerKind::ReleasePublished,
        "workflow_dispatch" => TriggerKind::Dispatch,
        "workflow_call" => TriggerKind::Call,
        "schedule" => TriggerKind::Schedule,
        other => TriggerKind::Other(other.to_string()),
    }
}

/// Declared defaults for `workflow_dispatch` and `workflow_call` inputs.
///
/// An input with a default is knowable; one without is whatever a human typed, and
/// `pypa/packaging` requires exactly that (`ref`, "Full git commit SHA"). An expression over an
/// input with no default stays unresolved, which is the correct answer rather than a limitation.
fn parse_input_defaults(on: Option<&Value>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Some(Value::Mapping(m)) = on else {
        return out;
    };
    for key in ["workflow_dispatch", "workflow_call"] {
        let Some(Value::Mapping(inputs)) = m
            .get(Value::String(key.into()))
            .and_then(|v| get(v, "inputs"))
        else {
            continue;
        };
        for (name, spec) in inputs {
            let (Value::String(name), Some(d)) = (name, get(spec, "default")) else {
                continue;
            };
            if let Some(text) = scalar(d).text() {
                out.insert(name.clone(), text);
            }
        }
    }
    out
}

fn parse_job(id: &str, j: &Value) -> Job {
    let runs_on = match get(j, "runs-on") {
        // `runs-on: { group: …, labels: [...] }` is the large-runner shape.
        Some(v @ Value::Mapping(_)) => as_list(get(v, "labels")),
        other => as_list(other),
    };

    let container = match get(j, "container") {
        Some(Value::String(s)) => Some(s.clone()),
        Some(v @ Value::Mapping(_)) => get(v, "image").and_then(|i| scalar(i).text()),
        _ => None,
    };

    let steps = match get(j, "steps") {
        Some(Value::Sequence(seq)) => seq.iter().map(parse_step).collect(),
        _ => Vec::new(),
    };

    Job {
        id: id.to_string(),
        needs: as_list(get(j, "needs")),
        runs_on,
        container,
        env: string_map(get(j, "env")),
        cells: expand_matrix(get(j, "strategy").and_then(|s| get(s, "matrix"))),
        outputs: string_map(get(j, "outputs")),
        defaults_working_directory: get(j, "defaults")
            .and_then(|d| get(d, "run"))
            .and_then(|r| get(r, "working-directory"))
            .and_then(|w| scalar(w).text()),
        steps,
    }
}

fn parse_step(s: &Value) -> RawStep {
    let with = match get(s, "with") {
        Some(Value::Mapping(m)) => m
            .iter()
            .filter_map(|(k, v)| match k {
                Value::String(k) => Some((k.clone(), scalar(v))),
                _ => None,
            })
            .collect(),
        _ => BTreeMap::new(),
    };
    RawStep {
        name: get(s, "name").and_then(|v| scalar(v).text()),
        uses: get(s, "uses").and_then(|v| scalar(v).text()),
        run: get(s, "run").and_then(|v| scalar(v).text()),
        with,
        env: string_map(get(s, "env")),
        working_directory: get(s, "working-directory").and_then(|v| scalar(v).text()),
        if_expr: get(s, "if").and_then(|v| scalar(v).text()),
    }
}

/// The matrix, as a list of concrete cells.
///
/// Cross product of every scalar-sequence key, then `exclude` removed, then `include` merged — in
/// that order, because Actions processes `include` after `exclude` so that an `include` can add
/// back a cell an `exclude` took out. The full Actions semantics for `include` are baroque — an
/// entry is added to every original cell whose *original* values it does not overwrite (values an
/// earlier `include` added can be overwritten), and an entry that fits no original cell appends
/// one — and they are implemented that way here because the common use is a per-cell extra
/// (`python-version` alongside `os`) and getting it wrong would attach the wrong toolchain to the
/// wrong platform.
///
/// It used to require an entry to share a key with a cell before extending it, so
/// `include: [{python-version: '3.12'}]` beside `os: [ubuntu-latest, windows-latest]` became a
/// third cell with a Python and no runner, while the two real cells had no Python at all.
fn expand_matrix(matrix: Option<&Value>) -> Vec<BTreeMap<String, String>> {
    let empty = vec![BTreeMap::new()];
    let Some(Value::Mapping(m)) = matrix else {
        return empty;
    };

    let mut cells: Vec<BTreeMap<String, String>> = vec![BTreeMap::new()];
    let mut original: BTreeSet<String> = BTreeSet::new();
    for (k, v) in m {
        let Value::String(k) = k else { continue };
        if k == "include" || k == "exclude" {
            continue;
        }
        let values = match v {
            Value::Sequence(seq) => seq.iter().filter_map(|x| scalar(x).text()).collect(),
            other => scalar(other).text().into_iter().collect::<Vec<_>>(),
        };
        if values.is_empty() {
            continue;
        }
        original.insert(k.clone());
        let mut next = Vec::with_capacity(cells.len() * values.len());
        for cell in &cells {
            for val in &values {
                if next.len() >= MAX_MATRIX_CELLS {
                    break;
                }
                let mut c = cell.clone();
                c.insert(k.clone(), val.clone());
                next.push(c);
            }
        }
        cells = next;
    }
    // A matrix of nothing but `include` has no original cells: each entry is a cell of its own.
    if original.is_empty() {
        cells.clear();
    }

    if let Some(Value::Sequence(exc)) = m.get(Value::String("exclude".into())) {
        let drops: Vec<BTreeMap<String, String>> =
            exc.iter().map(|e| string_map(Some(e))).collect();
        cells.retain(|cell| {
            !drops
                .iter()
                .any(|d| !d.is_empty() && d.iter().all(|(k, v)| cell.get(k) == Some(v)))
        });
    }

    if let Some(Value::Sequence(inc)) = m.get(Value::String("include".into())) {
        // Only the cells of the cross product are extended. A cell an earlier entry appended is
        // not one a later entry can join: Actions' own example keeps `{fruit: banana}` and
        // `{fruit: banana, animal: cat}` apart.
        let originals = cells.len();
        for entry in inc {
            let add = string_map(Some(entry));
            if add.is_empty() {
                continue;
            }
            let mut matched = false;
            for cell in cells.iter_mut().take(originals) {
                let keeps_the_original = add
                    .iter()
                    .all(|(k, v)| !original.contains(k) || cell.get(k) == Some(v));
                if keeps_the_original {
                    matched = true;
                    for (k, v) in &add {
                        cell.insert(k.clone(), v.clone());
                    }
                }
            }
            if !matched && cells.len() < MAX_MATRIX_CELLS {
                cells.push(add);
            }
        }
    }

    if cells.is_empty() { empty } else { cells }
}

/// What an expression could be resolved against.
pub struct ExprCtx<'a> {
    /// Workflow `env` merged under job `env` merged under step `env`, already flattened.
    pub env: &'a BTreeMap<String, String>,
    pub matrix: &'a BTreeMap<String, String>,
    pub inputs: &'a BTreeMap<String, String>,
}

/// Resolve `${{ }}` interpolations, or say which one defeated us.
///
/// The subset is deliberately small: `env.X`, `matrix.X`, `inputs.X`, `github.workspace`, and a
/// quoted literal. Everything else — `steps.*.outputs`, `needs.*.outputs`, `fromJSON`, any function
/// call, `github.event.*` — is unresolvable, and the caller is expected to decline rather than
/// substitute a guess. A strategy that renders with a literal `${{ }}` in it is a build that fails
/// in a way that reads like the package's fault.
///
/// Returns `Err(the first unresolved expression)`.
pub fn resolve(raw: &str, ctx: &ExprCtx<'_>) -> Result<String, String> {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(start) = rest.find("${{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 3..];
        let Some(end) = after.find("}}") else {
            // An unterminated `${{` is not an expression; it is text that happens to start like
            // one. Copy it through and stop looking.
            out.push_str(&rest[start..]);
            return Ok(out);
        };
        let expr = after[..end].trim();
        match lookup(expr, ctx) {
            Some(v) => out.push_str(&v),
            None => return Err(format!("${{{{ {expr} }}}}")),
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

fn lookup(expr: &str, ctx: &ExprCtx<'_>) -> Option<String> {
    let e = expr.trim();
    if let Some(lit) = e.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
        return Some(lit.to_string());
    }
    // `a || b` is Actions' coalescing operator and appears in almost every `concurrency:` group.
    // Nothing load-bearing uses it, so it is left unresolved rather than approximated.
    if e.contains("||") || e.contains("&&") || e.contains('(') {
        return None;
    }
    let (head, tail) = e.split_once('.')?;
    match head {
        "env" => ctx.env.get(tail).cloned(),
        "matrix" => ctx.matrix.get(tail).cloned(),
        "inputs" => ctx.inputs.get(tail).cloned(),
        // `github.event.inputs.X` is the older spelling of `inputs.X` and means the same thing.
        "github" if tail.starts_with("event.inputs.") => ctx
            .inputs
            .get(tail.trim_start_matches("event.inputs."))
            .cloned(),
        // Actions runs every job with the workspace as the working directory, so this is the
        // relative root. Resolving it to `.` keeps a path like `${{ github.workspace }}/dist`
        // usable instead of forcing a decline over a constant.
        "github" if tail == "workspace" => Some(".".into()),
        _ => None,
    }
}

/// `needs.<job>.outputs.<name>`, which names a producing job directly.
///
/// The one expression shape we read for its *structure* rather than its value. `flask`'s publish
/// job downloads by `artifact-ids: ${{ needs.build.outputs.artifact-id }}`, so the artifact name
/// never appears anywhere and a name-matching edge finds nothing; the expression itself is the
/// edge, and it is exact rather than heuristic.
pub fn needs_output_producer(raw: &str) -> Option<(String, String)> {
    let start = raw.find("${{")?;
    let after = &raw[start + 3..];
    let end = after.find("}}")?;
    let expr = after[..end].trim();
    let rest = expr.strip_prefix("needs.")?;
    let (job, tail) = rest.split_once('.')?;
    let output = tail.strip_prefix("outputs.")?;
    (!output.is_empty()).then(|| (job.to_string(), output.to_string()))
}

/// Every `secrets.NAME` referenced in a blob of text.
///
/// Scanned rather than parsed, because a secret can appear in a `run:` body, in an `env:` value or
/// inside an `if:`, and all three mean the same thing: this step reads something we do not have.
pub fn secrets_in(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut rest = text;
    while let Some(i) = rest.find("secrets.") {
        // `i` and the marker are ASCII, and a secret name is ASCII by GitHub's own rule, so every
        // index arrived at here is a char boundary. Slicing by a character count instead would
        // panic mid-codepoint on a workflow with a non-ASCII step name, which several of the
        // fixtures have (`platformdirs` names its steps with emoji).
        let name: String = rest[i + "secrets.".len()..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        rest = &rest[i + "secrets.".len() + name.len()..];
        if !name.is_empty() {
            out.insert(name);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matrix(yaml: &str) -> Vec<BTreeMap<String, String>> {
        let v: Value = serde_yaml_ng::from_str(yaml).unwrap();
        expand_matrix(Some(&v))
    }

    fn cell(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn include_follows_the_actions_documentation_example_exactly() {
        // The example GitHub's own documentation gives for `include`, with the result it states.
        // An entry sharing no key with the matrix (`color: green`) extends every cell; one that
        // would overwrite an original value (`fruit: banana`) appends a cell; a value an earlier
        // entry added (`color`) can be overwritten; an appended cell is never extended.
        let got = matrix(
            "fruit: [apple, pear]\nanimal: [cat, dog]\ninclude:\n  - color: green\n  \
             - color: pink\n    animal: cat\n  - fruit: apple\n    shape: circle\n  \
             - fruit: banana\n  - fruit: banana\n    animal: cat\n",
        );
        let want = vec![
            cell(&[
                ("fruit", "apple"),
                ("animal", "cat"),
                ("color", "pink"),
                ("shape", "circle"),
            ]),
            cell(&[
                ("fruit", "apple"),
                ("animal", "dog"),
                ("color", "green"),
                ("shape", "circle"),
            ]),
            cell(&[("fruit", "pear"), ("animal", "cat"), ("color", "pink")]),
            cell(&[("fruit", "pear"), ("animal", "dog"), ("color", "green")]),
            cell(&[("fruit", "banana")]),
            cell(&[("fruit", "banana"), ("animal", "cat")]),
        ];
        assert_eq!(got, want);
    }

    #[test]
    fn a_per_cell_extra_goes_to_every_cell_it_does_not_contradict() {
        // The shape that matters for a toolchain: an interpreter named once beside a list of
        // runners belongs to every runner, not to a runner-less cell of its own.
        let got =
            matrix("os: [ubuntu-latest, windows-latest]\ninclude:\n  - python-version: '3.12'\n");
        assert_eq!(
            got,
            vec![
                cell(&[("os", "ubuntu-latest"), ("python-version", "3.12")]),
                cell(&[("os", "windows-latest"), ("python-version", "3.12")]),
            ]
        );
    }

    #[test]
    fn a_matrix_of_only_includes_has_one_cell_per_entry() {
        let got =
            matrix("include:\n  - os: ubuntu-22.04\n    python: '3.11'\n  - target: aarch64\n");
        assert_eq!(
            got,
            vec![
                cell(&[("os", "ubuntu-22.04"), ("python", "3.11")]),
                cell(&[("target", "aarch64")]),
            ]
        );
    }

    #[test]
    fn exclude_drops_partial_matches_and_include_can_add_a_cell_back() {
        // Actions processes `include` after `exclude`, so this is how a workflow adds back one
        // combination it excluded wholesale — with an extra key it wanted on that one cell.
        let got = matrix(
            "os: [ubuntu-latest, windows-latest]\npython: ['3.11', '3.12']\nexclude:\n  \
             - os: windows-latest\ninclude:\n  - os: windows-latest\n    python: '3.12'\n    \
             experimental: 'true'\n",
        );
        assert_eq!(
            got,
            vec![
                cell(&[("os", "ubuntu-latest"), ("python", "3.11")]),
                cell(&[("os", "ubuntu-latest"), ("python", "3.12")]),
                cell(&[
                    ("os", "windows-latest"),
                    ("python", "3.12"),
                    ("experimental", "true")
                ]),
            ]
        );
        // An empty exclude entry excludes nothing, rather than everything.
        assert_eq!(matrix("os: [a, b]\nexclude:\n  - {}\n").len(), 2);
    }

    #[test]
    fn a_matrix_is_bounded_and_a_non_mapping_is_one_empty_cell() {
        // A cross product over a file a package controls is a memory bomb in a sweep.
        let got = matrix("a: [1, 2, 3, 4, 5, 6, 7, 8]\nb: [1, 2, 3, 4, 5, 6, 7, 8]\n");
        assert_eq!(got.len(), MAX_MATRIX_CELLS);
        // `matrix: ${{ fromJSON(...) }}` is a string; there is nothing to expand, and a job still
        // has one cell so every loop downstream is the same loop.
        assert_eq!(
            matrix("'${{ fromJSON(needs.plan.outputs.m) }}'"),
            vec![cell(&[])]
        );
        assert_eq!(expand_matrix(None), vec![cell(&[])]);
        // A key whose value is a scalar is a one-value axis; one that is a mapping is no axis.
        assert_eq!(
            matrix("os: ubuntu-latest\nextra: {a: b}\n"),
            vec![cell(&[("os", "ubuntu-latest")])]
        );
    }

    #[test]
    fn a_file_that_is_not_a_workflow_is_skipped_rather_than_failing_the_read() {
        // A `.github/workflows` directory holds whatever someone put there.
        for text in [
            "",
            "not: [valid",
            "name: no jobs\non: push\n",
            "jobs: [a, b]\n",
            "{{ jinja }}\n",
        ] {
            assert!(parse_workflow("w.yml", text).is_none(), "{text:?}");
        }
    }

    fn triggers(on: &str) -> Vec<TriggerKind> {
        let text = format!("{on}\njobs:\n  a:\n    runs-on: ubuntu-latest\n");
        parse_workflow("w.yml", &text).unwrap().triggers
    }

    #[test]
    fn every_shape_of_on_is_read_and_a_tag_push_is_told_from_a_branch_push() {
        assert_eq!(triggers("on: push"), [TriggerKind::BranchPush]);
        assert_eq!(
            triggers("on: [push, pull_request_target, workflow_call, schedule, gollum]"),
            [
                TriggerKind::BranchPush,
                TriggerKind::PullRequest,
                TriggerKind::Schedule,
                TriggerKind::Other("gollum".into()),
                TriggerKind::Call,
            ]
        );
        assert_eq!(
            triggers("on:\n  push:\n    tags: ['v*']\n"),
            [TriggerKind::TagPush]
        );
        assert_eq!(
            triggers("on:\n  push:\n    tags-ignore: ['nightly']\n"),
            [TriggerKind::TagPush]
        );
        assert_eq!(
            triggers("on:\n  push:\n    branches: [main]\n    tags: ['*']\n"),
            [TriggerKind::BranchPush, TriggerKind::TagPush]
        );
        assert_eq!(
            triggers("on:\n  release:\n    types: [published]\n  workflow_dispatch:\n"),
            [TriggerKind::Dispatch, TriggerKind::ReleasePublished]
        );
        assert_eq!(
            triggers("on:\n  release:\n    types: [created, edited]\n"),
            [TriggerKind::Other("release:created+edited".into())]
        );
        assert_eq!(
            triggers("on:\n  release:\n"),
            [TriggerKind::ReleasePublished]
        );
        // A YAML 1.1 reader folds `on` to `true`; a workflow written for one is still read.
        assert_eq!(triggers("true: [release]"), [TriggerKind::ReleasePublished]);
        assert!(triggers("name: x").is_empty());
    }

    #[test]
    fn a_job_is_read_in_each_of_the_shapes_actions_accepts() {
        let wf = parse_workflow(
            "release.yml",
            r#"
name: Release
env: { GLOBAL: g, NUM: 3, FLAG: true, LIST: [1, 2] }
on:
  workflow_dispatch:
    inputs:
      ref: { description: "Full git commit SHA" }
      target: { default: pypi }
  workflow_call:
    inputs:
      retries: { default: 3 }
jobs:
  build:
    runs-on: { group: large, labels: [ubuntu-22.04, x64] }
    container: { image: "python:3.12@sha256:abc", options: --privileged }
    needs: lint
    outputs: { artifact-id: "${{ steps.up.outputs.artifact-id }}" }
    defaults: { run: { working-directory: pkg } }
    steps:
      - uses: actions/setup-python@v5
        with: { python-version: 3.10, cache: pip, check-latest: false, versions: [a, b] }
      - name: Build
        run: python -m build
        env: { SOURCE_DATE_EPOCH: 0 }
        working-directory: sub
        if: github.ref_type == 'tag'
      - run: |
          echo first line
          echo second
      - uses: ./.github/actions/local
  publish:
    runs-on: [ubuntu-latest]
    container: node:20
    needs: [build, test]
    steps: not-a-list
"#,
        )
        .expect("a workflow");
        assert_eq!(wf.title(), "Release");
        assert_eq!(wf.env.get("GLOBAL").map(String::as_str), Some("g"));
        assert_eq!(wf.env.get("NUM").map(String::as_str), Some("3"));
        assert_eq!(wf.env.get("FLAG").map(String::as_str), Some("true"));
        assert!(!wf.env.contains_key("LIST"), "not a scalar");
        // A dispatch input with no default is whatever a human typed, and stays unknown.
        assert_eq!(
            wf.input_defaults,
            BTreeMap::from([
                ("retries".to_string(), "3".to_string()),
                ("target".to_string(), "pypi".to_string()),
            ])
        );

        let build = &wf.jobs[0];
        assert_eq!(build.id, "build");
        assert_eq!(build.runs_on, ["ubuntu-22.04", "x64"]);
        assert_eq!(build.container.as_deref(), Some("python:3.12@sha256:abc"));
        assert_eq!(build.needs, ["lint"]);
        assert_eq!(
            build.outputs.get("artifact-id").map(String::as_str),
            Some("${{ steps.up.outputs.artifact-id }}")
        );
        assert_eq!(build.defaults_working_directory.as_deref(), Some("pkg"));
        assert_eq!(build.cells, vec![cell(&[])]);

        let setup = &build.steps[0];
        assert_eq!(
            setup.action(),
            Some(("actions/setup-python".to_string(), "v5".to_string()))
        );
        assert_eq!(setup.label(), "actions/setup-python@v5");
        // The unquoted `3.10` is a float by the time it arrives, and is kept as what was parsed
        // so a refusal can quote it; it never reads as a version.
        let py = &setup.with["python-version"];
        assert_eq!(py.version_text(), Err("3.1".to_string()));
        assert_eq!(py.text(), None);
        assert_eq!(setup.with["cache"].version_text(), Ok(Some("pip".into())));
        assert_eq!(setup.with["check-latest"].text().as_deref(), Some("false"));
        assert_eq!(setup.with["versions"], Scalar::Compound);
        assert_eq!(setup.with["versions"].version_text(), Ok(None));

        let run = &build.steps[1];
        assert_eq!(run.label(), "Build");
        assert_eq!(run.action(), None);
        assert_eq!(
            run.env.get("SOURCE_DATE_EPOCH").map(String::as_str),
            Some("0")
        );
        assert_eq!(run.working_directory.as_deref(), Some("sub"));
        assert_eq!(run.if_expr.as_deref(), Some("github.ref_type == 'tag'"));
        assert_eq!(build.steps[2].label(), "echo first line");
        assert_eq!(
            build.steps[3].action(),
            Some(("./.github/actions/local".to_string(), String::new()))
        );

        let publish = &wf.jobs[1];
        assert_eq!(publish.runs_on, ["ubuntu-latest"]);
        assert_eq!(publish.container.as_deref(), Some("node:20"));
        assert_eq!(publish.needs, ["build", "test"]);
        assert!(publish.steps.is_empty());
    }

    #[test]
    fn a_workflow_with_no_name_is_called_by_its_path_and_an_empty_step_by_nothing() {
        let wf = parse_workflow(
            ".github/workflows/ci.yml",
            "jobs:\n  a:\n    steps:\n      - {}\n",
        )
        .unwrap();
        assert_eq!(wf.title(), ".github/workflows/ci.yml");
        assert_eq!(wf.jobs[0].steps[0].label(), "(unnamed step)");
        assert!(wf.jobs[0].runs_on.is_empty());
    }

    fn ctx<'a>(
        env: &'a BTreeMap<String, String>,
        matrix: &'a BTreeMap<String, String>,
        inputs: &'a BTreeMap<String, String>,
    ) -> ExprCtx<'a> {
        ExprCtx {
            env,
            matrix,
            inputs,
        }
    }

    #[test]
    fn the_small_expression_subset_resolves_and_everything_else_is_named_back() {
        let env = cell(&[("DIST", "dist")]);
        let m = cell(&[("python", "3.12")]);
        let inputs = cell(&[("target", "pypi")]);
        let c = ctx(&env, &m, &inputs);
        assert_eq!(
            resolve(
                "${{ github.workspace }}/${{env.DIST}} py${{ matrix.python }} \
                 ${{ inputs.target }} ${{ github.event.inputs.target }} ${{ 'lit' }}",
                &c
            ),
            Ok("./dist py3.12 pypi pypi lit".to_string())
        );
        assert_eq!(resolve("no expressions", &c), Ok("no expressions".into()));
        // The first expression that defeats the resolver is what comes back, so a decline can
        // quote it.
        for (raw, first) in [
            ("${{ secrets.PYPI_TOKEN }}", "${{ secrets.PYPI_TOKEN }}"),
            ("a ${{ env.MISSING }} b", "${{ env.MISSING }}"),
            (
                "${{ matrix.os || 'ubuntu' }}",
                "${{ matrix.os || 'ubuntu' }}",
            ),
            ("${{ fromJSON(x) }}", "${{ fromJSON(x) }}"),
            (
                "${{ steps.v.outputs.version }}",
                "${{ steps.v.outputs.version }}",
            ),
            ("${{ github.ref_name }}", "${{ github.ref_name }}"),
            ("${{ bare }}", "${{ bare }}"),
        ] {
            assert_eq!(resolve(raw, &c), Err(first.to_string()), "{raw}");
        }
        // An unterminated `${{` is text that happens to start like an expression.
        assert_eq!(
            resolve("x ${{ env.DIST }} ${{ never closed", &c),
            Ok("x dist ${{ never closed".to_string())
        );
    }

    #[test]
    fn a_needs_output_is_read_for_the_job_it_names() {
        assert_eq!(
            needs_output_producer("${{ needs.build.outputs.artifact-id }}"),
            Some(("build".to_string(), "artifact-id".to_string()))
        );
        for raw in [
            "${{ steps.up.outputs.artifact-id }}",
            "${{ needs.build.result }}",
            "${{ needs.build.outputs. }}",
            "needs.build.outputs.x",
            "${{ needs.build.outputs.x",
        ] {
            assert_eq!(needs_output_producer(raw), None, "{raw}");
        }
    }

    #[test]
    fn every_secret_a_text_reads_is_found_once() {
        let got = secrets_in(
            "📦 ${{ secrets.PYPI_TOKEN }} and ${{secrets.GH_PAT}} and secrets.PYPI_TOKEN again; \
             secrets. alone",
        );
        assert_eq!(
            got.into_iter().collect::<Vec<_>>(),
            ["GH_PAT".to_string(), "PYPI_TOKEN".to_string()]
        );
        assert!(secrets_in("no secret here").is_empty());
    }
}
