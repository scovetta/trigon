//! The M1 DSL corpus: `google/oss-rebuild`'s `definitions/`, imported and rendered.
//!
//! 53 overrides written for packages where inference failed, so this is the pathological tail. It
//! exercises the flow DSL, the template engine and the tool registry harder than anything we would
//! write, and it says nothing at all about the common-path reproduction rate. Both halves matter:
//! `docs/13-roadmap.md` M1 keeps these as two separate corpora for that reason.
//!
//! Skipped when the checkout is absent, so the suite still runs on a machine without it.

use std::path::{Path, PathBuf};

use trigon_strategy::{
    Context, EnvCtx, LocationCtx, Strategy, ToolRegistry, import, render, strategy_digest,
};

fn definitions_root() -> Option<PathBuf> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../oss-rebuild/definitions")
        .canonicalize()
        .ok()?;
    p.is_dir().then_some(p)
}

fn all_build_yaml(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.file_name().is_some_and(|n| n == "build.yaml") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

fn cx_for(s: &Strategy) -> Context {
    let l = s.location().cloned().unwrap_or_default();
    Context {
        location: LocationCtx {
            repo: l.repo,
            git_ref: l.git_ref,
            subdir: l.subdir.unwrap_or_default(),
        },
        env: EnvCtx {
            arch: "x86_64".into(),
            platform: "linux".into(),
            has_repo: false,
            timewarp_base: "timewarp".into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

#[test]
fn the_definitions_corpus_imports_and_renders() {
    let Some(root) = definitions_root() else {
        eprintln!("skipped: ../oss-rebuild/definitions is not checked out");
        return;
    };
    let files = all_build_yaml(&root);
    assert!(
        files.len() >= 50,
        "expected the full corpus, found {}",
        files.len()
    );

    let tools = ToolRegistry::builtin().unwrap();
    let (mut rendered, mut hinted, mut with_stabilizers) = (0, 0, 0);
    let mut refused: Vec<String> = Vec::new();
    let mut failed: Vec<String> = Vec::new();

    for f in &files {
        let name = f.strip_prefix(&root).unwrap().display().to_string();
        let src = std::fs::read_to_string(f).unwrap();

        let imported = match import(&src) {
            Ok(i) => i,
            // A shape we decline by name is a scope statement, not a bug. A shape we lower wrongly
            // would build something other than what the definition asked for.
            Err(e) => {
                refused.push(format!("{name}: {e}"));
                continue;
            }
        };
        if !imported.custom_stabilizers.is_empty() {
            with_stabilizers += 1;
            for cs in &imported.custom_stabilizers {
                assert!(
                    !cs.reason.is_empty(),
                    "{name}: a custom stabilizer needs a reason"
                );
            }
        }

        if !imported.strategy.is_executable() {
            hinted += 1;
            continue;
        }

        // Round-trips through our own schema, then renders.
        let yaml = trigon_strategy::to_yaml(&imported.strategy).unwrap();
        let reparsed = trigon_strategy::from_yaml(&yaml)
            .unwrap_or_else(|e| panic!("{name}: our own output does not reparse: {e}\n{yaml}"));
        assert_eq!(
            reparsed, imported.strategy,
            "{name}: round trip changed the strategy"
        );

        match render(&imported.strategy, &cx_for(&imported.strategy), &tools) {
            Ok(i) => {
                assert!(
                    !i.build.trim().is_empty(),
                    "{name}: rendered an empty build"
                );
                assert!(!i.location.commit.is_empty(), "{name}: no commit pinned");
                strategy_digest(&imported.strategy, &tools).unwrap();
                rendered += 1;
            }
            Err(e) => failed.push(format!("{name}: {e}")),
        }
    }

    println!(
        "{} definitions: {rendered} rendered, {hinted} location-only, {} refused by shape, \
         {} carry custom stabilizers",
        files.len(),
        refused.len(),
        with_stabilizers
    );
    for r in &refused {
        println!("  refused  {r}");
    }
    for f in &failed {
        println!("  FAILED   {f}");
    }

    assert!(failed.is_empty(), "definitions we accepted must render");
    assert!(
        rendered >= 50,
        "expected at least 50 of {} to render, got {rendered}",
        files.len()
    );
}

#[test]
fn the_npm_override_renders_the_script_its_definition_describes() {
    // One npm definition in the corpus, and it is the interesting shape: a package whose publish
    // ran a script before packing. Asserted line by line, because the ported npm tools have no
    // other check on them until a sandbox exists to run one.
    let Some(root) = definitions_root() else {
        eprintln!("skipped: ../oss-rebuild/definitions is not checked out");
        return;
    };
    let f = all_build_yaml(&root)
        .into_iter()
        .find(|p| p.display().to_string().contains("app-route"))
        .expect("the app-route definition");
    let imported = import(&std::fs::read_to_string(f).unwrap()).unwrap();
    let i = render(
        &imported.strategy,
        &cx_for(&imported.strategy),
        &ToolRegistry::builtin().unwrap(),
    )
    .unwrap();
    println!("--- deps ---\n{}\n--- build ---\n{}", i.deps, i.build);

    // node_version: 8.16.0, npm_version: 6.4.1, registry_time: 2018-09-13T19:55:58Z
    //
    // The official glibc distribution by default. The prior art hardcodes the musl build because
    // its base image is Alpine, and that URL does not exist for every version: Node 9.2.1, which
    // published left-pad 1.3.0, 404s on unofficial-builds and is present on nodejs.org.
    assert!(
        i.deps
            .contains("nodejs.org/dist/v8.16.0/node-v8.16.0-linux-x64.tar.gz"),
        "{}",
        i.deps
    );
    assert!(!i.deps.contains("musl"), "musl is opt-in: {}", i.deps);
    // The pinned npm reaches npx through a quoted variable rather than spliced into the word, so
    // this checks both halves: that the version is what the registry recorded, and that it arrives
    // as data. `_npmVersion` is publisher-controlled — `framer-motion@12.36.0` records a lerna
    // user-agent string — and an unquoted splice made that a shell syntax error inside our own
    // deps script.
    assert!(
        i.deps.contains("TRIGON_NPM_VERSION='6.4.1'"),
        "the recorded npm version, assigned once and quoted: {}",
        i.deps
    );
    assert!(
        i.deps
            .contains(r#"npx --package="npm@$TRIGON_NPM_VERSION""#),
        "npx has to run under that version, and take it as a word: {}",
        i.deps
    );
    assert!(
        i.deps
            .contains("npm_config_registry=http://npm:2018-09-13T19:55:58Z@timewarp"),
        "the install has to resolve against the mirror: {}",
        i.deps
    );
    // command: prepare
    assert!(
        i.build.contains("npm run prepare && npm pack"),
        "{}",
        i.build
    );
    // And *not* Debian's `npm`. This definition installs its own pinned Node and points every npm
    // invocation at it, so asking apt for a second one adds a Node 18 plus a system-wide
    // `NODE_PATH` that the pinned Node 10 then loads modules from — it aborts with SIGABRT after
    // the install has already succeeded, which reads as a toolchain too old for the kernel and is
    // not. This assertion used to require the opposite, which is how the bug survived a corpus run.
    assert!(
        !i.requires.system_deps.contains("npm"),
        "a strategy that installs its own Node must not also pull Debian's: {:?}",
        i.requires
    );
    assert!(
        i.requires.system_deps.contains("wget"),
        "it still needs what actually fetches that Node: {:?}",
        i.requires
    );
}
