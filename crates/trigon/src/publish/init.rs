//! `trigon log init --origin <origin> --repo <location>`: begin an evidence repository's log
//! (`docs/19` §2.3, §10 phase 5).
//!
//! One commit, on `[publish] branch`: `keys/` — the log's verifier key and the attestation key, as
//! copies for people and for trust on first use — the README, which states the origin, the keys,
//! how often a checkpoint appears and where a dispute goes, and a checkpoint of size 0, whose root
//! is SHA-256 of nothing. The checkpoint is signed by `trigon log sign --init`, a child process
//! that holds the log key, as every checkpoint after it is; this never opens the key. A repository
//! that already has a log, or keys, is refused.
//!
//! The commit holds exactly those files, as `publish`'s do ([`git::commit`]), whatever the branch's
//! `.gitignore` says; a branch that names git attributes is refused.
//!
//! On GitHub the branch then wants a ruleset that forbids force-pushes and deletion with an empty
//! bypass list (`docs/19` §8). That is a change to the repository's settings, made with the
//! operator's own credentials, so this prints the `gh api` call that makes it and never runs it.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, anyhow, bail};
use trigon_attest::config::{Env, EvidenceConfig, check_origin, read_attestation_key};
use trigon_attest::location::{Location, Transport};
use trigon_attest::log::{Checkpoint, SignedCheckpoint};
use trigon_attest::{AttestationKey, LogVkey};

use super::{git, human, lock};
use crate::evidence_log::replace;
use crate::{field, style};

/// What `trigon log init` is given.
pub(crate) struct InitArgs {
    pub origin: String,
    pub repo: Option<String>,
    pub attestation_key: String,
    pub log_key: Option<PathBuf>,
}

pub(crate) fn run(args: InitArgs) -> Result<()> {
    let env = Env::from_process()?;
    let config = EvidenceConfig::load(&env)?;
    let p = config.publish();
    check_origin(&args.origin).map_err(anyhow::Error::msg)?;
    if let Some(configured) = &p.origin
        && configured != &args.origin
    {
        bail!(
            "--origin is `{}`, and `[publish] origin` is `{configured}`: publish would refuse the \
             log this begins. Make them one",
            args.origin
        );
    }
    let disputes = p.disputes.clone().ok_or_else(|| {
        anyhow!(
            "`[publish] disputes` is not set in evidence.toml. The README says where a dispute \
             goes, and every divergence names it: set it to where disputes are filed, such as the \
             repository's issues"
        )
    })?;
    let attestation = read_attestation_key(&args.attestation_key, &env.cwd, env.home.as_deref())
        .map_err(|e| anyhow!("--attestation-key: {e}"))?;
    let log_key = args
        .log_key
        .clone()
        .or_else(|| p.log_key.clone())
        .ok_or_else(|| {
            anyhow!(
                "no log key: give --log-key <file>, or set `[publish] log_key` in evidence.toml. \
             `trigon log keygen --origin {} --out <file>` makes one",
                args.origin
            )
        })?;
    let location = match &args.repo {
        Some(r) => Location::parse(r, &env.cwd, env.home.as_deref())?,
        None => p.repo.clone().ok_or_else(|| {
            anyhow!(
                "no repository is named: give --repo <location>, set TRIGON_PUBLISH_REPO, or set \
                 `[publish] repo`"
            )
        })?,
    };
    let branch = &p.branch;

    // A working tree is begun in place; anything else, a bare repository's path included, in a
    // clone of its own that is pushed and then removed.
    let in_place = match location.local_path() {
        Some(path) if path.exists() => git::kind_of(path)?.is_some_and(|tree| tree),
        _ => false,
    };
    let (root, _scratch) = if in_place {
        let tree = location.local_path().expect("a local path").to_path_buf();
        if let Some(why) = git::unfit_to_publish_into(&tree, branch, &WRITES)? {
            bail!("{} cannot have a log begun in it: {why}", tree.display());
        }
        (tree, None)
    } else {
        let scratch = std::env::temp_dir().join(format!(
            "trigon-log-init-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        git::clone(&location, &scratch)?;
        let guard = super::Scratch(scratch.clone());
        let tracking = format!("refs/remotes/origin/{branch}");
        if git::succeeds(
            Some(&scratch),
            &["rev-parse", "--verify", "--quiet", &tracking],
        ) {
            if let Some(why) = git::attributes(&scratch, Some(&tracking))? {
                bail!("{location} cannot have a log begun in it: {why}");
            }
            git::run(
                Some(&scratch),
                &["checkout", "--quiet", "--force", "-B", branch, &tracking],
            )?;
        } else {
            git::run(Some(&scratch), &["switch", "--quiet", "--orphan", branch])?;
        }
        (scratch, Some(guard))
    };
    let _lock = if in_place {
        let git_dir = git::text(Some(&root), &["rev-parse", "--absolute-git-dir"])?;
        Some(lock::Lock::take(
            &Path::new(&git_dir).join("trigon-publish.lock"),
            &format!("pid {}, beginning a log", std::process::id()),
        )?)
    } else {
        None
    };
    for there in ["log", "keys"] {
        if std::fs::symlink_metadata(root.join(there)).is_ok() {
            bail!(
                "{} already has {there}/ on `{branch}`, so it already has a log, or the start of \
                 one: a log is begun once. Publish to it with `trigon publish`",
                location
            );
        }
    }
    let head = git::text(Some(&root), &["rev-parse", "--verify", "--quiet", "HEAD"]).ok();
    // A branch fetched was asked before it was checked out; this asks a working tree's, and the
    // git directory's own `info/attributes` either way.
    if let Some(why) = git::attributes(&root, head.as_deref())? {
        bail!("{location} cannot have a log begun in it: {why}");
    }

    let mut unwind = Unwind {
        root: &root,
        head: head.as_deref(),
        armed: in_place,
    };
    // The log key's half first, by the step that holds the key: its verifier key and the empty
    // checkpoint.
    let exe = std::env::current_exe().context("finding this binary to run `trigon log sign`")?;
    let out = std::process::Command::new(exe)
        .args(["log", "sign", "--init", "--tree"])
        .arg(&root)
        .arg("--key")
        .arg(&log_key)
        .stdin(std::process::Stdio::null())
        .output()
        .context("running `trigon log sign --init`")?;
    if !out.status.success() {
        bail!(
            "`trigon log sign --init` did not begin the log:\n{}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let vkey_text = std::fs::read_to_string(root.join("keys/log.vkey"))?;
    let vkey = LogVkey::parse(vkey_text.trim())?;
    if vkey.origin() != args.origin {
        bail!(
            "the log key {} is for the log `{}`, and --origin is `{}`: a log key's name is its \
             log's origin. Make a key for this origin with `trigon log keygen --origin {}`",
            log_key.display(),
            vkey.origin(),
            args.origin,
            args.origin
        );
    }
    let checkpoint = std::fs::read(root.join("log/checkpoint"))?;
    let signed = SignedCheckpoint::open(&checkpoint, &vkey)?;
    if signed.checkpoint() != &Checkpoint::empty(&args.origin) {
        bail!("`trigon log sign --init` signed something other than an empty log");
    }
    let pem = attestation.to_pem();
    let text = readme(&args.origin, &vkey, &attestation, p.heartbeat, &disputes);
    // Replaced, never written through: the branch's own README.md may be a link.
    replace(&root.join("keys/attestation.pub"), pem.as_bytes())?;
    replace(&root.join("README.md"), text.as_bytes())?;
    let change = git::Change {
        writes: vec![
            ("keys/log.vkey", vkey_text.as_bytes()),
            ("log/checkpoint", &checkpoint),
            ("keys/attestation.pub", pem.as_bytes()),
            ("README.md", text.as_bytes()),
        ],
        removes: Vec::new(),
    };
    let message = format!("log init: {}, tree 0", args.origin);
    let commit = git::commit(&root, head.as_deref(), &change, &message)?;
    if !in_place {
        let refspec = format!("refs/heads/{branch}:refs/heads/{branch}");
        git::run_network(
            Some(&root),
            &["push", "--quiet", "--no-signed", "origin", &refspec],
        )
        .map_err(|e| {
            anyhow!(
                "{e}\nNothing was begun in {location}: the push was refused, never forced. If \
                 somebody else wrote `{branch}` meanwhile, look at what is there first"
            )
        })?;
    }
    unwind.armed = false;

    field("repository", format!("{location} ({branch})"));
    field("commit", style::ident(&commit));
    field("origin", &args.origin);
    field("log key", style::ident(&vkey.to_string()));
    field(
        "attestation",
        format!(
            "{} {}",
            style::ident(&attestation.to_hex()),
            style::muted(&format!("(key id {})", attestation.key_id()))
        ),
    );
    println!();
    println!(
        "{}",
        style::muted(&style::wrap(
            "On GitHub, forbid force-pushes and deletion of the branch with a ruleset whose bypass \
             list is empty, so that no admin is exempt (docs/19 §8). This does not make the change \
             itself; with the GitHub CLI and a token that may administer the repository, it is:",
            0
        ))
    );
    println!();
    println!("{}", ruleset(&args.origin, &location, branch));
    Ok(())
}

/// The paths `log init` writes. A working tree it begins a log in holds nothing git ignores under
/// them, and a log begun there that fails is discarded from them.
const WRITES: [&str; 3] = ["keys", "log", "README.md"];

/// Discards a log begun in a working tree in place that failed: the commit, if one was made and
/// then refused, and everything this wrote. The tree was clean when it began, with nothing git
/// ignores under [`WRITES`], and `keys/` and `log/` were not there.
struct Unwind<'a> {
    root: &'a Path,
    /// The commit the branch was at, or `None` where it had none yet.
    head: Option<&'a str>,
    armed: bool,
}

impl Drop for Unwind<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let root = Some(self.root);
        let _ = match self.head {
            Some(head) => git::run(root, &["reset", "--quiet", "--mixed", head]),
            // A branch with no commit before this one has none again, and nothing staged.
            None => {
                let _ = git::run(root, &["update-ref", "-d", "HEAD"]);
                git::run(root, &["read-tree", "--empty"])
            }
        };
        for dir in ["keys", "log"] {
            let _ = std::fs::remove_dir_all(self.root.join(dir));
        }
        // A README the branch has is put back as it has it; one it has not is removed.
        if git::run(root, &["checkout", "--quiet", "--", "README.md"]).is_err() {
            let _ = std::fs::remove_file(self.root.join("README.md"));
        }
    }
}

/// The README of a new evidence repository: `docs/19` §2.3 and §10 phase 5 say it states the
/// origin, the keys, the checkpoint rate and how to report a dispute.
fn readme(
    origin: &str,
    vkey: &LogVkey,
    attestation: &AttestationKey,
    heartbeat: std::time::Duration,
    disputes: &str,
) -> String {
    format!(
        "# Trigon evidence: {origin}\n\
         \n\
         Signed records of whether published packages were rebuilt from their source, the\n\
         append-only log that holds them, and an index for finding them. `trigon publish` writes\n\
         it; `trigon evidence sync`, `trigon lookup` and `trigon check` read it, and so can any\n\
         tool that verifies a C2SP checkpoint and an RFC 6962 tree.\n\
         \n\
         ## Origin\n\
         \n\
         `{origin}`\n\
         \n\
         The name of this log, signed into every checkpoint and into every verdict's falsifying\n\
         command. It never changes; a successor log has an origin of its own.\n\
         \n\
         ## Keys\n\
         \n\
         - The log key, which signs `log/checkpoint` (also `keys/log.vkey`):\n\
         \x20 `{vkey}`\n\
         - The attestation key, which signs every record (also `keys/attestation.pub`): Ed25519\n\
         \x20 `{}`, key id `{}`\n\
         \n\
         Pin both. The copies here are for people, and for trust on first use: a key read from\n\
         the repository it vouches for is only as good as that repository.\n\
         \n\
         ## Checkpoint rate\n\
         \n\
         A new checkpoint appears once per publication, and at least every {} from a heartbeat\n\
         leaf when nothing else is published. A log whose newest leaf is older than that has\n\
         stopped, or is being withheld from you.\n\
         \n\
         ## Disputes\n\
         \n\
         Every divergence names where it is disputed:\n\
         \n\
         {disputes}\n\
         \n\
         To dispute a record, report it there with the record's digest, the name of its file\n\
         under `records/`, and what you believe is wrong. A record is never deleted: a correction\n\
         is a new record that supersedes it, and both stay in the log.\n",
        attestation.to_hex(),
        attestation.key_id(),
        human(heartbeat),
    )
}

/// The `gh api` call that sets a ruleset on `branch`, the one the log is published to, forbidding
/// force-pushes and deletion, with no one exempt. Named by its ref, not as the default branch:
/// `[publish] branch` need not be the default, and a ruleset on another branch would leave the
/// log's open. The repository is read from the origin, or from a GitHub location, and left for the
/// operator to fill in where neither names one.
fn ruleset(origin: &str, location: &Location, branch: &str) -> String {
    let named = github_repository(origin, location);
    let repo = named.clone().unwrap_or_else(|| "<owner>/<repo>".into());
    // Built as JSON, so that a branch name is a string in it whatever it holds.
    let body = serde_json::json!({
        "name": "trigon-evidence: no force-push, no deletion",
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": {"ref_name": {"include": [format!("refs/heads/{branch}")], "exclude": []}},
        "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}],
    });
    let body = serde_json::to_string_pretty(&body).expect("a JSON value serializes");
    let mut out =
        format!("gh api --method POST repos/{repo}/rulesets --input - <<'EOF'\n{body}\nEOF");
    if named.is_none() {
        out.push_str(
            "\n\nNeither the origin nor the location names a GitHub repository; on another host, \
             forbid force-pushes and deletion of the branch its own way.",
        );
    }
    out
}

/// `<owner>/<repo>` where the origin or the location is on github.com.
fn github_repository(origin: &str, location: &Location) -> Option<String> {
    let from = |path: &str| -> Option<String> {
        let mut parts = path.trim_matches('/').split('/');
        let (owner, repo) = (parts.next()?, parts.next()?);
        let repo = repo.strip_suffix(".git").unwrap_or(repo);
        (!owner.is_empty() && !repo.is_empty()).then(|| format!("{owner}/{repo}"))
    };
    if let Some(path) = origin.strip_prefix("github.com/") {
        return from(path);
    }
    let url = location.as_git_arg();
    let path = match location.transport() {
        Transport::Https | Transport::Http => url
            .split_once("://")
            .and_then(|(_, r)| r.strip_prefix("github.com/")),
        Transport::Ssh => url
            .strip_prefix("git@github.com:")
            .or_else(|| url.strip_prefix("ssh://git@github.com/")),
        _ => None,
    }?;
    from(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ruleset_names_the_repository_its_origin_or_location_is_on_github() {
        let at = |s: &str| Location::parse(s, Path::new("/cwd"), None).unwrap();
        let local = at("/srv/evidence.git");
        assert_eq!(
            github_repository("github.com/owner/trigon-evidence", &local).as_deref(),
            Some("owner/trigon-evidence")
        );
        for l in [
            "https://github.com/owner/trigon-evidence.git",
            "git@github.com:owner/trigon-evidence.git",
            "ssh://git@github.com/owner/trigon-evidence.git",
        ] {
            assert_eq!(
                github_repository("example.com/evidence", &at(l)).as_deref(),
                Some("owner/trigon-evidence"),
                "{l}"
            );
        }
        assert_eq!(github_repository("example.com/evidence", &local), None);
        let call = ruleset("github.com/owner/trigon-evidence", &local, "main");
        assert!(call.starts_with("gh api --method POST repos/owner/trigon-evidence/rulesets"));
        // The body is JSON, so `gh` sends exactly what it says.
        let body: String = call.lines().skip(1).take_while(|l| *l != "EOF").collect();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(body["bypass_actors"], serde_json::json!([]));
        assert_eq!(
            body["rules"],
            serde_json::json!([{"type": "deletion"}, {"type": "non_fast_forward"}])
        );
        assert_eq!(
            body["conditions"]["ref_name"]["include"],
            serde_json::json!(["refs/heads/main"])
        );
        assert!(ruleset("example.com/evidence", &local, "main").contains("<owner>/<repo>"));
    }

    /// The ruleset protects the branch the log is published to, whichever it is, and never the
    /// default branch in its place.
    #[test]
    fn the_ruleset_protects_the_branch_the_log_is_on() {
        let local = Location::parse("/srv/evidence.git", Path::new("/cwd"), None).unwrap();
        let call = ruleset("github.com/owner/trigon-evidence", &local, "evidence");
        let body: String = call.lines().skip(1).take_while(|l| *l != "EOF").collect();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            body["conditions"]["ref_name"]["include"],
            serde_json::json!(["refs/heads/evidence"])
        );
        assert!(!call.contains("DEFAULT_BRANCH"), "{call}");
    }
}
