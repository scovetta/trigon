//! The crates.io sparse index, filtered to an instant.
//!
//! Cargo's sparse protocol is the simplest of the four registries this mirror speaks. An index
//! document is **newline-delimited JSON, one object per version**, and the objects are already in
//! publication order. There is no envelope to rebuild, no paging, and no separate metadata
//! document — filtering is dropping lines.
//!
//! **`pubtime` is why this is a timestamp filter and not an index commit.**
//! [`B19`](../../../docs/17-backlog.md) argued that Cargo needed a pinned `crates.io-index` git
//! commit because "a timestamp isn't precise enough": the index was a git repository, resolution
//! was a function of a commit, and commits are not evenly spaced in time. The sparse index carries
//! a `pubtime` on every line — verified present on all 56 versions of `hashbrown` and all 316 of
//! `serde`, back to 2014 — in RFC 3339 UTC at whole-second resolution, which is exactly the shape
//! [`moment::normalize`](crate::moment) already compares lexically. The instant is now a property
//! of the document rather than of a repository's history, so the npm and PyPI shape applies after
//! all and a build resolves against the versions that existed when the crate was published.
//!
//! **Yank state is the one field that has no history, and it is cleared rather than trusted.** A
//! line's `yanked` flag is its state *today*. Nothing in the sparse index records when a version
//! was yanked, and neither does the crates.io API — `/api/v1/crates/{name}/versions` returns
//! `yanked` and `yank_message` and no timestamp — so the state at the filtered instant cannot be
//! reconstructed from anything crates.io publishes.
//!
//! Both available answers are wrong somewhere, so the choice is which way. Keeping today's flag
//! makes Cargo skip a version the publisher resolved happily, and that is not hypothetical:
//! `bitflags@2.6.0` pins `bytemuck = "1.12"`, its published lockfile names 1.16.1, and every
//! 1.15.x and 1.16.x has since been yanked — so the rebuild resolved 1.14.0 and the crate diverged
//! on `Cargo.lock`. Two of ten crates in a sweep failed exactly this way, each of them blamed on
//! the package for a fact about our own afternoon.
//!
//! Clearing it can admit a version that was *already* yanked at the pin. That error is much rarer,
//! because Cargo takes the newest version satisfying a requirement and a long-yanked one is
//! normally superseded by something newer that it would pick instead; the flag only changes an
//! outcome when the yank is recent relative to the pin, which is precisely the case where the
//! version was live at the pin. So the flag is cleared on every surviving line, and the run says
//! so in its assumptions rather than leaving a reader to find this comment.

use serde_json::Value;

use crate::moment::published_by;

/// Where crates.io serves `.crate` bytes from, per its own `config.json`.
///
/// Named here rather than read from upstream's `config.json` at request time, because the mirror
/// rewrites `dl` to point at itself and a value it did not choose is a value it cannot allowlist.
pub const DOWNLOAD_HOST: &str = "static.crates.io";

/// The index this mirror filters.
pub const INDEX_BASE: &str = "https://index.crates.io";

/// The `config.json` a Cargo sparse registry must serve, pointing `dl` back at this mirror.
///
/// `dl` carries no `{crate}`/`{version}` markers, so Cargo appends `/{crate}/{version}/download` —
/// which is a real crates.io path and not a synthetic one, so the artifact route proxies it
/// unchanged.
///
/// `api` is deliberately left at the real crates.io. It is only used for `publish`, `yank` and
/// `search`, none of which a rebuild performs, and at `mirror-only` egress it is unreachable — so
/// a strategy that somehow tried would fail loudly rather than reach the network through us.
pub fn config_json(artifact_base: &str) -> Value {
    serde_json::json!({
        "dl": format!("{artifact_base}/{DOWNLOAD_HOST}/crates"),
        "api": "https://crates.io",
    })
}

/// Drop every version published after `moment`, and clear stale yank state on what survives.
///
/// Returns the filtered document, how many lines were withheld, and how many surviving lines had
/// a `yanked` flag cleared — the last so the caller can say that it happened. A line that will not parse, or
/// that carries no `pubtime`, is **withheld rather than served**: the alternative is serving a
/// version we cannot date, which is the one outcome the filter exists to prevent. Every line in
/// the live index has the field, so this is a guard against a document shape changing under us
/// rather than a case that fires today.
pub fn filter_index(body: &str, moment: &str) -> (String, u64, u64) {
    let mut out = String::with_capacity(body.len());
    let (mut withheld, mut unyanked) = (0u64, 0u64);
    for line in body.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let parsed = serde_json::from_str::<Value>(line).ok();
        let keep = match &parsed {
            Some(v) => match v.get("pubtime").and_then(Value::as_str) {
                Some(ts) => published_by(ts, moment),
                None => {
                    tracing::debug!("index line with no pubtime; withholding it");
                    false
                }
            },
            None => {
                tracing::debug!("unparseable index line; withholding it");
                false
            }
        };
        if !keep {
            withheld += 1;
            continue;
        }
        // Re-serialized **only** when the flag actually changes, so every other line goes out as
        // the registry wrote it. Cargo parses this as JSON and does not care about key order, but
        // the transcript records the bytes served and there is no reason to churn them.
        match parsed {
            Some(mut v) if v.get("yanked").and_then(Value::as_bool) == Some(true) => {
                v["yanked"] = Value::Bool(false);
                out.push_str(&serde_json::to_string(&v).unwrap_or_else(|_| line.to_string()));
                out.push('\n');
                unyanked += 1;
            }
            _ => {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    (out, withheld, unyanked)
}

/// Whether a filtered index document offers nothing at all.
///
/// A crate whose every version postdates the pin did not exist at that moment, and saying so with
/// a 404 is what Cargo already knows how to report — "no matching package named `x` found". An
/// empty 200 is a document claiming the crate exists with no versions, which Cargo reports as a
/// resolution failure several layers further from the cause.
pub fn is_empty(filtered: &str) -> bool {
    filtered.trim().is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two real `hashbrown` lines, trimmed to the fields the filter reads.
    const INDEX: &str = concat!(
        r#"{"name":"hashbrown","vers":"0.1.0","cksum":"aa","pubtime":"2018-10-29T14:28:15Z"}"#,
        "\n",
        r#"{"name":"hashbrown","vers":"0.17.0","cksum":"bb","pubtime":"2026-04-09T14:14:59Z"}"#,
        "\n",
        r#"{"name":"hashbrown","vers":"0.17.1","cksum":"cc","pubtime":"2026-05-09T04:35:04Z"}"#,
        "\n",
    );

    #[test]
    fn a_version_published_after_the_moment_is_withheld() {
        let (out, withheld, _unyanked) = filter_index(INDEX, "2026-04-09T14:14:59");
        assert_eq!(withheld, 1, "0.17.1 postdates the pin: {out}");
        assert!(out.contains(r#""vers":"0.17.0""#));
        assert!(
            !out.contains(r#""vers":"0.17.1""#),
            "the version published a month later is still being offered: {out}"
        );
        // The boundary is inclusive: a crate published *at* the pinned instant existed then.
        assert!(out.contains(r#""vers":"0.1.0""#));
    }

    #[test]
    fn the_whole_index_survives_a_moment_after_every_release() {
        let (out, withheld, _unyanked) = filter_index(INDEX, "2026-12-01T00:00:00");
        assert_eq!(withheld, 0);
        assert_eq!(out.lines().count(), 3);
    }

    #[test]
    fn a_crate_that_did_not_exist_yet_filters_to_nothing() {
        let (out, withheld, _unyanked) = filter_index(INDEX, "2015-01-01T00:00:00");
        assert_eq!(withheld, 3);
        assert!(is_empty(&out), "{out}");
    }

    /// The failure mode this is guarding: a line we cannot date must not be served.
    ///
    /// Serving it would let a build resolve a version the filter could not place in time, which is
    /// the same hole `moment::published_by` closes for npm and PyPI. Tested rather than asserted in
    /// a comment, because "excluded what it could not read" and "included what it could not read"
    /// are one character apart in the implementation and opposite in consequence.
    #[test]
    fn a_line_with_no_pubtime_or_no_json_is_withheld_not_served() {
        let odd = concat!(
            r#"{"name":"x","vers":"1.0.0","cksum":"aa"}"#,
            "\n",
            "this is not json\n",
            r#"{"name":"x","vers":"0.9.0","cksum":"bb","pubtime":"2020-01-01T00:00:00Z"}"#,
            "\n",
        );
        let (out, withheld, _unyanked) = filter_index(odd, "2026-01-01T00:00:00");
        assert_eq!(withheld, 2, "{out}");
        assert_eq!(out.lines().count(), 1);
        assert!(out.contains(r#""vers":"0.9.0""#));
    }

    /// The `bitflags@2.6.0` case, reduced: a version live at the pin and yanked since.
    ///
    /// Keeping today's flag made Cargo skip it and resolve two minor versions back, so the rebuild
    /// diverged on `Cargo.lock` and the package wore the blame.
    #[test]
    fn a_version_yanked_since_the_pin_is_offered_as_live() {
        let idx = concat!(
            r#"{"name":"bytemuck","vers":"1.14.0","cksum":"aa","yanked":false,"pubtime":"2023-09-05T21:32:46Z"}"#,
            "\n",
            r#"{"name":"bytemuck","vers":"1.16.1","cksum":"bb","yanked":true,"pubtime":"2024-06-19T03:26:53Z"}"#,
            "\n",
        );
        let (out, withheld, unyanked) = filter_index(idx, "2024-06-24T23:57:30");
        assert_eq!(withheld, 0);
        assert_eq!(
            unyanked, 1,
            "the yank postdates the pin, so it is not a fact about that day"
        );
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2);
        let newest: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(newest["vers"], "1.16.1");
        assert_eq!(
            newest["yanked"], false,
            "Cargo would otherwise resolve 1.14.0"
        );
        // Untouched lines keep their exact bytes.
        assert!(lines[0].starts_with(r#"{"name":"bytemuck","vers":"1.14.0""#));
    }

    #[test]
    fn config_points_downloads_back_at_this_mirror() {
        let c = config_json("http://timewarp:8129/-artifact/cargo/2026-05-09T04:35:04");
        assert_eq!(
            c["dl"],
            "http://timewarp:8129/-artifact/cargo/2026-05-09T04:35:04/static.crates.io/crates"
        );
        // No `{crate}` or `{version}` marker, so Cargo appends `/{crate}/{version}/download` and
        // the result is a path crates.io actually serves.
        assert!(!c["dl"].as_str().unwrap().contains('{'));
    }
}
