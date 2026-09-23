//! A network transcript, summarized for a run page.
//!
//! The transcript is one JSON line per exchange that crossed into the build: the upstream URL, the
//! route the mirror served it by (`toolchain`, `index`, `artifact`), its digest and size, how the
//! guard checked it, and — for an index — how many versions the mirror withheld because they were
//! published after the pinned moment. Thousands of lines on an npm build. A reader wants the shape
//! first: how much crossed, from where, how much of it the guard could actually check, and which
//! exchanges were the big ones.
//!
//! **Class-gated like the transcript itself.** The summary carries URLs, and a transcript's URLs
//! are unredacted. The route that serves this asks the evidence table exactly as the raw route
//! does, so a summary never reaches a reader the raw transcript would be refused to.
//!
//! Bounded: every list is capped with its total stated, and a line that does not parse is counted
//! rather than dropped silently.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// How many hosts a summary lists.
const HOSTS: usize = 30;
/// How many of the largest exchanges a summary lists.
const LARGEST: usize = 15;
/// How many toolchain exchanges a summary lists. There are usually one or two.
const TOOLCHAIN: usize = 30;

/// One transcript line, as `trigon-mirror` writes it.
#[derive(Debug, Deserialize)]
struct Line {
    route: String,
    url: String,
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    bytes: Option<u64>,
    #[serde(default)]
    checked: Option<String>,
    #[serde(default)]
    withheld: Option<u64>,
}

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct Summary {
    /// Exchanges that parsed.
    pub exchanges: u64,
    /// Bytes that crossed, summed over them.
    pub bytes: u64,
    /// By route, in the order a build meets them.
    pub routes: Vec<Bucket>,
    /// By what the guard could do with each exchange.
    pub checked: Vec<Bucket>,
    /// Versions the mirror withheld from an index because they postdate the pinned moment, summed.
    pub withheld: u64,
    /// Index documents that withheld at least one version.
    pub indexes_withholding: u64,
    /// The hosts that served the most bytes, largest first, up to a bound.
    pub hosts: Vec<Host>,
    pub hosts_total: usize,
    /// The largest single exchanges, largest first, up to a bound.
    pub largest: Vec<Exchange>,
    /// Every toolchain exchange, up to a bound: the compilers and runtimes, which a reader checks
    /// first.
    pub toolchain: Vec<Exchange>,
    pub toolchain_total: usize,
    /// Lines that were not a transcript exchange. Counted, never silently skipped.
    pub unreadable: u64,
}

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct Bucket {
    pub name: String,
    pub count: u64,
    pub bytes: u64,
}

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct Host {
    pub host: String,
    pub count: u64,
    pub bytes: u64,
    /// The routes this host served, sorted.
    pub routes: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct Exchange {
    pub route: String,
    pub url: String,
    pub bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// The host of a URL, without pulling in a URL parser for one field: the part between `://` and
/// the next `/`, `?` or `#`, with any userinfo removed so a credential never becomes a row label.
fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if host.is_empty() {
        "(no host)".into()
    } else {
        host.to_ascii_lowercase()
    }
}

/// The order routes are listed in: the order a build meets them, then anything unknown.
fn route_rank(r: &str) -> u8 {
    match r {
        "toolchain" => 0,
        "index" => 1,
        "artifact" => 2,
        _ => 3,
    }
}

pub fn summarize(transcript: &[u8]) -> Summary {
    let mut s = Summary::default();
    let mut routes: BTreeMap<String, Bucket> = BTreeMap::new();
    let mut checked: BTreeMap<String, Bucket> = BTreeMap::new();
    let mut hosts: BTreeMap<String, (u64, u64, std::collections::BTreeSet<String>)> =
        BTreeMap::new();
    let mut all: Vec<Exchange> = Vec::new();

    for raw in transcript.split(|b| *b == b'\n') {
        if raw.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let Ok(line) = serde_json::from_slice::<Line>(raw) else {
            s.unreadable += 1;
            continue;
        };
        let bytes = line.bytes.unwrap_or(0);
        s.exchanges += 1;
        s.bytes += bytes;

        let r = routes.entry(line.route.clone()).or_insert_with(|| Bucket {
            name: line.route.clone(),
            ..Bucket::default()
        });
        r.count += 1;
        r.bytes += bytes;

        let how = line.checked.clone().unwrap_or_else(|| "unrecorded".into());
        let c = checked.entry(how.clone()).or_insert_with(|| Bucket {
            name: how,
            ..Bucket::default()
        });
        c.count += 1;
        c.bytes += bytes;

        if let Some(w) = line.withheld {
            s.withheld += w;
            if w > 0 {
                s.indexes_withholding += 1;
            }
        }

        let h = hosts.entry(host_of(&line.url)).or_default();
        h.0 += 1;
        h.1 += bytes;
        h.2.insert(line.route.clone());

        all.push(Exchange {
            route: line.route,
            url: line.url,
            bytes,
            checked: line.checked,
            sha256: line.sha256,
        });
    }

    let mut routes: Vec<Bucket> = routes.into_values().collect();
    routes.sort_by(|a, b| {
        route_rank(&a.name)
            .cmp(&route_rank(&b.name))
            .then(a.name.cmp(&b.name))
    });
    s.routes = routes;

    let mut checked: Vec<Bucket> = checked.into_values().collect();
    checked.sort_by(|a, b| b.count.cmp(&a.count).then(a.name.cmp(&b.name)));
    s.checked = checked;

    let mut hosts: Vec<Host> = hosts
        .into_iter()
        .map(|(host, (count, bytes, routes))| Host {
            host,
            count,
            bytes,
            routes: routes.into_iter().collect(),
        })
        .collect();
    hosts.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.host.cmp(&b.host)));
    s.hosts_total = hosts.len();
    hosts.truncate(HOSTS);
    s.hosts = hosts;

    let toolchain: Vec<Exchange> = all.iter().filter(|e| e.route == "toolchain").cloned().collect();
    s.toolchain_total = toolchain.len();
    s.toolchain = toolchain.into_iter().take(TOOLCHAIN).collect();

    all.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.url.cmp(&b.url)));
    all.truncate(LARGEST);
    s.largest = all;
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: &str = concat!(
        r#"{"route":"toolchain","url":"https://nodejs.org/dist/v20.8.0/node.tar.gz","sha256":"aa","bytes":1000,"checked":"hashed"}"#,
        "\n",
        r#"{"route":"index","url":"https://registry.npmjs.org/eslint","sha256":"bb","bytes":50,"checked":"generated","withheld":7}"#,
        "\n",
        r#"{"route":"index","url":"https://registry.npmjs.org/aud","sha256":"cc","bytes":20,"checked":"generated","withheld":0}"#,
        "\n",
        r#"{"route":"artifact","url":"https://user:tok@registry.npmjs.org/a/-/a-1.tgz","sha256":"dd","bytes":300,"checked":"opened"}"#,
        "\n",
        "not json\n",
        "\n",
    );

    #[test]
    fn totals_routes_and_withheld_are_summed() {
        let s = summarize(T.as_bytes());
        assert_eq!(s.exchanges, 4);
        assert_eq!(s.bytes, 1370);
        assert_eq!(s.unreadable, 1, "a bad line is counted, and a blank one is not a line");
        let names: Vec<_> = s.routes.iter().map(|b| b.name.as_str()).collect();
        assert_eq!(names, ["toolchain", "index", "artifact"], "in the order a build meets them");
        assert_eq!(s.withheld, 7);
        assert_eq!(s.indexes_withholding, 1, "an index that withheld nothing is not counted");
        assert_eq!(s.toolchain_total, 1);
        assert_eq!(s.largest[0].bytes, 1000, "largest first");
    }

    #[test]
    fn a_credential_in_a_url_never_becomes_a_host_label() {
        let s = summarize(T.as_bytes());
        let hosts: Vec<_> = s.hosts.iter().map(|h| h.host.as_str()).collect();
        assert!(hosts.contains(&"registry.npmjs.org"), "{hosts:?}");
        assert!(hosts.iter().all(|h| !h.contains("tok")), "{hosts:?}");
        let npm = s.hosts.iter().find(|h| h.host == "registry.npmjs.org").unwrap();
        assert_eq!(npm.count, 3);
        assert_eq!(npm.routes, ["artifact", "index"]);
    }

    #[test]
    fn an_empty_transcript_is_an_empty_summary_not_an_error() {
        assert_eq!(summarize(b""), Summary::default());
    }
}
