//! The divergence feed, `feed/divergences.atom` (`docs/19` §2.3, D7), when `[publish]
//! divergences = "feed"`: ADR-0010's safeguard 4 without infrastructure, a feed maintainers and
//! registry security teams subscribe to, published in the same commit as each divergence.
//!
//! **Regenerated from the log, never edited.** Whoever can push can write a feed entry nobody
//! signed (`docs/19` §8), so the feed is derived whole from the verified log each time a
//! publication logs a divergence, or a record superseding one, and by `--reconcile`: an entry
//! planted in it is gone at the next. It holds the most recent [`ENTRIES`] divergences, newest
//! first; the log holds every one. Each entry names its record by digest and links the record's
//! file and the dispute pointer the record signs, with the command that would falsify it, and one
//! whose record is missing or fails verification says so rather than being left out.
//!
//! Atom (RFC 4287) as UTF-8 text, written here rather than by a library: the elements are few and
//! fixed, and every string that reaches the file is escaped for XML, characters XML cannot carry
//! replaced. An entry's id is the record's digest as an RFC 6920 `ni:` URI, which is permanent and
//! names exactly one record; the feed's is the same over the repository's first origin. The record
//! and the feed are linked relatively, so the feed reads wherever the repository is served from,
//! and a GitHub repository's feed carries an `xml:base` of its file browser as well.

use base64::Engine as _;
use sha2::Digest as _;
use trigon_attest::SupersedeReason;
use trigon_attest::evidence::record_path;
use trigon_attest::log::RecordLeaf;
use trigon_core::Digest;

/// Where the feed is in the repository.
pub(crate) const PATH: &str = "feed/divergences.atom";

/// How many divergences the feed holds: the most recent, by their place in the log.
pub(crate) const ENTRIES: usize = 200;

/// One divergence the log holds, as the feed shows it.
#[derive(Clone, Debug)]
pub(crate) struct Item {
    pub leaf: RecordLeaf,
    /// The leaf's index in its log, and that log's origin.
    pub index: u64,
    pub origin: String,
    pub read: Read,
    /// The logged record that supersedes it, where one does.
    pub superseded: Option<Superseding>,
}

/// What reading a divergence's record found.
#[derive(Clone, Debug)]
pub(crate) enum Read {
    /// It verified: where it is disputed and the command that would falsify it, as it signs them.
    Verified {
        dispute: Option<String>,
        command: Option<String>,
    },
    /// The log holds its leaf and the repository no file: every client reports it deleted.
    Missing,
    /// It failed verification, and why.
    Failed(String),
}

/// A record that supersedes a divergence.
#[derive(Clone, Debug)]
pub(crate) struct Superseding {
    pub record: Digest,
    pub index: u64,
    pub origin: String,
    pub reason: SupersedeReason,
    pub time: u64,
}

/// The feed's own facts.
#[derive(Clone, Debug)]
pub(crate) struct Meta {
    /// The origin of the repository's first log, which names the feed for good.
    pub first_origin: String,
    /// The origin of the log publications append to now.
    pub origin: String,
    /// A base the relative links resolve against, where the repository's web address is known.
    pub base: Option<String>,
    /// When the feed was last updated where it holds no entry: the newest leaf's time.
    pub quiet: u64,
}

/// The feed of `items` — every divergence the log holds, in the log's order — as bytes: the most
/// recent [`ENTRIES`], newest first.
pub(crate) fn render(items: &[Item], meta: &Meta) -> Vec<u8> {
    let shown: Vec<&Item> = items.iter().rev().take(ENTRIES).collect();
    let updated = shown.iter().map(|i| updated(i)).max().unwrap_or(meta.quiet);
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    out.push_str("<feed xmlns=\"http://www.w3.org/2005/Atom\"");
    if let Some(base) = &meta.base {
        out.push_str(&format!(" xml:base=\"{}\"", attr(base)));
    }
    out.push_str(">\n");
    let id = ni(&sha2::Sha256::digest(
        format!("trigon divergence feed\n{}\n", meta.first_origin).as_bytes(),
    ));
    out.push_str(&format!("  <id>{id}</id>\n"));
    out.push_str(&format!(
        "  <title>Trigon divergences: {}</title>\n",
        text(&meta.origin)
    ));
    out.push_str(&format!(
        "  <subtitle>The most recent {ENTRIES} divergences published to this evidence \
         repository, newest first. Each is a claim that a package does not match its source, with \
         where to dispute it; the log holds every one, and this feed is regenerated from it.\
         </subtitle>\n"
    ));
    out.push_str(&format!("  <updated>{}</updated>\n", date(updated)));
    out.push_str("  <author><name>trigon publish</name></author>\n");
    out.push_str("  <generator>trigon</generator>\n");
    out.push_str("  <link rel=\"self\" href=\"divergences.atom\"/>\n");
    for item in shown {
        entry(&mut out, item);
    }
    out.push_str("</feed>\n");
    out.into_bytes()
}

/// When an item last changed: when it was logged, or when what supersedes it was.
fn updated(i: &Item) -> u64 {
    i.superseded.as_ref().map_or(i.leaf.time, |s| s.time)
}

fn entry(out: &mut String, i: &Item) {
    let l = &i.leaf;
    out.push_str("  <entry>\n");
    out.push_str(&format!("    <id>{}</id>\n", ni(l.record.as_bytes())));
    out.push_str(&format!(
        "    <title>divergent: {}</title>\n",
        text(&l.purl)
    ));
    out.push_str(&format!("    <published>{}</published>\n", date(l.time)));
    out.push_str(&format!("    <updated>{}</updated>\n", date(updated(i))));
    out.push_str(&format!(
        "    <link rel=\"alternate\" type=\"application/json\" href=\"../{}\"/>\n",
        attr(&record_path(&l.record))
    ));
    if let Read::Verified {
        dispute: Some(url), ..
    } = &i.read
    {
        out.push_str(&format!(
            "    <link rel=\"related\" href=\"{}\" title=\"Where to dispute it\"/>\n",
            attr(url)
        ));
    }
    out.push_str("    <category term=\"divergent\"/>\n");
    if i.superseded.is_some() {
        out.push_str("    <category term=\"superseded\"/>\n");
    }
    let mut body = Vec::new();
    if let Some(s) = &i.superseded {
        body.push(format!(
            "Superseded ({}) by the record sha256:{}, leaf {} of {}, logged {}.",
            s.reason.as_str(),
            s.record.to_hex(),
            s.index,
            s.origin,
            date(s.time)
        ));
    }
    body.push(format!(
        "Trigon rebuilt {} from its source, and the rebuild diverges from the published \
         artifact.",
        l.purl
    ));
    for (alg, hex) in &l.subject {
        body.push(format!("Artifact {alg}: {hex}"));
    }
    if let Some(set) = &l.stabilizer_set {
        body.push(format!("Stabilizer set: sha256:{}", set.to_hex()));
    }
    body.push(format!(
        "Record: sha256:{}, leaf {} of {}, logged {}.",
        l.record.to_hex(),
        i.index,
        i.origin,
        date(l.time)
    ));
    match &i.read {
        Read::Verified { dispute, command } => {
            if let Some(url) = dispute {
                body.push(format!("Dispute it: {url}"));
            }
            if let Some(c) = command {
                body.push(format!("Check it yourself: {c}"));
            }
        }
        Read::Missing => body.push(
            "Its record file is not in the repository, though the log holds its leaf: every \
             client reports it as deleted."
                .into(),
        ),
        Read::Failed(why) => body.push(format!(
            "Its record fails verification, and every client reports it so: {why}"
        )),
    }
    out.push_str(&format!(
        "    <content type=\"text\">{}</content>\n",
        text(&body.join("\n"))
    ));
    out.push_str("  </entry>\n");
}

/// A digest as an RFC 6920 named-information URI: `ni:///sha-256;<base64url, unpadded>`.
fn ni(digest: &[u8]) -> String {
    format!(
        "ni:///sha-256;{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    )
}

/// A Unix time as RFC 3339, as Atom's dates are.
fn date(t: u64) -> String {
    crate::rfc3339_from_unix(t)
}

/// Text for an element's content: escaped for XML, and every character XML 1.0 cannot carry
/// replaced, since a purl or a URL in a signed statement is anyone's bytes until it is shown.
fn text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\n' | '\t' => out.push(c),
            c if (c as u32) < 0x20 || matches!(c, '\u{fffe}' | '\u{ffff}') => out.push('\u{fffd}'),
            c => out.push(c),
        }
    }
    out
}

/// Text for an attribute's value, in double quotes.
fn attr(s: &str) -> String {
    text(s)
        .replace('"', "&quot;")
        .replace('\n', "&#10;")
        .replace('\t', "&#9;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn item(n: u64, dispute: Option<&str>) -> Item {
        let d = |s: &str| Digest::from_bytes(sha2::Sha256::digest(s.as_bytes()).into());
        Item {
            leaf: RecordLeaf {
                time: 1_790_467_200 + n,
                subject: BTreeMap::from([("sha256".into(), d(&format!("a{n}")).to_hex())]),
                purl: format!("pkg:npm/demo-{n}@1.0.0"),
                purl_canon: 1,
                predicate_type: trigon_attest::DIVERGENCE_V2.into(),
                outcome: Some(trigon_attest::log::LeafOutcome::Divergent),
                stabilizer_set: Some(d("set")),
                key_id: "0123456789abcdef".into(),
                record: d(&format!("record {n}")),
                supersedes: None,
                reason: None,
            },
            index: n,
            origin: "example.com/trigon-evidence".into(),
            read: Read::Verified {
                dispute: dispute.map(str::to_string),
                command: Some(format!(
                    "trigon verify-attestation --lookup sha256:{n} --origin example.com/<x>"
                )),
            },
            superseded: None,
        }
    }

    fn meta() -> Meta {
        Meta {
            first_origin: "example.com/trigon-evidence".into(),
            origin: "example.com/trigon-evidence".into(),
            base: None,
            quiet: 1_790_467_200,
        }
    }

    const ATOM: &str = "http://www.w3.org/2005/Atom";

    fn child<'a>(n: roxmltree::Node<'a, 'a>, name: &str) -> Vec<roxmltree::Node<'a, 'a>> {
        n.children()
            .filter(|c| c.tag_name().namespace() == Some(ATOM) && c.tag_name().name() == name)
            .collect()
    }

    /// Valid Atom, parsed by an XML parser: the feed's and each entry's required elements, the
    /// record and the dispute pointer linked, and the most recent entries only, newest first.
    #[test]
    fn the_feed_is_atom_and_holds_the_most_recent_divergences() {
        let items: Vec<Item> = (0..ENTRIES as u64 + 50)
            .map(|n| item(n, Some("https://example.com/issues")))
            .collect();
        let bytes = render(&items, &meta());
        let xml = String::from_utf8(bytes).unwrap();
        let doc = roxmltree::Document::parse(&xml).unwrap();
        let feed = doc.root_element();
        assert_eq!(feed.tag_name().namespace(), Some(ATOM));
        assert_eq!(feed.tag_name().name(), "feed");
        for required in ["id", "title", "updated", "author"] {
            assert_eq!(child(feed, required).len(), 1, "{required}");
        }
        let entries = child(feed, "entry");
        assert_eq!(entries.len(), ENTRIES);
        // Newest first: the last item logged is the first entry, and the oldest fifty are gone.
        let title = |e: roxmltree::Node| child(e, "title")[0].text().unwrap().to_string();
        assert_eq!(
            title(entries[0]),
            format!("divergent: pkg:npm/demo-{}@1.0.0", ENTRIES + 49)
        );
        assert_eq!(
            title(entries[ENTRIES - 1]),
            "divergent: pkg:npm/demo-50@1.0.0"
        );
        for e in &entries {
            for required in ["id", "title", "updated", "published", "content"] {
                assert_eq!(child(*e, required).len(), 1, "{required}");
            }
            assert!(
                child(*e, "id")[0]
                    .text()
                    .unwrap()
                    .starts_with("ni:///sha-256;")
            );
            let links = child(*e, "link");
            let href = |rel: &str| {
                links
                    .iter()
                    .find(|l| l.attribute("rel") == Some(rel))
                    .and_then(|l| l.attribute("href"))
            };
            assert!(href("alternate").unwrap().starts_with("../records/"));
            assert_eq!(href("related"), Some("https://example.com/issues"));
        }
        // The feed is as new as its newest entry.
        assert_eq!(
            child(feed, "updated")[0].text().unwrap(),
            crate::rfc3339_from_unix(1_790_467_200 + ENTRIES as u64 + 49)
        );
    }

    /// What a signed statement or a leaf carries is escaped, and a character XML cannot hold is
    /// replaced rather than written: the feed parses whatever the record says.
    #[test]
    fn a_record_s_strings_cannot_break_the_feed() {
        let mut i = item(1, Some("https://example.com/i?a=1&b=\"<x>\"\u{1}"));
        i.leaf.purl = "pkg:npm/%3C%2Ffeed%3E@1.0.0".into();
        i.read = Read::Verified {
            dispute: Some("https://example.com/i?a=1&b=\"<x>\"\u{1}".into()),
            command: Some("</content></entry></feed>\u{0}".into()),
        };
        let mut failed = item(2, None);
        failed.read = Read::Failed("<script>".into());
        let mut gone = item(3, None);
        gone.read = Read::Missing;
        gone.superseded = Some(Superseding {
            record: failed.leaf.record,
            index: 9,
            origin: "example.com/trigon-evidence".into(),
            reason: SupersedeReason::Withdrawn,
            time: 1_790_500_000,
        });
        let xml = String::from_utf8(render(
            &[i, failed, gone],
            &Meta {
                base: Some("https://github.com/o/r/blob/main/feed/".into()),
                ..meta()
            },
        ))
        .unwrap();
        let doc = roxmltree::Document::parse(&xml).unwrap();
        let entries = child(doc.root_element(), "entry");
        assert_eq!(entries.len(), 3);
        let content = |e: roxmltree::Node| child(e, "content")[0].text().unwrap().to_string();
        assert!(content(entries[0]).starts_with("Superseded (withdrawn)"));
        assert!(content(entries[0]).contains("reports it as deleted"));
        assert!(content(entries[1]).contains("<script>"));
        assert!(content(entries[2]).contains("</content></entry></feed>\u{fffd}"));
        assert_eq!(
            doc.root_element()
                .attribute(("http://www.w3.org/XML/1998/namespace", "base")),
            Some("https://github.com/o/r/blob/main/feed/")
        );
    }

    /// A feed with nothing in it is still a feed: dated by the newest leaf, and parsed.
    #[test]
    fn an_empty_feed_is_a_feed() {
        let xml = String::from_utf8(render(&[], &meta())).unwrap();
        let doc = roxmltree::Document::parse(&xml).unwrap();
        assert!(child(doc.root_element(), "entry").is_empty());
        assert_eq!(
            child(doc.root_element(), "updated")[0].text().unwrap(),
            crate::rfc3339_from_unix(1_790_467_200)
        );
    }
}
