//! A framing-level description of how two stabilized archives differ.
//!
//! The differential test needs to answer "what, exactly, is different" rather than "the digests
//! disagree", for one reason: a deviation list keyed by artifact name is a hiding place. Adding a
//! filename to an exemption list takes no thought and silences a real bug as readily as a known
//! one. A deviation keyed by *what the difference is* cannot: a wheel that differs for a new reason
//! stays unexplained even though every other wheel in the corpus is exempt.
//!
//! So each mismatch is reduced to a set of codes naming the fields that differ, and a deviation
//! declares the codes it explains. An artifact is explained when every code it produced is claimed
//! by some deviation. See `docs/05-archive-and-normalization.md` §6.
//!
//! Codes are stable strings of the form `<what>@<path>`, or bare `<what>` for whole-archive
//! properties:
//!
//! ```text
//! container:gzip.os                       the outer gzip header's OS byte
//! entry-order                             same members, different order
//! member-only-in-reference@pkg/x.txt      membership
//! entry:tar.uid@pkg/x.txt                 a header field
//! body@pkg/.cargo_vcs_info.json           the bytes of a member
//! ```

use std::collections::BTreeSet;

use trigon_archive::{Archive, Body, Entry, RawMeta, Trailer};

/// Compare two stabilized archives and return every difference, named.
///
/// An empty set from two archives with different digests means the difference is below this
/// function's resolution, which is itself a finding: `signature` is the vocabulary the deviation
/// list is written in, so a gap in it is a gap in the test.
pub fn signature(reference: &Archive, ours: &Archive) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    collect(reference, ours, "", &mut out);
    out
}

fn collect(reference: &Archive, ours: &Archive, prefix: &str, out: &mut BTreeSet<String>) {
    if reference.format != ours.format {
        out.insert(format!("container:format{}", at(prefix)));
    }
    trailer(&reference.trailer, &ours.trailer, prefix, out);

    // Members are keyed by (path, ordinal), the same total order the writer sorts by, so a
    // duplicate path in one archive lines up with the same occurrence in the other.
    let key = |e: &Entry| (e.path.as_bytes().to_vec(), e.ordinal);
    let rk: Vec<_> = reference.entries.iter().map(key).collect();
    let ok: Vec<_> = ours.entries.iter().map(key).collect();
    let rset: BTreeSet<_> = rk.iter().cloned().collect();
    let oset: BTreeSet<_> = ok.iter().cloned().collect();

    for k in rset.difference(&oset) {
        out.insert(format!(
            "member-only-in-reference@{prefix}{}",
            String::from_utf8_lossy(&k.0)
        ));
    }
    for k in oset.difference(&rset) {
        out.insert(format!(
            "member-only-in-ours@{prefix}{}",
            String::from_utf8_lossy(&k.0)
        ));
    }
    if rset == oset && rk != ok {
        out.insert(format!("entry-order{}", at(prefix)));
    }

    for r in &reference.entries {
        let Some(o) = ours
            .entries
            .iter()
            .find(|o| o.path == r.path && o.ordinal == r.ordinal)
        else {
            continue;
        };
        entry(r, o, prefix, out);
    }
}

fn entry(r: &Entry, o: &Entry, prefix: &str, out: &mut BTreeSet<String>) {
    let path = format!("{prefix}{}", r.path.to_lossy());
    let mut field = |name: &str| {
        out.insert(format!("entry:{name}@{path}"));
    };

    if r.kind != o.kind {
        field("kind");
    }
    if r.meta.size != o.meta.size {
        field("size");
    }
    if r.meta.mtime != o.meta.mtime {
        field("mtime");
    }
    if r.meta.mode != o.meta.mode {
        field("mode");
    }

    match (&r.raw, &o.raw) {
        (RawMeta::Tar(a), RawMeta::Tar(b)) => {
            if a.typeflag != b.typeflag {
                field("tar.typeflag");
            }
            if a.linkname != b.linkname {
                field("tar.linkname");
            }
            if a.uid != b.uid {
                field("tar.uid");
            }
            if a.gid != b.gid {
                field("tar.gid");
            }
            if a.uname != b.uname {
                field("tar.uname");
            }
            if a.gname != b.gname {
                field("tar.gname");
            }
            if a.devmajor != b.devmajor || a.devminor != b.devminor {
                field("tar.device");
            }
            if a.atime != b.atime {
                field("tar.atime");
            }
            if a.ctime != b.ctime {
                field("tar.ctime");
            }
            // Named individually: a difference in one PAX keyword and a difference in twenty are
            // not the same finding, and an exemption for the first must not cover the second.
            for k in a.pax.keys().chain(b.pax.keys()) {
                if a.pax.get(k) != b.pax.get(k) {
                    out.insert(format!("entry:tar.pax.{k}@{path}"));
                }
            }
        }
        (RawMeta::Zip(a), RawMeta::Zip(b)) => {
            if a.creator_version != b.creator_version {
                field("zip.creator_version");
            }
            if a.reader_version != b.reader_version {
                field("zip.reader_version");
            }
            if a.flags != b.flags {
                field("zip.flags");
            }
            if a.method != b.method {
                field("zip.method");
            }
            if a.crc32 != b.crc32 {
                field("zip.crc32");
            }
            if a.extra != b.extra {
                field("zip.extra");
            }
            if a.comment != b.comment {
                field("zip.comment");
            }
            if a.external_attrs != b.external_attrs {
                field("zip.external_attrs");
            }
            if a.internal_attrs != b.internal_attrs {
                field("zip.internal_attrs");
            }
            if a.dos_datetime != b.dos_datetime {
                field("zip.dos_datetime");
            }
        }
        _ => field("raw.format"),
    }

    // A nested archive descends, so a difference inside a gem's data.tar.gz is named by its inner
    // path rather than collapsing to "the member differs".
    match (&r.body, &o.body) {
        (Body::Nested { inner: a, .. }, Body::Nested { inner: b, .. }) => {
            collect(a, b, &format!("{path}!"), out)
        }
        _ => {
            let (Ok(a), Ok(b)) = (r.body_bytes(), o.body_bytes()) else {
                out.insert(format!("body-unreadable@{path}"));
                return;
            };
            if a != b {
                out.insert(format!("body@{path}"));
            }
        }
    }
}

fn trailer(r: &Trailer, o: &Trailer, prefix: &str, out: &mut BTreeSet<String>) {
    match (r, o) {
        (Trailer::Gzip(a), Trailer::Gzip(b)) => {
            let mut f = |n: &str| {
                out.insert(format!("container:gzip.{n}{}", at(prefix)));
            };
            if a.mtime != b.mtime {
                f("mtime");
            }
            if a.name != b.name {
                f("name");
            }
            if a.comment != b.comment {
                f("comment");
            }
            if a.extra != b.extra {
                f("extra");
            }
            if a.os != b.os {
                f("os");
            }
            if a.xfl != b.xfl {
                f("xfl");
            }
        }
        (Trailer::Zip { comment: a }, Trailer::Zip { comment: b }) if a != b => {
            out.insert(format!("container:zip.comment{}", at(prefix)));
        }
        (a, b) if std::mem::discriminant(a) != std::mem::discriminant(b) => {
            out.insert(format!("container:trailer{}", at(prefix)));
        }
        _ => {}
    }
}

fn at(prefix: &str) -> String {
    if prefix.is_empty() {
        String::new()
    } else {
        format!("@{}", prefix.trim_end_matches('!'))
    }
}

/// Match a code against a deviation pattern, where `*` stands for any run of characters.
///
/// Deliberately not a path glob: `*` crosses `/`, because the useful patterns are things like
/// `body@*/.cargo_vcs_info.json` and `entry:zip.*@*`, and a pattern that stops at a separator makes
/// the common case need two wildcards for no gain.
pub fn matches(pattern: &str, code: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == code;
    }
    let Some(rest) = code.strip_prefix(parts[0]) else {
        return false;
    };
    let last = parts[parts.len() - 1];
    let mut rest = rest;
    for p in &parts[1..parts.len() - 1] {
        match rest.find(p) {
            Some(i) => rest = &rest[i + p.len()..],
            None => return false,
        }
    }
    rest.len() >= last.len() && rest.ends_with(last)
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn patterns_are_anchored_at_both_ends() {
        assert!(matches(
            "body@*/.cargo_vcs_info.json",
            "body@pkg-1.0/.cargo_vcs_info.json"
        ));
        assert!(!matches(
            "body@*/.cargo_vcs_info.json",
            "body@pkg/.cargo_vcs_info.json.bak"
        ));
        assert!(matches("entry:zip.*@*", "entry:zip.creator_version@a/b.py"));
        assert!(!matches("entry:zip.*@*", "entry:tar.uid@a/b.py"));
        assert!(matches("entry-order", "entry-order"));
        assert!(!matches("entry-order", "entry-order@x"));
    }

    #[test]
    fn a_wildcard_may_match_nothing() {
        assert!(matches("body@*", "body@"));
        assert!(matches("a*b*c", "abc"));
        assert!(!matches("a*b*c", "abd"));
    }
}
