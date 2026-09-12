//! A framing-level description of how two stabilized archives differ.
//!
//! Two callers need exactly this vocabulary, which is why it lives here rather than beside either
//! of them:
//!
//! - **The differential test** answers "what, exactly, is different" rather than "the digests
//!   disagree", for one reason: a deviation list keyed by artifact name is a hiding place. Adding a
//!   filename to an exemption list takes no thought and silences a real bug as readily as a known
//!   one. A deviation keyed by *what the difference is* cannot: a wheel that differs for a new
//!   reason stays unexplained even though every other wheel in the corpus is exempt.
//! - **The divergence attestation** must carry a *deterministic* difference signature
//!   (`docs/09-attestations.md`), because a divergence is a public claim about someone else's
//!   package and "these two files differ" is an accusation a maintainer cannot act on. `zip.method`
//!   on four members is something they can.
//!
//! One implementation, because two would drift and the published one is signed.
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
/// `reference` is the side being compared *against* and `ours` is what we produced: the upstream
/// artifact and our rebuild in a comparison, the reference implementation's output and our
/// stabilizer's in the differential test. The code names follow that, so
/// `member-only-in-reference` in a divergence means the published artifact has a file our rebuild
/// does not.
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

    // Members are keyed by (path, *occurrence of that path*), so a duplicate path in one archive
    // lines up with the same occurrence in the other.
    //
    // Not `Entry::ordinal`, which is the entry's position in the archive. Keying on that made every
    // member of an archive whose length differs look unmatched: `escalade 3.2.0` publishes seven
    // files `npm pack` does not produce, and this named `package.json` as present only in the
    // rebuild *and* only in the published artifact, while the member diff correctly called it
    // identical. These codes go into a signed divergence statement about somebody else's package,
    // which makes a false one the most expensive kind of wrong there is (`docs/09` §10.3).
    let rk = keys(&reference.entries);
    let ok = keys(&ours.entries);
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

    // Paired by the same key, so the second `lib/index.js` in one is compared with the second in
    // the other rather than with whatever sits at the same position.
    let paired: std::collections::BTreeMap<_, _> = ok.iter().cloned().zip(&ours.entries).collect();
    for (k, r) in rk.iter().zip(&reference.entries) {
        let Some(o) = paired.get(k) else {
            continue;
        };
        entry(r, o, prefix, out);
    }
}

/// `(path, occurrence)` for each entry, in archive order.
fn keys(entries: &[Entry]) -> Vec<(Vec<u8>, u32)> {
    let mut seen: std::collections::BTreeMap<Vec<u8>, u32> = Default::default();
    entries
        .iter()
        .map(|e| {
            let path = e.path.as_bytes().to_vec();
            let n = seen.entry(path.clone()).or_insert(0);
            let key = (path, *n);
            *n += 1;
            key
        })
        .collect()
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
    use super::{matches, signature};
    use trigon_archive::{Archive, Limits};
    use trigon_core::Format;

    /// A tar holding these paths, in this order, each with the same body.
    fn tar(paths: &[&str]) -> Archive {
        let mut b = ::tar::Builder::new(Vec::new());
        for p in paths {
            let mut h = ::tar::Header::new_ustar();
            h.set_size(1);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, p, &b"x"[..]).unwrap();
        }
        let bytes = b.into_inner().unwrap();
        trigon_archive::parse(bytes, Format::Tar, &Limits::default(), &mut Vec::new())
            .unwrap()
            .archive
    }

    #[test]
    fn a_member_present_in_both_is_not_named_as_missing_from_either() {
        // Found on `escalade 3.2.0`, whose published tarball carries seven files `npm pack` does
        // not produce. Keyed on `Entry::ordinal` — the position in the archive — every member after
        // the first difference looked unmatched, so `package.json` was reported as present only in
        // the rebuild *and* only in the published artifact while the member diff called it
        // identical. These codes go into a signed statement about somebody else's package.
        let published = tar(&["pkg/dist/index.js", "pkg/package.json", "pkg/readme.md"]);
        let ours = tar(&["pkg/package.json", "pkg/readme.md"]);

        let codes = signature(&published, &ours);
        assert!(codes.contains("member-only-in-reference@pkg/dist/index.js"), "{codes:?}");
        assert!(
            !codes.iter().any(|c| c.starts_with("member-only-in-ours@")),
            "the rebuild has no file the published artifact lacks: {codes:?}"
        );
        assert!(
            !codes.contains("member-only-in-reference@pkg/package.json"),
            "a file present in both was named as missing: {codes:?}"
        );
    }

    #[test]
    fn a_duplicate_path_lines_up_with_the_same_occurrence() {
        // What the key exists for. Two archives holding `a` twice must compare first-with-first,
        // whatever else sits between them.
        let reference = tar(&["a", "b", "a"]);
        let ours = tar(&["a", "a"]);
        let codes = signature(&reference, &ours);
        assert!(codes.contains("member-only-in-reference@b"), "{codes:?}");
        assert!(
            !codes.iter().any(|c| c.starts_with("member-only-in-ours@")),
            "{codes:?}"
        );
    }

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
