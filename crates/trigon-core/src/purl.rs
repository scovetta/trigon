//! The canonical form of a package URL, under a numbered set of rules.
//!
//! A purl becomes a lookup key and a signed field (`docs/19` §4.2 item 8, §5): an evidence
//! repository files a record under the sha256 of its canonical purl, with and without the version,
//! and a record found under a purl is accepted only if its signed purl canonicalises to that key.
//! So the rule is part of the lookup protocol, and two spellings of one package that canonicalise
//! differently are two packages to every reader. **The rule is versioned** — [`PURL_CANON`] is
//! signed beside every purl, and is the digit in the `purl1` and `pkg1` index paths — so a change
//! to it starts new keys rather than silently missing old ones.
//!
//! Version 1 is the purl specification's own parse and build procedure, with its per-type case
//! rules, and one deliberate departure: PyPI names are normalised as PEP 503 says, not only as the
//! purl spec does. The test vectors in `crates/trigon-core/testdata/purl-canon-v1.json` are shared
//! by every writer and reader of these keys, including any client not written in Rust; they are the
//! rule's other definition, and the tests hold this code to them.
//!
//! What version 1 does, in order:
//!
//! - The scheme is `pkg`, in any case, and slashes after it are ignored (`pkg://npm/x` is
//!   `pkg:npm/x`). The type is lowercased; `crates.io` and `rubygems`, which Trigon accepts as
//!   types, become `cargo` and `gem`.
//! - Every component is percent-decoded, then re-encoded: ASCII letters, digits and `-._~:` are
//!   written as themselves, and so is `/` inside a version or a qualifier value; every other byte
//!   of the UTF-8 is `%XX` with uppercase hex. `%2d` and `-` are one spelling, as are `@` and
//!   `%40` in an npm scope.
//! - Namespace segments that are empty are dropped. Names and namespaces are lowercased where the
//!   purl spec says the type is case-insensitive, and nowhere else (see [`lowercases_namespace`]
//!   and [`lowercases_name`]); a PyPI name is lowercased and each run of `-`, `_` and `.` becomes
//!   one `-`, which is PEP 503's rule for when two names are the same project. Lowercasing is of
//!   ASCII letters only, so a non-ASCII letter keeps its case and never becomes an ASCII one.
//! - Qualifier keys are lowercased, a pair with an empty value is dropped, a key given twice is
//!   refused, and the pairs are sorted by key.
//! - Subpath segments that decode to nothing, `.` or `..` are dropped, however they were encoded.
//! - The versionless form ([`CanonicalPurl::package`], the `pkg1` key) is the package and nothing
//!   about any one version of it: `pkg:<type>/<namespace>/<name>`, with the `repository_url`
//!   qualifier where there is one and no other. The version goes, and so do the subpath and every
//!   other qualifier, because most qualifiers name one version's files — `file_name`, `checksum`,
//!   `download_url` — and kept, they gave every version its own `pkg1` key, where the key is meant
//!   to find every version. `repository_url` stays because it changes which package this is: the
//!   same name on another registry is another package.
//!
//! Lenient where the intent is unambiguous: an unencoded npm scope, `pkg:npm/@babel/core@7.24.0`,
//! is read as the purl spec's `pkg:npm/%40babel/core@7.24.0`, because an `@` that begins a path
//! segment cannot be a version separator. Strict where it is not: whitespace, a malformed escape,
//! bytes that do not decode to UTF-8, and a qualifier key given twice are refused, because any
//! reading of them would be a guess, and a guessed key finds the wrong record or none.

use std::collections::BTreeMap;
use std::fmt;

/// The canonicalisation version this code implements. Signed beside every canonical purl as
/// `purlCanon`, and the digit in the `purl1` and `pkg1` index paths (`docs/19` §5).
pub const PURL_CANON: u32 = 1;

/// A package URL in canonical form, with and without its version.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CanonicalPurl {
    purl: String,
    package: String,
    versioned: bool,
}

impl CanonicalPurl {
    /// The canonical purl: what a statement signs, and what the `purl1` key hashes.
    pub fn as_str(&self) -> &str {
        &self.purl
    }

    /// The package, without anything that names one version of it: what the `pkg1` key hashes.
    ///
    /// `pkg:<type>/<namespace>/<name>`, and the `repository_url` qualifier where the purl has one,
    /// which says which registry's package this is. No version, no subpath, and no other
    /// qualifier, since `file_name`, `checksum` and `download_url` each name one version's files.
    /// The same string as [`Self::as_str`] only for a purl with none of those.
    pub fn package(&self) -> &str {
        &self.package
    }

    /// Whether the purl named a version. A statement's purl always does; a lookup by package may
    /// not.
    pub fn has_version(&self) -> bool {
        self.versioned
    }
}

impl fmt::Display for CanonicalPurl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.purl)
    }
}

/// Why a string has no canonical form.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PurlCanonError {
    #[error("`{0}` is not a package URL: a package URL starts with `pkg:`")]
    NotAPurl(String),
    #[error(
        "`{0}` contains whitespace or a control character. A package URL carries none; \
         percent-encode it (a space is `%20`)"
    )]
    Whitespace(String),
    #[error("`{0}` names no type: a package URL is `pkg:<type>/<name>`, as in `pkg:npm/left-pad`")]
    NoType(String),
    #[error(
        "`{purl}` has the type `{ty}`, which is not a purl type: a type is ASCII letters, digits, \
         `.`, `+` and `-`, and does not start with a digit"
    )]
    BadType { purl: String, ty: String },
    #[error("`{0}` names no package: a package URL is `pkg:<type>/<name>`")]
    NoName(String),
    #[error(
        "`{0}` ends its version separator with nothing after it. Drop the `@`, or name the version"
    )]
    EmptyVersion(String),
    #[error(
        "`{purl}` has a malformed percent-escape at `{near}`: a `%` is followed by two hex digits, \
         and a literal `%` is written `%25`"
    )]
    BadEscape { purl: String, near: String },
    #[error("the {component} of `{purl}` percent-decodes to bytes that are not UTF-8")]
    NotUtf8 {
        purl: String,
        component: &'static str,
    },
    #[error(
        "`{purl}` has the qualifier key `{key}`. A key is ASCII letters, digits, `.`, `-` and `_`, \
         does not start with a digit, and is never percent-encoded"
    )]
    BadQualifierKey { purl: String, key: String },
    #[error(
        "`{purl}` gives the qualifier `{key}` more than once (keys are compared lowercased). \
         Which one is meant is a guess, and a guessed key finds the wrong record"
    )]
    DuplicateQualifier { purl: String, key: String },
}

/// The canonical form of `purl` under version [`PURL_CANON`].
pub fn canonicalize(purl: &str) -> Result<CanonicalPurl, PurlCanonError> {
    if purl.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(PurlCanonError::Whitespace(purl.to_string()));
    }

    // The purl spec's parse, right to left: subpath, then qualifiers, then the scheme from the
    // left. Each separator is unambiguous in its position because the spec requires it encoded
    // anywhere else.
    let (rest, subpath) = match purl.rsplit_once('#') {
        Some((rest, sub)) => (rest, Some(sub)),
        None => (purl, None),
    };
    let (rest, qualifiers) = match rest.rsplit_once('?') {
        Some((rest, q)) => (rest, Some(q)),
        None => (rest, None),
    };
    let (scheme, rest) = rest
        .split_once(':')
        .ok_or_else(|| PurlCanonError::NotAPurl(purl.to_string()))?;
    if !scheme.eq_ignore_ascii_case("pkg") {
        return Err(PurlCanonError::NotAPurl(purl.to_string()));
    }

    // `pkg://npm/…` is accepted and read as `pkg:npm/…`, as the spec requires of a parser.
    let rest = rest.trim_start_matches('/');
    let (ty, rest) = rest.split_once('/').ok_or_else(|| match rest.is_empty() {
        true => PurlCanonError::NoType(purl.to_string()),
        false => PurlCanonError::NoName(purl.to_string()),
    })?;
    let ty = canonical_type(purl, ty)?;

    let (path, version) = split_version(rest);
    let version = match version {
        Some("") => return Err(PurlCanonError::EmptyVersion(purl.to_string())),
        Some(v) => Some(decode(purl, v, "version")?),
        None => None,
    };
    let path = path.trim_matches('/');

    let (namespace, name) = match path.rsplit_once('/') {
        Some((ns, name)) => (Some(ns), name),
        None => (None, path),
    };
    let mut name = decode(purl, name, "name")?;
    if name.is_empty() {
        return Err(PurlCanonError::NoName(purl.to_string()));
    }
    let mut segments = Vec::new();
    for segment in namespace.into_iter().flat_map(|ns| ns.split('/')) {
        if !segment.is_empty() {
            segments.push(decode(purl, segment, "namespace")?);
        }
    }

    // ASCII only. Every type lowercased here spells its names in ASCII, so this loses nothing a
    // registry would accept, and Unicode's case mapping would merge names that are not the same:
    // KELVIN SIGN lowercases to `k`, which made `%E2%84%AAeras` the key of `keras`. It is also not
    // one mapping — full and simple case folding disagree on `İ` — and a client in another
    // language would compute another key.
    if lowercases_namespace(&ty) {
        for s in &mut segments {
            s.make_ascii_lowercase();
        }
    }
    if ty == "pypi" {
        name = pep503(&name);
    } else if lowercases_name(&ty) {
        name.make_ascii_lowercase();
    }

    let qualifiers = match qualifiers {
        Some(q) => canonical_qualifiers(purl, q)?,
        None => BTreeMap::new(),
    };
    // Dropped by what a segment decodes to, not by how it was written: `%2E%2E` and `..` are one
    // spelling, as every `%XX` of an unreserved byte is, and dropping only the literal one wrote
    // `..` back out of `%2E%2E` — a canonical form that canonicalised again to another key.
    let mut subpath_segments = Vec::new();
    for segment in subpath.into_iter().flat_map(|s| s.split('/')) {
        let segment = decode(purl, segment, "subpath")?;
        if !matches!(segment.as_str(), "" | "." | "..") {
            subpath_segments.push(segment);
        }
    }

    let mut package = format!("pkg:{ty}/");
    for s in &segments {
        package.push_str(&encode(s, false));
        package.push('/');
    }
    package.push_str(&encode(&name, false));
    // The package alone, for the `pkg1` key: its registry, where the purl names one, and nothing
    // that names a version's files.
    let package_key = match qualifiers.get("repository_url") {
        Some(url) => format!("{package}?repository_url={}", encode(url, true)),
        None => package.clone(),
    };
    let mut tail = String::new();
    for (i, (k, v)) in qualifiers.iter().enumerate() {
        tail.push(if i == 0 { '?' } else { '&' });
        tail.push_str(k);
        tail.push('=');
        tail.push_str(&encode(v, true));
    }
    if !subpath_segments.is_empty() {
        tail.push('#');
        let encoded: Vec<String> = subpath_segments.iter().map(|s| encode(s, false)).collect();
        tail.push_str(&encoded.join("/"));
    }

    let purl = match &version {
        Some(v) => format!("{package}@{}{tail}", encode(v, true)),
        None => format!("{package}{tail}"),
    };
    Ok(CanonicalPurl {
        purl,
        package: package_key,
        versioned: version.is_some(),
    })
}

/// Types whose namespace the purl spec says is case-insensitive and lowercased.
///
/// Only where the spec says so. Lowercasing a case-sensitive name merges two packages, which is
/// worse than a lookup by purl that misses: a miss still leaves the digest keys, and a merge
/// answers for the wrong package. So Go module paths, Maven coordinates, NuGet ids and crate names
/// keep their case in version 1, whatever their registries do.
pub fn lowercases_namespace(ty: &str) -> bool {
    matches!(
        ty,
        "alpm" | "apk" | "bitbucket" | "composer" | "deb" | "github" | "hex" | "rpm"
    )
}

/// Types whose name the purl spec says is case-insensitive and lowercased. PyPI is not here: its
/// name gets PEP 503's normalisation, of which lowercasing is one part.
pub fn lowercases_name(ty: &str) -> bool {
    matches!(
        ty,
        "alpm"
            | "apk"
            | "bitbucket"
            | "bitnami"
            | "composer"
            | "deb"
            | "github"
            | "hex"
            | "npm"
            | "oci"
    )
}

/// PEP 503: lowercase, and each run of `-`, `_` and `.` is one `-`.
///
/// Stricter than the purl spec, which maps only `_` to `-`. PyPI resolves `zope.interface`,
/// `zope-interface` and `Zope_Interface` to one project, and a lockfile may spell it any of those
/// ways, so a key that kept them apart would answer "never checked" for a package that was.
/// Lowercased in ASCII only: a PyPI project name is ASCII (PEP 508), so no real name is changed by
/// that, and one that is not ASCII keeps its other letters rather than merging with another name.
fn pep503(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut in_run = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !in_run {
                out.push('-');
            }
            in_run = true;
        } else {
            out.push(c.to_ascii_lowercase());
            in_run = false;
        }
    }
    out
}

fn canonical_type(purl: &str, ty: &str) -> Result<String, PurlCanonError> {
    let ty = ty.to_ascii_lowercase();
    let valid = !ty.is_empty()
        && !ty.starts_with(|c: char| c.is_ascii_digit())
        && ty
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '+' | '-'));
    if !valid {
        return Err(match ty.is_empty() {
            true => PurlCanonError::NoType(purl.to_string()),
            false => PurlCanonError::BadType {
                purl: purl.to_string(),
                ty,
            },
        });
    }
    // The two spellings `TargetRef::from_str` accepts for these ecosystems. Neither is a purl
    // type, and a target written either way is the same package as one written `cargo` or `gem`.
    Ok(match ty.as_str() {
        "crates.io" => "cargo".to_string(),
        "rubygems" => "gem".to_string(),
        _ => ty,
    })
}

/// The path and the version, split at the version separator.
///
/// The last `@` separates the version, as the spec says, **unless it begins a namespace segment**:
/// an npm scope written unencoded, `@babel/core`, is a namespace and never a version. So an `@` at
/// the start of a segment with a `/` somewhere after it is not a separator. One at the start of
/// the last segment still is, as the spec reads it, which leaves `pkg:npm/@1.3.0` with no name
/// rather than a package called `@1.3.0`.
fn split_version(rest: &str) -> (&str, Option<&str>) {
    match rest.rfind('@') {
        Some(at) => {
            let begins_segment = at == 0 || rest.as_bytes()[at - 1] == b'/';
            if begins_segment && rest[at + 1..].contains('/') {
                (rest, None)
            } else {
                (&rest[..at], Some(&rest[at + 1..]))
            }
        }
        None => (rest, None),
    }
}

fn canonical_qualifiers(purl: &str, q: &str) -> Result<BTreeMap<String, String>, PurlCanonError> {
    let mut out = BTreeMap::new();
    for pair in q.split('&').filter(|p| !p.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = key.to_ascii_lowercase();
        let valid = !key.is_empty()
            && !key.starts_with(|c: char| c.is_ascii_digit())
            && key.chars().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-' | '_')
            });
        if !valid {
            return Err(PurlCanonError::BadQualifierKey {
                purl: purl.to_string(),
                key,
            });
        }
        let value = decode(purl, value, "qualifiers")?;
        if out.contains_key(&key) {
            return Err(PurlCanonError::DuplicateQualifier {
                purl: purl.to_string(),
                key,
            });
        }
        // Checked for a duplicate before the empty value is dropped, so `?a=&a=1` is refused
        // rather than read as `a=1`: the spec drops an empty value, and it does not say which of
        // two keys wins.
        out.insert(key, value);
    }
    out.retain(|_, v| !v.is_empty());
    Ok(out)
}

fn decode(purl: &str, s: &str, component: &'static str) -> Result<String, PurlCanonError> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            // Two hex digits exactly. `u8::from_str_radix` alone would take `+f`, since it accepts
            // a sign.
            match bytes.get(i + 1..i + 3) {
                Some(&[hi, lo]) if hi.is_ascii_hexdigit() && lo.is_ascii_hexdigit() => {
                    out.push(hex_value(hi) << 4 | hex_value(lo));
                    i += 3;
                }
                _ => {
                    let end = (i + 3).min(s.len());
                    return Err(PurlCanonError::BadEscape {
                        purl: purl.to_string(),
                        near: String::from_utf8_lossy(&bytes[i..end]).into_owned(),
                    });
                }
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| PurlCanonError::NotUtf8 {
        purl: purl.to_string(),
        component,
    })
}

fn hex_value(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        _ => b - b'A' + 10,
    }
}

/// Percent-encode everything but ASCII letters, digits and `-._~:`, and `/` where `slash` says it
/// is unambiguous (a version, a qualifier value).
fn encode(s: &str, slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        let literal = b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'.' | b'_' | b'~' | b':')
            || (slash && b == b'/');
        if literal {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pep503_collapses_runs_and_lowercases() {
        assert_eq!(pep503("Zope.Interface"), "zope-interface");
        assert_eq!(pep503("a__b--c..d"), "a-b-c-d");
        assert_eq!(pep503("a_-.b"), "a-b");
    }

    #[test]
    fn an_at_that_begins_a_segment_is_a_scope_and_never_a_version() {
        assert_eq!(split_version("@babel/core"), ("@babel/core", None));
        assert_eq!(
            split_version("@babel/core@7.24.0"),
            ("@babel/core", Some("7.24.0"))
        );
        assert_eq!(split_version("a/@b/c"), ("a/@b/c", None));
        assert_eq!(split_version("left-pad@1.3.0"), ("left-pad", Some("1.3.0")));
        // The last segment's `@` is the separator, as the spec reads it, and leaves no name.
        assert_eq!(split_version("@1.3.0"), ("", Some("1.3.0")));
        // A version may hold a `/`, and the `@` before it is still the separator.
        assert_eq!(split_version("x@y/z"), ("x", Some("y/z")));
    }

    #[test]
    fn the_encoder_writes_uppercase_hex_and_keeps_the_unreserved_set() {
        assert_eq!(encode("a-b.c_d~e:f", false), "a-b.c_d~e:f");
        assert_eq!(encode("@x", false), "%40x");
        assert_eq!(encode("a/b", false), "a%2Fb");
        assert_eq!(encode("a/b", true), "a/b");
        assert_eq!(encode("1.0+b", true), "1.0%2Bb");
        assert_eq!(encode("caf\u{e9}", false), "caf%C3%A9");
    }
}
