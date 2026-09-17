//! Filtering a NuGet V3 feed to a moment.
//!
//! **The registration index is the only NuGet document that carries dates.** The flat container's
//! `{id}/index.json` is a bare `{"versions": [...]}` array with nothing to filter on, so a mirror
//! that proxied it would pass every version through and quietly do nothing — the same shape as the
//! PyPI HTML index this crate refuses to serve. So the registration is filtered and the flat
//! container's version list is *derived* from what survives.
//!
//! **Pages are the trap.** A registration index splits into pages, and a page either carries its
//! leaves inline or carries only an `@id` to fetch them from. Which one you get depends on how many
//! versions the package has: `newtonsoft.json` and `azure.core` are entirely inline, and
//! `system.text.json` has three pages and **none** of them inline. A filter that reads only the
//! inline `items` therefore works perfectly in testing and silently passes everything for exactly
//! the packages most likely to be depended on. Every page is resolved before anything is filtered.

use serde_json::{Value, json};

use crate::moment::published_by;

/// Upstream, SemVer2 and gzipped.
///
/// The `-gz-` variants are what nuget.org advertises for `RegistrationsBaseUrl/3.6.0`, and the
/// client that talks to us never sees them: the index client has reqwest's `gzip` feature, so this
/// is decompressed here and served on as plain JSON. Taking the SemVer1 feed instead would have
/// avoided the compression and silently dropped every SemVer2-only package from the answer.
pub const REGISTRATION_BASE: &str = "https://api.nuget.org/v3/registration5-gz-semver2";

/// Upstream flat container, which serves the `.nupkg` bytes themselves.
pub const FLAT_BASE: &str = "https://api.nuget.org/v3-flatcontainer";

/// The service index this mirror serves in place of `https://api.nuget.org/v3/index.json`.
///
/// Only the two resources a restore needs, pointed back here. Advertising fewer resources than
/// nuget.org is legitimate and deliberate: a `SearchQueryService` we do not filter would be a route
/// to unfiltered metadata, and there is no reason for a build to search.
/// `base` is this mirror's NuGet root *including the moment* — `http://host/-nuget/<moment>` — so
/// every resource below is one path segment away from it. Appending `/-nuget/` again here produced
/// `/-nuget/<moment>/-nuget/flat/`, which answered 404 and which restore reported as
/// `NU1101 … No packages exist with this id`: a message about the package, for a broken URL.
pub fn service_index(base: &str) -> Value {
    let base = base.trim_end_matches('/');
    json!({
        "version": "3.0.0",
        "resources": [
            {
                "@id": format!("{base}/flat/"),
                "@type": "PackageBaseAddress/3.0.0",
                "comment": "Filtered to this run's moment by trigon."
            },
            // Every registration alias the client might ask for, all pointing at the one route.
            // A client picks the highest it supports; omitting the older names would make an older
            // client fall through to no registration resource at all and fail to resolve.
            {
                "@id": format!("{base}/reg/"),
                "@type": "RegistrationsBaseUrl",
                "comment": "Filtered to this run's moment by trigon."
            },
            {
                "@id": format!("{base}/reg/"),
                "@type": "RegistrationsBaseUrl/3.0.0-rc"
            },
            {
                "@id": format!("{base}/reg/"),
                "@type": "RegistrationsBaseUrl/3.4.0"
            },
            {
                "@id": format!("{base}/reg/"),
                "@type": "RegistrationsBaseUrl/3.6.0"
            },
            {
                "@id": format!("{base}/reg/"),
                "@type": "RegistrationsBaseUrl/Versioned"
            }
        ]
    })
}

/// Whether a registration page carries its leaves, or only a URL to fetch them from.
pub fn page_is_inline(page: &Value) -> bool {
    page.get("items").and_then(Value::as_array).is_some()
}

/// The URL a non-inline page's leaves live at.
pub fn page_url(page: &Value) -> Option<&str> {
    page.get("@id").and_then(Value::as_str)
}

/// Package ids that are part of the .NET toolchain rather than of a package's dependency graph.
///
/// **Exempt from the moment filter, for the reason the `-toolchain` route exists.** The SDK chooses
/// these itself: build Polly with SDK 8.0.423 and it demands `Microsoft.NETCore.App.Ref 6.0.36`,
/// a targeting pack released in late 2024 — a year *after* Polly 8.2.0 was published. Filtering it
/// out is filtering the wrong thing: the version is a function of the SDK in the image, not of the
/// dependency ranges in the project, so a date filter on it asks when the toolchain was released
/// and calls the answer a dependency decision.
///
/// The measured symptom, which reads as the mirror being broken: `NU1102 … Found 91 version(s) in
/// trigon [ Nearest version: 7.0.0-preview.1.22076.8 ]` — the filter had worked perfectly and left
/// a constraint nothing could satisfy.
///
/// **This does weaken the pin, and deliberately narrowly.** These are Microsoft-owned ids whose
/// content is a function of a pinned SDK, matched by prefix on the lowercased id. Anything a
/// project actually depends on stays filtered. They are counted separately from the moment's
/// removals so `versions_withheld` stays the evidence that the pin bound something.
const TOOLCHAIN_PREFIXES: &[&str] = &[
    "microsoft.netcore.app.",
    "microsoft.aspnetcore.app.",
    "microsoft.windowsdesktop.app.",
    "microsoft.net.illink.",
    "microsoft.net.sdk.",
    "microsoft.netframework.referenceassemblies",
    "microsoft.dotnet.ilcompiler",
    "netstandard.library",
];

/// Whether this id is the toolchain's own, and so not a thing to date.
pub fn is_toolchain_package(id: &str) -> bool {
    let id = id.to_ascii_lowercase();
    TOOLCHAIN_PREFIXES.iter().any(|p| id.starts_with(p))
}

/// Drop every leaf published after the moment. Returns how many went.
///
/// Applied to a page whose `items` are present — a caller that has not resolved remote pages first
/// is filtering a document with nothing in it and will report that it removed nothing, which is
/// indistinguishable from a page where nothing needed removing.
pub fn filter_page(page: &mut Value, moment: &str) -> usize {
    let Some(items) = page.get_mut("items").and_then(Value::as_array_mut) else {
        return 0;
    };
    let before = items.len();
    items.retain(|leaf| {
        let entry = leaf.get("catalogEntry");
        // `published` lives on the catalog entry, not the leaf. A leaf without one cannot be dated
        // and is excluded, which is the same call `pypi.rs` makes for a file with no upload time.
        let Some(ts) = entry
            .and_then(|c| c.get("published"))
            .and_then(Value::as_str)
        else {
            return false;
        };
        // **`1900-01-01` means unlisted, not published in 1900.** Found by the test below rather
        // than reasoned about: filtering Newtonsoft.Json to mid-2018 removed every *listed*
        // release after the moment and left 13.0.4-beta1 standing, because a delisted package
        // carries that sentinel and the sentinel precedes every moment there is. The effect was a
        // filter that worked on exactly the versions nobody was going to resolve and passed the
        // unlisted ones through for ever.
        //
        // Excluded rather than dated: an unlisted version is one the author withdrew, so offering
        // it to a resolver is wrong quite apart from the arithmetic.
        // `trigon-registry`'s NuGet client already knew this; the mirror did not.
        if ts.starts_with("1900-01-01") {
            return false;
        }
        // And where the feed says so outright. Cheaper than the sentinel and not always present.
        if entry.and_then(|c| c.get("listed")).and_then(Value::as_bool) == Some(false) {
            return false;
        }
        // The toolchain's own packages are pinned by the SDK rather than resolved by date.
        if entry
            .and_then(|c| c.get("id"))
            .and_then(Value::as_str)
            .is_some_and(is_toolchain_package)
        {
            return true;
        }
        published_by(ts, moment)
    });
    let after = items.len();
    // `count` is the client's own check on the page. Leaving it at the pre-filter number makes a
    // filtered page self-inconsistent, and NuGet reports that as a corrupt feed rather than as a
    // short one.
    if let Some(c) = page.get_mut("count") {
        *c = json!(after);
    }
    before - after
}

/// Drop the one version this run is rebuilding, wherever it appears.
///
/// The same reasoning as `pypi::withhold_version`: the guard already refuses the target's own
/// bytes, but a resolver told a version exists and then denied the file *fails* rather than
/// choosing another. A version that was never offered is routed around instead. This matters more
/// here than anywhere else, because .NET packages routinely depend on an earlier release of
/// themselves — Polly 8.2.0's own projects reference `Polly.Core 8.1.0`.
///
/// Counted separately from the moment filter, so `versions_withheld` stays the evidence that the
/// pin bound something rather than a total of two different removals.
pub fn withhold_version(page: &mut Value, w: &crate::guard::Withheld) -> usize {
    let Some(items) = page.get_mut("items").and_then(Value::as_array_mut) else {
        return 0;
    };
    let before = items.len();
    items.retain(|leaf| {
        let e = leaf.get("catalogEntry");
        let id = e.and_then(|c| c.get("id")).and_then(Value::as_str);
        let version = e.and_then(|c| c.get("version")).and_then(Value::as_str);
        match (id, version) {
            // NuGet ids are case-insensitive and versions are not, but a published version string
            // is served back verbatim, so an exact match on version and a folded one on id is what
            // the feed itself guarantees.
            (Some(i), Some(v)) => !(i.eq_ignore_ascii_case(&w.project) && v == w.version),
            _ => true,
        }
    });
    let after = items.len();
    if let Some(c) = page.get_mut("count") {
        *c = json!(after);
    }
    before - after
}

/// Point every URL in a page back at this mirror.
///
/// `packageContent` is the one that must be rewritten or nothing works: it is an absolute
/// `api.nuget.org` URL, and at an enforced tier that host is unreachable from inside the island.
/// `registration` and the page's own `@id` are rewritten too — a client that followed either would
/// leave the mirror and be refused, which reads as a broken feed rather than as a boundary.
pub fn rewrite_urls(page: &mut Value, base: &str) {
    let base = base.trim_end_matches('/');
    let reg = format!("{base}/reg/");
    let flat = format!("{base}/flat/");

    let rebase = |v: &mut Value, from: &str, to: &str| {
        if let Some(s) = v.as_str()
            && let Some(rest) = s.strip_prefix(from)
        {
            *v = json!(format!("{to}{}", rest.trim_start_matches('/')));
        }
    };

    if let Some(id) = page.get_mut("@id") {
        rebase(id, REGISTRATION_BASE, &reg);
    }
    let Some(items) = page.get_mut("items").and_then(Value::as_array_mut) else {
        return;
    };
    for leaf in items {
        // `packageContent` appears twice — on the leaf and again on its catalog entry — and NuGet
        // reads whichever it finds first, so both are rewritten.
        if let Some(v) = leaf.get_mut("packageContent") {
            rebase(v, FLAT_BASE, &flat);
        }
        if let Some(v) = leaf
            .get_mut("catalogEntry")
            .and_then(|c| c.get_mut("packageContent"))
        {
            rebase(v, FLAT_BASE, &flat);
        }
        for key in ["@id", "registration"] {
            if let Some(v) = leaf.get_mut(key) {
                rebase(v, REGISTRATION_BASE, &reg);
            }
        }
    }
}

/// Every version surviving in a set of filtered pages, in the order the feed gave them.
///
/// This is what the flat container's `{id}/index.json` must answer with. Derived rather than
/// proxied, because the upstream version list carries no dates and so cannot be filtered at all.
pub fn versions(pages: &[Value]) -> Vec<String> {
    let mut out = Vec::new();
    for page in pages {
        let Some(items) = page.get("items").and_then(Value::as_array) else {
            continue;
        };
        for leaf in items {
            if let Some(v) = leaf
                .get("catalogEntry")
                .and_then(|c| c.get("version"))
                .and_then(Value::as_str)
            {
                out.push(v.to_string());
            }
        }
    }
    out
}

/// A package id as the feed spells it in a URL.
pub fn normalized(id: &str) -> String {
    id.trim().to_ascii_lowercase()
}
