//! Parsing the filter out of a request, and comparing timestamps to it.
//!
//! The filter arrives as HTTP basic auth: `http://npm:2018-04-09T01:10:45.796Z@mirror/`. That looks
//! like a trick and is in fact the only thing that works. A package manager has one configuration
//! knob for its index, a URL, and it must pass the filter through unchanged on every request it
//! makes. Credentials in a URL are the one component every client already forwards, so the filter
//! rides along with no per-client support and no MITM.
//!
//! Timestamps are compared as strings, not as parsed instants. RFC 3339 in UTC with a fixed number
//! of digits sorts lexically in time order, and every registry publishes exactly that. Parsing
//! would mean picking a date library, handling five registry-specific dialects, and introducing a
//! way to be wrong about leap seconds in a comparison that is otherwise a `<=`.

use crate::error::MirrorError;

/// A registry, and the instant to filter it to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Filter {
    pub platform: Platform,
    /// RFC 3339, normalized to a form that compares lexically.
    pub moment: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    Npm,
    PyPI,
}

impl Platform {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "npm" => Some(Platform::Npm),
            "pypi" => Some(Platform::PyPI),
            _ => None,
        }
    }

    pub const fn upstream(self) -> &'static str {
        match self {
            Platform::Npm => "https://registry.npmjs.org",
            Platform::PyPI => "https://pypi.org",
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Platform::Npm => "npm",
            Platform::PyPI => "pypi",
        }
    }
}

impl Filter {
    /// Read the filter from an `Authorization: Basic` header value.
    pub fn from_authorization(header: &str) -> Result<Self, MirrorError> {
        let b64 = header
            .strip_prefix("Basic ")
            .or_else(|| header.strip_prefix("basic "))
            .ok_or(MirrorError::NoFilter)?;
        let decoded = base64_decode(b64.trim()).ok_or(MirrorError::NoFilter)?;
        let text = String::from_utf8(decoded).map_err(|_| MirrorError::NoFilter)?;

        // Split on the FIRST colon. An RFC 3339 timestamp contains two more, and they belong to
        // the timestamp.
        let (user, pass) = text.split_once(':').ok_or(MirrorError::NoFilter)?;
        let platform = Platform::parse(user).ok_or_else(|| MirrorError::UnknownPlatform {
            found: user.to_string(),
        })?;
        Ok(Filter {
            platform,
            moment: normalize(pass)?,
        })
    }
}

/// Normalize a timestamp to a form that compares lexically against registry timestamps.
///
/// Registries publish several shapes of the same instant: npm writes `2018-04-09T01:10:45.796Z` and
/// PyPI writes `2024-02-25T23:20:01.196159Z` or, on the older field, `2024-02-25 23:20:01`. All are
/// UTC, so the only thing standing between them and a lexical comparison is the fractional part and
/// the separator. Both are normalized away: the comparison is at whole-second resolution, which is
/// far finer than the gap between any two releases we are trying to separate.
pub fn normalize(ts: &str) -> Result<String, MirrorError> {
    let t = ts.trim();
    // URL-encoded, because a timestamp in a URL's userinfo often arrives that way.
    let t = if t.contains("%3A") || t.contains("%3a") {
        t.replace("%3A", ":").replace("%3a", ":")
    } else {
        t.to_string()
    };
    let t = t.replace(' ', "T");
    let t = t.strip_suffix('Z').unwrap_or(&t).to_string();
    // Drop any fractional seconds and any offset: everything here is UTC.
    let t = t.split('+').next().unwrap_or(&t).to_string();
    let t = t.split('.').next().unwrap_or(&t).to_string();

    // 2018-04-09T01:10:45 exactly. Anything else is refused rather than compared, because a
    // silently mis-parsed filter would serve a different index than the one asked for and the
    // rebuild would be of a different dependency graph with nothing to show it.
    let b = t.as_bytes();
    let shaped = b.len() == 19
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && b.iter()
            .enumerate()
            .all(|(i, c)| matches!(i, 4 | 7 | 10 | 13 | 16) || c.is_ascii_digit());
    if !shaped {
        return Err(MirrorError::BadMoment {
            found: ts.to_string(),
        });
    }
    Ok(t)
}

/// Whether a registry timestamp is at or before the filter.
///
/// A timestamp that will not normalize is treated as **not** published in time, so it is excluded.
/// The alternative, including what we cannot read, means a rebuild can resolve a version we could
/// not date, which is the failure this whole mechanism exists to prevent.
pub fn published_by(ts: &str, moment: &str) -> bool {
    match normalize(ts) {
        Ok(t) => t.as_str() <= moment,
        Err(_) => {
            tracing::debug!(ts, "unparseable timestamp; excluding it");
            false
        }
    }
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in s.bytes().filter(|c| *c != b'=') {
        let v = ALPHABET.iter().position(|a| *a == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// Build the URL a package manager should be pointed at.
pub fn url_for(host: &str, platform: Platform, moment: &str) -> String {
    format!("http://{}:{moment}@{host}", platform.as_str())
}
