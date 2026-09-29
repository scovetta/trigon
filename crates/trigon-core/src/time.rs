//! Reading the instants this project writes.
//!
//! Every time a record carries is RFC 3339 in UTC, to the second, `YYYY-MM-DDTHH:MM:SSZ`, written
//! by one formatter in the binary. Reading one back was done in one place, the watch page, until
//! the publication gate had to subtract two of them; it lives here so the gate and the page read
//! the same instant from the same string.

/// The instant `s` names, as seconds since the Unix epoch.
///
/// `None` for anything that is not the shape this project writes — an offset, a fraction, a date
/// alone — rather than a guess at what it meant: a caller that reads a time it cannot parse as
/// "now" or as "zero" makes a stale thing look fresh or an old thing look new.
pub fn rfc3339_epoch(s: &str) -> Option<i64> {
    let (date, rest) = s.split_once('T')?;
    let time = rest.strip_suffix('Z')?;
    let mut d = date.split('-');
    let (y, m, day): (i64, i64, i64) = (
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
    );
    let mut t = time.split(':');
    let (hh, mm, ss): (i64, i64, i64) = (
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
    );
    if d.next().is_some()
        || t.next().is_some()
        || !(1..=12).contains(&m)
        || !(1..=31).contains(&day)
        || !(0..24).contains(&hh)
        || !(0..60).contains(&mm)
        || !(0..=60).contains(&ss)
    {
        return None;
    }
    // Days from civil, Howard Hinnant's algorithm: the inverse of the formatter in the binary.
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_what_the_binary_writes() {
        assert_eq!(rfc3339_epoch("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(rfc3339_epoch("2026-09-27T00:00:00Z"), Some(1_790_467_200));
        assert_eq!(rfc3339_epoch("2000-02-29T12:34:56Z"), Some(951_827_696));
        assert_eq!(
            rfc3339_epoch("2026-01-01T01:00:00Z").unwrap()
                - rfc3339_epoch("2026-01-01T00:00:00Z").unwrap(),
            3600
        );
    }

    #[test]
    fn refuses_what_it_would_have_to_guess_at() {
        for s in [
            "",
            "2026-09-27",
            "2026-09-27T00:00:00",
            "2026-09-27T00:00:00+02:00",
            "2026-09-27T00:00:00.5Z",
            "2026-13-01T00:00:00Z",
            "2026-09-27T24:00:00Z",
            "2026-09-27T00:00:00:00Z",
            "not a time",
        ] {
            assert_eq!(rfc3339_epoch(s), None, "{s:?}");
        }
    }
}
