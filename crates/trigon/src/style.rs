//! Colour and weight for the human-readable output, and nothing the machine reads.
//!
//! Three rules, and they are the whole module:
//!
//! - **Colour follows the terminal.** Escape sequences written into a pipe corrupt whatever reads
//!   them, so a result piped to a file or another program is plain — the same principle the log
//!   subscriber already applies to stderr. `--output json` never reaches here.
//! - **`NO_COLOR` wins.** Set to anything non-empty, it turns colour off regardless of the
//!   terminal, per <https://no-color.org>. `CLICOLOR_FORCE` forces it back on for the reader who is
//!   piping into a pager that understands escapes.
//! - **Colour is an accent, never the message.** Every distinction the colour draws — a match from
//!   a divergence, a label from its value — is also there in the words and the symbols, so the
//!   plain output says exactly what the coloured one does. A reader who turned colour off, or whose
//!   terminal never had it, loses nothing but the accent.
//!
//! Widths are computed on the plain text and the colour wrapped around the result, because an
//! escape sequence has bytes but no width: pad first, paint second, or the columns drift by exactly
//! the length of the codes.

use std::io::IsTerminal as _;
use std::sync::OnceLock;

/// Whether stdout is a terminal at all, cached. This is the fact both colour and wrapping turn on:
/// escapes into a pipe corrupt it, and a hard wrap into a pipe changes bytes a program downstream
/// meant to rewrap itself. Decided once — the terminal does not change under us mid-command.
fn is_tty() -> bool {
    static TTY: OnceLock<bool> = OnceLock::new();
    *TTY.get_or_init(|| std::io::stdout().is_terminal())
}

/// Whether to emit escape sequences at all. Decided once — the terminal and the environment do not
/// change under us mid-command — and cheap to ask repeatedly thereafter.
pub fn enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        // Presence with any non-empty value, whatever the value, disables colour. `NO_COLOR=0` is
        // still `NO_COLOR` set; the standard is deliberate about that, and honouring the letter of
        // it is what makes the promise worth relying on.
        if std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()) {
            return false;
        }
        // A terminal that says it cannot do this is taken at its word.
        if std::env::var_os("TERM").is_some_and(|v| v == "dumb") {
            return false;
        }
        // The one override that turns colour back on for a pipe: a pager the reader chose, told to
        // interpret the escapes rather than print them.
        if std::env::var_os("CLICOLOR_FORCE").is_some_and(|v| !v.is_empty() && v != "0") {
            return true;
        }
        is_tty()
    })
}

/// The terminal's usable column count, or `None` when there is no terminal to measure. Read once.
///
/// `COLUMNS` wins when a caller exports it — the reader piping through `less -R` who has chosen a
/// width — and otherwise `TIOCGWINSZ` on stdout answers, behind the same `libc` the crate already
/// links. `None` when stdout is not a terminal, so wrapping leaves piped output as single lines the
/// bytes it always was.
pub fn width() -> Option<usize> {
    static W: OnceLock<Option<usize>> = OnceLock::new();
    *W.get_or_init(|| {
        // An explicit `COLUMNS` is honoured whether or not stdout is a terminal — it is the reader
        // stating a width, for a pager or a captured preview — and it is the only thing that makes
        // a *piped* run wrap. Without it, a pipe measures nothing and the value stays one line.
        if let Some(cols) = std::env::var("COLUMNS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            && cols >= 20
        {
            return Some(cols);
        }
        if !is_tty() {
            return None;
        }
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd as _;
            // SAFETY: `winsize` is plain old data and `ioctl` fills it; the fd is stdout's, valid
            // for the length of the call. A non-zero return or an absurd width falls through.
            let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
            let fd = std::io::stdout().as_raw_fd();
            if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } == 0 && ws.ws_col >= 20 {
                return Some(ws.ws_col as usize);
            }
        }
        // A terminal we could not measure: wrap to a conventional width rather than not at all.
        Some(100)
    })
}

/// Fold a long value to the terminal width with a hanging indent, so an explanation flows *under*
/// its value column instead of wrapping back to the left margin. The first line carries no indent —
/// the caller has already placed it after the label — and every continuation begins at `indent`.
///
/// Piped or redirected ([`width`] is `None`), the value comes back as one line: the layout a
/// program downstream sees is unchanged, and it is free to rewrap. The text must be plain — measure
/// before you paint, or the escape bytes count as width — so a caller wraps, then colours the whole
/// result in one span.
pub fn wrap(value: &str, indent: usize) -> String {
    match width() {
        Some(cols) => wrap_to(cols, value, indent),
        None => value.to_string(),
    }
}

/// The fold itself, against an explicit width, so a test drives it without a terminal.
fn wrap_to(cols: usize, value: &str, indent: usize) -> String {
    let avail = cols.saturating_sub(indent).max(20);
    let pad = " ".repeat(indent);
    let mut out = String::new();
    let mut col = 0usize;
    let mut fresh_line = true;
    for word in value.split(' ') {
        let wlen = word.chars().count();
        if !fresh_line && col + 1 + wlen > avail {
            out.push('\n');
            out.push_str(&pad);
            col = 0;
            fresh_line = true;
        }
        if !fresh_line {
            out.push(' ');
            col += 1;
        }
        out.push_str(word);
        col += wlen;
        fresh_line = false;
    }
    out
}

/// The column a `label   value` line's value starts at: the two-space indent, the label, one space.
/// The indent [`wrap`] hangs a long value under, so callers do not re-derive it.
pub const VALUE_COL: usize = 2 + LABEL + 1;

/// Wrap `text` in one SGR sequence and its reset, or hand it back untouched when colour is off.
///
/// The codes are combined into one parameter string (`"1;32"`) rather than nested, so there is one
/// reset and no inner reset can strip an outer weight. That keeps the styles below flat: none wraps
/// another.
fn paint(code: &str, text: &str) -> String {
    paint_with(enabled(), code, text)
}

/// The wrapping itself, with the decision handed in — so a test can exercise both branches without
/// depending on whether the harness's stdout happens to be a terminal.
fn paint_with(on: bool, code: &str, text: &str) -> String {
    if on {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

/// The one width every `label   value` line pads its label to, tool-wide. A single column means a
/// value starts at the same place in the resolve narration, the build stats, the verdict and the
/// listings alike — so a whole run reads down one edge rather than stepping in and out as the
/// sections change. Twelve fits the longest label that recurs (`isolation`, `stabilizers`) with a
/// space to spare; the rare wider one is styled by hand.
pub const LABEL: usize = 12;

/// A section or phase title — the package reference, `strategy <digest>`, `applied`, `members`.
/// Bold and bright white, so it parts the run into blocks the eye can jump between. Weight over
/// hue here, because a title's job is to separate, and separation reads on any palette.
pub fn heading(text: &str) -> String {
    paint("1;97", text)
}

/// The left-hand word in a label/value pair. **Bold blue** — a real hue with weight behind it, so
/// the key stands off from its value and the whole left edge carries colour rather than the grey it
/// used to. Bright blue rather than plain blue, because a terminal that does not brighten bold
/// leaves plain blue dark and low-contrast on a dark ground — the exact washed-out look this
/// replaces. Blue is the structural colour throughout; cyan, next to it, is reserved for the data.
pub fn label(text: &str) -> String {
    paint("1;94", text)
}

/// Secondary prose — an aside, a fallback explanation, a "no data". Grey (bright black), not faint:
/// faint is the lowest-contrast code a terminal has and several render it invisible, which is what
/// made the first pass read as washed out. Grey recedes without disappearing.
pub fn muted(text: &str) -> String {
    paint("90", text)
}

/// A digest, a reference, an identifier the reader might copy. **Bright cyan** — the data colour,
/// one step brighter than the blue of the labels so the two never blur into each other.
pub fn ident(text: &str) -> String {
    paint("96", text)
}

/// A good outcome, or the "=" that says two hashes agree. Green.
pub fn good(text: &str) -> String {
    paint("32", text)
}

/// A caveat: reached a match, but not the clean one. Yellow.
pub fn warn(text: &str) -> String {
    paint("33", text)
}

/// A divergence, or the "≠" that says two hashes differ. Red.
pub fn bad(text: &str) -> String {
    paint("31", text)
}

/// The verdict line's mark and word together, painted to the outcome: green and bold for a match,
/// yellow for a caveated one, red for a divergence. Bold as well as coloured because it is the one
/// line a reader looks for first.
pub fn verdict(code: &str, mark: &str, word: &str) -> String {
    paint(code, &format!("{mark} {word}"))
}

/// Left-pad `text` to [`LABEL`] on the plain string, then paint it as a label. The padding is part
/// of the label, so the colour covers the trailing spaces — invisible either way — and the value
/// that follows starts at the same column on every row and in every section.
pub fn label_col(text: &str) -> String {
    label(&format!("{text:<width$}", width = LABEL))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Remove every `ESC[…m` sequence, leaving what a reader actually sees.
    fn visible(s: &str) -> String {
        let mut out = String::new();
        let mut chars = s.chars();
        while let Some(ch) = chars.next() {
            if ch == '\x1b' {
                // Swallow through the terminating `m`.
                for c in chars.by_ref() {
                    if c == 'm' {
                        break;
                    }
                }
            } else {
                out.push(ch);
            }
        }
        out
    }

    #[test]
    fn without_colour_the_text_is_returned_untouched() {
        // The property every plain reader depends on: the bytes are the input's bytes, no escapes.
        assert_eq!(paint_with(false, "1;32", "matched"), "matched");
        assert_eq!(paint_with(false, "2", "  format      "), "  format      ");
    }

    #[test]
    fn with_colour_it_is_wrapped_once_and_reset_once() {
        let s = paint_with(true, "36", "sha256…");
        assert_eq!(s, "\x1b[36msha256…\x1b[0m");
        // One reset, never two: the codes are combined, not nested.
        assert_eq!(s.matches("\x1b[0m").count(), 1);
    }

    #[test]
    fn a_label_column_is_padded_on_the_visible_text_whether_or_not_it_is_painted() {
        // Whatever `enabled()` decided in this harness, the width the reader sees is the same: the
        // padding is measured in visible characters, so columns line up either way — and every
        // label pads to the one tool-wide `LABEL` width, so sections line up with each other too.
        assert_eq!(visible(&label_col("raw")).chars().count(), LABEL);
        assert_eq!(
            visible(&label_col("raw")),
            format!("{:<width$}", "raw", width = LABEL)
        );
        // A label already as wide as the column gets no padding and is not truncated.
        assert_eq!(
            visible(&label_col("stabilizers")),
            format!("{:<width$}", "stabilizers", width = LABEL)
        );
        // And the painted form, forced on, strips back to exactly the visible text.
        assert_eq!(
            visible(&paint_with(true, "90", "raw         ")),
            "raw         "
        );
    }

    #[test]
    fn a_long_value_folds_under_its_column_with_a_hanging_indent() {
        let indent = VALUE_COL; // where the value starts, so continuations sit under it
        let text = "the project declares a target framework and the package was published later";
        let folded = wrap_to(40, text, indent);
        let lines: Vec<&str> = folded.lines().collect();
        assert!(
            lines.len() > 1,
            "a value wider than the terminal should fold: {folded:?}"
        );
        // First line has no indent — the label already placed it.
        assert!(!lines[0].starts_with(' '), "{:?}", lines[0]);
        // Every continuation hangs at exactly `indent`, so it aligns under the value column.
        for cont in &lines[1..] {
            assert!(cont.starts_with(&" ".repeat(indent)), "{cont:?}");
            assert!(
                !cont[indent..].starts_with(' '),
                "one indent, not more: {cont:?}"
            );
        }
        // No content line runs past the width (words are short here, none exceeds `avail`).
        for l in &lines {
            assert!(l.chars().count() <= 40, "over width: {l:?}");
        }
        // Nothing is lost or duplicated: the words come back in order.
        assert_eq!(
            folded.split_whitespace().collect::<Vec<_>>(),
            text.split(' ').collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_value_that_fits_is_returned_as_one_line() {
        assert_eq!(wrap_to(80, "short enough", VALUE_COL), "short enough");
    }
}
