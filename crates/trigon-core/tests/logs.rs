//! Compressing a build log: the edges of "honest about what it dropped".
//!
//! Every elision says how many lines went (`src/logs.rs`). The in-crate tests hold the common
//! shapes; these hold the two ends a log can lose lines from without an error line to anchor them —
//! the very end, and everything — and the escape sequences a build script can hide text behind.

use trigon_core::{compress, strip_controls};

#[test]
fn a_log_that_ends_in_noise_says_how_many_lines_it_left_off_the_end() {
    // Noise never survives, not even as the tail, so this log ends in a gap. The gap is marked
    // with its count rather than the output simply stopping.
    let mut log = String::new();
    for i in 0..100 {
        log.push_str(&format!("step {i}\n"));
    }
    log.push_str("error: the build broke here\n");
    for i in 0..60 {
        log.push_str(&format!(
            "Downloading https://registry.example/pkg-{i}.tgz\n"
        ));
    }
    let c = compress(&log, 1024);

    assert!(c.text.contains("error: the build broke here"), "{}", c.text);
    assert_eq!(
        c.text.lines().last(),
        Some("… 60 lines omitted …"),
        "{}",
        c.text
    );
    assert!(
        !c.text.contains("compressed to fit"),
        "everything chosen fitted, so nothing was cut for space: {}",
        c.text
    );
    assert_eq!(c.original_lines, 161);
    // Every line is either kept or counted by a marker, whatever the head and context are sized at.
    let omitted: usize = c
        .text
        .lines()
        .filter_map(|l| l.strip_prefix("… ")?.strip_suffix(" lines omitted …"))
        .map(|n| n.parse::<usize>().unwrap())
        .sum();
    let shown = c
        .text
        .lines()
        .filter(|l| !l.ends_with(" lines omitted …"))
        .count();
    assert_eq!(c.kept_lines, shown, "{}", c.text);
    assert_eq!(c.kept_lines + omitted, c.original_lines, "{}", c.text);
}

#[test]
fn a_budget_too_small_for_any_line_keeps_none_and_says_so() {
    let mut log = "error: first\n".to_string();
    for i in 0..50 {
        log.push_str(&format!("ordinary output line {i}\n"));
    }
    let c = compress(&log, 8);
    assert_eq!(c.kept_lines, 0);
    assert!(c.text.starts_with("… 51 lines omitted …"), "{}", c.text);
    assert!(c.text.contains("compressed to fit"), "{}", c.text);
}

#[test]
fn an_empty_log_is_not_smaller_by_any_factor() {
    let c = compress("", 1024);
    assert_eq!(c.ratio(), 1.0, "not a division by zero");
}

#[test]
fn a_two_character_escape_is_dropped_with_the_character_it_introduces() {
    // `ESC 7` and `ESC 8` save and restore the cursor; `ESC c` resets the terminal. None of them is
    // text, and the byte after the escape is part of the sequence rather than the log.
    assert_eq!(strip_controls("\u{1b}7saved\u{1b}8 here"), "saved here");
    assert_eq!(strip_controls("\u{1b}cafter a reset"), "after a reset");
    // An escape as the last character has nothing to take with it.
    assert_eq!(strip_controls("trailing\u{1b}"), "trailing");
}

#[test]
fn a_csi_sequence_ends_on_its_final_byte_and_not_on_the_next_letter() {
    // `ESC [ 4 ~` is complete at `~`. Reading only a letter as final would eat `keep` too.
    assert_eq!(strip_controls("\u{1b}[4~keep"), "keep");
    assert_eq!(strip_controls("a\u{1b}[1;31mred\u{1b}[0m b"), "ared b");
}
