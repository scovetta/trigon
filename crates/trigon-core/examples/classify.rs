//! Name the failure in a build log.
//!
//!     cargo run -p trigon-core --example classify -- build.log
//!
//! For working on the rule table. A cluster you do not recognize, or a sweep reporting a pile of
//! `unknown`, is a gap in `failure.rs`, and this is the shortest path from a log to the rule that
//! should have matched it. Blocks separated by `=== title ===` are classified individually, so a
//! file of collected failures reads as a table.

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: classify <build.log>");
        std::process::exit(2);
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("reading {path}: {e}");
            std::process::exit(1);
        }
    };

    let blocks: Vec<(&str, &str)> = if text.starts_with("=== ") {
        text.split("=== ")
            .skip(1)
            .filter_map(|b| b.split_once(" ===\n"))
            .collect()
    } else {
        vec![(path.as_str(), text.as_str())]
    };

    for (title, log) in blocks {
        let s = trigon_core::classify(log);
        println!(
            "{:<38} {:<34} fault={:?}{}{}",
            title,
            s.key(),
            s.fault,
            if s.retryable { " retryable" } else { "" },
            if s.repairable { "" } else { " no-repair" },
        );
        if s.is_unknown() {
            // The whole point of running this: an unnamed failure is a missing rule, and the line
            // it could not match is what the rule has to key on.
            println!("    unmatched: {}", s.evidence);
        }
    }
}
