fn main() {
    for a in std::env::args().skip(1) {
        let t = std::fs::read_to_string(&a).unwrap_or_default();
        let s = trigon_core::classify(&t);
        let c = trigon_core::compress(&t, 4096);
        println!(
            "{:<12} {:<42} {:.0}x  ({} -> {} lines)",
            a.split('/').rev().nth(1).unwrap_or("?"),
            s.key(),
            c.ratio(),
            c.original_lines,
            c.kept_lines
        );
    }
}
