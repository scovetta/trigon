//! The one event a comparison emits, as a fleet reads it.
//!
//! `compare` promises "one event carrying the verdict and the digests it rests on", and that it
//! "names the outcome as a string rather than an ordinal: a downstream filter written against an
//! integer breaks the moment an outcome is inserted" (`src/lib.rs`). The string is the outcome's
//! wire name, the one `Match` reads back from.
//!
//! The events are caught by a subscriber scoped to the test's own thread, so nothing here depends
//! on, or changes, what any other test in the binary has installed.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::sync::{Arc, Mutex};

use tracing::field::{Field, Visit};
use tracing::level_filters::LevelFilter;
use tracing::{Event, Level, Metadata, span};
use trigon_archive::Limits;
use trigon_compare::{Comparison, compare_bytes};
use trigon_core::{Format, Match};
use trigon_stabilize::profile;

/// One event: its level and every field it recorded, as text.
#[derive(Debug)]
struct Seen {
    level: Level,
    fields: BTreeMap<String, String>,
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<Seen>>>);

struct Fields<'a>(&'a mut BTreeMap<String, String>);

impl Visit for Fields<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0
            .insert(field.name().to_string(), format!("{value:?}"));
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_string(), value.to_string());
    }
}

impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    /// Says it wants everything, so the process-wide level ceiling another test's subscriber may
    /// have left behind cannot filter these events out before `enabled` is asked.
    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(LevelFilter::TRACE)
    }
    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }
    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
    fn event(&self, event: &Event<'_>) {
        let mut fields = BTreeMap::new();
        event.record(&mut Fields(&mut fields));
        self.0.lock().unwrap().push(Seen {
            level: *event.metadata().level(),
            fields,
        });
    }
    fn enter(&self, _: &span::Id) {}
    fn exit(&self, _: &span::Id) {}
}

/// A stored zip holding one member.
fn zip_of(body: &[u8]) -> Vec<u8> {
    use zip::write::SimpleFileOptions;
    let opts = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .unix_permissions(0o644);
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    w.start_file("lib/x.py", opts).unwrap();
    w.write_all(body).unwrap();
    w.finish().unwrap().into_inner()
}

/// Compare under a capturing subscriber: the comparison, and every `compared` event it emitted.
fn traced(upstream: &[u8], rebuild: &[u8]) -> (Comparison, Vec<Seen>) {
    let capture = Capture::default();
    let c = tracing::subscriber::with_default(capture.clone(), || {
        compare_bytes(
            zip_of(upstream),
            zip_of(rebuild),
            Format::Zip,
            &profile("zip").unwrap(),
            &Limits::default(),
        )
        .unwrap()
    });
    let events = std::mem::take(&mut *capture.0.lock().unwrap());
    let compared = events
        .into_iter()
        .filter(|e| e.fields.get("message").map(String::as_str) == Some("compared"))
        .collect();
    (c, compared)
}

#[test]
fn a_comparison_emits_one_event_naming_its_outcome_by_its_wire_name() {
    for (rebuild, outcome) in [
        (&b"print(1)\n"[..], Match::Exact),
        (b"print(22)\n", Match::Divergent),
    ] {
        let (c, events) = traced(b"print(1)\n", rebuild);
        assert_eq!(c.outcome, outcome);

        assert_eq!(events.len(), 1, "one event per comparison: {events:?}");
        let e = &events[0];
        assert_eq!(e.level, Level::INFO, "{e:?}");
        assert_eq!(e.fields["outcome"], outcome.to_string(), "{e:?}");
        assert_eq!(
            e.fields["outcome"].parse::<Match>(),
            Ok(outcome),
            "a name the verdict reads back from"
        );
        assert_eq!(
            e.fields["upstream_stabilized"],
            c.upstream.stabilized.sha256.to_string()
        );
        assert_eq!(
            e.fields["rebuild_stabilized"],
            c.rebuild.stabilized.sha256.to_string()
        );
    }
}
