//! What `parse` says about its notes on the way past, for an operator who is not reading reports.
//!
//! `parse` promises two things about the notes it leaves (`src/parse.rs`): each is traced as well
//! as returned, so a corpus sweep sees them without opening every report, and the level follows
//! what the note means. `warn` for a note that means something went unseen, because a run that hit
//! a recursion limit "answered a narrower question than it was asked, and that should not need a
//! `-v` to discover"; `debug` for one that is merely unusual.
//!
//! The events are caught by a subscriber scoped to the test's own thread, so nothing here depends
//! on, or changes, what any other test in the binary has installed.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use tracing::field::{Field, Visit};
use tracing::level_filters::LevelFilter;
use tracing::{Event, Level, Metadata, span};
use trigon_archive::{Limits, parse};
use trigon_core::{Format, Note, NoteCode};

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

/// Parse under a capturing subscriber: the notes, and the events that carried a note's code.
fn traced(bytes: Vec<u8>, limits: &Limits) -> (Vec<Note>, Vec<Seen>) {
    let capture = Capture::default();
    let mut notes = Vec::new();
    tracing::subscriber::with_default(capture.clone(), || {
        parse(bytes, Format::Tar, limits, &mut notes).unwrap();
    });
    let events = std::mem::take(&mut *capture.0.lock().unwrap());
    let coded = events
        .into_iter()
        .filter(|e| e.fields.contains_key("code"))
        .collect();
    (notes, coded)
}

fn tar_of(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = ::tar::Builder::new(Vec::new());
    for (name, body) in members {
        let mut h = ::tar::Header::new_ustar();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, name, *body).unwrap();
    }
    b.into_inner().unwrap()
}

#[test]
fn a_nested_archive_that_would_not_open_is_traced_at_warn_with_its_code_and_member() {
    let (notes, events) = traced(
        tar_of(&[("data.tar.gz", b"not a gzip member")]),
        &Limits::default(),
    );
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert_eq!(notes[0].code, NoteCode::NestedParseFailed);

    assert_eq!(events.len(), 1, "one event per note: {events:?}");
    let e = &events[0];
    assert_eq!(e.level, Level::WARN, "{e:?}");
    assert_eq!(e.fields["code"], "NestedParseFailed");
    assert_eq!(e.fields["path"], "data.tar.gz");
    assert_eq!(
        e.fields["message"], notes[0].detail,
        "the detail is the message"
    );
}

#[test]
fn a_recursion_limit_is_traced_at_warn() {
    // `recursion: 1` descends into nothing, so a member that looks nested is where it stops.
    let limits = Limits {
        recursion: 1,
        ..Limits::default()
    };
    let (notes, events) = traced(tar_of(&[("inner.gz", b"anything")]), &limits);
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert_eq!(notes[0].code, NoteCode::RecursionLimitReached);

    assert_eq!(events.len(), 1, "one event per note: {events:?}");
    assert_eq!(events[0].level, Level::WARN, "{:?}", events[0]);
    assert_eq!(events[0].fields["code"], "RecursionLimitReached");
}

#[test]
fn a_note_that_is_merely_unusual_is_traced_at_debug() {
    let (notes, events) = traced(
        tar_of(&[("lib/a.rb", b"1"), ("lib/a.rb", b"2")]),
        &Limits::default(),
    );
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert_eq!(notes[0].code, NoteCode::DuplicateEntryPath);
    assert!(!NoteCode::DuplicateEntryPath.is_noteworthy());

    assert_eq!(events.len(), 1, "one event per note: {events:?}");
    assert_eq!(events[0].level, Level::DEBUG, "{:?}", events[0]);
    assert_eq!(events[0].fields["code"], "DuplicateEntryPath");
}
