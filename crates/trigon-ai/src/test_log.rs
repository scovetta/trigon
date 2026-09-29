//! What a test can read of the warnings this crate logs.
//!
//! Some of them are promises rather than chatter: a salvaged answer is "said out loud", and a
//! retry at a lower depth names the depths it went between, because each step is a paid call and
//! the log is where an operator sees why one proposal cost three. The binary installs a subscriber
//! that prints them; a test installs this one and reads them back.
//!
//! **Process-wide, recording only on the threads that ask.** `tracing::subscriber::with_default`
//! is the obvious tool and is flaky here: while a single dispatcher is registered, tracing-core
//! works out a callsite's interest from the default of whichever thread reaches it first, so a
//! sibling test reaching the same `warn!` on a thread with no subscriber fixes it at "never" for
//! every thread. One subscriber installed as the global default is every thread's default, and a
//! thread that is not capturing costs it one thread-local read.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Once;

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::subscriber::Interest;
use tracing::{Event, Level, Metadata, Subscriber};

/// One event, as a test reads it: its level and its fields, each rendered as it would print.
#[derive(Debug)]
pub(crate) struct Logged {
    pub(crate) level: Level,
    fields: BTreeMap<String, String>,
}

impl Logged {
    pub(crate) fn message(&self) -> &str {
        self.field("message").unwrap_or_default()
    }

    pub(crate) fn field(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(String::as_str)
    }
}

thread_local! {
    static CAPTURED: RefCell<Option<Vec<Logged>>> = const { RefCell::new(None) };
}

/// Run `f`, and hand back what it logged on this thread beside what it returned.
pub(crate) fn capture<T>(f: impl FnOnce() -> T) -> (T, Vec<Logged>) {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        tracing::subscriber::set_global_default(Capture)
            .expect("nothing else in this test binary installs a subscriber");
    });
    CAPTURED.with(|c| *c.borrow_mut() = Some(Vec::new()));
    let out = f();
    let logged = CAPTURED.with(|c| c.borrow_mut().take()).unwrap_or_default();
    (out, logged)
}

struct Capture;

impl Subscriber for Capture {
    fn register_callsite(&self, _: &'static Metadata<'static>) -> Interest {
        // Asked on every call rather than cached, because the answer is per thread.
        Interest::sometimes()
    }

    fn enabled(&self, _: &Metadata<'_>) -> bool {
        CAPTURED.with(|c| c.borrow().is_some())
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut fields = Fields(BTreeMap::new());
        event.record(&mut fields);
        let logged = Logged {
            level: *event.metadata().level(),
            fields: fields.0,
        };
        CAPTURED.with(|c| {
            if let Some(events) = c.borrow_mut().as_mut() {
                events.push(logged);
            }
        });
    }

    fn enter(&self, _: &Id) {}

    fn exit(&self, _: &Id) {}
}

struct Fields(BTreeMap<String, String>);

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_string(), value.to_string());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.0
            .insert(field.name().to_string(), format!("{value:?}"));
    }
}
