//! A mutable, recursive archive model with byte-exact tar, zip and gzip writers.
//!
//! Readers come from the ecosystem. Writers are ours, because byte-exact output is the product and
//! no crate lets us control general-purpose bit flags, creator versions, zeroed CRC fields, or
//! first-class PAX record emission. See `docs/05-archive-and-normalization.md` §2.1.

#![warn(missing_debug_implementations)]

mod error;
mod limits;
mod model;

pub mod gzip;
mod parse;
pub mod tar;
pub mod zip;

pub use error::{ArchiveError, Result};
pub use limits::Limits;
pub use model::{
    Archive, Body, Entry, EntryKind, GzipHeader, Meta, RawMeta, SourceMap, SpillFile, TarRaw,
    Trailer, ZipRaw,
};
pub use parse::{Parsed, parse, serialize};
