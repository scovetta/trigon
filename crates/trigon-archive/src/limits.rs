/// Bounds on what we will decompress.
///
/// We decompress attacker-controlled bytes, and the prior art has no limits at all. Breaching one
/// produces a note or an `Unsupported` verdict, never a silent truncation.
/// See `docs/05-archive-and-normalization.md` §2.2 (5).
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// How deep nested archives may go before the walker stops descending.
    pub recursion: u8,
    /// Above this, a member body spills to a temp file rather than sitting on the heap.
    pub max_inline_bytes: u64,
    /// Total inline budget for one archive.
    pub max_inline_total: u64,
    /// Hard ceiling on everything one artifact expands to.
    pub total_expanded_bytes: u64,
    /// Hard ceiling on member count.
    pub max_entries: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            recursion: 4,
            max_inline_bytes: 8 * 1024 * 1024,
            max_inline_total: 256 * 1024 * 1024,
            total_expanded_bytes: 4 * 1024 * 1024 * 1024,
            max_entries: 1_000_000,
        }
    }
}

impl Limits {
    /// Small limits for tests and fuzzing, where tripping a limit is the point.
    pub const fn tiny() -> Self {
        Self {
            recursion: 2,
            max_inline_bytes: 1024,
            max_inline_total: 64 * 1024,
            total_expanded_bytes: 1024 * 1024,
            max_entries: 1000,
        }
    }
}
