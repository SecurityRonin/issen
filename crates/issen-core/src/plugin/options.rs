//! Per-parse configuration threaded through [`ForensicParser::parse`].
//!
//! [`ParseOptions`] is the general seam that lets a caller tune how a parser
//! emits — without each parser inventing its own back door. The default is the
//! safe, flood-resistant shape: high-volume tables aggregate per-entity rather
//! than emitting one event per row. A caller that genuinely wants every row opts
//! in explicitly.
//!
//! [`ForensicParser::parse`]: crate::plugin::traits::ForensicParser::parse

/// Tunable, parser-agnostic options for a single parse.
///
/// Most parsers ignore every field — they have one natural output shape — and
/// take `&ParseOptions` only so the trait method is uniform. Parsers with a
/// high-volume / low-signal table (SRUM PushNotifications/EnergyUsage; a future
/// `$LogFile` per-operation stream) consult [`verbose_rows`] to decide between an
/// aggregate summary and full per-row events.
///
/// `#[non_exhaustive]`: new knobs are added as a non-breaking minor bump.
/// Construct via [`ParseOptions::default`] (and update individual fields), never
/// a struct literal outside this crate.
///
/// [`verbose_rows`]: ParseOptions::verbose_rows
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ParseOptions {
    /// Emit full per-row events for high-volume tables instead of an
    /// aggregate-per-entity summary.
    ///
    /// `false` (the default) is the safe, flood-resistant shape: a parser with a
    /// table that can hold hundreds of low-signal rows (e.g. SRUM
    /// PushNotifications) collapses it into one summary event per entity carrying
    /// an `occurrences` count. Setting `true` opts into one event per row — the
    /// full-fidelity view an analyst may want when chasing a specific row, at the
    /// cost of a much larger timeline.
    pub verbose_rows: bool,
}

impl ParseOptions {
    /// Builder: set [`verbose_rows`](Self::verbose_rows).
    ///
    /// `#[non_exhaustive]` blocks struct-literal construction from other crates,
    /// so callers build from [`ParseOptions::default`] and set fields through
    /// builders like this:
    ///
    /// ```
    /// use issen_core::plugin::ParseOptions;
    /// let opts = ParseOptions::default().with_verbose_rows(true);
    /// assert!(opts.verbose_rows);
    /// ```
    #[must_use]
    pub fn with_verbose_rows(mut self, verbose_rows: bool) -> Self {
        self.verbose_rows = verbose_rows;
        self
    }
}
