/// Default buffer size for streaming reads (64 KiB).
pub const DEFAULT_BUFFER_SIZE: usize = 64 * 1024;

/// Maximum events per batch emit.
pub const MAX_BATCH_SIZE: usize = 10_000;

/// Default DuckDB in-memory threshold before spill to disk.
pub const DUCKDB_MEMORY_LIMIT: &str = "512MB";

/// Rayon thread pool size (0 = auto-detect CPU count).
pub const RAYON_THREADS: usize = 0;

/// Pipeline timeout per artifact in seconds.
pub const ARTIFACT_TIMEOUT_SECS: u64 = 300;
