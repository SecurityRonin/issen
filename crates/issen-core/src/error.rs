use thiserror::Error;

/// Top-level error type for all Issen operations.
#[derive(Debug, Error)]
pub enum RtError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error at offset {offset}: {message}")]
    Parse { offset: u64, message: String },

    #[error("Invalid data: {0}")]
    InvalidData(String),

    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),

    #[error("Configuration error: {0}")]
    Config(String),
}
