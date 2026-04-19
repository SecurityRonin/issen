use anyhow::Result;

use crate::operator::operator_for_uri;

/// Fetch remote content at `uri` and return it as a UTF-8 string.
///
/// Creates a temporary single-threaded Tokio runtime so that this function works
/// from any context (blocking or async).
///
/// # Errors
/// Returns an error if the operator cannot be created, the read fails, or the bytes
/// are not valid UTF-8.
pub fn fetch_remote_text(uri: &str) -> Result<String> {
    let (op, path) = operator_for_uri(uri)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let bytes = rt.block_on(op.read(&path))?;
    let text = String::from_utf8(bytes.to_vec())?;
    Ok(text)
}
