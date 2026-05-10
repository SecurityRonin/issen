use anyhow::Result;
use opendal::{EntryMode, Operator, options};
use std::io;

/// List all non-directory entries under `prefix` in `op`.
///
/// For each entry, writes a tab-separated line `"<path>\t<size_in_bytes>\n"` to `out`.
/// Returns the total count of files written.
///
/// Creates a temporary single-threaded Tokio runtime so this works from any context.
///
/// # Errors
/// Returns an error if listing fails or writing to `out` fails.
pub fn walk_remote_prefix(
    op: &Operator,
    prefix: &str,
    out: &mut dyn io::Write,
) -> Result<usize> {
    let list_opts = options::ListOptions {
        recursive: true,
        ..Default::default()
    };

    let entries = match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            tokio::task::block_in_place(|| handle.block_on(op.list_options(prefix, list_opts)))?
        }
        Err(_) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(op.list_options(prefix, list_opts))?
        }
    };

    let mut count = 0usize;
    for entry in entries {
        if entry.metadata().mode() == EntryMode::DIR {
            continue;
        }
        // Stat each file individually to get accurate content_length (listing may return 0).
        let size = match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                let stat = tokio::task::block_in_place(|| handle.block_on(op.stat(entry.path())))?;
                stat.content_length()
            }
            Err(_) => {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                let stat = rt.block_on(op.stat(entry.path()))?;
                stat.content_length()
            }
        };
        writeln!(out, "{}\t{size}", entry.path())?;
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operator::operator_for_uri;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn walk_returns_count_and_correct_line() {
        let (op, _) = operator_for_uri("mem://walkbucket/ignored").expect("mem op");
        // Write a test file into the mem backend using the async operator.
        op.write("artifacts/sample.txt", b"hello walk\n".to_vec())
            .await
            .expect("write sample file");

        let mut out = Vec::<u8>::new();
        let count =
            walk_remote_prefix(&op, "artifacts/", &mut out).expect("walk should succeed");
        assert_eq!(count, 1, "expected exactly one file");
        let text = String::from_utf8(out).expect("valid utf-8");
        // Line format: "<path>\t<size>\n"
        assert!(
            text.contains('\t'),
            "output line must contain a tab separator"
        );
        assert!(
            text.trim_end().ends_with("11"),
            "size of b\"hello walk\\n\" (11 bytes) should be last field; got: {text:?}"
        );
    }
}
