use anyhow::Result;
use opendal::Operator;
use std::io;
use tokio::runtime::Handle;

/// A `std::io::Write` implementation that buffers bytes and flushes them to a
/// remote backend via OpenDAL when [`finish`](RemoteWriter::finish) is called.
pub struct RemoteWriter {
    op: Operator,
    path: String,
    buf: Vec<u8>,
    finished: bool,
}

impl RemoteWriter {
    /// Create a new writer that will write to `path` within `op`.
    pub fn new(op: Operator, path: impl Into<String>) -> Self {
        Self {
            op,
            path: path.into(),
            buf: Vec::new(),
            finished: false,
        }
    }

    /// Flush the internal buffer to the remote backend.
    ///
    /// # Errors
    /// Returns an error if the write to the backend fails.
    pub fn finish(&mut self) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        let bytes = std::mem::take(&mut self.buf);
        let op = self.op.clone();
        let path = self.path.clone();

        // Drive the async write to completion.
        //
        // If a Tokio runtime is already active on this thread (e.g. when Drop
        // fires inside a `#[tokio::test]`), creating a new runtime would panic
        // with "Cannot start a runtime from within a Tokio runtime".  Instead
        // we hand the future to a fresh OS thread that has no runtime context;
        // that thread can safely drive the future by calling `Handle::block_on`
        // against the existing runtime handle.  This works with both
        // current-thread and multi-thread runtimes.
        //
        // When no runtime is active at all we spin up a temporary single-
        // threaded runtime as before.
        match Handle::try_current() {
            Ok(handle) => {
                std::thread::spawn(move || handle.block_on(op.write(&path, bytes)))
                    .join()
                    .map_err(|_| anyhow::anyhow!("writer thread panicked"))??;
            }
            Err(_) => {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                rt.block_on(op.write(&path, bytes))?;
            }
        }

        self.finished = true;
        Ok(())
    }
}

impl io::Write for RemoteWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for RemoteWriter {
    fn drop(&mut self) {
        if !self.finished {
            // Best-effort flush on drop; ignore errors.
            let _ = self.finish();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operator::operator_for_uri;
    use std::io::Write as _;

    fn mem_op() -> Operator {
        let (op, _) = operator_for_uri("mem://testbucket/ignored").expect("mem op");
        op
    }

    #[tokio::test]
    async fn writer_buffers_and_finish_succeeds() {
        let op = mem_op();
        let mut w = RemoteWriter::new(op, "test/hello.txt");
        w.write_all(b"hello remote").expect("write_all");
        w.finish().expect("finish should succeed on mem backend");
    }

    #[tokio::test]
    async fn drop_without_finish_does_not_panic() {
        let op = mem_op();
        let mut w = RemoteWriter::new(op, "test/nodrop.txt");
        w.write_all(b"data").expect("write");
        // Drop without calling finish — should not panic.
        drop(w);
    }

    /// Regression test: dropping a RemoteWriter from inside a Tokio async
    /// context (e.g. inside `#[tokio::test]`) must not panic with
    /// "Cannot start a runtime from within a Tokio runtime".
    #[tokio::test]
    async fn drop_from_async_context_does_not_panic() {
        let op = mem_op();
        let mut w = RemoteWriter::new(op, "test/async_drop.txt");
        w.write_all(b"async drop test").expect("write");
        // Drop fires finish() from within an active Tokio runtime — must not SIGABORT.
        drop(w);
    }
}
