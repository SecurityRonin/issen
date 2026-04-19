use anyhow::Result;
use opendal::Operator;
use std::io;

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

        // Drive the async write to completion.  We use a fresh single-threaded
        // runtime so this works from any calling context (blocking, async
        // current-thread, or async multi-thread) without `block_in_place`.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(op.write(&path, bytes))?;

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
}
