//! Test helper that captures the log lines code emits, so tests can assert a
//! secret or personal value never reaches the logs.

use std::sync::{Arc, Mutex};

/// Everything `future` logs, at every level and target, with its output.
pub(crate) async fn capture_logs<T>(future: impl std::future::Future<Output = T>) -> (String, T) {
    // Captures run one at a time, as in policy_audit, so two cannot race
    // on the process-wide callsite cache and drop events.
    static CAPTURE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _capture = CAPTURE_LOCK.lock().await;
    // A process-wide TRACE subscriber keeps a test running under no
    // subscriber from caching these callsites as disabled.
    static GLOBAL: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    GLOBAL.get_or_init(|| {
        use tracing_subscriber::layer::SubscriberExt;
        let _ = tracing::subscriber::set_global_default(
            tracing_subscriber::registry().with(tracing_subscriber::filter::LevelFilter::TRACE),
        );
    });
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = buffer.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || LogWriter(writer.clone()))
        .finish();
    let output = {
        let _default = tracing::subscriber::set_default(subscriber);
        future.await
    };
    let logs = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
    (logs, output)
}

struct LogWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogWriter {
    fn write(
        &mut self,
        bytes: &[u8],
    ) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap()
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
