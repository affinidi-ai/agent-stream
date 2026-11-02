use std::fmt::Debug;
use std::fs::OpenOptions;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicUsize, Ordering};

const TEST_PORT_MIN: usize = 30_000;
const TEST_PORT_MAX_EXCLUSIVE: usize = 40_000;
const TEST_PORT_RANGE: usize = TEST_PORT_MAX_EXCLUSIVE - TEST_PORT_MIN;

static NEXT_TEST_PORT_OFFSET: LazyLock<AtomicUsize> = LazyLock::new(|| {
    let process_offset = std::process::id() as usize % TEST_PORT_RANGE;
    AtomicUsize::new(process_offset)
});

pub struct ReservedPort {
    port_number: u16,
    reason: String,
    listener: Option<TcpListener>,
    lock_path: PathBuf,
}

impl ReservedPort {
    pub fn release_listener(&mut self) {
        self.listener.take();
    }
}

impl Debug for ReservedPort {
    fn fmt(
        &self,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        write!(formatter, "ReservedPort({}: {})", self.port_number, self.reason)
    }
}

impl Drop for ReservedPort {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.lock_path);
    }
}

pub fn reserve_free_port(reason: &str) -> (u16, ReservedPort) {
    let lock_dir = std::env::temp_dir().join("agent-stream-bdd-ports");
    std::fs::create_dir_all(&lock_dir).expect("create Agent Stream BDD port lock directory");

    for _ in 0..TEST_PORT_RANGE {
        let offset = NEXT_TEST_PORT_OFFSET.fetch_add(1, Ordering::Relaxed) % TEST_PORT_RANGE;
        let port = TEST_PORT_MIN + offset;
        let lock_path = lock_dir.join(format!("{port}.lock"));
        let Ok(_lock_file) = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        else {
            continue;
        };

        match TcpListener::bind(("0.0.0.0", port as u16)) {
            Ok(listener) => {
                return (
                    port as u16,
                    ReservedPort {
                        port_number: port as u16,
                        reason: reason.to_string(),
                        listener: Some(listener),
                        lock_path,
                    },
                );
            }
            Err(_) => {
                let _ = std::fs::remove_file(lock_path);
            }
        }
    }

    panic!("no available BDD port in {TEST_PORT_MIN}..{TEST_PORT_MAX_EXCLUSIVE}");
}
