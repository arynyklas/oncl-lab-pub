//! Ports for tests that start the daemon.
//!
//! The daemon listens on a port of `13579..=13679` (`NCALAYERPORT`; any other value means
//! 13579), so a test cannot bind port 0 and pass the bound port on: it has to pick one of a
//! hundred. Picking by "bind, close, hope" races when tests run at the same time, within a
//! binary (threads) or across binaries (`cargo nextest` runs them as processes). A
//! [`DaemonPort`] is therefore a lease: an exclusive lock on a per-port file in the system
//! temporary directory, held as long as the value lives. The operating system drops a lock
//! with its process, so a crashed test leaves nothing to clean up.

use std::fs::{File, OpenOptions, TryLockError};
use std::net::{Ipv4Addr, TcpListener};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The first port a test may give the daemon: 13579 is left to a real NCALayer that may run.
pub const FIRST_DAEMON_PORT: u16 = 13580;
/// The highest port `NCALAYERPORT` accepts.
pub const LAST_DAEMON_PORT: u16 = 13679;

/// A port of `13580..=13679` that nothing listens on and no other test of any process holds.
#[derive(Debug)]
pub struct DaemonPort {
    port: u16,
    _lock: File,
}

impl DaemonPort {
    /// Leases a free port; it stays reserved against other users of this function until the
    /// value is dropped.
    ///
    /// # Panics
    ///
    /// Panics if the lock directory cannot be used or every port of the range is leased or
    /// taken.
    pub fn lease() -> Self {
        static LEASES: AtomicUsize = AtomicUsize::new(0);
        let count = usize::from(LAST_DAEMON_PORT - FIRST_DAEMON_PORT) + 1;
        // Start somewhere process-specific so that concurrent processes seldom probe the same
        // ports in the same order; the locks, not the start, make the choice safe.
        let pid = usize::try_from(std::process::id()).unwrap_or_default();
        let start =
            pid.wrapping_mul(2_654_435_761) % count + LEASES.fetch_add(1, Ordering::Relaxed);
        let dir = lock_dir();
        std::fs::create_dir_all(&dir)
            .unwrap_or_else(|e| panic!("cannot create {}: {e}", dir.display()));
        for step in 0..count {
            let offset = u16::try_from((start + step) % count).expect("within the port range");
            let port = FIRST_DAEMON_PORT + offset;
            let path = dir.join(format!("{port}.lock"));
            let file = OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(&path)
                .unwrap_or_else(|e| panic!("cannot open {}: {e}", path.display()));
            match file.try_lock() {
                Ok(()) => {}
                Err(TryLockError::WouldBlock) => continue,
                Err(TryLockError::Error(e)) => panic!("cannot lock {}: {e}", path.display()),
            }
            // Leased, but something outside the tests may still listen there.
            if TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok() {
                return Self { port, _lock: file };
            }
        }
        panic!("no free daemon port in {FIRST_DAEMON_PORT}..={LAST_DAEMON_PORT}");
    }

    /// The leased port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Binds the port on `127.0.0.1` for a test of a busy port; the daemon cannot take the
    /// port while the listener lives.
    ///
    /// # Panics
    ///
    /// Panics if something else took the port since the lease.
    pub fn hold(&self) -> TcpListener {
        TcpListener::bind((Ipv4Addr::LOCALHOST, self.port))
            .unwrap_or_else(|e| panic!("cannot hold port {}: {e}", self.port))
    }
}

/// The directory of the lock files: shared by every test process of this machine user that
/// has the same temporary directory.
fn lock_dir() -> PathBuf {
    std::env::temp_dir().join("oncl-test-ports")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn leases_held_at_once_are_distinct_and_in_range() {
        let leases: Vec<DaemonPort> = std::thread::scope(|scope| {
            let threads: Vec<_> = (0..16).map(|_| scope.spawn(DaemonPort::lease)).collect();
            threads.into_iter().map(|t| t.join().unwrap()).collect()
        });
        let ports: HashSet<u16> = leases.iter().map(DaemonPort::port).collect();
        assert_eq!(ports.len(), leases.len(), "{leases:?}");
        assert!(
            ports
                .iter()
                .all(|p| (FIRST_DAEMON_PORT..=LAST_DAEMON_PORT).contains(p))
        );
    }

    #[test]
    fn a_leased_port_is_locked_and_a_dropped_one_is_free_again() {
        let lease = DaemonPort::lease();
        let path = lock_dir().join(format!("{}.lock", lease.port()));
        let other = OpenOptions::new().write(true).open(&path).unwrap();
        assert!(matches!(other.try_lock(), Err(TryLockError::WouldBlock)));
        drop(lease);
        assert!(other.try_lock().is_ok());
    }

    #[test]
    fn a_held_port_refuses_a_second_bind_and_is_not_leased_meanwhile() {
        let lease = DaemonPort::lease();
        let listener = lease.hold();
        assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, lease.port())).is_err());
        assert_ne!(DaemonPort::lease().port(), lease.port());
        drop(listener);
    }
}
