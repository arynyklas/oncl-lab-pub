//! A request the server does not finish (its deadline runs out, or the client goes away)
//! must leave one line in the server's own log: the client sees a typed refusal it may
//! never read, or nothing. Real `oncl-server` binary, real socket, real stderr.
use crate::server_support as support;

use std::{
    collections::BTreeMap,
    io::{Read, Write},
    sync::{Arc, Mutex},
    thread::JoinHandle,
    time::{Duration, Instant},
};

/// The operation deadline of the server under test, in milliseconds.
const DEADLINE_MS: u64 = 1500;

/// A server whose stderr is collected as it is written, so that a test waits for the line it
/// expects instead of sleeping for a guessed time.
struct Server {
    process: support::Process,
    stderr: Arc<Mutex<Vec<u8>>>,
    reader: JoinHandle<()>,
}

impl Server {
    fn start() -> Self {
        let mut process = support::Process::configured("127.0.0.1:0", |root| {
            format!(
                "scratch_directory = {}\noperation_timeout_ms = {DEADLINE_MS}\nheader_timeout_ms = 1000",
                support::toml_path(&root.join("scratch")),
            )
        });
        let stderr = Arc::new(Mutex::new(Vec::new()));
        let mut pipe = process.child.stderr.take().unwrap();
        let sink = stderr.clone();
        let reader = std::thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            while let Ok(n) = pipe.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                sink.lock().unwrap().extend_from_slice(&chunk[..n]);
            }
        });
        Self {
            process,
            stderr,
            reader,
        }
    }

    fn text(&self) -> String {
        snapshot(&self.stderr)
    }

    /// Waits (at most `LIMIT`) until the server has logged an aborted request.
    fn wait_for_abort(&self) {
        const LIMIT: Duration = Duration::from_secs(10);
        let began = Instant::now();
        while !self.text().contains("request aborted") {
            assert!(
                began.elapsed() < LIMIT,
                "no abort line within {LIMIT:?}: {:?}",
                self.text()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Stops the server and returns everything it wrote to stderr.
    fn stop(mut self) -> String {
        self.process
            .child
            .stdin
            .take()
            .unwrap()
            .write_all(b"\n")
            .unwrap();
        self.process.child.wait().unwrap();
        self.reader.join().unwrap();
        snapshot(&self.stderr)
    }

    fn head(&self, path: &str, content_type: &str, length: usize) -> String {
        format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: {content_type}\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n",
            self.process.address,
            self.process.token.as_str(),
        )
    }

    fn hash_head(&self, length: usize) -> String {
        self.head("/v1/hash", "application/octet-stream", length)
    }

    fn connect(&self) -> std::net::TcpStream {
        let stream = std::net::TcpStream::connect(self.process.address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
    }
}

fn snapshot(stderr: &Mutex<Vec<u8>>) -> String {
    String::from_utf8_lossy(&stderr.lock().unwrap()).into_owned()
}

fn fields(line: &str) -> BTreeMap<&str, &str> {
    line.split(' ')
        .skip(3)
        .map(|pair| pair.split_once('=').expect("key=value"))
        .collect()
}

/// The only line of `stderr`, as its fields.
fn only_line(stderr: &str) -> BTreeMap<&str, &str> {
    let lines: Vec<&str> = stderr.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "exactly one line per aborted request: {stderr:?}"
    );
    assert!(
        lines[0].starts_with("oncl-server: request aborted: "),
        "{stderr:?}"
    );
    fields(lines[0])
}

/// RED before the change: the server wrote nothing.
#[test]
fn a_client_that_goes_away_mid_upload_is_logged() {
    let server = Server::start();
    {
        let mut stream = server.connect();
        stream
            .write_all(server.hash_head(1_000_000).as_bytes())
            .unwrap();
        stream.write_all(&[7u8; 100]).unwrap();
        // Closed here, with the body unfinished.
    }
    server.wait_for_abort();
    let stderr = server.stop();
    let fields = only_line(&stderr);
    assert_eq!(fields["route"], "hash", "{stderr:?}");
    assert_eq!(fields["reason"], "client_disconnected", "{stderr:?}");
    fields["elapsed_ms"].parse::<u64>().unwrap();
    assert_eq!(fields.len(), 3, "no field beyond the documented ones");
}

/// RED before the change: the client got a 504, and the server wrote nothing.
#[test]
fn a_deadline_that_ends_an_upload_is_logged() {
    let server = Server::start();
    let mut stream = server.connect();
    stream
        .write_all(server.hash_head(1_000_000).as_bytes())
        .unwrap();
    stream.write_all(&[7u8; 100]).unwrap();
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    let response = String::from_utf8_lossy(&response);
    assert!(response.starts_with("HTTP/1.1 504 "), "{response}");
    assert!(response.contains("DeadlineExceeded"), "{response}");
    server.wait_for_abort();
    let stderr = server.stop();
    let fields = only_line(&stderr);
    assert_eq!(fields["route"], "hash", "{stderr:?}");
    assert_eq!(fields["reason"], "deadline_exceeded", "{stderr:?}");
    // The deadline starts after the request did, and the line is written once it ran out.
    let elapsed: u64 = fields["elapsed_ms"].parse().unwrap();
    assert!(
        elapsed >= DEADLINE_MS,
        "{elapsed} ms for a {DEADLINE_MS} ms deadline"
    );
}

/// The batch route reports its own name.
#[test]
fn a_batch_upload_that_hits_the_deadline_names_its_route() {
    let server = Server::start();
    let mut stream = server.connect();
    stream
        .write_all(
            server
                .head("/v1/batch", "multipart/form-data; boundary=b", 1_000_000)
                .as_bytes(),
        )
        .unwrap();
    stream
        .write_all(b"--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{\"items\":")
        .unwrap();
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    server.wait_for_abort();
    let stderr = server.stop();
    let fields = only_line(&stderr);
    assert_eq!(fields["route"], "batch", "{stderr:?}");
    assert_eq!(fields["reason"], "deadline_exceeded", "{stderr:?}");
}

/// The line is built from numbers and closed names only: the token, the peer's address, the
/// actor, the operator's paths and the bytes of the request never reach the log.
#[test]
fn the_abort_line_carries_no_user_data() {
    let server = Server::start();
    let token = server.process.token.to_string();
    let address = server.process.address.to_string();
    let mut stream = server.connect();
    stream
        .write_all(server.hash_head(1_000_000).as_bytes())
        .unwrap();
    stream
        .write_all(b"CANARY citizen IIN 900101300123")
        .unwrap();
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    server.wait_for_abort();
    let stderr = server.stop();
    assert!(!stderr.is_empty(), "the abort must be logged at all");
    for canary in [
        token.as_str(),
        address.as_str(),
        "127.0.0.1",
        "CANARY",
        "900101300123",
        "synthetic-actor",
        "scratch",
        "audit",
        "/v1/hash",
    ] {
        assert!(
            !stderr.contains(canary),
            "{canary:?} leaked into {stderr:?}"
        );
    }
    assert!(
        stderr.trim_end().bytes().all(|b| b == b' '
            || b == b':'
            || b == b'-'
            || b == b'='
            || b == b'_'
            || b.is_ascii_alphanumeric()),
        "only closed names and numbers: {stderr:?}"
    );
}

/// A request that completes writes nothing.
#[test]
fn a_completed_request_logs_nothing() {
    let server = Server::start();
    let mut stream = server.connect();
    stream.write_all(server.hash_head(3).as_bytes()).unwrap();
    stream.write_all(b"abc").unwrap();
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    let response = String::from_utf8_lossy(&response);
    assert!(response.starts_with("HTTP/1.1 200 "), "{response}");
    assert_eq!(server.stop(), "");
}
