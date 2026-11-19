//! The integration tests of `oncl-server` as one test binary: one link of the crate and its
//! dependencies instead of one per file. A test is `<file>::<test>`.
//!
//! A binary of its own: `process_lock` runs its one test in its own process (a POSIX child
//! may briefly inherit the journal descriptors of parallel tests until exec) and starts
//! itself again with `--exact <test>`.

// The real `oncl-server` process and the in-process token rig.
mod server_support;
// `audit`'s actual key and durable guard, and its batch rig.
#[path = "support/batch.rs"]
mod batch_support;
mod support;
// `telemetry`'s OTLP/HTTP receiver and loopback PKI.
mod telemetry_support;

mod access;
mod audit;
mod concurrency;
mod connection_abort_process;
mod default_limits;
mod example_config;
mod executor_ownership;
mod http_operations_process;
mod http_progress_process;
mod install_file;
mod plugin_bytes_config;
mod refusal_close;
mod stream_abort_process;
mod telemetry;
mod upload_stall_process;
