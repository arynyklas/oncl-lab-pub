//! The oncl-plugin integration tests in one binary: each file of this directory is a module.

mod common;

#[cfg(feature = "distribution")]
mod builtins;
#[cfg(feature = "distribution")]
mod caps;
#[cfg(feature = "distribution")]
mod caps_crypto;
#[cfg(feature = "distribution")]
mod caps_files;
#[cfg(feature = "distribution")]
mod caps_flows;
#[cfg(feature = "distribution")]
mod caps_keys;
#[cfg(feature = "distribution")]
mod caps_keystore;
#[cfg(feature = "distribution")]
mod caps_net;
#[cfg(feature = "distribution")]
mod caps_state;
#[cfg(feature = "distribution")]
mod caps_tokens;
#[cfg(feature = "distribution")]
mod caps_verify;
#[cfg(feature = "distribution")]
mod example;
mod manifest_version;
mod manual;
#[cfg(feature = "distribution")]
mod modules;
mod operations;
#[cfg(feature = "distribution")]
mod package;
#[cfg(feature = "distribution")]
mod runtime;
#[cfg(feature = "distribution")]
mod store;
