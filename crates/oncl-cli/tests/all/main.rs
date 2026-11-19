//! The oncl-cli integration tests in one binary: each file of this directory is a module.
//! `config_budget` stays separate: it installs its own `#[global_allocator]`.

mod remote_support;
mod support;

mod batch;
#[cfg(windows)]
mod batch_signal;
mod cms_pem;
mod dense_pdf;
mod e2e_signed;
mod evidence;
mod families;
mod gost_chain;
mod jks;
mod jose;
mod kalkan_pades;
mod legacy;
mod local;
mod loopback_pki;
mod named;
mod network_share;
mod output_faults;
mod plugin;
mod remote;
mod remote_signal;
mod remote_signed_limit;
mod signal;
mod strict;
#[cfg(windows)]
mod terminal;
#[cfg(feature = "token-emulator")]
mod token;
mod wsse;
mod xml_interop_defects;
