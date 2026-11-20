//! The root of trust of the TUF client, `keys/root.json`, built in when the build has it.

/// The trust anchor of the TUF client, `keys/root.json`, if the build had one.
const EMBEDDED_ROOT: Option<&[u8]> = include!(concat!(env!("OUT_DIR"), "/tuf_root.rs"));

/// The root file (`keys/root.json`, root version 1 or a later one) the TUF client starts
/// from, built in; `None` if the build had none, and then the TUF client has nothing to
/// trust and the updater is off. A file that is there was checked structurally at build
/// time ([`crate::tuf::model::Root::from_signed`]): a malformed one fails the build.
pub fn embedded_root() -> Option<&'static [u8]> {
    EMBEDDED_ROOT
}
