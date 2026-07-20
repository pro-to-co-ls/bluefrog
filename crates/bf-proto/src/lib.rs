//! bluefrog wire-protocol codecs.
//!
//! Pure, allocation-free parsing and serialization — no I/O, no shared state — so every branch is
//! unit-testable. Currently the BEP-15 UDP tracker protocol; HTTP/bencode land in later milestones.
#![forbid(unsafe_code)]

pub mod bencode;
pub mod udp;
