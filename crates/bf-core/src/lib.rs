//! Core shared types for bluefrog: info-hashes, peer ids, announce events, peer flags.
//!
//! These cover the wire peer flag byte layout and the UDP `event` codes.
#![forbid(unsafe_code)]

pub mod connid;
pub mod store;

pub use connid::ConnId;
pub use store::{Counts, Store, Totals};

/// Length of a BitTorrent info-hash or peer-id (SHA-1), in bytes.
pub const HASH_LEN: usize = 20;

/// A 20-byte torrent info-hash.
pub type InfoHash = [u8; HASH_LEN];

/// A 20-byte peer id.
pub type PeerId = [u8; HASH_LEN];

/// Peer-state flags (the wire peer flag byte).
pub mod flag {
    /// Peer has the complete torrent (`left == 0`).
    pub const SEEDING: u8 = 0x80;
    /// Peer reported `event=completed` on this announce.
    pub const COMPLETED: u8 = 0x40;
    /// Peer reported `event=stopped` (is leaving the swarm).
    pub const STOPPED: u8 = 0x20;
    /// Peer was learned via cluster live-sync (unused here; reserved).
    pub const FROM_SYNC: u8 = 0x10;
    /// Peer is downloading (no bits set).
    pub const LEECHING: u8 = 0x00;
}

/// Announce `event`, as the tracker acts on it.
///
/// BEP-15 `started` (code 2) carries no special peer accounting, so it folds into
/// [`Event::None`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// Periodic announce, `started`, or an unknown code.
    None,
    /// `completed` (code 1) — the peer just finished downloading.
    Completed,
    /// `stopped` (code 3) — the peer is leaving.
    Stopped,
}

impl Event {
    /// Decode a BEP-15 UDP `event` field: `1` ⇒ [`Event::Completed`], `3` ⇒ [`Event::Stopped`],
    /// anything else (`0` none, `2` started, unknown) ⇒ [`Event::None`].
    #[must_use]
    pub fn from_udp(code: u32) -> Self {
        match code {
            1 => Event::Completed,
            3 => Event::Stopped,
            _ => Event::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_len_and_type_aliases() {
        assert_eq!(HASH_LEN, 20);
        let h: InfoHash = [0u8; HASH_LEN];
        let p: PeerId = [1u8; HASH_LEN];
        assert_eq!(h.len(), 20);
        assert_eq!(p.len(), 20);
    }

    #[test]
    fn flag_values_are_stable() {
        assert_eq!(flag::SEEDING, 0x80);
        assert_eq!(flag::COMPLETED, 0x40);
        assert_eq!(flag::STOPPED, 0x20);
        assert_eq!(flag::FROM_SYNC, 0x10);
        assert_eq!(flag::LEECHING, 0x00);
    }

    #[test]
    fn event_from_udp_maps_every_code() {
        assert_eq!(Event::from_udp(0), Event::None);
        assert_eq!(Event::from_udp(1), Event::Completed);
        assert_eq!(Event::from_udp(2), Event::None); // started folds into None
        assert_eq!(Event::from_udp(3), Event::Stopped);
        assert_eq!(Event::from_udp(9999), Event::None);
    }

    #[test]
    fn event_derives_are_exercised() {
        let a = Event::Completed;
        let b = a; // Copy
        assert_eq!(a, b); // PartialEq (equal)
        assert_ne!(a, Event::None); // PartialEq (not equal)
        assert_eq!(format!("{a:?}"), "Completed"); // Debug
    }
}
