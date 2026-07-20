//! In-memory, sharded torrent/peer store.
//!
//! Torrents are spread over [`SHARD_COUNT`] shards keyed by the top 10 bits of the info-hash,
//! each behind its own lock so the hot path only ever contends a
//! single shard. Peers are held per family (v4 / v6) in their compact wire form (`ip + port`), so
//! building an announce/scrape response is a copy, not a serialization. State is ephemeral: peers
//! age out and empty torrents are collected — nothing is persisted.

use crate::{InfoHash, flag};
use parking_lot::RwLock;
use std::collections::HashMap;

/// Number of top-level shards.
pub const SHARD_COUNT: usize = 1024;

/// Minutes of inactivity after which a peer is dropped.
pub const PEER_TIMEOUT_MINUTES: u32 = 45;
/// Minutes of inactivity after which an empty torrent is collected (24 h).
pub const TORRENT_TIMEOUT_MINUTES: u32 = 24 * 60;

/// Combined (v4 + v6) swarm counters for a torrent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counts {
    /// Number of seeders (peers with the complete torrent).
    pub complete: u32,
    /// Number of leechers (peers still downloading).
    pub incomplete: u32,
    /// Number of completed downloads recorded.
    pub downloaded: u32,
}

#[derive(Clone, Copy)]
struct PeerVal {
    flags: u8,
    seen: u32,
}

/// A single-family peer list holding compact `N`-byte peers (`N` = 6 for v4, 18 for v6).
struct PeerList<const N: usize> {
    peers: HashMap<[u8; N], PeerVal>,
    seeders: usize,
    downloaded: u64,
}

impl<const N: usize> PeerList<N> {
    fn new() -> Self {
        Self {
            peers: HashMap::new(),
            seeders: 0,
            downloaded: 0,
        }
    }

    fn leechers(&self) -> usize {
        self.peers.len() - self.seeders
    }

    /// Add or refresh a peer. Applies the peer flag rules: `completed` implies `seeding`
    /// (a bare `completed` is cleared), and once a peer is `completed` it stays that way.
    fn announce(&mut self, key: [u8; N], mut flags: u8, now: u32) {
        if flags & flag::COMPLETED != 0 && flags & flag::SEEDING == 0 {
            flags &= !flag::COMPLETED;
        }
        let is_seed = flags & flag::SEEDING != 0;
        match self.peers.get_mut(&key) {
            Some(old) => {
                let was_seed = old.flags & flag::SEEDING != 0;
                if flags & flag::COMPLETED != 0 && old.flags & flag::COMPLETED == 0 {
                    self.downloaded += 1;
                }
                flags |= old.flags & flag::COMPLETED; // once completed, always completed
                if is_seed && !was_seed {
                    self.seeders += 1;
                } else if !is_seed && was_seed {
                    self.seeders -= 1;
                }
                old.flags = flags;
                old.seen = now;
            }
            None => {
                if flags & flag::COMPLETED != 0 {
                    self.downloaded += 1;
                }
                if is_seed {
                    self.seeders += 1;
                }
                self.peers.insert(key, PeerVal { flags, seen: now });
            }
        }
    }

    /// Remove a peer (an `event=stopped` announce).
    fn remove(&mut self, key: &[u8; N]) {
        if let Some(old) = self.peers.remove(key)
            && old.flags & flag::SEEDING != 0
        {
            self.seeders -= 1;
        }
    }

    /// Append up to `numwant` compact peers to `out`, leechers before seeders.
    fn write_compact(&self, numwant: usize, out: &mut Vec<u8>) {
        let mut remaining = numwant;
        for want_seed in [false, true] {
            for (key, val) in &self.peers {
                if remaining == 0 {
                    return;
                }
                if (val.flags & flag::SEEDING != 0) == want_seed {
                    out.extend_from_slice(key);
                    remaining -= 1;
                }
            }
        }
    }

    /// Drop peers unseen for `timeout` minutes; recompute the seeder count.
    fn expire(&mut self, now: u32, timeout: u32) {
        self.peers
            .retain(|_, v| now.saturating_sub(v.seen) < timeout);
        self.seeders = self
            .peers
            .values()
            .filter(|v| v.flags & flag::SEEDING != 0)
            .count();
    }
}

struct Torrent {
    v4: PeerList<6>,
    v6: PeerList<18>,
    base: u32,
}

impl Torrent {
    fn new() -> Self {
        Self {
            v4: PeerList::new(),
            v6: PeerList::new(),
            base: 0,
        }
    }

    fn counts(&self) -> Counts {
        Counts {
            complete: (self.v4.seeders + self.v6.seeders) as u32,
            incomplete: (self.v4.leechers() + self.v6.leechers()) as u32,
            downloaded: (self.v4.downloaded + self.v6.downloaded) as u32,
        }
    }

    fn is_empty(&self) -> bool {
        self.v4.peers.is_empty()
            && self.v6.peers.is_empty()
            && self.v4.downloaded == 0
            && self.v6.downloaded == 0
    }
}

type Shard = HashMap<InfoHash, Torrent>;

/// The sharded torrent store.
pub struct Store {
    shards: Box<[RwLock<Shard>]>,
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

impl Store {
    /// Create an empty store with [`SHARD_COUNT`] shards.
    #[must_use]
    pub fn new() -> Self {
        let shards = (0..SHARD_COUNT)
            .map(|_| RwLock::new(Shard::new()))
            .collect();
        Self { shards }
    }

    fn shard_index(hash: &InfoHash) -> usize {
        let top = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);
        (top >> (32 - 10)) as usize
    }

    /// Total number of torrents currently tracked.
    #[must_use]
    pub fn torrent_count(&self) -> usize {
        self.shards.iter().map(|s| s.read().len()).sum()
    }

    /// Register/refresh an IPv4 peer and return the swarm counts plus, in `peers_out`, up to
    /// `numwant` compact v4 peers.
    pub fn announce_v4(
        &self,
        hash: &InfoHash,
        key: [u8; 6],
        flags: u8,
        numwant: usize,
        now: u32,
        peers_out: &mut Vec<u8>,
    ) -> Counts {
        let mut shard = self.shards[Self::shard_index(hash)].write();
        let t = shard.entry(*hash).or_insert_with(Torrent::new);
        t.base = now;
        t.v4.announce(key, flags, now);
        t.v4.write_compact(numwant, peers_out);
        t.counts()
    }

    /// Register/refresh an IPv6 peer; returns counts and up to `numwant` compact v6 peers.
    pub fn announce_v6(
        &self,
        hash: &InfoHash,
        key: [u8; 18],
        flags: u8,
        numwant: usize,
        now: u32,
        peers_out: &mut Vec<u8>,
    ) -> Counts {
        let mut shard = self.shards[Self::shard_index(hash)].write();
        let t = shard.entry(*hash).or_insert_with(Torrent::new);
        t.base = now;
        t.v6.announce(key, flags, now);
        t.v6.write_compact(numwant, peers_out);
        t.counts()
    }

    /// Remove an IPv4 peer (`event=stopped`); returns the updated counts (zeros if unknown).
    pub fn remove_v4(&self, hash: &InfoHash, key: &[u8; 6], now: u32) -> Counts {
        let mut shard = self.shards[Self::shard_index(hash)].write();
        match shard.get_mut(hash) {
            Some(t) => {
                t.base = now;
                t.v4.remove(key);
                t.counts()
            }
            None => Counts::default(),
        }
    }

    /// Remove an IPv6 peer (`event=stopped`); returns the updated counts (zeros if unknown).
    pub fn remove_v6(&self, hash: &InfoHash, key: &[u8; 18], now: u32) -> Counts {
        let mut shard = self.shards[Self::shard_index(hash)].write();
        match shard.get_mut(hash) {
            Some(t) => {
                t.base = now;
                t.v6.remove(key);
                t.counts()
            }
            None => Counts::default(),
        }
    }

    /// Scrape counts for a torrent (zeros if unknown).
    #[must_use]
    pub fn scrape(&self, hash: &InfoHash) -> Counts {
        let shard = self.shards[Self::shard_index(hash)].read();
        shard.get(hash).map_or(Counts::default(), Torrent::counts)
    }

    /// Expire stale peers and collect empty, long-idle torrents.
    pub fn gc(&self, now: u32) {
        for shard in &self.shards {
            let mut shard = shard.write();
            shard.retain(|_, t| {
                t.v4.expire(now, PEER_TIMEOUT_MINUTES);
                t.v6.expire(now, PEER_TIMEOUT_MINUTES);
                !(t.is_empty() && now.saturating_sub(t.base) >= TORRENT_TIMEOUT_MINUTES)
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HASH_LEN;

    const H: InfoHash = [7u8; HASH_LEN];
    const K1: [u8; 6] = [1, 1, 1, 1, 0x1a, 0xe1];
    const K2: [u8; 6] = [2, 2, 2, 2, 0x1a, 0xe2];

    #[test]
    fn shard_index_uses_top_ten_bits() {
        let mut h = [0u8; HASH_LEN];
        h[0] = 0xff;
        h[1] = 0xc0; // top 10 bits all ones -> 1023
        assert_eq!(Store::shard_index(&h), 1023);
        assert_eq!(Store::shard_index(&[0u8; HASH_LEN]), 0);
    }

    #[test]
    fn leecher_then_seed_transitions() {
        let s = Store::new();
        let mut peers = Vec::new();
        // new leecher
        let c = s.announce_v4(&H, K1, flag::LEECHING, 50, 10, &mut peers);
        assert_eq!(
            c,
            Counts {
                complete: 0,
                incomplete: 1,
                downloaded: 0
            }
        );
        // second leecher; first client now completes (seeding)
        peers.clear();
        let c = s.announce_v4(&H, K2, flag::LEECHING, 50, 10, &mut peers);
        assert_eq!(c.incomplete, 2);
        let c = s.announce_v4(&H, K1, flag::SEEDING | flag::COMPLETED, 50, 11, &mut peers);
        assert_eq!(
            c,
            Counts {
                complete: 1,
                incomplete: 1,
                downloaded: 1
            }
        );
        assert_eq!(s.torrent_count(), 1);
    }

    #[test]
    fn completed_implies_seeding_and_sticks() {
        let s = Store::new();
        let mut peers = Vec::new();
        // bare completed (no seeding bit) is sanitized: not counted as download/seed
        let c = s.announce_v4(&H, K1, flag::COMPLETED, 50, 10, &mut peers);
        assert_eq!(
            c,
            Counts {
                complete: 0,
                incomplete: 1,
                downloaded: 0
            }
        );
        // now truly completes
        let c = s.announce_v4(&H, K1, flag::SEEDING | flag::COMPLETED, 50, 11, &mut peers);
        assert_eq!(
            c,
            Counts {
                complete: 1,
                incomplete: 0,
                downloaded: 1
            }
        );
        // renew as plain leecher: stays completed (no second download), drops to leecher seed-wise
        let c = s.announce_v4(&H, K1, flag::LEECHING, 50, 12, &mut peers);
        assert_eq!(
            c,
            Counts {
                complete: 0,
                incomplete: 1,
                downloaded: 1
            }
        );
    }

    #[test]
    fn write_compact_orders_and_caps() {
        let s = Store::new();
        let mut peers = Vec::new();
        s.announce_v4(&H, K1, flag::LEECHING, 50, 10, &mut peers);
        peers.clear();
        s.announce_v4(&H, K2, flag::SEEDING, 50, 10, &mut peers);
        // both peers, numwant large: 12 bytes
        peers.clear();
        s.announce_v4(&H, K1, flag::LEECHING, 50, 10, &mut peers);
        assert_eq!(peers.len(), 12);
        // numwant caps output
        peers.clear();
        s.announce_v4(&H, K1, flag::LEECHING, 1, 10, &mut peers);
        assert_eq!(peers.len(), 6);
    }

    #[test]
    fn remove_and_scrape() {
        let s = Store::new();
        let mut peers = Vec::new();
        s.announce_v4(&H, K1, flag::SEEDING, 50, 10, &mut peers);
        s.announce_v4(&H, K2, flag::LEECHING, 50, 10, &mut peers);
        assert_eq!(
            s.scrape(&H),
            Counts {
                complete: 1,
                incomplete: 1,
                downloaded: 0
            }
        );
        // remove the seeder
        let c = s.remove_v4(&H, &K1, 11);
        assert_eq!(
            c,
            Counts {
                complete: 0,
                incomplete: 1,
                downloaded: 0
            }
        );
        // removing an unknown peer / torrent is a no-op
        s.remove_v4(&H, &K1, 11);
        let unknown: InfoHash = [9u8; HASH_LEN];
        assert_eq!(s.remove_v4(&unknown, &K1, 11), Counts::default());
        assert_eq!(s.scrape(&unknown), Counts::default());
    }

    #[test]
    fn v6_path() {
        let s = Store::new();
        let k6 = [0u8; 18];
        let mut peers = Vec::new();
        let c = s.announce_v6(&H, k6, flag::SEEDING, 50, 10, &mut peers);
        assert_eq!(
            c,
            Counts {
                complete: 1,
                incomplete: 0,
                downloaded: 0
            }
        );
        assert_eq!(peers.len(), 18);
        let c = s.remove_v6(&H, &k6, 11);
        assert_eq!(c.complete, 0);
        assert_eq!(s.remove_v6(&[3u8; HASH_LEN], &k6, 11), Counts::default());
    }

    #[test]
    fn gc_expires_peers_and_empty_torrents() {
        let s = Store::default();
        let mut peers = Vec::new();
        s.announce_v4(&H, K1, flag::SEEDING, 50, 10, &mut peers);
        s.announce_v6(&H, [0u8; 18], flag::LEECHING, 50, 10, &mut peers);
        // not yet expired
        s.gc(10 + PEER_TIMEOUT_MINUTES - 1);
        assert_eq!(s.scrape(&H).complete, 1);
        // peers expire, but the torrent lingers until torrent-timeout
        s.gc(10 + PEER_TIMEOUT_MINUTES);
        assert_eq!(s.scrape(&H), Counts::default());
        assert_eq!(s.torrent_count(), 1);
        // after torrent timeout, the empty torrent is collected
        s.gc(10 + TORRENT_TIMEOUT_MINUTES);
        assert_eq!(s.torrent_count(), 0);
    }

    #[test]
    fn torrent_with_download_history_survives_empty() {
        let s = Store::new();
        let mut peers = Vec::new();
        s.announce_v4(&H, K1, flag::SEEDING | flag::COMPLETED, 50, 10, &mut peers);
        s.remove_v4(&H, &K1, 10);
        // empty of peers but has a recorded download -> is_empty() false -> not collected
        s.gc(10 + TORRENT_TIMEOUT_MINUTES);
        assert_eq!(s.torrent_count(), 1);
        assert_eq!(s.scrape(&H).downloaded, 1);
    }

    #[test]
    fn counts_derives() {
        let c = Counts::default();
        assert_eq!(
            c,
            Counts {
                complete: 0,
                incomplete: 0,
                downloaded: 0
            }
        );
        assert_ne!(c, Counts { complete: 1, ..c });
        assert!(format!("{c:?}").contains("Counts"));
    }
}
