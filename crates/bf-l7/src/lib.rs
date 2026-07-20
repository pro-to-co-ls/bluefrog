//! L7 behavioral abuse detection.
//!
//! Inline on every parsed announce (and connection-id mismatch), this keeps bounded per-source
//! state and raises a decaying suspicion score from three signals — **re-announce interval
//! abuse**, **connection-id mismatches**, and **peer_id fingerprinting**. When the score crosses
//! a threshold it returns [`Verdict::Ban`], which the runtime turns into an auto-expiring nft set
//! entry. Pure logic (no I/O, no sockets), so every path is unit-testable. See `SPEC.md` §5.
#![forbid(unsafe_code)]

use bf_core::{InfoHash, PeerId};
use parking_lot::Mutex;

/// Number of lock shards for the per-source state map.
pub const SHARDS: usize = 16;
/// How many recent (info_hash, time) announces are remembered per source for interval detection.
const RING: usize = 8;

/// peer_id prefixes of well-known BitTorrent clients (Azureus-style). A peer_id matching none of
/// these is a weak abuse signal.
pub const KNOWN_CLIENT_PREFIXES: &[&[u8]] = &[
    b"-qB", b"-TR", b"-LT", b"-lt", b"-DE", b"-UT", b"-UM", b"-AZ", b"-BT", b"-BL", b"-TX", b"-FD",
    b"-D5", b"-DE", b"-KT", b"-XL", b"-WW", b"M4-", b"M5-",
];

/// True if `peer_id` starts with a recognised BitTorrent client prefix.
#[must_use]
pub fn is_known_client(peer_id: &PeerId) -> bool {
    KNOWN_CLIENT_PREFIXES.iter().any(|p| peer_id.starts_with(p))
}

/// Tunables for the detector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// Seconds below which re-announcing the *same* torrent counts as an interval violation.
    pub reannounce_min_interval: u32,
    /// Score at or above which a source is banned.
    pub score_ban_threshold: u32,
    /// Ban duration handed to the nft set element (seconds).
    pub ban_duration: u32,
    /// Total cap on tracked sources (spread across [`SHARDS`]).
    pub max_entries: usize,
    /// Score added per interval violation.
    pub weight_interval: u32,
    /// Score added per connection-id mismatch.
    pub weight_connid: u32,
    /// Score added when a peer_id matches no known client.
    pub weight_peerid: u32,
    /// Score decayed per elapsed second since a source was last seen.
    pub decay_per_sec: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            reannounce_min_interval: 60,
            score_ban_threshold: 100,
            ban_duration: 3600,
            max_entries: 1_000_000,
            weight_interval: 20,
            weight_connid: 15,
            weight_peerid: 5,
            decay_per_sec: 1,
        }
    }
}

/// The outcome of feeding an event to the detector.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Keep serving this source.
    Allow,
    /// Deny in-app and ban the source's IP in nft for `duration` seconds.
    Ban {
        /// nft element timeout, seconds.
        duration: u32,
    },
}

#[derive(Clone, Copy)]
struct Client {
    score: u32,
    last_seen: u32,
    ring: [Option<(InfoHash, u32)>; RING],
    ring_pos: usize,
}

impl Client {
    fn new(now: u32) -> Self {
        Self {
            score: 0,
            last_seen: now,
            ring: [None; RING],
            ring_pos: 0,
        }
    }

    fn decay(&mut self, now: u32, per_sec: u32) {
        let elapsed = now.saturating_sub(self.last_seen);
        self.score = self.score.saturating_sub(elapsed.saturating_mul(per_sec));
        self.last_seen = now;
    }

    /// Was this exact torrent announced within `floor` seconds? Records the announce either way.
    fn interval_violation(&mut self, info_hash: &InfoHash, now: u32, floor: u32) -> bool {
        let violated = self
            .ring
            .iter()
            .flatten()
            .any(|(h, t)| h == info_hash && now.saturating_sub(*t) < floor);
        self.ring[self.ring_pos] = Some((*info_hash, now));
        self.ring_pos = (self.ring_pos + 1) % RING;
        violated
    }
}

type Ip = [u8; 16];
type Shard = std::collections::HashMap<Ip, Client>;

/// Bounded, sharded behavioral detector.
pub struct Detector {
    config: Config,
    shards: Box<[Mutex<Shard>]>,
    per_shard_cap: usize,
}

impl Detector {
    /// Create a detector with the given tunables.
    #[must_use]
    pub fn new(config: Config) -> Self {
        let shards = (0..SHARDS).map(|_| Mutex::new(Shard::new())).collect();
        let per_shard_cap = (config.max_entries / SHARDS).max(1);
        Self {
            config,
            shards,
            per_shard_cap,
        }
    }

    fn shard(&self, ip: &Ip) -> &Mutex<Shard> {
        &self.shards[usize::from(ip[15]) % SHARDS]
    }

    fn verdict(&self, score: u32) -> Verdict {
        if score >= self.config.score_ban_threshold {
            Verdict::Ban {
                duration: self.config.ban_duration,
            }
        } else {
            Verdict::Allow
        }
    }

    /// Insert-or-get the client for `ip`, evicting the least-recently-seen entry if the shard is
    /// at capacity. Applies score decay before returning.
    fn touch<'a>(&self, shard: &'a mut Shard, ip: &Ip, now: u32) -> &'a mut Client {
        if !shard.contains_key(ip)
            && shard.len() >= self.per_shard_cap
            && let Some(oldest) = shard
                .iter()
                .min_by_key(|(_, c)| c.last_seen)
                .map(|(k, _)| *k)
        {
            shard.remove(&oldest);
        }
        let client = shard.entry(*ip).or_insert_with(|| Client::new(now));
        client.decay(now, self.config.decay_per_sec);
        client
    }

    /// Feed an announce. Raises the score on interval abuse and unknown peer_ids.
    pub fn on_announce(
        &self,
        ip: &Ip,
        info_hash: &InfoHash,
        peer_id: &PeerId,
        now: u32,
    ) -> Verdict {
        let mut shard = self.shard(ip).lock();
        let client = self.touch(&mut shard, ip, now);
        if client.interval_violation(info_hash, now, self.config.reannounce_min_interval) {
            client.score = client.score.saturating_add(self.config.weight_interval);
        }
        if !is_known_client(peer_id) {
            client.score = client.score.saturating_add(self.config.weight_peerid);
        }
        self.verdict(client.score)
    }

    /// Feed a connection-id mismatch (a UDP announce/scrape whose connid failed validation).
    pub fn on_connid_mismatch(&self, ip: &Ip, now: u32) -> Verdict {
        let mut shard = self.shard(ip).lock();
        let client = self.touch(&mut shard, ip, now);
        client.score = client.score.saturating_add(self.config.weight_connid);
        self.verdict(client.score)
    }

    /// Number of currently-tracked sources (for a metrics gauge).
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.shards.iter().map(|s| s.lock().len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP: Ip = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4];
    const H1: InfoHash = [1u8; 20];
    const H2: InfoHash = [2u8; 20];
    const GOOD_PEER: PeerId = *b"-qB5000-abcdefghijkl";
    const BAD_PEER: PeerId = [0u8; 20];

    fn detector() -> Detector {
        Detector::new(Config::default())
    }

    #[test]
    fn known_client_detection() {
        assert!(is_known_client(&GOOD_PEER));
        assert!(is_known_client(b"M5-1-2--abcdefghijkl"));
        assert!(!is_known_client(&BAD_PEER));
    }

    #[test]
    fn clean_announce_is_allowed() {
        let d = detector();
        // known client, first announce: no interval violation, no peer_id penalty
        assert_eq!(d.on_announce(&IP, &H1, &GOOD_PEER, 1000), Verdict::Allow);
        assert_eq!(d.tracked(), 1);
    }

    #[test]
    fn interval_abuse_raises_score_only_for_same_torrent() {
        let d = Detector::new(Config {
            weight_interval: 40,
            weight_peerid: 0, // isolate the interval signal
            score_ban_threshold: 100,
            ..Config::default()
        });
        // first announce of H1
        assert_eq!(d.on_announce(&IP, &H1, &GOOD_PEER, 1000), Verdict::Allow);
        // a *different* torrent right away is fine (score stays 0)
        assert_eq!(d.on_announce(&IP, &H2, &GOOD_PEER, 1000), Verdict::Allow);
        // re-announcing H1 within the floor is a violation (+40), still under threshold
        assert_eq!(d.on_announce(&IP, &H1, &GOOD_PEER, 1005), Verdict::Allow);
        // two more fast H1 re-announces cross 100 -> ban
        d.on_announce(&IP, &H1, &GOOD_PEER, 1006);
        assert_eq!(
            d.on_announce(&IP, &H1, &GOOD_PEER, 1007),
            Verdict::Ban { duration: 3600 }
        );
    }

    #[test]
    fn slow_reannounce_is_not_a_violation() {
        let d = detector();
        d.on_announce(&IP, &H1, &GOOD_PEER, 1000);
        // re-announce well after the 60 s floor: no interval violation
        assert_eq!(d.on_announce(&IP, &H1, &GOOD_PEER, 2000), Verdict::Allow);
    }

    #[test]
    fn unknown_peer_id_scores() {
        let d = Detector::new(Config {
            weight_peerid: 100, // one unknown peer_id crosses the threshold
            ..Config::default()
        });
        assert_eq!(
            d.on_announce(&IP, &H1, &BAD_PEER, 1000),
            Verdict::Ban { duration: 3600 }
        );
    }

    #[test]
    fn connid_mismatches_accumulate_to_a_ban() {
        let d = Detector::new(Config {
            weight_connid: 60,
            decay_per_sec: 0,
            ..Config::default()
        });
        assert_eq!(d.on_connid_mismatch(&IP, 1000), Verdict::Allow); // 60
        assert_eq!(
            d.on_connid_mismatch(&IP, 1000),
            Verdict::Ban { duration: 3600 } // 120 >= 100
        );
    }

    #[test]
    fn score_decays_over_time() {
        let d = Detector::new(Config {
            weight_connid: 90,
            decay_per_sec: 10,
            score_ban_threshold: 100,
            ..Config::default()
        });
        d.on_connid_mismatch(&IP, 1000); // score 90
        // 5 s later, decay removes 50 -> 40, +90 = 130 >= 100 -> ban
        assert_eq!(
            d.on_connid_mismatch(&IP, 1005),
            Verdict::Ban { duration: 3600 }
        );
        // a fresh source, long gap: decay floors at 0
        let ip2 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 9, 9, 9, 9];
        d.on_connid_mismatch(&ip2, 1000); // 90
        assert_eq!(d.on_connid_mismatch(&ip2, 2000), Verdict::Allow); // decayed to 0, +90 = 90
    }

    #[test]
    fn state_is_bounded_by_eviction() {
        let d = Detector::new(Config {
            max_entries: SHARDS, // 1 entry per shard
            ..Config::default()
        });
        // two IPs landing in the same shard (same last byte): the older is evicted
        let a = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 1, 1, 7];
        let b = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 2, 2, 2, 7];
        d.on_announce(&a, &H1, &GOOD_PEER, 1000);
        d.on_announce(&b, &H1, &GOOD_PEER, 1001);
        assert_eq!(d.tracked(), 1); // only one survives in that shard
    }

    #[test]
    fn verdict_and_config_derives() {
        assert_ne!(Verdict::Allow, Verdict::Ban { duration: 1 });
        assert!(format!("{:?}", Verdict::Allow).contains("Allow"));
        let c = Config::default();
        assert!(format!("{c:?}").contains("Config"));
        let _ = c; // Copy/Clone
    }
}
