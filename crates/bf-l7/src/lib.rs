//! L7 behavioral abuse detection.
//!
//! Inline on every parsed request, this keeps bounded per-source state and raises a decaying
//! suspicion score from protocol-grounded signals:
//!
//! * **stateless violations** — a single packet that contradicts the spec (trivial `key`, an
//!   `IP` field set from a public source, an unconnectable port, a seeder that never transferred,
//!   an absurd `num_want`);
//! * **identity churn** — BEP-15's `key` and BEP-20's `peer_id` identify one client and are meant
//!   to be stable, so churning them for one torrent means fabricated peers;
//! * **enumeration** — a genuine peer touches a bounded set of torrents and scrapes its own, so
//!   breadth across many info-hashes is harvesting;
//! * **connection-id mismatches** and **re-announce interval abuse**.
//!
//! When the score crosses a threshold it returns [`Verdict::Ban`] carrying an **escalation tier**
//! that rises with repeat offences, which the runtime maps onto progressively longer-lived nft
//! sets. Pure logic (no I/O, no sockets), so every path is unit-testable.
//!
//! All times (`now`, [`Config::reannounce_min_interval`], `decay_per_sec`) are in **seconds**.
#![forbid(unsafe_code)]

use bf_core::{InfoHash, PeerId};
use parking_lot::Mutex;

/// Number of lock shards for the per-source state map.
pub const SHARDS: usize = 16;
/// How many recent announces are remembered per source for interval/churn detection.
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

/// The announce fields the detector inspects, decoupled from the wire codec.
#[derive(Debug, Clone, Copy)]
pub struct AnnounceInfo<'a> {
    /// Torrent being announced.
    pub info_hash: &'a InfoHash,
    /// Client-supplied peer id.
    pub peer_id: &'a PeerId,
    /// BEP-15 `key`: meant to be random, unique per client, and stable across announces.
    pub key: u32,
    /// BEP-15 `IP address` field; `0` means "use my source address".
    pub declared_ip: u32,
    /// Announced listening port.
    pub port: u16,
    /// Bytes left (`0` marks a seeder).
    pub left: u64,
    /// Bytes downloaded so far.
    pub downloaded: u64,
    /// Bytes uploaded so far.
    pub uploaded: u64,
    /// Requested peer count (`-1` means "tracker default").
    pub num_want: i32,
    /// Whether the *source* address is publicly routable. The `IP` field is only a legitimate NAT
    /// hint from private space, so this decides whether setting it is suspicious.
    pub source_is_public: bool,
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
    /// Score added for a trivial BEP-15 `key` (`0` or all-ones).
    pub weight_bad_key: u32,
    /// Score added when the `IP` field is set from a publicly routable source.
    pub weight_declared_ip: u32,
    /// Score added for an unconnectable or privileged port.
    pub weight_bad_port: u32,
    /// Score added when a client claims a complete copy having transferred nothing.
    pub weight_fake_seeder: u32,
    /// Score added when `key` churns for one torrent from one source.
    pub weight_key_churn: u32,
    /// Score added when `peer_id` churns for one torrent from one source.
    pub weight_peerid_churn: u32,
    /// Score added for an excessive `num_want`.
    pub weight_numwant: u32,
    /// `num_want` above which the request is treated as peer harvesting.
    pub numwant_abuse: i32,
    /// Score added once a source has touched [`Config::breadth_threshold`] distinct torrents.
    pub weight_breadth: u32,
    /// Approximate distinct-torrent count that marks a source as enumerating the tracker.
    pub breadth_threshold: u32,
    /// Score added for a bulk scrape.
    pub weight_scrape_volume: u32,
    /// Info-hash count at or above which a scrape counts as bulk enumeration.
    pub scrape_volume_threshold: usize,
    /// Cap on remembered offenders (the escalation registry).
    pub max_offenders: usize,
    /// Number of escalation tiers; tier `0` is the first offence.
    pub ban_tiers: u32,
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
            weight_bad_key: 40,
            weight_declared_ip: 60,
            weight_bad_port: 30,
            weight_fake_seeder: 50,
            weight_key_churn: 35,
            weight_peerid_churn: 35,
            weight_numwant: 10,
            numwant_abuse: 100,
            weight_breadth: 60,
            breadth_threshold: 32,
            weight_scrape_volume: 15,
            scrape_volume_threshold: 32,
            max_offenders: 100_000,
            ban_tiers: 3,
        }
    }
}

/// The outcome of feeding an event to the detector.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Keep serving this source.
    Allow,
    /// Deny in-app and ban the source's IP in nft.
    Ban {
        /// nft element timeout hint, seconds (the target set's own timeout governs expiry).
        duration: u32,
        /// Escalation tier: `0` on the first offence, rising with repeats. The runtime maps this
        /// onto progressively longer-lived nft sets.
        tier: u32,
    },
}

/// One remembered announce, used for interval and identity-churn detection.
#[derive(Clone, Copy)]
struct Seen {
    hash: InfoHash,
    at: u32,
    key: u32,
    peer: u32,
}

#[derive(Clone, Copy)]
struct Client {
    score: u32,
    last_seen: u32,
    banned: bool,
    /// Bitmap fingerprint of the distinct torrents this source has touched.
    breadth: u64,
    ring: [Option<Seen>; RING],
    ring_pos: usize,
}

/// Fingerprint the random tail of a peer_id (BEP-20 fixes only the prefix).
fn peer_fingerprint(peer_id: &PeerId) -> u32 {
    peer_id[8..20].iter().fold(0u32, |acc, b| {
        acc.wrapping_mul(31).wrapping_add(u32::from(*b))
    })
}

/// Map an info-hash onto one of 64 breadth buckets.
fn breadth_bit(hash: &InfoHash) -> u32 {
    let x = u64::from_le_bytes([
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
    ]);
    (x.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 58) as u32
}

impl Client {
    fn new(now: u32) -> Self {
        Self {
            score: 0,
            last_seen: now,
            banned: false,
            breadth: 0,
            ring: [None; RING],
            ring_pos: 0,
        }
    }

    fn decay(&mut self, now: u32, per_sec: u32) {
        let elapsed = now.saturating_sub(self.last_seen);
        self.score = self.score.saturating_sub(elapsed.saturating_mul(per_sec));
        self.last_seen = now;
    }

    /// Record the announce and report `(interval_violation, key_churn, peer_id_churn)` against the
    /// remembered announces for the *same* torrent.
    fn observe(&mut self, a: &AnnounceInfo, now: u32, floor: u32, peer: u32) -> (bool, bool, bool) {
        let (mut interval, mut key_churn, mut peer_churn) = (false, false, false);
        for seen in self.ring.iter().flatten() {
            if seen.hash != *a.info_hash {
                continue;
            }
            if now.saturating_sub(seen.at) < floor {
                interval = true;
            }
            if seen.key != a.key {
                key_churn = true;
            }
            if seen.peer != peer {
                peer_churn = true;
            }
        }
        self.ring[self.ring_pos] = Some(Seen {
            hash: *a.info_hash,
            at: now,
            key: a.key,
            peer,
        });
        self.ring_pos = (self.ring_pos + 1) % RING;
        (interval, key_churn, peer_churn)
    }

    /// Fold a torrent into the breadth fingerprint; returns the approximate distinct count.
    fn widen(&mut self, hash: &InfoHash) -> u32 {
        self.breadth |= 1u64 << breadth_bit(hash);
        self.breadth.count_ones()
    }
}

type Ip = [u8; 16];
type Shard = std::collections::HashMap<Ip, Client>;

/// A source's ban history, used to escalate repeat offenders.
#[derive(Clone, Copy, Default)]
struct Offender {
    offenses: u32,
    last: u32,
}

/// Bounded, sharded behavioral detector.
pub struct Detector {
    config: Config,
    shards: Box<[Mutex<Shard>]>,
    per_shard_cap: usize,
    offenders: Mutex<std::collections::HashMap<Ip, Offender>>,
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
            offenders: Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn shard(&self, ip: &Ip) -> &Mutex<Shard> {
        &self.shards[usize::from(ip[15]) % SHARDS]
    }

    /// Single-packet checks that need no per-source state: each is a direct contradiction of what
    /// the tracker protocol says a well-behaved client does.
    fn stateless_score(&self, a: &AnnounceInfo) -> u32 {
        let c = &self.config;
        let mut score = 0;
        // A real client randomises `key`; crude flood tools leave it at a trivial constant.
        if a.key == 0 || a.key == u32::MAX {
            score += c.weight_bad_key;
        }
        // The `IP` field is only a legitimate NAT hint from private space.
        if a.declared_ip != 0 && a.source_is_public {
            score += c.weight_declared_ip;
        }
        // A peer nobody can connect to is not participating in the swarm.
        if a.port < 1024 {
            score += c.weight_bad_port;
        }
        // Claims a complete copy while never having transferred a byte.
        if a.left == 0 && a.downloaded == 0 && a.uploaded == 0 {
            score += c.weight_fake_seeder;
        }
        // "Even 30 peers is plenty" - demanding far more is harvesting, not downloading.
        if a.num_want > c.numwant_abuse {
            score += c.weight_numwant;
        }
        score
    }

    /// Whether this observation crosses into a ban. Fires **once** per offence: while the source
    /// stays over the threshold further packets are suppressed, otherwise a sustained flood would
    /// re-ban (and re-write nft for) the same IP on every packet.
    fn crosses(&self, client: &mut Client) -> bool {
        if client.score >= self.config.score_ban_threshold {
            if client.banned {
                false
            } else {
                client.banned = true;
                true
            }
        } else {
            client.banned = false;
            false
        }
    }

    /// Turn a ban decision into a verdict, escalating on repeat offences.
    fn decide(&self, ip: &Ip, ban: bool, now: u32) -> Verdict {
        if !ban {
            return Verdict::Allow;
        }
        Verdict::Ban {
            duration: self.config.ban_duration,
            tier: self.record_offence(ip, now),
        }
    }

    /// Bump the source's ban history and return its escalation tier. Kept in a small registry
    /// separate from the hot per-source map: an eviction there would erase exactly the history
    /// escalation depends on, and offenders are far fewer than tracked sources.
    fn record_offence(&self, ip: &Ip, now: u32) -> u32 {
        let mut reg = self.offenders.lock();
        if !reg.contains_key(ip)
            && reg.len() >= self.config.max_offenders
            && let Some(oldest) = reg.iter().min_by_key(|(_, o)| o.last).map(|(k, _)| *k)
        {
            reg.remove(&oldest);
        }
        let entry = reg.entry(*ip).or_default();
        entry.offenses = entry.offenses.saturating_add(1);
        entry.last = now;
        (entry.offenses - 1).min(self.config.ban_tiers.saturating_sub(1))
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

    /// Feed an announce. `now` is in **seconds**.
    pub fn on_announce(&self, ip: &Ip, a: &AnnounceInfo, now: u32) -> Verdict {
        let peer = peer_fingerprint(a.peer_id);
        let stateless = self.stateless_score(a);
        let ban = {
            let mut shard = self.shard(ip).lock();
            let client = self.touch(&mut shard, ip, now);
            let (interval, key_churn, peer_churn) =
                client.observe(a, now, self.config.reannounce_min_interval, peer);
            let mut add = stateless;
            if interval {
                add += self.config.weight_interval;
            }
            if key_churn {
                add += self.config.weight_key_churn;
            }
            if peer_churn {
                add += self.config.weight_peerid_churn;
            }
            if !is_known_client(a.peer_id) {
                add += self.config.weight_peerid;
            }
            // A genuine peer participates in a bounded set of torrents.
            if client.widen(a.info_hash) >= self.config.breadth_threshold {
                add += self.config.weight_breadth;
            }
            client.score = client.score.saturating_add(add);
            self.crosses(client)
        };
        self.decide(ip, ban, now)
    }

    /// Feed a connection-id mismatch (a UDP announce/scrape whose connid failed validation).
    /// `now` is in **seconds**.
    pub fn on_connid_mismatch(&self, ip: &Ip, now: u32) -> Verdict {
        let ban = {
            let mut shard = self.shard(ip).lock();
            let client = self.touch(&mut shard, ip, now);
            client.score = client.score.saturating_add(self.config.weight_connid);
            self.crosses(client)
        };
        self.decide(ip, ban, now)
    }

    /// Feed a scrape carrying `hashes` info-hashes. BEP-15 caps a scrape at ~74 hashes; repeatedly
    /// asking for the maximum is bulk enumeration of swarm stats, not a client checking its own.
    /// `now` is in **seconds**.
    pub fn on_scrape(&self, ip: &Ip, hashes: usize, now: u32) -> Verdict {
        let ban = {
            let mut shard = self.shard(ip).lock();
            let client = self.touch(&mut shard, ip, now);
            if hashes >= self.config.scrape_volume_threshold {
                client.score = client
                    .score
                    .saturating_add(self.config.weight_scrape_volume);
            }
            self.crosses(client)
        };
        self.decide(ip, ban, now)
    }

    /// Number of currently-tracked sources (for a metrics gauge).
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.shards.iter().map(|s| s.lock().len()).sum()
    }

    /// Number of remembered offenders (for a metrics gauge).
    #[must_use]
    pub fn offenders(&self) -> usize {
        self.offenders.lock().len()
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

    /// A clean announce: nothing in it should score.
    fn clean<'a>(hash: &'a InfoHash, peer: &'a PeerId) -> AnnounceInfo<'a> {
        AnnounceInfo {
            info_hash: hash,
            peer_id: peer,
            key: 0x1234_5678,
            declared_ip: 0,
            port: 6881,
            left: 100,
            downloaded: 10,
            uploaded: 5,
            num_want: 50,
            source_is_public: true,
        }
    }

    fn detector() -> Detector {
        Detector::new(Config::default())
    }

    /// Every signal silenced, so a test can enable exactly one weight and isolate it.
    fn quiet() -> Config {
        Config {
            weight_interval: 0,
            weight_connid: 0,
            weight_peerid: 0,
            weight_bad_key: 0,
            weight_declared_ip: 0,
            weight_bad_port: 0,
            weight_fake_seeder: 0,
            weight_key_churn: 0,
            weight_peerid_churn: 0,
            weight_numwant: 0,
            weight_breadth: 0,
            weight_scrape_volume: 0,
            decay_per_sec: 0,
            ..Config::default()
        }
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
        assert_eq!(
            d.on_announce(&IP, &clean(&H1, &GOOD_PEER), 1000),
            Verdict::Allow
        );
        assert_eq!(d.tracked(), 1);
        assert_eq!(d.offenders(), 0);
    }

    // --- tier 1: stateless protocol violations -------------------------------------------------

    #[test]
    fn trivial_key_scores() {
        let d = Detector::new(Config {
            weight_bad_key: 100,
            ..quiet()
        });
        let mut a = clean(&H1, &GOOD_PEER);
        a.key = 0;
        assert!(matches!(d.on_announce(&IP, &a, 1000), Verdict::Ban { .. }));
        // all-ones is the same tell
        let d2 = Detector::new(Config {
            weight_bad_key: 100,
            ..quiet()
        });
        let mut b = clean(&H1, &GOOD_PEER);
        b.key = u32::MAX;
        assert!(matches!(d2.on_announce(&IP, &b, 1000), Verdict::Ban { .. }));
    }

    #[test]
    fn declared_ip_scores_only_from_public_sources() {
        let cfg = Config {
            weight_declared_ip: 100,
            ..quiet()
        };
        // a public source asking to be listed under another address
        let d = Detector::new(cfg);
        let mut a = clean(&H1, &GOOD_PEER);
        a.declared_ip = 0x0a00_0001;
        assert!(matches!(d.on_announce(&IP, &a, 1000), Verdict::Ban { .. }));
        // the same request from private space is a legitimate NAT hint
        let d2 = Detector::new(cfg);
        let mut b = clean(&H1, &GOOD_PEER);
        b.declared_ip = 0x0a00_0001;
        b.source_is_public = false;
        assert_eq!(d2.on_announce(&IP, &b, 1000), Verdict::Allow);
    }

    #[test]
    fn unconnectable_port_scores() {
        let d = Detector::new(Config {
            weight_bad_port: 100,
            ..quiet()
        });
        let mut a = clean(&H1, &GOOD_PEER);
        a.port = 0;
        assert!(matches!(d.on_announce(&IP, &a, 1000), Verdict::Ban { .. }));
    }

    #[test]
    fn fake_seeder_scores() {
        let d = Detector::new(Config {
            weight_fake_seeder: 100,
            ..quiet()
        });
        let mut a = clean(&H1, &GOOD_PEER);
        a.left = 0;
        a.downloaded = 0;
        a.uploaded = 0;
        assert!(matches!(d.on_announce(&IP, &a, 1000), Verdict::Ban { .. }));
    }

    #[test]
    fn excessive_numwant_scores() {
        let d = Detector::new(Config {
            weight_numwant: 100,
            ..quiet()
        });
        let mut a = clean(&H1, &GOOD_PEER);
        a.num_want = 5000;
        assert!(matches!(d.on_announce(&IP, &a, 1000), Verdict::Ban { .. }));
    }

    #[test]
    fn unknown_peer_id_scores() {
        let d = Detector::new(Config {
            weight_peerid: 100,
            ..quiet()
        });
        assert!(matches!(
            d.on_announce(&IP, &clean(&H1, &BAD_PEER), 1000),
            Verdict::Ban { .. }
        ));
    }

    // --- tier 2: identity churn and interval abuse ---------------------------------------------

    #[test]
    fn key_churn_for_one_torrent_scores() {
        let d = Detector::new(Config {
            weight_key_churn: 60,
            ..quiet()
        });
        let a = clean(&H1, &GOOD_PEER);
        assert_eq!(d.on_announce(&IP, &a, 1000), Verdict::Allow);
        // same source, same torrent, different `key` -> fabricated identity
        let mut b = clean(&H1, &GOOD_PEER);
        b.key = 0xdead_beef;
        assert_eq!(d.on_announce(&IP, &b, 1000), Verdict::Allow); // 60
        let mut c = clean(&H1, &GOOD_PEER);
        c.key = 0x0bad_0bad;
        assert!(matches!(d.on_announce(&IP, &c, 1000), Verdict::Ban { .. })); // 120
    }

    #[test]
    fn peer_id_churn_for_one_torrent_scores() {
        let d = Detector::new(Config {
            weight_peerid_churn: 100,
            ..quiet()
        });
        assert_eq!(
            d.on_announce(&IP, &clean(&H1, &GOOD_PEER), 1000),
            Verdict::Allow
        );
        let other: PeerId = *b"-qB5000-zzzzzzzzzzzz";
        assert!(matches!(
            d.on_announce(&IP, &clean(&H1, &other), 1000),
            Verdict::Ban { .. }
        ));
    }

    #[test]
    fn interval_abuse_is_per_torrent() {
        let d = Detector::new(Config {
            weight_interval: 60,
            ..quiet()
        });
        assert_eq!(
            d.on_announce(&IP, &clean(&H1, &GOOD_PEER), 1000),
            Verdict::Allow
        );
        // a different torrent right away is fine
        assert_eq!(
            d.on_announce(&IP, &clean(&H2, &GOOD_PEER), 1000),
            Verdict::Allow
        );
        assert_eq!(
            d.on_announce(&IP, &clean(&H1, &GOOD_PEER), 1005),
            Verdict::Allow
        ); // 60
        assert!(matches!(
            d.on_announce(&IP, &clean(&H1, &GOOD_PEER), 1006),
            Verdict::Ban { .. }
        ));
    }

    #[test]
    fn slow_reannounce_is_not_a_violation() {
        let d = detector();
        d.on_announce(&IP, &clean(&H1, &GOOD_PEER), 1000);
        assert_eq!(
            d.on_announce(&IP, &clean(&H1, &GOOD_PEER), 2000),
            Verdict::Allow
        );
    }

    // --- tier 3: enumeration -------------------------------------------------------------------

    #[test]
    fn breadth_across_many_torrents_scores() {
        let d = Detector::new(Config {
            weight_breadth: 100,
            breadth_threshold: 4,
            ..quiet()
        });
        // announce distinct torrents until the fingerprint reports enough buckets
        let mut banned = false;
        for i in 0..64u8 {
            let hash: InfoHash = [i; 20];
            if matches!(
                d.on_announce(&IP, &clean(&hash, &GOOD_PEER), 1000),
                Verdict::Ban { .. }
            ) {
                banned = true;
                break;
            }
        }
        assert!(banned, "a source enumerating many torrents must be flagged");
    }

    #[test]
    fn bulk_scrape_scores_but_small_scrape_does_not() {
        let d = Detector::new(Config {
            weight_scrape_volume: 100,
            scrape_volume_threshold: 32,
            ..quiet()
        });
        assert_eq!(d.on_scrape(&IP, 4, 1000), Verdict::Allow);
        assert!(matches!(d.on_scrape(&IP, 74, 1000), Verdict::Ban { .. }));
    }

    // --- connid, ban-once, decay ---------------------------------------------------------------

    #[test]
    fn connid_mismatches_accumulate_to_a_ban() {
        let d = Detector::new(Config {
            weight_connid: 60,
            decay_per_sec: 0,
            ..Config::default()
        });
        assert_eq!(d.on_connid_mismatch(&IP, 1000), Verdict::Allow);
        assert!(matches!(
            d.on_connid_mismatch(&IP, 1000),
            Verdict::Ban { tier: 0, .. }
        ));
    }

    #[test]
    fn ban_fires_once_then_suppressed_while_over_threshold() {
        let d = Detector::new(Config {
            weight_connid: 50,
            decay_per_sec: 0,
            ..Config::default()
        });
        assert_eq!(d.on_connid_mismatch(&IP, 1000), Verdict::Allow);
        assert!(matches!(
            d.on_connid_mismatch(&IP, 1000),
            Verdict::Ban { .. }
        ));
        for _ in 0..1000 {
            assert_eq!(d.on_connid_mismatch(&IP, 1000), Verdict::Allow);
        }
        // exactly one offence was recorded despite the flood
        assert_eq!(d.offenders(), 1);
    }

    #[test]
    fn score_decays_over_time() {
        let d = Detector::new(Config {
            weight_connid: 90,
            decay_per_sec: 10,
            ..Config::default()
        });
        d.on_connid_mismatch(&IP, 1000); // 90
        assert!(matches!(
            d.on_connid_mismatch(&IP, 1005),
            Verdict::Ban { .. }
        ));
        let ip2 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 9, 9, 9, 9];
        d.on_connid_mismatch(&ip2, 1000);
        assert_eq!(d.on_connid_mismatch(&ip2, 2000), Verdict::Allow);
    }

    #[test]
    fn rebans_after_score_decays_below_threshold() {
        let d = Detector::new(Config {
            weight_connid: 60,
            decay_per_sec: 10,
            ..Config::default()
        });
        assert_eq!(d.on_connid_mismatch(&IP, 1000), Verdict::Allow);
        assert!(matches!(
            d.on_connid_mismatch(&IP, 1000),
            Verdict::Ban { tier: 0, .. }
        ));
        assert_eq!(d.on_connid_mismatch(&IP, 1100), Verdict::Allow);
        // second offence escalates a tier
        assert!(matches!(
            d.on_connid_mismatch(&IP, 1100),
            Verdict::Ban { tier: 1, .. }
        ));
    }

    // --- escalation ----------------------------------------------------------------------------

    #[test]
    fn repeat_offences_escalate_then_cap() {
        // The weight sits below the threshold so each round has a sub-threshold hit that re-arms
        // the detector, followed by one that crosses — mirroring how a real source re-offends.
        let d = Detector::new(Config {
            weight_connid: 60,
            decay_per_sec: 10,
            ban_tiers: 3,
            ..quiet()
        });
        let mut tiers = Vec::new();
        for round in 0..5u32 {
            let now = 1000 + round * 100; // a long gap decays the previous score away
            d.on_connid_mismatch(&IP, now); // 60 -> under threshold, re-arms
            if let Verdict::Ban { tier, .. } = d.on_connid_mismatch(&IP, now) {
                tiers.push(tier);
            }
        }
        // first offence is tier 0, escalating one tier per ban, capped at ban_tiers - 1
        assert_eq!(tiers, vec![0, 1, 2, 2, 2]);
        assert_eq!(d.offenders(), 1);
    }

    #[test]
    fn offender_registry_is_bounded() {
        let d = Detector::new(Config {
            weight_connid: 100,
            max_offenders: 2,
            ..Config::default()
        });
        for i in 0..5u8 {
            let ip = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 1, 1, i];
            d.on_connid_mismatch(&ip, 1000 + u32::from(i));
        }
        assert!(d.offenders() <= 2, "registry must stay bounded");
    }

    #[test]
    fn state_is_bounded_by_eviction() {
        let d = Detector::new(Config {
            max_entries: SHARDS,
            ..Config::default()
        });
        let a = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 1, 1, 7];
        let b = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 2, 2, 2, 7];
        d.on_announce(&a, &clean(&H1, &GOOD_PEER), 1000);
        d.on_announce(&b, &clean(&H1, &GOOD_PEER), 1001);
        assert_eq!(d.tracked(), 1);
    }

    #[test]
    fn verdict_and_config_derives() {
        assert_ne!(
            Verdict::Allow,
            Verdict::Ban {
                duration: 1,
                tier: 0
            }
        );
        assert!(format!("{:?}", Verdict::Allow).contains("Allow"));
        let c = Config::default();
        assert_eq!(c, c);
        assert!(format!("{c:?}").contains("Config"));
        let a = clean(&H1, &GOOD_PEER);
        assert!(format!("{a:?}").contains("AnnounceInfo"));
        let _copy = a;
    }
}
