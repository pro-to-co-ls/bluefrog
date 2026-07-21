//! BEP-15 UDP request handler: the pure logic that turns a datagram into a response by driving
//! the store, the connection-id validator, and the codec. No sockets here — the runtime does I/O
//! and calls [`Handler::handle`], so every path is unit-testable.
#![forbid(unsafe_code)]

use bf_core::{ConnId, Counts, Event, InfoHash, Store, flag};
use bf_proto::udp;
use std::sync::Arc;

/// UDP numwant cap for IPv4 clients.
pub const NUMWANT_MAX_V4: usize = 200;
/// UDP numwant cap for IPv6 clients.
pub const NUMWANT_MAX_V6: usize = 66;

/// What the runtime should do with the datagram after handling.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Send the first `usize` bytes of the output buffer back to the client.
    Reply(usize),
    /// Silently drop the datagram (malformed, unknown, or denied).
    Drop,
    /// Drop a datagram whose connection id failed validation. Distinct from [`Action::Drop`] so the
    /// runtime can count it and feed the L7 detector — without sending a (backscatter) error reply.
    ConnidMismatch,
}

/// Ties the store and connection-id scheme together for the UDP protocol.
pub struct Handler {
    store: Arc<Store>,
    connid: ConnId,
}

fn numwant(requested: i32, is_v4: bool) -> usize {
    let max = if is_v4 {
        NUMWANT_MAX_V4
    } else {
        NUMWANT_MAX_V6
    };
    if requested < 0 {
        max
    } else {
        (requested as usize).min(max)
    }
}

fn v4_key(src_ip: &[u8; 16], port: u16) -> [u8; 6] {
    let mut k = [0u8; 6];
    k[0..4].copy_from_slice(&src_ip[12..16]);
    k[4..6].copy_from_slice(&port.to_be_bytes());
    k
}

fn v6_key(src_ip: &[u8; 16], port: u16) -> [u8; 18] {
    let mut k = [0u8; 18];
    k[0..16].copy_from_slice(src_ip);
    k[16..18].copy_from_slice(&port.to_be_bytes());
    k
}

impl Handler {
    /// Create a handler over a shared store and a connection-id scheme.
    #[must_use]
    pub fn new(store: Arc<Store>, connid: ConnId) -> Self {
        Self { store, connid }
    }

    /// Handle one datagram. `src_ip` is the 16-byte (v4-mapped for IPv4) source address, `is_v4`
    /// selects the peer family, `now_secs` is the current wall-clock second, and `interval` is the
    /// (already jittered) announce interval to advertise. The response is written into `out`.
    pub fn handle(
        &self,
        buf: &[u8],
        src_ip: &[u8; 16],
        is_v4: bool,
        now_secs: u64,
        interval: u32,
        out: &mut Vec<u8>,
    ) -> Action {
        let Ok(req) = udp::parse(buf) else {
            return Action::Drop;
        };
        match req {
            udp::Request::Connect { transaction_id } => {
                let cid = self.connid.generate(src_ip, now_secs);
                out.clear();
                out.resize(16, 0);
                udp::write_connect(out, transaction_id, cid);
                Action::Reply(16)
            }
            udp::Request::Announce(a) => {
                if !self.connid.validate(a.connection_id, src_ip, now_secs) {
                    return Action::ConnidMismatch;
                }
                out.clear();
                out.resize(20, 0); // reserve the header; the store appends peers after it
                let counts = self.apply_announce(&a, src_ip, is_v4, now_secs, out);
                udp::write_announce(
                    out,
                    a.transaction_id,
                    interval,
                    counts.incomplete,
                    counts.complete,
                    &[],
                );
                Action::Reply(out.len())
            }
            udp::Request::Scrape(s) => {
                if !self.connid.validate(s.connection_id, src_ip, now_secs) {
                    return Action::ConnidMismatch;
                }
                let entries: Vec<(u32, u32, u32)> = s
                    .iter_hashes()
                    .map(|h| {
                        let c = self.store.scrape(h);
                        (c.complete, c.downloaded, c.incomplete)
                    })
                    .collect();
                out.clear();
                out.resize(8 + entries.len() * 12, 0);
                let n = udp::write_scrape(out, s.transaction_id, &entries);
                Action::Reply(n)
            }
        }
    }

    /// Apply an announce to the store, leaving the compact peer bytes in `out`; returns counts.
    fn apply_announce(
        &self,
        a: &udp::Announce,
        src_ip: &[u8; 16],
        is_v4: bool,
        now_secs: u64,
        out: &mut Vec<u8>,
    ) -> Counts {
        let now_min = (now_secs / 60) as u32;
        let hash: &InfoHash = a.info_hash;
        let mut flags = 0u8;
        if a.left == 0 {
            flags |= flag::SEEDING;
        }
        if a.event == Event::Completed {
            flags |= flag::COMPLETED;
        }
        // `out` already holds the 20-byte header placeholder; the store appends peers after it.
        let stopped = a.event == Event::Stopped;
        if is_v4 {
            let key = v4_key(src_ip, a.port);
            if stopped {
                self.store.remove_v4(hash, &key, now_min)
            } else {
                self.store
                    .announce_v4(hash, key, flags, numwant(a.num_want, true), now_min, out)
            }
        } else {
            let key = v6_key(src_ip, a.port);
            if stopped {
                self.store.remove_v6(hash, &key, now_min)
            } else {
                self.store
                    .announce_v6(hash, key, flags, numwant(a.num_want, false), now_min, out)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bf_core::HASH_LEN;
    use bf_proto::udp::{ANNOUNCE_MIN, MIN_PACKET, PROTOCOL_ID};

    const V4_IP: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1];
    const V6_IP: [u8; 16] = [0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    fn handler() -> Handler {
        Handler::new(Arc::new(Store::new()), ConnId::new([1u8; 32], 120))
    }

    fn header(action: u32, cid: u64, txid: u32, len: usize) -> Vec<u8> {
        let mut p = vec![0u8; len];
        p[0..8].copy_from_slice(&cid.to_be_bytes());
        p[8..12].copy_from_slice(&action.to_be_bytes());
        p[12..16].copy_from_slice(&txid.to_be_bytes());
        p
    }

    fn announce(cid: u64, txid: u32, left: u64, event: u32, num_want: i32, port: u16) -> Vec<u8> {
        let mut p = header(1, cid, txid, ANNOUNCE_MIN);
        p[16..36].copy_from_slice(&[3u8; HASH_LEN]); // info_hash
        p[64..72].copy_from_slice(&left.to_be_bytes());
        p[80..84].copy_from_slice(&event.to_be_bytes());
        p[92..96].copy_from_slice(&num_want.to_be_bytes());
        p[96..98].copy_from_slice(&port.to_be_bytes());
        p
    }

    #[test]
    fn parse_error_drops() {
        let h = handler();
        let mut out = Vec::new();
        assert_eq!(
            h.handle(&[0u8; 4], &V4_IP, true, 100, 1800, &mut out),
            Action::Drop
        );
    }

    #[test]
    fn connect_roundtrip_and_numwant_helper() {
        let h = handler();
        let mut out = Vec::new();
        let pkt = header(0, PROTOCOL_ID, 0xaa, MIN_PACKET);
        assert_eq!(
            h.handle(&pkt, &V4_IP, true, 1000, 1800, &mut out),
            Action::Reply(16)
        );
        // the returned connection id validates for a subsequent announce
        let cid = u64::from_be_bytes(out[8..16].try_into().unwrap());
        assert!(h.connid.validate(cid, &V4_IP, 1000));

        assert_eq!(numwant(-1, true), NUMWANT_MAX_V4);
        assert_eq!(numwant(-1, false), NUMWANT_MAX_V6);
        assert_eq!(numwant(10, true), 10);
        assert_eq!(numwant(9999, false), NUMWANT_MAX_V6);
    }

    #[test]
    fn announce_bad_connid_drops() {
        let h = handler();
        let mut out = Vec::new();
        let pkt = announce(0xbad, 0x11, 0, 0, -1, 6881);
        let action = h.handle(&pkt, &V4_IP, true, 1000, 1800, &mut out);
        // bad connid: silent drop (no backscatter reply), flagged so the runtime counts/feeds L7
        assert_eq!(action, Action::ConnidMismatch);
    }

    #[test]
    fn announce_v4_seeder_then_leecher_gets_peers() {
        let h = handler();
        let now = 1000u64;
        let cid = h.connid.generate(&V4_IP, now);
        let mut out = Vec::new();

        // a seeder announces (left=0); the peer is returned in its own list
        let seed = announce(cid, 0x1, 0, 0, -1, 6881);
        let a = h.handle(&seed, &V4_IP, true, now, 1620, &mut out);
        assert_eq!(a, Action::Reply(26)); // 20 header + itself (one 6-byte v4 peer)
        assert_eq!(&out[0..4], &1u32.to_be_bytes()); // announce action
        assert_eq!(&out[8..12], &1620u32.to_be_bytes()); // interval
        assert_eq!(&out[12..16], &0u32.to_be_bytes()); // leechers
        assert_eq!(&out[16..20], &1u32.to_be_bytes()); // seeders
        assert_eq!(&out[20..26], &[10, 0, 0, 1, 0x1a, 0xe1]); // itself: 10.0.0.1:6881

        // a leecher on a different IP: response holds both peers (leecher first, then the seeder)
        let leech_ip = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 2];
        let cid2 = h.connid.generate(&leech_ip, now);
        let leech = announce(cid2, 0x2, 100, 2, -1, 6882);
        let a = h.handle(&leech, &leech_ip, true, now, 1620, &mut out);
        assert_eq!(a, Action::Reply(32)); // 20 header + two 6-byte v4 peers
        assert_eq!(&out[12..16], &1u32.to_be_bytes()); // one leecher
        assert_eq!(&out[16..20], &1u32.to_be_bytes()); // one seeder
        assert_eq!(&out[20..26], &[10, 0, 0, 2, 0x1a, 0xe2]); // leecher first
        assert_eq!(&out[26..32], &[10, 0, 0, 1, 0x1a, 0xe1]); // seeder after
    }

    #[test]
    fn announce_completed_and_stopped() {
        let h = handler();
        let now = 600u64;
        let cid = h.connid.generate(&V4_IP, now);
        let mut out = Vec::new();

        // completed event
        let done = announce(cid, 0x3, 0, 1, -1, 6881);
        h.handle(&done, &V4_IP, true, now, 1800, &mut out);
        assert_eq!(h.store.scrape(&[3u8; HASH_LEN]).downloaded, 1);

        // stopped event removes the peer, reply is the 20-byte header only
        let stop = announce(cid, 0x4, 0, 3, -1, 6881);
        let a = h.handle(&stop, &V4_IP, true, now, 1800, &mut out);
        assert_eq!(a, Action::Reply(20));
        assert_eq!(h.store.scrape(&[3u8; HASH_LEN]).complete, 0);
    }

    #[test]
    fn announce_v6_path() {
        let h = handler();
        let now = 1000u64;
        let cid = h.connid.generate(&V6_IP, now);
        let mut out = Vec::new();
        let seed = announce(cid, 0x5, 0, 0, 5, 6881);
        let a = h.handle(&seed, &V6_IP, false, now, 1620, &mut out);
        assert_eq!(a, Action::Reply(38)); // 20 header + itself (one 18-byte v6 peer)
        assert_eq!(h.store.scrape(&[3u8; HASH_LEN]).complete, 1);

        // a v6 stopped announce removes the peer
        let stop = announce(cid, 0x6, 0, 3, -1, 6881);
        let a = h.handle(&stop, &V6_IP, false, now, 1800, &mut out);
        assert_eq!(a, Action::Reply(20));
        assert_eq!(h.store.scrape(&[3u8; HASH_LEN]).complete, 0);
    }

    #[test]
    fn scrape_roundtrip_and_bad_connid() {
        let h = handler();
        let now = 1000u64;
        let cid = h.connid.generate(&V4_IP, now);
        let mut out = Vec::new();

        // seed one torrent so scrape has non-zero counts
        let seed = announce(cid, 0x1, 0, 0, -1, 6881);
        h.handle(&seed, &V4_IP, true, now, 1800, &mut out);

        // scrape that hash
        let mut pkt = header(2, cid, 0x9, MIN_PACKET + HASH_LEN);
        pkt[MIN_PACKET..MIN_PACKET + HASH_LEN].copy_from_slice(&[3u8; HASH_LEN]);
        let a = h.handle(&pkt, &V4_IP, true, now, 1800, &mut out);
        assert_eq!(a, Action::Reply(8 + 12));
        assert_eq!(&out[0..4], &2u32.to_be_bytes()); // scrape action
        assert_eq!(&out[8..12], &1u32.to_be_bytes()); // seeders

        // scrape with a bad connection id -> silent drop
        let bad = header(2, 0xbad, 0x9, MIN_PACKET + HASH_LEN);
        let a = h.handle(&bad, &V4_IP, true, now, 1800, &mut out);
        assert_eq!(a, Action::ConnidMismatch);
    }

    #[test]
    fn action_derives() {
        assert_ne!(Action::Reply(1), Action::Drop);
        assert_ne!(Action::Drop, Action::ConnidMismatch);
        assert!(format!("{:?}", Action::Drop).contains("Drop"));
        assert!(format!("{:?}", Action::ConnidMismatch).contains("ConnidMismatch"));
    }
}
