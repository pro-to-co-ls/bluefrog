//! BEP-15 UDP tracker protocol: request parsing and response serialization.
//!
//! All multi-byte fields are big-endian. Parsing borrows from the input datagram (zero-copy);
//! serialization writes into a caller-provided buffer (allocation-free), so this maps cleanly
//! onto a reusable per-worker scratch buffer on the hot path.

use bf_core::{Event, HASH_LEN, InfoHash, PeerId};

/// The BEP-15 magic protocol id present in every `connect` request (`0x41727101980`).
pub const PROTOCOL_ID: u64 = 0x0000_0417_2710_1980;
/// Minimum size of any request datagram: connection_id(8) + action(4) + transaction_id(4).
pub const MIN_PACKET: usize = 16;
/// Minimum size of an `announce` request.
pub const ANNOUNCE_MIN: usize = 98;
/// Compact IPv4 peer size: 4-byte address + 2-byte port.
pub const PEER4_LEN: usize = 6;
/// Compact IPv6 peer size: 16-byte address + 2-byte port.
pub const PEER6_LEN: usize = 18;
/// Maximum number of info-hashes honoured in a single UDP scrape.
pub const MAX_SCRAPE_HASHES: usize = 75;

/// A parsed BEP-15 request, borrowing from the source datagram.
#[derive(Debug, PartialEq, Eq)]
pub enum Request<'a> {
    /// `connect` (action 0) with a valid protocol id.
    Connect {
        /// Client transaction id to echo back.
        transaction_id: u32,
    },
    /// `announce` (action 1).
    Announce(Announce<'a>),
    /// `scrape` (action 2).
    Scrape(Scrape<'a>),
}

/// A parsed BEP-15 `announce` request.
#[derive(Debug, PartialEq, Eq)]
pub struct Announce<'a> {
    /// Connection id supplied by the client (validated by the caller against the connid scheme).
    pub connection_id: u64,
    /// Client transaction id to echo back.
    pub transaction_id: u32,
    /// The torrent info-hash (borrowed).
    pub info_hash: &'a InfoHash,
    /// The client's peer id (borrowed).
    pub peer_id: &'a PeerId,
    /// Bytes downloaded (informational; not used for peer accounting).
    pub downloaded: u64,
    /// Bytes left; `0` marks a seeder.
    pub left: u64,
    /// Bytes uploaded (informational).
    pub uploaded: u64,
    /// Decoded announce event.
    pub event: Event,
    /// Requested peer count (signed per BEP-15; `-1` means "tracker default").
    pub num_want: i32,
    /// The port the peer listens on.
    pub port: u16,
}

/// A parsed BEP-15 `scrape` request.
#[derive(Debug, PartialEq, Eq)]
pub struct Scrape<'a> {
    /// Connection id supplied by the client.
    pub connection_id: u64,
    /// Client transaction id to echo back.
    pub transaction_id: u32,
    /// Concatenated 20-byte info-hashes, capped at [`MAX_SCRAPE_HASHES`] and to whole strides.
    pub hashes: &'a [u8],
}

impl Scrape<'_> {
    /// Iterator over the requested info-hashes.
    pub fn iter_hashes(&self) -> impl Iterator<Item = &InfoHash> {
        self.hashes.chunks_exact(HASH_LEN).map(hash_ref)
    }
}

/// Why a datagram could not be parsed as a BEP-15 request.
#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Datagram shorter than [`MIN_PACKET`].
    TooShort,
    /// `connect` request without the [`PROTOCOL_ID`] magic.
    BadProtocolId,
    /// `announce` request shorter than [`ANNOUNCE_MIN`].
    AnnounceTooShort,
    /// Action field greater than 2.
    UnknownAction(u32),
}

#[inline]
fn be_u16(b: &[u8]) -> u16 {
    u16::from_be_bytes(b.try_into().expect("2 bytes"))
}

#[inline]
fn be_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes(b.try_into().expect("4 bytes"))
}

#[inline]
fn be_u64(b: &[u8]) -> u64 {
    u64::from_be_bytes(b.try_into().expect("8 bytes"))
}

/// Borrow a 20-byte hash from a slice of exactly [`HASH_LEN`] bytes.
#[inline]
fn hash_ref(b: &[u8]) -> &InfoHash {
    <&InfoHash>::try_from(b).expect("HASH_LEN bytes")
}

/// Parse a UDP datagram into a [`Request`].
///
/// # Errors
/// Returns a [`ParseError`] for datagrams that are too short, carry a bad connect magic, are an
/// undersized announce, or use an unknown action.
pub fn parse(buf: &[u8]) -> Result<Request<'_>, ParseError> {
    if buf.len() < MIN_PACKET {
        return Err(ParseError::TooShort);
    }
    let connection_id = be_u64(&buf[0..8]);
    let action = be_u32(&buf[8..12]);
    let transaction_id = be_u32(&buf[12..16]);

    match action {
        0 => {
            if connection_id != PROTOCOL_ID {
                return Err(ParseError::BadProtocolId);
            }
            Ok(Request::Connect { transaction_id })
        }
        1 => {
            if buf.len() < ANNOUNCE_MIN {
                return Err(ParseError::AnnounceTooShort);
            }
            Ok(Request::Announce(Announce {
                connection_id,
                transaction_id,
                info_hash: hash_ref(&buf[16..36]),
                peer_id: hash_ref(&buf[36..56]),
                downloaded: be_u64(&buf[56..64]),
                left: be_u64(&buf[64..72]),
                uploaded: be_u64(&buf[72..80]),
                event: Event::from_udp(be_u32(&buf[80..84])),
                num_want: be_u32(&buf[92..96]) as i32,
                port: be_u16(&buf[96..98]),
            }))
        }
        2 => {
            let full = ((buf.len() - MIN_PACKET) / HASH_LEN).min(MAX_SCRAPE_HASHES);
            Ok(Request::Scrape(Scrape {
                connection_id,
                transaction_id,
                hashes: &buf[MIN_PACKET..MIN_PACKET + full * HASH_LEN],
            }))
        }
        other => Err(ParseError::UnknownAction(other)),
    }
}

/// Write a 16-byte `connect` response into the first 16 bytes of `out`.
pub fn write_connect(out: &mut [u8], transaction_id: u32, connection_id: u64) {
    out[0..4].copy_from_slice(&0u32.to_be_bytes());
    out[4..8].copy_from_slice(&transaction_id.to_be_bytes());
    out[8..16].copy_from_slice(&connection_id.to_be_bytes());
}

/// Write an `announce` response (20-byte header + compact `peers`) into `out`.
///
/// Returns the number of bytes written. `out` must hold at least `20 + peers.len()` bytes.
pub fn write_announce(
    out: &mut [u8],
    transaction_id: u32,
    interval: u32,
    leechers: u32,
    seeders: u32,
    peers: &[u8],
) -> usize {
    out[0..4].copy_from_slice(&1u32.to_be_bytes());
    out[4..8].copy_from_slice(&transaction_id.to_be_bytes());
    out[8..12].copy_from_slice(&interval.to_be_bytes());
    out[12..16].copy_from_slice(&leechers.to_be_bytes());
    out[16..20].copy_from_slice(&seeders.to_be_bytes());
    out[20..20 + peers.len()].copy_from_slice(peers);
    20 + peers.len()
}

/// Write a `scrape` response into `out`: 8-byte header then `(seeders, downloaded, leechers)`
/// (each big-endian `u32`) per requested hash. Returns bytes written.
pub fn write_scrape(out: &mut [u8], transaction_id: u32, entries: &[(u32, u32, u32)]) -> usize {
    out[0..4].copy_from_slice(&2u32.to_be_bytes());
    out[4..8].copy_from_slice(&transaction_id.to_be_bytes());
    let mut off = 8;
    for &(seeders, downloaded, leechers) in entries {
        out[off..off + 4].copy_from_slice(&seeders.to_be_bytes());
        out[off + 4..off + 8].copy_from_slice(&downloaded.to_be_bytes());
        out[off + 8..off + 12].copy_from_slice(&leechers.to_be_bytes());
        off += 12;
    }
    off
}

/// Write an `error` response (action 3) into `out`: 8-byte header then the message bytes.
/// Returns bytes written.
pub fn write_error(out: &mut [u8], transaction_id: u32, message: &[u8]) -> usize {
    out[0..4].copy_from_slice(&3u32.to_be_bytes());
    out[4..8].copy_from_slice(&transaction_id.to_be_bytes());
    out[8..8 + message.len()].copy_from_slice(message);
    8 + message.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(action: u32, connection_id: u64, txid: u32, len: usize) -> Vec<u8> {
        let mut p = vec![0u8; len];
        p[0..8].copy_from_slice(&connection_id.to_be_bytes());
        p[8..12].copy_from_slice(&action.to_be_bytes());
        p[12..16].copy_from_slice(&txid.to_be_bytes());
        p
    }

    fn announce_packet(event: u32) -> Vec<u8> {
        let mut p = header(1, 0x1122_3344_5566_7788, 0xdead_beef, ANNOUNCE_MIN);
        for (i, b) in p[16..36].iter_mut().enumerate() {
            *b = i as u8;
        }
        for (i, b) in p[36..56].iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(100);
        }
        p[56..64].copy_from_slice(&10u64.to_be_bytes());
        p[64..72].copy_from_slice(&20u64.to_be_bytes());
        p[72..80].copy_from_slice(&30u64.to_be_bytes());
        p[80..84].copy_from_slice(&event.to_be_bytes());
        p[92..96].copy_from_slice(&(-1i32).to_be_bytes());
        p[96..98].copy_from_slice(&6881u16.to_be_bytes());
        p
    }

    #[test]
    fn constants_are_correct() {
        assert_eq!(PROTOCOL_ID, 0x0000_0417_2710_1980);
        assert_eq!((MIN_PACKET, ANNOUNCE_MIN), (16, 98));
        assert_eq!((PEER4_LEN, PEER6_LEN, MAX_SCRAPE_HASHES), (6, 18, 75));
    }

    // The fixed-width readers are only ever fed correctly-sized slices by `parse`, but their
    // wrong-length contract is exercised here so the error paths are covered.
    #[test]
    #[should_panic(expected = "2 bytes")]
    fn be_u16_rejects_wrong_length() {
        let _ = be_u16(&[1]);
    }

    #[test]
    #[should_panic(expected = "4 bytes")]
    fn be_u32_rejects_wrong_length() {
        let _ = be_u32(&[1, 2, 3]);
    }

    #[test]
    #[should_panic(expected = "8 bytes")]
    fn be_u64_rejects_wrong_length() {
        let _ = be_u64(&[1, 2, 3]);
    }

    #[test]
    #[should_panic(expected = "HASH_LEN bytes")]
    fn hash_ref_rejects_wrong_length() {
        let _ = hash_ref(&[0u8; 5]);
    }

    #[test]
    fn parse_rejects_too_short() {
        assert_eq!(parse(&[0u8; 15]), Err(ParseError::TooShort));
    }

    #[test]
    fn parse_connect_ok_and_bad_magic() {
        let good = header(0, PROTOCOL_ID, 42, MIN_PACKET);
        assert_eq!(parse(&good), Ok(Request::Connect { transaction_id: 42 }));

        let bad = header(0, PROTOCOL_ID + 1, 42, MIN_PACKET);
        assert_eq!(parse(&bad), Err(ParseError::BadProtocolId));
    }

    fn expected_announce<'a>(ih: &'a InfoHash, pid: &'a PeerId, event: Event) -> Request<'a> {
        Request::Announce(Announce {
            connection_id: 0x1122_3344_5566_7788,
            transaction_id: 0xdead_beef,
            info_hash: ih,
            peer_id: pid,
            downloaded: 10,
            left: 20,
            uploaded: 30,
            event,
            num_want: -1,
            port: 6881,
        })
    }

    #[test]
    fn parse_announce_fields_and_events() {
        let mut ih = [0u8; HASH_LEN];
        for (i, b) in ih.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut pid = [0u8; HASH_LEN];
        for (i, b) in pid.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(100);
        }

        // Whole-value comparison covers every parsed field and the event mapping in the codec.
        assert_eq!(
            parse(&announce_packet(1)),
            Ok(expected_announce(&ih, &pid, Event::Completed))
        );
        assert_eq!(
            parse(&announce_packet(3)),
            Ok(expected_announce(&ih, &pid, Event::Stopped))
        );
        assert_eq!(
            parse(&announce_packet(0)),
            Ok(expected_announce(&ih, &pid, Event::None))
        );
    }

    #[test]
    fn parse_announce_too_short() {
        let p = header(1, PROTOCOL_ID, 1, ANNOUNCE_MIN - 1);
        assert_eq!(parse(&p), Err(ParseError::AnnounceTooShort));
    }

    #[test]
    fn parse_scrape_counts_and_caps() {
        // two full hashes
        let two = header(2, 7, 9, MIN_PACKET + 2 * HASH_LEN);
        assert_eq!(
            parse(&two),
            Ok(Request::Scrape(Scrape {
                connection_id: 7,
                transaction_id: 9,
                hashes: &two[MIN_PACKET..MIN_PACKET + 2 * HASH_LEN],
            }))
        );

        // trailing partial hash is ignored (floor to whole strides)
        let partial = header(2, 0, 0, MIN_PACKET + HASH_LEN + 5);
        assert_eq!(
            parse(&partial),
            Ok(Request::Scrape(Scrape {
                connection_id: 0,
                transaction_id: 0,
                hashes: &partial[MIN_PACKET..MIN_PACKET + HASH_LEN],
            }))
        );

        // more than MAX_SCRAPE_HASHES is capped
        let many = header(2, 0, 0, MIN_PACKET + (MAX_SCRAPE_HASHES + 5) * HASH_LEN);
        assert_eq!(
            parse(&many),
            Ok(Request::Scrape(Scrape {
                connection_id: 0,
                transaction_id: 0,
                hashes: &many[MIN_PACKET..MIN_PACKET + MAX_SCRAPE_HASHES * HASH_LEN],
            }))
        );
    }

    #[test]
    fn scrape_iter_hashes_yields_each_stride() {
        let mut hashes = [0u8; 2 * HASH_LEN];
        hashes[HASH_LEN] = 0xff; // second hash's first byte
        let s = Scrape {
            connection_id: 0,
            transaction_id: 0,
            hashes: &hashes,
        };
        let collected: Vec<&InfoHash> = s.iter_hashes().collect();
        assert_eq!(collected.len(), 2);
        assert_eq!(collected[0][0], 0);
        assert_eq!(collected[1][0], 0xff);
    }

    #[test]
    fn parse_unknown_action() {
        let p = header(3, 0, 0, MIN_PACKET);
        assert_eq!(parse(&p), Err(ParseError::UnknownAction(3)));
    }

    #[test]
    fn write_connect_response_bytes() {
        let mut out = [0u8; 16];
        write_connect(&mut out, 0xaabb_ccdd, 0x0102_0304_0506_0708);
        assert_eq!(&out[0..4], &0u32.to_be_bytes());
        assert_eq!(&out[4..8], &0xaabb_ccddu32.to_be_bytes());
        assert_eq!(&out[8..16], &0x0102_0304_0506_0708u64.to_be_bytes());
    }

    #[test]
    fn write_announce_response_bytes() {
        let mut out = [0u8; 64];
        let peers = [1u8, 2, 3, 4, 0x1a, 0xe1]; // one v4 peer
        let n = write_announce(&mut out, 0xdead_beef, 1800, 5, 3, &peers);
        assert_eq!(n, 20 + peers.len());
        assert_eq!(&out[0..4], &1u32.to_be_bytes());
        assert_eq!(&out[4..8], &0xdead_beefu32.to_be_bytes());
        assert_eq!(&out[8..12], &1800u32.to_be_bytes());
        assert_eq!(&out[12..16], &5u32.to_be_bytes());
        assert_eq!(&out[16..20], &3u32.to_be_bytes());
        assert_eq!(&out[20..26], &peers);

        // empty peer list path
        let n0 = write_announce(&mut out, 1, 1620, 0, 0, &[]);
        assert_eq!(n0, 20);
    }

    #[test]
    fn write_scrape_response_bytes() {
        let mut out = [0u8; 64];
        let entries = [(10u32, 100u32, 20u32), (1, 2, 3)];
        let n = write_scrape(&mut out, 0x11, &entries);
        assert_eq!(n, 8 + 2 * 12);
        assert_eq!(&out[0..4], &2u32.to_be_bytes());
        assert_eq!(&out[4..8], &0x11u32.to_be_bytes());
        assert_eq!(&out[8..12], &10u32.to_be_bytes());
        assert_eq!(&out[12..16], &100u32.to_be_bytes());
        assert_eq!(&out[16..20], &20u32.to_be_bytes());

        // empty entries path
        assert_eq!(write_scrape(&mut out, 0, &[]), 8);
    }

    #[test]
    fn write_error_response_bytes() {
        let mut out = [0u8; 64];
        let msg = b"Connection ID missmatch.";
        let n = write_error(&mut out, 0x22, msg);
        assert_eq!(n, 8 + msg.len());
        assert_eq!(&out[0..4], &3u32.to_be_bytes());
        assert_eq!(&out[4..8], &0x22u32.to_be_bytes());
        assert_eq!(&out[8..8 + msg.len()], msg);
    }

    #[test]
    fn public_types_are_debug_and_partial_eq() {
        // Debug + PartialEq(false branch) coverage for the public request/error types.
        let c1 = Request::Connect { transaction_id: 1 };
        let c2 = Request::Connect { transaction_id: 2 };
        assert_ne!(c1, c2);
        assert!(format!("{c1:?}").contains("Connect"));

        let p = announce_packet(1);
        let a = parse(&p).unwrap();
        assert!(format!("{a:?}").contains("Announce"));

        let s = header(2, 0, 0, MIN_PACKET);
        let sc = parse(&s).unwrap();
        assert!(format!("{sc:?}").contains("Scrape"));

        let e = ParseError::UnknownAction(7);
        assert_ne!(e, ParseError::TooShort);
        assert!(format!("{e:?}").contains("UnknownAction"));
    }
}
