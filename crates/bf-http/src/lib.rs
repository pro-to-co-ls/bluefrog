//! HTTP tracker handler: announce / scrape / `GET /` redirect.
//!
//! Pure logic — given a request target (`/announce?...`) and the client's address, it returns a
//! [`Response`]; the hyper glue in the binary does the socket work. The bencode bodies are
//! compact-only (`compact=0` is a 400). Stats are served separately via Prometheus.
#![forbid(unsafe_code)]

use bf_core::{HASH_LEN, InfoHash, Store, flag};
use bf_proto::bencode;
use std::sync::Arc;

/// Numwant cap for HTTP announces.
pub const NUMWANT_MAX: usize = 200;
/// Default numwant when the client omits it.
pub const NUMWANT_DEFAULT: usize = 50;
/// Maximum info-hashes honoured in a single HTTP scrape (matches the UDP cap).
pub const MAX_SCRAPE_HASHES: usize = 75;

/// A tracker HTTP response (the runtime maps these onto status codes).
#[derive(Debug, PartialEq, Eq)]
pub enum Response {
    /// `200 OK`, `text/plain`, with a bencoded body.
    Body(Vec<u8>),
    /// `302 Found` to the configured redirect URL (`GET /`).
    Redirect,
    /// `400 Invalid Request`.
    BadRequest,
    /// `404 Not Found`.
    NotFound,
}

/// The HTTP tracker handler over a shared store.
pub struct HttpHandler {
    store: Arc<Store>,
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Percent-decode `input` into `out` (`+` becomes space). Returns `false` on a malformed escape.
fn percent_decode(input: &[u8], out: &mut Vec<u8>) -> bool {
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'%' => {
                let (Some(&h), Some(&l)) = (input.get(i + 1), input.get(i + 2)) else {
                    return false;
                };
                let (Some(h), Some(l)) = (hex_val(h), hex_val(l)) else {
                    return false;
                };
                out.push((h << 4) | l);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    true
}

/// Split a `k=v&k=v` query, yielding each `(key, raw_value)` (value not yet percent-decoded).
fn query_pairs(query: &str) -> impl Iterator<Item = (&str, &str)> {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| p.split_once('=').unwrap_or((p, "")))
}

impl HttpHandler {
    /// Create a handler over a shared store.
    #[must_use]
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }

    /// Handle a request. `target` is the raw request target (path + optional query), `src_ip` the
    /// 16-byte client address, `is_v4` the family, and `interval` the (jittered) announce interval.
    pub fn handle(
        &self,
        target: &str,
        src_ip: &[u8; 16],
        is_v4: bool,
        now: u32,
        interval: u32,
    ) -> Response {
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        match path {
            "/" => Response::Redirect,
            "/announce" => self.announce(query, src_ip, is_v4, now, interval),
            "/scrape" => self.scrape(query),
            _ => Response::NotFound,
        }
    }

    fn announce(
        &self,
        query: &str,
        src_ip: &[u8; 16],
        is_v4: bool,
        now: u32,
        interval: u32,
    ) -> Response {
        let mut info_hash: Option<InfoHash> = None;
        let mut port: Option<u16> = None;
        let mut left: u64 = 1;
        let mut event = "";
        let mut numwant = NUMWANT_DEFAULT;
        let mut buf = Vec::new();

        for (key, raw) in query_pairs(query) {
            match key {
                "info_hash" => {
                    buf.clear();
                    if !percent_decode(raw.as_bytes(), &mut buf) || buf.len() != HASH_LEN {
                        return Response::BadRequest;
                    }
                    info_hash = Some(to_hash(&buf));
                }
                "port" => match raw.parse::<u16>() {
                    Ok(p) => port = Some(p),
                    Err(_) => return Response::BadRequest,
                },
                "left" => left = raw.parse().unwrap_or(1), // malformed -> leecher, not seeder
                "event" => event = raw,
                "compact" => {
                    if raw == "0" {
                        return Response::BadRequest; // only compact responses are supported
                    }
                }
                "numwant" => {
                    if let Ok(n) = raw.parse::<usize>() {
                        numwant = n.min(NUMWANT_MAX);
                    }
                }
                _ => {}
            }
        }

        let (Some(hash), Some(port)) = (info_hash, port) else {
            let mut body = Vec::new();
            bencode::failure(
                &mut body,
                b"Your client forgot to send your torrent's info_hash.",
            );
            return Response::Body(body);
        };

        let mut flags = 0u8;
        if left == 0 {
            flags |= flag::SEEDING;
        }
        if event == "completed" {
            flags |= flag::COMPLETED;
        }

        let mut peers4 = Vec::new();
        let mut peers6 = Vec::new();
        let counts = if event == "stopped" {
            if is_v4 {
                self.store.remove_v4(&hash, &v4_key(src_ip, port), now)
            } else {
                self.store.remove_v6(&hash, &v6_key(src_ip, port), now)
            }
        } else if is_v4 {
            self.store.announce_v4(
                &hash,
                v4_key(src_ip, port),
                flags,
                numwant,
                now,
                &mut peers4,
            )
        } else {
            self.store.announce_v6(
                &hash,
                v6_key(src_ip, port),
                flags,
                numwant,
                now,
                &mut peers6,
            )
        };

        let mut body = Vec::new();
        bencode::announce_response(&mut body, counts, interval, &peers4, &peers6);
        Response::Body(body)
    }

    fn scrape(&self, query: &str) -> Response {
        let mut files: Vec<(InfoHash, bf_core::Counts)> = Vec::new();
        let mut buf = Vec::new();
        for (key, raw) in query_pairs(query) {
            if key == "info_hash" {
                if files.len() >= MAX_SCRAPE_HASHES {
                    break;
                }
                buf.clear();
                if !percent_decode(raw.as_bytes(), &mut buf) || buf.len() != HASH_LEN {
                    return Response::BadRequest;
                }
                let hash = to_hash(&buf);
                files.push((hash, self.store.scrape(&hash)));
            }
        }
        let refs: Vec<(&InfoHash, bf_core::Counts)> = files.iter().map(|(h, c)| (h, *c)).collect();
        let mut body = Vec::new();
        bencode::scrape_response(&mut body, &refs);
        Response::Body(body)
    }
}

fn to_hash(b: &[u8]) -> InfoHash {
    <InfoHash>::try_from(b).expect("caller checked HASH_LEN")
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

#[cfg(test)]
mod tests {
    use super::*;

    const V4_IP: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 5];
    const V6_IP: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
    // percent-encoded 20-byte info-hash of all 0x41 ('A')
    const IH: &str = "AAAAAAAAAAAAAAAAAAAA";

    fn handler() -> HttpHandler {
        HttpHandler::new(Arc::new(Store::new()))
    }

    fn body(r: Response) -> String {
        match r {
            Response::Body(b) => String::from_utf8_lossy(&b).into_owned(),
            other => panic!("expected body, got {other:?}"),
        }
    }

    #[test]
    #[should_panic(expected = "expected body")]
    fn body_helper_requires_body_variant() {
        let _ = body(Response::NotFound);
    }

    #[test]
    #[should_panic(expected = "HASH_LEN")]
    fn to_hash_requires_exact_len() {
        let _ = to_hash(&[0u8; 5]);
    }

    #[test]
    fn percent_decode_cases() {
        let mut out = Vec::new();
        assert!(percent_decode(b"a+b%20%41", &mut out));
        assert_eq!(out, b"a b A");
        // malformed: truncated and non-hex
        out.clear();
        assert!(!percent_decode(b"%4", &mut out));
        out.clear();
        assert!(!percent_decode(b"%zz", &mut out));
    }

    #[test]
    fn dispatch_redirect_and_notfound() {
        let h = handler();
        assert_eq!(h.handle("/", &V4_IP, true, 10, 1800), Response::Redirect);
        assert_eq!(
            h.handle("/nope", &V4_IP, true, 10, 1800),
            Response::NotFound
        );
    }

    #[test]
    fn announce_missing_info_hash_is_failure_body() {
        let h = handler();
        let text = body(h.handle("/announce?port=6881", &V4_IP, true, 10, 1800));
        assert!(text.contains("failure reason"));
    }

    #[test]
    fn announce_v4_roundtrip() {
        let h = handler();
        // includes compact=1 (non-zero) and an unknown param, both of which are accepted
        let q = format!(
            "/announce?info_hash={IH}&port=6881&left=0&numwant=30&event=started&compact=1&x=y"
        );
        let text = body(h.handle(&q, &V4_IP, true, 10, 1620));
        assert!(text.contains("8:completei1e"));
        assert!(text.contains("8:intervali1620e"));
        assert!(text.contains("12:min intervali810e"));
        // the seeder is returned in its own compact peer list (6 bytes)
        assert!(text.contains("5:peers6:"));

        // a v4 stopped announce removes the peer
        let stop = format!("/announce?info_hash={IH}&port=6881&event=stopped");
        body(h.handle(&stop, &V4_IP, true, 10, 1800));
        assert_eq!(h.store.scrape(&[0x41u8; HASH_LEN]).complete, 0);
    }

    #[test]
    fn announce_v6_and_stopped_and_completed() {
        let h = handler();
        let hash = [0x41u8; HASH_LEN];
        // completed
        let q = format!("/announce?info_hash={IH}&port=6881&left=0&event=completed");
        body(h.handle(&q, &V6_IP, false, 10, 1800));
        assert_eq!(h.store.scrape(&hash).downloaded, 1);
        // stopped removes it
        let q = format!("/announce?info_hash={IH}&port=6881&event=stopped");
        body(h.handle(&q, &V6_IP, false, 10, 1800));
        assert_eq!(h.store.scrape(&hash).complete, 0);
    }

    #[test]
    fn announce_rejects_compact_zero_bad_port_and_bad_hash() {
        let h = handler();
        assert_eq!(
            h.handle(
                &format!("/announce?info_hash={IH}&port=1&compact=0"),
                &V4_IP,
                true,
                10,
                1800
            ),
            Response::BadRequest
        );
        assert_eq!(
            h.handle(
                &format!("/announce?info_hash={IH}&port=99999"),
                &V4_IP,
                true,
                10,
                1800
            ),
            Response::BadRequest
        );
        assert_eq!(
            h.handle(
                "/announce?info_hash=tooshort&port=1",
                &V4_IP,
                true,
                10,
                1800
            ),
            Response::BadRequest
        );
    }

    #[test]
    fn scrape_roundtrip_and_bad_hash() {
        let h = handler();
        // seed a torrent
        let q = format!("/announce?info_hash={IH}&port=6881&left=0");
        body(h.handle(&q, &V4_IP, true, 10, 1800));
        // scrape it (an extra non-info_hash param is ignored)
        let text = body(h.handle(
            &format!("/scrape?info_hash={IH}&extra=1"),
            &V4_IP,
            true,
            10,
            1800,
        ));
        assert!(text.starts_with("d5:filesd20:AAAAAAAAAAAAAAAAAAAA"));
        assert!(text.contains("8:completei1e"));
        // scrape with no hashes -> empty files dict
        assert_eq!(
            body(h.handle("/scrape", &V4_IP, true, 10, 1800)),
            "d5:filesdee"
        );
        // bad hash
        assert_eq!(
            h.handle("/scrape?info_hash=x", &V4_IP, true, 10, 1800),
            Response::BadRequest
        );
    }

    #[test]
    fn scrape_caps_hash_count() {
        let h = handler();
        // a scrape carrying more than the cap of info_hash params
        let mut q = String::from("/scrape?info_hash=");
        q.push_str(IH);
        for _ in 0..(MAX_SCRAPE_HASHES + 3) {
            q.push_str("&info_hash=");
            q.push_str(IH);
        }
        let text = body(h.handle(&q, &V4_IP, true, 10, 1800));
        // only MAX_SCRAPE_HASHES entries are emitted, not the MAX+4 requested
        assert_eq!(
            text.matches("20:AAAAAAAAAAAAAAAAAAAA").count(),
            MAX_SCRAPE_HASHES
        );
    }

    #[test]
    fn response_derives() {
        assert_ne!(Response::Redirect, Response::NotFound);
        assert!(format!("{:?}", Response::BadRequest).contains("BadRequest"));
    }
}
