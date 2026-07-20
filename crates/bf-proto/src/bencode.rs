//! Minimal bencode writer plus the exact tracker response bodies (announce / scrape / failure).
//!
//! Allocation-free apart from the caller's output buffer; integers are formatted with `itoa`.
//! Only the small surface the HTTP tracker needs — this is a writer, not a general parser.

use bf_core::{Counts, InfoHash};

/// A streaming bencode writer over a caller-owned byte buffer.
pub struct Encoder<'a> {
    out: &'a mut Vec<u8>,
}

impl<'a> Encoder<'a> {
    /// Wrap an output buffer.
    pub fn new(out: &'a mut Vec<u8>) -> Self {
        Self { out }
    }

    /// Write a bencoded integer (`i<n>e`).
    pub fn int(&mut self, v: u64) -> &mut Self {
        self.out.push(b'i');
        self.write_uint(v);
        self.out.push(b'e');
        self
    }

    /// Write a bencoded byte string (`<len>:<bytes>`).
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.write_uint(b.len() as u64);
        self.out.push(b':');
        self.out.extend_from_slice(b);
        self
    }

    /// Open a dictionary (`d`).
    pub fn dict(&mut self) -> &mut Self {
        self.out.push(b'd');
        self
    }

    /// Open a list (`l`).
    pub fn list(&mut self) -> &mut Self {
        self.out.push(b'l');
        self
    }

    /// Close the current dictionary or list (`e`).
    pub fn end(&mut self) -> &mut Self {
        self.out.push(b'e');
        self
    }

    fn write_uint(&mut self, v: u64) {
        let mut buf = itoa::Buffer::new();
        self.out.extend_from_slice(buf.format(v).as_bytes());
    }
}

/// Write an HTTP announce response body: counts, intervals, and the compact peer strings.
///
/// `interval` is the (jittered) announce interval; `min interval` is half of it.
pub fn announce_response(
    out: &mut Vec<u8>,
    counts: Counts,
    interval: u32,
    peers4: &[u8],
    peers6: &[u8],
) {
    let mut e = Encoder::new(out);
    e.dict()
        .bytes(b"complete")
        .int(u64::from(counts.complete))
        .bytes(b"downloaded")
        .int(u64::from(counts.downloaded))
        .bytes(b"incomplete")
        .int(u64::from(counts.incomplete))
        .bytes(b"interval")
        .int(u64::from(interval))
        .bytes(b"min interval")
        .int(u64::from(interval / 2))
        .bytes(b"peers")
        .bytes(peers4)
        .bytes(b"peers6")
        .bytes(peers6)
        .end();
}

/// Write an HTTP scrape response body for the given `(hash, counts)` files.
pub fn scrape_response(out: &mut Vec<u8>, files: &[(&InfoHash, Counts)]) {
    let mut e = Encoder::new(out);
    e.dict().bytes(b"files").dict();
    for (hash, counts) in files {
        e.bytes(hash.as_slice())
            .dict()
            .bytes(b"complete")
            .int(u64::from(counts.complete))
            .bytes(b"downloaded")
            .int(u64::from(counts.downloaded))
            .bytes(b"incomplete")
            .int(u64::from(counts.incomplete))
            .end();
    }
    e.end().end();
}

/// Write a bencoded `failure reason` body.
pub fn failure(out: &mut Vec<u8>, reason: &[u8]) {
    Encoder::new(out)
        .dict()
        .bytes(b"failure reason")
        .bytes(reason)
        .end();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[u8]) -> String {
        String::from_utf8(v.to_vec()).unwrap()
    }

    #[test]
    fn primitives() {
        let mut out = Vec::new();
        let mut e = Encoder::new(&mut out);
        e.int(0).int(12345).bytes(b"spam").list().end();
        assert_eq!(s(&out), "i0ei12345e4:spamle");
    }

    #[test]
    fn announce_body() {
        let mut out = Vec::new();
        let counts = Counts {
            complete: 2,
            incomplete: 3,
            downloaded: 5,
        };
        announce_response(&mut out, counts, 1800, &[1, 2, 3, 4, 0, 80], &[]);
        assert_eq!(
            s(&out),
            "d8:completei2e10:downloadedi5e10:incompletei3e8:intervali1800e12:min intervali900e5:peers6:\u{1}\u{2}\u{3}\u{4}\u{0}P6:peers60:e"
        );
    }

    #[test]
    fn scrape_body_multiple_and_empty() {
        let h1: InfoHash = [0x41; 20];
        let h2: InfoHash = [0x42; 20];
        let c1 = Counts {
            complete: 1,
            incomplete: 0,
            downloaded: 9,
        };
        let c2 = Counts::default();
        let mut out = Vec::new();
        scrape_response(&mut out, &[(&h1, c1), (&h2, c2)]);
        let text = s(&out);
        assert!(text.starts_with("d5:filesd20:AAAAAAAAAAAAAAAAAAAA"));
        assert!(text.contains("d8:completei1e10:downloadedi9e10:incompletei0ee"));
        assert!(text.ends_with("ee"));

        // empty file list
        let mut empty = Vec::new();
        scrape_response(&mut empty, &[]);
        assert_eq!(s(&empty), "d5:filesdee");
    }

    #[test]
    fn failure_body() {
        let mut out = Vec::new();
        failure(&mut out, b"nope");
        assert_eq!(s(&out), "d14:failure reason4:nopee");
    }
}
