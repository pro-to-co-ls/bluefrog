//! Prometheus/OpenMetrics counters and text exposition.
//!
//! Lock-free atomic counters incremented on the hot path; [`Metrics::render`] produces the text
//! exposition format the runtime serves on the metrics endpoint. Gauges (torrents, seeders,
//! leechers, tracked sources) are sampled at render time and passed in. Pure — no I/O.
#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicU64, Ordering};

/// The tracker's counter set.
#[derive(Debug, Default)]
pub struct Metrics {
    /// UDP announces served.
    pub udp_announces: AtomicU64,
    /// UDP scrapes served.
    pub udp_scrapes: AtomicU64,
    /// UDP connect handshakes served.
    pub udp_connects: AtomicU64,
    /// UDP connection-id validation failures.
    pub udp_connid_mismatch: AtomicU64,
    /// UDP datagrams dropped as malformed/unknown.
    pub udp_dropped: AtomicU64,
    /// HTTP announces served.
    pub http_announces: AtomicU64,
    /// HTTP scrapes served.
    pub http_scrapes: AtomicU64,
    /// Requests answered with an error/failure.
    pub errors: AtomicU64,
    /// Sources flagged by the L7 layer.
    pub l7_flagged: AtomicU64,
    /// Sources banned into the nft set by the L7 layer.
    pub l7_bans: AtomicU64,
    /// Bans issued above tier 0 — i.e. repeat offenders that actually escalated.
    pub l7_bans_escalated: AtomicU64,
    /// nft writer errors.
    pub nft_errors: AtomicU64,
}

/// A monotonic counter field of [`Metrics`], addressed for `inc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Counter {
    /// [`Metrics::udp_announces`].
    UdpAnnounce,
    /// [`Metrics::udp_scrapes`].
    UdpScrape,
    /// [`Metrics::udp_connects`].
    UdpConnect,
    /// [`Metrics::udp_connid_mismatch`].
    UdpConnidMismatch,
    /// [`Metrics::udp_dropped`].
    UdpDropped,
    /// [`Metrics::http_announces`].
    HttpAnnounce,
    /// [`Metrics::http_scrapes`].
    HttpScrape,
    /// [`Metrics::errors`].
    Error,
    /// [`Metrics::l7_flagged`].
    L7Flagged,
    /// [`Metrics::l7_bans`].
    L7Ban,
    /// [`Metrics::l7_bans_escalated`].
    L7BanEscalated,
    /// [`Metrics::nft_errors`].
    NftError,
}

/// Gauges sampled from live state at render time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Gauges {
    /// Torrents currently tracked.
    pub torrents: u64,
    /// Seeders (complete peers) across all torrents.
    pub seeders: u64,
    /// Leechers (downloading peers) across all torrents.
    pub leechers: u64,
    /// L7 sources currently tracked.
    pub l7_tracked: u64,
    /// Sources in the L7 escalation registry (repeat offenders).
    pub l7_offenders: u64,
}

impl Metrics {
    /// A fresh, all-zero counter set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment a counter by one (Relaxed — counters are independent).
    pub fn inc(&self, counter: Counter) {
        self.field(counter).fetch_add(1, Ordering::Relaxed);
    }

    fn field(&self, counter: Counter) -> &AtomicU64 {
        match counter {
            Counter::UdpAnnounce => &self.udp_announces,
            Counter::UdpScrape => &self.udp_scrapes,
            Counter::UdpConnect => &self.udp_connects,
            Counter::UdpConnidMismatch => &self.udp_connid_mismatch,
            Counter::UdpDropped => &self.udp_dropped,
            Counter::HttpAnnounce => &self.http_announces,
            Counter::HttpScrape => &self.http_scrapes,
            Counter::Error => &self.errors,
            Counter::L7Flagged => &self.l7_flagged,
            Counter::L7Ban => &self.l7_bans,
            Counter::L7BanEscalated => &self.l7_bans_escalated,
            Counter::NftError => &self.nft_errors,
        }
    }

    /// Render the OpenMetrics text exposition, sampling `gauges` for the live values.
    #[must_use]
    pub fn render(&self, gauges: Gauges) -> String {
        const COUNTERS: &[(&str, Counter)] = &[
            ("bf_udp_announces_total", Counter::UdpAnnounce),
            ("bf_udp_scrapes_total", Counter::UdpScrape),
            ("bf_udp_connects_total", Counter::UdpConnect),
            ("bf_udp_connid_mismatch_total", Counter::UdpConnidMismatch),
            ("bf_udp_dropped_total", Counter::UdpDropped),
            ("bf_http_announces_total", Counter::HttpAnnounce),
            ("bf_http_scrapes_total", Counter::HttpScrape),
            ("bf_errors_total", Counter::Error),
            ("bf_l7_flagged_total", Counter::L7Flagged),
            ("bf_l7_bans_total", Counter::L7Ban),
            ("bf_l7_bans_escalated_total", Counter::L7BanEscalated),
            ("bf_nft_errors_total", Counter::NftError),
        ];
        let mut out = String::new();
        for (name, counter) in COUNTERS {
            let v = self.field(*counter).load(Ordering::Relaxed);
            out.push_str(&format!("# TYPE {name} counter\n{name} {v}\n"));
        }
        for (name, v) in [
            ("bf_torrents", gauges.torrents),
            ("bf_seeders", gauges.seeders),
            ("bf_leechers", gauges.leechers),
            ("bf_l7_tracked_sources", gauges.l7_tracked),
            ("bf_l7_offenders", gauges.l7_offenders),
        ] {
            out.push_str(&format!("# TYPE {name} gauge\n{name} {v}\n"));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_increment_and_render() {
        let m = Metrics::new();
        m.inc(Counter::UdpAnnounce);
        m.inc(Counter::UdpAnnounce);
        m.inc(Counter::L7Ban);
        let text = m.render(Gauges {
            torrents: 42,
            seeders: 30,
            leechers: 12,
            l7_tracked: 7,
            l7_offenders: 3,
        });
        assert!(text.contains("# TYPE bf_udp_announces_total counter\nbf_udp_announces_total 2\n"));
        assert!(text.contains("bf_l7_bans_total 1\n"));
        assert!(text.contains("bf_l7_bans_escalated_total 0\n"));
        assert!(text.contains("# TYPE bf_torrents gauge\nbf_torrents 42\n"));
        assert!(text.contains("# TYPE bf_seeders gauge\nbf_seeders 30\n"));
        assert!(text.contains("bf_leechers 12\n"));
        assert!(text.contains("bf_l7_tracked_sources 7\n"));
        assert!(text.contains("# TYPE bf_l7_offenders gauge\nbf_l7_offenders 3\n"));
    }

    #[test]
    fn every_counter_is_addressable() {
        let m = Metrics::default();
        for c in [
            Counter::UdpAnnounce,
            Counter::UdpScrape,
            Counter::UdpConnect,
            Counter::UdpConnidMismatch,
            Counter::UdpDropped,
            Counter::HttpAnnounce,
            Counter::HttpScrape,
            Counter::Error,
            Counter::L7Flagged,
            Counter::L7Ban,
            Counter::L7BanEscalated,
            Counter::NftError,
        ] {
            m.inc(c);
            assert_eq!(m.field(c).load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn derives() {
        assert_ne!(Counter::UdpAnnounce, Counter::Error);
        assert!(format!("{:?}", Counter::L7Ban).contains("L7Ban"));
        let g = Gauges::default();
        assert_eq!(
            g,
            Gauges {
                torrents: 0,
                seeders: 0,
                leechers: 0,
                l7_tracked: 0,
                l7_offenders: 0
            }
        );
        assert!(format!("{g:?}").contains("Gauges"));
        assert!(format!("{:?}", Metrics::new()).contains("Metrics"));
    }
}
