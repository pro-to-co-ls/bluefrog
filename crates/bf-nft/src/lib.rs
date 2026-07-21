//! Native-netlink nft ban sink.
//!
//! Bans are written directly to nftables over a netlink socket via [`NetlinkSink`] — no process
//! spawn, so a burst of bans is a socket write, not a `fork()`+`exec()`. A ban adds the source IP
//! as an element of an auto-expiring set (`flags timeout`), so nftables removes it on its own when
//! the set's default timeout lapses; the firewall defines the sets. The netlink I/O lives in
//! [`sink`] and is Linux-only (a non-Linux stub keeps the workspace building on dev machines), so
//! it is verified on Linux rather than by the unit-coverage gate.

pub mod sink;
pub use sink::{BanSink, NetlinkSink};
