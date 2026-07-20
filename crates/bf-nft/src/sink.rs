//! The ban sink: adds an offending source IP to an nft set.
//!
//! On Linux this is a **native netlink write** via `rustables` — no process spawn, so a burst of
//! bans is a socket write, not a `fork()`+`exec()`. On non-Linux hosts it is a stub, so the
//! workspace still builds and tests on a dev machine (production is linux arm64/amd64).
//!
//! rustables 0.8 has no per-element timeout, so auto-expiry comes from the **set's default
//! `timeout`** — the firewall defines the sets as
//! `set l7ban4 { type ipv4_addr; flags timeout; timeout <dur>; }` and added elements inherit it.

use std::net::IpAddr;

/// Adds an offending source IP to the nft ban set.
pub trait BanSink {
    /// Ban `ip`. `duration` is informational — expiry is the set's default timeout.
    ///
    /// # Errors
    /// Returns a message if the netlink write fails (or, on non-Linux, always).
    fn ban(&self, ip: IpAddr, duration: u32) -> Result<(), String>;
}

#[cfg(target_os = "linux")]
mod imp {
    use super::BanSink;
    use rustables::set::SetBuilder;
    use rustables::{Batch, MsgType, ProtocolFamily, Table};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// Adds ban elements to existing nft sets over netlink.
    pub struct NetlinkSink {
        family: ProtocolFamily,
        table: String,
        set4: String,
        set6: String,
    }

    impl NetlinkSink {
        /// Build a sink for the given nft table spec (e.g. `"inet filter"`) and ban set names.
        #[must_use]
        pub fn new(table: &str, set4: String, set6: String) -> Self {
            let mut parts = table.split_whitespace();
            let family = match parts.next() {
                Some("ip") => ProtocolFamily::Ipv4,
                Some("ip6") => ProtocolFamily::Ipv6,
                _ => ProtocolFamily::Inet,
            };
            let table = parts.next().unwrap_or("filter").to_string();
            Self {
                family,
                table,
                set4,
                set6,
            }
        }
    }

    impl BanSink for NetlinkSink {
        fn ban(&self, ip: IpAddr, _duration: u32) -> Result<(), String> {
            let table = Table::new(self.family).with_name(self.table.clone());
            let elements = match ip {
                IpAddr::V4(v4) => {
                    let mut b = SetBuilder::<Ipv4Addr>::new(self.set4.clone(), &table)
                        .map_err(|e| format!("{e:?}"))?;
                    b.add(&v4);
                    b.finish().1
                }
                IpAddr::V6(v6) => {
                    let mut b = SetBuilder::<Ipv6Addr>::new(self.set6.clone(), &table)
                        .map_err(|e| format!("{e:?}"))?;
                    b.add(&v6);
                    b.finish().1
                }
            };
            let mut batch = Batch::new();
            batch.add(&elements, MsgType::Add);
            batch.send().map_err(|e| format!("{e:?}"))
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::BanSink;
    use std::net::IpAddr;

    /// Non-Linux stub — nftables netlink is Linux-only.
    pub struct NetlinkSink;

    impl NetlinkSink {
        /// Construct the stub (arguments are ignored).
        #[must_use]
        pub fn new(_table: &str, _set4: String, _set6: String) -> Self {
            Self
        }
    }

    impl BanSink for NetlinkSink {
        fn ban(&self, _ip: IpAddr, _duration: u32) -> Result<(), String> {
            Err("nft ban sink is only available on Linux".to_string())
        }
    }
}

pub use imp::NetlinkSink;
