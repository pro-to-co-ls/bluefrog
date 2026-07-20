//! Construction of the `nft` command that bans a source into an auto-expiring set.
//!
//! Pure string-building only — this crate never touches the network or spawns a process. The
//! binary takes [`ban_argv`] and hands it to `nft` (that syscall glue is the runtime's job and is
//! covered by Linux integration tests, not here). A ban is an element added to an interval set
//! with a per-element `timeout`, so nft expires it on its own:
//!
//! ```text
//! nft add element inet filter l7ban4 { 1.2.3.4 timeout 3600s }
//! ```

pub mod sink;
pub use sink::{BanSink, NetlinkSink};

use std::net::IpAddr;

/// Choose the v4 or v6 ban set for `ip`.
#[must_use]
pub fn ban_set<'a>(ip: IpAddr, set4: &'a str, set6: &'a str) -> &'a str {
    match ip {
        IpAddr::V4(_) => set4,
        IpAddr::V6(_) => set6,
    }
}

/// Build the `nft` argument vector that adds `ip` to `set` in `table` with a `duration`-second
/// auto-expiring timeout. `table` may be multi-token (e.g. `"inet filter"`).
#[must_use]
pub fn ban_argv(table: &str, set: &str, ip: IpAddr, duration: u32) -> Vec<String> {
    let mut argv = vec!["add".to_string(), "element".to_string()];
    argv.extend(table.split_whitespace().map(str::to_string));
    argv.push(set.to_string());
    argv.push(format!("{{ {ip} timeout {duration}s }}"));
    argv
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn selects_set_by_family() {
        let v4 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(ban_set(v4, "s4", "s6"), "s4");
        assert_eq!(ban_set(v6, "s4", "s6"), "s6");
    }

    #[test]
    fn builds_v4_ban_argv() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
        let argv = ban_argv("inet filter", "l7ban4", ip, 3600);
        assert_eq!(
            argv,
            vec![
                "add",
                "element",
                "inet",
                "filter",
                "l7ban4",
                "{ 10.0.0.9 timeout 3600s }",
            ]
        );
    }

    #[test]
    fn builds_v6_ban_argv() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let argv = ban_argv("inet filter", "l7ban6", ip, 60);
        assert_eq!(argv.last().unwrap(), "{ 2001:db8::1 timeout 60s }");
    }
}
