//! Configuration parser.
//!
//! A line-based directive format (`section.key value`, `#` comments), with `udp.*`, `l7.*`,
//! `nft.*`, and `metrics.*` sections. Unknown directives (accesslist, livesync, proxy) are parsed
//! and ignored. Pure text → [`Config`]; the runtime does the I/O.
#![forbid(unsafe_code)]

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

/// Default tracker port when a listen directive gives only an address.
pub const DEFAULT_PORT: u16 = 6969;

/// A parsed configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// UDP listen sockets.
    pub udp_listen: Vec<SocketAddr>,
    /// TCP (HTTP) listen sockets.
    pub tcp_listen: Vec<SocketAddr>,
    /// Number of blocking UDP worker sockets (`SO_REUSEPORT`).
    pub udp_workers: usize,
    /// `SO_RCVBUF` for the UDP sockets, if set.
    pub udp_rcvbuf: Option<usize>,
    /// Connection-id key window in seconds (BEP-15).
    pub connid_window: u32,
    /// `GET /` redirect target.
    pub redirect_url: Option<String>,
    /// chroot/chdir directory.
    pub rootdir: Option<String>,
    /// setuid target user.
    pub user: Option<String>,
    /// Prometheus metrics listen socket.
    pub metrics_listen: Option<SocketAddr>,
    /// Whether the L7 detector is enabled.
    pub l7_enable: bool,
    /// L7 detector tunables.
    pub l7: bf_l7::Config,
    /// Whether nft enforcement is enabled.
    pub nft_enable: bool,
    /// nft table for the ban sets.
    pub nft_table: String,
    /// nft IPv4 ban set name.
    pub nft_set4: String,
    /// nft IPv6 ban set name.
    pub nft_set6: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            udp_listen: Vec::new(),
            tcp_listen: Vec::new(),
            udp_workers: 0,
            udp_rcvbuf: None,
            connid_window: 120,
            redirect_url: None,
            rootdir: None,
            user: None,
            metrics_listen: None,
            l7_enable: false,
            l7: bf_l7::Config::default(),
            nft_enable: false,
            nft_table: "inet filter".to_string(),
            nft_set4: "l7ban4".to_string(),
            nft_set6: "l7ban6".to_string(),
        }
    }
}

/// A parse failure, with the 1-based line number.
#[derive(Debug, PartialEq, Eq)]
pub struct ParseError {
    /// 1-based line number.
    pub line: usize,
    /// Human-readable reason.
    pub message: String,
}

fn field<T: FromStr>(val: &str, line: usize) -> Result<T, ParseError> {
    val.parse().map_err(|_| ParseError {
        line,
        message: format!("invalid value: {val:?}"),
    })
}

fn boolean(val: &str, line: usize) -> Result<bool, ParseError> {
    match val {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        _ => Err(ParseError {
            line,
            message: format!("expected a boolean, got {val:?}"),
        }),
    }
}

/// Parse a listen address: `ip:port`, `[v6]:port`, or a bare address (which takes [`DEFAULT_PORT`]).
fn listen_addr(val: &str, line: usize) -> Result<SocketAddr, ParseError> {
    if let Ok(sa) = val.parse::<SocketAddr>() {
        Ok(sa)
    } else if let Ok(ip) = val.parse::<IpAddr>() {
        Ok(SocketAddr::new(ip, DEFAULT_PORT))
    } else {
        Err(ParseError {
            line,
            message: format!("invalid listen address: {val:?}"),
        })
    }
}

/// Parse a whole configuration file.
///
/// # Errors
/// Returns a [`ParseError`] on the first line with a malformed value.
pub fn parse(text: &str) -> Result<Config, ParseError> {
    let mut c = Config::default();
    for (idx, raw) in text.lines().enumerate() {
        let line = idx + 1;
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let (key, val) = match trimmed.split_once(char::is_whitespace) {
            Some((k, v)) => (k, v.trim()),
            None => (trimmed, ""),
        };
        match key {
            "listen.udp" => c.udp_listen.push(listen_addr(val, line)?),
            "listen.tcp" => c.tcp_listen.push(listen_addr(val, line)?),
            "listen.tcp_udp" => {
                let sa = listen_addr(val, line)?;
                c.udp_listen.push(sa);
                c.tcp_listen.push(sa);
            }
            "listen.udp.workers" => c.udp_workers = field(val, line)?,
            "listen.udp.rcvbuf" => c.udp_rcvbuf = Some(field(val, line)?),
            "udp.connid_window" => c.connid_window = field(val, line)?,
            "tracker.redirect_url" => c.redirect_url = Some(val.to_string()),
            "tracker.rootdir" => c.rootdir = Some(val.to_string()),
            "tracker.user" => c.user = Some(val.to_string()),
            "metrics.listen" => c.metrics_listen = Some(field(val, line)?),
            "l7.enable" => c.l7_enable = boolean(val, line)?,
            "l7.reannounce_min_interval" => c.l7.reannounce_min_interval = field(val, line)?,
            "l7.score_ban_threshold" => c.l7.score_ban_threshold = field(val, line)?,
            "l7.ban_duration" => c.l7.ban_duration = field(val, line)?,
            "l7.max_entries" => c.l7.max_entries = field(val, line)?,
            "nft.enable" => c.nft_enable = boolean(val, line)?,
            "nft.table" => c.nft_table = val.to_string(),
            "nft.set4" => c.nft_set4 = val.to_string(),
            "nft.set6" => c.nft_set6 = val.to_string(),
            // Unknown directives (accesslist, livesync, proxy, …) are ignored.
            _ => {}
        }
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_comments_and_unknown() {
        let c =
            parse("# a comment\n\n   \naccess.whitelist /x\nlivesync.cluster.node_ip 1.2.3.4\n")
                .unwrap();
        assert_eq!(c, Config::default());
        assert_eq!(c.connid_window, 120);
        assert!(c.udp_listen.is_empty());
    }

    #[test]
    fn parses_a_typical_config() {
        let text = "\
listen.udp.workers 16
listen.udp.rcvbuf 8388608
listen.tcp [::]:27108
listen.udp [::]:2710
access.stats 127.0.0.0/8
tracker.rootdir /etc/bluefrog
tracker.redirect_url https://example.com/
";
        let c = parse(text).unwrap();
        assert_eq!(c.udp_workers, 16);
        assert_eq!(c.udp_rcvbuf, Some(8_388_608));
        assert_eq!(c.tcp_listen, vec!["[::]:27108".parse().unwrap()]);
        assert_eq!(c.udp_listen, vec!["[::]:2710".parse().unwrap()]);
        // `access.stats` is now an ignored directive (localhost-only metrics is enforced in code).
        assert_eq!(c.rootdir.as_deref(), Some("/etc/bluefrog"));
        assert_eq!(c.redirect_url.as_deref(), Some("https://example.com/"));
    }

    #[test]
    fn tcp_udp_and_bare_address_default_port() {
        let c = parse("listen.tcp_udp 0.0.0.0\n").unwrap();
        let expected: SocketAddr = format!("0.0.0.0:{DEFAULT_PORT}").parse().unwrap();
        assert_eq!(c.udp_listen, vec![expected]);
        assert_eq!(c.tcp_listen, vec![expected]);
    }

    #[test]
    fn l7_and_nft_and_metrics_and_user_directives() {
        let text = "\
udp.connid_window 3600
tracker.user nobody
l7.enable yes
l7.reannounce_min_interval 30
l7.score_ban_threshold 200
l7.ban_duration 7200
l7.max_entries 500000
nft.enable 1
nft.table inet foo
nft.set4 bans4
nft.set6 bans6
metrics.listen 127.0.0.1:9100
";
        let c = parse(text).unwrap();
        assert_eq!(c.connid_window, 3600);
        assert_eq!(c.user.as_deref(), Some("nobody"));
        assert!(c.l7_enable);
        assert_eq!(c.l7.reannounce_min_interval, 30);
        assert_eq!(c.l7.score_ban_threshold, 200);
        assert_eq!(c.l7.ban_duration, 7200);
        assert_eq!(c.l7.max_entries, 500_000);
        assert!(c.nft_enable);
        assert_eq!(c.nft_table, "inet foo");
        assert_eq!(c.nft_set4, "bans4");
        assert_eq!(c.nft_set6, "bans6");
        assert_eq!(c.metrics_listen, Some("127.0.0.1:9100".parse().unwrap()));
    }

    #[test]
    fn boolean_false_forms() {
        assert!(!parse("l7.enable 0\n").unwrap().l7_enable);
        assert!(!parse("nft.enable false\n").unwrap().nft_enable);
        assert!(!parse("nft.enable no\n").unwrap().nft_enable);
    }

    #[test]
    fn errors_carry_line_numbers() {
        assert_eq!(
            parse("\n\nlisten.udp.workers abc\n").unwrap_err(),
            ParseError {
                line: 3,
                message: "invalid value: \"abc\"".to_string()
            }
        );
        assert_eq!(parse("listen.udp notanaddr\n").unwrap_err().line, 1);
        assert_eq!(parse("listen.tcp bad\n").unwrap_err().line, 1);
        assert_eq!(parse("listen.tcp_udp bad\n").unwrap_err().line, 1);
        assert_eq!(parse("l7.enable maybe\n").unwrap_err().line, 1);
        assert_eq!(parse("metrics.listen nope\n").unwrap_err().line, 1);
        assert_eq!(parse("listen.udp.rcvbuf x\n").unwrap_err().line, 1);
    }

    #[test]
    fn key_without_value_is_handled() {
        // a bare key (no value) parses; string fields become empty
        let c = parse("nft.set4\n").unwrap();
        assert_eq!(c.nft_set4, "");
    }

    #[test]
    fn derives() {
        let c = Config::default();
        assert_eq!(c, c.clone());
        assert!(format!("{c:?}").contains("Config"));
        let e = ParseError {
            line: 1,
            message: "x".to_string(),
        };
        assert_ne!(
            e,
            ParseError {
                line: 2,
                message: "x".to_string()
            }
        );
        assert!(format!("{e:?}").contains("ParseError"));
    }
}
