//! bluefrog tracker daemon.
//!
//! Thin I/O glue over the tested library crates: a tokio multi-threaded runtime running the UDP
//! hot path (one `SO_REUSEPORT` socket + task per worker), a hyper HTTP server, a background GC
//! sweep, and a Prometheus endpoint — with the L7 detector feeding bans into an nft set. All
//! request logic lives in `bf-udp` / `bf-http` (100% unit-tested); this file is the socket wiring
//! and is validated by the integration test in `tests/`, not the unit-coverage gate.

use bf_core::{ConnId, Store};
use bf_http::{HttpHandler, Response as HttpResponse};
use bf_l7::{AnnounceInfo, Detector, Verdict};
use bf_metrics::{Counter, Gauges, Metrics};
use bf_nft::{BanSink, NetlinkSink};
use bf_proto::udp;
use bf_udp::{Action, Handler};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use socket2::{Domain, Protocol, Socket, Type};
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, UdpSocket};

const GC_INTERVAL_SECS: u64 = 120;
const UDP_BUF: usize = 2048;

/// Everything the request paths share, behind a single `Arc`.
struct Shared {
    udp: Handler,
    http: HttpHandler,
    detector: Detector,
    metrics: Metrics,
    store: Arc<Store>,
    config: bf_config::Config,
    clock: AtomicU64,
    sink: NetlinkSink,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn ip_to_16(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// Canonicalize an address: a dual-stack `[::]` socket delivers IPv4 peers as IPv4-mapped IPv6
/// (`::ffff:a.b.c.d`), so un-map them back to real IPv4. Without this, IPv4 clients are treated as
/// v6 — stored in the v6 swarm and banned into the v6 nft set, where the `ip saddr @l7ban4` drop
/// rule never matches them (and `ip6 saddr @l7ban6` can't match a v4 packet either).
fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

fn random_key() -> [u8; 32] {
    // The connid MAC key is the anti-spoofing root of trust — it must come from the OS CSPRNG,
    // never a non-cryptographic PRNG.
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).expect("OS CSPRNG unavailable");
    key
}

fn bind_reuseport_udp(addr: SocketAddr, rcvbuf: Option<usize>) -> std::io::Result<UdpSocket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.set_reuse_port(true)?;
    if let Some(sz) = rcvbuf {
        sock.set_recv_buffer_size(sz)?;
    }
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    UdpSocket::from_std(sock.into())
}

/// Whether an address is publicly routable. BEP-15's `IP` field is only a legitimate NAT hint from
/// private space, so this decides whether a client setting it is suspicious.
fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation())
        }
        IpAddr::V6(v6) => {
            let head = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || (head & 0xfe00) == 0xfc00   // unique-local fc00::/7
                || (head & 0xffc0) == 0xfe80) // link-local fe80::/10
        }
    }
}

/// Feed the L7 detector from the pre-parsed request and the handler's verdict. `now_secs` is the
/// current time in seconds (the L7 clock).
fn feed_l7(
    sh: &Shared,
    parsed: &Result<udp::Request, udp::ParseError>,
    ip: IpAddr,
    ip16: &[u8; 16],
    action: &Action,
    now_secs: u32,
) -> Verdict {
    if matches!(action, Action::ConnidMismatch) {
        return sh.detector.on_connid_mismatch(ip16, now_secs);
    }
    match parsed {
        Ok(udp::Request::Announce(a)) => {
            let info = AnnounceInfo {
                info_hash: a.info_hash,
                peer_id: a.peer_id,
                key: a.key,
                declared_ip: a.declared_ip,
                port: a.port,
                left: a.left,
                downloaded: a.downloaded,
                uploaded: a.uploaded,
                num_want: a.num_want,
                source_is_public: is_public(ip),
            };
            sh.detector.on_announce(ip16, &info, now_secs)
        }
        Ok(udp::Request::Scrape(s)) => {
            sh.detector
                .on_scrape(ip16, s.iter_hashes().count(), now_secs)
        }
        Ok(udp::Request::Connect { .. }) => sh.detector.on_connect(ip16, now_secs),
        Err(_) => Verdict::Allow,
    }
}

/// Ban a source IP by adding it to the nft set for its escalation `tier`. Runs on the blocking
/// pool so the netlink syscall never stalls the async worker.
fn ban(sh: Arc<Shared>, ip: IpAddr, tier: usize, duration: u32) {
    tokio::task::spawn_blocking(move || {
        if sh.sink.ban(ip, tier, duration).is_err() {
            sh.metrics.inc(Counter::NftError);
        }
    });
}

fn record_udp_metric(
    metrics: &Metrics,
    parsed: &Result<udp::Request, udp::ParseError>,
    action: &Action,
) {
    match action {
        Action::Drop => {
            metrics.inc(Counter::UdpDropped);
            return;
        }
        Action::ConnidMismatch => {
            metrics.inc(Counter::UdpConnidMismatch);
            return;
        }
        Action::Reply(_) => {}
    }
    match parsed {
        Ok(udp::Request::Connect { .. }) => metrics.inc(Counter::UdpConnect),
        Ok(udp::Request::Announce(_)) => metrics.inc(Counter::UdpAnnounce),
        Ok(udp::Request::Scrape(_)) => metrics.inc(Counter::UdpScrape),
        Err(_) => metrics.inc(Counter::UdpDropped),
    }
}

async fn udp_worker(sock: UdpSocket, sh: Arc<Shared>) {
    let mut buf = vec![0u8; UDP_BUF];
    let mut out = Vec::with_capacity(1500);
    loop {
        let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
            continue;
        };
        let ip = canonical_ip(peer.ip());
        let ip16 = ip_to_16(ip);
        let is_v4 = ip.is_ipv4();
        let now = sh.clock.load(Ordering::Relaxed);
        let interval = 1620 + fastrand::u32(0..360);
        // Parse once and share it with the metric counter and the L7 feed.
        let parsed = udp::parse(&buf[..n]);
        let action = sh
            .udp
            .handle(&buf[..n], &ip16, is_v4, now, interval, &mut out);

        record_udp_metric(&sh.metrics, &parsed, &action);
        if sh.config.l7_enable {
            // The L7 detector runs on a seconds clock (its `reannounce_min_interval` /
            // `decay_per_sec` are in seconds), unlike the store's minutes clock.
            let now_secs = u32::try_from(now).unwrap_or(u32::MAX);
            if let Verdict::Ban { duration, tier } =
                feed_l7(&sh, &parsed, ip, &ip16, &action, now_secs)
            {
                sh.metrics.inc(Counter::L7Ban);
                if sh.config.nft_enable {
                    ban(sh.clone(), ip, tier as usize, duration);
                }
            }
        }
        if let Action::Reply(len) = action {
            let _ = sock.send_to(&out[..len], peer).await;
        }
    }
}

fn http_reply(status: StatusCode, body: Vec<u8>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

fn handle_http(sh: &Shared, target: &str, ip: IpAddr) -> Response<Full<Bytes>> {
    let is_v4 = ip.is_ipv4();
    let ip16 = ip_to_16(ip);
    let now_min = u32::try_from(sh.clock.load(Ordering::Relaxed) / 60).unwrap_or(u32::MAX);
    let interval = 1620 + fastrand::u32(0..360);
    match sh.http.handle(target, &ip16, is_v4, now_min, interval) {
        HttpResponse::Body(b) => {
            if target.starts_with("/announce") {
                sh.metrics.inc(Counter::HttpAnnounce);
            } else if target.starts_with("/scrape") {
                sh.metrics.inc(Counter::HttpScrape);
            }
            http_reply(StatusCode::OK, b)
        }
        HttpResponse::Redirect => {
            let url = sh.config.redirect_url.clone().unwrap_or_default();
            Response::builder()
                .status(StatusCode::FOUND)
                .header("location", url)
                .body(Full::new(Bytes::new()))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
        }
        HttpResponse::BadRequest => {
            sh.metrics.inc(Counter::Error);
            http_reply(StatusCode::BAD_REQUEST, b"400".to_vec())
        }
        HttpResponse::NotFound => http_reply(StatusCode::NOT_FOUND, b"404".to_vec()),
    }
}

async fn serve_http(listener: TcpListener, sh: Arc<Shared>) {
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            continue;
        };
        let sh = sh.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req: Request<Incoming>| {
                let sh = sh.clone();
                let ip = canonical_ip(peer.ip());
                let target = req
                    .uri()
                    .path_and_query()
                    .map_or_else(|| "/".to_string(), |pq| pq.as_str().to_string());
                async move { Ok::<_, Infallible>(handle_http(&sh, &target, ip)) }
            });
            let _ = http1::Builder::new().serve_connection(io, service).await;
        });
    }
}

async fn serve_metrics(listener: TcpListener, sh: Arc<Shared>) {
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            continue;
        };
        if !peer.ip().is_loopback() {
            continue; // metrics are localhost-only; access is not otherwise gated
        }
        let sh = sh.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |_req: Request<Incoming>| {
                let sh = sh.clone();
                async move {
                    let totals = sh.store.totals();
                    let gauges = Gauges {
                        torrents: totals.torrents,
                        seeders: totals.seeders,
                        leechers: totals.leechers,
                        l7_tracked: sh.detector.tracked() as u64,
                        l7_offenders: sh.detector.offenders() as u64,
                    };
                    Ok::<_, Infallible>(http_reply(
                        StatusCode::OK,
                        sh.metrics.render(gauges).into_bytes(),
                    ))
                }
            });
            let _ = http1::Builder::new().serve_connection(io, service).await;
        });
    }
}

async fn clock_task(sh: Arc<Shared>) {
    loop {
        sh.clock.store(now_secs(), Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn gc_task(sh: Arc<Shared>) {
    loop {
        tokio::time::sleep(Duration::from_secs(GC_INTERVAL_SECS)).await;
        let now_min = u32::try_from(now_secs() / 60).unwrap_or(u32::MAX);
        sh.store.gc(now_min);
    }
}

fn build_shared(config: bf_config::Config) -> Arc<Shared> {
    let store = Arc::new(Store::new());
    let connid = ConnId::new(random_key(), u64::from(config.connid_window));
    let detector = Detector::new(config.l7);
    let sink = NetlinkSink::new(
        &config.nft_table,
        config.nft_set4.clone(),
        config.nft_set6.clone(),
    );
    Arc::new(Shared {
        udp: Handler::new(store.clone(), connid),
        http: HttpHandler::new(store.clone()),
        detector,
        metrics: Metrics::new(),
        store,
        config,
        clock: AtomicU64::new(now_secs()),
        sink,
    })
}

async fn run(config: bf_config::Config) -> std::io::Result<()> {
    let sh = build_shared(config);
    sh.clock.store(now_secs(), Ordering::Relaxed);

    tokio::spawn(clock_task(sh.clone()));
    tokio::spawn(gc_task(sh.clone()));

    for addr in &sh.config.udp_listen {
        let workers = sh.config.udp_workers.max(1);
        for _ in 0..workers {
            let sock = bind_reuseport_udp(*addr, sh.config.udp_rcvbuf)?;
            tokio::spawn(udp_worker(sock, sh.clone()));
        }
        eprintln!("bluefrog: udp listening on {addr} ({workers} workers)");
    }

    for addr in &sh.config.tcp_listen {
        let listener = TcpListener::bind(addr).await?;
        eprintln!("bluefrog: http listening on {addr}");
        tokio::spawn(serve_http(listener, sh.clone()));
    }

    if let Some(addr) = sh.config.metrics_listen {
        let listener = TcpListener::bind(addr).await?;
        eprintln!("bluefrog: metrics on {addr}");
        tokio::spawn(serve_metrics(listener, sh.clone()));
    }

    wait_for_shutdown().await;
    eprintln!("bluefrog: shutting down");
    Ok(())
}

async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
        } else {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let arg = std::env::args().nth(1);
    if matches!(arg.as_deref(), Some("--version" | "-V")) {
        println!("bluefrog {}", env!("BLUEFROG_VERSION"));
        return Ok(());
    }
    let path = arg.unwrap_or_else(|| "/etc/bluefrog/bluefrog.conf".to_string());
    let text = std::fs::read_to_string(&path)?;
    let config = bf_config::parse(&text).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{path}:{}: {}", e.line, e.message),
        )
    })?;
    run(config).await
}
