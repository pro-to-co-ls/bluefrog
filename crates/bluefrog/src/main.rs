//! bluefrog tracker daemon.
//!
//! Thin I/O glue over the tested library crates: a tokio multi-threaded runtime running the UDP
//! hot path (one `SO_REUSEPORT` socket + task per worker), a hyper HTTP server, a background GC
//! sweep, and a Prometheus endpoint — with the L7 detector feeding bans into an nft set. All
//! request logic lives in `bf-udp` / `bf-http` (100% unit-tested); this file is the socket wiring
//! and is validated by the integration test in `tests/`, not the unit-coverage gate.

use bf_core::{ConnId, Store};
use bf_http::{HttpHandler, Response as HttpResponse};
use bf_l7::{Detector, Verdict};
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
    std::array::from_fn(|_| fastrand::u8(..))
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

/// Feed the L7 detector from the datagram and the handler's verdict on it.
fn feed_l7(sh: &Shared, req: &[u8], ip16: &[u8; 16], action: &Action, now_min: u32) -> Verdict {
    if matches!(action, Action::ConnidMismatch) {
        return sh.detector.on_connid_mismatch(ip16, now_min);
    }
    if let Ok(udp::Request::Announce(a)) = udp::parse(req) {
        return sh
            .detector
            .on_announce(ip16, a.info_hash, a.peer_id, now_min);
    }
    Verdict::Allow
}

/// Ban a source IP by adding it to the nft set over netlink (native, no process spawn).
fn ban(sh: &Shared, ip: IpAddr, duration: u32) {
    if sh.sink.ban(ip, duration).is_err() {
        sh.metrics.inc(Counter::NftError);
    }
}

fn record_udp_metric(metrics: &Metrics, req: &[u8], action: &Action) {
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
    match udp::parse(req) {
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
        let action = sh
            .udp
            .handle(&buf[..n], &ip16, is_v4, now, interval, &mut out);

        record_udp_metric(&sh.metrics, &buf[..n], &action);
        if sh.config.l7_enable {
            let now_min = u32::try_from(now / 60).unwrap_or(u32::MAX);
            if let Verdict::Ban { duration } = feed_l7(&sh, &buf[..n], &ip16, &action, now_min) {
                sh.metrics.inc(Counter::L7Ban);
                if sh.config.nft_enable {
                    ban(&sh, ip, duration);
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
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
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
        let mut term =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
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
