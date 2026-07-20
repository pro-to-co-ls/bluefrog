//! End-to-end integration test: spawn the real `bluefrog` daemon and do a BEP-15 connect +
//! announce round-trip over a real UDP socket. Validates the socket wiring the unit tests can't.

use std::net::UdpSocket;
use std::process::{Child, Command};
use std::time::Duration;

const PROTOCOL_ID: u64 = 0x0000_0417_2710_1980;

struct Daemon {
    child: Child,
    port: u16,
    _cfg: std::path::PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self._cfg);
    }
}

fn spawn_daemon() -> Daemon {
    // grab a free UDP port, then let the daemon rebind it (SO_REUSEPORT)
    let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let cfg = std::env::temp_dir().join(format!("bluefrog-it-{port}.conf"));
    std::fs::write(&cfg, format!("listen.udp 127.0.0.1:{port}\nl7.enable 1\n")).unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_bluefrog"))
        .arg(&cfg)
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(700)); // let it bind
    Daemon {
        child,
        port,
        _cfg: cfg,
    }
}

fn connect(client: &UdpSocket, port: u16, txid: u32) -> u64 {
    let mut pkt = [0u8; 16];
    pkt[0..8].copy_from_slice(&PROTOCOL_ID.to_be_bytes());
    pkt[12..16].copy_from_slice(&txid.to_be_bytes());
    client.send_to(&pkt, ("127.0.0.1", port)).unwrap();
    let mut resp = [0u8; 64];
    let n = client.recv(&mut resp).unwrap();
    assert_eq!(n, 16);
    assert_eq!(&resp[0..4], &0u32.to_be_bytes(), "connect action");
    assert_eq!(&resp[4..8], &txid.to_be_bytes(), "echoed txid");
    u64::from_be_bytes(resp[8..16].try_into().unwrap())
}

#[test]
fn connect_and_announce_end_to_end() {
    let d = spawn_daemon();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();

    // 1) connect handshake yields a connection id
    let cid = connect(&client, d.port, 0xabcd_1234);

    // 2) announce with that connection id gets an announce reply naming us as the seeder
    let mut pkt = vec![0u8; 98];
    pkt[0..8].copy_from_slice(&cid.to_be_bytes());
    pkt[8..12].copy_from_slice(&1u32.to_be_bytes()); // action announce
    pkt[12..16].copy_from_slice(&0x1111_2222u32.to_be_bytes()); // txid
    pkt[16..36].copy_from_slice(&[0x33u8; 20]); // info_hash
    // left = 0 (seeder), num_want = -1, port = 6881
    pkt[92..96].copy_from_slice(&(-1i32).to_be_bytes());
    pkt[96..98].copy_from_slice(&6881u16.to_be_bytes());
    client.send_to(&pkt, ("127.0.0.1", d.port)).unwrap();

    let mut resp = [0u8; 256];
    let n = client.recv(&mut resp).unwrap();
    assert!(n >= 20, "announce reply header");
    assert_eq!(&resp[0..4], &1u32.to_be_bytes(), "announce action");
    assert_eq!(&resp[4..8], &0x1111_2222u32.to_be_bytes(), "echoed txid");
    assert_eq!(&resp[16..20], &1u32.to_be_bytes(), "one seeder");
}
