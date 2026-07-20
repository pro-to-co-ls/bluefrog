# bluefrog

[![CI](https://github.com/pro-to-co-ls/bluefrog/actions/workflows/ci.yml/badge.svg)](https://github.com/pro-to-co-ls/bluefrog/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/pro-to-co-ls/bluefrog/badge.svg?branch=main)](https://coveralls.io/github/pro-to-co-ls/bluefrog?branch=main)

A fast, small BitTorrent tracker written in Rust.

## Features

- **UDP tracker** (BEP-15): connect / announce / scrape, IPv4 and IPv6, compact peer lists.
- **HTTP tracker**: announce / scrape, plus a `GET /` redirect.
- **In-memory sharded peer store** with background expiry — no persistence required.
- **Time-windowed connection IDs** (keyed BLAKE3) on the UDP path.
- **Behavioural client checks (L7)**: flags misbehaving clients (re-announce rate,
  connection-id failures, peer-id checks) and can add them to an auto-expiring nftables set.
- **Prometheus metrics** endpoint.
- Single static binary; a systemd unit (`deploy/`) and a sample config are included.

## Build & run

```bash
cargo build --release            # → target/release/bluefrog
bluefrog /etc/bluefrog/bluefrog.conf
```

See [`bluefrog.conf.sample`](./bluefrog.conf.sample) for configuration.

## Development

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo llvm-cov --workspace --fail-under-lines 100   # requires cargo-llvm-cov
```

The toolchain is pinned by `rust-toolchain.toml` (Rust 1.97.1). The library crates are kept at
100% line coverage; the runtime binary is validated by an integration test.

## License

GPL-3.0-or-later — see [`LICENSE`](./LICENSE).
