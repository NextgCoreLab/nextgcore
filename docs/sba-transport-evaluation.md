# SBA Transport Evaluation: HTTP/2 vs HTTP/3 (QUIC)

> **Non-normative 6G research.** 3GPP TS 29.500 mandates HTTP/2 + JSON as the
> SBI transport; there is **no frozen Rel-20/6G Stage-3 specification** for any
> alternate transport. Nothing here is a conformance target, and no NF binary
> uses the HTTP/3 prototype. Tracking issue:
> [#15](https://github.com/NextgCoreLab/nextgcore/issues/15).

## What was built

- A criterion benchmark harness, `libs/nextgcore-sbi/benches/transport.rs`,
  measuring a warm GET round-trip (one reused connection, new stream per
  request) through the real `SbiClient` → `SbiServer` stack on loopback.
- A feature-gated HTTP/3-over-QUIC prototype, `libs/nextgcore-sbi/src/http3.rs`
  (`--features http3`, off by default), built on `h3` + `quinn`. It drives the
  same `SbiRequestHandler` the HTTP/2 server drives and returns the same
  `SbiResponse` shape the HTTP/2 client returns; a feature-gated test proves
  the response body is byte-identical across both transports for the same
  request against the same handler.

Run it:

```bash
cargo bench -p nextgcore-sbi                    # HTTP/2 baselines
cargo bench -p nextgcore-sbi --features http3   # + HTTP/3 rows
cargo test  -p nextgcore-sbi --features http3   # byte-parity test
```

## Results

Warm round-trip latency (criterion median, loopback, Apple Silicon macOS,
default `bench` profile). Fixed ASCII JSON body served by the identical
handler; the measured path includes the real per-request client costs
(traceparent stamping, timeout wrappers, header/body conversion).

| Transport | 256 B body | 16 KiB body |
|-----------|-----------:|------------:|
| HTTP/2 h2c (production path) | 38.7 µs | 49.7 µs |
| HTTP/2 over TLS 1.2/1.3      | 37.9 µs | 54.7 µs |
| HTTP/3 over QUIC (prototype) | 44.1 µs | 93.7 µs |

Observations:

- **TLS is free per-request on HTTP/2** — h2c and h2-tls are within noise at
  256 B; the handshake cost is per-connection and NFs hold connections open.
- **HTTP/3 pays a per-request and per-byte penalty on loopback**: ~16% slower
  than h2-tls for small bodies (~14% vs h2c), ~71% for 16 KiB. This is expected: quinn runs
  QUIC (packetization, encryption per packet, ACK bookkeeping) in userspace
  over UDP sockets, while the HTTP/2 path rides the kernel TCP stack.
- **Loopback is the most hostile venue for QUIC**: zero loss and zero RTT hide
  exactly the properties HTTP/3 exists for (no TCP head-of-line blocking under
  loss, connection migration, 1-RTT/0-RTT setup). A meaningful evaluation
  needs an emulated lossy/high-RTT link and concurrent multiplexed streams —
  explicitly out of scope for this bounded spike.

## Dependency and build footprint

- Default build is untouched: `cargo tree -p nextgcore-sbi -e normal` shows
  **zero** new dependencies; the `http3` deps are `optional = true` and
  crate-local (workspace root unchanged).
- `--features http3` adds 16 crates to the build (`h3`, `h3-quinn`, `quinn`,
  `quinn-proto`, `quinn-udp`, `lru-slab`, `chacha20`, the `futures` family
  and other small transitive crates). `criterion` and its ~25-crate tree are dev-dependencies, compiled
  only for `cargo bench`/`cargo test` of this crate.
- CI runs default features only, so neither the prototype nor its deps are
  compiled in the fast gate; `--features http3` builds/tests must be run
  manually.

## TLS / certificate story

- QUIC has **no plaintext mode** (RFC 9001 mandates TLS 1.3, ALPN `h3`), so
  the h2c deployment style used inside trusted zones today has no HTTP/3
  equivalent — adopting HTTP/3 SBI means PKI everywhere.
- The prototype takes DER cert/key directly (tests generate them with
  `rcgen`); the HTTP/2 `SbiServer` takes PEM file paths. Unifying this needs
  an in-memory TLS-material API on `SbiServerConfig` first.
- The N32/SEPP RFC 5705 exporter-key extraction wired into the HTTP/2 TLS
  path (`tls::export_n32_master_key`) is **not** wired for QUIC; rustls
  exposes an exporter on QUIC connections, but SEPP-over-HTTP/3 would need
  its own plumbing and a spec basis that does not exist yet.

## Recommendation

Keep HTTP/2 as the only SBI transport. The prototype stays feature-gated and
off by default; the new dependencies are not worth carrying in default builds
for a transport with no 3GPP basis and no loopback win. Revisit only if (a)
3GPP SBA evolution work produces a concrete HTTP/3/QUIC direction, and (b) a
follow-up benchmark under emulated WAN impairments (loss, RTT, many concurrent
streams) shows a material advantage for NF-to-NF traffic patterns. gRPC was
deliberately not prototyped — it has only inert type stubs in-tree
(`nextgcore-sbi/src/grpc.rs`) and a different message model; that comparison
would be a separate spike.
