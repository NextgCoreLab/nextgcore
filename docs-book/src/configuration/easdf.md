# EASDF Configuration

The EASDF (Edge Application Server Discovery Function, `nextgcore-easdfd`) performs DNS handling
for Edge Computing per TS 23.501 §6.2.31 and TS 23.548 §6.2.3.2. It registers with the NRF as
`nfType: EASDF` and serves two services — `neasdf-dnscontext` (the per-PDU-session DNS context an
SMF creates, TS 29.556) and `neasdf-baselinednspattern` (the EASDF-wide fallback patterns) — plus
edge DNS resolution over two transports:

- **over SBI**: `GET /neasdf-dnscontext/v1/dns-queries?fqdn=<name>[&dns-context-id=<id>]`, always
  available;
- **over UDP/53**: a real DNS listener, behind the `dns-udp` cargo feature and **off by default**.

> **Honesty note:** TS 29.556 is **not vendored** in this repository, so the `Neasdf_DNSContext`
> member names are not schema-checked against an OpenAPI file — they follow TS 23.548 §6.2.3.2.2's
> description and deliberately accept several spellings for the same thing (`domainNames` /
> `dnsQueryMdt` / `fqdnList`, `ueIpv4Address` / `ueIpAddress`, …). Anything unrecognised is
> preserved verbatim on the stored context, so nothing an SMF sends is lost. The DNS wire codec, by
> contrast, is checked against RFC 1035 and RFC 6891, which are normative and public.

## Off by default, twice over

Two independent switches, for two different reasons:

1. **The NF itself.** `nextgcore-easdfd` exits immediately unless `--enabled` or
   `easdf.enabled: true` is set. Edge computing is an optional deployment feature.
2. **The UDP listener.** Compiled only with `--features dns-udp`. Unlike everything else in this
   crate it binds a privileged port and changes the process's network posture, so it is opt-in at
   *build* time, not just at runtime. Without the feature the binary has no UDP socket at all and
   the `easdf.dns.udp_*` keys below are ignored.

## Example configuration

```yaml
easdf:
  enabled: true
  sbi:
    server:
      - address: 0.0.0.0
        port: 7818
    client:
      nrf:
        - uri: http://127.0.0.1:7777

  # Static FQDN -> EAS address map. `*.` is a subdomain wildcard: it matches
  # app.edge.example.com but NOT edge.example.com itself. Matching is
  # case-insensitive and ignores a trailing dot.
  eas_map:
    - fqdn: "*.edge.example.com"
      addresses: ["10.60.0.1", "2001:db8::60"]

  dns:
    # What to do with an FQDN no rule, no map entry and no baseline pattern
    # matched: "forward" (needs `upstream`) or "nxdomain" (default).
    miss_action: forward
    upstream: "10.10.0.53"

    # DNS/UDP listener (dns-udp feature only).
    udp_address: 0.0.0.0
    udp_port: 5353
```

## YAML parameters

| Key | Default | Effect |
|---|---|---|
| `easdf.enabled` | `false` | Start the NF. Also settable with `--enabled`. |
| `easdf.sbi.server[0].address` / `.port` | `0.0.0.0` / `7818` | SBI bind. Overrides `--sbi-addr` / `--sbi-port`. |
| `easdf.sbi.client.nrf[0].uri` | `http://127.0.0.1:7777` | NRF for registration and heartbeat. Overrides `--nrf-uri`. |
| `easdf.eas_map[].fqdn` / `.addresses` | *(empty)* | Static edge FQDN → EAS address map. |
| `easdf.dns.miss_action` | `nxdomain` | `forward` or `nxdomain`. `forward` without `upstream` warns and falls back to `nxdomain`. |
| `easdf.dns.upstream` | *(none)* | Upstream DNS server. Reported as `FORWARD` to SBI callers, and **dialled** by the UDP plane. |
| `easdf.dns.udp_address` | `0.0.0.0` | UDP listener bind address. `dns-udp` only; overrides `--dns-udp-addr`. |
| `easdf.dns.udp_port` | `53` | UDP listener port. `dns-udp` only; overrides `--dns-udp-port`. |

`upstream` accepts a bare IP address (port 53 assumed) or `address:port`. A **hostname is
refused**, with a warning: the EASDF would have to ask a resolver to find its own resolver.

## Command-line flags

`-c/--config` (default `/etc/nextgcore/easdf.yaml`), `-e/--log-level`, `-l/--log-file`,
`-m/--no-color`, `--sbi-addr`, `--sbi-port`, `--tls`/`--tls-cert`/`--tls-key`, `--nrf-uri`,
`--nf-instance-id`, `--enabled`, `--max-dns-contexts` (default 4096, and also the ceiling on stored
baseline patterns), and — with `dns-udp` — `--dns-udp-addr` and `--dns-udp-port`.

## Port 53 needs a capability

Binding UDP/53 requires `CAP_NET_BIND_SERVICE` or root. A **bind failure is fatal**: the operator
compiled the feature in and named the port, so starting without the listener would be an EASDF that
reports healthy and answers nothing.

For a container without the capability, set `udp_port` to an unprivileged port and redirect:

```yaml
# docker-compose
services:
  easdf:
    cap_add: ["NET_BIND_SERVICE"]   # …or drop this and use the redirect below
```

```sh
# host- or pod-side redirect when the capability is unavailable
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5353
```

## How a query is resolved

The same precedence for both transports, most specific first:

1. **The querying session's own DNS handling rules**, when the query can be attributed to a session.
2. **The static `eas_map`.**
3. **The baseline DNS patterns** (`neasdf-baselinednspattern`).
4. **The configured miss behaviour** — forward to `upstream`, or NXDOMAIN / `404 FQDN_NOT_FOUND`.

Attribution differs by transport, and this is the part worth understanding:

- Over **SBI**, the caller passes `dns-context-id` explicitly. A query without one is answered from
  step 2 onward — never from some other session's rules.
- Over **UDP**, a datagram carries no context id, so the query's **source address** is the only
  correlator. The SMF therefore sends the UE's address (`ueIpv4Address`) when it creates the DNS
  context, and the EASDF indexes it. A query from an address no context claims falls through to
  step 2.

If two live contexts claim one UE address, the **newer** wins and the collision is logged with both
context ids: an SMF assigns a UE address to one live session at a time, so a collision means the
older context's DELETE was lost.

**Not implemented:** `ueIpv6Prefix`. Matching a source address against a prefix is a different
operation from an exact lookup, and treating the network address as the UE's would answer for one
address out of 2^64. A context carrying only a prefix logs a warning and its sessions fall through
to the static map over UDP.

## What the UDP plane answers

| Query | Resolution | Answer |
|---|---|---|
| `A` / `AAAA` | edge-served, matching family | `NOERROR` + records, `AA` set, TTL 30s |
| `A` / `AAAA` | edge-served, no address of that family | `NOERROR`, no records (NODATA) — **not** NXDOMAIN |
| any other type (`MX`, `SVCB`, …) | edge-served | `NOERROR`, no records (NODATA) |
| any | miss, `upstream` configured | the upstream's own reply, relayed **verbatim** |
| any | miss, no upstream | `NXDOMAIN` |
| any | `upstream` configured but unreachable | `SERVFAIL` — never NXDOMAIN |
| class other than `IN`, or a non-`QUERY` opcode | — | `NOTIMP` |
| malformed, ID readable | — | `FORMERR` |
| malformed, too short to hold an ID | — | no reply |

NODATA rather than NXDOMAIN for a wrong-family or unserved type is deliberate: the name
demonstrably exists, and telling a dual-stack resolver it does not would stop it asking for the
other family too.

EDNS(0) is read and echoed: a response carries an `OPT` record only when the query did (RFC 6891
§6.1.1), and the requestor's advertised payload size sets the truncation ceiling (clamped to
512…4096). An answer set that does not fit is a `TC`-flagged prefix, never a silently short one.

The TTL on an EASDF-authored answer is **30 seconds**, deliberately short: an EAS address is a
steering decision the SMF may re-take on the next DNS message report, so a long-cached answer would
keep a UE pointed at an EAS the network has moved away from.

## DNS message reporting

A handling rule with `reportInd: true` causes the EASDF to POST a DNS-message report to the
context's notification URI (`notificationUri` on create) before answering the query — on both
transports. That is how the SMF learns the resolved EAS address and can drive UL-CL / PSA
re-selection. The report is awaited before the answer goes out, so the SMF is never told about an
address the UE already has. A failed report is logged and swallowed: the UE's DNS answer is not held
hostage to the SMF's reachability, and the EASDF has no retry queue.

## Not in the shipped deployment

The EASDF is not a service in `docker/rust/docker-compose.yml` and no `easdf.yaml` ships under
`docker/rust/configs/5gc/`, so nothing above is exercised by the docker E2E gate. The DNS codec, the
resolution precedence, the source-address scoping and the UDP listener are covered by the crate's
own tests (including a real socket round trip); the deployment surface is not.
