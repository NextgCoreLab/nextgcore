# NextGCore Rust EPC Configuration Files

This directory contains configuration files for the NextGCore Rust EPC (Evolved Packet Core) Docker deployment.

## Network Functions

| NF | IP Address | Config | Description |
|----|------------|--------|-------------|
| MongoDB | 172.24.0.2 | — | Database for subscriber data |
| SGW-C | 172.24.0.3 | `sgwc.yaml` | Serving Gateway - Control Plane |
| PGW-C | 172.24.0.4 | `pgwc.yaml` | PDN Gateway - Control Plane. `nextgcore-smfd` in its PGW-C role (#380) |
| MME | 172.24.0.5 | `mme.yaml` | Mobility Management Entity |
| SGW-U | 172.24.0.6 | `sgwu.yaml` | Serving Gateway - User Plane |
| PGW-U | 172.24.0.7 | `pgwu.yaml` | PDN Gateway - User Plane. `nextgcore-upfd` in its PGW-U role (#380) |
| HSS | 172.24.0.8 | `hss.yaml` | Home Subscriber Server |
| PCRF | 172.24.0.9 | `pcrf.yaml` | Policy and Charging Rules Function |

This table documented the PGW-C and PGW-U addresses before either container
existed, and `mme.yaml`'s `gtpc.client.smf: 172.24.0.4` has pointed at nothing
since the file was written. Issue #380 declared the services at the addresses
already documented here, so the addressing is unchanged — what changed is that
something now answers on them.

### Why the PGW-C/PGW-U are the 5G binaries

TS 23.401 §4.2.1's single-gateway option permits a combined SGW/PGW node, and
TS 29.244 §5.2.6 is how that is realised with split CP/UP: a combined Sxa/Sxb
interface. `nextgcore-smfd` already terminates S5/S8 GTPv2-C and allocates the
PDN Address (a PGW function, TS 23.401 §5.3.2.1); `nextgcore-upfd` already speaks
PFCP and GTP-U. There is one image per binary, not one per role — the role is
which config file and which network a container gets.

They are **dedicated instances on the `epc` network**, not the 5GC's `smf`/`upf`
attached to a second network. `specs/epc-pgw-container.md` records the decision
and the rejected alternative; the short version is that the two Docker bridges
have no route between them, an S5-U F-TEID must carry an address the SGW-U can
reach (TS 29.274 §8.22), and TS 29.244 §6.2.6 scopes a PFCP association to one
CP/UP function pair — which `upfd` implements literally, as a single `Option`.

### Values that must agree across files

Each of these appears in more than one place, and a mismatch fails **silently**,
because GTP-U is unacknowledged:

| Value | Sites |
|---|---|
| PGW-C S5/S8 address | `pgwc.yaml` `smf.gtpc.server`; `SGWC_PGW_S5C` on the `sgwc` service; `mme.yaml` `gtpc.client.smf` |
| PGW-U PFCP address | `pgwc.yaml` `smf.pfcp.client.upf`; `UPF_PFCP_ADDR` on the `pgwc` service; `pgwu.yaml` `upf.pfcp.server`; `--pfcp-addr` on the `pgwu` service |
| UE address pool | `pgwc.yaml` `smf.session.subnet`; `pgwu.yaml` `upf.session.subnet`; `--tun-ip`/`--tun-prefix` on the `pgwu` service |

`upfd` takes its addresses from CLI **flags** and `smfd` takes its PFCP peers
from the **environment**, so `docker-compose-epc.yml` is authoritative for both.
The YAML states the same values because that is the file an operator reads first.

## Interfaces

### Control Plane
- **S1-MME**: eNB ↔ MME (SCTP, port 36412)
- **S6a**: MME ↔ HSS (Diameter)
- **S11**: MME ↔ SGW-C (GTP-C, port 2123)
- **S5/S8-C**: SGW-C ↔ PGW-C (GTP-C, port 2123 — TS 29.274 §4.1)
- **Sxa**: SGW-C ↔ SGW-U (PFCP, port 8805)
- **Sxb**: PGW-C ↔ PGW-U (PFCP, port 8805)
- **Gx**: PGW-C ↔ PCRF (Diameter). Declared for completeness: `smfd` carries Gx
  *state* (CCR/CCA fields in `gsm_sm.rs`) and no Gx transport, so the PGW-C
  serves sessions from its config-default policy. TS 23.401 does not require a
  PCRF for a PGW to serve a session.

### User Plane
- **S1-U**: eNB ↔ SGW-U (GTP-U, port 2152)
- **S5/S8-U**: SGW-U ↔ PGW-U (GTP-U, port 2152)
- **SGi**: PGW-U ↔ packet data network (via the `epctun` TUN device)

## PLMN Configuration

- MCC: 999
- MNC: 70
- TAC: 1

## freeDiameter Configuration

The `freeDiameter/` subdirectory contains Diameter protocol configuration for:
- `mme.conf` - MME Diameter configuration (S6a interface to HSS)
- `hss.conf` - HSS Diameter configuration (S6a interface to MME)
- `pcrf.conf` - PCRF Diameter configuration (Gx interface to PGW-C/SMF)

## Usage

```bash
# Start EPC deployment
docker compose -f docker-compose-epc.yml up -d

# View logs
docker compose -f docker-compose-epc.yml logs -f

# Stop deployment
docker compose -f docker-compose-epc.yml down
```
