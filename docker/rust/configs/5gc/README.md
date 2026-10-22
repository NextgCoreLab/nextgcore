# NextGCore Rust 5G Core Configuration

This directory contains configuration files for the 5G Core network functions.

## Network Functions

Addresses and ports as `docker-compose.yml` runs them (`ipv4_address`, `command`
and the files here).

| NF | IP Address | SBI Port | Other Ports | Description |
|----|------------|----------|-------------|-------------|
| NRF | 172.23.0.10 | 7777 | - | Network Repository Function |
| AUSF | 172.23.0.11 | 7777 | - | Authentication Server Function |
| UDM | 172.23.0.12 | 7777 | - | Unified Data Management |
| UDR | 172.23.0.20 | 7777 | - | Unified Data Repository |
| PCF | 172.23.0.13 | 7777 | 9090 (metrics) | Policy Control Function |
| NSSF | 172.23.0.14 | 7777 | - | Network Slice Selection Function |
| BSF | 172.23.0.15 | 7777 | - | Binding Support Function |
| AMF | 172.23.0.5 | 7777 | 38412 (NGAP, SCTP over UDP by default), 9090 (metrics) | Access and Mobility Management |
| SMF | 172.23.0.4 | 7777 | 8805/udp (PFCP), 9090 (metrics) | Session Management Function |
| UPF | 172.23.0.7 | - | 2152/udp (GTP-U), 8805/udp (PFCP), 9090 (metrics) | User Plane Function |
| NWDAF | 172.23.0.30 | 7777 | - | Network Data Analytics Function |
| EES | 172.23.0.31 | 7777 | - | Edge Enabler Server |
| LMF | 172.23.0.32 | 7777 | - | Location Management Function |
| MB-SMF | 172.23.0.33 | 7777 | - | MBS Session Management Function |
| NSACF | 172.23.0.34 | 7777 | - | Network Slice Admission Control Function |
| PIN | 172.23.0.35 | 7815 | - | Personal IoT Network server |
| DCCF | 172.23.0.36 | 7777 | - | Data Collection Coordination Function |
| SCP | 172.23.0.37 | 7777 | - | Service Communication Proxy (`../scp.yaml`) |
| SEPP | 172.23.0.38 | 7777 | - | Security Edge Protection Proxy (`../sepp1.yaml`) |
| UCMF | 172.23.0.39 | 7777 | - | UE radio Capability Management Function (RACS) |

## Infrastructure

| Service | IP Address | Port | Description |
|---------|------------|------|-------------|
| MongoDB | 172.23.0.2 | 27017 | Subscriber database |

## Network Configuration

- Network: `172.23.0.0/24`
- Gateway: `172.23.0.1`
- UE IP Pool: `10.45.0.0/16` (IPv4), `2001:db8:cafe::/48` (IPv6)

## PLMN Configuration

- MCC: 999
- MNC: 70
- TAC: 1
- S-NSSAI: SST=1

## Usage

```bash
# Start the 5G Core (plus the nextgsim gNB/UE and observability)
cd docker/rust
docker compose up -d

# View logs
docker compose logs -f amf smf upf

# Stop, and remove volumes
docker compose down -v
```

## Home Network Keys (UDM)

For SUPI concealment, generate home network keys:

```bash
# Generate X25519 key (scheme 1)
openssl genpkey -algorithm X25519 -out hnet/curve25519-1.key

# Generate secp256r1 key (scheme 2)
openssl ecparam -name prime256v1 -genkey -conv_form compressed -out hnet/secp256r1-2.key
```

## Connecting a gNB

Configure your gNB to connect to:
- AMF NGAP: `172.23.0.5:38412`. The default transport is SCTP over UDP
  (`sctp-proto`), which nextgsim's gNB speaks. A standard RAN needs native
  kernel SCTP: run the AMF with `--sctp-backend kernel` (binary built with
  `--features kernel-sctp`), as `docker-compose.kernel-sctp.yml` does.

## Adding Subscribers

Use the NextGCore WebUI or directly insert into MongoDB:

```bash
# Connect to MongoDB
docker exec -it nextgcore-mongodb mongosh nextgcore

# The stack already seeds IMSI 999700000000001 from
# docs/assets/webui/mongo-init.js. A further subscriber looks like this:
db.subscribers.insertOne({
  "imsi": "999700000000002",
  "msisdn": [],
  "imeisv": [],
  "mme_host": [],
  "mme_realm": [],
  "purge_flag": [],
  "security": {
    "k": "465B5CE8B199B49FAA5F0A2EE238A6BC",
    "amf": "8000",
    "op": null,
    "opc": "E8ED289DEBA952E4283B54E88E6183CA"
  },
  "ambr": {
    "downlink": {"value": 1, "unit": 3},
    "uplink": {"value": 1, "unit": 3}
  },
  "slice": [{
    "sst": 1,
    "default_indicator": true,
    "session": [{
      "name": "internet",
      "type": 3,
      "ambr": {
        "downlink": {"value": 1, "unit": 3},
        "uplink": {"value": 1, "unit": 3}
      },
      "qos": {
        "index": 9,
        "arp": {
          "priority_level": 8,
          "pre_emption_capability": 1,
          "pre_emption_vulnerability": 1
        }
      }
    }]
  }]
})
```
