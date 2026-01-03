# NextGCore Rust 5G Core Configuration

This directory contains configuration files for the 5G Core network functions.

## Network Functions

| NF | IP Address | SBI Port | Other Ports | Description |
|----|------------|----------|-------------|-------------|
| NRF | 172.23.0.10 | 7777 | - | Network Repository Function |
| AUSF | 172.23.0.11 | 7777 | - | Authentication Server Function |
| UDM | 172.23.0.12 | 7777 | - | Unified Data Management |
| UDR | 172.23.0.20 | 7777 | - | Unified Data Repository |
| PCF | 172.23.0.13 | 7777 | 9090 (metrics) | Policy Control Function |
| NSSF | 172.23.0.14 | 7777 | - | Network Slice Selection Function |
| BSF | 172.23.0.15 | 7777 | - | Binding Support Function |
| AMF | 172.23.0.5 | 7777 | 38412/sctp (NGAP), 9090 (metrics) | Access and Mobility Management |
| SMF | 172.23.0.4 | 7777 | 8805/udp (PFCP), 9090 (metrics) | Session Management Function |
| UPF | 172.23.0.7 | - | 2152/udp (GTP-U), 9090 (metrics) | User Plane Function |

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
# Start 5G Core
cd docker/rust
docker-compose -f docker-compose-5gc.yml up -d

# View logs
docker-compose -f docker-compose-5gc.yml logs -f

# Stop 5G Core
docker-compose -f docker-compose-5gc.yml down

# Stop and remove volumes
docker-compose -f docker-compose-5gc.yml down -v
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
- AMF NGAP: `172.23.0.5:38412` (SCTP)

## Adding Subscribers

Use the NextGCore WebUI or directly insert into MongoDB:

```bash
# Connect to MongoDB
docker exec -it nextgcore-5gc-mongodb mongosh nextgcore

# Example subscriber (IMSI: 999700000000001)
db.subscribers.insertOne({
  "imsi": "999700000000001",
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
