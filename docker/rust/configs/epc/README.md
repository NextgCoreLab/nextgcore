# NextGCore Rust EPC Configuration Files

This directory contains configuration files for the NextGCore Rust EPC (Evolved Packet Core) Docker deployment.

## Network Functions

| NF | IP Address | Description |
|----|------------|-------------|
| MongoDB | 172.24.0.2 | Database for subscriber data |
| SGW-C | 172.24.0.3 | Serving Gateway - Control Plane |
| SMF/PGW-C | 172.24.0.4 | Session Management Function / PDN Gateway - Control Plane |
| MME | 172.24.0.5 | Mobility Management Entity |
| SGW-U | 172.24.0.6 | Serving Gateway - User Plane |
| UPF/PGW-U | 172.24.0.7 | User Plane Function / PDN Gateway - User Plane |
| HSS | 172.24.0.8 | Home Subscriber Server |
| PCRF | 172.24.0.9 | Policy and Charging Rules Function |

## Interfaces

### Control Plane
- **S1-MME**: eNB ↔ MME (SCTP, port 36412)
- **S6a**: MME ↔ HSS (Diameter)
- **S11**: MME ↔ SGW-C (GTP-C, port 2123)
- **S5/S8-C**: SGW-C ↔ PGW-C (GTP-C)
- **Sxa**: SGW-C ↔ SGW-U (PFCP, port 8805)
- **Gx**: PGW-C ↔ PCRF (Diameter)

### User Plane
- **S1-U**: eNB ↔ SGW-U (GTP-U, port 2152)
- **S5/S8-U**: SGW-U ↔ PGW-U (GTP-U)

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
