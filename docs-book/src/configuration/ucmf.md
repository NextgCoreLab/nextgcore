# UCMF Configuration

The UCMF (UE radio Capability Management Function, `nextgcore-ucmfd`) is the network side of RACS, radio capability signalling optimisation (TS 23.501 §5.4.4.1a / §6.2.21). It stores every UE Radio Capability ID mapping in the PLMN and assigns PLMN-assigned IDs. It serves:

- **`Nucmf_UECapabilityManagement`** (TS 29.673, URI apiName `nucmf-uecm`): Resolve (`GET /nucmf-uecm/v1/dic-entries`, `GET .../dic-entries/{dicEntryId}`), Assign (`POST .../dic-entries`), Subscribe / Unsubscribe (`POST .../subscriptions`, `DELETE .../subscriptions/{id}`), and Notify to the subscriber's `ucmfNotificationUri`.
- **`Nucmf_Provisioning`** (TS 29.675, `nucmf-provisioning`): create (`POST /nucmf-provisioning/v1/provisionings`), read, replace, update and delete (`GET`/`PUT`/`PATCH`/`DELETE .../provisionings/{id}`) manufacturer-assigned dictionary entries, as offered to the NEF.

Every dictionary entry is completed on creation (#585): the missing format is transcoded between TS 38.331 (NR) and TS 36.331 (E-UTRA) using the generated RRC codecs (`nextgcore-nr-rrc-gen`, `nextgcore-lte-rrc-gen`), and the UE Radio Capability for Paging of each format is derived. A format that cannot be derived stays absent and a request for it is answered `404 NO_DICTIONARY_ENTRY_FOUND`.

The UCMF registers with the NRF as `nfType: UCMF` with two services, `nucmf-uecapabilitymanagement` (allowed: AMF, MME, SCP) and `nucmf-provisioning` (allowed: NEF, SCP).

> **Honesty note:** UCMF behavior is validated by this project's own unit tests and the AMF-side RACS tests, not by third-party certification. Known gaps, stated in the source: deleting a provisioning notifies the deletion of the PLMN-assigned IDs it took with it, but TS 29.673 has no event for deleted manufacturer-assigned IDs, so those are not notified; `racsParamEps` / `racsParam5Gs` are taken as hexadecimal octet strings because the TS 29.122 OpenAPI gives them no format.

## Example configuration

From `docker/rust/configs/5gc/ucmf.yaml` (mounted by `docker-compose.yml`, which runs the daemon with `--sbi-addr 172.23.0.39 --sbi-port 7777 --nrf-uri http://172.23.0.10:7777`):

```yaml
logger:
  level: info

ucmf:
  nrf:
    uri: http://172.23.0.10:7777
  version_id: "01"
  mode: B
  purge_outdated_ids: false
  # state_file: /var/lib/nextgcore/ucmf.json
```

## YAML parameters

Parsed by `UcmfYaml` / `UcmfSection` in `src/bins/nextgcore-ucmfd/src/main.rs`. An invalid file fails startup.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `ucmf.nrf.uri` | string | `--nrf-uri` | NRF base URI. **Wins over `--nrf-uri`** when present. |
| `ucmf.version_id` | string, two hex digits | `"00"` | TS 23.003 §29.2 Version ID of the PLMN-assigned IDs this UCMF assigns. Changing it makes every older PLMN-assigned ID resolve as `OUT_DATED_VERSION_ID_IN_RAC_ID`, notified to subscribers. `--version-id` overrides it. |
| `ucmf.mode` | `A` or `B` | `B` | TS 23.501 §5.4.4.1a mode of operation. B (the RAN sends the TS 38.331 format only) is the only mode allowed when RACS is used in 5GS alone. `--mode` overrides it. |
| `ucmf.purge_outdated_ids` | bool | `false` | Delete PLMN-assigned IDs under older Version IDs at startup. |
| `ucmf.state_file` | path | unset | JSON snapshot of the dictionary, subscriptions and provisionings. Unset: memory only. `--state-file` overrides it. Written behind (#786): changes are flushed every 500 ms and at shutdown, not on every request, so a crash can lose up to the last 500 ms of changes. IDs are never reissued after such a crash: the snapshot reserves 1024 IDs of each kind ahead, written synchronously, so a restart continues above every ID handed out. |
| `ucmf.limits.max_dic_entries` | integer | `10000` | Most dictionary entries, assigned plus provisioned (#786). Past it Assign answers `500 INSUFFICIENT_RESOURCES` and Provisioning reports the RACS ID `OTHER_REASON`. |
| `ucmf.limits.max_subscriptions` | integer | `10000` | Most Nucmf_UECapabilityManagement subscriptions; past it Subscribe answers `500 INSUFFICIENT_RESOURCES`. |
| `ucmf.limits.max_subscriptions_per_consumer` | integer | `16` | Most subscriptions per consumer (its `nfId`, else the notification URI's `host:port`). |
| `ucmf.sbi.oauth2.require` | bool | `false` | Require an OAuth2 token on the SBI. `--oauth2-require` overrides it. |

`logger.level` is not read; use `-e/--log-level` or `RUST_LOG`.

## Command-line flags

| Flag | Type | Default | Description |
|---|---|---|---|
| `-c, --config` | path | `/etc/nextgcore/ucmf.yaml` | Configuration file path. |
| `-e, --log-level` | string | `info` | Log level; `RUST_LOG` overrides it. |
| `--sbi-addr` / `--sbi-port` | string / u16 | `0.0.0.0` / `7777` | SBI bind address and port. |
| `--tls`, `--tls-cert`, `--tls-key` | flag, path, path | off | TLS on the SBI listener. |
| `--nrf-uri` | string | `http://127.0.0.1:7777` | NRF base URI, used when the YAML names none. |
| `--version-id` | string | from YAML | Overrides `ucmf.version_id`. |
| `--mode` | `A`/`B` | from YAML | Overrides `ucmf.mode`. |
| `--state-file` | path | from YAML | Overrides `ucmf.state_file`. |
| `--oauth2-require` | bool | from YAML | Overrides `ucmf.sbi.oauth2.require`. |

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://jaeger:4317` | OpenTelemetry OTLP exporter. |
| `RUST_LOG` | unset | Overrides the log level. |

## How the AMF reaches it

`amfd` is the `Nucmf_UECapabilityManagement` consumer (`src/bins/nextgcore-amfd/src/racs.rs`, #570): it resolves and assigns IDs, subscribes to dictionary notifications, answers NGAP UE RADIO CAPABILITY ID MAPPING, acts on UE RADIO CAPABILITY INFO INDICATION, carries the UE Radio Capability ID (NGAP IE 264) in Initial Context Setup, Handover Request and Path Switch Request Acknowledge, and gives a RACS-capable UE its ID over NAS. It discovers the UCMF through the NRF; when none is discoverable it falls back to `UCMF_SBI_ADDR` / `UCMF_SBI_PORT` (port default `7777`) set on the AMF.
