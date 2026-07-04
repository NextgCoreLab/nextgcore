# AMF Configuration

`nextgcore-amfd` (Access and Mobility Management Function) reads a single YAML file, `/etc/nextgcore/amf.yaml` by default (override with `-c/--config`). Configuration is intentionally forgiving: every field is `Option`al in the typed config structs, and a missing/unreadable/unparsable file or missing `amf:` section logs a warning and continues with built-in defaults rather than failing startup.

> **Honesty note:** this configuration surface has been validated against matched nextgsim peers and in-process strict-peer tests; it is not third-party certified for 3GPP conformance.

## Example (`configs/amf.yaml`)

```yaml
# NextGCore AMF Configuration
# PLMN 999-70, TAC 1, S-NSSAI SST=1

amf:
  amf_name: "NextGCore AMF"

  guami:
    - plmn_id:
        mcc: "999"
        mnc: "70"
      amf_id:
        region: 1
        set: 1
        pointer: 1

  tai:
    - plmn_id:
        mcc: "999"
        mnc: "70"
      tac: 1

  plmn_support:
    - plmn_id:
        mcc: "999"
        mnc: "70"
      s_nssai:
        - sst: 1

  security:
    integrity_order: ["NIA2", "NIA1", "NIA0"]
    ciphering_order: ["NEA2", "NEA1", "NEA0"]
```

## Parameters

All keys live under the top-level `amf:` section. Types and defaults below come from the `#[derive(Deserialize)]` structs and the `load_config` logic in `src/bins/nextgcore-amfd/src/lib.rs`.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `amf_name` | string | none | Human-readable AMF name, stored in the AMF context and logged at startup. |
| `network_name.full` | string | empty (`NetworkName::default()`) | Full network name presented to UEs. |
| `network_name.short` | string | empty | Short network name presented to UEs. |
| `guami` | list | empty list | Served GUAMI list. Entries without a resolvable `plmn_id` are silently skipped. |
| `guami[].plmn_id.mcc` / `.mnc` | string or int | required per entry | PLMN identity; accepts quoted strings (`"999"`) or bare integers — both are normalized. |
| `guami[].amf_id.region` | u8 | `0` | AMF Region ID. |
| `guami[].amf_id.set` | u16 | `0` | AMF Set ID. |
| `guami[].amf_id.pointer` | u8 | `0` | AMF Pointer. |
| `tai` | list | empty list | Served TAI list. |
| `tai[].plmn_id` | object | required per entry | PLMN identity (same string-or-int handling as GUAMI). |
| `tai[].tac` | u32 | `0` | Tracking Area Code for this TAI (single TAC per entry, stored as a TAI list-0). |
| `plmn_support` | list | empty list | Supported PLMN + slice list. |
| `plmn_support[].plmn_id` | object | required per entry | Supported PLMN identity. |
| `plmn_support[].s_nssai` | list | empty list | Slices for the PLMN. |
| `plmn_support[].s_nssai[].sst` | u8 | `1` | Slice/Service Type. |
| `plmn_support[].s_nssai[].sd` | u32 | none | Slice Differentiator (optional; omitted = no SD). |
| `security.integrity_order` | list of strings | empty list | NAS integrity preference order. Recognized: `NIA0`–`NIA3` (with or without `128-` prefix); unknown names fall back to `0` (NIA0). |
| `security.ciphering_order` | list of strings | empty list | NAS ciphering preference order. Recognized: `NEA0`–`NEA3`; unknown names fall back to `0` (NEA0). |
| `sbi.client.nrf` | list of `{uri}` | none | NRF client endpoints. Only the **first** entry's `uri` is used, seeded into the SBI context for NF registration. |
| `sbi.oauth2.require` | bool | `false` | Opt-in SBI OAuth2 enforcement (producer token verification + outbound Bearer-token attach; code comments cite TS 33.501 §13.4.1, TS 29.510 §5.4.2). Parsed root-key-agnostically: true if any top-level section sets it. `NEXTGCORE_SBI_OAUTH2_REQUIRE` env var takes precedence. With enforcement on but no NRF URI configured, the server fails closed (503). |
| `nas.use_nextgcore_security` | bool | `false` | NAS-security canary knob. Default off keeps the legacy byte-for-byte NAS path. The `AMF_NAS_SECURITY` env var overrides this YAML value. |

## Command-line flags

The binary also takes flags that are not part of the YAML file:

| Flag | Default | Description |
|---|---|---|
| `-c, --config` | `/etc/nextgcore/amf.yaml` | Configuration file path. |
| `-l, --log-level` | `info` | `trace`, `debug`, `info`, `warn`, `error`. |
| `--ngap-addr` | `0.0.0.0:38412` | NGAP (N2) bind address. |
| `--sctp-backend` | `userspace` | `userspace` (sctp-proto over UDP, matched nextgsim gNB) or `kernel` (Linux kernel SCTP for an external RAN; requires the `kernel-sctp` build feature and libsctp). |
| `--no-color` | off | Disable colored log output. |
| `-d, --daemon` | off | Run in daemon mode. |

## Environment overrides

| Variable | Effect |
|---|---|
| `AMF_NAS_SECURITY` | Overrides `amf.nas.use_nextgcore_security` (truthy: `1`/`true`/`yes`). |
| `NEXTGCORE_SBI_OAUTH2_REQUIRE` | Overrides `sbi.oauth2.require` (truthy: `1`/`true`/`TRUE`/`yes`); useful for docker overlays without editing the YAML. |

## Behavior notes and caveats

- **Lenient loading:** a missing config file, YAML parse error, or missing `amf:` section logs a warning and starts the AMF with defaults — it does not abort. Typos in key names are therefore silently ignored; check the startup log lines (`Configured GUAMI: ...`, `AMF configuration loaded: N GUAMI, N TAI, N PLMN support`) to confirm what was actually applied.
- **PLMN flexibility:** `mcc`/`mnc` accept YAML strings or integers; a 2-digit MNC is encoded with the filler digit per standard PLMN encoding.
- **Empty security lists:** if `security` is omitted, the integrity/ciphering preference lists in the AMF context stay empty; supply explicit orders (as in the example) for deterministic algorithm selection.
- **Multiple NRF entries** in `sbi.client.nrf` are parsed but only the first is used — additional entries are currently inert.
- There is no `amf.sbi.server` bind-address key in the typed config; the SBI server and NGAP addresses are controlled by code defaults and the `--ngap-addr` flag, not this YAML file.
