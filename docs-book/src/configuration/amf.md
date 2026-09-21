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

  # REGULATORY switch, default true. Read "Unauthenticated emergency service"
  # below before changing it: this key decides whether an emergency call
  # connects when the AUSF is unreachable, and the correct value is a matter of
  # local law, not of taste.
  emergency:
    allow_unauthenticated: true
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
| `emergency.allow_unauthenticated` | bool | **`true`** | Whether an EMERGENCY registration the network could not authenticate (e.g. the AUSF is unreachable) proceeds as an unauthenticated, emergency-only registration, or is refused. **This is a regulatory setting** — see [Unauthenticated emergency service](#unauthenticated-emergency-service) below. `AMF_EMERGENCY_ALLOW_UNAUTHENTICATED` overrides it. |

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
| `AMF_EMERGENCY_ALLOW_UNAUTHENTICATED` | Overrides `amf.emergency.allow_unauthenticated` (truthy: `1`/`true`/`yes`/`on`). Any other value — including an empty one — reads as **disabled** rather than falling back to the YAML or the default, so a typo in a regulatory setting fails visibly instead of silently reverting. |

## Behavior notes and caveats

- **Lenient loading:** a missing config file, YAML parse error, or missing `amf:` section logs a warning and starts the AMF with defaults — it does not abort. Typos in key names are therefore silently ignored; check the startup log lines (`Configured GUAMI: ...`, `AMF configuration loaded: N GUAMI, N TAI, N PLMN support`) to confirm what was actually applied.
- **PLMN flexibility:** `mcc`/`mnc` accept YAML strings or integers; a 2-digit MNC is encoded with the filler digit per standard PLMN encoding.
- **Empty security lists:** if `security` is omitted, the integrity/ciphering preference lists in the AMF context stay empty; supply explicit orders (as in the example) for deterministic algorithm selection.
- **Multiple NRF entries** in `sbi.client.nrf` are parsed but only the first is used — additional entries are currently inert.
- There is no `amf.sbi.server` bind-address key in the typed config; the SBI server and NGAP addresses are controlled by code defaults and the `--ngap-addr` flag, not this YAML file.

## Unauthenticated emergency service

> **Set this key deliberately.** `amf.emergency.allow_unauthenticated` decides whether an emergency call connects when the AMF cannot authenticate the caller. In some jurisdictions the answer is legally mandatory; in others the feature is forbidden. The shipped default is `true`, and it is not the right value everywhere.

### What the setting does

When a UE sends a REGISTRATION REQUEST whose 5GS registration type is **Emergency Registration** and the AMF **cannot obtain an authentication vector** — the AUSF is unreachable, or refuses the request — the AMF has two conformant options, and this key chooses between them.

**`true` (default): proceed unauthenticated.** The AMF continues the registration without authentication, per TS 33.501 §10.2.2.2 ("If the AMF cannot identify the subscriber, or cannot obtain authentication vector (when SUPI is provided), the AMF shall send NAS SMC with NULL algorithms to the UE"). Concretely:

- **NIA0 and NEA0 are forced**, not negotiated, regardless of the algorithms the UE advertised (TS 33.501 §6.7.3.6). **The session has no NAS integrity protection and no NAS ciphering.**
- K_AMF is generated **locally from the OS CSPRNG**, per TS 33.501 §10.2.2.3.1 ("the UE and the AMF independently generate the K_(AMF) in an implementation defined way"). The UE generates its own; the two never match, and nothing requires them to, because NIA0 computes no MAC and NEA0 enciphers nothing.
- **No UDM, PCF or NSACF interaction.** TS 23.502 §4.12.2.3: "if the UE was not successfully authenticated, the AMF shall not update the UDM ... the AMF shall not check for access restrictions, regional restrictions or subscription restrictions", and AM/UE policy "are not required for Emergency Registration". So no subscription is fetched and no SUPI is registered at the UECM.
- **No Allowed NSSAI** is sent in the Registration Accept (same clause).
- The Registration Accept reports the UE **Emergency registered** (TS 24.501 §9.11.3.6 octet 3 bit 6).
- **Only the emergency DNN is reachable.** A PDU session request on any other DNN is refused with 5GMM/5GSM cause #29, per TS 23.501 §5.16.4.9a ("the network shall reject any PDU Session Establishment request for normal service from the UE on this Access Type").
- The UE security capabilities conveyed to the gNB are **narrowed to the null set** (TS 33.501 §6.7.3.6).

**`false`: refuse.** The registration is rejected and the UE released, exactly as an ordinary registration with an unreachable AUSF would be. Set this where local regulation forbids unauthenticated emergency service — TS 33.501 §5.1.2: "Serving networks located in regions where unauthenticated emergency services are forbidden shall not support this feature."

### Why the default is `true`

TS 33.501 §5.1.2 imposes two obligations pointing opposite ways: the 5G system "shall support unauthenticated access for emergency services ... only to those serving networks where regulatory requirements for unauthenticated emergency services exist", and networks where it is forbidden "shall not support this feature". A shipped default must pick one, and the two are not symmetric:

- An operator deploying into a **forbidding** jurisdiction knows that fact and can set the key. The spec expects this: TS 33.501 §10.2.2.2 says "It shall be possible to configure whether the network allows or rejects an emergency registration request".
- A default of `false` would make the software non-conformant out of the box in every jurisdiction where unauthenticated emergency calling is mandatory — and it fails in the direction where the failure is a caller who cannot reach a PSAP.

The worst case under `true` is an unauthenticated device obtaining an emergency-only, null-ciphered, single-DNN, no-subscription session — which is precisely the fenced session TS 33.501 §10.2.2 and TS 23.501 §5.16.4.9a specify for this case. The worst case under `false` is an emergency call that does not connect. The full argument, with the rejected alternatives, is in `specs/decide-unauthenticated-emergency-registration.md`.

### Operational notes

- Every unauthenticated emergency registration logs at **`warn`**, twice: once when the AMF decides to continue without authentication, and once when it sends the Security Mode Command with NULL algorithms. A refusal under `false` also logs at `warn`, naming the setting. Neither case is silent.
- The setting is read **once at startup**. Changing it requires an AMF restart.
- An emergency registration that **does** authenticate successfully is unaffected by this key: it keeps a real key hierarchy, a real SUPI, its UDM subscription and a non-NULL integrity algorithm. It is still reported "Emergency registered" and still restricted to the emergency DNN, because that restriction follows from the registration type rather than from the authentication outcome.

### Current limitations

- **Authentication *failure* is still refused, regardless of this setting.** Only the *inability to obtain* a vector takes the unauthenticated path. A UE that answers with 5GMM cause #20 (MAC failure), or an AUSF that answers `AUTHENTICATION_FAILURE`, is refused. TS 33.501 §10.2.2.2 would permit NULL algorithms there too; it is not yet implemented.
- **No PEI-only (UICC-less) registration.** TS 33.501 §10.2.2.1 behaviour (b) admits UEs presenting only a PEI. This AMF's registration parser accepts SUCI and 5G-GUTI identities only, so a credential-less UE is refused before the emergency path is reached. This implements §10.2.2.1 behaviour **(a)**, "IMSI required, authentication optional", and not (b).
- **No IMS leg.** The emergency PDU session is established on the emergency DNN and a P-CSCF address is configurable, but there is no IMS core in this tree, so no SIP INVITE reaches a PSAP.
- **The EPC/MME path is unchanged.** An emergency *attach* over S1 (`nextgcore-mmed`) is recognised and recorded but follows the normal authentication path; see `specs/fix-mmed-attach-tau-accept-correctness.md`.
