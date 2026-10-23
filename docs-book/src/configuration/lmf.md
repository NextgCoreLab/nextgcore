# LMF Configuration

The LMF (Location Management Function, `nextgcore-lmfd`) computes UE position fixes for the 5G core, per TS 23.273 (as cited in the daemon's source comments). It serves the `Nlmf_Location` service under the apiName `nlmf-loc` (TS 29.572 §6.1.1 per code comments): `POST /nlmf-loc/v1/determine-location` (§6.1.4.2), the custom operations `cancel-location`, `location-context-transfer`, `measure-location`, `configure-up`, and `up-subscriptions` (§6.1.4 per code comments), plus a `GET /nlmf-loc/v1/capabilities` query. It also serves two Namf_Communication notify callbacks — `POST /nlmf-loc/v1/notify/n1` and `/notify/n2` (TS 29.518 §5.2.2.4 N1MessageNotify / §5.2.2.3.3 N2InfoNotify per code comments) — which complete pending positioning sessions from uplink LPP/NRPPa reports. For deferred PERIODIC location requests the LMF acts as an outbound EventNotify producer, POSTing `EventNotifyDataExt` to the request's `hgmlcCallBackURI` (TS 29.572 §6.1.5.1 per code comments); UPNotify (§6.1.5.2) is deferred. It also serves `Nlmf_Broadcast` (`POST /nlmf-broadcast/v1/cipher-key-data`) and `Nlmf_DataExposure` (`/nlmf-dataexposure/v1/subscriptions`, #104). LPP and NRPPa are encoded and decoded by the codecs generated from the 3GPP ASN.1 (`nextgcore-lpp-gen`, TS 37.355; `nextgcore-nrppa-gen`, TS 38.455; #515); the hand-written codecs were removed (#527, #563). An uplink LPP carrying a sidelink ranging report in an EPDU (TS 37.355 §6.5.7) is decoded and stored for the UE (#559). Six additional ingest routes (`measurements`, `nrppa-reports`, `nrppa-binary-reports`, `lpp-binary-reports`, `ue-locations/{supi}`) are explicitly marked in the source as **not** TS 29.572 resources and are gated behind `--debug-endpoints` (default off).

Configuration is split between a YAML file (default path `/etc/nextgcore/lmf.yaml`, overridable with `-c/--config`), command-line flags, and two environment variables. Unusually for this project, the LMF reads almost nothing from YAML: the file is probed exactly once, for the OAuth2 knob. Bind address/port, TLS, the NRF URI, the measurement-pool cap, and the debug-route gate are all CLI flags.

> **Honesty note:** LMF behavior is validated by this project's own unit tests and matched-simulator Docker E2E only — not third-party conformance certification (positioning is not on the matched-sim registration+PDU+ping path, so E2E coverage of these flows is limited). The six `--debug-endpoints` ingest routes and the `capabilities` endpoint are bespoke NextGCore extensions, not TS 29.572 resources. UPNotify and area/motion-event triggered LDR are not implemented (scoped out per code comments).

## Example configuration

From `nextgcore/docker/rust/configs/5gc/lmf.yaml`:

```yaml
# LMF (Location Management Function) Configuration
logger:
  level: info

lmf:
  sbi:
    server:
      - address: 0.0.0.0
        advertise: 172.23.0.32
        port: 7777
  nrf:
    uri: http://172.23.0.10:7777
```

## YAML parameters

The LMF defines **no** `#[derive(Deserialize)]` configuration structs. The only read of the config file is the `oauth2_required()` function in `src/bins/nextgcore-lmfd/src/main.rs`, which parses the file as an untyped `serde_yaml::Value` and probes one path (the `Deserialize` structs in `nlmf.rs` are SBI message payloads, not configuration).

| Parameter | Type | Default | Description |
|---|---|---|---|
| `lmf.positioning.cells[]` | list | absent | **Serving-cell reference coordinates (#103).** Each entry is `{ id, lat, lon, height? }`. `id` is the key measurement reports use (an NR-CGI, a `pci-<n>`, a TRP id) and is not interpreted — it must match what the RAN reports. `height` is optional (metres above the WGS-84 ellipsoid, default 0; the 2-D solvers do not read it). See *Positioning reference points* below. |
| `lmf.positioning.trps[]` | list | absent | **TRP reference points (#103).** Same shape as `cells`. A separate list because TS 38.455 §8.2.6 makes TRP information its own exchange and an operator provisioning one is not necessarily provisioning the other; both lists land in the same registry the solvers read. |
| `lmf.sbi.oauth2.require` | bool | `false` | SBI OAuth2 bearer-token enforcement (TS 33.501 §13.4.1, TS 29.510 §5.4.2 per code comments). The probe is root-key agnostic: it is `true` iff **any** top-level YAML section carries `sbi.oauth2.require: true`. When enabled, incoming requests must carry an NRF-issued token whose audience includes `LMF` (verified against the NRF JWKS; with no NRF URI configured the server fails closed with 503, per the code comment referencing `nextgcore-sbi` server.rs), and outbound SBI calls attach tokens. An unreadable or unparseable file, or an absent field, means `false`. The environment variable `NEXTGCORE_SBI_OAUTH2_REQUIRE` is checked **first** and, when set, decides in either direction — the YAML is not consulted at all. |

### Parsed-but-inert / decorative YAML fields

Everything else in the shipped example file is decorative — unknown keys are silently ignored:

- **`logger.level` is inert.** The log level comes from the CLI flag `-e/--log-level` (default `info`), overridable by `RUST_LOG`.
- **`lmf.sbi.server[]` (address/advertise/port) is inert.** The SBI bind address and port come only from `--sbi-addr`/`--sbi-port`; the docker deployment passes them on the command line (`--sbi-addr 172.23.0.32 --sbi-port 7777`).
- **`lmf.nrf.uri` is inert.** The NRF URI comes only from the `--nrf-uri` flag (default `http://127.0.0.1:7777`). The docker deployment passes `--nrf-uri http://172.23.0.10:7777` explicitly — setting only the YAML field has no effect.

## Command-line flags

From the clap `Args` struct in `src/bins/nextgcore-lmfd/src/main.rs`:

| Flag | Type | Default | Description |
|---|---|---|---|
| `-c, --config` | path | `/etc/nextgcore/lmf.yaml` | Configuration file path (probed only for `sbi.oauth2.require`). |
| `-e, --log-level` | string | `info` | Log level (env_logger filter; `RUST_LOG` takes precedence when set). |
| `-l, --log-file` | path | unset | Accepted but currently **unused** — the daemon never reads this field. |
| `-m, --no-color` | flag | off | Accepted but currently **unused**. |
| `--sbi-addr` | string | `0.0.0.0` | SBI server bind address. Also used as the advertised host for N1N2 notify callback URIs — `0.0.0.0` falls back to `127.0.0.1` (see behavior notes). |
| `--sbi-port` | u16 | `7816` | SBI server port (docker deployments pass `7777`). |
| `--tls` | flag | off | Enable TLS on the SBI server. |
| `--tls-cert` | path | `/etc/nextgcore/tls/server.crt` (when `--tls`) | TLS certificate file. |
| `--tls-key` | path | `/etc/nextgcore/tls/server.key` (when `--tls`) | TLS private key file. |
| `--max-measurements` | usize | `1024` | Maximum concurrent measurement contexts in the LMF context store. When full, new positioning sessions fail with 500 `POSITIONING_FAILED` ("measurement store exhausted"). |
| `--nrf-uri` | string | `http://127.0.0.1:7777` | NRF base URI for registration, heartbeat, AMF discovery, and (when OAuth2 is on) token issuance/JWKS. |
| `--debug-endpoints` | bool | `false` | Enable the six bespoke/debug ingest routes (`measurements`, `nrppa-reports`, `nrppa-binary-reports`, `lpp-binary-reports`, `ue-locations`). Fail-closed by default: when disabled these paths 404 exactly like any unknown path (no route disclosure), and in particular `PUT ue-locations/{supi}` — which would inject an arbitrary client-supplied fix — is unreachable. Marked in source as "must not be enabled in production". The `nrppa-reports` JSON takes `cellMeasurements[]` with `nrCgi`, `rsrp`, `rsrq`, `timingAdvance`, `aoa`, `rttNs` (a two-sided RTT), `rstdNs`, and, since #713, `ueRxTxNs` and `gnbRxTxNs` (the signed UE and gNB Rx-Tx halves, ns, ranged only as a pair), and since #832 `ecidRttNs` (the E-CID round trip, ns). `timingAdvance` on this route is an NR TA command (TS 38.213 §4.2). |

## Behavior notes

- **Environment variables.** `NEXTGCORE_SBI_OAUTH2_REQUIRE` (`1`/`true`/`TRUE`/`yes` = on) overrides the YAML OAuth2 knob in both directions and is how the `docker-compose.oauth2.yml` overlay enables enforcement. `OTEL_EXPORTER_OTLP_ENDPOINT` sets the OpenTelemetry OTLP exporter endpoint (default `http://jaeger:4317`). `RUST_LOG`, when set, overrides `--log-level` via env_logger.
- **NRF registration is best-effort, no retry.** At startup the LMF PUTs an NFProfile (`nfType: LMF`, service `nlmf-loc`, `allowedNfTypes: [AMF, SCP]`, `heartBeatTimer: 10`) to `/nnrf-nfm/v1/nf-instances/{id}`. On failure it logs a warning and **operates without NRF** — and the heartbeat worker is only spawned after a successful registration. On success it heartbeats every 5 s, PATCHing a real `/load` gauge derived from the active positioning-session count saturated at 100 (TS 29.510 §5.2.2.3.2 per code comment) — no fabricated CPU numbers.
- **Positioning reference points are REQUIRED (#103).** Every geometric solver reads the cell/TRP registry, and before #103 the only writer was test code — so a deployed LMF had an empty registry and could never produce a fix. Provision them under `lmf.positioning`:

  ```yaml
  lmf:
    positioning:
      cells:
        - id: pci-42
          lat: 37.5665
          lon: 126.9780
          height: 38.0
      trps:
        - id: trp-1
          lat: 37.5670
          lon: 126.9790
  ```

  A bad entry (latitude outside ±90, longitude outside ±180, missing `id`/`lat`/`lon`) is **rejected individually and named at error level**; the rest of the list still loads, because one typo should not cost every cell. With **nothing** configured, `DetermineLocation` is refused with 500 `POSITIONING_FAILED` whose detail names `lmf.positioning.cells` — it does not fabricate a coordinate. With **fewer than three**, only E-CID is selectable however high the requested accuracy; both cases are warned about once at startup.
- **The requested positioning method follows the LCS QoS (#103).** Before #103 every network-initiated request was LPP E-CID with the Multi-RTT and DL-TDOA bodies hardcoded absent, so a request for ≤10 m accuracy was answered by a method whose output is a Timing-Advance ring. The rule, in order: fewer than three reference points ⇒ E-CID; the UE reported E-CID-only capability ⇒ E-CID; `hAccuracy ≤ 10` or `EMERGENCY_SERVICES` ⇒ **NR Multi-RTT** when the gNB half can be obtained (`LMF_NRPPA_DOWNLINK=1` and at least one `lmf.positioning.ngRanNodes` entry, #807), else **NR DL-TDOA** (#713: a Multi-RTT range is UE Rx-Tx plus gNB Rx-Tx, TS 38.305 §8.10, and a UE-only Multi-RTT report is not ranged; DL-TDOA relies on the reference keying fix #714); `LOW_DELAY` ⇒ E-CID (it is a statement about time, and PRS scheduling is not fast); otherwise E-CID. Every E-CID is the one of the UE's access (#715): **NR E-CID** (`nr-ECID-RequestLocationInformation-r16`, SS-RSRP/RSRQ) when `InputData` names an `ncgi` or no serving cell, **E-UTRA E-CID** (RSRP, RSRQ and the UE Rx-Tx, `ueRxTxReq`) when it names only an `ecgi` (ng-eNB). NR E-CID over LPP carries no UE timing quantity, so an LPP-only NR E-CID report yields no fix (500 `POSITIONING_FAILED`). With `LMF_NRPPA_DOWNLINK=1` the session also waits for the gNB's E-CID answer, and **the legs are solved together** once both are in, or with whatever arrived when the response-time budget runs out; whichever leg arrives first no longer decides the outcome alone (#715 review). The gNB's answer to the on-demand request is read from the E-CID MEASUREMENT INITIATION RESPONSE (TS 38.455 §8.2.1.2), as well as from an E-CID MEASUREMENT REPORT. **Limitation:** only the E-UTRA TADV arms are decoded. A gNB on NR reports its timing term as `NR-TADV`, which is not decoded yet (#859), so an NR E-CID request against a real NR gNB still ends in 500 `POSITIONING_FAILED`. Fixes are reported as `NR_ECID` or `ECID` by the serving cell's RAT. The E-CID timing term is decoded from its own report mapping into a round trip (#832): E-UTRA TADV Type 1/2 from NRPPa per TS 36.133 §10.3.1, and the E-UTRA UE Rx-Tx from LPP per TS 36.133 §9.1.9.3 (2 T_s steps up to 4096 T_s, then 8 T_s; the last, open-ended value is not used; on a TDD cell, identified by its EARFCN, the N_TA,offset of 624 T_s is removed). When a gNB reports both TADV Type 1 and Type 2, Type 1 is used (TS 36.305 §8.3, the more accurate). The NR TADV (`NR-TADV`, an NRPPa extension) is not decoded yet (#859).
- **TRP keys for the NR methods (#714).** An LPP NR-DL-TDOA or Multi-RTT measurement is looked up as `pci-<n>` when the UE reported the NR PCI, else as `prs-<id>` (its DL-PRS ID), so either spelling works in `lmf.positioning.cells`/`.trps`. The DL-TDOA reference TRP never carries a PCI (`DL-PRS-ID-Info-r16` has none), so it is found only as `prs-<id>`. When the registry does not hold it, the RSTDs are rebased on a neighbour it does hold. The fix is unaffected, but the reported accuracy is doubled, because one TRP of redundancy is lost. When an MO-LR carries several LPP reports with different reference TRPs, each report stays relative to its own reference. The reports are joined through a TRP they share, matched by DL-PRS ID (unique to one TRP within a session) rather than by PCI, and a report that shares none is dropped (#824 review). A PCI does not identify a TRP: a **multi-TRP cell** puts one PCI on several TRPs, and PCIs are reused across sites. A `pci-<n>` key reached from two different DL-PRS IDs in one session is therefore treated as ambiguous and not used (logged at warn). Where measured TRPs share a PCI, key the registry by `prs-<id>`. Use **one key scheme per registry**, all `pci-<n>` or all `prs-<id>`: in a mixed registry, a neighbour whose PCI is missing can match another TRP's `prs-<id>`. DL-TDOA fixes are reported as `DL_TDOA`. Open-ended NR-RSTD report values (the first and last bins, TS 38.133 §10.1.23.3) are not used.
- **Multi-RTT, the gNB half (#807).** With the NRPPa downlink on and `lmf.positioning.ngRanNodes` set, a Multi-RTT request runs the NRPPa procedures of TS 38.305 §8.10.3.2 before the UE is asked: TRP Information Exchange with each configured node once (TS 38.455 §8.2.8; TRP-ID → NR PCI and position, a position not in the registry is added as `pci-<n>`, a configured one is kept), Positioning Information Exchange with the serving gNB (§8.2.6; semi-persistent SRS requested, the SRS configuration returned), Positioning Activation (§8.2.9; none for periodic SRS), and an on-demand MEASUREMENT REQUEST for the gNB Rx-Tx time difference of each node's TRPs (§8.5.1, carrying the UE's SRS configuration). The non-UE-associated messages go through the AMF's `NonUeN2MessageTransfer` (TS 29.518 §5.2.2.4.1.2) and come back through a `NonUeN2InfoSubscribe` for the NRPPa class that the LMF creates. Answers are matched by NRPPa procedure code and transaction id. The gNB halves are keyed `pci-<n>` by the TRP information and paired with the UE halves of the same TRP whose time stamps (`nr-TimeStamp-r16` and the NRPPa `TimeStamp`) are within 200 ms, across the SFN wrap. The session waits for both legs, or for the response-time budget. Open-ended gNB Rx-Tx report values are not used, and the SRS is deactivated afterwards (§8.2.10). When any of this cannot be set up (no TRP with a PCI, no SRS configuration, the activation refused, no Measurement Request sent), the UE is asked for DL-TDOA instead. Once it is set up, the UE is asked for **Multi-RTT and DL-TDOA in one request**, and both result sets are kept, so a gNB that answers MEASUREMENT FAILURE or never answers leaves a DL-TDOA fix rather than a 500 (#903 review). A PCI that TRP Information reports on more than one TRP (a multi-TRP cell, or PCI reuse) names no single TRP: those TRPs are not measured, their position is not learned, and a UE-half key reached from two DL-PRS IDs is not ranged. A node that does not answer TRP Information is not asked again for 60 s. The setup counts against the response-time budget. The requested SRS bandwidth is `lmf.positioning.srsBandwidthMhz` (an FR1 value of TS 38.455 `BandwidthSRS`, default 20). **Limitation:** no DL-PRS assistance data is sent (TS 38.305 §8.10.3.2 step 7, #911), so a UE measures only the PRS its posSIBs describe; this affects DL-TDOA equally. **Not covered end to end:** nextgsim's gNB answers TRP and Positioning Information but not Positioning Activation or the Measurement procedure, so this path is tested in-process against amfd's real Namf handlers and a scripted NG-RAN.

  ```yaml
  lmf:
    positioning:
      ngRanNodes:
        - mcc: "001"
          mnc: "01"
          gnbId: "000001"   # hex (TS 29.571 GNbId.gNBValue)
          bitLength: 22     # 22..32
  ```
- **NRPPa toward NG-RAN is gated (#103).** `LMF_NRPPA_DOWNLINK=1` makes the LMF send an E-CID Measurement Initiation Request (TS 38.455 §8.2.1.2, procedure code 2) to the serving gNB before it asks the UE over LPP — the gNB half of the measurement. Off by default because it is new external N2 signalling. Best-effort: a gNB that declines must not fail a request the UE could still answer. The AMF relays it over NGAP procedure 8 and echoes the LMF id into the RoutingID, so the uplink reply routes back here.
- **MO-LR assistance data delivers a reference location (#103).** `ueLocationServiceInd: LOCATION_ASSISTANCE_DATA` used to answer a bare 204 without looking at the UE's PDU. It now decodes the UE's LPP `RequestAssistanceData`, builds a `ProvideAssistanceData` carrying a GNSS reference location (the centroid of the configured reference points, with their spread as the uncertainty at 68% confidence), and delivers it over N1 — still answering 204 to the AMF, but a 204 that means something happened. An attached body that is *not* a `RequestAssistanceData` is a 400. Only a reference location is provided: ephemerides, ionospheric models and Earth-orientation parameters would need a GNSS data feed this build has no client for, and fabricating them would be worse than omitting them.
- **Area- and motion-event deferred LDRs are REFUSED (#103).** `ENTERING_INTO_AREA`, `LEAVING_FROM_AREA`, `BEING_INSIDE_AREA` and `MOTION` answer **501 `UNSUPPORTED_EVENT_TYPE`** (TS 29.572 Table 6.1.7.3-1: "the request for creation of a subscription is rejected because none of the events is supported by the LMF"). They used to register a context and answer 200 while nothing armed the trigger and nothing ever reported it. `PERIODIC` deferred location still works and still registers. `UE_AVAILABLE` still registers and is not reported — left that way deliberately, because its trigger source is the AMF's reachability report rather than a missing UE capability, so the gap is an AMF subscription.
- **DetermineLocation never fabricates a fix.** A real measurement-derived fix returns 200 `LocationDataExt`; failures map per the TS 29.572 Table 6.1.7.3-1 cause table (per code comments): no discoverable serving AMF, UE not reachable, or timeout → 504 `UNREACHABLE_USER`; report received but unsolvable → 500 `POSITIONING_FAILED`; malformed `InputData`, `ecgi`+`ncgi` together, or a dangling multipart `contentId` → 400; unsupported media type → 415. A stored per-SUPI fix short-circuits the procedure only when its capture timestamp allows an honest `ageOfLocationEstimate`.
- **Response-time budget.** The handler waits `min(maxRespTime, QoS bound, 20 s hard cap)` for the positioning outcome; `responseTime: LOW_DELAY` caps the wait at 5 s and `NO_DELAY` waits not at all (`maxRespTime: 0` is rejected 504 immediately). SBI client timeouts (2 s connect / 3 s request) nest inside this cap.
- **Callback reachability.** The N1N2 notify callback base advertised to the AMF is `http://<sbi-addr>:<sbi-port>`; when `--sbi-addr` is the default `0.0.0.0` it falls back to `127.0.0.1`, so in any multi-host or container deployment you must bind to (or pass) a concretely reachable address — the docker compose passes `172.23.0.32`.
- **No state file.** All measurement contexts, positioning sessions, LDR registrations, and stored fixes live in memory and are lost on restart; periodic-LDR scheduler tasks are aborted on shutdown, and EventNotify delivery retries exactly once before auto-cancelling the deferred session (no infinite retry).
