# Changelog

All notable changes to **nextgcore** are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Scope of validation.** nextgcore is a research/interop implementation, **not a
> production-certified 5G core.** Conformance is verified against 3GPP spec text,
> hand-derived golden byte-vectors, strict-peer tests (one NF driving another NF's
> real handler), and the matched-simulator end-to-end suite. It has **not** been run
> against a TTCN certification suite or an independent third-party gNB/UE/core.

## [Unreleased]

### Added
- Releases publish their container images to Docker Hub (#420). On a version tag, `release.yml`
  pushes every image in `docker/release-images.json` as `<namespace>/<image>:<version>`, then
  moves `latest` once every versioned push has succeeded. The images are `nextgcore-core`, one
  `nextgcore-<nf>` per daemon (28) and `nextgcore-webui`. nextgsim publishes its gNB, UE, eNB
  and LTE UE images the same way. Publishing needs the `DOCKERHUB_USERNAME` and
  `DOCKERHUB_TOKEN` repository secrets, and is skipped with a notice without them. A CI check
  fails when a daemon, Dockerfile or deployed image is missing from the list. See
  `docs/ci-and-release.md`, "Docker Hub images".
- The `docker/webui` image runs on Node 22 LTS (was the end-of-life Node 19) as the `node` user,
  and no longer downloads the docker-compose-wait binary at build time. Order its start after
  MongoDB with compose `depends_on` health conditions (#420).

### Changed
- mmed binds a configured IPv6 S1-MME address. Before, a bracketed IPv6 `mme.s1ap.server`
  address without a port (`[fd00::5]`) was dropped as unparsable, and the IPv6 server list
  `s1ap_list6` was never filled or read, so such a config fell back to `127.0.0.1:36412`. IPv6
  entries now go in `s1ap_list6`, and the bind takes the first IPv4 entry, else the first IPv6
  one. Loopback remains the default only when nothing is configured (#1299 follow-up).
  The bracketed-IPv6 parse fix covers every mmed listen address read through the same parser:
  S11 (`mme.gtpc.server`), N26 (`mme.n26.server`) and SBc-AP (`mme.sbcap.server`, and the CBC
  allowlist). Those bind the same way: the first IPv4 entry, else the first IPv6 one (#1312).
- A configuration file that does not parse now fails startup with the parse error, where it
  was ignored and the daemon fell back to its defaults (loopback binds among them). Affects
  amfd, nrfd, ausfd, bsfd, nssfd, pcfd, udmd, udrd, smfd, dccfd, eesd, lmfd, mbsmfd, nsacfd,
  nwdafd and pind. A missing file is still no configuration (#1312, #1313 review).
- dccfd, eesd, lmfd, mbsmfd, nsacfd, nwdafd and pind bind `<nf>.sbi.server[0]` from their YAML
  when `--sbi-addr` / `--sbi-port` are not given; the flags still win (#1312).
- **ausfd, bsfd, nssfd, pcfd, udmd and udrd: `--sbi-addr` / `--sbi-port` now beat
  `<nf>.sbi.server[0]`**, which used to override them; the order is the flags, then the YAML,
  then `127.0.0.1` (#1312). No shipped deployment passes the flags, so none changes its bind.
- The SBI host registered with the NRF and put in callback URIs is set apart from the bind
  (#1312): `--sbi-advertise`, else `NEXTGCORE_SBI_ADVERTISE`, else `<nf>.sbi.server[0].advertise`,
  else the bind address when it is not a wildcard. A wildcard is never advertised: an NF that
  binds `0.0.0.0` or `::` with nothing to advertise does not register with the NRF, and logs
  why. pcfd then also publishes no self identity, so it builds no callback URI, absolute
  resourceUri or BSF PcfBinding endpoint on the wildcard (each is skipped). Applies to ausfd, bsfd, nssfd, pcfd, udmd, udrd, dccfd, lmfd, mbsmfd, nsacfd and nwdafd,
  and to eesd's ECS registration. The k8s manifests, the EKS profiles (which build on them)
  and the Helm chart set `NEXTGCORE_SBI_ADVERTISE` to the pod IP for the first six.
- **amfd, smfd, nefd and ucmfd refuse to start on a wildcard SBI bind with nothing to
  advertise**, where they put `0.0.0.0` (amfd, nefd, ucmfd), `127.0.0.1` or `::` (smfd) in
  the callback URIs, `Location` / resource URIs and NFProfiles they hand peers (#1322). The
  advertised host is `NEXTGCORE_SBI_ADVERTISE` (and `--sbi-advertise` for nefd and ucmfd),
  else `<nf>.sbi.server[0].advertise` (amfd, smfd), else the bind when it is not a wildcard.
  `SMF_SBI_ADVERTISE_URI` and nefd's `--notify-base` still win, and are refused when they name
  no host or a wildcard. amfd's callback URIs now follow `amf.sbi.server[0]` too; they used
  `AMF_SBI_ADDR` or `127.0.0.1` even when the YAML set the bind. easdfd and tsctsf take
  `--sbi-advertise` and skip NRF registration rather than register a wildcard. pcfd no longer
  sends a BSF PcfBinding when it has no advertised host (logged once). The k8s, EKS and Helm
  manifests set `NEXTGCORE_SBI_ADVERTISE` to the pod IP for amf and smf as well. No shipped
  deployment binds these NFs to a wildcard with nothing to advertise.
- The inert `metrics.server` blocks are gone from the shipped configs and both ConfigMaps: no
  daemon read them. The metrics listeners are set by environment variables, listed in
  `docs-book/src/observability.md` (#1312).
- The shipped-config parse tests also parse each NF config as the Helm chart renders it; CI
  installs helm for them (#1312, #1317 review).
- **mmed: S1-MME binds `127.0.0.1:36412` when `mme.s1ap.server` is unset**, where it bound the
  wildcard `0.0.0.0` (#1299). Break risk: a deployment that relied on the implicit wildcard
  (no `mme.s1ap.server`) no longer accepts eNBs from other hosts; it logs a warning and needs
  `mme.s1ap.server` set. Every shipped config (`docker/rust/configs/epc/mme.yaml`, which the
  EKS EPC profile also uses) sets it.
- mmed serves SBc-AP toward a CBC when `mme.sbcap` is configured (TS 29.168: Write-Replace and
  Stop Warning, and the PWS Restart / Failure Indication relay of TS 23.007 §15A.1.2), off by
  default, CBC allowlist (#1071).
- lmfd reads an NRPPa E-UTRA AoA (`valueAngleOfArrival-EUTRA`, 0..719) per TS 36.133 Table
  10.2.1-1: 0.5 degree bins, counter-clockwise from North (TS 36.214 §5.2.7). It is turned into
  the AoA solver's clockwise bearing, at the bin midpoint. Before, it took the report value as
  the angle, which was both twice too large and the wrong way round (#1269).
- smfd (PGW-C) picks packet filter precedences under one allocator per PDN connection, and
  counts the precedences of procedures still in flight. A Bearer Resource Command's added
  filters are only stored once the SGW-C accepts them. Before, an activation or a Command
  on another bearer in that window could pick the same precedence, and the UE would delete
  one of the two filters (TS 24.301 §6.4.2.4 d) 2); #1296 review).
- An IPv6 SBI address goes in square brackets in the URIs built from it (RFC 3986 §3.2.2):
  pcfd's apiRoot and callback URIs; the apiRoot or self/callback base of amfd, ausfd, lmfd, nefd,
  nrfd, nwdafd, smfd, ucmfd, udmd and udrd; seppd's N32f forward URI; and the SBI client's and
  SCP's base URI and connect address. Before, an IPv6 address gave `http://fd00::1:7777/...`,
  which is not a valid URI (Refs #1277). The shared helper
  `nextgcore_sbi::uri_encode::uri_authority` does the bracketing. Its first change missed some
  URIs; those are covered by the #1298 entry.
- Every daemon's listen addresses accept an IPv6 address, bracketed or not:
  - the SBI bind of amfd, ausfd, bsfd, dccfd, easdfd, eesd, lmfd, mbsmfd, nefd, nrfd, nsacfd, nssfd,
    nwdafd, pcfd, pind, smfd, tsctsf, ucmfd, udmd and udrd;
  - smfd's PFCP bind, easdfd's DNS/UDP bind, amfd's N26 bind and the metrics servers.
  Before, `format!("{addr}:{port}")` made `fd00::1:7777`, which is not a socket address, and the
  daemon failed at startup. Something that is not an IP literal is still refused at startup with
  an error naming the value, and never replaced by a wildcard. The defaults are unchanged.
  The remaining unbracketed URIs are bracketed as well: nwdafd's NRF callback, seppd's N32f
  client URI and local apiRoot, and scpd's forward target URI and its client, OAuth2-client and
  circuit-breaker keys. An IPv6 producer behind the SCP is now reached (#1298).
- smfd (PGW-C) gives the packet filters of a dedicated bearer precedences that no filter of the
  PDN connection uses, keeping their relative order. This applies to local PCC rules and to the
  filters a Bearer Resource Command adds or replaces. Before, every local rule numbered its
  filters 0, 1, …. A second rule on the same PDN connection then duplicated the first rule's
  precedences, and the UE deleted the older filters, or the whole bearer (TS 24.301 §6.4.2.4 d) 2))
  (#1293). A Delete Bearer Command whose bearers all have a Delete Bearer Request in flight is now
  answered with a Delete Bearer Failure Indication, cause #101 "Collision with network
  initiated request" (TS 29.274 §7.2.17.2). Before, it got no answer (#619).
- An IPv6 SBI address goes in square brackets in every URI a daemon builds from it
  (RFC 3986 §3.2.2). That covers pcfd's apiRoot and callback URIs, the apiRoot or self/callback
  base of amfd, ausfd, lmfd, nefd, nrfd, nwdafd, smfd, ucmfd, udmd and udrd, seppd's N32f
  forward URI, and the SBI client's and SCP's base URI and connect address. Before, an IPv6
  address gave `http://fd00::1:7777/...`, which is not a valid URI (Refs #1277). One shared
  helper, `nextgcore_sbi::uri_encode::uri_authority`, does it. The bind-address parse has
  the same defect and is tracked in #1298.
- lmfd reads the LPP NR PRS-RSRP of a Multi-RTT or DL-TDOA measurement (`nr-DL-PRS-RSRP-Result`)
  as `v − 157` dBm, the lower edge of TS 38.133 Table 10.1.24.3.1-1. It read `v − 140`, the
  E-UTRA RSRP offset, which put every PRS-RSRP 16-17 dB too high (#1278).
- pcfd's `resourceUri`, in AM and UE PolicyUpdates (notifications and Update responses) and in
  SM policy notifications, is now the complete resource URI `{apiRoot}/<apiName>/...` (TS 29.501
  §4.4.1), with the configured FQDN as host when there is one. Before, it was the bare path. The
  TS 29.507 / 29.512 / 29.525 notes let a consumer use either the complete URI or its
  apiSpecificResourceUriPart (#1277).
- lmfd decodes the NR E-CID quantities of an NRPPa E-CID report into physical values, so NR
  E-CID against a real NR gNB gives a fix where it gave 500 `POSITIONING_FAILED`. NR-TADV is the
  round trip of TS 38.133 §13.5.1 Table 13.5.1-1, used as the E-CID timing term (bin
  midpoint). The serving cell's SS/CSI-RSRP and RSRQ rank the cell (§10.1.6.1, §10.1.11.1), a
  GCS AoA NR becomes a bearing (§13.4.1), and the UE Rx-Tx (§10.1.25.3.1, k = 5) is decoded but
  ranges nothing (#859).
- lmfd decodes NR-RSTD, UE Rx-Tx and gNB Rx-Tx reports (LPP and NRPPa) to the bin midpoint of
  TS 38.133 Tables 10.1.23.3.1-x, 10.1.25.3.1-x and 13.2.1-x. Before, it took the upper edge,
  a bias of half a reporting step (8 ns, about 2.4 m, at k = 5). NR SS/CSI-RSRP reads as the
  bin's lower edge, `v − 157` dBm (Table 10.1.6.1-1), where it read the upper edge (#1270).
- pcfd now acts on a change of the UE's policy data at the UDR (the policy-data notification
  it already subscribes to) for the UE's AM and UE policy associations, not only its SM
  sessions (TS 29.513 §5.1.2.2, §5.6.2.2.2). A changed AM policy is pushed to the AMF with
  Npcf_AMPolicyControl_UpdateNotify, `POST {notificationUri}/update`, whose PolicyUpdate carries
  only the changed `rfsp`/`servAreaRes` (TS 29.507 §4.2.4.2, §4.2.3.3). `ueAmbr` is not sent:
  this PCF does not negotiate UE-AMBR_Authorization. A changed URSP is delivered to the UE as a
  new MANAGE UE POLICY COMMAND over N1N2. Nothing is sent when nothing changed, or when the UDR
  read fails. Before, nothing in pcfd sent a PCF-initiated AM or UE policy change. A new UE policy
  delivery now stops the T3501 loop of the one it replaces, so the old command is not
  retransmitted. A UE policy association whose request names no serving PLMN (`servingPlmn` or
  `guami`) gets no MANAGE UE POLICY COMMAND, where it used to get a section for the test PLMN
  001-01 (#1261).
- smfd keeps each SM context's UPF N3 uplink F-TEID in the durable snapshot (`upfUlEndpoints`),
  so a restored PDU session can still have its user plane activated, be paged for downlink data,
  or be handed over (#1230). Before, a restart lost it, and those all failed: activation was
  answered 500, and the paging transfer had no UL NG-U tunnel (TS 38.413 §9.3.4.1). A Downlink
  Data Report for a restored session now pages the UE.
  **Upgrade:** smfd 0.1.0 had no durable state. The snapshots affected are 0.2.0-dev ones
  written before #1230, which have no endpoints. No session is released for that. A native
  5G session's endpoint is recovered from the UPF the first time it is needed: PDR 1 is
  removed and created again with the UPF choosing the F-TEID, once per session even when
  requests race. That happens at the UP activation, the paging, a handover preparation or
  a Modify Indication. For a session that is still connected and handed over before going
  idle, uplink is lost from that point until the UE has moved. An EPS→5GS-migrated session
  from such a snapshot is released at boot with #39 "reactivation requested", and its UE
  re-establishes it (TS 24.501 §6.3.3).
  **Rollback:** the snapshot version stays 2, and `upfUlEndpoints` is an extra field that a
  pre-#1230 build ignores. That build reads the file and drops the field at its next write,
  and the next upgrade recovers the endpoints as above.
- smfd sends a restored session's boot "RELEASED" notifications (#193) after boot,
  16 at a time, and writes the snapshot once for all of them. Before, it wrote it once per
  session and waited for each AMF in turn, all before the SMF served anything.
- smfd's PDU SESSION ESTABLISHMENT REJECT leaves out the Back-off timer value IE for #26 and #69
  when the request is for emergency services (SmContextCreateData `requestType`
  INITIAL_EMERGENCY_REQUEST or EXISTING_EMERGENCY_PDU_SESSION), and for #26, #27 and #69 when the
  UE is configured for high priority access, so the UE can retry at once (TS 24.501 §6.4.1.4.1).
  High priority access is the AMF's `3gpp-Sbi-Message-Priority` header with a higher priority
  than the default 24, i.e. a numerically lower value, 0 being the highest (TS 23.502 §4.3.2.2.1
  step 3, TS 29.500 §5.2.3.2.2, §6.8.4), which amfd sets for a priority UE
  (#1222), or `priorityUserInd` (TS 29.502, home-routed and V-SMF insertion) (#1188).
- smfd's EBI assignment request (`Namf_Communication_EBIAssignment`) now gives the default flow's
  ARP as NOT_PREEMPT / NOT_PREEMPTABLE, the same ARP the N2 default QoS flow carries. Before, it
  said PREEMPTABLE, so the AMF could revoke the EBI for a higher-priority request that the RAN
  would never pre-empt (TS 23.502 §4.11.1.4.1). Both now come from one source,
  `n2_transfer::Arp::default_flow` (#1179). Its priority level is clamped into 1..=15 there, so
  a policy level of 0 or above 15 is the same clamped value on N2 as in the EBI assignment
  (#1179).
- smfd (PGW-C) codes EPS bearer rates in kbit/s on S5/S8 and holds them in bit/s, as N4 and N2
  read them (TS 29.274 §8.15, §8.16). The Create Session Request's Bearer QoS and a Bearer
  Resource Command's Flow QoS on an existing bearer were stored unconverted, so their MBR/GBR
  reached the PGW-U QER and the EPS→5GS mapping 1000 times too low. The Create Session Response
  and the Update Bearer Request sent the stored bit/s values as kbit/s, so the values seen on
  the wire change. A rate is rounded up to whole kbit/s and capped at the 5-octet field (#1165).
- smfd's N1N2MessageTransfer for a network-triggered Service Request (buffered downlink data)
  now carries the session's PDUSessionResourceSetupRequestTransfer, as an
  `application/vnd.3gpp.ngap` part that `ngapData` references. It includes the UPF N3 tunnel,
  every QoS flow and the Session-AMBR (TS 23.502 §4.2.3.3 step 3a, TS 29.518 §6.1.6.2.27). It
  also carries the paged flow's `5qi` and `arp` (§6.1.6.2.18). The non-conformant JSON
  `ngapData: {qfi}` is gone. With no recorded user plane, no policy binding, or a transfer that
  fails to encode, no N1N2MessageTransfer is sent: paging a UE for a session that cannot be
  activated only drains its battery, and an `n2InfoContent` without `ngapData` (M) is malformed.
  The data stays buffered and the error names the session (#1162).
- smfd (PGW-C): a Create Session Request for the [IMSI, EBI, interface type] of an existing PDN
  connection deletes that connection first, at the PGW-U too, and frees its PDN address (TS
  29.274 §7.2.1). If the EBI belongs to a dedicated bearer, only that bearer and its PGW-U rules
  are deleted. Before, every MME or SGW-C restart left one more PGW-U session and address for
  the same UE. A dedicated bearer whose rules this PGW-C did not install (one that came over
  N26) cannot be removed alone, so its whole PDN connection goes: a deviation from §7.2.1, which
  deletes only the bearer. An SGW-C whose Restart counter moves ahead has the PDN connections of
  its old incarnation deleted (TS 23.007 §18, §17.1A.1): those set up under another counter, and
  those set up with no Recovery IE no later than the last message that showed the old counter.
  One set up after that, of unknown incarnation, is kept, so a same-address restart does not
  delete the new incarnation's live connections. The deletions run in the background, 16 at a
  time, after the message that showed the restart is answered
  (`smf_s5s8_sgw_restart_pdn_deleted_total`, `smf_s5s8_sgw_restart_deletions_running`). The
  counter is read from the Recovery IE of a Create Session Request or an Echo. Create Session
  Requests are served one at a time per IMSI. A retransmitted Create Session Request is answered
  with the response already sent (TS 29.274 §7.6) and is not served again (#1194).
- smfd discovers the NSACF per S-NSSAI. NRF discovery carries the session's `snssais` (TS 29.510
  §6.2.3.2.3.1), and the instance taken is one whose `sNssais` or `perPlmnSnssaiList` serves it.
  A profile with neither serves any slice (§6.1.6.2.2). The discovery cache is keyed by the
  S-NSSAI too. Before, the first NSACF was used for every slice (TS 23.501 §5.15.11). `NSACF_URI`
  still names one NSACF for all slices (#1164).
- smfd sends a PDU session's NSACF DECREASE to the NSACF that admitted it, recorded on its
  policy binding (and in the durable snapshot), instead of re-discovering one: with two NSACFs
  for a slice and the NRF's order changed, the count leaked on the first. The NSACF discovery
  also honours the `nnsacf-nsac` service's own `sNssais` / `perPlmnSnssaiList` (TS 29.510
  §6.1.6.2.3), reads a `perPlmnSnssaiList` for the serving PLMN only, skips an instance whose
  endpoint cannot be read (and reaches an FQDN-only one by its FQDN) rather than giving up, and
  an SM Context Create whose S-NSSAI SD is not 6 hex digits (TS 29.571 §5.4.4.2) is answered 400
  INVALID_MSG_FORMAT (#1164). That answer is an SmContextCreateError carrying the N1 PDU SESSION
  ESTABLISHMENT REJECT (5GSM cause #31) when the request carried an N1 SM message (TS 29.502
  §5.2.2.2.1), so the UE is answered at once rather than running out T3580. A DECREASE that has to
  resolve its NSACF again (no NSACF recorded) resolves it for the serving PLMN the session was
  admitted in, which the policy binding now records (#1164).
- smfd ignores the Recovery Time Stamp in a PFCP Association Setup Response, and keeps a UPF's
  Recovery Time Stamp in memory only (TS 23.007 §19A; TS 29.244 Table 7.4.4.2-1 NOTE). A new
  association starts with no stored stamp, and its first Heartbeat stamp is the baseline. Whether
  a UPF that re-associates still holds the SMF's sessions is answered by session retention: no
  PSREI in the response releases them (#718). Before, a changed stamp at Association Setup was
  taken as a restart, and the stamp was persisted as `upfRecoveryTimeStamps` in the durable
  snapshot to seed that check after an SMF restart. A snapshot's `upfRecoveryTimeStamps` is now
  ignored on load and dropped at the next write. The stored stamp is forgotten when the
  association goes down. A session request answered with cause 72 "No established PFCP
  Association" (a UPF that restarted after the Association Setup) tears the association down and
  releases that UPF's sessions, so it is set up again (#966). Only the association the request
  was sent on: a late cause 72 answering a request sent before a re-association leaves the
  association set up since, and its sessions, in place. The association is the one the request left on, read as
  each transmission is sent (#966).
- smfd takes its durable snapshot through a poisoned lock: the maps and the IPv4 pool are read
  as the panicking writer left them, and the poison is logged. Before, a poisoned map was written
  as empty over the last good snapshot, and the next restart restored nothing (#1178). The
  poison is then cleared, so the map's writers (which skip a poisoned lock) and the IPv4 pool's
  allocation resume, and it is logged once per poisoning rather than at every write. That holds
  with the durable state off too (the default, where no snapshot is taken): every `persist()`
  heals a poisoned context map, and the IPv4 pool uses its bitmap through a poison and clears
  it at every allocation and release (#1178). Every lock of the SMF context, and the global
  context's own, is now taken through a poison and cleared at its next use, so a reader or
  writer that skipped a poisoned lock no longer waits for anything else to heal it (#1178).
- smfd answers its own SM Context Create and Update errors as SmContextCreateError /
  SmContextUpdateError (TS 29.502 Tables 6.1.3.2.3.1-3, 6.1.3.3.4.2.2-2): the ProblemDetails is
  under `error`, at `application/json`. A failed activation adds `upCnxState: DEACTIVATED`, and a
  failed handover preparation adds `hoState: NONE` with a Handover Preparation Unsuccessful
  Transfer. N1/N2 SM information that is missing is 400 MANDATORY_IE_MISSING, and present but
  erroneous 403 N1_SM_ERROR / N2_SM_ERROR. A UDM that cannot be reached is 500 SYSTEM_FAILURE,
  or 504 PEER_NOT_RESPONDING when it did not answer. Causes now come from the TS 29.502 / 29.500
  tables: SSC_NOT_SUPPORTED, PDUTYPE_NOT_SUPPORTED, 500 INSUFFICIENT_RESOURCES_SLICE (an NSACF refusal),
  SUBSCRIPTION_DENIED (a PCF refusal) and PEER_NOT_RESPONDING (no PCF answer). A third-party AMF
  that read a top-level `cause` must read `error.cause` (#1097). The UE's PDU SESSION
  ESTABLISHMENT REJECT for an NSACF refusal carries 5GSM #69 "insufficient resources for
  specific slice" (TS 24.501 §4.6.3.1, §6.2.8); it was #67, the S-NSSAI+DNN cause.
- amfd refuses to start on a config it cannot serve NG Setup with. It used to start an AMF
  that failed every NG Setup. The cases:
  - a `plmn_support` entry with no usable S-NSSAI, meaning none configured or every one
    `sst: 0`. The Slice Support List must hold at least one slice (TS 38.413 §9.3.1.17);
  - a `plmn_support` or `guami` list that resolves to nothing: empty, or no entry with a
    usable PLMN ID. The NG Setup Response's PLMN Support List and Served GUAMI List are
    SIZE(1..) (TS 38.413 §9.2.6.2).

  The error names the file, and the PLMN as MCC/MNC. A refused config applies nothing. These
  are the exceptions to lenient config loading (#1060, #1070).
- amfd: a `guami`, `tai`, `plmn_support`, `integrity_order` or `ciphering_order` list in the
  config replaces the AMF's list instead of being appended to it (#1070).

### Upgrade notes
- **Listeners default to loopback, not every interface (#1308, #1305). This can break a
  bare-metal deployment.** A daemon started without a listen address used to bind `0.0.0.0`, so it
  accepted connections on every interface of the host. Now it binds `127.0.0.1` and logs a
  warning at startup that names the setting a remote peer needs. A peer on another host cannot
  reach a loopback listener, so **a bare-metal or host-network deployment that relied on the
  implicit wildcard must now set the address** to one of the host's private addresses (or
  `0.0.0.0`, knowingly):
  - SBI: `--sbi-addr` for ausfd, bsfd, dccfd, easdfd, eesd, lmfd, mbsmfd, nefd, nrfd, nsacfd,
    nssfd, nwdafd, pcfd, pind, tsctsf, ucmfd, udmd and udrd (ausfd, bsfd, dccfd, easdfd, eesd,
    lmfd, mbsmfd, nsacfd, nssfd, nwdafd, pcfd, pind, udmd and udrd also take
    `<nf>.sbi.server[0].address` from the config file, after the flag (#1312); nrfd and the
    others do not), and `smf.sbi.server[0].address` for smfd. amfd (`AMF_SBI_ADDR`), scpd and
    seppd were loopback already and now warn as well.
  - amfd NGAP: `--ngap-addr` (`ip:port`). `amf.ngap.server` in the config file does not set it.
  - smfd N4 PFCP: `SMF_PFCP_ADDR`. Unset, the PFCP Node ID and the CP F-SEID address are now
    `127.0.0.1` too, not a routed address the socket did not listen on.
  - sgwcd: `SGWC_S11_BIND` (S11/S5-C GTP-C) and `SGWC_PFCP_BIND_ADDR` (Sxa).
  - sgwud: `SGWU_GTPU_BIND` (S1-U/S5-U GTP-U) and `PFCP_BIND_ADDR` (Sxa).
  - hssd S6a: `--diameter-addr` or `hss.diameter.addr`. A value that is not an IP address now
    fails startup; it used to fall back to `0.0.0.0`.
  - pcrfd Gx/Rx: `--diameter-addr` (`ip:port`) or `pcrf.diameter.addr`.
  - easdfd DNS/UDP (`dns-udp` feature): `--dns-udp-addr` or `easdf.dns.udp_address`.

  The `/metrics` listeners (#837), upfd and webui were loopback already. mmed's S1-MME and SBc-AP
  are changed separately (#1299). Every shipped deployment now passes its binds explicitly, so
  none of them changes behaviour: `docker/rust/docker-compose.yml` (nrf `--sbi-addr`, amf
  `--ngap-addr`, also in `docker-compose.kernel-sctp.yml`), `docker/rust/docker-compose-epc.yml`
  (hss, pcrf, sgwc, sgwu), `k8s/manifests/{nrf,amf}.yaml` (and so the EKS 5G profile, whose
  amf patch already set `--ngap-addr`), the Helm chart's nrf and amf, and the EKS EPC profile
  (hss, pcrf, sgwc, sgwu). Those binds stay `0.0.0.0` inside the container or pod, which publishes
  nothing beyond `127.0.0.1` (compose) or the cluster network. No published port or NodePort
  changed.
- **PFCP Recovery Time Stamp: upgrade the user plane and the control plane together
  (#1033).** TS 29.244 §8.2.65 defines the Recovery Time Stamp only as NTP-era seconds (since
  1900-01-01). 0.1.x sent Unix seconds; 0.2.0 sends NTP seconds (#995) and reads a received
  stamp as sent. The transition shim that also read a stamp as Unix seconds
  (`nextgcore_pfcp::recovery_time::normalize_received`, in smfd, sgwcd, sgwud and upfd) is
  removed and never shipped in a release. So a 0.1.x peer's stamp now reads as a time about 70
  years off, and restart detection against it (TS 23.007 §19A) is unreliable in a mixed
  0.1.x / 0.2.0 deployment:
  - a changed stamp can be read as a restart, which releases that peer's sessions;
  - a real restart can be missed. A 0.2.0 SGW-C holding a 0.1.x SGW-U's stamp reads the
    upgraded SGW-U's NTP stamp as older (RFC 1982) and does not re-establish its sessions.
    smfd logs that a 0.1.x UPF's stored stamp "is in the future".

  A rolling upgrade from 0.1.x is not supported. Upgrade every PFCP function in one
  maintenance window, in this order:
  1. the user plane: upfd and sgwud;
  2. the control plane straight after: smfd, sgwcd and mbsmfd.

  The 0.1.x control plane takes any changed stamp as a restart, so it sees each upgraded user
  plane function as restarted, which it is. The 0.2.0 user plane then sees each upgraded control
  plane function as restarted, which it also is. Do not upgrade the control plane first. Each
  upgrade restarts its function, so expect PDU sessions and bearers through it to be released
  and set up again. smfd keeps no peer stamps (#966), so a 0.1.x snapshot's
  `upfRecoveryTimeStamps` is ignored.

## [0.2.0] — Unreleased (draft for operator review)

Draft built from the PRs merged into `main` since the 0.1.0 tag (2026-07-02), cross-checked
against `git log 0.1.0..main`. Every bullet cites its PR; the operator reviews this section
before the tag. The validation line is filled from the release run, not carried over.

### Highlights
- **Generated ASN.1 codecs.** NGAP, S1AP, NRPPa, LPP, NR RRC and LTE RRC are generated from
  the 3GPP ASN.1 by the NextgCoreLab/asn1-codegen compiler (pinned at v0.1.0) instead of being
  hand-written (#440, #519, #520, #579). amfd, mmed, lmfd, smfd and mbsmfd encode and decode on
  them (#417, #514, #515 stage PRs below).
- **A real EPC.** mmed, sgwcd/sgwud, hssd and the PGW side of smfd complete an LTE attach with a
  nextgsim eNB and UE, and the EPC stage of the E2E asserts the attach and a 0%-loss ping (#509).
- **Paging and Service Request.** CM-IDLE UEs are paged; a Service Request from CM-IDLE or
  CM-CONNECTED re-activates the user plane and delivers the paged N1 (#516, #521, #550, #652,
  #683, #685).
- **EPS↔5GS interworking over N26**, idle and connected mode, both directions (#409, #416, #474,
  #477, #483, #598, #621, #624).
- **RACS**: a new UCMF NF (`nextgcore-ucmfd`) and the AMF side of RACS (#569, #578, #603).
- **EKS deployment** with `PROFILE=5g|epc|6g`, a UE-to-internet check and pod-restart recovery
  (#127, #656, #660, #663, #681).
- **Nightly gate** on the 0.2.0 UE flows: paging, idle uplink, de-registration, UDM
  re-registration (#651).

### Generated ASN.1 codecs
- New crates `nextgcore-ngap-gen` (#440), `nextgcore-s1ap-gen` (#519), `nextgcore-nrppa-gen`
  and `nextgcore-lpp-gen` (#520), plus the NR/LTE RRC generated crates used by ucmfd (#603);
  the compiler is pinned to NextgCoreLab/asn1-codegen v0.1.0, no longer to a nextgsim commit (#579).
- amfd moved procedure families onto the generated NGAP codec, applying TS 38.413 §10.3.4 error
  handling: NG Setup (#443, #444), UE Context Release (#446), PDU Session Resource Release/Setup
  (#448, #449), Initial Context Setup (#458), NAS transport (#504), Paging (#513), NG Reset
  (#532), Overload Start/Stop (#534), the handover family (#539, #556, #562), Path Switch (#566),
  RAN Configuration Update (#571), Error Indication (#572), MBS (#574), PWS, NRPPa transport and
  PDU Session Resource Notify (#575). Production amfd no longer depends on `nextgcore-asn1c` (#576).
- smfd (#590) and mbsmfd (#597) build their N2 SM transfers on the generated codec; consumers
  outside amfd/smfd/mmed left the hand-written NGAP crate (#623).
- mmed moved all of S1AP onto the generated codec, applying TS 36.413 §10.3.4: S1 Setup (#523),
  NAS transport (#526), Initial Context Setup (#531), UE Context Release (#533), E-RAB management
  (#535), Paging (#538), handover (#543, #551), Reset and Error Indication (#545), Path Switch
  (#547), the rest (#552); the hand-written S1AP codec left production (#555).
- lmfd uses generated NRPPa (#522, #524) and LPP with NR capabilities and the Rel-18 time arms (#544).
- Codec fixes found on the way: extension bits, criticalities and object sets (#456, #463, #464,
  #470), 16,383-octet ceiling lifted (#460), misdecoded eNB TargetID (#556), NG Reset
  connection-list length form (#532).

### LTE / EPC
- S1-MME over SCTP (#153), uplink NAS dispatch into EMM/ESM (#154), a real NAS security context
  (#155), EMM abnormal cases (#156), config parsing (#158).
- S6a: freeDiameter `.conf` parsing (#159), AIR (#160), CLR/IDR (#161), ULR/ULA (#162, #163),
  APN matching (#164), multiplexed instead of serialised (#149); HSS-initiated CLR/NOR/DSR/RSR
  (#282); hssd opens the subscriber store at startup (#484).
- Attach end to end: S11 endpoint on the shared GTP codec (#316), accept content from negotiated
  state (#317), attach reaching S11 (#330), Create Session after the ULA with IMSI and PAA
  (#486), K_eNB derivation (#487), Bearer Contexts and Modify Bearer Request (#499), EBI/ESM
  octet packing (#498), ATTACH/PDN CONNECTIVITY REJECT on a refused Create Session (#494), S1
  release after ATTACH REJECT (#473), protected downlink ESM (#503), and the E2E assertion (#509).
- SGW/PGW: GTP-C path management and restart restoration (#214), Sxa results gating S11 and DDN
  end to end (#312), S5/S8 on both legs (#318, #385, #388, #493, #507, #508), Create Session
  retransmission and configured addresses (#489), Delete/Modify Bearer Command relayed (#634),
  Commands closed on their triggered message (#611).
- sgwud: real Sxa PFCP transport (#302), Error Indication, BAR/DDN buffering, End Marker, QER
  (#216), path failure detection and Node Report (#218, #307), URR usage measurement and reports
  (#266, #269, #427).
- S1AP: missing elementary procedures (#168), setup failure/error indication handling (#165),
  Paging (#166), S1 Status Transfer, data forwarding and Handover Cancel (#337), interworking
  handover types and mapped QCI (#348); E-RAB Release/Modification Indication, Location
  Reporting (#598); Change Notification Request toward the PGW (#616).
- Diameter: application registry and CER/CEA negotiation (#150), Origin-State-Id and bounded
  answers (#148, #286), peer-restart detection (#366), failover with the T flag (#332),
  Message Length < 20 rejected (#617); pcrfd reacts to Event-Triggers and restarted PCEFs (#281,
  #372); hssd/pcrfd parse their YAML Diameter config (#147).

### Paging and Service Request
- Page CM-IDLE UEs and let the Service Request answer the page (#516); deliver the paged N1 and
  re-activate uplink sessions (#521); network-triggered service and idle-mode user-plane
  resumption end to end (#550); a page after a Service Request from CM-IDLE reaches the UE (#652).
- Service Request from CM-CONNECTED re-activates the user plane (#683), with the Service Accept
  in the PDU Session Resource Setup Request (#685); N1N2MessageTransfer and Resource Release to a
  CM-CONNECTED UE (#671); an integrity-protected Registration Request from CM-IDLE (#650).
- NAS fixes behind these flows: Service Request ngKSI/service-type half-octet order (#553), TV
  IEs and the ESR M-TMSI (#639), fixed-layout IEs within their length (#631), every decoder
  returns `Err` on short input (#612).

### EPS↔5GS interworking (N26)
- Non-N26 seam (#345), EBI assignment over Namf and Mapped EPS bearer contexts (#290, #297).
- Idle-mode 5GS→EPS context transfer (#409), connected-mode Forward Relocation (#416).
- EPS→5GS handover with this AMF as target (#474), the PGW-C+SMF side (#477), 5GS→EPS Handover
  Command with the F-Container type (#483), ueEpsPdnConnection consumed on CreateSMContext (#419).
- mmed as EPS→5GS source (#598), data-forwarding tunnels and every EPS bearer as a QoS flow
  (#621), Relocation Cancel (#624), N26/S10 transactions close (#632).

### RACS (TS 23.501 §5.4.4.1a)
- New NF `nextgcore-ucmfd` with Nucmf_UECapabilityManagement and Nucmf_Provisioning (#569);
  TS 36.331/38.331 transcoding, paging derivation and delete notification (#603).
- amfd: Nucmf client, NGAP UE Radio Capability ID mapping and info indication, IE 264, NAS ID (#578).

### 5GC control plane (selected)
- amfd: gNB-initiated NGAP dispatch arms (#120, #222), N2/Xn mobility control plane (#333) and
  the {NH, NCC} chain (#213), the unwired 5GMM procedures (#354), one authoritative UE store
  (#374) and one AmfContext (#371), UE context retrieval from the old AMF (#390), unauthenticated
  emergency registration under operator policy (#389), PWS (#401, #405), Namf producer surface and
  event fire points (#398, #402, #407, #410), UDM dereg-notify handling (#605, #626), AM policy
  termination on every deregistration (#640), one UE id space (#644), several lock-order and
  deadlock fixes (#604, #638, #646, #647).
- amfd **refuses to start** in two cases:
  - a `plmn_support` entry with no usable S-NSSAI (none, or only `sst: 0`; TS 38.413
    §9.3.1.17);
  - a `plmn_support` or `guami` list that resolves to nothing (TS 38.413 §9.2.6.2).

  Check configs before upgrading (#1060, #1070).
- smfd: UE-initiated 5GSM procedures (#224), SM context registration/404s/N2 handover/DDN paging
  (#283), UDM interaction and event exposure (#292, #298), durable PFCP/binding/IP-pool store
  (#279), URR quotas over N4 (#376), dual connectivity and Notify-released sessions (#633), UPF
  restart releases with reactivation (#672), graceful restart keeps the PFCP association (#678),
  `UPF_PFCP_ADDR` accepts a hostname (#665), subscribed default DNN (#265, #364).
- udmd/udrd/pcfd/nrfd/nssfd/bsfd/nsacfd conformance passes (#219, #220, #227–#232, #237–#241,
  #243, #253, #263, #311, #339, #350, #377); RFC 3339 migration onto `nextgcore_sbi::datetime`
  (#246–#250).
- Other NFs: nefd (#33, #199, #268), easdfd (#35, #277, #288), tsctsf (#37, #285, #322), lmfd
  (#278, #324, #358, #559), eesd (#270, #274, #323), dccfd (#275), mbsmfd (#294, #300, #309, #379),
  nwdafd (#169–#177, #198), seppd (#202, #271), scpd (#152, #255–#260).

### SBI and security
- Production SBI security profile on by default for the core NFs, outbound calls follow it (#188,
  #189); fail closed when an OAuth2 token cannot be obtained (#181); UDR audience binding (#182).
- nrfd: authenticated token requester (#185), persisted ES256 signing key (#184), x5c in the CCA
  bound to the NF Instance ID (#395); identity from a verified TLS peer certificate (#195).
- One NFProfile per startup (#394), deregister on shutdown and a validityPeriod-bounded discovery
  cache (#244), re-register on a 404 heartbeat (#437), evict a cached profile on transport failure
  (#438), redial a dead pooled connection (#565), resend to a peer restarted at a new address
  (#670), route SM Context Update/Release to the SMF holding the context (#679).
- §6.4.2.2 overload abatement by default (#383); OAuth2 overlay shows the secure posture (#391).
- Hybrid X25519MLKEM768 TLS under the `pqc-tls` feature (#30).
- webui no longer returns subscriber keys, authenticates `/api`, and has no default admin (#179);
  SQN stored as BSON Int64 (#137).

### Deployment
- **Upgrade together (PFCP wire format):** two IE encodings are now spec-correct, and an
  upgraded and a non-upgraded peer disagree on them until both sides are upgraded:
  - Apply Action octets 5 and 6 (TS 29.244 §8.2.26): smfd and upfd (#1008, #1019);
  - the Remote GTP-U Peer V4/V6 flags (§8.2.70, Figure 8.2.70-1: bit 1 V6, bit 2 V4) in
    the shared `nextgcore-pfcp` codec: sgwud with sgwcd, and upfd with smfd, for the
    PFCP Node Report (#994, #1028).
  A rolling upgrade must move each CP/UP pair at the same time.
- **Operational change:** smfd registers with the NRF as `UNDISCOVERABLE`. It turns `REGISTERED`
  only once the N4 association its new sessions use is up, and goes back to `UNDISCOVERABLE`
  while that association is down (TS 29.510 Table 6.1.6.3.7-1, §5.2.2.3.2). A restarted SMF
  is no longer discovered before it has a UPF.
  - amfd re-selects an SMF on a 504 UPF_NOT_RESPONDING within the #796 window, instead of
    answering 5GSM #26.
  - upfd holds a Setup from an address its host-named PFCP allowlist does not list, while the
    names are re-resolved off the receive task, and judges it against the fresh answer. Still
    fail-closed (#1112).
- **Deploy together (GTPv2-C S5/S8):** smfd (PGW-C) and sgwcd (SGW-C) now put every
  F-TEID at the IE instance TS 29.274 gives it (#1113):
  - smfd's Create Session Response carries the PGW S5/S8-C F-TEID at instance 1 (Table
    7.2.2-1). It was at 0, so sgwcd stored PGW TEID 0 and relayed no Delete Session on
    detach, and the PGW session, its PGW-U PFCP session and the UE address leaked;
  - smfd's F-TEIDs are well-formed for IPv6-only S5/S8 addresses (no V4 flag without an
    IPv4 address) and carry the S2b interface types 32/33 untruncated;
  - smfd's Create Bearer Request carries the S5/S8-U PGW F-TEID at instance 1 (Table
    7.2.3-2), with its mandatory TFT and Charging Id;
  - sgwcd builds the S5/S8 Modify Bearer Request with the S5/S8-U SGW F-TEID at instance 1
    (Table 7.2.7-2). It has no production caller yet; smfd also accepts the old instance 2
    when its interface type is S5/S8 SGW GTP-U.

  The detach leak ends when smfd is upgraded. An upgraded sgwcd also reads an old smfd's
  instance-0 F-TEID when its interface type names the PGW, so a rolling upgrade in either
  order does not leak. Upgrade both in the same rollout all the same.
- smfd answers PFCP Node Reports and acts on user plane path failure and recovery; a
  path still down after `SMF_UP_PATH_FAILURE_HOLD_SECS` (default 120 s) releases its
  sessions with #39 (#994, #1028).
- **Operational change:** smfd, sgwcd, upfd, sgwud and mbsmfd refuse to start when the local
  clock reads before 2020-01-01, because their PFCP Recovery Time Stamp, now NTP-era seconds per
  TS 29.244 §8.2.65 (#995, #1004), would be wrong. On RTC-less hosts, start them after
  `time-sync.target`, give the pod an NTP-wait init container, or rely on the restart policy
  (#1040). See the configuration overview, "A set clock is required". 0.2.0 does not read a
  0.1.x peer's Unix-seconds stamp: upgrade the user plane, then the control plane, in one
  window. See "Upgrade notes" under [Unreleased] (#1033).
- EKS overlay for the matched-pair E2E on a shared cluster (#127), image tags by git SHA (#146,
  #431), rollout reporting (#439).
- `deploy/eks` script interface `PROFILE=5g|epc|6g` (#656), `e2e-internet.sh` UE-to-internet
  check (#660), re-runs keep live MongoDB storage and UPF data-plane modes (#663), 5G peers
  addressed by Service name with the pinned-peer restarts dropped (#681).
- k8s base advertises pod IPs and seeds idempotently (#135); the Helm chart renders a working
  5GC control plane (#136); SBI-profile opt-out fixed in k8s/Helm (#432).
- Docker: UDR durable state on by default (#194), PGW-C/PGW-U deployed for S5/S8 (#385), pinned
  builder toolchain (#138), scoped build-context ignore (#140).

### CI and release
- Cross-repo E2E runs nightly (#378); a nightly gate on the 0.2.0 UE flows (#651).
- Each E2E run records the (nextgcore, nextgsim) commit pair it validated (#425); a release is cut
  by promoting an E2E-validated pair (#426).
- A failed NF image build fails `docker-build` (#424); every cargo feature compiles and CI checks
  all features (#466); EPC bring-up asserted on real readiness (#381).

### Fuzzing
- `src/fuzz` builds as its own workspace and every target drives the real decoders, including the
  generated NGAP/S1AP/NRPPa/LPP codecs (#599).

### SCTP
- The patched pure-Rust `sctp-proto` lives in `src/vendor/sctp-proto` and the userspace backend
  carries the PPID verbatim (#468); the kernel backend reassembles partial deliveries until
  `MSG_EOR` (#517), pins its structs against libc's ABI (#429, #442); the dead userspace client
  was removed and the kernel client kept (#441). Diameter over kernel SCTP behind a default-off
  feature (#151).

### 6G research prototypes (feature-gated, off by default)
- HTTP/3 SBI transport spike (#28), ISAC sensing pipeline (#29), NTN timing advance (#31),
  compute-aware UPF selection (#34), per-NF energy metrics (#36), intent-driven policy loop (#38),
  network-state snapshot (#39), NWDAF inference with an ONNX subset (#40), slice-SLA observe loop (#41).

### Removed
- Hand-written codecs: E1AP/F1AP/XnAP modules in `nextgcore-asn1c` (#459), the hand-written LPP
  codec and its UPER engine (#563), the hand-written NRPPa codec (#527), the hand-written S1AP
  oracle (#560).
- Dead code that read as working: the udmd state-machine SBI half (#262) and a second Nudm
  implementation (#243), bsfd/nwdafd registries (#245), upfd rule and session models (#336, #342),
  seppd security modules (#271).

### Fixed (test isolation)
- Process-global test locks declared beside their globals and fixtures in per-process temp dirs
  (#314, #367, #369, #567, #568, #604, #610, #615, #642, #674).

### Known limitations / deferred to next release
Issues labelled `post-0.2.0` (open, as of this draft):
- #686 amfd: an AMF restart loses every UE context (no AMF restoration); each UE re-registers.
- #668 amfd: no NRF NF-status subscription; a changed peer profile is noticed only on failure.
- #653 amfd: no service restoration after a radio link failure when the mobility update has no
  follow-on request.
- #641 mmed / #619 smfd (PGW-C): no dedicated EPS bearer activation.
- #614, #607 sgwcd: Change Notification and bearer Responses are not relayed to the PGW.
- #630 nextgcore-nas: a malformed optional IE fails the message instead of being ignored.
- #655 pcfd, #654 ausfd: dead C-port handlers that would re-take a held context lock.
- #643 clippy: 77 `await_holding_lock` warnings in amfd test code.
- #417 amfd/smfd/mmed: the hand-written NGAP crate is not yet fully deleted.

### Validation
- _To be filled from the release run (`cargo test --workspace`, clippy, fmt, nightly E2E pair)._

## [0.1.0] — 2026-07-02

First release aligning the core with the 3GPP Rel-15/16/17/18 procedures and adding a
full matched-simulator data-plane validation path. 25 NF binaries + 17 shared libraries,
zero C dependencies. Dual 5G-SA / 4G-EPS (5GS↔EPS interworking retained).

### Added
- **One-command matched-sim E2E** (`docker/rust/e2e.sh`): disk preflight (#269 guard) →
  build → registration + PDU session + user-plane ping through the GTP-U tunnel. **84/84 green.**
- **Positioning** (lmfd↔amfd): LMF-initiated LPP/NRPPa over Namf_Communication N1N2,
  uplink NRPPa ingest, measurement-derived location fixes (TS 23.273 / 29.572 / 37.355 / 38.455).
- **UE policy** (pcfd): URSP delivery via a real UPDP codec and N1 chain (TS 24.501 Annex D / 24.526).
- **SoR/UPU Part B** (udmd/ausfd): SoR-MAC-IAUSF / UPU-MAC-IAUSF (TS 33.501 §6.14/6.15).
- **SIDF** (udmd): SUCI de-concealment at the UDM; the UDR only ever sees the SUPI (§6.12).
- **NRF security** (nrfd): CCA ES256-JWS verification + token-requester transport auth (TS 29.510 §13.3.8.3).
- **SEPP** (seppd): N32-c certificate signing-key path.
- **Standard OAuth2** on the SBI layer (`/oauth2/token`, TS 29.510).
- **Edge** (eesd): spec-exact ACInfoSubscription / EECContextPush bodies + notifier.
- **MBS** (mbsmfd): N2 multipart ContextUpdate + NGAP MBS transfer ASN.1 (TS 29.532).
- **Analytics** (nwdafd): real per-NF NF_LOAD ingestion via NRF NFStatusSubscribe (TS 29.520).
- **Slice admission** (nsacfd): slice-quota provisioning from config (TS 29.536 §6.1.3.4).
- **Test infrastructure**: amfd/pcfd/udmd/ausfd/bsfd split into lib+bin so cross-NF tests
  drive the peer's real handler; hand-derived golden byte-vectors for the wire encoders.

### Fixed
- **nsacfd** did not provision its configured slice quotas → 403'd every PDU session
  (5GSM cause #67), taking down the whole data plane. Now provisioned per TS 29.536, with an
  SST-wide quota covering SD-specific requests.
- **amfd** never discovered the NSACF on-demand and dropped NSACF NRF profiles → slice admission
  was silently degrade-open. On-demand NRF discovery added (TS 29.510).
- NAS/NGAP/PFCP wire fixes across the fleet (e.g. amfd T3512 GPRS-timer unit, smfd PFCP PDI
  UE-IP S/D flag, udrd SQN side-effects).
- CI-flaky tests sharing a process-global NF context / env under parallel `cargo test`
  serialized on a per-crate test guard (nsacfd, udmd, ausfd).

### Changed
- Documentation synced with the code (getting-started, docker/E2E, per-component gap docs, NF table).
- Honesty pass: dropped "production-ready" framing; 6G/Rel-20 items are research prototypes.

### Validation
- `cargo test --workspace`: 5170 passed / 0 failed · `clippy`: 0 errors · `fmt`: clean · Docker E2E: 84/84.

## [0.0.1] — 2026-03-08
- Initial public tag.
