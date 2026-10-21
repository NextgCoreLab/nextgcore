# Provenance of `rrc-19.3.0.asn1`

| | |
|---|---|
| Source | 3GPP TS 38.331 V19.3.0 (`6g_docs/specs/38331-j30.docx`, sha256 `9f95ee3b0cf0a4cf81bfe4fb97f073c17f4a24503fde40e6f9e1d3b2b8352e39`) |
| Output sha256 | `73f13736e14c0fc91514ada8898cbcd63876d18618e35fcb193223b679cfcdba` |
| Modules | NR-RRC-Definitions, NR-UE-Variables, NR-Sidelink-Preconf, NR-Sidelink-DiscoveryMessage, NR-InterNodeDefinitions |

Byte-identical to nextgsim `tools/rrc-19.3.0.asn1` (what `nextgsim-rrc` generates
from) and to asn1-codegen `codegen-golden/schemas/rrc-19.3.0.asn1` at the pinned
rev 6d75c49, whose golden test is what keeps the pinned compiler able to compile
it. `NR-InterNodeDefinitions` carries `UERadioAccessCapabilityInformation` and
`UERadioPagingInformation` (§11.2), the two types the UCMF needs (#585).

Upgrading: take the newer file from nextgsim `tools/` (or re-extract with
`nextgsim/tools/extract_asn1.py`), update both sha256 values here.
