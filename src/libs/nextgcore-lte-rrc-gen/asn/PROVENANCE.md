# Provenance of `lte-rrc-19.4.0.asn` and `lte-rrc-internode-19.4.0.asn`

| | |
|---|---|
| Source | 3GPP TS 36.331 V19.4.0 (`6g_docs/specs/36331-j40.docx`, sha256 `26407c6c0ae31fd5da09eb81f7e9cd8cf49c0c51606811b13ce15a2e326fe058`) |
| `lte-rrc-19.4.0.asn` sha256 | `d3a80171a15fb8ebfe99e73883021dd63f483e5c2058194a7d0d8326065e9084` (EUTRA-RRC-Definitions) |
| `lte-rrc-internode-19.4.0.asn` sha256 | `772d2cd0875d9f676ac96bb8d89f13ad16d60e9b4e332d425780a825b2036965` (EUTRA-InterNodeDefinitions) |

## Method (reproducible)

```bash
python3 nextgsim/tools/extract_asn1.py 36331-j40.docx lte-rrc-19.4.0.asn \
    --only-module EUTRA-RRC-Definitions --space-glued-comments
python3 nextgsim/tools/extract_asn1.py 36331-j40.docx lte-rrc-internode-19.4.0.asn \
    --only-module EUTRA-InterNodeDefinitions --space-glued-comments
```

The first file is byte-identical to nextgsim `tools/lte-rrc-19.4.0.asn` (see its
`LTE-RRC-PROVENANCE.md` for the one whitespace edit `--space-glued-comments`
makes). The second is the inter-node module nextgsim does not vendor; the UCMF
needs it for `UERadioAccessCapabilityInformation` and `UERadioPagingInformation`
(§10.2), the S1AP-carried forms of the UE radio capability (#585).
