# Provenance of `lpp-19.3.0.asn`

| | |
|---|---|
| Source | 3GPP TS 37.355 V19.3.0, `37355-j30.docx` from `https://www.3gpp.org/ftp/Specs/archive/37_series/37.355/` (`6g_docs/specs/37355-j30.docx`) |
| Source sha256 | `bae72f96ce4340cd2a8e36f702d87f8e815e24395246de2e6af9f3eb49336345` |
| Output sha256 | `2c9e73f44cd7ae6a2118521f1d42c29426af2e066bc2d59c6ea0ca5b7bd5b563` |
| Modules | LPP-PDU-Definitions, LPP-Broadcast-Definitions |

## Method (reproducible)

```bash
python3 nextgsim/tools/extract_asn1.py 37355-j30.docx lpp-19.3.0.asn --space-glued-comments
sha256sum lpp-19.3.0.asn   # must match the table above
```

`--space-glued-comments` inserts one space before two `--` comments that the
.docx glues to the preceding token (`OPTIONAL-- Need OR`,
`AlmanacNavIC-AlmanacSet2-r19-- Model-9`). X.680 §12.6.2 starts a comment at
`--` wherever it appears and §12.3 forbids `--` inside an identifier, so the
edit cannot change the schema; the vendored tokenizer would otherwise read
`OPTIONAL--` as one identifier. Without the flag the output sha256 is
`8eab92435fc611f7e0206654b7d355fa06a27111300fd806b4db3b2321976ea0`.

## Known limitation

The forked asn1-compiler does not generate SEQUENCE extension additions
(nextgsim #253), and every NR positioning method in LPP (nr-DL-TDOA,
nr-Multi-RTT, nr-ECID, sidelink ranging) is carried in an addition group of the
r9 IEs. Until that is fixed this crate represents only the root (LTE-era)
content; `src/tests.rs` pins the limitation.
