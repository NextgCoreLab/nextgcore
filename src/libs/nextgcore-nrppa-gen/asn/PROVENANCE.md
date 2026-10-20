# Provenance of `nrppa-19.2.0.asn`

| | |
|---|---|
| Source | 3GPP TS 38.455 V19.2.0, `38455-j20.docx` from `https://www.3gpp.org/ftp/Specs/archive/38_series/38.455/` (`6g_docs/specs/38455-j20.docx`) |
| Source sha256 | `7f0fedbd4fb1b2a2da9c3b696918eb65058c2eedd4f003fef344cbf2b88c4580` |
| Output sha256 | `f4995cfa8229bd64246e210405a376c27ab7f739180ef4a01634ba6dbb904b3d` |
| Modules | NRPPA-PDU-Descriptions, NRPPA-PDU-Contents, NRPPA-IEs, NRPPA-CommonDataTypes, NRPPA-Constants, NRPPA-Containers (§9.3.2–§9.3.7) |

## Method (reproducible)

```bash
python3 nextgsim/tools/extract_asn1.py 38455-j20.docx nrppa-19.2.0.asn
sha256sum nrppa-19.2.0.asn   # must match the table above
```

The extractor is nextgsim's `tools/extract_asn1.py` (see nextgsim
`tools/S1AP-PROVENANCE.md`): it reads the `.docx` paragraphs from
`word/document.xml` and keeps the text between each `-- ASN1START` /
`-- ASN1STOP` pair, verbatim. No other edits.

## Relation to nextgsim's `tools/nrppa-19.2.0.asn1`

nextgsim's copy, which has no recorded provenance, is the same schema: compared
with `diff -w -B` the only differences are inside comments (it has straight
quotes and a hyphen where the .docx has typographic quotes and an en dash) and
trailing whitespace. This crate keeps the verbatim extraction so its sha256 is
reproducible from the 3GPP source.
