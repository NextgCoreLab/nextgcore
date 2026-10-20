# s1ap-19.2.0.asn provenance

| field | value |
|---|---|
| specification | 3GPP TS 36.413 (S1AP), V19.2.0 (2026-06) |
| source document | `36413-j20.docx`, from `https://www.3gpp.org/ftp/Specs/archive/36_series/36.413/` (also `6g_docs/specs/36413-j20.docx`) |
| source sha256 | `a4f845161803b1a77659175795c635cf09b6711dd77f11f7f68702b551c07ae7` |
| output sha256 | `c3d60594ecb7dbc730efe740b66f05f91dfd1fd69344353dea3372b1a9d2ac62` |
| lines | 8,397 |
| modules | S1AP-PDU-Descriptions, S1AP-PDU-Contents, S1AP-IEs, S1AP-CommonDataTypes, S1AP-Constants, S1AP-Containers (§9.3.2–§9.3.7) |
| excluded | `SonTransfer-IEs` (Annex B): the SON Transfer application's IE module, carried inside transparent containers and imported by no S1AP module |

## Method (reproducible)

Extracted in this repo, not copied, with `../tools/extract_asn1.py` (a copy of
nextgsim's `tools/extract_asn1.py`):

```bash
python3 -I tools/extract_asn1.py 36413-j20.docx asn/s1ap-19.2.0.asn \
    --skip-module SonTransfer-IEs
sha256sum asn/s1ap-19.2.0.asn   # must match the table above
```

The script reads the paragraphs of `word/document.xml` one per line and keeps
the text between each `-- ASN1START` / `-- ASN1STOP` pair. It reads the `.docx`,
not a pandoc `.txt`, because pandoc wraps long paragraphs and a wrapped `--`
comment turns its tail into schema text.

The output is **byte-identical** to nextgsim's `tools/s1ap-19.2.0.asn` (same
sha256), so both repos compile one schema with one compiler while each keeps
its own generated codec (nextgsim #45: the simulator's codec stays independent
of the core it tests).

## Upgrading

Download the newer `36413-xNN.docx`, rerun the command above into
`asn/s1ap-<version>.asn`, point `build.rs` at it, and update this table,
including both sha256 values.
