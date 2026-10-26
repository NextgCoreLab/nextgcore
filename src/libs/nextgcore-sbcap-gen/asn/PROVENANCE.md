# sbcap-19.0.0.asn provenance

| field | value |
|---|---|
| specification | 3GPP TS 29.168 (SBc-AP), V19.0.0 |
| source document | `29168-j00.docx` (`6g_docs/specs/29168-j00.docx`) |
| source sha256 | `cdac77e14d6d9aebeff490ff8c0ecce9d35c9fdb9bc93f69a92a94736c4e0652` |
| output sha256 | `c1ac49b3895f89275af71f5894d6809f867bf2763b864cf72341e09b0e0e26dd` |
| lines | 1,417 |
| modules | SBC-AP-PDU-Descriptions, SBC-AP-PDU-Contents, SBC-AP-IEs, SBC-AP-CommonDataTypes, SBC-AP-Constants, SBC-AP-Containers (§4.4.3–§4.4.8) |

## Method (reproducible)

TS 29.168 has no `-- ASN1START` / `-- ASN1STOP` markers, so `extract_asn1.py`
does not apply. `../tools/extract_modules.py` reads the paragraphs of
`word/document.xml` one per line (so no comment is wrapped into schema text) and
keeps each module from its `SBC-AP-… {` header (with the comment banner above
it) to its `END`:

```bash
python3 -I tools/extract_modules.py 29168-j00.docx asn/sbcap-19.0.0.asn \
    --prefix SBC-AP-
sha256sum asn/sbcap-19.0.0.asn   # must match the table above
```

## Upgrading

Download the newer `29168-xNN.docx`, rerun the command into
`asn/sbcap-<version>.asn`, point `build.rs` at it, and update this table.
