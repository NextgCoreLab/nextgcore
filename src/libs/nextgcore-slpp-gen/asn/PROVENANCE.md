# Provenance of `slpp-19.2.0.asn`

| | |
|---|---|
| Source | 3GPP TS 38.355 V19.2.0 (2026-06), `38355-j20.docx` inside `38355-j20.zip` from `https://www.3gpp.org/ftp/Specs/archive/38_series/38.355/` (`6g_docs/specs/38355-j20.docx`) |
| Source sha256 | `8371673f6dd651c8133ec36d05707556eb3beb1c26e4f306774df5f9b58683ef` (the .docx alone, and also the zip member) |
| Output sha256 | `04e13f314eb41a000fea50ffd88c5100ce2a59131ece7bc132e2076e76812d6f` |
| Modules | SLPP-PDU-Definitions, SLPP-PDU-CommonContents, SLPP-PDU-CommonSL-PRS-MethodsContents, SLPP-PDU-SL-AoA-Contents, SLPP-PDU-SL-RTT-Contents, SLPP-PDU-SL-TDOA-Contents, SLPP-PDU-SL-TOA-Contents, NR-DiscoveryMessageMetaDataContents |

## Method (reproducible)

```bash
python3 nextgsim/tools/extract_asn1.py 38355-j20.docx slpp-19.2.0.asn
sha256sum slpp-19.2.0.asn   # must match the table above
```

No flags are used: the extraction is verbatim. No `--` comment in the
document is glued to a preceding token (`grep -E '[A-Za-z0-9]--'` returns
nothing), so `--space-glued-comments` is not needed.

## The module merge in build.rs

The eight modules import from each other in a cycle.
SLPP-PDU-Definitions imports every method's contents, and each contents
module imports `maxNrOfUEs`, `nrMaxBands` and the common types back from
SLPP-PDU-Definitions. The pinned asn1-codegen (`aa0db6c`) sorts MODULES
topologically, and a cycle drops silently out of that sort, so compiling
this file as-is generates only `NR-DiscoveryMessageMetaDataContents`
(three types, and `SLPP_Message` does not exist).

`build.rs` therefore compiles a single module, written to `OUT_DIR`, made
from the eight bodies with their IMPORTS clauses removed. This file is not
edited. The merge cannot change an encoding:

- every module is `AUTOMATIC TAGS`, and PER does not encode tags;
- no module has an EXPORTS clause, so each one exports everything;
- the build stops if a name is assigned twice, if any import names a module
  that does not define it, or if the module count is not 8.

The proper fix is module-cycle support in asn1-codegen. Once that lands,
the merge can go.
