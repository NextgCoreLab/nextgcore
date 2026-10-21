# ngap-17.9.asn provenance

| field | value |
|---|---|
| specification | 3GPP TS 38.413 (NGAP), Release 17, V17.9.0 |
| copied from | `NextgCoreLab/nextgsim` `tools/ngap-17.9.asn` at `67a0d792b5b3990258ca0b3d7517dfdc17359e41` |
| upstream history | added in nextgsim `77f4b04` (2026-01-04); no later commit touches it -- still byte-identical at `2f27979f178fc68ab47f2d7f19c9d4733555f561`, the nextgsim rev the compiler was pinned to from nextgsim #253 / PR #256 until the compiler moved to NextgCoreLab/asn1-codegen v0.1.0 (`6d75c49`, its own repository; the schema itself stays here) (previously `f2d8a59`, before that `f545a28`, before that `aa3dc2b`, before that `fbc8284`, before that `6b97b4b`, before that `20495c0`, before that `67a0d79`) |
| lines | 12,004 |
| sha256 | `cac6d7255af905913fb84cf8983ff60d945b5be3afbcb4b1aad46834baa534fd` |

Copied byte for byte. Do not edit it here. It must stay identical to the module
nextgsim generates from, so that both repos compile one schema with one compiler
(see the dependency comment in the workspace `src/Cargo.toml`).

**What is not known.** The release comes from the file name. nextgsim does not
record how the module was extracted from the specification. If the file is ever
re-extracted, for example to move to a later release, use nextgsim #45's method:
take the ASN.1 from the `PL` paragraphs of the `.docx`, not from the flattened
`.txt`. In the `.txt`, wrapped comment tails survive as bare identifiers, and the
compiler's `parse_object_set` then loops forever. Record the source document, its
version and the extraction command here when you do.
