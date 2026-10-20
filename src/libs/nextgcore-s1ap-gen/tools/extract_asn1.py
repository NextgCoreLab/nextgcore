#!/usr/bin/env python3
"""Extract the ASN.1 modules from a 3GPP specification .docx.

3GPP marks every normative ASN.1 block with a ``-- ASN1START`` paragraph and
closes it with ``-- ASN1STOP``. This script reads the document's paragraphs
directly from ``word/document.xml`` -- one paragraph per output line, with tabs
and line breaks kept -- and writes the text between each START/STOP pair.

Reading the .docx rather than a pandoc ``.txt`` matters: pandoc's plain-text
writer wraps long paragraphs, and a wrapped ``--`` comment turns its tail into
schema text. Stdlib only, so it runs anywhere Python 3 does.

Usage:
    extract_asn1.py SPEC.docx OUT.asn [--blocks N] [--skip-module NAME ...]
                                      [--only-module NAME ...]
                                      [--space-glued-comments]

``--blocks N`` keeps only the first N blocks; ``--skip-module`` drops every block
belonging to module NAME (e.g. an annex-defined module that the main protocol
does not import); ``--only-module`` keeps only the blocks of the named modules.

A module may span many blocks: TS 36.413 gives each module one block, but
TS 36.331 opens ``EUTRA-RRC-Definitions`` in one block and then delimits every
message and IE definition separately, ~560 blocks before its ``END``. So a
block belongs to the module whose header block most recently preceded it.

``--space-glued-comments`` inserts one space before a ``--`` that directly
follows a letter or digit (TS 36.331 V19.4.0 has two: ``OPTIONAL-- Need OR``).
X.680 §12.6.2 starts a comment at ``--`` wherever it appears and §12.3 forbids
``--`` inside an identifier, so the edit cannot change the schema's meaning; it
exists because the vendored asn1-compiler tokenizer reads ``OPTIONAL--`` as one
identifier. It is opt-in so that every other extraction stays verbatim.
"""
import argparse
import re
import sys
import zipfile
import xml.etree.ElementTree as ET

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


def paragraphs(docx):
    with zipfile.ZipFile(docx) as z:
        root = ET.fromstring(z.read("word/document.xml"))
    for p in root.find(W + "body").iter(W + "p"):
        parts = []
        for el in p.iter():
            if el.tag == W + "t":
                parts.append(el.text or "")
            elif el.tag == W + "tab":
                parts.append("\t")
            elif el.tag in (W + "br", W + "cr"):
                parts.append("\n")
        # Non-breaking and other exotic spaces are not ASN.1 whitespace.
        yield "".join(parts).replace(" ", " ").replace("‑", "-")


def blocks(lines):
    cur = None
    for line in lines:
        s = line.strip()
        if s == "-- ASN1START":
            cur = []
        elif s == "-- ASN1STOP":
            if cur is not None:
                yield cur
            cur = None
        elif cur is not None:
            cur.append(line)


GLUED_COMMENT_RE = re.compile(r"([A-Za-z0-9])--")
MODULE_RE = re.compile(r"^([A-Z][A-Za-z0-9-]*)\s*(\{|DEFINITIONS|$)")


def module_name(block):
    for line in block:
        s = line.strip()
        if not s or s.startswith("--"):
            continue
        m = MODULE_RE.match(s)
        return m.group(1) if m else None
    return None


def is_module_header(block):
    """True when the block opens a module: a ``DEFINITIONS ... ::=`` line before
    ``BEGIN``. The name, OID and DEFINITIONS may span several lines (TS 36.413
    puts the OID on its own lines), and comment lines may precede them."""
    for line in block:
        s = line.strip()
        if s == "BEGIN":
            return False
        if "DEFINITIONS" in s and "::=" in s:
            return True
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("docx")
    ap.add_argument("out")
    ap.add_argument("--blocks", type=int)
    ap.add_argument("--skip-module", action="append", default=[])
    ap.add_argument("--only-module", action="append", default=[])
    ap.add_argument("--space-glued-comments", action="store_true")
    a = ap.parse_args()
    out = []
    kept = []
    current = None
    for i, b in enumerate(blocks(paragraphs(a.docx))):
        if a.blocks is not None and i >= a.blocks:
            break
        name = module_name(b)
        if is_module_header(b):
            current = name
        if current in a.skip_module:
            continue
        if a.only_module and current not in a.only_module:
            continue
        if is_module_header(b):
            kept.append(name)
        if a.space_glued_comments:
            b = [GLUED_COMMENT_RE.sub(r"\1 --", line) for line in b]
        out.append("\n".join(b).rstrip() + "\n")
    with open(a.out, "w", encoding="utf-8") as f:
        f.write("\n".join(out))
    print("modules:", ", ".join(str(k) for k in kept), file=sys.stderr)


if __name__ == "__main__":
    main()
