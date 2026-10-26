#!/usr/bin/env python3
"""Extract the ASN.1 modules of a 3GPP specification .docx that has no
``-- ASN1START`` / ``-- ASN1STOP`` markers (TS 29.168, SBc-AP).

Each module runs from its header paragraph -- ``NAME {`` followed by the OID,
then ``DEFINITIONS AUTOMATIC TAGS ::=`` -- to the first paragraph that is
exactly ``END``. Paragraphs are read from ``word/document.xml`` one per line,
as ``extract_asn1.py`` does, so a long comment is never wrapped into schema
text. The comment banner just above each header is kept.

Usage: extract_modules.py SPEC.docx OUT.asn --prefix SBC-AP-
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
        yield "".join(parts).replace(" ", " ").replace("‑", "-")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("docx")
    ap.add_argument("out")
    ap.add_argument("--prefix", required=True)
    a = ap.parse_args()
    header = re.compile(r"^" + re.escape(a.prefix) + r"[A-Za-z0-9-]+\s*\{")
    lines = list(paragraphs(a.docx))
    out, names, i = [], [], 0
    while i < len(lines):
        if header.match(lines[i]):
            # Keep the comment banner that precedes the header.
            j = i
            while j > 0 and lines[j - 1].lstrip().startswith("--"):
                j -= 1
            k = i
            while k < len(lines) and lines[k].strip() != "END":
                k += 1
            if k == len(lines):
                sys.exit(f"module at paragraph {i} has no END")
            names.append(lines[i].split("{")[0].strip())
            out.extend(lines[j : k + 1])
            out.append("")
            i = k + 1
        else:
            i += 1
    with open(a.out, "w", encoding="utf-8") as f:
        f.write("\n".join(out))
    print("modules:", ", ".join(names))


if __name__ == "__main__":
    main()
