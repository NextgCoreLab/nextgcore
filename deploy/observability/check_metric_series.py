#!/usr/bin/env python3
"""Every series a shipped Prometheus rule or Grafana dashboard queries must be
exported by some NF (#1334).

A rule that queries a series no process emits never fires, and a panel on one is
always empty; both look like coverage and are not. This check reads every rule
file (`groups:` / `rules:` / `expr:`) and every Grafana dashboard JSON (`"expr"`)
in the tree, extracts the metric names their PromQL selects, and requires each to
be one of:

- a name that appears in a string literal of the non-test source of an NF daemon
  (`src/bins/*/src`) or of the shared exposition (`src/libs/nextgcore-metrics/src`).
  A histogram's `_bucket` / `_sum` / `_count` series match its base name;
- a series Prometheus itself synthesises for every target (`up`,
  `scrape_duration_seconds`, ...);
- a name a rule file records (`record:`).

Usage: check_metric_series.py [REPO_ROOT]   (default: the repository root)
Exit status 1 lists each unexported series with the files that query it.
"""

import json
import pathlib
import re
import sys

import yaml

PROMETHEUS_SYNTHETIC = {
    "up",
    "scrape_duration_seconds",
    "scrape_samples_scraped",
    "scrape_samples_post_metric_relabeling",
    "scrape_series_added",
    "ALERTS",
    "ALERTS_FOR_STATE",
}

PROMQL_KEYWORDS = {
    "and", "or", "unless", "bool", "offset", "by", "without", "on", "ignoring",
    "group_left", "group_right", "inf", "nan", "Inf", "NaN", "atan2",
}

HISTOGRAM_SUFFIXES = ("_bucket", "_sum", "_count")

SKIP_DIRS = {".git", "target", "node_modules", "vendor", "fuzz"}


def series_in_expr(expr):
    """The metric names a PromQL expression selects."""
    s = re.sub(r'"(?:\\.|[^"\\])*"', '""', expr)
    s = re.sub(r"'(?:\\.|[^'\\])*'", "''", s)
    s = re.sub(r"`[^`]*`", "``", s)
    s = re.sub(r"\{[^}]*\}", " ", s)  # label matchers
    s = re.sub(r"\[[^\]]*\]", " ", s)  # range and subquery selectors
    # Label lists of aggregation and vector-matching modifiers.
    s = re.sub(
        r"\b(by|without|on|ignoring|group_left|group_right)\s*\([^)]*\)", " ", s
    )
    names = set()
    for m in re.finditer(r"[a-zA-Z_:][a-zA-Z0-9_:]*", s):
        tok = m.group(0)
        before = s[m.start() - 1] if m.start() > 0 else " "
        if before.isdigit() or before in ".$":
            continue  # 1e3, 0.5e-3, or a Grafana $variable
        if s[m.end():].lstrip().startswith("("):
            continue  # a function
        if tok in PROMQL_KEYWORDS:
            continue
        names.add(tok)
    return names


def walk(root, suffixes):
    for p in root.rglob("*"):
        if p.suffix in suffixes and not (set(p.relative_to(root).parts) & SKIP_DIRS):
            yield p


def rule_files(root):
    for p in walk(root, {".yml", ".yaml"}):
        try:
            docs = list(yaml.safe_load_all(p.read_text()))
        except Exception:
            continue
        for doc in docs:
            if isinstance(doc, dict) and isinstance(doc.get("groups"), list):
                if any(isinstance(g, dict) and "rules" in g for g in doc["groups"]):
                    yield p, doc


def dashboard_exprs(node):
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "expr" and isinstance(v, str):
                yield v
            else:
                yield from dashboard_exprs(v)
    elif isinstance(node, list):
        for v in node:
            yield from dashboard_exprs(v)


def strip_rust_tests(src):
    """`src` without its `#[cfg(test)]` items, and its string-literal contents."""
    out_literals = []
    i, n = 0, len(src)
    depth_skip = None  # brace depth at which a skipped test item ends
    depth = 0
    pending_test = False
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
            continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if src.startswith("#[cfg(test)]", i):
            pending_test = True
            i += len("#[cfg(test)]")
            continue
        raw = re.match(r'b?r(#*)"', src[i:i + 16])
        if raw:
            hashes = raw.group(1)
            start = i + raw.end()
            end = src.find('"' + hashes, start)
            end = n if end < 0 else end
            if depth_skip is None:
                out_literals.append(src[start:end])
            i = end + 1 + len(hashes)
            continue
        if c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            if depth_skip is None:
                out_literals.append(src[i + 1:j])
            i = j + 1
            continue
        if c == "'":
            m = re.match(r"'(\\.|[^'\\])'", src[i:i + 6])
            if m:
                i += m.end()
                continue
        if c == "{":
            if pending_test and depth_skip is None:
                depth_skip = depth
            pending_test = False
            depth += 1
        elif c == "}":
            depth -= 1
            if depth_skip is not None and depth == depth_skip:
                depth_skip = None
        elif c == ";" and pending_test and depth_skip is None:
            pending_test = False  # `#[cfg(test)] mod x;` or a test-only `use`
        i += 1
    return out_literals


def exported_names(root):
    names = set()
    dirs = [p for p in (root / "src" / "bins").glob("*/src")]
    dirs.append(root / "src" / "libs" / "nextgcore-metrics" / "src")
    for d in dirs:
        for p in d.rglob("*.rs"):
            if "tests" in p.relative_to(d).parts or p.name.endswith("_tests.rs"):
                continue
            for lit in strip_rust_tests(p.read_text()):
                names.update(re.findall(r"[a-zA-Z_:][a-zA-Z0-9_:]*", lit))
    return names


def main():
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else
                        pathlib.Path(__file__).resolve().parents[2])
    queried = {}  # name -> {file}
    recorded = set()
    for p, doc in rule_files(root):
        for g in doc["groups"]:
            for r in g.get("rules") or []:
                if "record" in r:
                    recorded.add(r["record"])
                for name in series_in_expr(str(r.get("expr", ""))):
                    queried.setdefault(name, set()).add(str(p.relative_to(root)))
    dashboards = 0
    for p in walk(root, {".json"}):
        if "dashboards" not in p.parts:
            continue
        dashboards += 1
        for expr in dashboard_exprs(json.loads(p.read_text())):
            for name in series_in_expr(expr):
                queried.setdefault(name, set()).add(str(p.relative_to(root)))
    exported = exported_names(root)

    def ok(name):
        if name in PROMETHEUS_SYNTHETIC or name in recorded or name in exported:
            return True
        return any(name.endswith(s) and name[: -len(s)] in exported
                   for s in HISTOGRAM_SUFFIXES)

    missing = {n: f for n, f in queried.items() if not ok(n)}
    for name in sorted(missing):
        print(f"{name}: queried by {', '.join(sorted(missing[name]))}, exported by no NF")
    print(f"{len(queried)} series queried by the rules and {dashboards} dashboard(s), "
          f"{len(missing)} not exported")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
