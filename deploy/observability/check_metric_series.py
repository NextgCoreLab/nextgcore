#!/usr/bin/env python3
"""Every series a shipped Prometheus rule or Grafana dashboard queries must be
exported by some NF (#1334).

A rule that queries a series no process emits never fires, and a panel on one is
always empty; both look like coverage and are not. This check reads every rule
file (`groups:` / `rules:` / `expr:`) and every Grafana dashboard JSON (`"expr"`)
in the tree, extracts the metric names their PromQL selects, and requires each to
be one of:

- a family the non-test source of an NF daemon (`src/bins/*/src`) or of the shared
  exposition (`src/libs/nextgcore-metrics/src`) renders: a literal in a metric-NAME
  position (see NAME_IN_CALL). A label value, a log message or any other string does
  not count. A histogram's `_bucket` / `_sum` / `_count` series match its base name;
- a series Prometheus itself synthesises for every target (`up`,
  `scrape_duration_seconds`, ...);
- a name a rule file records (`record:`).

Usage: check_metric_series.py [REPO_ROOT]   (default: the repository root)
       check_metric_series.py --self-test
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
    """`src` without comments and `#[cfg(test)]` items: (the code that is left, with
    every string literal written back as `"..."`, and the literals' contents)."""
    out_literals = []
    kept = []
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
                kept.append('"' + src[start:end] + '"')
            i = end + 1 + len(hashes)
            continue
        if c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            if depth_skip is None:
                out_literals.append(src[i + 1:j])
                kept.append(src[i:j + 1])
            i = j + 1
            continue
        if c == "'":
            m = re.match(r"'(\\.|[^'\\])'", src[i:i + 6])
            if m:
                if depth_skip is None:
                    kept.append(m.group(0))
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
                i += 1
                continue
        elif c == ";" and pending_test and depth_skip is None:
            pending_test = False  # `#[cfg(test)] mod x;` or a test-only `use`
        if depth_skip is None:
            kept.append(c)
        i += 1
    return "".join(kept), out_literals


METRIC_NAME = r"[a-zA-Z_:][a-zA-Z0-9_:]*"

# A metric family the code renders. Only literals in a metric-NAME position count,
# never a label value or any other string (#1371, #1372 review):
#
# - the name argument of the shared helpers (`write_metric(out, "x", ..)`,
#   `write_header(out, "x", ..)`, `CounterFamily::new("x", ..)`);
# - the name in a `# TYPE x <kind>` line of a hand-written exposition;
# - a literal followed by its metric type, `"x", "counter"` (a local helper such as
#   ucmfd's `metric(..)`);
# - the name of a (name, help) pair in a family table, `("x", "Help text ...")`:
#   the help is prose, which a label pair's value never is;
# - a `const ..._METRIC: &str = "x"` naming one family.
NAME_IN_CALL = [
    re.compile(r"\bwrite_(?:metric|header)\(\s*[\w.&]+\s*,\s*\"(" + METRIC_NAME + r")\""),
    re.compile(r"\bCounterFamily::new\(\s*\"(" + METRIC_NAME + r")\""),
    re.compile(r"\"(" + METRIC_NAME + r")\"\s*,\s*\"(?:counter|gauge|histogram|summary)\""),
    re.compile(r"\(\s*\"(" + METRIC_NAME + r")\"\s*,\s*\"[^\"]*\s[^\"]*\""),
    re.compile(r"\bconst\s+[A-Z0-9_]*_METRIC\s*:\s*&str\s*=\s*\"(" + METRIC_NAME + r")\""),
]
TYPE_LINE = re.compile(r"# TYPE (" + METRIC_NAME + r") ")


def exported_from_source(src):
    """The metric family names one Rust source file renders (see NAME_IN_CALL)."""
    code, literals = strip_rust_tests(src)
    names = set()
    for rx in NAME_IN_CALL:
        names.update(rx.findall(code))
    for lit in literals:
        names.update(TYPE_LINE.findall(lit))
    return names


def exported_names(root):
    names = set()
    dirs = [p for p in (root / "src" / "bins").glob("*/src")]
    dirs.append(root / "src" / "libs" / "nextgcore-metrics" / "src")
    for d in dirs:
        for p in d.rglob("*.rs"):
            if "tests" in p.relative_to(d).parts or p.name.endswith("_tests.rs"):
                continue
            names |= exported_from_source(p.read_text())
    return names


def self_test():
    """The checks catch what they must, on synthetic inputs."""
    cases = [
        # (rust source, name, exported?)
        ('fn r(out: &mut String) { write_metric(out, "x_up", "gauge", "h", 1); }', "x_up", True),
        ('static F: CounterFamily = CounterFamily::new("x_ops_total", "h", &[]);', "x_ops_total", True),
        ('fn r() -> String { "# TYPE y_sessions gauge\\ny_sessions 1\\n".into() }', "y_sessions", True),
        # A log message naming an identifier is no export.
        ('fn f() { log::info!("sess_id={}", 1); }', "sess_id", False),
        ('fn f() { let k = "sess_id"; }', "sess_id", False),
        # A test module's expectations are no export.
        ('#[cfg(test)]\nmod tests { fn t() { write_metric(out, "z_total", "c", "h", 1); } }', "z_total", False),
        # A (name, help) table rendered through a variable is; so is a local
        # helper given the name and its type, and a `_METRIC` const.
        ('const F: [(&str, &str); 1] = [("w_dropped_total", "Packets dropped, any cause")];\nfn r() { format!("# TYPE {n} counter"); }', "w_dropped_total", True),
        ('fn r() { metric("u_refusals_total", "counter", "Refused", 1); }', "u_refusals_total", True),
        ('pub const DROPS_METRIC: &str = "v_drops_total";', "v_drops_total", True),
        # #1372 review: a name table nothing serves is no export, even in a file
        # that renders other names through variables ...
        ('fn name(&self) -> &str { match self { Self::A => "fivegs_amffunction_rm_reginitreq" } }\nfn r() { format!("# TYPE {name} counter"); }', "fivegs_amffunction_rm_reginitreq", False),
        # ... and a label value is no series, as a match arm or as a label pair.
        ('fn label(&self) -> &str { match self { Self::NoPdr => "no_pdr_match" } }\nfn r() { format!("# TYPE {name} counter"); }', "no_pdr_match", False),
        ('fn r() { labels(&[("reason", "no_pdr_match")]); }', "no_pdr_match", False),
        ('fn r() { labels(&[("nf_type", "AMF")]); }', "nf_type", False),
    ]
    failures = 0
    for src, name, want in cases:
        got = name in exported_from_source(src)
        if got != want:
            print(f"self-test: {name!r} exported={got}, want {want}: {src!r}")
            failures += 1
    exprs = [
        ('rate(a_total{job="x"}[5m]) / on(job) b_total > 0.1', {"a_total", "b_total"}),
        ('sum by (le) (rate(c_bucket[5m]))', {"c_bucket"}),
        ('histogram_quantile(0.5, d_bucket) > 1e3 and $__var', {"d_bucket"}),
    ]
    for expr, want in exprs:
        got = series_in_expr(expr)
        if got != want:
            print(f"self-test: {expr!r} selects {sorted(got)}, want {sorted(want)}")
            failures += 1
    print(f"self-test: {len(cases) + len(exprs)} case(s), {failures} failure(s)")
    return 1 if failures else 0


def main():
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
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
