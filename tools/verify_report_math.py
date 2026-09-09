"""Recompute the published rates from the raw artifacts and compare.

The rates in results/summary.json are the headline of this pilot. They are
also the one number nobody can check by eye, which by the pattern recorded in
METHODOLOGY-NOTES.md note 4 makes them the next place a false pass would hide.
An arithmetic error in the aggregation would not look like a bug. It would
look like a finding.

So this script recomputes every published number from the per-cell evidence
files, using plain counting and division and nothing from harness/report.py.
That independence is the whole point: calling the same aggregation twice and
getting the same answer proves only that it is deterministic.

What is checked, per tool and overall:

  scored, insufficient and supplied cell counts
  alert-closed count and rate
  verified count and rate
  the gap
  the insufficient rate
  the failure class distribution

Exit code 0 means the published summary matches an independent count.

Usage:
  python tools/verify_report_math.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from harness import corpus

ROOT = corpus.ROOT
SUMMARY = os.path.join(ROOT, "results", "summary.json")

TOLERANCE = 1e-9


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def collect():
    """Count the artifacts on disk directly. No harness aggregation involved."""
    findings = [f for f in corpus.list_findings() if f.status == "built"]
    per_tool = {}
    for finding in findings:
        results_dir = os.path.join(ROOT, finding.results_dir)
        patches_dir = os.path.join(ROOT, finding.entry.get(
            "patches_dir", os.path.join("patches", finding.id)))
        if not os.path.isdir(results_dir):
            continue
        for name in sorted(os.listdir(results_dir)):
            if not name.endswith(".json"):
                continue
            if name.endswith(".provenance.json"):
                continue
            if name.endswith(".insufficient.json"):
                tool = name[:-len(".insufficient.json")]
                stats = per_tool.setdefault(tool, _blank())
                stats["insufficient"] += 1
                continue
            tool = name[:-len(".json")]
            data = load(os.path.join(results_dir, name))
            stats = per_tool.setdefault(tool, _blank())
            stats["scored"] += 1
            if data["verdict"] == "VERIFIED":
                stats["verified"] += 1
            else:
                fc = data["failure_class"]
                stats["classes"][fc] = stats["classes"].get(fc, 0) + 1
            if data["checks"]["A_alert_closed"]["pass"]:
                stats["alert_closed"] += 1
        for tool, stats in per_tool.items():
            for ext in (".patch", ".py"):
                if os.path.exists(os.path.join(patches_dir, tool + ext)):
                    stats["supplied"] += 1
                    break
    return per_tool


def _blank():
    return {"supplied": 0, "scored": 0, "insufficient": 0, "verified": 0,
            "alert_closed": 0, "classes": {}}


def rate(n, d):
    return None if not d else n / float(d)


def close(a, b):
    if a is None or b is None:
        return a is None and b is None
    return abs(a - b) < TOLERANCE


def main():
    if not os.path.exists(SUMMARY):
        print("no results/summary.json. Run run_matrix.py first.")
        return 3

    published = load(SUMMARY)
    counted = collect()
    problems = []

    published_tools = set(published["coverage"]["tools"])
    if published_tools != set(counted):
        problems.append("tool sets differ: published %s, counted %s"
                        % (sorted(published_tools), sorted(counted)))

    total = _blank()
    for tool in sorted(set(counted) & published_tools):
        c = counted[tool]
        p = published["per_tool"][tool]
        for key in ("supplied", "scored", "insufficient"):
            if p["cells"][key] != c[key]:
                problems.append("%s cells.%s: published %d, counted %d"
                                % (tool, key, p["cells"][key], c[key]))
        for key in ("verified", "alert_closed"):
            if p[key] != c[key]:
                problems.append("%s %s: published %d, counted %d"
                                % (tool, key, p[key], c[key]))
        checks = [
            ("alert_closed_rate", rate(c["alert_closed"], c["scored"])),
            ("verified_fix_rate", rate(c["verified"], c["scored"])),
            ("insufficient_rate", rate(c["insufficient"],
                                       c["scored"] + c["insufficient"])),
        ]
        for key, expected in checks:
            if not close(p[key], expected):
                problems.append("%s %s: published %r, computed %r"
                                % (tool, key, p[key], expected))
        a = rate(c["alert_closed"], c["scored"])
        v = rate(c["verified"], c["scored"])
        expected_gap = None if a is None or v is None else a - v
        if not close(p["gap"], expected_gap):
            problems.append("%s gap: published %r, computed %r"
                            % (tool, p["gap"], expected_gap))
        if p["failure_classes"] != c["classes"]:
            problems.append("%s failure classes: published %r, counted %r"
                            % (tool, p["failure_classes"], c["classes"]))

        for key in ("supplied", "scored", "insufficient", "verified",
                    "alert_closed"):
            total[key] += c[key]
        for fc, n in c["classes"].items():
            total["classes"][fc] = total["classes"].get(fc, 0) + n

    o = published["overall"]
    for key in ("supplied", "scored", "insufficient"):
        if o["cells"][key] != total[key]:
            problems.append("overall cells.%s: published %d, counted %d"
                            % (key, o["cells"][key], total[key]))
    a = rate(total["alert_closed"], total["scored"])
    v = rate(total["verified"], total["scored"])
    for key, expected in (("alert_closed_rate", a), ("verified_fix_rate", v),
                          ("gap", None if a is None or v is None else a - v),
                          ("insufficient_rate",
                           rate(total["insufficient"],
                                total["scored"] + total["insufficient"]))):
        if not close(o[key], expected):
            problems.append("overall %s: published %r, computed %r"
                            % (key, o[key], expected))
    if o["failure_classes"] != total["classes"]:
        problems.append("overall failure classes: published %r, counted %r"
                        % (o["failure_classes"], total["classes"]))

    print("Report arithmetic, recounted from the per-cell artifacts")
    print("=" * 64)
    print("  tools counted        : %s" % ", ".join(sorted(counted)))
    print("  scored cells         : %d" % total["scored"])
    print("  insufficient cells   : %d" % total["insufficient"])
    print("  alert closed         : %d" % total["alert_closed"])
    print("  verified             : %d" % total["verified"])
    print("  alert-closed rate    : %s" % ("n/a" if a is None else "%.4f" % a))
    print("  verified-fix rate    : %s" % ("n/a" if v is None else "%.4f" % v))
    print("=" * 64)
    if problems:
        for p in problems:
            print("  MISMATCH  %s" % p)
        print("RESULT: PUBLISHED SUMMARY DOES NOT MATCH THE ARTIFACTS")
        return 1
    print("RESULT: PUBLISHED SUMMARY MATCHES AN INDEPENDENT COUNT")
    return 0


if __name__ == "__main__":
    sys.exit(main())
