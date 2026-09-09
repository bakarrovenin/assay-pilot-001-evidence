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

## The check is tested before it is trusted

A recount that has only ever agreed has not been tested. If check() returned
an empty problem list for every input, this script would print RESULT: MATCHES
on any summary at all, and the failure would look exactly like a pass. That is
the shape recorded in METHODOLOGY-NOTES.md notes 2, 4 and 6, and there is no
reason to assume the recount is immune to it.

So before the real summary is read, the published summary is deliberately
corrupted in memory, one field at a time, and check() has to report each one.
A corruption that goes unreported is a hard failure and nothing is recounted:
an instrument that cannot fail is not measuring anything.

Each corruption also has to be named correctly. It is not enough that the
check complained; the complaint has to identify the field that was moved. A
recount that objects for the wrong reason is still broken, the same standard
tools/verify_insufficient_evidence.py holds the scorer to.

The corruptions run in both directions. CORRUPTIONS marks which, because the
flattering direction is the one that would survive review: a verified-fix rate
that came out too high reads as a finding rather than as a bug.

Exit code 0 means the check failed on every corrupted summary and then matched
the real one. Exit 2 means the negative control did not fire, which invalidates
the pass regardless of what the real summary says.

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


def check(published, counted):
    """Compare a published summary against an independent count.

    Returns (problems, totals). Pure: it reads neither disk nor globals, which
    is what lets the negative control below hand it a corrupted summary.
    """
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

    return problems, total


# ---------------------------------------------------------------------------
# The negative control.
#
# One corruption per branch of check(). Each is a plausible mistake rather than
# a nonsense value: a count off by one, a rate that did not get recomputed
# after its numerator moved, a failure class dropped from the distribution.
#
# "direction" is what the corruption would do to the published story if it
# survived. flattering means the numbers look better than the artifacts
# support, which is the direction that gets waved through.
# ---------------------------------------------------------------------------

def _victim(published):
    """The tool the corruptions are applied to. Deterministic, not arbitrary."""
    return sorted(published["coverage"]["tools"])[0]


def _bump_count(key):
    def mutate(s):
        t = _victim(s)
        s["per_tool"][t][key] += 1
    return mutate


def _bump_cells(key):
    def mutate(s):
        t = _victim(s)
        s["per_tool"][t]["cells"][key] += 1
    return mutate


def _shift_rate(key, delta):
    def mutate(s):
        t = _victim(s)
        s["per_tool"][t][key] = (s["per_tool"][t][key] or 0.0) + delta
    return mutate


def _drop_failure_class(s):
    for tool, stats in sorted(s["per_tool"].items()):
        if stats["failure_classes"]:
            stats["failure_classes"] = {}
            return
    # Nothing to drop means nothing failed. Add one instead: a class the
    # artifacts do not support is the same lie in the other direction.
    s["per_tool"][_victim(s)]["failure_classes"] = {"invented-class": 1}


def _overall_rate(s):
    s["overall"]["verified_fix_rate"] = (s["overall"]["verified_fix_rate"]
                                         or 0.0) + 0.25


def _overall_cells(s):
    s["overall"]["cells"]["scored"] += 1


def _overall_classes(s):
    s["overall"]["failure_classes"] = dict(
        s["overall"]["failure_classes"], **{"invented-class": 1})


def _drop_tool(s):
    s["coverage"]["tools"] = s["coverage"]["tools"][1:]


CORRUPTIONS = [
    # label, mutation, direction, substring the complaint must contain
    ("per-tool verified count off by one", _bump_count("verified"),
     "flattering", "verified:"),
    ("per-tool alert-closed count off by one", _bump_count("alert_closed"),
     "flattering", "alert_closed:"),
    ("per-tool scored denominator off by one", _bump_cells("scored"),
     "either", "cells.scored:"),
    ("per-tool supplied count off by one", _bump_cells("supplied"),
     "either", "cells.supplied:"),
    ("per-tool insufficient count off by one", _bump_cells("insufficient"),
     "either", "cells.insufficient:"),
    ("verified-fix rate not recomputed", _shift_rate("verified_fix_rate", 0.25),
     "flattering", "verified_fix_rate:"),
    ("alert-closed rate not recomputed",
     _shift_rate("alert_closed_rate", -0.25), "accusing", "alert_closed_rate:"),
    ("insufficient rate understated",
     _shift_rate("insufficient_rate", 0.25), "either", "insufficient_rate:"),
    ("gap widened", _shift_rate("gap", 0.25), "flattering", "gap:"),
    ("failure class distribution altered", _drop_failure_class,
     "flattering", "failure classes:"),
    ("overall verified-fix rate not recomputed", _overall_rate,
     "flattering", "overall verified_fix_rate:"),
    ("overall scored denominator off by one", _overall_cells,
     "either", "overall cells.scored:"),
    ("overall failure classes altered", _overall_classes,
     "either", "overall failure classes:"),
    ("a tool dropped from coverage", _drop_tool,
     "flattering", "tool sets differ:"),
]


def negative_control(published, counted):
    """Corrupt the summary one field at a time. Every one must be caught.

    Returns the list of corruptions that were missed or misreported. Empty
    means the check demonstrably fails when it should.
    """
    missed = []
    for label, mutate, direction, expected in CORRUPTIONS:
        corrupted = json.loads(json.dumps(published))
        mutate(corrupted)
        if corrupted == published:
            missed.append((label, direction,
                           "corruption changed nothing, so it proves nothing"))
            continue
        problems, _ = check(corrupted, counted)
        if not problems:
            missed.append((label, direction, "not caught"))
        elif not any(expected in p for p in problems):
            missed.append((label, direction,
                           "caught, but named none of the right field (%r): %s"
                           % (expected, "; ".join(problems))))
    return missed


def main():
    if not os.path.exists(SUMMARY):
        print("no results/summary.json. Run run_matrix.py first.")
        return 3

    published = load(SUMMARY)
    counted = collect()

    # 1. Prove the instrument can fail, before trusting it to pass.
    missed = negative_control(published, counted)
    print("Negative control, %d deliberately corrupted summaries"
          % len(CORRUPTIONS))
    print("=" * 64)
    for label, _mutate, direction, _expected in CORRUPTIONS:
        status = "MISSED" if any(m[0] == label for m in missed) else "caught"
        print("  %-8s %-42s %s" % (status, label, direction))
    print("=" * 64)
    if missed:
        for label, direction, detail in missed:
            print("  NOT CAUGHT  %-42s %s" % (label, detail))
        print("RESULT: THE RECOUNT DOES NOT FAIL WHEN IT SHOULD")
        print("  A check that cannot report a mismatch cannot confirm one "
              "either. The clean result below, if any, means nothing.")
        return 2
    print()

    # 2. Now the real recount.
    problems, total = check(published, counted)
    a = rate(total["alert_closed"], total["scored"])
    v = rate(total["verified"], total["scored"])

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
    print("  and the recount reported every one of the %d corrupted summaries."
          % len(CORRUPTIONS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
