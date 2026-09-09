"""Aggregate the matrix into the numbers protocol section 5 asks for.

Per tool: alert-closed rate, verified-fix rate, the gap between them, the
insufficient-evidence rate, and the failure class distribution.

The headline is the gap, not the rate. Alert-closed near 100 percent with
verified-fix materially below it is the result the pilot is hunting. If
verified-fix comes back above 85 percent the thesis is smaller than claimed
and we say so, which is why print_summary states that out loud rather than
leaving it to whoever reads the table.

## Denominators, stated because they are the first thing worth attacking

A cell is one finding scored against one tool. Cells are counted like this:

  supplied      a diff exists on disk for that cell
  run           the scorer actually ran it
  scored        the run produced VERIFIED or NOT VERIFIED
  insufficient  the run produced INSUFFICIENT EVIDENCE

  alert-closed rate      alert closed / scored
  verified-fix rate      verified / scored
  gap                    alert-closed rate minus verified-fix rate
  insufficient rate      insufficient / run

Rates are over `scored`, not over `run`, because a run that produced no
verdict produced no check A result either and cannot be counted for or
against. That choice flatters a tool with many insufficient runs, so the
insufficient rate sits in the same table rather than in a footnote, and every
row prints its own cell counts. A rate whose denominator is not on screen is
not evidence.

Coverage is reported separately. A verified-fix rate over three cells and the
same rate over sixty are not the same claim, and only one of them is a rate.

## What we do not measure, said plainly

Protocol section 5 also asks for median patch latency and cost per fix. The
harness does not call the fixers (see harness/matrix.py), so it cannot observe
either. They are reported as not measured rather than estimated. The wall
clock in the provenance files is how long scoring took, which is a fact about
this harness and not about any tool.
"""

import json
import os
import time

from harness import matrix

NOT_MEASURED = [
    "median patch latency: the harness does not call the fixers, so it never "
    "observes generation time",
    "cost per fix: same reason, no API call is made by this harness",
]

# Protocol section 0. If verified-fix comes back above this, the thesis is
# smaller than claimed and we say so publicly.
THESIS_THRESHOLD = 0.85


def _rate(numerator, denominator):
    """None rather than zero when there is nothing to divide by.

    A tool with no scored cells has no verified-fix rate. Returning 0.0 would
    render as a real and very bad result.
    """
    if not denominator:
        return None
    return numerator / float(denominator)


def _tool_stats(cells, tool):
    supplied = run = scored = insufficient = verified = alert_closed = 0
    failure_classes = {}
    for (_, t), cell in cells.items():
        if t != tool or not cell.built:
            continue
        if cell.supplied:
            supplied += 1
        state = cell.state
        if state == matrix.SCORED:
            run += 1
            scored += 1
            if cell.verdict == "VERIFIED":
                verified += 1
            else:
                fc = cell.failure_class or "unclassified"
                failure_classes[fc] = failure_classes.get(fc, 0) + 1
            if cell.alert_closed:
                alert_closed += 1
        elif state == matrix.INSUFFICIENT:
            run += 1
            insufficient += 1

    alert_rate = _rate(alert_closed, scored)
    verified_rate = _rate(verified, scored)
    gap = (None if alert_rate is None or verified_rate is None
           else alert_rate - verified_rate)
    return {
        "cells": {"supplied": supplied, "run": run, "scored": scored,
                  "insufficient": insufficient},
        "alert_closed": alert_closed,
        "verified": verified,
        "alert_closed_rate": alert_rate,
        "verified_fix_rate": verified_rate,
        "gap": gap,
        "insufficient_rate": _rate(insufficient, run),
        "failure_classes": dict(sorted(failure_classes.items())),
    }


def aggregate(findings, tools, cells, scanner=None):
    built = [f for f in findings if f.status == "built"]
    per_tool = {tool: _tool_stats(cells, tool) for tool in tools}

    pooled = {"supplied": 0, "run": 0, "scored": 0, "insufficient": 0}
    verified = alert_closed = 0
    classes = {}
    for stats in per_tool.values():
        for k in pooled:
            pooled[k] += stats["cells"][k]
        verified += stats["verified"]
        alert_closed += stats["alert_closed"]
        for fc, n in stats["failure_classes"].items():
            classes[fc] = classes.get(fc, 0) + n

    alert_rate = _rate(alert_closed, pooled["scored"])
    verified_rate = _rate(verified, pooled["scored"])
    summary = {
        "schema": "assay-pilot-001/summary",
        "schema_version": 1,
        "pilot": "assay-pilot-001",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scanner": scanner,
        "coverage": {
            "findings_built": len(built),
            "findings_in_corpus": len(findings),
            "tools": list(tools),
            "cells_possible": len(built) * len(tools),
            "cells_supplied": pooled["supplied"],
            "cells_run": pooled["run"],
        },
        "denominators": {
            "alert_closed_rate": "alert closed / scored",
            "verified_fix_rate": "verified / scored",
            "gap": "alert_closed_rate minus verified_fix_rate",
            "insufficient_rate": "insufficient / run",
            "note": "rates are over cells that produced a verdict. A run with "
                    "no verdict has no check A result and is counted only in "
                    "the insufficient rate.",
        },
        "per_tool": per_tool,
        "overall": {
            "cells": pooled,
            "alert_closed": alert_closed,
            "verified": verified,
            "alert_closed_rate": alert_rate,
            "verified_fix_rate": verified_rate,
            "gap": (None if alert_rate is None or verified_rate is None
                    else alert_rate - verified_rate),
            "insufficient_rate": _rate(pooled["insufficient"], pooled["run"]),
            "failure_classes": dict(sorted(classes.items())),
        },
        "not_measured": NOT_MEASURED,
    }
    summary["caveats"] = caveats(summary)
    return summary


# A rate needs a denominator big enough to be a rate. Below this a row is a
# count wearing a percent sign, and the report says so rather than leaving the
# reader to assume otherwise.
RATE_FLOOR = 3


def caveats(summary):
    """What this table does not support, derived from the table itself.

    Generated rather than written by hand, so it cannot fall out of date with
    the numbers it qualifies. A published percentage nobody has qualified is
    the failure this pilot exists to document in other people's tooling, and
    we do not get an exemption for our own table.
    """
    out = []
    cov = summary["coverage"]
    if cov["findings_built"] < cov["findings_in_corpus"]:
        n = cov["findings_built"]
        out.append(
            "Coverage is partial. %d of the %d findings in the corpus %s "
            "built, so every number here describes %s and says nothing about "
            "the shapes not yet written: numeric context, LIKE, ORDER BY, "
            "multi-parameter, ORM, second order, multi-hop. The gap is "
            "expected to be larger in the harder shapes, which is a reason to "
            "distrust this number as an estimate of the whole."
            % (n, cov["findings_in_corpus"], "is" if n == 1 else "are",
               "that one finding" if n == 1 else "those %d findings" % n))

    thin = [t for t in cov["tools"]
            if summary["per_tool"][t]["cells"]["scored"] < RATE_FLOOR]
    if thin:
        lead = ("This row is a count, not a rate" if len(thin) == 1
                else "These rows are counts, not rates")
        out.append(
            "%s: %s. Each was scored on fewer than %d cells, so the "
            "percentage restates one or two results and can only move in "
            "whole steps. Read the per cell table instead."
            % (lead, ", ".join(thin), RATE_FLOOR))

    if cov["cells_run"] < RATE_FLOOR * 2:
        out.append(
            "The overall row is %d cells. It shows that the four checks "
            "separate a real fix from patches that only close the alert. It "
            "is not a rate that generalises to any tool or any codebase."
            % cov["cells_run"])

    out.append(
        "The harness does not call the fixers. Tool names are the names of "
        "the diff files supplied, and for Pilot 001 they are illustrative "
        "patches written to exercise the method, not output from the vendors "
        "named in the protocol. This is not a vendor comparison. See README.")
    return out


def _pct(value):
    return "n/a" if value is None else "%.0f%%" % (value * 100)


def _pp(value):
    """Gap is a difference of two rates, so it is in percentage points."""
    return "n/a" if value is None else "%+.0f pp" % (value * 100)


def render_table(summary):
    """The results table, for a terminal."""
    lines = []
    cov = summary["coverage"]
    lines.append("Assay Pilot 001 results")
    lines.append("scanner: %s" % (summary.get("scanner") or "not recorded"))
    lines.append("coverage: %d of %d findings built, %d tools, %d of %d "
                 "possible cells supplied, %d run"
                 % (cov["findings_built"], cov["findings_in_corpus"],
                    len(cov["tools"]), cov["cells_supplied"],
                    cov["cells_possible"], cov["cells_run"]))
    lines.append("")
    header = ("%-12s %7s %7s %7s   %11s %11s %9s %9s"
              % ("tool", "supplied", "scored", "insuff", "alert-closed",
                 "verified", "gap", "insuff %"))
    lines.append(header)
    lines.append("-" * len(header))
    for tool in cov["tools"]:
        s = summary["per_tool"][tool]
        c = s["cells"]
        lines.append("%-12s %7d %7d %7d   %11s %11s %9s %9s"
                     % (tool, c["supplied"], c["scored"], c["insufficient"],
                        _pct(s["alert_closed_rate"]),
                        _pct(s["verified_fix_rate"]),
                        _pp(s["gap"]), _pct(s["insufficient_rate"])))
    lines.append("-" * len(header))
    o = summary["overall"]
    lines.append("%-12s %7d %7d %7d   %11s %11s %9s %9s"
                 % ("ALL", o["cells"]["supplied"], o["cells"]["scored"],
                    o["cells"]["insufficient"], _pct(o["alert_closed_rate"]),
                    _pct(o["verified_fix_rate"]), _pp(o["gap"]),
                    _pct(o["insufficient_rate"])))
    lines.append("")
    lines.append("failure classes, over patches that were scored NOT VERIFIED")
    if not o["failure_classes"]:
        lines.append("  (none)")
    for fc, n in o["failure_classes"].items():
        lines.append("  %-30s %d" % (fc, n))
    lines.append("")
    lines.append("how to read this")
    for c in summary.get("caveats", []):
        lines.append("  - %s" % c)
    lines.append("")
    lines.append("denominators: %s" % summary["denominators"]["note"])
    for item in summary["not_measured"]:
        lines.append("not measured: %s" % item)

    vr = o["verified_fix_rate"]
    lines.append("")
    if vr is None:
        lines.append("No cell produced a verdict, so there is no gap to read "
                     "yet. That is a coverage statement, not a result.")
    elif vr > THESIS_THRESHOLD:
        lines.append("Verified-fix rate is above %.0f%%. Protocol section 0: "
                     "the thesis is smaller than claimed and we say so."
                     % (THESIS_THRESHOLD * 100))
    else:
        lines.append("Headline is the gap, not the rate: alert-closed %s "
                     "against verified-fix %s."
                     % (_pct(o["alert_closed_rate"]), _pct(vr)))
    return "\n".join(lines)


def render_markdown(summary, cells=None, findings=None):
    """The published results table."""
    cov = summary["coverage"]
    out = []
    out.append("# Assay Pilot 001 results")
    out.append("")
    out.append("Generated %s by `run_matrix.py`. Scanner: %s."
               % (summary["generated_utc"],
                  summary.get("scanner") or "not recorded"))
    out.append("")
    out.append("Coverage: %d of %d findings built, %d tools, %d of %d possible "
               "cells supplied, %d run."
               % (cov["findings_built"], cov["findings_in_corpus"],
                  len(cov["tools"]), cov["cells_supplied"],
                  cov["cells_possible"], cov["cells_run"]))
    out.append("")
    out.append("## How to read this")
    out.append("")
    for c in summary.get("caveats", []):
        out.append("- %s" % c)
    out.append("")
    out.append("## Rates per tool")
    out.append("")
    out.append("| Tool | Supplied | Scored | Insufficient | Alert closed | "
               "Verified fix | Gap | Insufficient rate |")
    out.append("|---|---|---|---|---|---|---|---|")
    for tool in cov["tools"]:
        s = summary["per_tool"][tool]
        c = s["cells"]
        out.append("| %s | %d | %d | %d | %s | %s | %s | %s |"
                   % (tool, c["supplied"], c["scored"], c["insufficient"],
                      _pct(s["alert_closed_rate"]),
                      _pct(s["verified_fix_rate"]), _pp(s["gap"]),
                      _pct(s["insufficient_rate"])))
    o = summary["overall"]
    out.append("| **All** | %d | %d | %d | %s | %s | %s | %s |"
               % (o["cells"]["supplied"], o["cells"]["scored"],
                  o["cells"]["insufficient"], _pct(o["alert_closed_rate"]),
                  _pct(o["verified_fix_rate"]), _pp(o["gap"]),
                  _pct(o["insufficient_rate"])))
    out.append("")
    out.append("Denominators: alert-closed rate and verified-fix rate are over "
               "cells that produced a verdict. A run that produced no verdict "
               "has no check A result and is counted only in the insufficient "
               "rate. Gap is a difference of two rates, so it is in percentage "
               "points.")
    out.append("")
    out.append("## Failure classes")
    out.append("")
    if o["failure_classes"]:
        out.append("| Class | Count |")
        out.append("|---|---|")
        for fc, n in o["failure_classes"].items():
            out.append("| %s | %d |" % (fc, n))
    else:
        out.append("No patch was scored NOT VERIFIED.")
    out.append("")

    if cells and findings:
        out.append("## Per cell")
        out.append("")
        out.append("| Finding | Tool | A | B | C | D | Verdict | Class |")
        out.append("|---|---|---|---|---|---|---|---|")
        for finding in findings:
            if finding.status != "built":
                continue
            for tool in cov["tools"]:
                cell = cells.get((finding.id, tool))
                if cell is None or cell.state in (matrix.NOT_SUPPLIED,
                                                  matrix.NOT_RUN):
                    continue
                if cell.state == matrix.INSUFFICIENT:
                    out.append("| %s | %s | . | . | . | . | INSUFFICIENT "
                               "EVIDENCE | %s |"
                               % (finding.id, tool,
                                  (cell.insufficient or {}).get("reason", "")))
                    continue
                c = cell.evidence["checks"]
                mark = lambda ok: "pass" if ok else "fail"
                out.append("| %s | %s | %s | %s | %s | %s | %s | %s |"
                           % (finding.id, tool,
                              mark(c["A_alert_closed"]["pass"]),
                              mark(c["B_hole_shut"]["pass"]),
                              mark(c["C_behaviour_preserved"]["pass"]),
                              mark(c["D_no_suppression"]["pass"]),
                              cell.verdict, cell.failure_class))
        out.append("")

    out.append("## Not measured")
    out.append("")
    for item in summary["not_measured"]:
        out.append("- %s" % item)
    out.append("")
    return "\n".join(out)


def write(summary, root, cells=None, findings=None):
    json_path = os.path.join(root, "results", "summary.json")
    md_path = os.path.join(root, "results", "RESULTS.md")
    os.makedirs(os.path.dirname(json_path), exist_ok=True)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(render_markdown(summary, cells, findings))
    return json_path, md_path
