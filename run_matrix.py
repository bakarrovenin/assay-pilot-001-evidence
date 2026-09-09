"""Assay Pilot 001 - stage 4. Run the findings by tools matrix and report.

Patches are supplied by the experimenter as diff files, one per cell:

    patches/<finding-id>/<tool>.patch

The harness never calls a fixer. It applies the diffs, scores each one in an
isolated container (stage 3), and aggregates the results into the rates
protocol section 5 asks for.

  python run_matrix.py                    score anything not yet scored, report
  python run_matrix.py --report-only      report from what is already on disk
  python run_matrix.py --rescore          score every supplied cell again
  python run_matrix.py --finding finding-01 --tool fixer-02
  python run_matrix.py --output-root /tmp/dry   write nothing into the repo

Outputs:

  results/<finding>/<tool>.json               evidence, one per scored patch
  results/<finding>/<tool>.insufficient.json  a run that produced no verdict
  results/<finding>/<tool>.provenance.json    the isolation that run had
  results/summary.json                        the aggregate
  results/RESULTS.md                          the published table

## Why it will not overwrite an existing result without being told to

The three Finding 1 artifacts have been byte-identical since the manual run,
through the stage 1 restructure and the stage 3 containerisation, and both
parity gates exist to prove it. Re-scoring them by default would put that
chain at the mercy of anyone who runs this script, and would silently rewrite
published evidence.

So a cell that already has a result is skipped and reported as such. --rescore
overwrites deliberately.

One thing to know before using --rescore on Finding 1: the committed evidence
records patch_file as the patched .py, because that is the input the manual
run was given. Scoring the same patch from its .patch diff records the diff
instead. The stage 3 gate shows the two agree on every other field, so this is
a difference in what was fed to the scorer and not in what the scorer found,
but it will show up as a diff against the committed artifact.
"""

import argparse
import json
import os
import shutil
import sys

from harness import container, corpus, matrix, report

ROOT = corpus.ROOT


def write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def run_cell(cell, finding, args, output_root):
    """Score one cell in a container. Returns a one line status string."""
    use_diff = bool(cell.patch) and args.input != "file"
    kwargs = {"run_date": args.run_date, "mode": args.mode}
    if use_diff:
        kwargs["patch"] = cell.patch
        shown = os.path.relpath(cell.patch, ROOT)
    elif cell.patched_file:
        kwargs["patched_file"] = cell.patched_file
        shown = os.path.relpath(cell.patched_file, ROOT)
    else:
        return "no patch supplied"

    try:
        outcome, provenance, out_dir = container.score_in_container(
            cell.tool, finding_id=cell.finding_id, **kwargs)
    except container.DockerUnavailable as e:
        # No container is not a verdict. Record it as such and keep going, so
        # one broken cell does not throw away the rest of the matrix.
        write_json(matrix.insufficient_path(finding, cell.tool, output_root), {
            "finding": cell.finding_id, "tool": cell.tool,
            "verdict": "INSUFFICIENT EVIDENCE",
            "reason": "no container runtime",
            "detail": str(e), "patch": shown,
        })
        return "INSUFFICIENT EVIDENCE (no container runtime)"

    try:
        prov_path = matrix.provenance_path(finding, cell.tool, output_root)
        ev_path = matrix.evidence_path(finding, cell.tool, output_root)
        ie_path = matrix.insufficient_path(finding, cell.tool, output_root)

        if outcome["verdict"] == "INSUFFICIENT EVIDENCE":
            record = {"finding": cell.finding_id, "tool": cell.tool,
                      "verdict": "INSUFFICIENT EVIDENCE",
                      "reason": outcome.get("reason"),
                      "detail": outcome.get("detail"), "patch": shown}
            write_json(ie_path, record)
            # A cell cannot be both. If it produced a verdict before and does
            # not now, the stale verdict must not survive.
            if os.path.exists(ev_path):
                os.remove(ev_path)
            provenance["evidence"] = {}
            write_json(prov_path, provenance)
            return "INSUFFICIENT EVIDENCE (%s)" % outcome.get("reason")

        written = {}
        for rel in (os.path.join(finding.results_dir, cell.tool + ".json"),
                    os.path.join(finding.entry["heldout"]["dir"], "results",
                                 cell.tool + ".json")):
            src = os.path.join(out_dir, rel)
            if not os.path.exists(src):
                continue
            dest = os.path.join(output_root, rel)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.copy(src, dest)
            written[rel] = "sha256:" + _sha256(dest)
        provenance["evidence"] = written
        write_json(prov_path, provenance)
        if os.path.exists(ie_path):
            os.remove(ie_path)
        return "%s (%s)" % (outcome["verdict"], outcome["failure_class"])
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


def _sha256(path):
    import hashlib
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def main():
    p = argparse.ArgumentParser(
        description="Run the findings by tools matrix and write the report.")
    p.add_argument("--finding", action="append", default=None,
                   help="limit to these findings (repeatable)")
    p.add_argument("--tool", action="append", default=None,
                   help="limit to these tools (repeatable)")
    p.add_argument("--report-only", action="store_true",
                   help="do not score anything, report what is on disk")
    p.add_argument("--rescore", action="store_true",
                   help="score supplied cells again, overwriting results")
    p.add_argument("--input", choices=("diff", "file"), default="diff",
                   help="score from the .patch diff (default) or the .py file")
    p.add_argument("--mode", default="network-none",
                   choices=sorted(container.MODE_FLAGS))
    p.add_argument("--run-date", default=None)
    p.add_argument("--output-root", default=None,
                   help="write artifacts under this root instead of the "
                        "repository")
    args = p.parse_args()

    output_root = args.output_root or ROOT
    findings, tools, cells = matrix.build(
        root=ROOT, findings=args.finding, tools=args.tool,
        results_root=output_root)

    if not tools:
        print("No patches found. Supply diffs as patches/<finding>/<tool>.patch")
        return 2

    if not args.report_only:
        for finding in findings:
            if finding.status != "built":
                continue
            for tool in tools:
                cell = cells[(finding.id, tool)]
                if not cell.supplied:
                    continue
                already = cell.state in (matrix.SCORED, matrix.INSUFFICIENT)
                if already and not args.rescore:
                    print("  %-12s %-10s skipped, already recorded as %s "
                          "(use --rescore)"
                          % (finding.id, tool, cell.verdict))
                    continue
                print("  %-12s %-10s scoring ..." % (finding.id, tool))
                status = run_cell(cell, finding, args, output_root)
                print("  %-12s %-10s %s" % (finding.id, tool, status))

        # Reread from disk so the report describes what was actually written.
        findings, tools, cells = matrix.build(
            root=ROOT, findings=args.finding, tools=args.tool,
            results_root=output_root)

    scanner = None
    for finding in findings:
        if finding.status == "built":
            try:
                from harness import scoring
                scanner = scoring.scanner_label(finding)
            except Exception:
                scanner = None
            break

    summary = report.aggregate(findings, tools, cells, scanner=scanner)
    json_path, md_path = report.write(summary, output_root, cells, findings)

    print()
    print(report.render_table(summary))
    print()
    print("wrote %s" % os.path.relpath(json_path, output_root))
    print("wrote %s" % os.path.relpath(md_path, output_root))
    return 0


if __name__ == "__main__":
    sys.exit(main())
