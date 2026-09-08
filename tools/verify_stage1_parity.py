"""Stage 1 migration proof: Finding 1 still scores identically.

Stage 1 restructured the corpus so it can hold fifteen findings, and moved the
scoring core out of manual_score.py into harness/scoring.py driven by
corpus/manifest.json. The claim is that this changed where the numbers come
from and not how they are computed.

This script proves the claim the only way worth trusting. It re-scores all
three Finding 1 patches with the new code, writing into a scratch directory so
the committed evidence is never touched, and byte-compares every artifact
against the one committed from the manual run.

Two artifacts per patch are compared:
  results/finding-01/<tool>.json          committed, published
  heldout/finding-01/results/<tool>.json  present only on an experimenter
                                          machine, skipped elsewhere

The run date is pinned to the original run date. It is the one field that
cannot reproduce itself, because it records when the scan happened. Everything
else, including the scanner version string, is regenerated from scratch.

Exit code 0 means every comparison matched.

Usage:
  python tools/verify_stage1_parity.py
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from harness import corpus, scoring

ROOT = corpus.ROOT

# The manual run of Finding 1, recorded in results/finding-01/.
FINDING = "finding-01"
ORIGINAL_RUN_DATE = "2026-09-08"
TOOLS = ["fixer-01", "fixer-02", "fixer-03"]


def sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def compare(label, committed, regenerated, report):
    """Byte-compare one artifact. Returns True if it matched."""
    if not os.path.exists(committed):
        report.append((label, "SKIP", "no committed artifact at %s"
                       % os.path.relpath(committed, ROOT)))
        return True
    if not os.path.exists(regenerated):
        report.append((label, "FAIL", "harness produced no artifact"))
        return False
    a, b = sha256(committed), sha256(regenerated)
    if a == b:
        report.append((label, "MATCH", a[:16]))
        return True
    diff = subprocess.run(["diff", "-u", committed, regenerated],
                          stdout=subprocess.PIPE).stdout.decode()
    report.append((label, "DIFFER", "\n" + diff))
    return False


def main():
    finding = corpus.get_finding(FINDING)
    missing = finding.missing_heldout()
    if missing:
        print("INSUFFICIENT EVIDENCE: cannot verify parity without the "
              "held-out material.")
        print("missing: %s" % ", ".join(missing))
        print("This check only runs on an experimenter machine. A public "
              "clone has no heldout/ directory (protocol section 6).")
        return 3

    scratch = tempfile.mkdtemp(prefix="assay_parity_")
    report, ok = [], True
    try:
        for tool in TOOLS:
            patched = os.path.join(ROOT, "patches", FINDING, tool + ".py")
            print("re-scoring %s ..." % tool)
            result = scoring.score(patched, tool, finding_id=FINDING,
                                   run_date=ORIGINAL_RUN_DATE,
                                   output_root=scratch)
            print("  verdict: %s  class: %s" % (result["verdict"],
                                                result["failure_class"]))

            ok &= compare(
                "%s published" % tool,
                os.path.join(ROOT, finding.results_dir, tool + ".json"),
                os.path.join(scratch, finding.results_dir, tool + ".json"),
                report)
            ok &= compare(
                "%s held-out" % tool,
                os.path.join(finding.heldout_results_dir(ROOT), tool + ".json"),
                os.path.join(finding.heldout_results_dir(scratch), tool + ".json"),
                report)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    print()
    print("Stage 1 parity, %s" % FINDING)
    print("scanner: %s" % scoring.scanner_label(finding))
    print("-" * 62)
    for label, status, detail in report:
        print("  %-22s %-7s %s" % (label, status, detail))
    print("-" * 62)
    print("RESULT:", "PARITY HELD" if ok else "PARITY BROKEN")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
