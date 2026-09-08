"""Capture both baselines for one finding.

  benign baseline   every benign input fired at the KNOWN-CORRECT REFERENCE
                    app, exact response recorded. Check C compares against it.
  scanner baseline  pinned Semgrep OSS over the finding's module, stored as
                    SARIF. Check A compares against it.

The benign baseline is captured from the reference app and never from the
unpatched app. That is METHODOLOGY-NOTES.md note 1, and harness/baseline.py
explains it at length and enforces it: there is no flag here that captures
from the unpatched app, because taking the baseline from the unpatched app
makes a correct fix score as a regression.

Every capture also fires the benign set at the unpatched app and publishes
which inputs it answers differently, so the reason for the deviation is
visible evidence in scanner/<finding>.capture.json rather than a claim.

Usage:
  python tools/capture_baseline.py --finding finding-01
  python tools/capture_baseline.py --finding finding-01 --check
  python tools/capture_baseline.py --finding finding-01 --force

An existing benign baseline is never overwritten without --force. The baseline
is what check C compares against, so regenerating it after patches have been
scored would silently invalidate every recorded result.

--check captures into a scratch directory instead, compares SHA-256 against
what is already committed, and changes nothing. Use it to prove the capture is
reproducible.
"""

import argparse
import hashlib
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from harness import baseline, corpus

ROOT = corpus.ROOT


def sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def report_record(record):
    s = record["scanner"]
    b = record["benign_baseline"]
    print()
    print("finding : %s  (%s)" % (record["finding"], record["shape"]))
    print("captured: %s" % record["captured"])
    print()
    print("scanner baseline")
    print("  %s %s, rule %s" % (s["tool"], s["version"], s["rule_file"]))
    print("  target %s" % s["scan_target"])
    print("  findings: %d" % s["findings"])
    for r in s["results"]:
        print("    %s:%s  %s" % (r["file"], r["start_line"], r["rule_id"]))
    print("  sarif %s" % s["sarif"])
    print("  sha256 %s" % s["sarif_sha256"])
    print()
    print("benign baseline")
    print("  source: %s (%s)" % (b["source"], b["reference_app"]))
    print("  captured from unpatched app: %s" % b["captured_from_unpatched_app"])
    print("  inputs: %d  statuses: %s" % (b["inputs"], b["status_counts"]))
    print("  sha256 %s" % b["sha256"])
    trap = record.get("note_1_trap_demonstration")
    if trap:
        print()
        print("note 1 trap demonstration (never used as a baseline)")
        if not trap["differs_on"]:
            print("  the unpatched app agreed on all %d benign inputs"
                  % trap["inputs_fired"])
        for d in trap["differs_on"]:
            print("  %s  reference %s  unpatched %s"
                  % (d["id"], d["reference_status"], d["unpatched_status"]))
        print("  %s" % trap["conclusion"])


def do_check(finding):
    """Recapture into a scratch root and compare against what is committed."""
    scratch = tempfile.mkdtemp(prefix="assay_capture_")
    try:
        committed_baseline = finding.heldout_path("baseline")
        committed_record = finding.capture_record_path
        committed_sarif = finding.sarif_path
        captured_date = "unknown"
        if os.path.exists(committed_baseline):
            import json
            with open(committed_baseline, encoding="utf-8") as f:
                captured_date = json.load(f)["captured"]

        record, new_baseline = baseline.capture(
            finding, captured=captured_date, output_root=scratch)
        new_record = baseline.write_capture_record(finding, record, scratch)
        new_sarif = os.path.join(scratch, "scanner", finding.id + ".sarif")

        rows, ok = [], True
        for label, old, new in (
                ("benign baseline", committed_baseline, new_baseline),
                ("scanner SARIF", committed_sarif, new_sarif),
                ("capture record", committed_record, new_record)):
            if not os.path.exists(old):
                rows.append((label, "NEW", "nothing committed yet"))
                continue
            a, b = sha256(old), sha256(new)
            if a == b:
                rows.append((label, "MATCH", a[:16]))
            else:
                rows.append((label, "DIFFER", "%s vs %s" % (a[:16], b[:16])))
                ok = False

        report_record(record)
        print()
        print("capture reproducibility, %s" % finding.id)
        print("-" * 58)
        for label, status, detail in rows:
            print("  %-18s %-7s %s" % (label, status, detail))
        print("-" * 58)
        print("RESULT:", "REPRODUCIBLE" if ok else "NOT REPRODUCIBLE")
        return 0 if ok else 1
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--finding", required=True, help="corpus finding id")
    p.add_argument("--captured", default=None,
                   help="date recorded in the artifacts (default: today)")
    p.add_argument("--force", action="store_true",
                   help="overwrite an existing benign baseline")
    p.add_argument("--check", action="store_true",
                   help="recapture into a scratch directory and compare "
                        "SHA-256 against what is committed, changing nothing")
    p.add_argument("--no-trap", action="store_true",
                   help="skip the note 1 trap demonstration")
    args = p.parse_args()

    try:
        finding = corpus.get_finding(args.finding)
    except corpus.ManifestError as e:
        print("manifest error: %s" % e)
        return 2

    try:
        if args.check:
            return do_check(finding)

        existing = finding.heldout_path("baseline")
        if os.path.exists(existing) and not args.force:
            print("refusing to overwrite an existing benign baseline:")
            print("  %s" % os.path.relpath(existing, ROOT))
            print()
            print("Check C compares every patched app against this file. "
                  "Regenerating it after patches have been scored would "
                  "silently invalidate every recorded result. Use --check to "
                  "confirm it still reproduces, or --force if you really mean "
                  "to replace it.")
            return 4

        record, path = baseline.capture(finding, captured=args.captured,
                                        run_trap=not args.no_trap)
        record_path = baseline.write_capture_record(finding, record)
        report_record(record)
        print()
        print("wrote %s" % os.path.relpath(path, ROOT))
        print("wrote %s" % os.path.relpath(record_path, ROOT))
        return 0
    except corpus.HeldOutMissing as e:
        print("INSUFFICIENT EVIDENCE: %s" % e)
        print("The benign baseline can only be captured from the held-out "
              "known-correct reference. Without it there is nothing to "
              "capture (protocol section 6).")
        return 3
    except baseline.CaptureError as e:
        print("capture failed: %s" % e)
        return 5


if __name__ == "__main__":
    sys.exit(main())
