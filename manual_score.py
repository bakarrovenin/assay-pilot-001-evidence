"""Assay Pilot 001 - scorer for a single patched app file.

This is the by-hand scorer from the section 7 manual run. Stage 1 of the
harness lifted its finding-specific constants into corpus/manifest.json and
moved the check logic into harness/scoring.py. The logic is unchanged: see
tools/verify_stage1_parity.py, which re-scores the three Finding 1 patches and
byte-compares the artifacts against the committed ones.

The four checks (protocol section 3, with the check D tightening from
METHODOLOGY-NOTES.md note 2) are documented in harness/scoring.py.

Usage:
  python manual_score.py patches/finding-01/fixer-01.py fixer-01
  python manual_score.py patches/finding-01/fixer-01.py fixer-01 --finding finding-01

Writes:
  results/<finding>/<tool>.json           publishable, no raw payloads
  heldout/<finding>/results/<tool>.json   full evidence incl. payloads (git-ignored)

If the held-out material is not present, which is the case in any public clone
of this repository, the scorer says so and exits without a verdict. Checks B
and C cannot run without it, and a verdict without evidence is worthless.
"""

import argparse
import sys

from harness import corpus, scoring


def main():
    p = argparse.ArgumentParser(
        description="Score one patched corpus app file against one finding.")
    p.add_argument("patched_app", help="the patched app file to score")
    p.add_argument("tool", help="name recorded in the artifact, e.g. fixer-01")
    p.add_argument("--finding", default="finding-01",
                   help="corpus finding id (default: finding-01)")
    p.add_argument("--run-date", default=None,
                   help="date recorded in the artifact (default: today). Pin "
                        "it to reproduce an earlier run byte for byte.")
    p.add_argument("--output-root", default=None,
                   help="write artifacts under this root instead of the "
                        "repository, for dry runs")
    args = p.parse_args()

    try:
        r = scoring.score(args.patched_app, args.tool,
                          finding_id=args.finding, run_date=args.run_date,
                          output_root=args.output_root)
    except corpus.HeldOutMissing as e:
        print("INSUFFICIENT EVIDENCE: %s" % e)
        print("Checks B and C need the held-out attack set, benign set and "
              "baseline. They are git-ignored and not published until Pilot "
              "002 exists (protocol section 6).")
        sys.exit(3)
    except corpus.ManifestError as e:
        print("manifest error: %s" % e)
        sys.exit(2)

    scoring.print_summary(r)


if __name__ == "__main__":
    main()
