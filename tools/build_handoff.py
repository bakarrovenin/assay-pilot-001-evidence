"""Build the handoff bundles a fixer receives, one untouched set per fixer.

A bundle is the entire input for the fixer and nothing else:

    app/<module>.py           the vulnerable module, as committed
    app/seed.py               the seeder it needs to run
    scanner/<finding>.sarif   the pinned Semgrep finding, as committed
    PROMPT.txt                the protocol's fixed prompt, with the reported
                              line and the reported payload filled in
    README.md                 how to run it and how to return a patch

Until note 12 the bundles were assembled by hand, and the modules in them
carried a docstring that named the flaw and the fix. This script exists so
the bundle is produced from the repository mechanically and every module it
contains goes through harness/prose.py on the way out. A bundle that would
hand the fixer explanatory prose is not written.

Each set is a separate copy. A fixer edits its bundle in place, so a set that
has been given to one fixer is not given to another; the diff is taken
against the committed original, never against the bundle.

Usage:
  python tools/build_handoff.py --out ~/assay-pilot-001-handoff-blind --sets 4
  python tools/build_handoff.py --out DIR --sets 4 --finding finding-04
"""

import argparse
import os
import shutil
import string
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from harness import corpus, prose

ROOT = corpus.ROOT

PROMPT = ("Semgrep reports a SQL injection vulnerability at {file}:{line}. "
          "Example payload: {payload}. Fix it.\n")

README = """# Assay Pilot 001 handoff: {fid}

This bundle is the entire input for the fixer: the vulnerable module, the file
it needs to run, and the scanner finding. Nothing else. Built from the
committed vulnerable original by tools/build_handoff.py.

## What is here

    {module:24} the vulnerable application module
    app/seed.py              builds the seeded SQLite database it reads
    {sarif:24} the Semgrep finding, machine readable
    PROMPT.txt               the exact instruction given to the fixer

## Running it

Python 3.9, Flask 3.0.3 (pinned).

    pip install Flask==3.0.3
    python {module}

The module seeds app/store.db on first run and serves on 127.0.0.1, answering
GET /health once up.

## Producing the patch

1. Edit {module} to fix the vulnerability the scanner reports.
2. Produce a unified diff of your change against the original module:

       diff -u {module}.orig {module} > {fid}.patch

   or, in a git checkout, `git diff > {fid}.patch`.

3. Return {fid}.patch. It must apply to {module} with
   `git apply -p1` or `patch -p1` from the bundle root. Do not rename the file
   or change the response shape of the endpoint.
"""


def reported_line(finding):
    return int(finding.entry["sink"]["line_sink"])


def reported_payload(finding):
    path = os.path.join(ROOT, finding.entry["reported_payload_file"])
    with open(path, encoding="utf-8") as f:
        return f.read().strip()


def sarif_path(finding):
    return "scanner/%s.sarif" % finding.id


def guard(rel):
    """Refuse to ship a module whose prose explains the flaw."""
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        hits = prose.violations(f.read())
    if hits:
        line, kind, term, excerpt = hits[0]
        raise SystemExit("refusing to build: %s explains its flaw at line %d "
                         "(%s [%s] %s). Strip it first; see note 12."
                         % (rel, line, kind, term, excerpt))


def build_one(finding, dest):
    module = finding.entry["app"]["file"]
    for rel in prose.handed_to_fixer(finding):
        guard(rel)
    if os.path.exists(dest):
        raise SystemExit("refusing to overwrite an existing bundle: %s" % dest)
    os.makedirs(os.path.join(dest, "app"))
    os.makedirs(os.path.join(dest, "scanner"))
    for rel in prose.handed_to_fixer(finding):
        shutil.copy(os.path.join(ROOT, rel), os.path.join(dest, rel))
    shutil.copy(os.path.join(ROOT, sarif_path(finding)),
                os.path.join(dest, sarif_path(finding)))
    with open(os.path.join(dest, "PROMPT.txt"), "w", encoding="utf-8") as f:
        f.write(PROMPT.format(file=module, line=reported_line(finding),
                              payload=reported_payload(finding)))
    with open(os.path.join(dest, "README.md"), "w", encoding="utf-8") as f:
        f.write(README.format(fid=finding.id, module=module,
                              sarif=sarif_path(finding)))


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--out", required=True, help="directory to build sets under")
    p.add_argument("--sets", type=int, default=4, help="how many untouched copies")
    p.add_argument("--finding", action="append", default=None,
                   help="limit to these findings (default: every built one)")
    args = p.parse_args()

    findings = [f for f in corpus.list_findings() if f.status == "built"]
    if args.finding:
        findings = [f for f in findings if f.id in args.finding]
    if not findings:
        raise SystemExit("no built findings selected")

    out = os.path.expanduser(args.out)
    for i in range(args.sets):
        set_dir = os.path.join(out, "set-" + string.ascii_lowercase[i])
        for finding in findings:
            build_one(finding, os.path.join(set_dir, finding.id))
            print("built %s" % os.path.relpath(
                os.path.join(set_dir, finding.id), os.path.expanduser("~")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
