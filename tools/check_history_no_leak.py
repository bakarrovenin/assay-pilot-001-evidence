"""Leak guard for the git objects, not the working tree.

tools/check_no_leak.py searches the files that are tracked right now. That is
the right question for "does the repository contain a leak today" and the
wrong question for "does the history we are about to publish contain one".

A file can carry a secret in one commit and be cleaned in the next. The
working tree is then clean, the tracked-file guard reports NO LEAK, and the
earlier blob is still reachable from the history. Push it and that blob is
fetchable by SHA forever, whether or not any commit still references it.

That is not hypothetical. It is why this file exists. Before the first push of
this repository, corpus/manifest.json carried the finding-01 attack success
oracle in the Stage 1 commit, and the Stage 2 commit removed it. Every
tracked-file check passed. See METHODOLOGY-NOTES.md note 6.

## What is a hard failure

  a held-out attack payload in any blob or commit message
  the distinctive prose from the experimenter manifest
  any blob that parses as a manifest carrying reference_fix, endpoint or
    oracle for a finding, whether it is the experimenter file or a public
    manifest that should never have held those fields
  any object path under heldout/

## What is reported and not failed

The reported payload is published on purpose: it is the one hint a real
developer gets from a bug report. The known correct fix for finding-01 is
published on purpose too, in README.md and patches/finding-01/, and was not
retracted when the manifest split landed. Both are listed so that an
appearance somewhere unexpected is visible.

## It refuses to pass when it cannot check

Without the held-out material there is nothing to search for, so the guard
exits non-zero and says so rather than reporting a clean history it never
inspected. A guard that passes because it had nothing to compare against is
the failure mode this repository keeps finding in itself.

Usage:
  python tools/check_history_no_leak.py                # what a push would send
  python tools/check_history_no_leak.py --range HEAD   # the entire history
  python tools/check_history_no_leak.py --range origin/main..HEAD
"""

import argparse
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from harness import corpus

ROOT = corpus.ROOT
EXPERIMENTER = os.path.join(ROOT, "heldout", "corpus", "experimenter.json")

# Fields that mean a manifest blob is carrying the answer key.
ANSWER_KEY_FIELDS = ("reference_fix", "endpoint", "oracle")


def git(*args, binary=False):
    out = subprocess.run(["git"] + list(args), cwd=ROOT,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL).stdout
    return out if binary else out.decode(errors="replace")


def needles():
    """What to search for. Raises if the held-out material is not present."""
    held, reported = [], []
    for finding in corpus.list_findings():
        if finding.status != "built":
            continue
        for a in finding.load_attacks():
            target = reported if a.get("reported") else held
            target.append((finding.id, a["id"], a["payload"]))

    prose, fix_text = [], []
    with open(EXPERIMENTER, encoding="utf-8") as f:
        exp = json.load(f)
    for fid, entry in exp.get("findings", {}).items():
        oracle = entry.get("oracle") or {}
        for cls, spec in (oracle.get("classes") or {}).items():
            why = spec.get("why")
            if why and len(why) > 20:
                prose.append((fid, "oracle.%s.why" % cls, why))
        fix = entry.get("reference_fix") or {}
        for key in ("summary", "code", "strategy"):
            value = fix.get(key)
            if isinstance(value, str) and len(value) > 20:
                fix_text.append((fid, "reference_fix.%s" % key, value))
    note = exp.get("note")
    if note and len(note) > 20:
        prose.append(("manifest", "note", note))
    return held, reported, prose, fix_text


def carries_answer_key(text):
    """True if this blob is a manifest carrying answer-key fields.

    Parsed as JSON rather than searched as text. The harness source names all
    three fields in the validation that refuses them, and matching on the
    names alone would fail the guard on its own safety check.
    """
    try:
        data = json.loads(text)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    findings = data.get("findings")
    entries = []
    if isinstance(findings, dict):
        entries = list(findings.items())
    elif isinstance(findings, list):
        entries = [(e.get("id", "?"), e) for e in findings
                   if isinstance(e, dict)]
    for fid, entry in entries:
        if not isinstance(entry, dict):
            continue
        present = [f for f in ANSWER_KEY_FIELDS if f in entry]
        if present:
            return "%s carries %s" % (fid, ", ".join(present))
    return None


def blobs_in(rev_range):
    """Every blob reachable in this range, with the path it was seen at."""
    listing = [l.split(maxsplit=1) for l in
               git("rev-list", "--objects", rev_range).splitlines() if l]
    if not listing:
        return []
    paths = {o[0]: (o[1] if len(o) > 1 else "") for o in listing}
    check = subprocess.run(["git", "cat-file", "--batch-check"], cwd=ROOT,
                           input="\n".join(paths).encode(),
                           stdout=subprocess.PIPE).stdout.decode()
    out = []
    for line in check.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "blob":
            out.append((parts[0], paths.get(parts[0], "")))
    return out


def main():
    p = argparse.ArgumentParser(
        description="Search the git objects for held-out material.")
    p.add_argument("--range", dest="rev_range", default="origin/main..HEAD",
                   help="commit range to scan (default: what a push would "
                        "send). Pass HEAD to scan the entire history.")
    args = p.parse_args()

    if not os.path.exists(EXPERIMENTER):
        print("cannot check: the held-out material is not on this machine.")
        print("missing: %s" % os.path.relpath(EXPERIMENTER, ROOT))
        print("There is nothing to search for, so this guard will not report a "
              "clean history it never inspected.")
        return 3

    held, reported, prose, fix_text = needles()
    blobs = blobs_in(args.rev_range)
    commits = git("rev-list", args.rev_range).split()

    print("history leak guard")
    print("  range                 : %s" % args.rev_range)
    print("  commits               : %d" % len(commits))
    print("  blobs scanned         : %d" % len(blobs))
    print("  held-out payloads     : %d" % len(held))
    print("  experimenter prose    : %d" % len(prose))
    print()

    fails, notes = [], []

    for sha, path in blobs:
        where = path or sha[:12]
        if path.startswith("heldout/"):
            fails.append(("HELD-OUT PATH", where, sha[:12]))
        text = git("cat-file", "blob", sha, binary=True).decode(
            "utf-8", errors="replace")

        for fid, aid, payload in held:
            if payload and payload in text:
                fails.append(("HELD-OUT PAYLOAD", where, "%s/%s" % (fid, aid)))
        for fid, key, value in prose:
            if value in text:
                fails.append(("EXPERIMENTER PROSE", where, "%s %s" % (fid, key)))
        detail = carries_answer_key(text)
        if detail:
            fails.append(("ANSWER KEY IN MANIFEST", where, detail))

        for fid, aid, payload in reported:
            if payload and payload in text:
                notes.append(("reported payload", where, "%s/%s" % (fid, aid)))
        for fid, key, value in fix_text:
            if value in text:
                notes.append(("known correct fix", where, "%s %s" % (fid, key)))

    for commit in commits:
        message = git("cat-file", "commit", commit)
        for fid, aid, payload in held:
            if payload and payload in message:
                fails.append(("HELD-OUT PAYLOAD IN COMMIT MESSAGE",
                              commit[:12], "%s/%s" % (fid, aid)))

    if notes:
        print("Published on purpose (reported payload, and the correct fix for")
        print("finding-01, which was published during the manual run):")
        for kind, where, what in sorted(set(notes)):
            print("  %-18s %-42s %s" % (kind, where, what))
        print()

    if fails:
        print("LEAK IN HISTORY")
        for kind, where, what in sorted(set(fails)):
            print("  %-26s %-42s %s" % (kind, where, what))
        print()
        print("RESULT: DO NOT PUSH")
        print("  A blob stays fetchable by SHA after the file is cleaned, so "
              "removing it in a later commit is not enough. The offending "
              "commit has to be rewritten.")
        return 1

    print("RESULT: NO LEAK IN HISTORY")
    print("  No held-out payload, no experimenter prose, no manifest carrying "
          "the answer key, and no heldout/ path in any of the %d blobs or %d "
          "commit messages." % (len(blobs), len(commits)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
