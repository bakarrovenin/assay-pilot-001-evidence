"""Leak guard: no held-out payload text in any tracked file.

The integrity of this experiment is that a fixer is judged on inputs it has
never seen. This repository is public. If a held-out attack payload ever
appears in a tracked file it is readable by every vendor and by every future
training run, and the finding it belongs to is void (protocol section 1).

This script is the mechanical check. It runs three tests.

  1. Nothing under heldout/ is tracked by git. Hard failure if anything is.

  2. No held-out attack payload appears in any tracked file. Hard failure.
     "Held out" means every attack except the one marked "reported": true.
     The reported payload is not held out. It is published on purpose in
     reported/finding-NN-reported-payload.txt, because it is the one hint a
     real developer gets from a bug report, and a fixer may legitimately
     quote it in its own patch. Where it appears is reported, not failed.

  3. Benign inputs appearing in tracked files are reported, not failed. The
     benign set is built from the seeded catalogue in app/seed.py, which is
     published on purpose so anyone can run the app. Expected. Listed so that
     an appearance somewhere unexpected is visible.

  4. Known-correct fix code appearing in tracked files is reported, not
     failed. A published patch that happens to be a correct fix legitimately
     contains it, which is the case for Finding 1 today: fixer-01 is a correct
     parameterised fix and is published. Listed so that a fix appearing
     somewhere it was not deliberately published is visible.

corpus.load_manifest separately refuses to load a public manifest carrying
reference_fix, endpoint or oracle, so the answer key cannot drift back into
the tracked half by accident. That check runs here too.

Run it before every commit. Exit code 0 means no leak.

Usage:
  python tools/check_no_leak.py
"""

import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from harness import corpus

ROOT = corpus.ROOT

# Very short strings would match by accident. Anything shorter is not searched.
MIN_SEARCH_LEN = 5


def tracked_files():
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, stdout=subprocess.PIPE,
                         check=True).stdout.decode()
    return [p for p in out.splitlines() if p]


def read_text(path):
    try:
        with open(os.path.join(ROOT, path), encoding="utf-8") as f:
            return f.read()
    except (UnicodeDecodeError, IsADirectoryError, FileNotFoundError):
        return None


def main():
    files = tracked_files()

    # TEST 1: heldout/ must not be tracked at all.
    tracked_heldout = [p for p in files if p == "heldout" or p.startswith("heldout/")]

    contents = {}
    for path in files:
        text = read_text(path)
        if text is not None:
            contents[path] = text

    leaks, reported_seen, benign_seen, skipped = [], set(), set(), []
    fix_seen, manifest_error = set(), None

    # The public manifest must not carry the answer key. load_manifest raises
    # if it does; surface that here rather than only at scoring time.
    try:
        corpus.load_manifest()
    except corpus.ManifestError as e:
        manifest_error = str(e)

    for finding in corpus.list_findings():
        if finding.status != "built":
            continue
        missing = finding.missing_heldout(("attacks", "benign"))
        if missing:
            skipped.append((finding.id, missing))
            continue

        for attack in finding.load_attacks():
            payload = attack["payload"]
            if len(payload) < MIN_SEARCH_LEN:
                continue
            for path, text in contents.items():
                if payload not in text:
                    continue
                if attack.get("reported"):
                    # TEST 2 exception: the reported payload is public.
                    reported_seen.add((finding.id, attack["id"], path))
                else:
                    leaks.append((finding.id, attack["id"], attack["class"], path))

        # TEST 3: informational only.
        for entry in finding.load_benign():
            value = entry["input"]
            if len(value) < MIN_SEARCH_LEN:
                continue
            for path, text in contents.items():
                if value in text:
                    benign_seen.add((finding.id, path))

        # TEST 4: informational only.
        try:
            fix_code = finding.reference_fix.get("code", "")
        except corpus.HeldOutMissing:
            fix_code = ""
        for line in [l.strip() for l in fix_code.splitlines() if l.strip()]:
            if len(line) < MIN_SEARCH_LEN:
                continue
            for path, text in contents.items():
                if line in text:
                    fix_seen.add((finding.id, path))

    print("leak guard: %d tracked files searched" % len(contents))
    for finding_id, missing in skipped:
        print("  SKIP %s: held-out material not present (%s)"
              % (finding_id, ", ".join(missing)))

    if reported_seen:
        print()
        print("Reported payloads in tracked files (published on purpose):")
        for finding_id, attack_id, path in sorted(reported_seen):
            print("  %s %s  in  %s" % (finding_id, attack_id, path))

    if benign_seen:
        print()
        print("Benign inputs visible in tracked files (expected for the seeded")
        print("catalogue, review anything outside app/ and the patches):")
        for finding_id, path in sorted(benign_seen):
            print("  %s  in  %s" % (finding_id, path))

    if fix_seen:
        print()
        print("Known-correct fix code visible in tracked files (expected where")
        print("a published patch is itself a correct fix, review anything else):")
        for finding_id, path in sorted(fix_seen):
            print("  %s  in  %s" % (finding_id, path))

    print()
    failed = False

    if manifest_error:
        failed = True
        print("LEAK: the public manifest carries experimenter material.")
        print("  %s" % manifest_error)
        print()

    if tracked_heldout:
        failed = True
        print("LEAK: files under heldout/ are tracked by git.")
        for path in tracked_heldout:
            print("  %s" % path)
        print()

    if leaks:
        failed = True
        print("LEAK: held-out attack payload text found in tracked files.")
        print("The findings below are VOID until the payloads are regenerated")
        print("(protocol section 1).")
        for finding_id, attack_id, klass, path in sorted(set(leaks)):
            print("  %s %s (%s)  in  %s" % (finding_id, attack_id, klass, path))
        print()

    if failed:
        print("RESULT: LEAK DETECTED")
        return 1

    print("RESULT: NO LEAK")
    print("  heldout/ is untracked, and no held-out attack payload appears in")
    print("  any tracked file.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
