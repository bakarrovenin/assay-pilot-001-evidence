"""Leak guard: no held-out payload text in any tracked file.

The integrity of this experiment is that a fixer is judged on inputs it has
never seen. This repository is public. If a held-out attack payload ever
appears in a tracked file it is readable by every vendor and by every future
training run, and the finding it belongs to is void (protocol section 1).

This script is the mechanical check.

  0. The tree it scans is complete. Every corpus material file that is not
     git-ignored (the public benchmark's attacks, benign sets, references) must
     be tracked, or a held-out payload inside an untracked file would be
     invisible to the search below. Present-but-untracked, or missing, is a hard
     failure, not a pass. This test exists because it once did pass on an
     incomplete tree: the benchmark material was present but not yet tracked, so
     the search never saw it, and the invariant was violated on the public repo
     for several days (METHODOLOGY-NOTES.md note 14).

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

  5. No explanatory prose in any module handed to a fixer. Hard failure.
     A comment or docstring in the vulnerable module, or in a support file
     that ships with it, that names the flaw, the shape, the sink, the
     attack, the scanner, the experiment or the fix. The vocabulary is in
     harness/prose.py. This test exists because findings 04, 08 and 13 were
     handed to three real tools with a docstring that said which fix works
     (METHODOLOGY-NOTES.md note 12), and tests 1 to 4 were correct by their
     own definition while it happened: none of them looks for prose.

corpus.load_manifest separately refuses to load a public manifest carrying
reference_fix, endpoint or oracle, so the answer key cannot drift back into
the tracked half by accident. That check runs here too.

Run it before every commit. Exit code 0 means no leak.

Usage:
  python tools/check_no_leak.py
"""

import glob
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from harness import corpus, prose

ROOT = corpus.ROOT

# Very short strings would match by accident. Anything shorter is not searched.
MIN_SEARCH_LEN = 5

# Every corpus in the repository: the pilot, and each benchmark edition. The
# guard must know about all of them, because a leak search that does not scan a
# corpus's files cannot report a leak in them (note 14).
MANIFESTS = [os.path.join("corpus", "manifest.json")] + [
    os.path.relpath(p, ROOT)
    for p in sorted(glob.glob(os.path.join(ROOT, "benchmark", "*", "manifest.json")))
]


def tracked_files():
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, stdout=subprocess.PIPE,
                         check=True).stdout.decode()
    return [p for p in out.splitlines() if p]


def git_ignored(rel):
    return subprocess.run(["git", "check-ignore", "-q", rel], cwd=ROOT).returncode == 0


def declared_material(entry):
    """Every corpus material path a built finding declares in its manifest."""
    app = entry.get("app", {})
    paths = [app.get("file"), app.get("scan_target")]
    paths += list(app.get("support_files") or [])
    for key, value in (entry.get("heldout") or {}).items():
        # "dir" is the directory the files live in, not a file; git tracks files.
        if key != "dir" and isinstance(value, str) and "/" in value:
            paths.append(value)
    paths.append(entry.get("reported_payload_file"))
    return [p for p in paths if p]


def blind_spots(tracked_set):
    """Corpus material the guard should scan but is not scanning.

    The bug this closes: the benchmark's public material was present in the
    working tree but not yet tracked, so it was absent from the file set this
    guard scans, and a held-out payload inside it was invisible. The guard
    reported NO LEAK while the invariant was in fact violated (note 14).

    A private corpus (the pilot) keeps its material git-ignored on purpose, and
    the guard reads it directly to search tracked files; that is expected and
    exempt. But any declared material that is NOT git-ignored must be tracked,
    or the guard is scanning an incomplete tree. Present-but-untracked or
    missing entirely both fail, rather than pass.
    """
    out = []
    for manifest in MANIFESTS:
        full_manifest = os.path.join(ROOT, manifest)
        if not os.path.exists(full_manifest):
            continue
        data = corpus.load_manifest(full_manifest)
        paths = []
        exp = data.get("experimenter_manifest")
        if exp:
            paths.append(exp)
        for entry in data["findings"]:
            if entry.get("status") == "built":
                paths += declared_material(entry)
        for rel in paths:
            if git_ignored(rel):
                continue  # private material, expected untracked
            if rel not in tracked_set:
                exists = os.path.exists(os.path.join(ROOT, rel))
                out.append((manifest, rel,
                            "present but untracked" if exists else "missing"))
    return out


def read_text(path):
    try:
        with open(os.path.join(ROOT, path), encoding="utf-8") as f:
            return f.read()
    except (UnicodeDecodeError, IsADirectoryError, FileNotFoundError):
        return None


def main():
    files = tracked_files()
    tracked_set = set(files)

    # TEST 0: the guard must be scanning a complete tree. Any corpus material
    # that is not git-ignored must be tracked, or a leak inside it is invisible
    # to the search below (note 14). This runs first: if the tree is incomplete
    # the rest of the guard cannot be trusted.
    incomplete = blind_spots(tracked_set)

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

    prose_leaks = []
    for finding in corpus.list_findings():
        if finding.status != "built":
            continue
        # TEST 5: needs no held-out material, so it runs before the skip.
        for rel in prose.handed_to_fixer(finding):
            text = contents.get(rel)
            if text is None:
                continue
            for line, kind, term, excerpt in prose.violations(text):
                prose_leaks.append((finding.id, rel, line, kind, term, excerpt))
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

    if incomplete:
        failed = True
        print("INCOMPLETE TREE: corpus material this guard should scan is not")
        print("tracked, so a held-out payload inside it would be invisible here")
        print("(note 14). Track it, or mark it git-ignored if it is private.")
        for manifest, rel, why in incomplete:
            print("  %-40s %s  (%s)" % (rel, why, manifest))
        print()

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

    if prose_leaks:
        failed = True
        print("LEAK: a module handed to fixers explains its own flaw or fix.")
        print("Comments and docstrings there may describe what the code does")
        print("for its users, nothing else (harness/prose.py, note 12).")
        seen = set()
        for fid, rel, line, kind, term, excerpt in prose_leaks:
            key = (fid, rel, line)
            if key in seen:
                continue
            seen.add(key)
            print("  %s %s:%d %s [%s] %s" % (fid, rel, line, kind, term, excerpt))
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
    print("  every corpus's material is in the scanned tree, heldout/ is")
    print("  untracked, no held-out attack payload appears in any tracked file,")
    print("  and no module handed to a fixer explains its flaw.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
