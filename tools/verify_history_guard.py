"""The history guard is checked in both directions, on a fixture built here.

tools/check_history_no_leak.py reads git objects rather than the working tree.
Every time it has been run on this repository it has reported NO LEAK IN
HISTORY, which is the answer we want and, on its own, no evidence at all. A
guard that has only ever passed has not been tested. That is the pattern
recorded in METHODOLOGY-NOTES.md notes 2, 4 and 6, and it is what this script
exists to close.

## Why the fixture is built rather than committed

The obvious way to test a leak guard is to commit a repository that leaks and
point the guard at it. We cannot do that. Reproducing the pre-rewrite history
means committing a manifest carrying the finding-01 oracle, which is precisely
the material note 6 records rewriting out of this history. A committed fixture
would be the leak it is testing for.

So the fixture is assembled at run time in a temporary directory, from the
git-ignored held-out material already on an experimenter machine, and deleted
when the run ends. Nothing it contains enters this repository's history. On a
machine without heldout/ there is nothing to build a fixture from, and this
script says so and exits non-zero rather than reporting a guard it never
exercised.

## The three cases

  1. leak in the working tree     a manifest carrying the answer key and a
                                  file carrying a held-out payload, committed.
                                  The guard must fail.

  2. leak cleaned in a later      the same repository, with a second commit
     commit, blob still in        deleting both files. The working tree is
     history                      clean and tools/check_no_leak.py would pass.
                                  The guard must still fail, because the blob
                                  is reachable in the range. This is note 6
                                  exactly, and it is the case worth having.

  3. no leak                      a repository with neither. The guard must
                                  pass, so case 1 and 2 are not just a guard
                                  that fails on everything.

  4. the real pre-rewrite commit  opportunistic. The Stage 1 commit that
                                  actually carried the answer key is still in
                                  this clone's object store, unreferenced,
                                  until git collects it. While it is there the
                                  guard is run over the genuine article rather
                                  than a reconstruction, and must fail.

Case 4 is skipped, loudly, once that object is gone. It is evidence while it
lasts and it is not something we can commit, for the same reason the fixture
is not committed: the object is the leak.

Exit code 0 means the guard failed when it should and passed when it should.

Usage:
  python tools/verify_history_guard.py
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from harness import corpus

ROOT = corpus.ROOT
GUARD = os.path.join(ROOT, "tools", "check_history_no_leak.py")
EXPERIMENTER = os.path.join(ROOT, "heldout", "corpus", "experimenter.json")


def git(repo, *args):
    return subprocess.run(["git"] + list(args), cwd=repo,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def init(repo):
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.email", "fixture@localhost")
    git(repo, "config", "user.name", "fixture")
    git(repo, "config", "commit.gpgsign", "false")


def commit(repo, message):
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)


def leaking_manifest():
    """A public manifest shaped like the one the Stage 1 commit carried.

    Built from the real experimenter manifest, so the guard is searching for
    the same needles it would search for on a real push rather than for a
    string invented here.
    """
    with open(EXPERIMENTER, encoding="utf-8") as f:
        exp = json.load(f)
    findings = []
    for fid, entry in sorted(exp.get("findings", {}).items()):
        leaked = {"id": fid, "status": "built"}
        for field in ("reference_fix", "endpoint", "oracle"):
            if field in entry:
                leaked[field] = entry[field]
        findings.append(leaked)
    return {"pilot": "assay-pilot-001", "schema_version": 1,
            "findings": findings}


def held_out_payload():
    """One real held-out attack payload, the thing that must never be public."""
    for finding in corpus.list_findings():
        if finding.status != "built":
            continue
        for a in finding.load_attacks():
            if not a.get("reported") and a.get("payload"):
                return finding.id, a["id"], a["payload"]
    return None, None, None


def build_fixture(root, with_leak, then_clean):
    repo = os.path.join(root, "clean" if not with_leak else
                        ("cleaned" if then_clean else "leaking"))
    os.makedirs(os.path.join(repo, "corpus"))
    init(repo)

    with open(os.path.join(repo, "README.md"), "w", encoding="utf-8") as f:
        f.write("fixture repository for tools/verify_history_guard.py\n")

    if with_leak:
        with open(os.path.join(repo, "corpus", "manifest.json"), "w",
                  encoding="utf-8") as f:
            json.dump(leaking_manifest(), f, indent=2)
        fid, aid, payload = held_out_payload()
        with open(os.path.join(repo, "attacks_notes.txt"), "w",
                  encoding="utf-8") as f:
            f.write("scratch notes\n%s %s\n%s\n" % (fid, aid, payload))
    else:
        with open(os.path.join(repo, "corpus", "manifest.json"), "w",
                  encoding="utf-8") as f:
            json.dump({"pilot": "assay-pilot-001", "schema_version": 1,
                       "findings": [{"id": "finding-01", "status": "built",
                                     "shape": "quoted-string context"}]},
                      f, indent=2)

    commit(repo, "first commit")

    if with_leak and then_clean:
        # Exactly the shape of note 6: the file is cleaned in a later commit,
        # the working tree is now spotless, and the blob is still reachable.
        os.remove(os.path.join(repo, "attacks_notes.txt"))
        with open(os.path.join(repo, "corpus", "manifest.json"), "w",
                  encoding="utf-8") as f:
            json.dump({"pilot": "assay-pilot-001", "schema_version": 1,
                       "findings": [{"id": "finding-01", "status": "built",
                                     "shape": "quoted-string context"}]},
                      f, indent=2)
        commit(repo, "split the answer key out of the public manifest")

    return repo


def run_guard(repo):
    return run_guard_on(repo, "HEAD")


def run_guard_on(repo, rev_range):
    proc = subprocess.run(
        [sys.executable, GUARD, "--repo", repo, "--range", rev_range],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return proc.returncode, proc.stdout.decode(errors="replace")


CASES = [
    # label, with_leak, then_clean, expected exit, what the output must contain
    ("leak in the working tree", True, False, 1, "LEAK IN HISTORY"),
    ("leak cleaned later, blob still in history", True, True, 1,
     "LEAK IN HISTORY"),
    ("no leak", False, False, 0, "NO LEAK IN HISTORY"),
]


def find_pre_rewrite_commit():
    """The real commit that carried the answer key, if it is still here.

    It was rewritten out before the first push and nothing references it, so
    it survives only until git collects the object. Found by inspecting the
    manifest blob of every commit this clone can still reach, including the
    reflog, rather than by hard-coding a SHA that will stop existing.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import check_history_no_leak as guard

    listing = subprocess.run(
        ["git", "rev-list", "--all", "--reflog"], cwd=ROOT,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.decode()
    for sha in listing.split():
        tree = subprocess.run(
            ["git", "ls-tree", "-r", sha, "--", "corpus/manifest.json"],
            cwd=ROOT, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL).stdout.decode().split()
        if len(tree) < 3:
            continue
        blob = subprocess.run(["git", "cat-file", "blob", tree[2]], cwd=ROOT,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL).stdout.decode(
                                  errors="replace")
        if guard.carries_answer_key(blob):
            return sha
    return None


def main():
    if not os.path.exists(EXPERIMENTER):
        print("cannot check: the held-out material is not on this machine.")
        print("missing: %s" % os.path.relpath(EXPERIMENTER, ROOT))
        print("There is nothing to build a fixture from, so this script will "
              "not report a guard it never exercised.")
        return 3

    fid, aid, payload = held_out_payload()
    if not payload:
        print("cannot check: no held-out attack payload found to plant.")
        return 3

    work = tempfile.mkdtemp(prefix="assay_history_guard_")
    results = []
    try:
        for label, with_leak, then_clean, want_code, want_text in CASES:
            repo = build_fixture(work, with_leak, then_clean)
            code, out = run_guard(repo)
            ok = (code == want_code) and (want_text in out)
            results.append((label, want_code, code, ok, out))
    finally:
        # The fixture holds real held-out material. It does not outlive the run.
        shutil.rmtree(work, ignore_errors=True)

    # The genuine article, while this clone still has it.
    real = find_pre_rewrite_commit()
    real_result = None
    if real:
        code, out = run_guard_on(ROOT, real)
        real_result = (real, code, "LEAK IN HISTORY" in out)

    print("History guard, checked in both directions")
    print("=" * 70)
    print("  fixture payload      : %s/%s (planted, not committed here)"
          % (fid, aid))
    print("  fixtures             : %d" % len(CASES))
    print()
    for label, want, got, ok, _out in results:
        print("  %-6s %-44s exit %d, wanted %d"
              % ("ok" if ok else "FAIL", label, got, want))
    if real_result:
        sha, code, found = real_result
        print("  %-6s %-44s exit %d, wanted 1"
              % ("ok" if (code == 1 and found) else "FAIL",
                 "the real pre-rewrite commit %s" % sha[:12], code))
    else:
        print("  %-6s %-44s %s"
              % ("skip", "the real pre-rewrite commit",
                 "collected by git, no longer in this clone"))
    print("=" * 70)

    bad = [r for r in results if not r[3]]
    if real_result and not (real_result[1] == 1 and real_result[2]):
        print()
        print("  WRONG RESULT: the guard did not fail on commit %s, which "
              "carries the answer key." % real_result[0][:12])
        print("RESULT: THE HISTORY GUARD DID NOT BEHAVE AS CLAIMED")
        return 1
    if bad:
        for label, want, got, _ok, out in bad:
            print()
            print("  WRONG RESULT: %s (exit %d, wanted %d)" % (label, got, want))
            print("  " + "\n  ".join(out.strip().splitlines()[-12:]))
        print("RESULT: THE HISTORY GUARD DID NOT BEHAVE AS CLAIMED")
        return 1

    print("RESULT: THE HISTORY GUARD FAILS ON A LEAK, INCLUDING ONE CLEANED")
    print("  FROM THE WORKING TREE, AND PASSES ON A CLEAN HISTORY")
    return 0


if __name__ == "__main__":
    sys.exit(main())
