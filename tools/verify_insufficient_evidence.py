"""INSUFFICIENT EVIDENCE is a result. Prove it actually fires.

The protocol makes INSUFFICIENT EVIDENCE first class: the app would not build,
the patch would not apply, the harness could not execute the attack set. The
danger with a state like that is not that it is wrong, it is that it quietly
never happens, and a run that should have refused to answer instead reports a
confident verdict built on nothing.

The worst of those is check B. Every attack in check B is judged by whether the
response leaked data. If the patched app never started, every attack fails to
connect, every one is recorded as "did not succeed", and the patch scores as
though it shut the hole. A silent failure in that direction does not look like
a bug. It looks like a pass.

So each way a run can fail to produce a verdict is provoked here on purpose,
and the scorer has to name it. A test that only ever exercises the happy path
would not have caught the startup case, which is exactly why it is in this
list.

  patch did not apply      a diff that does not match the file
  patched app did not start  a patch that raises on import
  isolation not established  a container that can reach the network
  held-out material missing  checks B and C have nothing to fire

The isolation case deliberately runs a container WITH egress, which is the one
thing the rest of the harness exists to prevent. It is safe here because
nothing is scored: the run is refused before any patched code is imported or
any payload is built. That ordering is the thing being tested.

Exit code 0 means every failure path reported itself.

Usage:
  python tools/verify_insufficient_evidence.py
"""

import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from harness import container, corpus

ROOT = corpus.ROOT
FINDING = "finding-01"


def run(**kwargs):
    outcome, provenance, out_dir = container.score_in_container(
        "probe", finding_id=FINDING, **kwargs)
    shutil.rmtree(out_dir, ignore_errors=True)
    return outcome, provenance


def case_patch_will_not_apply(results):
    """A diff whose context does not match cannot be scored."""
    tmp = tempfile.mkdtemp(prefix="assay_badpatch_")
    diff = os.path.join(tmp, "bad.patch")
    with open(diff, "w", encoding="utf-8") as f:
        f.write("diff --git a/app/corpus_app.py b/app/corpus_app.py\n"
                "--- a/app/corpus_app.py\n"
                "+++ b/app/corpus_app.py\n"
                "@@ -1,3 +1,3 @@\n"
                "-this line is not in the file\n"
                "+neither is this one\n"
                " context that does not exist\n")
    try:
        outcome, _ = run(patch=diff)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    results.append(("patch did not apply", outcome,
                    outcome.get("reason") == "patch did not apply"))


def case_app_will_not_start(results):
    """A patch that raises on import must not score as a shut hole."""
    tmp = tempfile.mkdtemp(prefix="assay_deadapp_")
    dest = os.path.join(ROOT, "patches", FINDING, "_probe_deadapp.py")
    with open(dest, "w", encoding="utf-8") as f:
        f.write("raise RuntimeError('this patch does not import')\n")
    try:
        outcome, _ = run(patched_file=dest)
    finally:
        os.remove(dest)
        shutil.rmtree(tmp, ignore_errors=True)
    results.append(("patched app did not start", outcome,
                    outcome.get("reason") == "patched app did not start"))


def case_container_has_egress(results):
    """A container that can reach the network is refused before scoring."""
    original = dict(container.MODE_FLAGS)
    container.MODE_FLAGS["probe-bridge"] = ["--network", "bridge"]
    try:
        outcome, provenance = run(
            patched_file=os.path.join(ROOT, "patches", FINDING, "fixer-01.py"),
            mode="probe-bridge")
    finally:
        container.MODE_FLAGS.clear()
        container.MODE_FLAGS.update(original)
    iso = (provenance.get("container_observed") or {}).get("isolation") or {}
    ok = (outcome.get("reason") == "isolation not established"
          and iso.get("egress_blocked") is False
          and iso.get("observed_mode") == "routed")
    results.append(("isolation not established", outcome, ok))


def case_heldout_missing(results):
    """Without the held-out material there is nothing for B and C to fire."""
    original = set(container.COPY_EXCLUDE)
    container.COPY_EXCLUDE.add("heldout")
    try:
        outcome, _ = run(patched_file=os.path.join(ROOT, "patches", FINDING,
                                                   "fixer-01.py"))
    finally:
        container.COPY_EXCLUDE.clear()
        container.COPY_EXCLUDE.update(original)
    results.append(("held-out material missing", outcome,
                    outcome.get("reason") == "held-out material missing"))


CASES = [
    case_patch_will_not_apply,
    case_app_will_not_start,
    case_container_has_egress,
    case_heldout_missing,
]


def main():
    try:
        container.require_docker()
    except container.DockerUnavailable as e:
        print("cannot run: %s" % e)
        return 3
    if not container.image_exists():
        print("building %s ..." % container.IMAGE)
        container.build_image(quiet=True)

    results = []
    for case in CASES:
        print("provoking: %s ..." % case.__doc__.splitlines()[0])
        case(results)

    print()
    print("INSUFFICIENT EVIDENCE paths")
    print("=" * 70)
    ok = True
    for expected, outcome, passed in results:
        verdict = outcome.get("verdict")
        got = outcome.get("reason")
        # The verdict must be INSUFFICIENT EVIDENCE and the reason must be the
        # specific one. A run that refused for the wrong reason is still a bug.
        good = passed and verdict == "INSUFFICIENT EVIDENCE"
        ok &= good
        print("  %-28s %s" % (expected, "OK" if good else "FAILED"))
        print("      verdict: %s" % verdict)
        print("      reason : %s" % got)
        if not good:
            print("      detail : %s" % (outcome.get("detail") or "")[:400])
    print("=" * 70)
    print("RESULT:", "ALL FAILURE PATHS REPORT THEMSELVES" if ok
          else "A FAILURE PATH WAS SILENT")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
