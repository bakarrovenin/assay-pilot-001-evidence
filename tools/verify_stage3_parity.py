"""Stage 3 gate: containerising the scorer changed nothing about the result.

Stage 1 proved that moving the scoring core out of manual_score.py into
harness/scoring.py left Finding 1 scoring identically. This is the same
argument one layer out. The claim is that running the four checks inside a
container with no network egress changes where they run and not what they
conclude.

The claim is worth distrusting, which is why it is tested rather than
asserted. The container is a different operating system, a different libc and
a different SQLite build from the machine the committed evidence was produced
on. Any of those could plausibly move a response body, and a moved response
body would move check C.

Three things are checked, in order of how much they would hurt.

  1. Byte parity.  Each patch is re-scored in a container and every artifact
     is byte-compared against the one committed from the manual run. The
     scorer is fed the same input stage 1 was fed, an already patched file,
     so the comparison is like for like.

  2. Diff path agreement.  The same patch is scored again from its unified
     diff, the input shape stage 3 is actually specified around. Every field
     except patch_file must be identical. patch_file is expected to differ:
     it records what was scored, and in one run that is the diff and in the
     other the patched file.

  3. Isolation.  Every run has to report that it measured no egress from
     inside the container. A parity pass in a container that could reach the
     network would prove the wrong thing.

The run date is pinned to the original. It is the one field that cannot
reproduce itself.

Exit code 0 means parity held, the diff path agreed, and every run was
isolated.

Usage:
  python tools/verify_stage3_parity.py
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from harness import container, corpus

ROOT = corpus.ROOT

FINDING = "finding-01"
ORIGINAL_RUN_DATE = "2026-09-08"
TOOLS = ["fixer-01", "fixer-02", "fixer-03"]

# The fields whose change would mean containerisation altered the result
# rather than merely relocating it. Named explicitly so the gate cannot be
# widened by accident later.
VERDICT_FIELDS = ("verdict", "failure_class")


def sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def compare_bytes(label, committed, regenerated, report):
    if not os.path.exists(committed):
        report.append((label, "SKIP", "no committed artifact at %s"
                       % os.path.relpath(committed, ROOT)))
        return True
    if not os.path.exists(regenerated):
        report.append((label, "FAIL", "container produced no artifact"))
        return False
    a, b = sha256(committed), sha256(regenerated)
    if a == b:
        report.append((label, "MATCH", a[:16]))
        return True
    diff = subprocess.run(["diff", "-u", committed, regenerated],
                          stdout=subprocess.PIPE).stdout.decode()
    report.append((label, "DIFFER", "\n" + diff))
    return False


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def compare_ignoring_patch_file(label, a_path, b_path, report):
    """Diff path vs file path. Everything but patch_file must agree."""
    if not (os.path.exists(a_path) and os.path.exists(b_path)):
        report.append((label, "FAIL", "one side produced no artifact"))
        return False
    a, b = load(a_path), load(b_path)
    a.pop("patch_file", None)
    b.pop("patch_file", None)
    if a == b:
        report.append((label, "AGREE", "all fields except patch_file"))
        return True
    differing = sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))
    report.append((label, "DIFFER", "fields: %s" % ", ".join(differing)))
    return False


def summarise_isolation(prov):
    iso = (prov.get("container_observed") or {}).get("isolation") or {}
    return {
        "requested": prov["execution"]["requested_isolation"],
        "observed": iso.get("observed_mode"),
        "egress_blocked": iso.get("egress_blocked"),
        "reached": iso.get("reached"),
        "bind_mounts": prov["execution"]["bind_mounts"],
        "image_id": prov["execution"]["image_id"],
    }


def run_one(tool, scratch, use_diff):
    """Score one patch in a container. Returns (outcome, provenance, root)."""
    kind = "diff" if use_diff else "file"
    dest = os.path.join(scratch, kind)
    os.makedirs(dest, exist_ok=True)
    kwargs = {"run_date": ORIGINAL_RUN_DATE, "mode": "network-none"}
    if use_diff:
        kwargs["patch"] = os.path.join(ROOT, "patches", FINDING, tool + ".patch")
    else:
        kwargs["patched_file"] = os.path.join(ROOT, "patches", FINDING,
                                              tool + ".py")
    outcome, provenance, out_dir = container.score_in_container(
        tool, finding_id=FINDING, **kwargs)
    try:
        for rel_root in ("results", "heldout"):
            src = os.path.join(out_dir, rel_root)
            if os.path.isdir(src):
                shutil.copytree(src, os.path.join(dest, rel_root),
                                dirs_exist_ok=True)
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)
    return outcome, provenance, dest


def main():
    finding = corpus.get_finding(FINDING)
    missing = finding.missing_heldout()
    if missing:
        print("INSUFFICIENT EVIDENCE: cannot verify parity without the "
              "held-out material.")
        print("missing: %s" % ", ".join(missing))
        return 3

    try:
        container.require_docker()
    except container.DockerUnavailable as e:
        print("INSUFFICIENT EVIDENCE: no container runtime. %s" % e)
        return 3
    if not container.image_exists():
        print("building %s ..." % container.IMAGE)
        container.build_image(quiet=True)

    scratch = tempfile.mkdtemp(prefix="assay_stage3_")
    report, isolation_rows, ok = [], [], True
    verdicts = {}
    try:
        for tool in TOOLS:
            print("scoring %s in a container (file input) ..." % tool)
            outcome_f, prov_f, root_f = run_one(tool, os.path.join(scratch, tool),
                                                use_diff=False)
            print("  verdict: %s  class: %s" % (outcome_f.get("verdict"),
                                                outcome_f.get("failure_class")))
            isolation_rows.append((tool + " file", summarise_isolation(prov_f)))
            verdicts[tool] = outcome_f

            if outcome_f.get("verdict") == "INSUFFICIENT EVIDENCE":
                report.append((tool + " run", "FAIL",
                               "container returned INSUFFICIENT EVIDENCE: %s"
                               % outcome_f.get("reason")))
                ok = False
                continue

            ok &= compare_bytes(
                "%s published" % tool,
                os.path.join(ROOT, finding.results_dir, tool + ".json"),
                os.path.join(root_f, finding.results_dir, tool + ".json"),
                report)
            ok &= compare_bytes(
                "%s held-out" % tool,
                os.path.join(finding.heldout_results_dir(ROOT), tool + ".json"),
                os.path.join(root_f, finding.entry["heldout"]["dir"],
                             "results", tool + ".json"),
                report)

            print("scoring %s in a container (diff input) ..." % tool)
            outcome_d, prov_d, root_d = run_one(tool, os.path.join(scratch, tool),
                                                use_diff=True)
            print("  verdict: %s  class: %s" % (outcome_d.get("verdict"),
                                                outcome_d.get("failure_class")))
            isolation_rows.append((tool + " diff", summarise_isolation(prov_d)))

            ok &= compare_ignoring_patch_file(
                "%s diff vs file" % tool,
                os.path.join(root_f, finding.results_dir, tool + ".json"),
                os.path.join(root_d, finding.results_dir, tool + ".json"),
                report)

            for field in VERDICT_FIELDS:
                if outcome_d.get(field) != outcome_f.get(field):
                    report.append(("%s %s" % (tool, field), "DIFFER",
                                   "file=%r diff=%r" % (outcome_f.get(field),
                                                        outcome_d.get(field))))
                    ok = False
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    # Isolation is a gate, not a note. A parity pass in a container that could
    # reach the network proves the wrong thing.
    isolated = True
    for label, iso in isolation_rows:
        if not iso["egress_blocked"] or iso["bind_mounts"]:
            isolated = False
            report.append(("%s isolation" % label, "FAIL",
                           "egress_blocked=%s reached=%s bind_mounts=%s"
                           % (iso["egress_blocked"], iso["reached"],
                              iso["bind_mounts"])))
    ok &= isolated

    print()
    print("Stage 3 parity, %s" % FINDING)
    print("=" * 68)
    print("verdicts (committed -> container)")
    for tool in TOOLS:
        committed = load(os.path.join(ROOT, finding.results_dir, tool + ".json"))
        got = verdicts.get(tool, {})
        same = (committed["verdict"] == got.get("verdict")
                and committed["failure_class"] == got.get("failure_class"))
        print("  %-9s %s / %-28s -> %s / %-28s %s"
              % (tool, committed["verdict"], committed["failure_class"],
                 got.get("verdict"), got.get("failure_class"),
                 "same" if same else "CHANGED"))
    print("-" * 68)
    print("artifact comparison")
    for label, status, detail in report:
        print("  %-22s %-7s %s" % (label, status, detail))
    print("-" * 68)
    print("isolation actually measured, per run")
    for label, iso in isolation_rows:
        print("  %-16s requested=%s observed=%s egress_blocked=%s mounts=%s"
              % (label, iso["requested"], iso["observed"],
                 iso["egress_blocked"], iso["bind_mounts"] or "none"))
    print("=" * 68)
    print("RESULT:", "PARITY HELD" if ok else "PARITY BROKEN")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
