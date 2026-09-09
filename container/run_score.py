"""Score one patch, inside the container. Never run this on the host.

This is the only thing the scoring image executes. It measures its own
isolation, applies the patch to a clean checkout, runs the four checks, and
writes everything it learned into the output directory the host collects.

Order matters here. Isolation is measured before any patched code is imported
or any attack payload is constructed. If the container turns out to have
egress, nothing is scored at all: the run stops and reports INSUFFICIENT
EVIDENCE. A result produced in a container that could reach the network is not
a result we are willing to publish, and quietly downgrading it to a warning is
exactly the silent failure this stage exists to remove.

Everything written to the output directory:

  results/<finding>/<tool>.json           publishable evidence, unchanged
                                          schema, byte identical to stage 1
  heldout/<finding>/results/<tool>.json   full evidence including payloads
  _container.json                         what the container observed about
                                          itself: isolation, patch
                                          application, artifact hashes
  _outcome.json                           the verdict, or the reason there
                                          is not one

_container.json is deliberately separate from the evidence artifacts. The
evidence keeps the stage 1 schema so it can still be byte-compared against the
committed results; the provenance the host merges around it carries the
isolation record. See tools/verify_stage3_parity.py.
"""

import argparse
import hashlib
import json
import os
import platform
import shutil
import sys
import traceback

sys.path.insert(0, "/assay")

from harness import corpus, isolation, patching, scoring


def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def write(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def insufficient(out, reason, detail, iso=None, extra=None):
    """Record INSUFFICIENT EVIDENCE and say why, in a file the host reads."""
    outcome = {
        "verdict": "INSUFFICIENT EVIDENCE",
        "reason": reason,
        "detail": detail,
    }
    if extra:
        outcome.update(extra)
    write(os.path.join(out, "_outcome.json"), outcome)
    write(os.path.join(out, "_container.json"), {
        "isolation": iso,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "artifacts": {},
    })
    print("INSUFFICIENT EVIDENCE: %s" % reason)
    print(detail)
    return 4


def main():
    p = argparse.ArgumentParser(description="Score one patch inside the container.")
    p.add_argument("--tool", required=True)
    p.add_argument("--finding", default="finding-01")
    p.add_argument("--run-date", default=None)
    p.add_argument("--out", default="/out")
    p.add_argument("--requested-mode", default=None,
                   help="isolation the host asked docker for, recorded beside "
                        "what was actually measured")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--patch", help="unified diff to apply to a clean checkout")
    src.add_argument("--patched-file",
                     help="an already patched app file, the stage 1 input shape")
    args = p.parse_args()

    out = args.out
    os.makedirs(out, exist_ok=True)

    # 1. Isolation, measured before anything else happens.
    iso = isolation.measure(requested_mode=args.requested_mode)
    if not iso["egress_blocked"]:
        return insufficient(
            out, "isolation not established",
            "This container reached %s. Checks B and C fire real attack "
            "payloads, and a container that can reach the network is not a "
            "container we will score in. Nothing was run."
            % ", ".join(iso["reached"]),
            iso)

    # 2. The finding, and the held-out material checks B and C need.
    try:
        finding = corpus.get_finding(args.finding)
        finding.require_heldout()
    except corpus.HeldOutMissing as e:
        return insufficient(out, "held-out material missing", str(e), iso,
                            {"missing": e.missing})
    except corpus.ManifestError as e:
        return insufficient(out, "manifest error", str(e), iso)

    # 3. The patch. A diff that will not apply is INSUFFICIENT EVIDENCE, not a
    #    failed patch: nothing about the vulnerability was tested.
    checkout = None
    if args.patch:
        try:
            patched_path = patching.apply_to_clean_checkout(finding, args.patch)
            checkout = os.path.dirname(os.path.dirname(patched_path))
        except patching.PatchFailed as e:
            return insufficient(out, "patch did not apply", e.detail, iso,
                                {"patch": args.patch})
        patch_input = {"kind": "diff", "path": args.patch,
                       "applied_cleanly": True,
                       "sha256": sha256_file(args.patch)}
        label = os.path.relpath(args.patch, "/assay")
    else:
        patched_path = args.patched_file
        patch_input = {"kind": "patched_file", "path": args.patched_file,
                       "applied_cleanly": None,
                       "sha256": sha256_file(args.patched_file)}
        label = None

    # 4. The four checks.
    try:
        result = scoring.score(patched_path, args.tool,
                               finding_id=args.finding,
                               run_date=args.run_date,
                               output_root=out,
                               patch_file_label=label)
    except scoring.AppDidNotStart as e:
        return insufficient(out, "patched app did not start", str(e), iso,
                            {"patch": patch_input})
    except Exception as e:
        return insufficient(out, "scorer raised",
                            "%s: %s\n%s" % (type(e).__name__, e,
                                            traceback.format_exc()), iso)
    finally:
        if checkout:
            shutil.rmtree(checkout, ignore_errors=True)

    # 5. What the container observed about itself, including the hash of every
    #    artifact it wrote, so the provenance cannot be attached to evidence it
    #    does not describe.
    artifacts = {}
    for rel in (os.path.join(finding.results_dir, args.tool + ".json"),
                os.path.join(finding.entry["heldout"]["dir"], "results",
                             args.tool + ".json")):
        full = os.path.join(out, rel)
        if os.path.exists(full):
            artifacts[rel] = "sha256:" + sha256_file(full)

    write(os.path.join(out, "_container.json"), {
        "isolation": iso,
        "patch_input": patch_input,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "scanner": scoring.scanner_label(finding),
        "artifacts": artifacts,
    })
    write(os.path.join(out, "_outcome.json"), {
        "verdict": result["verdict"],
        "failure_class": result["failure_class"],
        "reason": None,
        "detail": None,
    })

    scoring.print_summary(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
