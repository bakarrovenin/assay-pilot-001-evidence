"""Assay Pilot 001 - stage 3 scorer. Score one patch in an isolated container.

Stage 1 scored a patched file on the host (manual_score.py). Stage 3 takes the
shape the protocol specifies: a patch diff and a finding id, applied to a clean
checkout and scored inside a container with no network egress, torn down
completely afterwards so nothing leaks into the next patch.

  python score_container.py patches/finding-01/fixer-01.patch fixer-01
  python score_container.py --patched-file patches/finding-01/fixer-01.py fixer-01

Two artifacts are written per patch, exactly as in stage 1, plus one new one:

  results/<finding>/<tool>.json              publishable evidence
  heldout/<finding>/results/<tool>.json      full evidence, git-ignored
  results/<finding>/<tool>.provenance.json   how the run was isolated

The provenance file is separate from the evidence on purpose. The evidence
keeps the stage 1 schema so it can still be byte-compared against the results
committed from the manual run; if the isolation record lived inside it, every
stage 1 artifact would differ from every stage 3 artifact by construction and
the comparison that proves the containerisation changed nothing would be
impossible to make. The provenance carries the sha256 of the evidence it
describes, so the two cannot be separated or recombined with something else.

Exit codes:
  0  a verdict was reached (VERIFIED or NOT VERIFIED)
  3  INSUFFICIENT EVIDENCE, with the reason recorded
  2  the harness could not run at all
"""

import argparse
import hashlib
import json
import os
import shutil
import sys

from harness import container, corpus

ROOT = corpus.ROOT


def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def install(out_dir, finding, tool, provenance, output_root):
    """Move the container's artifacts into place and bind provenance to them."""
    written = {}
    for rel in (os.path.join(finding.results_dir, tool + ".json"),
                os.path.join(finding.entry["heldout"]["dir"], "results",
                             tool + ".json")):
        src = os.path.join(out_dir, rel)
        if not os.path.exists(src):
            continue
        dest = os.path.join(output_root, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy(src, dest)
        written[rel] = "sha256:" + sha256_file(dest)

    provenance["evidence"] = written
    prov_path = os.path.join(output_root, finding.results_dir,
                             tool + ".provenance.json")
    os.makedirs(os.path.dirname(prov_path), exist_ok=True)
    with open(prov_path, "w", encoding="utf-8") as f:
        json.dump(provenance, f, ensure_ascii=False, indent=2)
    return written, prov_path


def main():
    p = argparse.ArgumentParser(
        description="Score one patch for one finding in an isolated container.")
    p.add_argument("patch", nargs="?",
                   help="unified diff to apply to a clean checkout")
    p.add_argument("tool", help="name recorded in the artifact, e.g. fixer-01")
    p.add_argument("--patched-file", default=None,
                   help="score an already patched app file instead of a diff, "
                        "the stage 1 input shape")
    p.add_argument("--finding", default="finding-01")
    p.add_argument("--run-date", default=None,
                   help="date recorded in the artifact (default: today)")
    p.add_argument("--mode", default="network-none",
                   choices=sorted(container.MODE_FLAGS),
                   help="isolation to request (default: network-none)")
    p.add_argument("--output-root", default=None,
                   help="write artifacts under this root instead of the "
                        "repository, for dry runs")
    args = p.parse_args()

    if (args.patch is None) == (args.patched_file is None):
        p.error("give either a patch diff or --patched-file, not both")

    try:
        finding = corpus.get_finding(args.finding)
    except corpus.ManifestError as e:
        print("manifest error: %s" % e)
        return 2

    try:
        outcome, provenance, out_dir = container.score_in_container(
            args.tool, finding_id=args.finding,
            patch=os.path.abspath(args.patch) if args.patch else None,
            patched_file=(os.path.abspath(args.patched_file)
                          if args.patched_file else None),
            run_date=args.run_date, mode=args.mode)
    except container.DockerUnavailable as e:
        print("INSUFFICIENT EVIDENCE: no isolated container to score in.")
        print(e)
        print("Stage 3 has no host fallback. A result whose isolation we "
              "cannot describe is worse than no result.")
        return 3

    try:
        iso = (provenance.get("container_observed") or {}).get("isolation") or {}
        print("isolation requested: %s" % provenance["execution"]["requested_isolation"])
        print("isolation measured : %s (egress blocked: %s)"
              % (iso.get("observed_mode"), iso.get("egress_blocked")))
        print("bind mounts        : %s"
              % (provenance["execution"]["bind_mounts"] or "none"))

        if outcome["verdict"] == "INSUFFICIENT EVIDENCE":
            print()
            print("INSUFFICIENT EVIDENCE: %s" % outcome.get("reason"))
            print(outcome.get("detail") or "")
            install(out_dir, finding, args.tool, provenance,
                    args.output_root or ROOT)
            return 3

        written, prov_path = install(out_dir, finding, args.tool, provenance,
                                     args.output_root or ROOT)
        print()
        print("verdict: %s   class: %s" % (outcome["verdict"],
                                           outcome["failure_class"]))
        for rel in sorted(written):
            print("  wrote %s" % rel)
        print("  wrote %s" % os.path.relpath(prov_path, args.output_root or ROOT))
        return 0
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
