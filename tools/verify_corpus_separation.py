"""The two corpora have opposite disclosure rules. This enforces the line.

There are now two corpora in this repository:

  corpus/manifest.json              the PILOT. Its answer key (the correct fix,
                                    the endpoint, the oracle) and its held-out
                                    attack, benign and baseline sets are SECRET,
                                    kept in a git-ignored experimenter manifest
                                    and under a git-ignored heldout/ tree.

  benchmark/edition-01/manifest.json  the BENCHMARK. Everything is PUBLIC on
                                    purpose, including the attacks and the
                                    correct fixes, because it is a self-service
                                    benchmark rotated each edition.

The only thing keeping them apart is which file the loader reads. A path moved,
a gitignore rule widened, or an answer-key field pasted into the wrong manifest
would silently break one of the two disclosure rules, and in the flattering
direction: a benchmark file quietly untracked still scores locally, and a pilot
answer key in a public file still loads. So this is a guard, not a convention.

Three properties, each with a negative control, because a check that cannot
fail on the broken case proves nothing about the intact one:

  A  The pilot public manifest carries no reference_fix, endpoint or oracle,
     and the loader refuses one that does.
  B  Every path the benchmark manifest names is under benchmark/, is not
     git-ignored, and does not resolve under the pilot's heldout/ tree; the
     benchmark's experimenter manifest is tracked (public).
  C  The pilot's experimenter manifest and held-out material stay git-ignored.

Usage: python tools/verify_corpus_separation.py
Exit 0 the line holds, 1 it is broken, 2 a negative control did not fire.
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from harness import corpus  # noqa: E402

ROOT = corpus.ROOT
PILOT_MANIFEST = os.path.join("corpus", "manifest.json")
BENCH_MANIFEST = os.path.join("benchmark", "edition-01", "manifest.json")
ANSWER_KEY_FIELDS = ("reference_fix", "endpoint", "oracle")


def ignored(rel):
    """True if git would ignore this path (git check-ignore exit 0)."""
    r = subprocess.run(["git", "check-ignore", "-q", rel], cwd=ROOT)
    return r.returncode == 0


def manifest_paths(data):
    """Every filesystem path a manifest names, flattened."""
    paths = []
    exp = data.get("experimenter_manifest")
    if exp:
        paths.append(exp)
    for f in data.get("findings", []):
        if f.get("status") != "built":
            continue
        app = f.get("app", {})
        paths += [app.get("file"), app.get("scan_target")]
        paths += list(app.get("support_files") or [])
        paths.append((f.get("sink") or {}).get("file"))
        for v in (f.get("heldout") or {}).values():
            if isinstance(v, str) and "/" in v:
                paths.append(v)
        paths.append(f.get("reported_payload_file"))
        for key in ("results_dir", "patches_dir", "scanner_dir"):
            if f.get(key):
                paths.append(f[key])
    return [p for p in paths if p]


def main():
    problems = []
    controls_ok = True

    # ---- A: the pilot public manifest carries no answer key ----------------
    with open(os.path.join(ROOT, PILOT_MANIFEST), encoding="utf-8") as fh:
        pilot = json.load(fh)
    for entry in pilot["findings"]:
        for field in ANSWER_KEY_FIELDS:
            if field in entry:
                problems.append("A: pilot manifest finding %s carries answer-key "
                                "field %r" % (entry["id"], field))
    # loader must accept the intact pilot manifest ...
    try:
        corpus.load_manifest(os.path.join(ROOT, PILOT_MANIFEST))
    except corpus.ManifestError as e:
        problems.append("A: loader rejected the intact pilot manifest: %s" % e)
    # ... and reject one with an answer key pasted in (negative control).
    import tempfile
    poisoned = json.loads(json.dumps(pilot))
    built = next(e for e in poisoned["findings"] if e["status"] == "built")
    built["oracle"] = {"planted": True}
    tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(poisoned, tf)
    tf.close()
    try:
        corpus.load_manifest(tf.name)
        controls_ok = False
        problems.append("A CONTROL: loader accepted a manifest carrying an "
                        "oracle field; the answer-key guard is not enforcing")
    except corpus.ManifestError:
        pass
    finally:
        os.unlink(tf.name)

    # ---- B: benchmark material is public, tracked, never held-out ----------
    bench_abs = os.path.join(ROOT, BENCH_MANIFEST)
    if not os.path.exists(bench_abs):
        problems.append("B: benchmark manifest not found at %s" % BENCH_MANIFEST)
    else:
        with open(bench_abs, encoding="utf-8") as fh:
            bench = json.load(fh)
        for rel in manifest_paths(bench):
            if not rel.startswith("benchmark/"):
                problems.append("B: benchmark manifest names a path outside "
                                "benchmark/: %s" % rel)
            if rel.startswith("heldout/") or "/heldout/" in rel:
                problems.append("B: benchmark path resolves under a heldout tree: "
                                "%s" % rel)
            if os.path.exists(os.path.join(ROOT, rel)) and ignored(rel):
                problems.append("B: benchmark material is git-ignored (would not "
                                "be published): %s" % rel)
        exp = bench.get("experimenter_manifest")
        if exp and not os.path.exists(os.path.join(ROOT, exp)):
            problems.append("B: benchmark experimenter manifest missing: %s" % exp)
        elif exp and ignored(exp):
            problems.append("B: benchmark experimenter manifest is git-ignored; "
                            "it is meant to be public: %s" % exp)

    # ---- C: pilot held-out material stays private --------------------------
    pilot_exp = pilot.get("experimenter_manifest")
    if pilot_exp and not ignored(pilot_exp):
        problems.append("C: pilot experimenter manifest is NOT git-ignored: %s"
                        % pilot_exp)
    # a concrete pilot held-out file, if present, must be ignored
    sample = "heldout/finding-01/attacks.json"
    if os.path.exists(os.path.join(ROOT, sample)) and not ignored(sample):
        problems.append("C: pilot held-out material is NOT git-ignored: %s"
                        % sample)

    # negative control for the gitignore checks: a path we know is ignored must
    # read as ignored, or check-ignore is not wired and B/C prove nothing.
    if not ignored("heldout/finding-01/attacks.json") and not ignored(".venv"):
        # fall back to a path that certainly matches a rule
        if not ignored("x.db"):
            controls_ok = False
            problems.append("B/C CONTROL: git check-ignore never reports an "
                            "ignored path; the tracking checks are inert")

    # ---- report ------------------------------------------------------------
    print("corpus separation guard")
    print("  pilot     : %s" % PILOT_MANIFEST)
    print("  benchmark : %s" % BENCH_MANIFEST)
    print()
    if not controls_ok:
        print("RESULT: A NEGATIVE CONTROL DID NOT FIRE, the guard cannot be trusted")
        for p in problems:
            print("  %s" % p)
        return 2
    if problems:
        print("RESULT: THE DISCLOSURE LINE IS BROKEN")
        for p in problems:
            print("  %s" % p)
        return 1
    print("RESULT: THE DISCLOSURE LINE HOLDS")
    print("  the pilot manifest carries no answer key and the loader refuses one,")
    print("  the benchmark material is public and tracked and never held-out,")
    print("  and the pilot's held-out material stays git-ignored.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
