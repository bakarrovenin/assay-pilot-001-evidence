"""Score one submitted patch against the public benchmark corpus.

This is the whole of the scoring logic, and it deliberately contains almost
none: it reuses harness.container.score_in_container exactly, the same code the
pilot is scored with, and never reimplements a check. Its job is to hand that
function a benchmark finding and a patch, under resource caps, and to translate
the evidence artifact it produces into the shape the front end already renders.

Isolation and teardown come from the harness: the patch runs inside a container
with --network none and no bind mounts, which is destroyed after the run. This
module adds the caps that matter when the code is untrusted and public: a hard
wall-clock timeout, a memory ceiling with swap disabled, a CPU limit, and a pid
limit against fork bombs. It also serialises runs, so the host is never asked
to execute more than one untrusted patch at a time.

Nothing from the patch is persisted. The patch is written to a temp file only
so the harness can tar it into the container, and both that file and the
container's output directory are removed in a finally block. The caller stores
the verdict and the structured checks, never the patch text.
"""

import os
import re
import shutil
import sys
import threading
import uuid

# The service runs from service/, so put the repository root on the path to
# import the harness that lives at its top level.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

# The benchmark corpus is selected before the harness is imported, because
# harness.corpus resolves its manifest path at import time from this variable.
os.environ.setdefault("ASSAY_MANIFEST", "benchmark/edition-01/manifest.json")

from harness import container, corpus  # noqa: E402

ROOT = corpus.ROOT

# The corpus edition, read from the manifest. Stored on every result so editions
# never merge in the leaderboard (service/ROTATION.md). Falls back to 1 if the
# manifest omits it.
try:
    EDITION = int(
        corpus.load_manifest(
            os.path.join(ROOT, os.environ["ASSAY_MANIFEST"])
        ).get("edition", 1)
    )
except Exception:
    EDITION = 1

# Front-end short id to benchmark finding id. The front end routes /benchmark/04
# and the corpus calls it finding-b04; the map is the only place the two meet.
FINDINGS = {
    "01": "finding-b01",
    "04": "finding-b04",
    "08": "finding-b08",
    "13": "finding-b13",
}

# The evidence artifact is written under this fixed key, so its filename never
# depends on the submitted tool name (which is untrusted text). The real tool
# and version live in the result and the database, not in a path.
EVIDENCE_KEY = "submitted"

# Caps for an untrusted, public run. These bound the sandbox; they never enter
# what the four checks compute, so they cannot move a verdict.
LIMITS = {
    "memory": "768m",
    "cpus": "1.0",
    "pids": 256,
    "timeout_s": 150,
}

# The patch is written here, inside the repo root, only so the harness tars it
# into the container. It is deleted after every run.
PATCH_DIR = os.path.join(ROOT, "service", "_patches")

# One untrusted patch scored at a time. This is the concurrency ceiling for the
# whole host: it bounds memory and CPU pressure and keeps the repo tar from
# ever carrying two submissions at once.
_lock = threading.Lock()


class ScoringError(Exception):
    """The request was malformed, e.g. an unknown finding id."""


def _read_json(path):
    import json
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _looks_like_diff(text):
    """A unified diff has hunk headers and file markers. A whole file does not."""
    return bool(re.search(r"^@@ ", text, re.M)) and bool(
        re.search(r"^\+\+\+ ", text, re.M)
    )


def _normalize_diff(text, rel):
    """Rewrite a submitted single-file diff to the path the harness applies at.

    The harness applies with `git apply -p1` against the app file at its repo
    relative path (benchmark/edition-01/app/finding_bNN.py). A fixer's diff
    names whatever path it was shown, so the file markers are rewritten to that
    path; git apply then matches by path and applies the hunks by context. Only
    the header lines change, never a hunk, so the patch content is untouched.
    """
    out = []
    for line in text.splitlines():
        if line.startswith("diff --git "):
            out.append("diff --git a/%s b/%s" % (rel, rel))
        elif line.startswith("--- "):
            out.append("--- a/%s" % rel)
        elif line.startswith("+++ "):
            out.append("+++ b/%s" % rel)
        else:
            out.append(line)
    return "\n".join(out) + "\n"


def _map_checks(checks):
    """Harness evidence checks to the front-end shape. None if not scored."""
    if not checks:
        return None
    a = checks["A_alert_closed"]
    b = checks["B_hole_shut"]
    c = checks["C_behaviour_preserved"]
    d = checks["D_no_suppression"]
    return {
        "A": {"pass": a["pass"], "findingsAfter": a["semgrep_findings_after"]},
        "B": {
            "pass": b["pass"],
            "fired": b["attacks_fired"],
            "succeeded": [
                {"id": x["id"], "class": x["class"]}
                for x in b.get("detail", [])
                if x.get("succeeded")
            ],
        },
        "C": {
            "pass": c["pass"],
            "fired": c["benign_fired"],
            "regressed": c.get("regressed_ids", []),
        },
        "D": {"pass": d["pass"], "suppressionInEffect": d["suppression_in_effect"]},
    }


def score(short_id, patch_text, tool, version):
    """Score a patch. Returns the front-end Result dict. Never stores the patch.

    Raises ScoringError for a bad request. Any harness or docker failure comes
    back as an INSUFFICIENT EVIDENCE result rather than an exception, so the
    front end always has something to render.
    """
    finding_id = FINDINGS.get(short_id)
    if not finding_id:
        raise ScoringError("unknown finding %r" % short_id)
    # Refuses a planted or non-benchmark finding.
    finding = corpus.get_finding(finding_id)

    os.makedirs(PATCH_DIR, exist_ok=True)
    rel = os.path.relpath(finding.app_file, ROOT)
    is_diff = _looks_like_diff(patch_text)
    # A diff is applied with git apply; a whole file is scored as the patched
    # module directly (the harness supports both). Either way the file written
    # here lives under the repo root so the harness can tar it into the
    # container, and it is deleted in the finally block.
    ext = ".patch" if is_diff else ".py"
    work_path = os.path.join(PATCH_DIR, uuid.uuid4().hex + ext)
    out_dir = None

    base = {
        "v": 1,
        "set": "submitted",
        "finding": short_id,
        "tool": (tool or "").strip(),
        "version": (version or "").strip(),
        "date": __import__("time").strftime("%Y-%m-%d"),
        "scorer": "pilot-001-harness",
    }

    with _lock:
        try:
            with open(work_path, "w", encoding="utf-8") as f:
                f.write(_normalize_diff(patch_text, rel) if is_diff else patch_text)

            kwargs = (
                {"patch": work_path} if is_diff else {"patched_file": work_path}
            )
            try:
                outcome, _prov, out_dir = container.score_in_container(
                    tool=EVIDENCE_KEY,
                    finding_id=finding_id,
                    mode="network-none",
                    limits=LIMITS,
                    **kwargs,
                )
            except container.DockerUnavailable as e:
                return {
                    **base,
                    "checks": None,
                    "verdict": "INSUFFICIENT EVIDENCE",
                    "failureClass": None,
                    "reason": "the scoring container could not run: %s" % e,
                }

            evidence = _read_json(
                os.path.join(out_dir, finding.results_dir, EVIDENCE_KEY + ".json")
            )
            checks = _map_checks(evidence.get("checks") if evidence else None)
            result = {
                **base,
                "checks": checks,
                "verdict": outcome.get("verdict", "INSUFFICIENT EVIDENCE"),
                "failureClass": (evidence or {}).get("failure_class")
                if evidence
                else None,
            }
            if checks is None and outcome.get("reason"):
                # A patch that would not apply, would not start, or timed out.
                result["reason"] = outcome["reason"]
            return result
        finally:
            try:
                os.remove(work_path)
            except OSError:
                pass
            if out_dir:
                shutil.rmtree(out_dir, ignore_errors=True)
