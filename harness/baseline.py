"""Stage 2: baseline capture.

Two baselines are captured per finding, and everything the scorer later
compares against comes from here.

  1. The benign baseline. Every benign input is fired at the KNOWN-CORRECT
     REFERENCE app and the exact response is recorded. Check C compares a
     patched app against this.

  2. The scanner baseline. The pinned Semgrep OSS version is run over the
     finding's module and the result is stored as SARIF. This is the input a
     real developer receives, and check A compares against it.

## Read this before changing anything here: the baseline source

The protocol as written says to capture the benign baseline by running the
benign inputs against the UNPATCHED app. Doing that is wrong, and this module
deliberately does not do it. METHODOLOGY-NOTES.md note 1 records why.

The short version, using Finding 1 as the example. One benign input is
"Chef's Knife", a legitimate product with an apostrophe in its name. The
unpatched app interpolates that apostrophe straight into the SQL string, the
query is malformed, and the app returns 500. If that 500 were recorded as the
expected baseline, then a correct parameterised fix, which makes the input
work and returns the product, would be scored as a REGRESSION in check C. The
better the patch, the worse it would score. That is the exact opposite of
what check C is for.

So the benign baseline is captured from the known-correct reference app the
experimenter wrote, which is the ground truth answer for every benign input.
For inputs with no special characters the reference and the unpatched app
agree; for the awkward inputs the reference gives the true correct answer and
the unpatched app gives a crash.

This is a deliberate, documented deviation from the protocol wording, and it
is enforced here rather than left to whoever runs the script:

  - BASELINE_SOURCE names the reference, and is the only source implemented.
  - There is no flag, no argument and no code path that captures the benign
    baseline from the unpatched app.
  - Every capture runs the trap demonstration below and publishes the result,
    so the reason for the deviation is evidence rather than an assertion.

## The trap demonstration

Every capture also fires the benign set at the unpatched app and records which
inputs answer differently from the reference. That output is never used as a
baseline. It exists so that a reader hostile to the result can see, in the
published capture record, exactly which inputs the naive protocol reading
would have poisoned and by how much.
"""

import hashlib
import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from harness import corpus, scoring

ROOT = corpus.ROOT

# The only baseline source this module implements. See the module docstring.
BASELINE_SOURCE = "known-correct reference"

# Recorded verbatim in every baseline file so the deviation travels with the
# artifact and not only with the methodology notes.
BASELINE_NOTE = (
    "Deliberate, documented deviation from protocol wording. The unpatched app "
    "500s on legitimate apostrophe inputs, so the true correct baseline is "
    "captured from the parameterised reference, not from the vulnerable app."
)

STARTUP_TRIES = 40
STARTUP_SLEEP = 0.3


class CaptureError(Exception):
    """The capture could not complete, so there is no baseline to trust."""


def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _wait_for_health(finding, port, proc):
    for _ in range(STARTUP_TRIES):
        if proc.poll() is not None:
            raise CaptureError("app exited before answering health on port %d"
                               % port)
        try:
            urllib.request.urlopen(finding.health_url(port), timeout=1)
            return
        except Exception:
            time.sleep(STARTUP_SLEEP)
    raise CaptureError("app never answered health on port %d" % port)


def _seed(finding, app_dir):
    subprocess.run([finding.python_bin, finding.seed_script], cwd=app_dir,
                   stdout=subprocess.DEVNULL, check=True)


def _fire_benign(finding, port):
    """Fire the benign set at whatever is listening on port, in order."""
    out = []
    for entry in finding.load_benign():
        status, body = scoring.call(finding, entry["input"], port=port)
        out.append({"id": entry["id"], "input": entry["input"],
                    "kind": entry["kind"], "status": status, "body": body})
    return out


def capture_from_reference(finding):
    """Fire the benign set at the known-correct reference app.

    The reference app reads the same seeded database the corpus app serves, so
    the database is rebuilt deterministically from the seed script first. The
    reference is started in place because it resolves the database by a path
    relative to its own location; it is experimenter material and never enters
    a fixer's checkout, so there is nothing to isolate it from.
    """
    reference = finding.reference_app
    if not os.path.exists(reference):
        raise corpus.HeldOutMissing(finding.id,
                                    [os.path.relpath(reference, ROOT)])

    _seed(finding, os.path.dirname(finding.app_file))

    port = finding.reference_port
    module = os.path.splitext(os.path.basename(reference))[0]
    proc = subprocess.Popen(
        [finding.python_bin, "-c",
         "import %s; %s.app.run(host=%r, port=%d, debug=False)"
         % (module, module, finding.host, port)],
        cwd=os.path.dirname(reference),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        _wait_for_health(finding, port, proc)
        return _fire_benign(finding, port)
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=10)


def capture_from_unpatched(finding):
    """Fire the benign set at the UNPATCHED app. NEVER used as a baseline.

    This is the trap demonstration described in the module docstring. Its
    output goes into the published capture record as evidence for why the
    baseline is taken from the reference instead.
    """
    work = tempfile.mkdtemp(prefix="assay_trap_")
    app_dir = os.path.join(work, "app")
    os.makedirs(app_dir)
    for support in finding.support_files:
        shutil.copy(support, os.path.join(app_dir, os.path.basename(support)))
    app_basename = os.path.basename(finding.app_file)
    shutil.copy(finding.app_file, os.path.join(app_dir, app_basename))
    _seed(finding, app_dir)

    proc = subprocess.Popen([finding.python_bin, app_basename], cwd=app_dir,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        _wait_for_health(finding, finding.port, proc)
        return _fire_benign(finding, finding.port)
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=10)
        shutil.rmtree(work, ignore_errors=True)


def trap_demonstration(finding, reference_rows):
    """Which benign inputs the unpatched app answers differently, by id only."""
    unpatched = {r["id"]: r for r in capture_from_unpatched(finding)}
    differences = []
    for row in reference_rows:
        other = unpatched.get(row["id"])
        if other is None:
            continue
        if other["status"] == row["status"] and other["body"] == row["body"]:
            continue
        differences.append({
            "id": row["id"],
            "reference_status": row["status"],
            "unpatched_status": other["status"],
            "body_match": bool(other["body"] == row["body"]),
        })
    return differences


def write_benign_baseline(finding, rows, captured, output_root=None):
    """Write the benign baseline in the shape check C reads."""
    out_root = output_root or ROOT
    payload = {
        "finding": finding.id,
        "source": "%s (%s)" % (BASELINE_SOURCE,
                               os.path.relpath(finding.reference_app, ROOT)),
        "note": BASELINE_NOTE,
        "captured": captured,
        "baseline": rows,
    }
    path = os.path.join(out_root, finding.entry["heldout"]["baseline"])
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return path


def capture_scanner_baseline(finding, output_root=None):
    """Run the pinned scanner over this finding's module, store SARIF.

    Run from the repository root with the target given as a relative path.
    Semgrep records the target in the SARIF exactly as it was passed, so this
    is what makes the SARIF identical on any machine rather than embedding
    somebody's home directory. The rule is vendored locally and metrics are
    off, so the scan needs no network.
    """
    out_root = output_root or ROOT
    sarif = os.path.join(out_root, "scanner", finding.id + ".sarif")
    os.makedirs(os.path.dirname(sarif), exist_ok=True)
    command = [finding.semgrep_bin, "scan",
               "--config", finding.rule_file_relative,
               "--no-git-ignore", "--metrics=off",
               "--sarif", "--output", sarif,
               finding.scan_target_relative]
    subprocess.run(command, cwd=ROOT, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, check=False)
    if not os.path.exists(sarif):
        raise CaptureError("scanner produced no SARIF for %s" % finding.id)
    with open(sarif, encoding="utf-8") as f:
        data = json.load(f)
    results = data["runs"][0]["results"]
    summary = []
    for r in results:
        loc = r["locations"][0]["physicalLocation"]
        summary.append({
            "rule_id": r["ruleId"],
            "file": loc["artifactLocation"]["uri"],
            "start_line": loc["region"]["startLine"],
            "end_line": loc["region"]["endLine"],
            "message": r["message"]["text"],
        })
    # The command is published with the binary path made relative, so the
    # record is reproducible rather than machine-specific.
    published_command = [finding.defaults["semgrep"]] + command[1:]
    published_command[published_command.index(sarif)] = os.path.relpath(sarif, out_root)
    return {
        "tool": "Semgrep OSS",
        "version": scoring.scanner_version(finding),
        "rule_file": finding.rule_file_relative,
        "rule_file_sha256": sha256_file(finding.rule_file),
        "scan_target": finding.scan_target_relative,
        "command": published_command,
        "sarif": os.path.relpath(sarif, out_root),
        "sarif_sha256": sha256_file(sarif),
        "findings": len(results),
        "results": summary,
    }


def capture(finding, captured=None, output_root=None, run_trap=True):
    """Capture both baselines for one finding and return the capture record.

    The returned record is publishable: it names inputs by id only and carries
    a SHA-256 of the held-out baseline so the baseline is attestable without
    being published.
    """
    finding.require_heldout(("attacks", "benign"))
    if captured is None:
        captured = time.strftime("%Y-%m-%d")

    scanner = capture_scanner_baseline(finding, output_root)

    rows = capture_from_reference(finding)
    baseline_path = write_benign_baseline(finding, rows, captured, output_root)

    statuses = {}
    for row in rows:
        key = str(row["status"])
        statuses[key] = statuses.get(key, 0) + 1

    record = {
        "finding": finding.id,
        "shape": finding.shape,
        "captured": captured,
        "scanner": scanner,
        "benign_baseline": {
            "source": BASELINE_SOURCE,
            "reference_app": os.path.relpath(finding.reference_app, ROOT),
            "captured_from_unpatched_app": False,
            "why": BASELINE_NOTE,
            "methodology_note": "METHODOLOGY-NOTES.md note 1",
            "path": finding.entry["heldout"]["baseline"],
            "sha256": sha256_file(baseline_path),
            "inputs": len(rows),
            "status_counts": statuses,
        },
    }

    if run_trap:
        differences = trap_demonstration(finding, rows)
        record["note_1_trap_demonstration"] = {
            "what": "The benign set fired at the UNPATCHED app and compared to "
                    "the reference baseline. Never used as a baseline. "
                    "Published so the deviation is evidence, not an assertion.",
            "inputs_fired": len(rows),
            "differs_on": differences,
            "conclusion": (
                "%d of %d benign inputs would have been recorded wrong if the "
                "baseline had been taken from the unpatched app. Every one of "
                "them would then have scored a correct fix as a check C "
                "regression." % (len(differences), len(rows))),
        }

    return record, baseline_path


def write_capture_record(finding, record, output_root=None):
    out_root = output_root or ROOT
    path = os.path.join(out_root, "scanner", finding.id + ".capture.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(record, f, ensure_ascii=False, indent=2)
        f.write("\n")
    return path
