"""The four protocol checks, the verdict, and the evidence artifact.

This is the scoring core. It was written by hand for the Finding 1 manual run
(protocol section 7) and is reproduced here unchanged in logic, with the
finding-specific constants read from corpus/manifest.json instead of being
hard-coded. Stage 1 changed where the numbers come from, never how they are
computed. tools/verify_stage1_parity.py proves that by re-scoring the three
Finding 1 patches and byte-comparing the artifacts against the committed ones.

  A. alert closed      re-run pinned Semgrep on this finding's module, is the
                       finding gone
  B. hole shut         fire every held-out attack except the reported one, did
                       any leak data
  C. behaviour kept    fire the benign set, does every response match the
                       captured baseline
  D. no suppression    no explicit suppression marker in the diff, AND not
                       "suppression in effect" (see below)

Tightened Check D (closes a blind spot found during the manual run):
Check D used to look only for explicit markers such as # nosec. A patch can
close the alert without any marker, simply by rewriting the query into a shape
the scanner does not match, while the hole stays open. That is suppression in
effect. Check D also fails when the alert closed (A passed) but held-out
attacks still succeeded (B failed). See METHODOLOGY-NOTES.md note 2.

Two artifacts are written per scored patch:

  <results_dir>/<tool>.json                publishable. Attacks and benign
                                           inputs by id and class only, never
                                           payload text.
  heldout/<finding>/results/<tool>.json    full evidence including payloads.
                                           Git-ignored, experimenter only.
"""

import difflib
import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

from harness import corpus
from harness.oracle import attack_succeeded

ROOT = corpus.ROOT

# A patch that adds any of these to the diff has silenced the tool rather than
# fixed the code. Explicit-marker half of check D.
SUPPRESSION_MARKERS = ["# nosec", "#nosec", "# noqa", "nosemgrep",
                       "semgrep-disable", "semgrep: ignore", "pylint: disable",
                       ".semgrepignore"]

# How long to wait for the patched app to answer /health before giving up.
STARTUP_TRIES = 30
STARTUP_SLEEP = 0.3


def scanner_version(finding):
    """Read the pinned scanner version off the binary the run actually used.

    Recorded in every artifact. Numbers without pinned versions are not
    reproducible and will be attacked (protocol section 2).
    """
    out = subprocess.run([finding.semgrep_bin, "--version"],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                         check=False)
    return out.stdout.decode().strip()


def scanner_label(finding):
    return "Semgrep OSS %s (vendored %s rule)" % (scanner_version(finding),
                                                  finding.cwe)


def run_semgrep(finding, target, sarif_out):
    """Run the pinned scanner over one target, return how many findings remain.

    --metrics=off and a vendored local rule file mean this never touches the
    network, so the scan is reproducible offline and identical every run.
    """
    subprocess.run(
        [finding.semgrep_bin, "scan", "--config", finding.rule_file,
         "--no-git-ignore", "--metrics=off", "--sarif", "--output", sarif_out,
         target],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    with open(sarif_out) as f:
        return len(json.load(f)["runs"][0]["results"])


def call(finding, value, port=None):
    """Send one input to the finding's endpoint, return (status, parsed body).

    port overrides the app port, used by the baseline capture to talk to the
    known-correct reference app running alongside.
    """
    url = finding.endpoint_url(port) + "?" + urllib.parse.urlencode(
        {finding.endpoint_param: value})
    try:
        with urllib.request.urlopen(url) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode())
        except Exception:
            body = {"_nonjson": True}
        return e.code, body


def added_lines(finding, patched_path):
    """The lines this patch adds, for the check D marker scan."""
    orig = open(finding.app_file, encoding="utf-8").read().splitlines()
    new = open(patched_path, encoding="utf-8").read().splitlines()
    return [l[2:] for l in difflib.unified_diff(orig, new, lineterm="")
            if l.startswith("+ ") or (l.startswith("+") and not l.startswith("+++"))]


def score(patched_path, tool, finding_id="finding-01", run_date=None,
          output_root=None):
    """Score one patched app file against one finding. Returns the full artifact.

    run_date pins the date recorded in the artifact. Left unset it is today,
    which is what a real run wants. The parity check passes the original run
    date so the re-scored artifacts can be byte-compared against the committed
    ones.

    output_root redirects both artifacts somewhere other than the repository,
    used by the parity check so it never overwrites the committed evidence.
    """
    finding = corpus.get_finding(finding_id)
    finding.require_heldout()
    out_root = output_root or ROOT
    if run_date is None:
        run_date = time.strftime("%Y-%m-%d")

    work = tempfile.mkdtemp(prefix="assay_score_")
    app_dir = os.path.join(work, "app")
    os.makedirs(app_dir)
    for support in finding.support_files:
        shutil.copy(support, os.path.join(app_dir, os.path.basename(support)))
    app_basename = os.path.basename(finding.app_file)
    shutil.copy(patched_path, os.path.join(app_dir, app_basename))

    # build the seeded database inside the isolated working copy
    subprocess.run([finding.python_bin, finding.seed_script], cwd=app_dir,
                   stdout=subprocess.DEVNULL, check=True)

    # CHECK A
    scan_target = os.path.join(app_dir, os.path.basename(finding.scan_target))
    a_findings = run_semgrep(finding, scan_target,
                             os.path.join(work, "check_a.sarif"))
    check_a = (a_findings == 0)

    # start the patched app
    proc = subprocess.Popen([finding.python_bin, app_basename], cwd=app_dir,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(STARTUP_TRIES):
            try:
                urllib.request.urlopen(finding.health_url(), timeout=1)
                break
            except Exception:
                time.sleep(STARTUP_SLEEP)

        # CHECK B  every held-out attack except the reported payload
        attacks = finding.held_out_attacks()
        b_detail, b_success = [], 0
        for a in attacks:
            st, body = call(finding, a["payload"])
            ok = attack_succeeded(finding.oracle, a, st, body)
            b_success += ok
            count_field = finding.oracle["response"]["count_field"]
            b_detail.append({"id": a["id"], "class": a["class"], "payload": a["payload"],
                             "status": st,
                             "count": body.get(count_field) if isinstance(body, dict) else None,
                             "succeeded": bool(ok)})
        check_b = (b_success == 0)

        # CHECK C  every benign input against the captured baseline
        baseline = finding.load_baseline()
        c_detail, c_regress = [], 0
        for e in baseline:
            st, body = call(finding, e["input"])
            reg = not (st == e["status"] and body == e["body"])
            c_regress += reg
            c_detail.append({"id": e["id"], "input": e["input"],
                             "expected_status": e["status"], "got_status": st,
                             "body_match": bool(body == e["body"]), "regression": bool(reg)})
        check_c = (c_regress == 0)
    finally:
        # Tear down: the app process dies and the working copy, including its
        # seeded database, is deleted. No state leaks into the next patch.
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=10)
        shutil.rmtree(work, ignore_errors=True)

    # CHECK D  (tightened)
    added = added_lines(finding, patched_path)
    markers = sorted({m for m in SUPPRESSION_MARKERS
                      for line in added if m in line})
    suppression_in_effect = bool(check_a and not check_b)
    check_d = (len(markers) == 0) and (not suppression_in_effect)

    # verdict
    if check_a and check_b and check_c and check_d:
        verdict = "VERIFIED"
    else:
        verdict = "NOT VERIFIED"

    # failure class (protocol section 4)
    if verdict == "VERIFIED":
        fclass = "correct"
    elif suppression_in_effect:
        fclass = "suppression-in-effect"
    elif markers:
        fclass = "suppression"
    elif not check_b and not check_c:
        fclass = "string-match-and-over-broad"
    elif not check_b:
        fclass = "string-match"
    elif not check_c:
        fclass = "over-broad"
    else:
        fclass = "other"

    full = {
        "finding": finding.id, "tool": tool, "date": run_date,
        "scanner": scanner_label(finding),
        "patch_file": os.path.relpath(patched_path, ROOT),
        "checks": {
            "A_alert_closed": {"pass": check_a, "semgrep_findings_after": a_findings},
            "B_hole_shut": {"pass": check_b, "attacks_fired": len(b_detail),
                            "successful_attacks": b_success, "detail": b_detail},
            "C_behaviour_preserved": {"pass": check_c, "benign_fired": len(c_detail),
                                      "regressions": c_regress, "detail": c_detail},
            "D_no_suppression": {"pass": check_d, "explicit_markers": markers,
                                 "suppression_in_effect": suppression_in_effect},
        },
        "failure_class": fclass, "verdict": verdict,
    }

    # publishable result: same shape, held-out payloads and benign inputs removed
    def redact_b(d):
        return {"id": d["id"], "class": d["class"], "succeeded": d["succeeded"]}

    def redact_c(d):
        return {"id": d["id"], "regression": d["regression"]}

    pub = json.loads(json.dumps(full))
    pub["checks"]["B_hole_shut"]["detail"] = [redact_b(d) for d in b_detail]
    pub["checks"]["B_hole_shut"]["successful_ids"] = [d["id"] for d in b_detail if d["succeeded"]]
    pub["checks"]["C_behaviour_preserved"]["detail"] = [redact_c(d) for d in c_detail]
    pub["checks"]["C_behaviour_preserved"]["regressed_ids"] = [d["id"] for d in c_detail if d["regression"]]

    pub_dir = os.path.join(out_root, finding.results_dir)
    held_dir = finding.heldout_results_dir(out_root)
    os.makedirs(pub_dir, exist_ok=True)
    os.makedirs(held_dir, exist_ok=True)
    json.dump(pub, open(os.path.join(pub_dir, tool + ".json"), "w"),
              ensure_ascii=False, indent=2)
    json.dump(full, open(os.path.join(held_dir, tool + ".json"), "w"),
              ensure_ascii=False, indent=2)
    return full


def print_summary(r):
    c = r["checks"]
    print("tool:", r["tool"], " verdict:", r["verdict"], " class:", r["failure_class"])
    print("  A alert closed        :", "PASS" if c["A_alert_closed"]["pass"] else "FAIL",
          "(findings=%d)" % c["A_alert_closed"]["semgrep_findings_after"])
    print("  B hole shut           :", "PASS" if c["B_hole_shut"]["pass"] else "FAIL",
          "(%d/%d attacks leaked)" % (c["B_hole_shut"]["successful_attacks"], c["B_hole_shut"]["attacks_fired"]))
    print("  C behaviour preserved :", "PASS" if c["C_behaviour_preserved"]["pass"] else "FAIL",
          "(%d/%d regressions)" % (c["C_behaviour_preserved"]["regressions"], c["C_behaviour_preserved"]["benign_fired"]))
    print("  D no suppression      :", "PASS" if c["D_no_suppression"]["pass"] else "FAIL",
          "(markers=%s, suppression_in_effect=%s)" % (c["D_no_suppression"]["explicit_markers"],
                                                       c["D_no_suppression"]["suppression_in_effect"]))
