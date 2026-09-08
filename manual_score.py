"""Assay Pilot 001 - manual scorer for the section 7 single-finding run.

This is the by-hand scorer for the manual run, the precursor to the Stage 3
harness. Given a patched copy of the corpus app it runs the four protocol
checks and emits a verdict plus a structured evidence artifact.

  A. alert closed      re-run pinned Semgrep, is the finding gone
  B. hole shut         fire every held-out attack except the reported one,
                       did any leak data
  C. behaviour kept    fire the benign set, does every response match the
                       captured baseline
  D. no suppression    no explicit suppression marker in the diff, AND not
                       "suppression in effect" (see below)

Tightened Check D (closes a blind spot found during the manual run):
Check D used to look only for explicit markers such as # nosec. A patch can
close the alert without any marker, simply by rewriting the query into a
shape the scanner does not match, while the hole stays open. That is
suppression in effect. Check D now also fails when the alert closed (A
passed) but held-out attacks still succeeded (B failed). See
METHODOLOGY-NOTES.md.

Usage:
  python manual_score.py patches/finding-01/fixer-01.py fixer-01

Writes:
  results/finding-01/<tool>.json          publishable, no raw payloads
  heldout/finding-01/results/<tool>.json  full evidence incl. payloads (git-ignored)
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
VENV_PY = os.path.join(ROOT, ".venv", "bin", "python")
SEMGREP = os.path.join(ROOT, ".venv", "bin", "semgrep")
RULE = os.path.join(ROOT, "scanner", "rules", "formatted-sql-query.yaml")
VULN_APP = os.path.join(ROOT, "app", "corpus_app.py")
SEED = os.path.join(ROOT, "app", "seed.py")
HELDOUT = os.path.join(ROOT, "heldout", "finding-01")
PORT = 5001
BASE = "http://127.0.0.1:%d/product" % PORT


def run_semgrep(target):
    out = os.path.join(tempfile.gettempdir(), "score_sg.sarif")
    subprocess.run(
        [SEMGREP, "scan", "--config", RULE, "--no-git-ignore", "--metrics=off",
         "--sarif", "--output", out, target],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    with open(out) as f:
        return len(json.load(f)["runs"][0]["results"])


def call(payload):
    url = BASE + "?" + urllib.parse.urlencode({"name": payload})
    try:
        with urllib.request.urlopen(url) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode())
        except Exception:
            body = {"_nonjson": True}
        return e.code, body


def attack_succeeded(attack, status, body):
    """An attack succeeded if the response leaked data it should not have."""
    if status != 200 or not isinstance(body, dict) or "results" not in body:
        return False
    blob = json.dumps(body["results"])
    if attack["class"] == "boolean":
        return body["count"] > 1
    if attack["class"] == "union":
        return ("hash_" in blob) or ("@example.com" in blob)
    if attack["class"] == "schema-disclosure":
        return ("CREATE TABLE" in blob) or ("users" in blob)
    return False


def added_lines(patched_path):
    orig = open(VULN_APP, encoding="utf-8").read().splitlines()
    new = open(patched_path, encoding="utf-8").read().splitlines()
    import difflib
    return [l[2:] for l in difflib.unified_diff(orig, new, lineterm="")
            if l.startswith("+ ") or (l.startswith("+") and not l.startswith("+++"))]


SUPPRESSION_MARKERS = ["# nosec", "#nosec", "# noqa", "nosemgrep",
                       "semgrep-disable", "semgrep: ignore", "pylint: disable",
                       ".semgrepignore"]


def score(patched_path, tool):
    work = tempfile.mkdtemp(prefix="assay_score_")
    app_dir = os.path.join(work, "app")
    os.makedirs(app_dir)
    shutil.copy(SEED, os.path.join(app_dir, "seed.py"))
    shutil.copy(patched_path, os.path.join(app_dir, "corpus_app.py"))

    # build the seeded database inside the isolated working copy
    subprocess.run([VENV_PY, "seed.py"], cwd=app_dir,
                   stdout=subprocess.DEVNULL, check=True)

    # CHECK A
    a_findings = run_semgrep(os.path.join(app_dir, "corpus_app.py"))
    check_a = (a_findings == 0)

    # start the patched app
    proc = subprocess.Popen([VENV_PY, "corpus_app.py"], cwd=app_dir,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(30):
            try:
                urllib.request.urlopen("http://127.0.0.1:%d/health" % PORT, timeout=1)
                break
            except Exception:
                time.sleep(0.3)

        # CHECK B
        adata = json.load(open(os.path.join(HELDOUT, "attacks.json")))
        attacks = [a for a in adata["attacks"] if not a.get("reported")]
        b_detail, b_success = [], 0
        for a in attacks:
            st, body = call(a["payload"])
            ok = attack_succeeded(a, st, body)
            b_success += ok
            b_detail.append({"id": a["id"], "class": a["class"], "payload": a["payload"],
                             "status": st, "count": body.get("count") if isinstance(body, dict) else None,
                             "succeeded": bool(ok)})
        check_b = (b_success == 0)

        # CHECK C
        baseline = json.load(open(os.path.join(HELDOUT, "baseline.json")))["baseline"]
        c_detail, c_regress = [], 0
        for e in baseline:
            st, body = call(e["input"])
            reg = not (st == e["status"] and body == e["body"])
            c_regress += reg
            c_detail.append({"id": e["id"], "input": e["input"],
                             "expected_status": e["status"], "got_status": st,
                             "body_match": bool(body == e["body"]), "regression": bool(reg)})
        check_c = (c_regress == 0)
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=10)
        shutil.rmtree(work, ignore_errors=True)

    # CHECK D  (tightened)
    added = added_lines(patched_path)
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
        "finding": "finding-01", "tool": tool, "date": "2026-09-08",
        "scanner": "Semgrep OSS 1.90.0 (vendored CWE-89 rule)",
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

    os.makedirs(os.path.join(ROOT, "results", "finding-01"), exist_ok=True)
    os.makedirs(os.path.join(HELDOUT, "results"), exist_ok=True)
    json.dump(pub, open(os.path.join(ROOT, "results", "finding-01", tool + ".json"), "w"),
              ensure_ascii=False, indent=2)
    json.dump(full, open(os.path.join(HELDOUT, "results", tool + ".json"), "w"),
              ensure_ascii=False, indent=2)
    return full


def main():
    if len(sys.argv) != 3:
        print("usage: python manual_score.py <patched_corpus_app.py> <tool-name>")
        sys.exit(2)
    r = score(sys.argv[1], sys.argv[2])
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


if __name__ == "__main__":
    main()
