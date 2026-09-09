# Assay Pilot 001

Published evidence behind Assay Pilot 001, a controlled experiment measuring
the gap between two things the security industry usually treats as one: whether
a scanner alert closed, and whether the vulnerability is actually shut.

This repository exists so that anyone can inspect, reproduce, and attack our
results. It is evidence, not a product.

## What this is, and what it is not

**It is** Pilot 001: a small, deliberately seeded corpus where we know ground
truth exactly, used to demonstrate the method and produce a first result.

**It is not** the Index. The Index will run on real projects with real
historical vulnerabilities. This runs on a flaw we wrote ourselves, which means
we know the correct fix but pay for it in realism. Cite this as Pilot 001 or a
methodology preview, never as the Index.

**It is not** a general-purpose tool for scanning your own code. It scores
patches against one seeded finding with a held-out test set. That is all it
does today.

## The finding tested

One endpoint (`app/corpus_app.py`) with a single SQL injection (CWE-89) in a
**quoted-string context, single parameter**. This is the easiest shape in the
protocol's variation table, the baseline case every tool is expected to get.
User input is interpolated straight into the SQL string between quotes.

The app is a tiny Flask service over a small seeded SQLite database with two
tables: `products` (the endpoint's intended data) and `users` (internal
records that a successful injection can steal, so "the hole is open" means
something concrete).

## The four checks and the verdict rule

Every patch is scored on four mechanical checks that produce evidence, not
opinion:

- **A. Alert closed.** Re-run pinned Semgrep on the patched file. Did the
  finding disappear?
- **B. Hole shut.** Start the patched app and fire every held-out attack
  except the reported payload. Did any leak data?
- **C. Behaviour preserved.** Fire the benign set and compare every response
  to a baseline of correct answers. Any difference is a regression.
- **D. No suppression.** Scan the diff for suppression markers (`# nosec`,
  ignore files, rule disables, swallowing try/except). Also fails on
  "suppression in effect": the alert closed but held-out attacks still
  succeeded (see METHODOLOGY-NOTES.md).

**Verdict rule: VERIFIED requires all four checks to pass. One successful
held-out attack is a fail.** The rule is deliberately strict, and we state that
plainly so nobody thinks it slipped past us.

## Results

Three patches were scored against Finding 1. Attacks are referenced by id and
class; the held-out set has 13 attacks (one reported, 12 held out) and the
benign set has 14 inputs.

| Patch    | A alert closed | B hole shut  | C behaviour | D no suppression | Verdict      | Failure class                |
|----------|----------------|--------------|-------------|------------------|--------------|------------------------------|
| fixer-01 | pass           | pass (0/12)  | pass        | pass             | VERIFIED     | correct                      |
| fixer-02 | fail           | fail (4/12)  | fail        | pass             | NOT VERIFIED | string-match-and-over-broad  |
| fixer-03 | pass           | fail (12/12) | fail        | fail             | NOT VERIFIED | suppression-in-effect        |

- **fixer-01** used a parameterised query. A real fix: it changes how the query
  is built and never inspects the payload.
- **fixer-02** escaped single quotes with a backslash. That is a MySQL
  convention SQLite does not honor, so 4 held-out attacks still leaked and the
  legitimate input "Chef's Knife" broke.
- **fixer-03** is the important row. It moved the query into a helper using
  string concatenation, a shape the Semgrep rule does not match. The scanner
  went green and the explicit-marker suppression check stayed clean, yet all 12
  held-out attacks still leaked, including password hashes. Only Check B caught
  it. This is why the held-out set exists.

A note on provenance: these three patches exercise the scoring method; they
are not a comparison of named tools. fixer-01 is a correct parameterised fix.
fixer-02 and fixer-03 are illustrative failing patches, and fixer-03 was
constructed by us specifically to demonstrate the suppression-in-effect shape.
None are output from the vendors named in the protocol (Claude Code, Cursor,
Copilot Autofix, Codex, Buttercup); that vendor comparison is future work. The
point of these three is that the four checks correctly separate a real fix from
patches that only close the alert.

Per-patch evidence is in `results/finding-01/`. The generated table across
every finding and tool is `results/RESULTS.md`, with the machine-readable
aggregate in `results/summary.json`.

## How the scorer runs

Every patch is scored inside a container with no network egress, one container
per patch, destroyed when that patch is done. The host builds the image and
collects the results; it never applies a patch, never starts the patched app
and never fires an attack payload.

Two things follow from that, and both are recorded rather than asserted.

**No state can leak between patches.** The container is created fresh, given a
copy of the repository, and removed with force when the run ends however it
ends. Nothing is bind mounted, so it cannot write back to the repository even
by accident. The patched file, the seeded database, the app process and the
whole writable layer go with it.

**The isolation is measured, not claimed.** An artifact that says "no network
egress" because the harness passed `--network none` is a claim about a command
line, not evidence: drop the flag and the file still says the same thing. So
the container measures itself from the inside, before it applies a patch or
builds a payload, and records which interfaces exist, whether a default route
exists at all, and the result of real TCP and DNS attempts to addresses off
the host. If any of them connects, the run is refused and reports INSUFFICIENT
EVIDENCE without scoring anything.

That measurement lives in `results/finding-01/<tool>.provenance.json`, beside
the evidence rather than inside it. It carries the sha256 of each evidence
file it describes, so provenance cannot be attached to evidence it does not
belong to. The reason it is a separate file is in METHODOLOGY-NOTES.md note 3:
the gate on this harness is that artifacts still byte compare against the ones
committed from the manual run, and adding a field to the evidence would end
that comparison permanently.

Run it:

    python score_container.py patches/finding-01/fixer-01.patch fixer-01

The scorer takes a patch diff and applies it to a clean checkout. A diff that
will not apply is INSUFFICIENT EVIDENCE, not a failed patch: nothing about the
vulnerability was tested. Pass `--patched-file` instead to score an already
patched file, which is the input shape the committed stage 1 evidence was
produced from.

### Checks on the harness itself

    python tools/verify_stage3_parity.py          # containerisation changed nothing
    python tools/verify_insufficient_evidence.py  # every failure path reports itself
    python tools/verify_report_math.py            # published rates match the artifacts
    python tools/check_no_leak.py                 # no held-out payload in a tracked file
    python tools/check_history_no_leak.py         # nor in any blob the history carries

`verify_stage3_parity.py` re-scores all three Finding 1 patches in the
container and byte-compares every artifact against the committed ones, scores
each patch a second time from its diff to confirm the two input paths agree,
and fails if any run reports egress. All three verdicts and all six artifacts
were unchanged, on a container whose SQLite and Python builds differ from the
machine the evidence was captured on.

`verify_insufficient_evidence.py` provokes each way a run can fail to produce
a verdict and requires the scorer to name it. That list includes a patch that
does not import, which before stage 3 would have scored as a patch that shut
the hole, because every attack failing to connect reads exactly like every
attack being blocked. See METHODOLOGY-NOTES.md note 4.

`check_history_no_leak.py` reads the git objects rather than the working tree.
The two leak guards answer different questions, and the difference matters: a
file can carry a secret in one commit and be cleaned in the next, leaving the
tracked-file guard correctly reporting nothing while the earlier blob stays
fetchable by SHA forever. That is not hypothetical, it is why the file exists.
See METHODOLOGY-NOTES.md note 6.

`verify_report_math.py` recounts every published rate from the per-cell
evidence files, using plain counting and division and nothing from the
aggregation code, then compares. Calling the same aggregation twice would
prove only that it is deterministic. The rates are the headline of this pilot
and the one number nobody can check by eye, which by the pattern in note 4
makes them the next place a false pass would hide: an arithmetic error there
would not look like a bug, it would look like a finding.

## The matrix and the report

`run_matrix.py` runs the grid: every built finding against every tool that
supplied a patch for it, scoring each cell in an isolated container and
aggregating the results.

    python run_matrix.py                 score anything not yet scored, report
    python run_matrix.py --report-only   report from what is already on disk
    python run_matrix.py --rescore       score every supplied cell again

Patches are supplied as diff files, one per cell, at
`patches/<finding-id>/<tool>.patch`. **The harness never calls a fixer.** That
is deliberate: a harness that invoked the tools itself would be making choices
about prompt, temperature, retries and timeouts, and every one of those
choices would end up inside the result. Protocol section 2 fixes the prompt
and requires it to be identical across tools, and keeping generation outside
the harness is how that stays true.

It will not overwrite an existing result without `--rescore`. The three
Finding 1 artifacts have been byte-identical since the manual run, through the
Stage 1 restructure and the Stage 3 containerisation, and two parity gates
exist to prove it. Re-scoring them by default would put that chain at the
mercy of whoever runs the script.

### Denominators

A cell is one finding scored against one tool.

| Denominator | Meaning |
|---|---|
| supplied | a diff exists on disk for that cell |
| run | the scorer actually ran it |
| scored | the run produced VERIFIED or NOT VERIFIED |
| insufficient | the run produced INSUFFICIENT EVIDENCE |

Alert-closed rate and verified-fix rate are over `scored`, because a run that
produced no verdict produced no check A result and cannot be counted for or
against. That choice flatters a tool with many insufficient runs, so the
insufficient rate sits in the same table rather than in a footnote, and every
row prints its own cell counts. A rate whose denominator is not on screen is
not evidence. A tool with no scored cells shows `n/a`, never `0%`.

The gap is a difference of two rates, so it is in percentage points.

The report also generates its own caveats from the data: partial corpus
coverage, rows whose denominator is too small to be a rate, and the fact that
the tool names here are illustrative patches rather than vendor output. Those
are generated rather than written by hand so they cannot fall out of date with
the numbers they qualify.

### What is not measured

Protocol section 5 also asks for median patch latency and cost per fix. The
harness does not call the fixers, so it cannot observe either. They are
reported as not measured rather than estimated. The wall clock in the
provenance files is how long scoring took, which is a fact about this harness
and not about any tool.

## Pinned versions

Numbers without pinned versions are not reproducible. Recorded in
`scanner/VERSIONS.txt`.

- Python 3.9.6
- Flask 3.0.3
- Semgrep OSS 1.90.0 (run with the vendored CWE-89 rule in
  `scanner/rules/formatted-sql-query.yaml`, so the scan needs no network)
- Full dependency lock in `requirements.lock.txt`

## Reproducing this

Setup:

    python3 -m venv .venv
    .venv/bin/python -m pip install -r requirements.txt
    .venv/bin/python app/seed.py

**What you can reproduce yourself:**

- The app and its vulnerability. Start it (`.venv/bin/python app/corpus_app.py`)
  and send your own inputs to `/product?name=...`.
- **Check A** on any patch: run the pinned Semgrep over the vulnerable file and
  over each patched file in `patches/finding-01/`. You will see one finding
  become zero for fixer-01 and fixer-03, and stay at one for fixer-02.
- **The scanner baseline.** `scanner/finding-01.sarif` regenerates byte for
  byte from the command recorded in `scanner/finding-01.capture.json`. The
  rule is vendored locally and metrics are off, so the scan needs no network
  and no Semgrep account, and the SARIF contains no machine-specific paths.
- The patches themselves (`patches/finding-01/`) and the recorded verdicts and
  evidence (`results/finding-01/`).

**What you cannot reproduce from this repository alone:** Checks B and C, and
therefore a full run of `manual_score.py`. Those checks read the held-out
attack set, the benign set, and the captured baseline, which are not published
(see below). Run the scorer without them and it prints INSUFFICIENT EVIDENCE
and the list of files it could not find, rather than a verdict. The scorer is
included so you can read exactly how B, C, and D work and audit the logic.

Re-running the scorer records the date it ran, so the artifact it writes will
differ from the committed one in the `date` field and nowhere else. Pass
`--run-date 2026-09-08` to reproduce a committed artifact byte for byte, and
`--output-root` to write somewhere other than the repository.

## Where the baseline comes from, and why it is not the unpatched app

The protocol as written says to capture the benign baseline by running the
benign inputs against the unpatched app. That is wrong, and we do not do it.

One benign input is "Chef's Knife", a legitimate product with an apostrophe in
its name. The unpatched app interpolates that apostrophe into the SQL string,
the query is malformed, and the app returns 500. Record that 500 as the
expected answer and a correct parameterised fix, which makes the input work,
scores as a **regression** in check C. The better the patch, the worse it
would score.

So the benign baseline is captured from a known-correct reference
implementation we wrote, which gives the true correct answer for every benign
input. This is a deliberate, documented deviation, recorded in
METHODOLOGY-NOTES.md note 1 and enforced in `harness/baseline.py`, which has
no code path that captures a baseline from the unpatched app.

We do not ask you to take that on trust. Every capture also fires the benign
set at the unpatched app and publishes the difference. From
`scanner/finding-01.capture.json`:

    "note_1_trap_demonstration": {
      "inputs_fired": 14,
      "differs_on": [
        { "id": "b09", "reference_status": 200, "unpatched_status": 500 }
      ]
    }

One of fourteen benign inputs would have been recorded wrong. That one input
is enough to fail a correct fix.

## Why the held-out sets are withheld

The attack set, benign set, baseline, and known-correct reference are kept out
of this repository on purpose. Publishing the attack payloads would let vendors
train or tune against these specific strings, which would quietly turn a real
failure into a fake pass and destroy the experiment's integrity. We withhold
them only until Pilot 002 exists, and we say so here rather than hiding it. The
results above reference every attack by id and class so the outcomes are fully
legible without the payloads.

## Limitations, stated by us

- The vulnerability was seeded by us, not found in the wild.
- One weakness class (SQL injection), one language (Python), one small
  application.
- A single finding, in the easiest shape. The gap the pilot is hunting is
  expected to be larger in harder shapes (numeric context, ORDER BY, second
  order, multi-hop) that are not in this pilot.
- Three patches is a small sample. It is a signal and a demonstration of
  method, not a rate that generalises.
- Small codebases are easier to patch correctly than large ones.
- Results describe these tool versions on this date (2026-09-08).

## Repository layout

    app/                  the vulnerable Flask app and its seeder
    corpus/               the corpus manifest, one entry per finding
    harness/              the scoring core, driven by the manifest
    container/            the scoring image and the script it runs inside it
    tools/                baseline capture, the parity proofs, the two leak
                          guards, the insufficient-evidence checks
    scanner/              pinned Semgrep finding (SARIF), the capture record,
                          the vendored rule, and the pinned versions
    patches/finding-01/   the three scored patches and their diffs
    results/finding-01/   the published verdicts and evidence (no raw payloads),
                          plus one provenance file per patch recording the
                          isolation that run actually had
    results/RESULTS.md    the generated results table across the matrix
    results/summary.json  the machine-readable aggregate
    run_matrix.py         stage 4 runner, the findings by tools matrix
    score_container.py    stage 3 scorer, one patch in an isolated container
    manual_score.py       stage 1 scorer, on the host, kept for the audit trail
    METHODOLOGY-NOTES.md  refinements found while running the pilot by hand
    assay-pilot-001-protocol.md   the governing protocol

## License

See LICENSE. The vendored Semgrep rule in `scanner/rules/` is under the Semgrep
Rules License, noted in that file.
