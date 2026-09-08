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

Per-patch evidence is in `results/finding-01/`.

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
    tools/                the parity proof and the held-out leak guard
    scanner/              pinned Semgrep finding (SARIF), vendored rule, versions
    patches/finding-01/   the three scored patches and their diffs
    results/finding-01/   the published verdicts and evidence (no raw payloads)
    manual_score.py       command line scorer, one patch against one finding
    METHODOLOGY-NOTES.md  refinements found while running the pilot by hand
    assay-pilot-001-protocol.md   the governing protocol

## License

See LICENSE. The vendored Semgrep rule in `scanner/rules/` is under the Semgrep
Rules License, noted in that file.
