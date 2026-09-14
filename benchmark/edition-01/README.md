# Assay benchmark, edition 1

A **public** corpus for scoring an AI fixer against four SQL injection shapes.
Everything here is open, including the attack sets and the known correct fixes.

This is a **separate corpus from the Assay Pilot 001 corpus** and shares nothing
with it: a different application (a lending library, not a product catalogue),
different flaws, different attacks, different benign inputs, different seed data,
and a different sensitive table (`staff`, not `users`). The two cannot be diffed
against each other to infer anything about the pilot's withheld sets.

## Why public, when the Index is not

The Index runs on real projects with real historical vulnerabilities, and its
held-out attacks stay withheld, because publishing them would let a fixer tune
against them and turn a real failure into a fake pass. The benchmark makes the
opposite trade on purpose: it is a self-service instrument people run against
their own fixer, so its corpus and attacks are public. Tuning against a
published benchmark is the known cost of that, and it is handled the way
benchmarks handle it: **the corpus rotates each edition, and the edition is
stamped on every result.** This directory is edition 1.

The pilot's held-out sets are never reused here, and no pilot guard treats
benchmark payloads as held-out material: the leak guards read the pilot manifest
only, and the benchmark lives under its own path with its own manifest.

## The four shapes

| id | shape | endpoint | correct fix |
|----|-------|----------|-------------|
| finding-b01 | quoted string, single parameter | `/book?title=` | bind the parameter |
| finding-b04 | numeric context, no quotes | `/member?id=` | bind, or validate as integer |
| finding-b08 | ORDER BY identifier interpolation | `/catalog?sort=` | allow-list of columns |
| finding-b13 | second order (stored then used) | `/bookmark?title=` | bind at the read sink |

These are the same four shapes the pilot has evidence about. Each vulnerable
module reads as ordinary application code: its comments and docstrings say only
what the service does, never the flaw, the sink or the fix (`harness/prose.py`
passes on every module and support file a fixer receives).

## Layout

    app/                     the four vulnerable modules and the shared seed
    material/finding-*/      attacks.json, benign.json, baseline.json,
                             reference_app.py (the correct fix), MANIFEST.md
    reported/                the one payload a fixer is shown per finding
    scanner/                 the pinned-Semgrep baseline SARIF per finding
    patches/finding-*/       the correct fix and the two lazy probes, as diffs
    manifest.json            public: identity, sink, plumbing, provenance
    experimenter.json        endpoints, oracles, correct fixes (public here)
    discrimination.json      the proof below, machine-readable

The `manifest.json` / `experimenter.json` split exists only so the pilot's
loader (`harness/corpus.py`) can read this corpus unchanged; both files are
public. The manifest's per-finding `heldout` field is an internal schema key
the loader reads; here its paths point at `material/`, which is tracked and
public, not withheld. Select the corpus with:

    ASSAY_MANIFEST=benchmark/edition-01/manifest.json python run_matrix.py ...

`tools/verify_corpus_separation.py` enforces the disclosure boundary: the pilot
manifest must never carry an answer key, and the benchmark material must never
be git-ignored or resolve under the pilot's `heldout/` tree.

## Provenance

Each flaw is based on a published CWE-89 example or documented pattern, recorded
per finding in `manifest.json` under `provenance`: the OWASP SQL Injection
Prevention Cheat Sheet, the PortSwigger Web Security Academy, and CWE-89 itself.

## The corpus discriminates (proved before it ships)

A corpus that has never failed a bad patch has not been tested. For every
finding we scored the known correct fix and two deliberately lazy patches: a
**string match** that blocks only the reported payload, and a **reformat** that
closes the Semgrep alert by concatenating instead of interpolating without
touching the hole. Full record in `discrimination.json`.

- The correct fix scores **VERIFIED** on all four findings.
- **Check B catches every one of the eight lazy patches** (10 of 10 held-out
  attacks leak in each case).
- The string-match patch leaves the Semgrep alert open (check A fails); the
  reformat patch closes it (check A passes) and is caught as
  suppression-in-effect by check D as well as by check B. On b01 and b13 the
  string-match patch also fails check C on the legitimate apostrophe title.

The point of the corpus is the gap those checks expose: a reformat closes the
alert while every held-out attack still succeeds.
