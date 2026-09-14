# Assay Pilot 001 results

Generated 2026-09-14T10:51:15Z by `run_matrix.py`. Scanner: Semgrep OSS 1.90.0 (vendored CWE-89 rule).

Coverage: 4 of 15 findings built, 8 tools, 15 of 32 possible cells supplied, 15 run, 1 no-alert.

1 cell(s) recorded **no alert raised**: the scanner found nothing, so the fixer produced no patch. This is not a verdict and not INSUFFICIENT EVIDENCE, and is counted in no rate. See the `.no-alert.json` sidecar for each.

## How to read this

- Coverage is partial. 4 of the 15 findings in the corpus are built, so every number here describes those 4 findings and says nothing about the shapes not yet written: numeric context, LIKE, ORDER BY, multi-parameter, ORM, second order, multi-hop. The gap is expected to be larger in the harder shapes, which is a reason to distrust this number as an estimate of the whole.
- These rows are counts, not rates: copilot-autofix, fixer-01, fixer-02, fixer-03, lazy-string-match, lazy-suppression. Each was scored on fewer than 3 cells, so the percentage restates one or two results and can only move in whole steps. Read the per cell table instead.
- The harness does not call the fixers. Tool names are the names of the diff files supplied. Some are illustrative patches we wrote to exercise the method: the finding-01 fixer cells, and the lazy-* probe cells built to test whether the held-out sets catch a lazy fix. Others are real tool output. patches/TOOLS.md says which is which and pins the versions and dates. Either way, with only a few scored cells per tool this is not a vendor comparison and no rate here generalises. See patches/TOOLS.md and README.

## Rates per tool

| Tool | Supplied | Scored | Insufficient | Alert closed | Verified fix | Gap | Insufficient rate |
|---|---|---|---|---|---|---|---|
| claude-code | 3 | 3 | 0 | 67% | 100% | -33 pp | 0% |
| copilot-autofix | 2 | 2 | 0 | 50% | 50% | +0 pp | 0% |
| cursor | 3 | 3 | 0 | 67% | 67% | +0 pp | 0% |
| fixer-01 | 1 | 1 | 0 | 100% | 100% | +0 pp | 0% |
| fixer-02 | 1 | 1 | 0 | 0% | 0% | +0 pp | 0% |
| fixer-03 | 1 | 1 | 0 | 100% | 0% | +100 pp | 0% |
| lazy-string-match | 2 | 2 | 0 | 0% | 0% | +0 pp | 0% |
| lazy-suppression | 2 | 2 | 0 | 100% | 0% | +100 pp | 0% |
| **All** | 15 | 15 | 0 | 60% | 47% | +13 pp | 0% |

Denominators: alert-closed rate and verified-fix rate are over cells that produced a verdict. A run that produced no verdict has no check A result and is counted only in the insufficient rate. Gap is a difference of two rates, so it is in percentage points.

## Failure classes

| Class | Count |
|---|---|
| over-broad | 2 |
| string-match | 1 |
| string-match-and-over-broad | 2 |
| suppression-in-effect | 3 |

## Per cell

| Finding | Tool | A | B | C | D | Verdict | Class |
|---|---|---|---|---|---|---|---|
| finding-01 | fixer-01 | pass | pass | pass | pass | VERIFIED | correct |
| finding-01 | fixer-02 | fail | fail | fail | pass | NOT VERIFIED | string-match-and-over-broad |
| finding-01 | fixer-03 | pass | fail | fail | fail | NOT VERIFIED | suppression-in-effect |
| finding-04 | claude-code | pass | pass | pass | pass | VERIFIED | correct |
| finding-04 | copilot-autofix | pass | pass | pass | pass | VERIFIED | correct |
| finding-04 | cursor | pass | pass | fail | pass | NOT VERIFIED | over-broad |
| finding-04 | lazy-string-match | fail | fail | pass | pass | NOT VERIFIED | string-match |
| finding-04 | lazy-suppression | pass | fail | pass | fail | NOT VERIFIED | suppression-in-effect |
| finding-08 | claude-code | fail | pass | pass | pass | VERIFIED | correct |
| finding-08 | copilot-autofix | fail | pass | fail | pass | NOT VERIFIED | over-broad |
| finding-08 | cursor | fail | pass | pass | pass | VERIFIED | correct |
| finding-13 | claude-code | pass | pass | pass | pass | VERIFIED | correct |
| finding-13 | copilot-autofix | . | . | . | . | no alert raised | py/sql-injection |
| finding-13 | cursor | pass | pass | pass | pass | VERIFIED | correct |
| finding-13 | lazy-string-match | fail | fail | fail | pass | NOT VERIFIED | string-match-and-over-broad |
| finding-13 | lazy-suppression | pass | fail | fail | fail | NOT VERIFIED | suppression-in-effect |

## Not measured

- median patch latency: the harness does not call the fixers, so it never observes generation time
- cost per fix: same reason, no API call is made by this harness
