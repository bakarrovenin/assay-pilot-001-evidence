# Assay Pilot 001 results

Generated 2026-09-14T15:00:56Z by `run_matrix.py`. Scanner: Semgrep OSS 1.90.0 (vendored CWE-89 rule).

Coverage: 4 of 15 findings built, 10 tools, 21 of 40 possible cells supplied, 21 run, 2 no-alert.

2 cell(s) recorded **no alert raised**: the scanner found nothing, so the fixer produced no patch. This is not a verdict and not INSUFFICIENT EVIDENCE, and is counted in no rate. See the `.no-alert.json` sidecar for each.

## How to read this

- Coverage is partial. 4 of the 15 findings in the corpus are built, so every number here describes those 4 findings and says nothing about the shapes not yet written: numeric context, LIKE, ORDER BY, multi-parameter, ORM, second order, multi-hop. The gap is expected to be larger in the harder shapes, which is a reason to distrust this number as an estimate of the whole.
- 13 cell(s) are provisional: claude-code, copilot-autofix, cursor, lazy-string-match, lazy-suppression. Each was produced against a corpus whose modules contained prose naming the flaw and the fix (METHODOLOGY-NOTES.md note 12). They are kept, not deleted: a valid test of the harness and an invalid measurement of the tools. They are reported in their own rows and subtotal and are never merged with a blind cell. The blind re-run of a tool is under the same name with the suffix -blind, so the two can be read side by side.
- These rows are counts, not rates: copilot-autofix, copilot-autofix-blind, fixer-01, fixer-02, fixer-03, lazy-string-match, lazy-suppression. Each was scored on fewer than 3 cells, so the percentage restates one or two results and can only move in whole steps. Read the per cell table instead.
- The harness does not call the fixers. Tool names are the names of the diff files supplied. Some are illustrative patches we wrote to exercise the method: the finding-01 fixer cells, and the lazy-* probe cells built to test whether the held-out sets catch a lazy fix. Others are real tool output. patches/TOOLS.md says which is which and pins the versions and dates. Either way, with only a few scored cells per tool this is not a vendor comparison and no rate here generalises. See patches/TOOLS.md and README.

## Rates per tool

| Tool | Run | Supplied | Scored | Insufficient | Alert closed | Verified fix | Gap | Insufficient rate |
|---|---|---|---|---|---|---|---|---|
| chatgpt-blind | standing | 4 | 4 | 0 | 100% | 75% | +25 pp | 0% |
| claude-code | provisional | 3 | 3 | 0 | 67% | 100% | -33 pp | 0% |
| copilot-autofix | provisional | 2 | 2 | 0 | 50% | 50% | +0 pp | 0% |
| copilot-autofix-blind | standing | 2 | 2 | 0 | 50% | 50% | +0 pp | 0% |
| cursor | provisional | 3 | 3 | 0 | 67% | 67% | +0 pp | 0% |
| fixer-01 | standing | 1 | 1 | 0 | 100% | 100% | +0 pp | 0% |
| fixer-02 | standing | 1 | 1 | 0 | 0% | 0% | +0 pp | 0% |
| fixer-03 | standing | 1 | 1 | 0 | 100% | 0% | +100 pp | 0% |
| lazy-string-match | provisional | 2 | 2 | 0 | 0% | 0% | +0 pp | 0% |
| lazy-suppression | provisional | 2 | 2 | 0 | 100% | 0% | +100 pp | 0% |
| **Provisional** | provisional | 12 | 12 | 0 | 58% | 50% | +8 pp | 0% |
| **Standing** | standing | 9 | 9 | 0 | 78% | 56% | +22 pp | 0% |
| **All (pooled, recount only)** | both | 21 | 21 | 0 | 67% | 52% | +14 pp | 0% |

Runs: provisional: cells produced against a corpus whose modules contained prose naming the flaw and the fix (note 12); a valid test of the harness, an invalid measurement of the tools. standing: every other cell. The two are never merged in a rate; the overall row above pools them and is kept for the recount only.

Denominators: alert-closed rate and verified-fix rate are over cells that produced a verdict. A run that produced no verdict has no check A result and is counted only in the insufficient rate. Gap is a difference of two rates, so it is in percentage points.

## Failure classes

| Class | Count |
|---|---|
| over-broad | 4 |
| string-match | 1 |
| string-match-and-over-broad | 2 |
| suppression-in-effect | 3 |

## Per cell

| Finding | Tool | Run | A | B | C | D | Verdict | Class |
|---|---|---|---|---|---|---|---|---|
| finding-01 | chatgpt-blind | standing | pass | pass | pass | pass | VERIFIED | correct |
| finding-01 | fixer-01 | standing | pass | pass | pass | pass | VERIFIED | correct |
| finding-01 | fixer-02 | standing | fail | fail | fail | pass | NOT VERIFIED | string-match-and-over-broad |
| finding-01 | fixer-03 | standing | pass | fail | fail | fail | NOT VERIFIED | suppression-in-effect |
| finding-04 | chatgpt-blind | standing | pass | pass | pass | pass | VERIFIED | correct |
| finding-04 | claude-code | provisional | pass | pass | pass | pass | VERIFIED | correct |
| finding-04 | copilot-autofix | provisional | pass | pass | pass | pass | VERIFIED | correct |
| finding-04 | copilot-autofix-blind | standing | pass | pass | pass | pass | VERIFIED | correct |
| finding-04 | cursor | provisional | pass | pass | fail | pass | NOT VERIFIED | over-broad |
| finding-04 | lazy-string-match | provisional | fail | fail | pass | pass | NOT VERIFIED | string-match |
| finding-04 | lazy-suppression | provisional | pass | fail | pass | fail | NOT VERIFIED | suppression-in-effect |
| finding-08 | chatgpt-blind | standing | pass | pass | fail | pass | NOT VERIFIED | over-broad |
| finding-08 | claude-code | provisional | fail | pass | pass | pass | VERIFIED | correct |
| finding-08 | copilot-autofix | provisional | fail | pass | fail | pass | NOT VERIFIED | over-broad |
| finding-08 | copilot-autofix-blind | standing | fail | pass | fail | pass | NOT VERIFIED | over-broad |
| finding-08 | cursor | provisional | fail | pass | pass | pass | VERIFIED | correct |
| finding-13 | chatgpt-blind | standing | pass | pass | pass | pass | VERIFIED | correct |
| finding-13 | claude-code | provisional | pass | pass | pass | pass | VERIFIED | correct |
| finding-13 | copilot-autofix | provisional | . | . | . | . | no alert raised | py/sql-injection |
| finding-13 | copilot-autofix-blind | standing | . | . | . | . | no alert raised | py/sql-injection |
| finding-13 | cursor | provisional | pass | pass | pass | pass | VERIFIED | correct |
| finding-13 | lazy-string-match | provisional | fail | fail | fail | pass | NOT VERIFIED | string-match-and-over-broad |
| finding-13 | lazy-suppression | provisional | pass | fail | fail | fail | NOT VERIFIED | suppression-in-effect |

## Not measured

- median patch latency: the harness does not call the fixers, so it never observes generation time
- cost per fix: same reason, no API call is made by this harness
