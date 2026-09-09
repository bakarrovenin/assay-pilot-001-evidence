# Assay Pilot 001 results

Generated 2026-09-09T07:50:49Z by `run_matrix.py`. Scanner: Semgrep OSS 1.90.0 (vendored CWE-89 rule).

Coverage: 1 of 15 findings built, 3 tools, 3 of 3 possible cells supplied, 3 run.

## How to read this

- Coverage is partial. 1 of the 15 findings in the corpus is built, so every number here describes that one finding and says nothing about the shapes not yet written: numeric context, LIKE, ORDER BY, multi-parameter, ORM, second order, multi-hop. The gap is expected to be larger in the harder shapes, which is a reason to distrust this number as an estimate of the whole.
- These rows are counts, not rates: fixer-01, fixer-02, fixer-03. Each was scored on fewer than 3 cells, so the percentage restates one or two results and can only move in whole steps. Read the per cell table instead.
- The overall row is 3 cells. It shows that the four checks separate a real fix from patches that only close the alert. It is not a rate that generalises to any tool or any codebase.
- The harness does not call the fixers. Tool names are the names of the diff files supplied, and for Pilot 001 they are illustrative patches written to exercise the method, not output from the vendors named in the protocol. This is not a vendor comparison. See README.

## Rates per tool

| Tool | Supplied | Scored | Insufficient | Alert closed | Verified fix | Gap | Insufficient rate |
|---|---|---|---|---|---|---|---|
| fixer-01 | 1 | 1 | 0 | 100% | 100% | +0 pp | 0% |
| fixer-02 | 1 | 1 | 0 | 0% | 0% | +0 pp | 0% |
| fixer-03 | 1 | 1 | 0 | 100% | 0% | +100 pp | 0% |
| **All** | 3 | 3 | 0 | 67% | 33% | +33 pp | 0% |

Denominators: alert-closed rate and verified-fix rate are over cells that produced a verdict. A run that produced no verdict has no check A result and is counted only in the insufficient rate. Gap is a difference of two rates, so it is in percentage points.

## Failure classes

| Class | Count |
|---|---|
| string-match-and-over-broad | 1 |
| suppression-in-effect | 1 |

## Per cell

| Finding | Tool | A | B | C | D | Verdict | Class |
|---|---|---|---|---|---|---|---|
| finding-01 | fixer-01 | pass | pass | pass | pass | VERIFIED | correct |
| finding-01 | fixer-02 | fail | fail | fail | pass | NOT VERIFIED | string-match-and-over-broad |
| finding-01 | fixer-03 | pass | fail | fail | fail | NOT VERIFIED | suppression-in-effect |

## Not measured

- median patch latency: the harness does not call the fixers, so it never observes generation time
- cost per fix: same reason, no API call is made by this harness
