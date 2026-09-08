# Assay Pilot 001
## Verified-fix experiment, v0 protocol

---

## 0. What this is, and what it is not

**Is:** a controlled experiment measuring the gap between two things the industry treats as one thing. Whether the scanner alert closed, and whether the vulnerability is actually shut.

**Is not:** the Index. The Index runs on real projects with real historical vulnerabilities. This runs on a corpus we wrote ourselves, which means we know ground truth exactly and can iterate fast, at the cost of realism. Publish it as Pilot 001, never as the Index.

**The result we are hunting:** alert-closed rate near 100 percent, verified-fix rate materially below it. If verified-fix comes back above 85 percent, the thesis is smaller than claimed and we say so publicly.

**Scope, deliberately narrow.** Python. SQL injection only (CWE-89). Fifteen findings. Four or five fixers. Anything outside that returns INSUFFICIENT EVIDENCE, which is the honest answer and the reason that state exists.

---

## 1. The corpus

Build one small Flask application with a real database behind it (SQLite is fine, Postgres is more realistic). Fifteen endpoints, each containing one deliberately written SQL injection flaw. We write the flaws, so we know the correct fix for every one.

The point of fifteen rather than one is that the flaws must differ in shape. A patch that works for a quoted string context often fails in a numeric context. That variation is where the gap lives.

### Required variation across the fifteen

| # | Shape | Why it is in the set |
|---|---|---|
| 1 to 3 | Quoted string context, single parameter | The baseline case. Every tool should get these. |
| 4 to 5 | Numeric context, no quotes in the query at all | Any patch that escapes or strips quotes does nothing here. |
| 6 to 7 | LIKE clause with wildcards | Escaping rules differ, naive patches break search. |
| 8 to 9 | ORDER BY / column name interpolation | Cannot be parameterised. Requires an allowlist. Tests whether the tool knows the difference. |
| 10 to 11 | Multiple parameters, only one tainted | Tests whether the fix is targeted or scattershot. |
| 12 | ORM raw query escape hatch | Realistic. Looks safe because an ORM is present. |
| 13 to 14 | Second order: input stored, then used in a later query | The reported sink and the vulnerable sink are in different functions. |
| 15 | Input reaching the query through two hops of helper functions | Tests whether the tool traces the taint or pattern matches the line. |

For each finding, record in the corpus file:
- the vulnerable code and its file and line
- the known correct fix, written by us
- the **held-out attack set**: 10 to 15 inputs that exploit this flaw, spanning boolean, union, and context-specific forms. One of these is designated the **reported payload**.
- the **benign set**: 10 to 15 ordinary inputs that must keep working, deliberately including awkward legitimate values (an apostrophe in a surname, a percent sign in a search term, a hyphenated value, unicode)
- the expected correct response for every benign input, captured from the unpatched app before anything is fixed

### The held-out rule

The fixer sees the file, and the scanner finding, and the **reported payload only**. It never sees the rest of the attack set and never sees the benign set. Those files stay out of the working directory the tool operates in. This is the entire integrity of the experiment. If a payload leaks into the tool's context, that finding is void and must be regenerated.

---

## 2. Producing the patches

Run a free scanner (Semgrep OSS) over the app first and record its findings. This is the input a real developer would have.

For each finding, in a clean checkout, give each tool an identical prompt. The prompt must be genuinely identical across tools or the comparison is worthless. Something in the shape of:

> Semgrep reports a SQL injection vulnerability at `<file>:<line>`. Example payload: `<reported payload>`. Fix it.

Nothing more. Do not hint at parameterisation, do not mention held-out testing, do not say the patch will be independently verified. We are measuring the tools as a developer actually uses them.

Tools for Pilot 001: Claude Code, Cursor agent, GitHub Copilot Autofix, OpenAI Codex, plus Buttercup as the free DARPA baseline row. Pin and record the exact version or model of each, with the date. Numbers without pinned versions are not reproducible and will be attacked.

Capture the raw patch diff for every tool and every finding. Sixty to seventy-five patches total. These are the primary artifacts.

---

## 3. Scoring

Every patch is scored on four checks. All four are mechanical and produce evidence, not opinion.

**Check A: alert closed.** Apply the patch, re-run the pinned Semgrep version. Did the finding disappear? This is the industry standard, and it is the number we expect to be near 100 percent.

**Check B: hole shut.** Start the patched app. Fire every attack in the held-out set except the reported payload. Any response that returns row data, leaks a column, or otherwise succeeds means the hole is open. Record which payloads succeeded, by class.

**Check C: behaviour preserved.** Fire the benign set at the patched app and compare every response to the pre-patch baseline captured in section 1. Any difference is a regression. This is where over-broad patches get caught: the fix that rejects all apostrophes and breaks the customer named O'Brien.

**Check D: no suppression, no new problem.** Scan the diff itself. Automatic fail if the patch adds `# nosec`, a `.semgrepignore` entry, a rule disable, or a broad try/except that swallows the failure. Also flag any new finding introduced by the diff.

### Verdict

- **VERIFIED** — A passes, B passes with zero successful held-out attacks, C passes, D passes.
- **NOT VERIFIED** — any of B, C or D fails.
- **INSUFFICIENT EVIDENCE** — the app would not build, the patch would not apply, the harness could not execute the attack set, or coverage was incomplete. This is a real result and must be reported, never quietly dropped.

The verdict is deliberately strict. One successful held-out attack is a fail. State that plainly in the methodology so nobody thinks it slipped past us.

---

## 4. Failure taxonomy

Classify every NOT VERIFIED. This is where the writing comes from, and it is more valuable than the headline number.

| Class | What it looks like |
|---|---|
| **String match** | Patch blocks the reported payload literally, or a close variant. Everything else walks through. |
| **Wrong context** | Patch escapes quotes in a numeric query where no quote was ever needed. |
| **Over-broad** | Hole is shut, but legitimate input is now rejected. Check C fails. |
| **Suppression** | Alert silenced rather than fixed. |
| **Partial** | The reported sink is fixed, another sink reachable from the same input is not. Second order and multi-hop cases. |
| **Correct** | Parameterised query, or an allowlist for identifier contexts. The fix never inspects the payload. |

Report the distribution. "Of the patches that closed the alert but failed verification, X percent blocked the reported string rather than changing how the query was built" is a stronger sentence than any rate.

---

## 5. What to report

Per tool: alert-closed rate, verified-fix rate, **the gap between them**, insufficient-evidence rate, failure class distribution, median patch latency, and cost per fix where measurable.

The headline is the gap, not the rate. The gap is the company.

Also report the Buttercup baseline row plainly, whatever it says. If the free DARPA system beats a paid vendor, that is the story. If it loses, publish that too. The moment we suppress an inconvenient row we are the thing we are criticising.

---

## 6. Publication

**Name it Pilot 001, or Methodology Preview. Not the Index.**

Publish: the harness, the corpus, the scoring code, the pinned tool versions, every raw patch diff, the full results, and the limitations.

Withhold: nothing except the held-out attack sets themselves, and only until Pilot 002 exists. Withholding those is defensible because publishing them lets vendors train against them. Say exactly that.

**Limitations, stated by us before anyone else states them:**
- the vulnerabilities were seeded by us, not found in the wild
- one weakness class, one language, one application
- fifteen findings is a signal, not a rate that generalises
- the app is small, and small codebases are easier to patch correctly than large ones
- results describe these tool versions on this date

**Vendor right of reply.** Contact every vendor before publication with their results and a window to respond. Publish their response alongside, unedited. This costs us nothing and is the single clearest demonstration that we are the neutral party. It is also what an assay office does.

---

## 7. Do the first one by hand

Before any harness exists, run finding 1 manually end to end. Write the flaw, write the attacks, run Semgrep, get a patch from one tool, apply it, fire the payloads with curl, watch what happens.

This takes an afternoon and it is not optional. You cannot write about this credibly until you have watched a patch close an alert and fail an attack with your own eyes.

---

## 8. Harness prompt for Claude Code

Paste this once the manual run is done and the corpus format is settled.

```
Build the harness for Assay Pilot 001, a controlled experiment measuring
whether AI-generated security patches actually fix the vulnerability or
just silence the scanner.

Read the protocol document in the repo first. Build in stages and stop
after each for review. Do not build the whole thing in one pass.

STAGE 1: THE CORPUS APP
A small Flask app, SQLite backend, seeded with realistic data. Fifteen
endpoints, each with one deliberately written SQL injection flaw, varying
across the shapes listed in the protocol: quoted string, numeric context,
LIKE clause, ORDER BY identifier interpolation, multi-parameter,
ORM raw query, second order, and multi-hop taint.

For each finding, a manifest entry with: id, file, line, shape, the known
correct fix, and pointers to its attack set and benign set. Store attack
and benign sets in a directory that is git-ignored from the working
checkout the fixers operate on. The fixers must never see them.

STAGE 2: BASELINE CAPTURE
Script that runs every benign input against the UNPATCHED app and records
the exact response for each. This is the regression baseline. Also run
pinned Semgrep OSS over the app and store the findings as SARIF.

STAGE 3: THE SCORER
Given a patch diff and a finding id:
  A. apply the patch to a clean checkout, re-run pinned Semgrep, record
     whether the finding is gone
  B. build and start the patched app in an isolated container, fire every
     held-out attack except the reported payload, record which succeeded
     and their class
  C. fire the benign set, diff every response against the baseline, record
     any regression
  D. scan the diff for suppression markers (# nosec, .semgrepignore edits,
     rule disables, broad exception swallowing) and for new findings
Emit VERIFIED, NOT VERIFIED or INSUFFICIENT EVIDENCE plus a structured
JSON evidence artifact: which checks passed, which payloads succeeded,
which benign responses changed, and why. The artifact is the point. A
verdict without evidence is worthless.

Everything runs in a container with no network egress. Tear down between
runs so no state leaks from one patch to the next.

STAGE 4: RUNNER AND REPORT
Orchestrate the matrix of findings by tools. Patches are supplied by me
as diff files, the harness does not call the fixers. Aggregate into
alert-closed rate, verified-fix rate, the gap, insufficient-evidence rate,
and failure class distribution per tool. Output a results table and the
per-patch evidence artifacts.

Constraints: Python. Pin every dependency and record scanner version. The
harness will be published, so it must be readable and reproducible by
someone hostile to the result. No em dashes or en dashes in any prose or
comments you write.
```

---

## 9. After the pilot

If the gap shows up, Pilot 001 becomes the credibility that funds the real thing: real projects, real historical vulnerabilities from ARVO, environment reconstruction, more classes, more languages. That is the Index.

If the gap does not show up, we have learned the most valuable thing available to us, three weeks in rather than a year in, and we say so publicly. That is what taking nobody's word for it means when the word is ours.
