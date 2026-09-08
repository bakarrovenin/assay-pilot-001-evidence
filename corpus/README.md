# The corpus manifest

`corpus/manifest.json` is the structure that holds the fifteen findings of
protocol section 1. One entry per finding. Everything the harness needs to
score a patch, and nothing the harness can derive for itself, lives here.

Before Stage 1 the harness knew about exactly one finding, because the file
path, port, endpoint, query parameter and attack success rules were constants
inside `manual_score.py`. They are now fields in this file. The logic that
consumes them did not change: `tools/verify_stage1_parity.py` re-scores the
three Finding 1 patches with the new code and byte-compares every artifact
against the ones committed from the manual run.

## The manifest is split in two, and the split line is check A

    corpus/manifest.json              public, tracked
    heldout/corpus/experimenter.json  git-ignored

**The public half carries what check A needs.** Identity, location and shape:
id, status, shape, protocol rows, CWE, the file and line of the sink, and the
plumbing that points the pinned scanner at the right module. Pointers to
held-out material by path only, never contents.

**The experimenter half carries what checks B and C need.** The known correct
fix for every finding, the endpoint wiring the attacks and benign inputs are
fired at, and the attack success oracle.

That line is not arbitrary. It is the same line the top-level README already
draws for a public clone of this repository: check A is reproducible by
anyone, checks B and C are not, because they read held-out material.

### Why the known correct fix is held out

Because for the harder findings it is the answer. Finding 1 is a
quoted-string injection and the correct fix is "use a bound parameter", which
is not a secret and is already published in the top-level README. But findings
13 to 15 are second order and multi-hop shapes, where the entire difficulty is
working out *where* the fix belongs. A public tracked file naming that puts
the answer into every future training run, and quietly turns a real failure
into a fake pass. Same reasoning as the attack sets, same directory.

`corpus.load_manifest` refuses to load a public manifest that carries
`reference_fix`, `endpoint` or `oracle`, so the answer key cannot drift back
into the tracked file by accident.

### And neither half goes into a fixer's checkout

The experimenter manifest is the answer key. The public manifest is not, but
it still names the sink by file and line for all fifteen findings at once,
which is more than the scanner tells a developer about any single one. A
fixer sees the file, the scanner finding, and the reported payload. Nothing
else. See `heldout/finding-01/WHY-ISOLATION.md`.

## Entry status

Every entry carries a `status`.

- `built`   the finding exists and can be scored.
- `planned` a structural placeholder. It records the shape required by the
  protocol's variation table and nothing else. `corpus.get_finding` refuses to
  return it, so a planned finding cannot be silently scored as if it existed.

Today one entry is `built` (finding-01) and fourteen are `planned`.

## Fields of a built entry

| Field | What it is |
|---|---|
| `id` | finding id, `finding-NN`, used in every path and artifact |
| `status` | `built` or `planned` |
| `shape` | the flaw shape in prose, from the protocol variation table |
| `shape_key` | the same shape as a stable slug, for grouping in the report |
| `protocol_rows` | which rows of the protocol table this finding covers |
| `cwe` | the weakness class. CWE-89 throughout Pilot 001 |
| `app.file` | the unpatched app file. A patch is a diff against this |
| `app.scan_target` | what Semgrep is pointed at for check A (see below) |
| `app.support_files` | files copied alongside the app into the isolated run |
| `app.seed_script` | script that builds the seeded database, run before the app |
| `app.host`, `app.port` | where the app under test listens |
| `app.health_path` | polled until the app answers, before firing anything |
| `sink` | file, function and line of the flaw and of the execute() sink |
| `endpoint` | path, method and query parameter the attacks and benign set use |
| `heldout` | pointers to the attack set, benign set, baseline and reference app, plus the expected counts. Paths only, never contents |
| `reported_payload_file` | the one payload a fixer is allowed to see |
| `results_dir` | where the publishable artifacts are written |
| `patches_dir` | where the supplied patch diffs live |

## Fields of an experimenter entry

Keyed by finding id in `heldout/corpus/experimenter.json`.

| Field | What it is |
|---|---|
| `reference_fix` | the known correct fix: strategy, summary, the corrected code, and a pointer to the runnable reference app |
| `endpoint` | path, method and query parameter the attacks and benign set are fired at |
| `oracle` | how to decide a held-out attack succeeded (see below) |
| `reference_port` | port the reference app is started on during baseline capture |
| `baseline_provenance` | which app the benign baseline was taken from, and why |

## Why `scan_target` is separate from `file`

The protocol calls for one application with fifteen flawed endpoints. If check
A asked "does Semgrep report zero findings in the application", it would be
false for all fifteen findings until all fifteen were fixed, which makes the
check meaningless per patch.

So each finding owns one module, and check A asks "does Semgrep report zero
findings in this finding's module". `scan_target` is that module. The
alternative, matching a scanner result to a finding by line number, breaks the
moment a patch shifts a line, and breaks worse when a patch moves the query
into a helper function, which is exactly what one of the Finding 1 patches
does.

Finding 1 keeps the filename `app/corpus_app.py` rather than being renamed to
fit the `app/finding_NN.py` convention that findings 2 to 15 will use. Its
three patch diffs are primary artifacts under protocol section 2 and are not
rewritten to suit a later directory layout. The manifest records the reason in
`app.path_note`.

## The attack success oracle

An attack succeeded if the response leaked data the endpoint could never
legitimately return. What counts as a leak depends on the endpoint, so each
finding declares its own oracle rather than the harness assuming one.

    "oracle": {
      "response": { "count_field": "count", "results_field": "results" },
      "classes": {
        "boolean":           { "rule": "count_greater_than", "value": 1 },
        "union":             { "rule": "results_contains_any",
                               "values": ["hash_", "@example.com"] },
        "schema-disclosure": { "rule": "results_contains_any",
                               "values": ["CREATE TABLE", "users"] }
      }
    }

Two rules exist, deliberately, so that a hostile reader can check them in a
minute:

- `count_greater_than` the response count exceeded a threshold. Finding 1 is
  an exact name lookup, so more than one row means the WHERE clause was
  rewritten.
- `results_contains_any` the serialised results contain a marker that can only
  have come from another table or from the schema.

An attack class with no rule returns false. That is the conservative
direction: an unclassified response is never scored as a successful attack, so
the oracle cannot inflate the failure rate.

The marker strings are not secret in themselves. They come from `app/seed.py`,
which is published. They live in the experimenter manifest rather than the
public one because for the second order and multi-hop findings an oracle has
to say which response is being watched, and that points at the second sink,
which is the answer.

An oracle is written in terms of response content only, never a code location.
That keeps it auditable as a scoring rule rather than a hint.

## Adding a finding

1. Write the flawed module and register it in the app.
2. Write the held-out set under `heldout/finding-NN/`: `attacks.json` with
   exactly one entry marked `"reported": true`, `benign.json`, and
   `reference_app.py` implementing the known correct fix.
3. Copy the reported payload to `reported/finding-NN-reported-payload.txt`.
4. Change the entry's `status` from `planned` to `built` and fill in the
   public fields above.
5. Add the matching entry to `heldout/corpus/experimenter.json`.
6. Capture both baselines:

       python tools/capture_baseline.py --finding finding-NN

   The benign baseline is taken from the reference app, never from the
   unpatched app (METHODOLOGY-NOTES.md note 1). The capture refuses to
   overwrite an existing baseline without `--force`, because check C compares
   against it and replacing it after patches were scored would silently
   invalidate every recorded result.
7. Run `python tools/check_no_leak.py` before committing.
