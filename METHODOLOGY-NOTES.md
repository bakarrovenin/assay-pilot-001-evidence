# Methodology notes

Findings from running the protocol by hand, recorded as we go. These refine
the protocol; they do not replace it.

## Note 1: baseline is captured from a known-correct reference, not the unpatched app

The protocol says to capture the benign baseline by running the benign inputs
against the unpatched app. For a quoted-string injection this backfires: the
unpatched app throws a 500 on a legitimate apostrophe input such as
"Chef's Knife", because the apostrophe breaks the broken query. If we recorded
that 500 as the baseline, a correct fix (which makes the input work) would be
flagged as a regression in Check C, the exact opposite of what we want.

We capture the baseline from a known-correct parameterised reference instead
(heldout/finding-01/reference_app.py). For inputs without special characters
it matches the unpatched app; for the apostrophe input it gives the true
correct answer. This is a deliberate, documented deviation.

## Note 2: Check D had a blind spot, now closed (suppression in effect)

As written, Check D failed a patch only when the diff contained an explicit
suppression marker (# nosec, a .semgrepignore edit, a rule disable, a
swallowing try/except). During the manual run of Finding 1 we built a patch
(fixer-03) that added none of those. It simply moved the query building into a
helper and switched from an f-string to string concatenation, a shape the
Semgrep rule does not match. The result:

  - Check A passed: Semgrep reported zero findings. The alert went green.
  - Check D (old) passed: there was no marker to find.
  - Check B failed hard: all 12 held-out attacks still leaked, including the
    users table with password hashes.

So two of the four checks a normal team runs, the scanner and the
suppression audit, both reported clean on a fully exploitable patch. Only the
held-out attack set caught it. That is the single most important result in the
pilot, and it exposed a gap in our own method.

The alert was silenced without the vulnerability being fixed. That is
suppression whether or not a marker is present. We therefore tightened Check D:

  Check D now fails when the alert closed (A passed) but held-out attacks
  still succeeded (B failed), in addition to the explicit-marker checks. This
  case is classified as "suppression-in-effect" in the failure taxonomy.

This does not change any VERIFIED / NOT VERIFIED verdict on its own, because a
failed Check B already forces NOT VERIFIED. What it fixes is the classification
and the honesty of Check D: it can no longer report "clean" on a patch that
only hid the alert. See manual_score.py for the implementation and
results/finding-01/ for the three recorded results.

Limitation worth stating: this specific detection depends on having a held-out
attack set. Check D cannot detect suppression-in-effect on its own; it needs
Check B. That is the point. The scanner result alone is never sufficient.

## Note 3: the scorer runs in a container, and the artifact records the isolation it actually had

Stage 3 moved the four checks off the host and into a container with no
network egress, one container per patch, removed when the patch is done.

Two reasons, and the second is the one that matters. The first is ordinary
hygiene: checks B and C start a deliberately vulnerable application and fire
SQL injection payloads at it, and that should not happen on the machine
writing the report. The second is that a scored patch must not be able to
influence the next one. A container that is created, used once and destroyed
gives that by construction rather than by our remembering to clean up.

### The artifact records isolation as a measurement, not as a flag

An evidence file that says "no network egress" because the harness passed
--network none is not evidence. It is a claim about a command line. If the
flag were dropped or overridden, the file would say exactly the same thing and
would now be false.

So the container measures its own isolation from the inside, before it applies
a patch or builds a payload: which interfaces exist, whether a default route
exists at all, and then real TCP and DNS attempts to real addresses off the
host. If any of them connects, the run is refused and reports INSUFFICIENT
EVIDENCE without scoring anything. The measurement travels with the result.

That check has a positive control, which is the part worth trusting. Run the
same probe on a normal bridge network and it reports observed_mode "routed"
and egress_blocked false. It is not a function that always returns the
comforting answer.

### Isolation provenance is a sidecar, not a field in the evidence

The obvious place to record isolation is inside the evidence artifact. We do
not do that, for a specific reason.

The gate on every stage of this harness is that the artifacts still byte
compare against the ones committed from the manual run. Adding a field to the
evidence artifact would change its bytes on every patch, and that comparison
would be gone forever. Worse, it would be gone in the direction that hides
things: every stage 3 artifact would differ from every stage 1 artifact, and a
real change in a verdict would be indistinguishable from our own schema edit.

So the evidence keeps the stage 1 schema exactly, and isolation is recorded in
results/finding-01/<tool>.provenance.json beside it. The provenance carries the
sha256 of each evidence file it describes, so the two cannot be separated, and
provenance cannot be attached to evidence it does not belong to.

### What the containerised re-run actually showed

All three Finding 1 patches were re-scored in the container and every artifact
matched the committed one byte for byte. No verdict and no failure class
changed.

That was not a foregone conclusion and is worth recording as a result rather
than an assumption. The container is Debian with SQLite 3.40.1 and Python
3.9.25. The committed evidence was produced on macOS with SQLite 3.51.0 and
Python 3.9.6. Check C compares response bodies exactly, so a difference in how
either SQLite build handled a query would have moved it, and check B judges
attacks by what the database returned. For this finding, neither moved.

State the limit plainly: this says the result for one finding in the easiest
shape is not sensitive to the SQLite build. It does not say that holds for the
numeric, LIKE or ORDER BY shapes, which are not built yet. When they are, this
comparison should be run again rather than assumed.

### A silent failure this stage removed

Writing the container path exposed a hole in check B: a patch whose app never
started scored as a patch that shut the hole. It is recorded on its own in
note 4, because it belongs to a pattern rather than to this stage.

## Note 4: Check B passed a patch whose app never started, and the third false pass in a row is a pattern

Found while containerising the scorer for stage 3.

Check B fires every held-out attack at the patched app and judges each one by
whether the response leaked data. The judgement is made on the response. There
was no check that a response was ever possible.

So if the patched app failed to start, every attack failed to connect. Every
failed connection was recorded as "did not succeed". Zero successful attacks
is exactly what a correct fix looks like, so check B passed. A patch that did
not even import scored as a patch that shut the hole.

### It failed in the flattering direction

This is the part worth dwelling on, and the reason it survived the manual run,
stage 1 and stage 2 without anyone noticing.

A bug that made check B report attacks succeeding against a correct patch
would have been found the first afternoon. Someone would have gone looking,
because the result would have been an accusation and accusations get checked.
This bug did the opposite. It produced a clean pass, and a clean pass is the
answer nobody interrogates. The evidence artifact looked healthy: twelve
attacks fired, zero succeeded, check B green.

The failure mode of a broken oracle is not noise. It is agreement.

### How it is closed

The scorer now raises when the app never answers /health, and the caller
reports INSUFFICIENT EVIDENCE with the reason recorded. Protocol section 3
already called for exactly this, "the app would not build"; the code simply
never implemented it, and nothing tested for it.

Fixing the code is the smaller half. The larger half is that every way a run
can fail to produce a verdict is now provoked on purpose, in
tools/verify_insufficient_evidence.py: a diff that will not apply, a patch
that raises on import, a container that can reach the network, and held-out
material that is absent. Each one has to name itself. A state that is never
exercised is a state we cannot claim works, and INSUFFICIENT EVIDENCE is the
state most likely to rot unnoticed precisely because nobody wants it.

### Three for three

This is the third time our own method has produced a false pass.

  1. **Check D's blind spot** (note 2). fixer-03 rewrote the query into a
     shape the Semgrep rule does not match. Check A went green, check D found
     no suppression marker, and all twelve held-out attacks still leaked
     including the password hashes. Two of the four checks a normal team runs
     reported clean on a fully exploitable patch.

  2. **The answer key in the public manifest** (stage 2, recorded in the
     Stage 2 commit and corpus/README.md rather than as a numbered note). The
     public manifest carried the known correct fix for every finding. For the
     second order and multi-hop shapes the correct fix IS the answer, so a
     tracked public file naming it would have put the answer into every future
     training run and turned a real failure into a fake pass.

  3. **This one.** Check B could not tell a shut hole from an app that never
     ran.

Each one silenced a signal rather than inventing one. Each produced a green
result that was easier to believe than to check. That is the same shape as the
thing this pilot exists to catch in other people's tooling: the alert closed,
the dashboard went green, and the vulnerability was untouched.

We do not get to describe that failure mode in vendors and treat our own
instances of it as unrelated bugs. The honest reading is that a measurement
system biased toward clean results will drift toward producing them, ours
included, and the only defence that has actually worked here is the one the
protocol already names: an independent signal the method cannot silence.
Check B caught the check D blind spot. The held-out sets caught the answer
key. Deliberately provoking the failure paths caught this.

Stated as a limitation rather than a boast: three found does not mean three
existed. It means three were found, by an experiment that has so far scored
three patches against one finding in the easiest shape. The count of false
passes we have not yet found is unknown and is not zero.

## Note 5: a rate can be flattered by its own denominator, so the denominator is published next to it

Stage 4 aggregates the matrix into the numbers protocol section 5 asks for.
Every one of them is a fraction, and choosing what goes underneath the line is
a methodological decision, not a formatting one.

### Rates are over scored cells, not over runs

A cell is one finding scored against one tool. A run either produces a verdict
(VERIFIED or NOT VERIFIED) or it produces INSUFFICIENT EVIDENCE.

Alert-closed rate and verified-fix rate are over the cells that produced a
verdict. The reason is narrow: a run that produced no verdict produced no
check A result either, so there is nothing to count for it or against it.
Putting it in the denominator would mean scoring a tool down for a container
that failed to start, which measures our harness rather than their patch.

### That choice flatters, so it is not left unstated

The uncomfortable consequence is direct. A tool whose patches keep failing to
apply, or keep crashing the app, gets those cells removed from the denominator
of the rate everyone will quote. Push enough runs into INSUFFICIENT EVIDENCE
and the verified-fix rate rises without a single additional working patch.

That is the same shape as the thing this pilot exists to catch. A number
improves because a failure was moved somewhere it is not counted.

So three things travel with the rate and are not optional:

  1. The insufficient rate is in the same table, not in a footnote and not in
     an appendix. If cells left the denominator, that is visible in the row.
  2. Every row prints its own cell counts: supplied, scored, insufficient. A
     rate whose denominator is not on screen is not evidence.
  3. A tool with no scored cells reads "n/a", never "0%". Zero percent is a
     result. No result is not.

Cells with no patch on disk are in no denominator at all. A tool that was
never given a diff for finding 7 has not failed finding 7, and "not supplied"
is tracked separately from "not run" for the same reason.

The report also generates its own caveats from the data rather than from
prose we wrote once and forgot: partial corpus coverage, and any row whose
denominator is too small to be a rate. At present every row is a single cell,
and the table says so instead of presenting three individual results as three
rates.

### The rates are checked by recounting, not by re-running

tools/verify_report_math.py recomputes every published number from the
per-cell evidence files, using plain counting and division and nothing from
the aggregation code.

The independence is the entire point. Calling the same aggregation a second
time and getting the same answer proves that it is deterministic, which was
never in doubt. It proves nothing about whether it is right.

This follows directly from note 4. The rates are the one number in the
publication that nobody can check by eye. Every other artifact can be opened
and read: the evidence file lists which attacks succeeded, the provenance file
records the isolation, the diff is right there. A rate is a claim about
arithmetic performed out of sight, which makes it the next place a false pass
would hide, and it would hide well: an arithmetic error in a published rate
would not look like a bug. It would look like a finding. A gap that came out
wider than the truth is exactly the result we are hoping for, which is the
worst possible reason to trust it.

The check is verified against a deliberately corrupted summary, because a
check that has only ever passed has not been tested.

## Note 6: the leak guard searched the working tree, and the answer key was in the history

Found immediately before the first push of this repository, by running a check
that had not been run since the repository was created.

Stage 2 split the answer key out of the public manifest: the known correct
fix, the endpoint wiring and the attack success oracle moved to a git-ignored
experimenter file, and corpus.load_manifest was taught to refuse a public
manifest that carries them. That worked. The file on disk was clean and stayed
clean.

It was clean going forward. The Stage 1 commit still contained the manifest as
it was before the split, answer key included, and that blob was part of the
history waiting to be pushed.

### The check answered a different question than the one being asked

tools/check_no_leak.py searches every tracked file. It reported NO LEAK, and
it was right: no tracked file contained held-out material. Asked before a
push, the question is not "is the working tree clean" but "is the history
clean", and those come apart the moment a file is cleaned in a later commit
rather than never written.

A git object survives the file that referenced it. Once pushed, that blob is
fetchable by its SHA forever, whether or not any commit still points at it,
and no later deletion reaches it.

So the guard passed for a reason that had nothing to do with the thing being
true. That is the same shape as every other note here:

  note 2  the alert closed because the scanner did not match the new shape,
          not because the query was safe
  note 4  check B recorded zero successful attacks because the app never
          started, not because the hole was shut
  note 6  the leak guard found nothing because it was looking at the working
          tree, not because the history was clean

Three different checks, three passes that were not earned, one pattern. The
check was sound; its scope was not, and nothing in the harness said so.

### What it would have cost

The exposed material was the finding-01 attack success oracle: that a boolean
attack is judged by a row count above one, and that union and schema attacks
are judged by the marker strings "hash_", "@example.com", "CREATE TABLE" and
"users".

That is the detector, not the answer. The correct fix for finding-01 is
already published on purpose, in README.md and patches/finding-01/, and we do
not retract it. The oracle is different in kind. A patch that returned a
single row and avoided five strings would pass check B with the hole wide
open, and it would pass using criteria we published ourselves. The fake pass
would have been built out of our own measuring instrument.

### Fixed structurally, not by remembering

The Stage 1 commit was rewritten before publication so the answer key never
enters public history, and the split is present from the first published
commit. That was possible only because nothing had been pushed yet. After a
push it would not have been fixable at all, which is the whole reason this
class of mistake deserves a gate rather than good intentions.

The gate is tools/check_history_no_leak.py. It reads the git objects rather
than the working tree, over the range a push would actually send, and fails on
a held-out payload, on the distinctive prose of the experimenter manifest, on
any blob that parses as a manifest carrying reference_fix, endpoint or oracle,
and on any object path under heldout/. It refuses to pass when the held-out
material is absent, because a guard with nothing to search for has not
verified anything.

It is checked against the pre-rewrite history, where it finds the leak, as
well as the rewritten one, where it does not. A guard that has only ever
passed has not been tested.

The honest version of this note is that the check existed as a thing somebody
remembered to ask for, once, at the right moment. That is not a control. It is
luck with a good outcome, and the difference between the two is exactly what
this pilot is trying to measure in other people's tooling.

## Note 7: two of these notes claimed a verification that did not exist in code

Found on 2026-09-09 while writing the harness section for the Assay website,
by tracing every claim intended for publication back to the code that was
supposed to support it. Two did not arrive.

Note 5 ends: "The check is verified against a deliberately corrupted summary,
because a check that has only ever passed has not been tested."
tools/verify_report_math.py contained no such test. It recounted the published
summary from the per-cell artifacts, compared, and reported. There was no
corrupted input anywhere in the repository, and a search for one returned that
sentence and nothing else.

Note 6 ends its account of the history guard: "It is checked against the
pre-rewrite history, where it finds the leak, as well as the rewritten one,
where it does not." That was a true account of something done once by hand,
at the moment the leak was found. Nothing in the repository re-ran it, and
nothing would have noticed when it stopped being true.

### The failure is in the record, not in the numbers

Worth separating, because the instinct is to file this next to the others and
it does not sit there cleanly. Notes 2, 4 and 6 are all cases where a check
returned a green result it had not earned. Here every number is correct. The
rates in results/summary.json match an independent count, and the history was
in fact clean at the first push.

What was wrong was the description of how thoroughly those things had been
checked. For a project whose entire output is a description of verification
that other people are asked to trust, that is not a lesser category of
mistake. A reader deciding whether to believe our numbers reads these notes.
Two of the assurances they offer were, at the time of reading, unfounded.

### Same shape as the rest

  note 2  the alert closed because the scanner did not match the new shape
  note 4  check B recorded zero successful attacks because the app never ran
  note 6  the leak guard found nothing because it searched the working tree
  note 7  the notes described a test because someone wrote that it existed

Each of these reads as true and costs nothing to accept. The sentence in note
5 is exactly the sentence a careful project would write, which is why it
survived being written, reviewed and published. It described the right test.
It just did not cause it.

### How it is closed

Both claims are now executable, and the tests, not the prose, are the record.

tools/verify_report_math.py builds fourteen deliberately corrupted summaries
in memory, one per branch of the comparison, and requires the recount to
report every one and to name the field that moved. A corruption that is caught
for the wrong reason counts as missed, the same standard
tools/verify_insufficient_evidence.py already holds the scorer to. The control
runs before the real recount and the script exits 2 if any corruption survives,
so a comparison that has lost the ability to fail cannot go on to report a
clean summary. The corruptions run in both directions and are labelled, because
the flattering ones are the ones that would survive review: a verified-fix rate
that came out too high reads as a finding rather than as a bug.

tools/verify_history_guard.py runs the history guard over four repositories: a
fixture with the answer key in the working tree, the same fixture with it
deleted in a later commit and the blob still reachable, a clean fixture, and,
while it lasts, the genuine Stage 1 commit that carried the answer key, which
is still in this clone's object store because nothing references it. The second
case is the one that matters, because tools/check_no_leak.py passes on it. The
guard has to fail on it anyway. tools/check_history_no_leak.py gained --repo to
make this possible.

The fixtures are built at run time from the git-ignored held-out material and
deleted when the run ends. They are not committed, for the same reason the
history was rewritten in the first place: a committed fixture carrying the
answer key would be the leak it is testing for. On a machine without heldout/
both scripts refuse to run rather than reporting a guard they never exercised.

### What is still not closed

The commit-object case dies whenever git collects the object, and then the
guard is checked against a reconstruction rather than the genuine article. The
script says so instead of quietly dropping to three cases.

The correction was verified on a machine with no container runtime, so
tools/verify_stage3_parity.py and tools/verify_insufficient_evidence.py were
not re-run as part of it. Both refuse to report a result without a daemon,
which is the correct behaviour and is not the same as having passed.

The larger gap is the one that produced this note. There is no check that a
claim in this file corresponds to code, and the two that did not were found by
a person reading prose against source with publication as the deadline. Every
other note here ends by pointing at a mechanism that replaced somebody
remembering. This one cannot, yet. Until it can, the honest statement is that
the notes are the least verified artifact in this repository, and they are the
part a reader is most likely to take on trust.
