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

## Note 8: the model authoring this corpus was re-routed mid-build after the content was flagged as cyber

Recorded on 2026-09-14 while building the Phase A findings (04, 08, 13).
Partway through authoring the SQL injection payloads, the session was moved to
a different model. The attribution the harness stamps on commits changed from
Claude Opus 5 to Claude Opus 4.8, and the session reported itself running on the
new model from that point on. This is the behaviour of a safety classifier that
flags cyber content, in this case exploit payloads for CWE-89, and routes the
session elsewhere.

It is worth having on the record, not as a complaint. This pilot's subject is
exploit payloads, so it will meet this repeatedly: any session that writes or
scores attack sets is producing exactly the content such a classifier looks for.
Two consequences follow.

First, provenance. The repository already discloses that the corpus was authored
by one of the subjects under test, and that disclosure is the reason the flaws
are based on published CWE-89 examples with citable sources rather than invented
freehand. The honest extension is that the author was not even a single fixed
model across the build. The corpus may be authored partly by one model and
partly by another, with the boundary decided by a classifier mid-session and not
by us. A reader auditing who wrote what should know that boundary is real and is
not visible in the commit graph.

Second, reproducibility of the process, not of the artifacts. The artifacts are
deterministic and gated: every attack was checked to leak on the vulnerable app
and be neutralised on the reference, and the byte-compare gates hold whichever
model produced a file. What is not reproducible is the authoring session itself.
Re-running this build may route differently, stop partway, or refuse, depending
on how the content is classified that day. The gates do not depend on the model,
which is the whole point of having them. The build process does.

Stated plainly: this note records an operational fact about how the corpus was
produced, so that the question "who authored this" has a truthful answer that
includes "more than one model, split at a point we did not choose". It changes
none of the verdicts and none of the held-out material.

## Note 9: check A cannot pass a correct identifier fix, and our own reference fails it

Found on 2026-09-14 scoring the Phase C patches on finding-08, the ORDER BY
identifier shape.

The correct fix for an identifier interpolation is an allow-list: validate the
column against a fixed set and reject anything else. An identifier cannot be a
bound parameter, so the f-string that builds the query stays in the code. The
Semgrep rule matches that f-string. So check A, which asks whether the scanner
still reports, stays red for a correct fix, because the correct fix does not
remove the thing the scanner matches.

This is not a theory about a hypothetical patch. Our own known-correct
reference, heldout/finding-08/reference_app.py, allow-lists the column and
still trips Semgrep at line 52. The reference we captured the baseline from,
the artifact we call the ground-truth correct fix, fails our own check A.
VERIFIED is therefore unreachable for finding-08 as built: no fix that keeps
the allow-list shape can pass A, and the intended correct fix is one of them.

Cursor's finding-08 patch showed it in a scored cell. It allow-listed all five
real columns. Check B passed with zero held-out attacks leaking, check C
passed with zero benign divergence, check D passed. The hole was shut and
behaviour was preserved. It scored NOT VERIFIED, failure class "other", on
check A alone, because the scanner still fired on the surviving f-string.

### Same shape as note 2, opposite direction

  note 2  fixer-03 rewrote the query into a shape Semgrep does not match.
          Check A went green while the hole stayed open. A false negative.
  note 9  a correct allow-list keeps the shape Semgrep does match.
          Check A stays red while the hole is shut. A false positive.

Both say the same thing the pilot exists to say: the scanner is not a fix
oracle. Note 2 caught the scanner passing a broken fix; note 9 catches it
failing a correct one. Check B caught the first. Nothing but reading the code
catches the second, because check A is behaving exactly as written.

### This is a note-7 class defect

Note 7 was about assurances in prose that no code backed. This is the same
category one level down: an artifact, the finding-08 reference, that does not
satisfy the property we assert of it. We call it the known-correct VERIFIED
fix. Under our own harness it is NOT VERIFIED. The claim and the code disagree,
and the code is right: the claim is what has to change.

### How it is being resolved, and what is not yet done

The resolution, accepted before building the remaining findings, is that for
identifier shapes check A is informational only and the verdict rests on B, C
and D. The scanner cannot distinguish a correct allow-list from the original
flaw, so its result carries no fix-signal here, and treating it as a gate
manufactures a false NOT VERIFIED.

Stated as a limitation, not a fix: this note records the defect. The check A
redefinition for identifier shapes and a reference that passes whatever A
becomes are both pending and are a precondition for building findings 08 and
09 for real. Until then finding-08 cannot yield VERIFIED, and the one Phase C
cell eligible for it, cursor, is recorded NOT VERIFIED for a check a correct
fix cannot pass. The recorded verdict is left as it scored rather than
hand-corrected, because the artifacts are mechanical and the fix belongs in
the method, not in an edit to one result.

## Note 10: check C is an exact full-body compare, so a cosmetic contract change reads as a regression

Found on 2026-09-14 scoring finding-04, the numeric shape.

Cursor's finding-04 patch cast the id to an integer and bound it. The products
it returned were byte-identical to the reference for every benign input. It
still failed check C on all fourteen, every one status 200 against an expected
200, because the response echoes the id back in a "query_id" field, and the
int cast made it echo as a number where the reference echoes the original
string: 7 against "007", 1 against "1". The returned data was the same. The
echoed type was not.

Check C is an exact compare of the whole response body against the reference
baseline. So it flagged a change in the echoed input type as a regression,
which it is in the strict sense that a consumer parsing query_id as a string
would break, and is not in the sense that mattered here, which is whether the
right products came back. The failure class "over-broad" was applied to a
patch that rejects nothing and returns the same rows.

### The obvious suspect was not the cause

Cursor's patch also added a 400 branch for non-integer input. During capture I
predicted that branch might trip check C, and predicted the numeric benign
inputs would pass because they are all numeric. Both halves were wrong in the
same direction: the 400 branch never fired, because no benign input is
non-numeric, and the numeric inputs did not pass, because the echo type
changed. The thing I flagged was harmless and the thing I did not look at was
the catch. Recorded because a check C failure is worth reading to its actual
cause rather than to the plausible one.

### What changes, accepted before building the rest

Check C stays an exact full-body compare. It is mechanical, it is defensible,
and "the fix changed the response contract" is a real regression a caller
would see. What changes is that this is stated plainly rather than discovered
per finding, and that the remaining findings are built with it in mind: either
the endpoint does not echo the raw input in a form a type-coercing correct fix
would alter, or the finding documents that check C will read such an echo as a
regression. A benign set and a response shape that make a cosmetic divergence
indistinguishable from a security-relevant one weaken the check, and that is a
construction choice, not a property of check C.

## Note 11: resolving note 9. Check A is informational for identifier shapes, and the reference is scanner-clean

Done on 2026-09-14, before handing findings 08 and 09 to more fixers, because
note 9 was a defect that blocked them: our known-correct fix failed our own
harness.

Two changes, and the order matters.

### Check A no longer gates the verdict for identifier shapes

An identifier fix is an allow-list. It cannot remove the f-string the Semgrep
rule matches, so the scanner fires on a correct fix, and its result carries no
fix-signal for this shape. So for shape_key "identifier-interpolation", check A
is measured and recorded but does not gate the verdict, which rests on B, C and
D. Every other shape gates on A exactly as before, so finding-01's committed
artifact is byte-identical and both parity gates still hold. The artifact for
an identifier finding now carries `A_alert_closed.informational` and
`gates_verdict` so it explains itself; that field appears only for this shape,
which is why it does not disturb the byte-compare on finding-01.

Check A still feeds suppression-in-effect. An evasion that closes the alert by
concatenating unvalidated input while leaving the hole open is still caught by
A green plus B open, on identifier shapes as everywhere else. What changed is
only that a correct fix is no longer failed for a scanner false positive.

The verdict this corrected: finding-08 cursor was NOT VERIFIED, failure class
"other", on check A alone, with the hole shut and behaviour preserved. It is
now VERIFIED. The old verdict was the defect, not the patch. It is re-scored
rather than hand-edited, because the artifacts are mechanical.

### The reference is rebuilt to be scanner-clean

The allow-list is the fix. The reference now assembles the query from the
validated column and the literal direction rather than interpolating them, so
there is no user string in the SQL and the scanner does not fire on it. Scored
as a patch it is VERIFIED with check A actually passing, so the reference now
passes its own gate under the strict scanner as well as the redefined one.

This is a choice made for the reference, not a requirement placed on fixers. A
fixer that allow-lists and keeps the f-string, as Cursor did, is VERIFIED,
because check A is informational for this shape. We do not make the scanner
dictate a fixer's code. We do make our own ground-truth artifact clean, so that
"your known-correct reference trips your own scanner" is no longer true. The
construction is incidental; the allow-list is the fix, and the experimenter
manifest says so.

### Same lesson as note 2, now closed in both directions

  note 2   the scanner passed a broken fix. A false negative. Check B caught it.
  note 9   the scanner failed a correct fix. A false positive. Reading the code
           caught it.
  note 11  the false positive is removed from the verdict for the shape it
           afflicts, and the reference no longer triggers it.

The scanner is not a fix oracle, which is the pilot's whole claim. The harness
now encodes that for the one shape where the scanner is not just weak but
actively wrong, instead of asserting it in prose while a gate contradicts it.

### What is still owed

This resolves the identifier shape. It does not touch the ORM raw-query shape
(finding-12) or the multi-hop shape (finding-15), which are not built. If a
correct fix for either also keeps a scanner-matched construction, the same
question returns and check A will need the same treatment there. The rule is
now explicit: check A gates only where a correct fix can close the alert. That
is a property of the shape and must be decided per shape as each is built, not
assumed.

## Note 12: the corpus handed the fixer the answer, in prose

Found on 2026-09-14, after the Claude Code batch was scored and every real
tool's output had passed check B.

The vulnerable modules for findings 04, 08 and 13 opened with a docstring
written for us, not for a developer. finding_13.py said, in its first twenty
lines, that the flaw was second order, that the sink was in show_favourite,
that a fixer guarding only the entry point would leave the real sink open, and
that "the correct fix is to bind the value as a parameter at the sink in
show_favourite". finding_04.py said "the only fixes that work are the ones
that change how the value reaches the query at all: bind it as a parameter,
or validate it as an integer". finding_08.py said "the only correct fix is to
validate the chosen column against an allow-list of real column names". Each
had a comment on the line above the sink saying, in as many words, "this is
the flaw". Each cited OWASP and PortSwigger for the shape.

That module, unaltered, was the file in every handoff bundle. Cursor, Copilot
Autofix and Claude Code were each given the bug and, in the same file, the
name of the shape, the location of the sink and the fix that works. Every one
of them produced that fix.

### What it plausibly explains

Eight real-tool cells were scored against this corpus. Check B, the held-out
attack set, caught none of them: 0 successful attacks out of 93 fired. The
held-out sets do discriminate; they caught all six of our own probe patches,
including the two suppression-in-effect probes that check A passed. So the
question the Phase C write-up asked, whether the shapes were too easy, had
the wrong subject. The shapes were not too easy. The file said which fix to
write. A held-out set cannot catch a fixer that was told the answer, because
there is nothing for it to catch: the fix is correct.

The two NOT VERIFIED cells were both check C, and both are consistent with the
same reading. The docstring told each tool what the fix was but not what the
benign inputs were, and check C is the one check the docstring did not
answer.

This does not mean the tools would have failed without the docstring. It
means we do not know, which is the same thing for the purpose of a published
number. Every scored cell to date is a dry run of the harness and not a
measurement of the tools, and is marked so.

### The third instance of one class

  note 6   the answer key (reference fix, endpoint, oracle) was in the public
           manifest, and in the history after it was removed from the tree
  (unrecorded)
           the finding-01 module, as first drafted on 2026-09-08, carried
           comments announcing the flaw; the experimenter stripped them before
           the first commit and before any handoff. No commit records this.
           Every version of app/corpus_app.py reachable from this clone,
           including the pre-rewrite history, is one blob, and it passes the
           prose test with zero hits. It is counted here on the experimenter's
           word, and marked as such.
  note 12  findings 04, 08 and 13 were built, after both of those, with a
           docstring that named the shape, the sink, the attack and the fix,
           and were handed to three real tools that way

Three carriers, one leak: the corpus told the fixer the answer. Data in a
manifest, comments in a module, a docstring in a module. A corpus can leak
its solution through prose as easily as through data, and prose is the harder
one to see, because the person who wrote it was explaining the finding to
themselves and it reads as documentation.

finding-01 is left as it is. Its module is clean under the test, its three
patches are illustrative fixes written by us rather than tool output, and its
evidence is published with byte parity gates over it. There was no fixer to
hand the answer to, so the confound this note records does not attach to
those three cells; what attaches to them is already stated in the README,
that they are ours. That is disclosed rather than corrected.

### Both leak guards passed, and were right

tools/check_history_no_leak.py was run on the seven unpushed commits that
carried these modules, on the same day, immediately before the README
correction was to be pushed. It reported NO LEAK IN HISTORY, and it was
correct by its own definition. It searches for held-out payloads, experimenter
oracle prose, reference fix code, the answer-key fields in a manifest, and
paths under heldout/. A docstring saying "bind it as a parameter" is none of
those. The working-tree guard, tools/check_no_leak.py, has the same
definition and passed for the same reason.

This is the shape recorded in notes 2, 4 and 6 again. A guard answered the
question it was written to answer, correctly, while the thing that mattered
walked past it. Both guards had been tested against known leaks
(tools/verify_history_guard.py) and had failed on every one. None of the
known leaks was prose in a module, so the guards were never asked.

The push did not happen. It was held for an unrelated reason (seven commits
behind, not one) long enough for the docstrings to be read.

### How it is closed

harness/prose.py defines the missing test. It extracts every comment and
standalone string from a module and matches them against a vocabulary that
names the flaw (flaw, inject, attack, sink, taint, second order), the
mechanism (interpolate, concatenate, f-string, quote, escape), the fix (fix,
bind, parameterise, allow-list, validate, identifier) and the experiment
(scanner, Semgrep, CWE, OWASP, finding, shape, manifest, fixer, patch). A
module handed to a fixer may say what it does for its users and nothing else.
The list is blunt on purpose and will produce false positives; the cost of a
false positive is rewording a comment, and the cost of the false negative is
this note.

Both guards now run it. check_no_leak.py fails on it in the working tree, as
test 5. check_history_no_leak.py fails on it in any blob at a path the
manifest hands to fixers, in any commit a push would send. Run on the same
seven commits it had passed, the extended history guard reported DO NOT PUSH
on exactly the three module blobs. verify_history_guard.py gained a fourth
fixture, a module whose comment names the flaw and the fix and is cleaned in
a later commit, and the guard fails on it. tools/build_handoff.py now builds
the bundles mechanically and refuses to write one whose module fails the
test; the first time it was run it refused, because a git checkout during a
smoke test had silently restored the unstripped finding_04.py.

The modules are stripped. Each docstring now says what the service does and
how to run it. The removed text is preserved verbatim in the git-ignored
experimenter manifest for each finding, with the pre-strip module beside it.
The seed's users-table line, which said the records were "never meant to be
publicly readable", now says "account records". finding-01's module was
already clean; it, its three patches and their evidence are untouched and the
byte parity gates over them still hold.

Stripping moved the sink. The scanner baselines for 04, 08 and 13 were
recaptured and the manifest's line numbers updated; the benign baselines were
recaptured in the same run and are byte-identical to before, because the
reference apps did not change. The harness was then run end to end on the
stripped finding-04 with a throwaway bound-parameter patch, in a scratch
output root, and returned VERIFIED with A, B and C all clean.

### What the strip does not fix

The twelve patches on findings 04, 08 and 13, nine from real tools and three
probes, were cut against the pre-strip modules and no longer apply to the
stripped ones. They are kept as they were produced. Their evidence stays on
disk, marked provisional, and a --rescore of any of them would now report
INSUFFICIENT EVIDENCE rather than a verdict, which is the truthful answer.

Every one of the nine real-tool patches also deletes the "this is the flaw"
comment from above the sink, so the diff itself carries those two or three
lines as removed context. The module docstrings, which carried the fix, are
not in any patch. This is disclosed rather than edited: the patches are what
the tools produced.

The blind re-run is the measurement. Until it happens there is no result
about any tool, only a result about the corpus.

### How the history reached the public repository

The eight local commits from corpus phase A to this note carried the
pre-strip modules as blobs, and a blob stays fetchable by SHA after the file
is cleaned (note 6). They were squashed into one commit built from the
stripped tree before the first push, with the eight messages carried in the
squash message, so the public history begins at the stripped state and never
carries the docstrings. The granular history is kept on the experimenter
machine as the local branch pre-squash-local, beside the held-out material,
and is not pushed. The extended history guard passes on what was pushed.
