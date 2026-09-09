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

Writing the container path exposed a real hole in the scorer, and it is worth
recording because it failed in the flattering direction.

Check B judges each attack by whether the response leaked data. If the patched
app never started, every attack would fail to connect, every one would be
recorded as "did not succeed", and check B would pass. A patch that does not
even import would have scored as a patch that shut the hole.

The scorer now raises when the app never answers /health, and the caller
reports INSUFFICIENT EVIDENCE. Protocol section 3 already called for that
("the app would not build"); the code simply did not implement it. Every way a
run can fail to produce a verdict is now provoked on purpose in
tools/verify_insufficient_evidence.py, because a state that is never exercised
is a state we cannot claim works.
